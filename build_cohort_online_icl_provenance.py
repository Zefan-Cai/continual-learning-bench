#!/usr/bin/env python3
"""Build and verify secret-free provenance for canonical Cohort online ICL.

The small provenance JSON is a fail-closed runtime contract.  The detailed
sidecar records the exact files, model, tokenizer, and environment behind each
digest.  Both outputs are published atomically and are never overwritten.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from build_cohort_causal_provenance import (
    _canonical_bytes,
    _file_record,
    _git_snapshot,
    collect_environment_payload,
    hash_hf_model,
)
from cohort_shared_causal_parity import verify_shared_causal_parity


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
AUDIT_KIND = "cohort_online_icl_provenance_audit"
BASE_CAUSAL_COMMIT = "1caf142f6ce611da8da8691d4c336388a4c3c4b3"
ONLINE_ICL_PROTOCOL = "cohort_reward_aware_online_icl_v1"
ICL_PREREG_FILENAME = "COHORT_MATCHED_ICL_PREREG_V1.md"

REQUIRED_PROVENANCE_FIELDS = frozenset(
    {
        "base_causal_commit",
        "environment_lock_sha256",
        "evaluation_code_sha256",
        "icl_prereg_sha256",
        "model_path",
        "model_sha256",
        "protocol",
        "shared_causal_code_sha256",
        "source_commit",
        "tokenizer_sha256",
    }
)

# Deliberately explicit: a new evaluation-affecting file is a protocol change,
# not something a recursive source-tree glob should silently absorb.
EVALUATION_CODE_ALLOWLIST = (
    "COHORT_MATCHED_ICL_PREREG_V1.md",
    "COHORT_QONLY_CAUSAL_PREREG.md",
    "COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md",
    "assemble_cohort_causal_manifest.py",
    "build_cohort_causal_provenance.py",
    "build_cohort_online_icl_protocol_seal.py",
    "build_cohort_online_icl_provenance.py",
    "cohort_shared_causal_parity.py",
    "data/cohort_studies/causal_adapt_2026071411/manifest.json",
    "data/cohort_studies/causal_eval_2026071412/manifest.json",
    "data/cohort_studies/online_icl_smoke_adapt_2026071496/manifest.json",
    "data/cohort_studies/online_icl_smoke_eval_2026071497/manifest.json",
    "experiments/cohort_studies/build_frozen_dataset.py",
    "generate_cohort_causal_grid.py",
    "generate_cohort_online_icl_grid.py",
    "grid_cohort_causal_formal.json",
    "grid_cohort_causal_smoke.json",
    "grid_cohort_online_icl_formal.json",
    "grid_cohort_online_icl_smoke.json",
    "launch_cohort_online_icl.sh",
    "run_cohort_causal.py",
    "run_cohort_online_icl.py",
    "src/artifacts.py",
    "src/errors.py",
    "src/interface.py",
    "src/logging_utils.py",
    "src/registry.py",
    "src/run_ids.py",
    "src/runtime/runner.py",
    "src/system_manifest.py",
    "src/systems/qwen_local/system.py",
    "src/systems/utils/structured_output.py",
    "src/tasks/cohort_studies/dgp.py",
    "src/tasks/cohort_studies/frozen_db.py",
    "src/tasks/cohort_studies/schedules/causal_adapt_2026071411.json",
    "src/tasks/cohort_studies/schedules/causal_eval_2026071412.json",
    "src/tasks/cohort_studies/scorer.py",
    "src/tasks/cohort_studies/scoring_cohorts.py",
    "src/tasks/cohort_studies/study_configs.py",
    "src/tasks/cohort_studies/task.py",
    "src/tasks/cohort_studies/templates/instance_brief.j2",
    "src/tasks/cohort_studies/templates/step_prompt.j2",
    "src/tasks/cohort_studies/tool_schemas.py",
    "src/tasks/schedules.py",
    "src/trace_metrics.py",
    "src/trace_storage.py",
    "src/usage.py",
    "validate_cohort_causal_results.py",
    "validate_cohort_causal_smoke.py",
    "validate_cohort_online_icl_results.py",
    "validate_cohort_online_icl_smoke.py",
)

_SENSITIVE_KEY_PARTS = frozenset(
    {
        "access_key",
        "api_key",
        "auth_token",
        "credential",
        "credentials",
        "oauth_token",
        "password",
        "passwd",
        "private_key",
        "secret",
        "secret_access_key",
        "token",
    }
)
_SENSITIVE_KEY_SUFFIXES = (
    "_access_key",
    "_api_key",
    "_auth_token",
    "_credential",
    "_credentials",
    "_oauth_token",
    "_passwd",
    "_password",
    "_private_key",
    "_secret",
    "_secret_access_key",
    "_secret_key",
    "_token",
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)(?:git\+https?|https?|ssh)://[^/@\s:]+:[^/@\s]+@"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\b(?:hf_|sk-)[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[a-z](?:\.[a-z0-9]+)?-[A-Za-z0-9.-]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_ALLOWED_RUNTIME_ARTIFACT_PREFIXES = (
    "artifacts/cohort_causal/",
    "artifacts/cohort_online_icl/",
)


def canonical_sha256(value: Any) -> str:
    """Return the canonical JSON SHA-256 used by every provenance binding."""

    import hashlib

    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _assert_clean_checkout_and_base_ancestry(root: Path, *, source_commit: str) -> None:
    status_lines = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    disallowed = []
    for line in status_lines:
        if line.startswith("?? ") and any(
            line[3:].startswith(prefix) for prefix in _ALLOWED_RUNTIME_ARTIFACT_PREFIXES
        ):
            continue
        disallowed.append(line)
    if disallowed:
        raise RuntimeError(
            "refusing checkout with tracked or unregistered untracked changes: "
            + ", ".join(disallowed)
        )
    ancestor = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            BASE_CAUSAL_COMMIT,
            source_commit,
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if ancestor.returncode != 0:
        raise RuntimeError(
            "online-ICL source commit does not descend from base causal commit"
        )


def _assert_secret_free(value: Any, *, path: str = "$") -> None:
    """Reject credential-shaped keys and values before an artifact is built."""

    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError(f"non-string provenance key at {path}")
            normalized = key.lower().replace("-", "_")
            if normalized in _SENSITIVE_KEY_PARTS or normalized.endswith(
                _SENSITIVE_KEY_SUFFIXES
            ):
                raise ValueError(f"secret-bearing key is forbidden at {path}.{key}")
            _assert_secret_free(nested, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _assert_secret_free(nested, path=f"{path}[{index}]")
        return
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
            raise ValueError(f"credential-shaped value is forbidden at {path}")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    raise TypeError(f"non-JSON provenance value at {path}: {type(value).__name__}")


def _json_clone(value: Any) -> Any:
    """Copy a payload while rejecting NaN, custom objects, and non-string keys."""

    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
    return json.loads(encoded)


def hash_evaluation_code(root: Path) -> dict[str, Any]:
    """Hash exactly the committed online-ICL evaluation surface."""

    if tuple(sorted(set(EVALUATION_CODE_ALLOWLIST))) != EVALUATION_CODE_ALLOWLIST:
        raise RuntimeError("evaluation code allowlist must be sorted and unique")
    records: list[dict[str, Any]] = []
    missing: list[str] = []
    for relative in EVALUATION_CODE_ALLOWLIST:
        path = root / relative
        if not path.is_file():
            missing.append(relative)
            continue
        records.append(_file_record(path, relative_to=root, role="evaluation_code"))
    if missing:
        raise FileNotFoundError(f"required evaluation code file(s) missing: {missing}")

    import subprocess

    tracked = subprocess.run(
        [
            "git",
            "ls-files",
            "--error-unmatch",
            "--",
            *EVALUATION_CODE_ALLOWLIST,
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if tracked.returncode != 0:
        raise RuntimeError(
            "every evaluation-code allowlist entry must be tracked by Git"
        )
    tracked_paths = {line for line in tracked.stdout.splitlines() if line}
    if tracked_paths != set(EVALUATION_CODE_ALLOWLIST):
        raise RuntimeError(
            "Git-tracked evaluation-code inventory differs from allowlist"
        )
    return {
        "allowlist": list(EVALUATION_CODE_ALLOWLIST),
        "files": records,
        "inventory_sha256": canonical_sha256(records),
    }


def hash_icl_preregistration(root: Path) -> dict[str, Any]:
    """Bind the competitive-ICL preregistration independently of inventory."""

    path = root / ICL_PREREG_FILENAME
    if not path.is_file():
        raise FileNotFoundError(f"required online-ICL preregistration missing: {path}")
    record = _file_record(path, relative_to=root, role="online_icl_preregistration")
    return {
        "path": record["path"],
        "sha256": record["sha256"],
        "size_bytes": record["size_bytes"],
    }


def create_provenance_bundle(
    *,
    root: Path,
    model_path: Path,
    environment_payload: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the runtime contract and detailed sidecar without writing."""

    root = root.resolve()
    source_commit = _git_snapshot(root)
    _assert_clean_checkout_and_base_ancestry(root, source_commit=source_commit)
    environment = _json_clone(
        collect_environment_payload()
        if environment_payload is None
        else environment_payload
    )
    _assert_secret_free(environment, path="$.environment")
    environment_sha256 = canonical_sha256(environment)
    model, tokenizer = hash_hf_model(model_path)
    shared_causal_code = verify_shared_causal_parity(
        repo_root=root,
        base_commit=BASE_CAUSAL_COMMIT,
    )
    evaluation = hash_evaluation_code(root)
    preregistration = hash_icl_preregistration(root)
    if _git_snapshot(root) != source_commit:
        raise RuntimeError("git HEAD changed while building provenance")
    _assert_clean_checkout_and_base_ancestry(root, source_commit=source_commit)

    provenance = {
        "base_causal_commit": BASE_CAUSAL_COMMIT,
        "environment_lock_sha256": environment_sha256,
        "evaluation_code_sha256": evaluation["inventory_sha256"],
        "icl_prereg_sha256": preregistration["sha256"],
        "model_path": str(model_path),
        "model_sha256": model["inventory_sha256"],
        "protocol": ONLINE_ICL_PROTOCOL,
        "shared_causal_code_sha256": shared_causal_code["inventory_sha256"],
        "source_commit": source_commit,
        "tokenizer_sha256": tokenizer["inventory_sha256"],
    }
    if set(provenance) != REQUIRED_PROVENANCE_FIELDS:
        raise RuntimeError("generated provenance fields drifted from runner contract")
    details = {
        "canonicalization": "UTF-8 canonical JSON; sorted keys; compact separators",
        "environment": {"payload": environment, "sha256": environment_sha256},
        "evaluation_code": evaluation,
        "git": {
            "base_causal_commit": BASE_CAUSAL_COMMIT,
            "source_commit": source_commit,
            "tracked_checkout_clean": True,
        },
        "hash_algorithm": "sha256",
        "kind": AUDIT_KIND,
        "model": {"path": str(model_path), **model},
        "preregistration": preregistration,
        "protocol": ONLINE_ICL_PROTOCOL,
        "provenance": provenance,
        "schema_version": SCHEMA_VERSION,
        "shared_causal_code": shared_causal_code,
        "tokenizer": {"path": str(model_path), **tokenizer},
    }
    _assert_secret_free(details)
    return provenance, details


def verify_current_provenance(
    *,
    root: Path,
    provenance: dict[str, Any],
    expected_model_path: Path | None = None,
    environment_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute every binding immediately before the online-ICL run."""

    if (
        not isinstance(provenance, dict)
        or set(provenance) != REQUIRED_PROVENANCE_FIELDS
    ):
        raise RuntimeError(
            "runtime provenance field schema differs from runner contract"
        )
    _assert_secret_free(provenance)
    model_path_value = provenance.get("model_path")
    if not isinstance(model_path_value, str) or not model_path_value:
        raise RuntimeError("runtime provenance model_path is invalid")
    if expected_model_path is not None and model_path_value != str(expected_model_path):
        raise RuntimeError("runtime model path differs from registered cell config")

    current, _details = create_provenance_bundle(
        root=root,
        model_path=Path(model_path_value),
        environment_payload=environment_payload,
    )
    mismatched = sorted(
        field
        for field in REQUIRED_PROVENANCE_FIELDS
        if _canonical_bytes(provenance[field]) != _canonical_bytes(current[field])
    )
    if mismatched:
        raise RuntimeError(
            "runtime provenance differs from current audited state: "
            + ", ".join(mismatched)
        )
    return current


def _publish_atomic_no_overwrite(path: Path, payload: bytes) -> None:
    """Link a fully fsynced temporary file into place without replacement."""

    requested = path.expanduser()
    requested.parent.mkdir(parents=True, exist_ok=True)
    path = requested.parent.resolve() / requested.name
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.tmp."
    )
    temporary = Path(temporary_name)
    linked = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
            linked = True
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to overwrite provenance artifact: {path}"
            ) from exc
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if linked:
            path.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def write_provenance_bundle(
    *,
    output: Path,
    details_output: Path,
    provenance: dict[str, Any],
    details: dict[str, Any],
) -> None:
    """Publish sidecar first and consumer JSON last as the commit marker."""

    output.parent.mkdir(parents=True, exist_ok=True)
    details_output.parent.mkdir(parents=True, exist_ok=True)
    output = output.expanduser().parent.resolve() / output.name
    details_output = details_output.expanduser().parent.resolve() / details_output.name
    if output == details_output:
        raise ValueError("provenance and details outputs must differ")
    existing = [path for path in (output, details_output) if path.exists()]
    if existing:
        raise FileExistsError(
            f"refusing to overwrite provenance artifact(s): {existing}"
        )
    _assert_secret_free(provenance)
    _assert_secret_free(details)
    details_payload = _canonical_bytes(details) + b"\n"
    provenance_payload = _canonical_bytes(provenance) + b"\n"
    _publish_atomic_no_overwrite(details_output, details_payload)
    try:
        _publish_atomic_no_overwrite(output, provenance_payload)
    except BaseException:
        details_output.unlink(missing_ok=True)
        raise


def _default_details_path(output: Path) -> Path:
    suffix = output.suffix or ".json"
    stem = output.stem if output.suffix else output.name
    return output.with_name(f"{stem}.details{suffix}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--details-output", type=Path)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = args.output.expanduser().parent.resolve() / args.output.name
    details_output = (
        (args.details_output.expanduser().parent.resolve() / args.details_output.name)
        if args.details_output is not None
        else _default_details_path(output)
    )
    if output.exists() or details_output.exists():
        raise SystemExit("refusing to overwrite an existing provenance artifact")
    provenance, details = create_provenance_bundle(
        root=args.root,
        model_path=args.model_path,
    )
    write_provenance_bundle(
        output=output,
        details_output=details_output,
        provenance=provenance,
        details=details,
    )
    print(json.dumps(provenance, indent=2, sort_keys=True))
    print(f"details: {details_output}")


if __name__ == "__main__":
    main()
