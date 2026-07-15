#!/usr/bin/env python3
"""Build a secret-free, auditable provenance bundle for Cohort causal runs.

The small provenance JSON is consumed directly by ``run_cohort_causal.py``.
Its detailed sidecar records every canonical input behind those digests.  Both
files are published atomically and are never overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# The fresh-retry clean-tree gate rejects ignored bytecode as an import-shadow
# channel.  Set this before importing any checkout-local module so provenance
# construction itself cannot create ``__pycache__``.
sys.dont_write_bytecode = True

from generate_cohort_causal_grid import ADAPTER_INIT_SEED  # noqa: E402
from run_cohort_causal import REQUIRED_PROVENANCE_FIELDS  # noqa: E402
from validate_cohort_causal_results import (  # noqa: E402
    EXPECTED_STATISTICAL_ADDENDUM_SHA256,
    PREREGISTERED_PARENT_COMMIT,
    STATISTICAL_ADDENDUM_FILENAME,
    _publish_no_overwrite,
)


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
AUDIT_KIND = "cohort_causal_provenance_audit"

# This is intentionally an allowlist, not a source-tree glob.  Adding or moving
# evaluation-affecting code must be an explicit provenance-contract change.
EVALUATION_CODE_ALLOWLIST = (
    "COHORT_CAUSAL_LOG_RECIPIENT_V1.txt",
    "COHORT_CAUSAL_SEALED_LOG_RUNTIME_V1.json",
    "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V1.md",
    "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V2.md",
    "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V3.md",
    "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V4.md",
    "COHORT_QONLY_CAUSAL_PREREG.md",
    "COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md",
    "assemble_cohort_causal_manifest.py",
    "build_cohort_causal_provenance.py",
    "generate_cohort_causal_grid.py",
    "grid_cohort_causal_formal.json",
    "grid_cohort_causal_smoke.json",
    "launch_cohort_causal.sh",
    "run_cohort_causal.py",
    "run_cohort_causal_cell_sealed.py",
    "run_cohort_causal_formal_registered.py",
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
    "wait_cohort_causal_phase_outputs.py",
)

_MODEL_CONFIG_NAMES = {"config.json", "generation_config.json"}
_MODEL_CODE_PATTERNS = (
    re.compile(r"configuration_.*\.py\Z"),
    re.compile(r"modeling_.*\.py\Z"),
)
_MODEL_WEIGHT_SUFFIXES = (".bin", ".ckpt", ".pt", ".pth", ".safetensors")
_TOKENIZER_NAMES = {
    "added_tokens.json",
    "chat_template.jinja",
    "chat_template.json",
    "merges.txt",
    "preprocessor_config.json",
    "special_tokens_map.json",
    "spiece.model",
    "tokenizer.json",
    "tokenizer.model",
    "tokenizer_config.json",
    "vocab.json",
    "vocab.txt",
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    stable = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if not stable:
        raise RuntimeError(f"file changed while hashing: {path}")
    return digest.hexdigest(), after.st_size


def _file_record(path: Path, *, relative_to: Path, role: str) -> dict[str, Any]:
    digest, size = _sha256_file(path)
    return {
        "path": path.relative_to(relative_to).as_posix(),
        "role": role,
        "sha256": digest,
        "size_bytes": size,
    }


def _run_text(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _git_snapshot(root: Path) -> str:
    top_level = Path(
        _run_text(["git", "rev-parse", "--show-toplevel"], cwd=root).strip()
    ).resolve()
    if top_level != root.resolve():
        raise RuntimeError(f"root is not the git checkout root: {root}")
    dirty = _run_text(
        ["git", "status", "--porcelain=v1", "--untracked-files=no"], cwd=root
    ).strip()
    if dirty:
        raise RuntimeError("refusing dirty tracked checkout")
    commit = _run_text(["git", "rev-parse", "--verify", "HEAD"], cwd=root).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("git HEAD is not a full lowercase commit SHA")
    return commit


def _sanitize_freeze_line(line: str) -> str:
    """Retain an exact one-way binding without persisting credentialed URLs."""

    stripped = line.strip()
    if "://" not in stripped:
        return stripped
    url_match = re.search(r"[A-Za-z][A-Za-z0-9+.-]*://", stripped)
    if url_match is None:
        raise ValueError("pip freeze URL marker could not be safely isolated")
    prefix = stripped[: url_match.start()].rstrip()
    separator = "" if not prefix else " "
    digest = hashlib.sha256(stripped.encode()).hexdigest()
    return f"{prefix}{separator}<url-sha256:{digest}>"


def _pip_freeze_all() -> list[str]:
    output = _run_text([sys.executable, "-m", "pip", "freeze", "--all"])
    return sorted(
        _sanitize_freeze_line(line) for line in output.splitlines() if line.strip()
    )


def _json_safe_version(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (tuple, list)):
        return [_json_safe_version(item) for item in value]
    return str(value)


def _torch_runtime() -> dict[str, Any]:
    try:
        import torch
    except ImportError:
        return {"installed": False}

    cudnn_version = None
    nccl_version = None
    try:
        cudnn_version = torch.backends.cudnn.version()
    except (AttributeError, RuntimeError):
        pass
    try:
        nccl_version = torch.cuda.nccl.version()
    except (AttributeError, RuntimeError):
        pass
    return {
        "cuda_available": bool(torch.cuda.is_available()),
        "cuda_build_version": _json_safe_version(torch.version.cuda),
        "cudnn_runtime_version": _json_safe_version(cudnn_version),
        "git_version": _json_safe_version(torch.version.git_version),
        "installed": True,
        "nccl_runtime_version": _json_safe_version(nccl_version),
        "torch_version": str(torch.__version__),
    }


def _nvidia_driver_versions() -> list[str]:
    try:
        completed = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=driver_version",
                "--format=csv,noheader",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return []
    if completed.returncode != 0:
        return []
    return sorted(
        {line.strip() for line in completed.stdout.splitlines() if line.strip()}
    )


def _age_runtime() -> dict[str, Any]:
    binary_value = os.environ.get("COHORT_CAUSAL_AGE_BINARY") or shutil.which("age")
    if binary_value is None:
        return {"installed": False}
    binary = Path(binary_value)
    if (
        not binary.is_absolute()
        or binary.is_symlink()
        or not binary.is_file()
        or binary.resolve() != binary
    ):
        raise RuntimeError("age runtime is not a direct absolute regular file")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    completed = subprocess.run(
        [str(binary), "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError("age runtime version cannot be captured")
    contract_path = ROOT / "COHORT_CAUSAL_SEALED_LOG_RUNTIME_V1.json"
    try:
        contract = json.loads(contract_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("sealed-log runtime contract cannot be loaded") from exc
    if (
        contract.get("age_binary_sha256") != digest
        or contract.get("age_version") != completed.stdout.strip()
    ):
        raise RuntimeError("age runtime differs from the sealed-log contract")
    return {
        "binary_path": str(binary),
        "binary_sha256": digest,
        "installed": True,
        "version": completed.stdout.strip(),
    }


def collect_environment_payload() -> dict[str, Any]:
    """Collect versioned runtime facts and the explicit pinned-age path only."""

    return {
        "pip_freeze_all": _pip_freeze_all(),
        "platform": {
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python_implementation": platform.python_implementation(),
            "release": platform.release(),
            "system": platform.system(),
            "version": platform.version(),
        },
        "python": {
            "compiler": platform.python_compiler(),
            "implementation": platform.python_implementation(),
            "runtime_version": platform.python_version(),
            "version_info": list(sys.version_info[:5]),
        },
        "runtime_versions": {
            "age": _age_runtime(),
            "nvidia_driver_versions": _nvidia_driver_versions(),
            "torch": _torch_runtime(),
        },
    }


def _model_role(path: Path) -> str | None:
    name = path.name
    if name in _MODEL_CONFIG_NAMES:
        return "generation_config" if name == "generation_config.json" else "config"
    if name.endswith(".index.json"):
        return "weight_index"
    if name.endswith(_MODEL_WEIGHT_SUFFIXES):
        return "weight"
    if any(pattern.fullmatch(name) for pattern in _MODEL_CODE_PATTERNS):
        return "remote_model_code"
    return None


def _is_tokenizer_file(path: Path) -> bool:
    name = path.name
    return (
        name in _TOKENIZER_NAMES
        or name.endswith(".tiktoken")
        or name.startswith("chat_template.")
        or name.startswith("sentencepiece")
        and name.endswith(".model")
    )


def hash_hf_model(model_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Hash model and tokenizer inventories separately by actual file content."""

    if not model_path.is_absolute():
        raise ValueError("model path must be absolute to match the registered grid")
    if not model_path.is_dir():
        raise FileNotFoundError(f"model path is not a directory: {model_path}")
    model_records: list[dict[str, Any]] = []
    tokenizer_records: list[dict[str, Any]] = []
    for path in sorted(model_path.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        if _is_tokenizer_file(path):
            tokenizer_records.append(
                _file_record(path, relative_to=model_path, role="tokenizer")
            )
            continue
        role = _model_role(path)
        if role is not None:
            model_records.append(_file_record(path, relative_to=model_path, role=role))

    roles = {record["role"] for record in model_records}
    if "config" not in roles:
        raise FileNotFoundError("HF model inventory is missing config.json")
    if "weight" not in roles:
        raise FileNotFoundError("HF model inventory contains no weight files")
    if not tokenizer_records:
        raise FileNotFoundError("HF tokenizer inventory is empty")

    model_files = {record["path"] for record in model_records}
    for record in model_records:
        if record["role"] != "weight_index":
            continue
        index_path = model_path / record["path"]
        try:
            index = json.loads(index_path.read_text())
            referenced = set(index["weight_map"].values())
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"malformed HF weight index: {index_path}") from exc
        missing = sorted(referenced - model_files)
        if missing:
            raise FileNotFoundError(
                f"HF weight index references missing shard(s): {missing}"
            )

    model_inventory = {
        "files": model_records,
        "inventory_sha256": canonical_sha256(model_records),
    }
    tokenizer_inventory = {
        "files": tokenizer_records,
        "inventory_sha256": canonical_sha256(tokenizer_records),
    }
    return model_inventory, tokenizer_inventory


def hash_evaluation_code(root: Path) -> dict[str, Any]:
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
            "Git-tracked evaluation-code inventory differs from the allowlist"
        )
    return {
        "allowlist": list(EVALUATION_CODE_ALLOWLIST),
        "files": records,
        "inventory_sha256": canonical_sha256(records),
    }


def hash_statistical_addendum(root: Path) -> dict[str, Any]:
    """Bind the exact registered addendum bytes independently of code inventory."""

    path = root / STATISTICAL_ADDENDUM_FILENAME
    if not path.is_file():
        raise FileNotFoundError(f"required statistical addendum missing: {path}")
    digest, size_bytes = _sha256_file(path)
    if digest != EXPECTED_STATISTICAL_ADDENDUM_SHA256:
        raise RuntimeError("statistical addendum bytes differ from registered SHA-256")
    return {
        "path": STATISTICAL_ADDENDUM_FILENAME,
        "sha256": digest,
        "size_bytes": size_bytes,
    }


def create_provenance_bundle(
    *,
    root: Path,
    model_path: Path,
    environment_payload: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the consumer JSON and detailed audit sidecar without writing."""

    root = root.resolve()
    source_commit = _git_snapshot(root)
    environment = (
        collect_environment_payload()
        if environment_payload is None
        else json.loads(json.dumps(environment_payload))
    )
    environment_sha256 = canonical_sha256(environment)
    model, tokenizer = hash_hf_model(model_path)
    evaluation = hash_evaluation_code(root)
    statistical_addendum = hash_statistical_addendum(root)
    if _git_snapshot(root) != source_commit:
        raise RuntimeError("git HEAD changed while building provenance")

    provenance = {
        "adapter_init_seed": ADAPTER_INIT_SEED,
        "environment_lock_sha256": environment_sha256,
        "evaluation_code_sha256": evaluation["inventory_sha256"],
        "model_path": str(model_path),
        "model_sha256": model["inventory_sha256"],
        "preregistered_parent_commit": PREREGISTERED_PARENT_COMMIT,
        "source_commit": source_commit,
        "statistical_addendum_sha256": statistical_addendum["sha256"],
        "tokenizer_sha256": tokenizer["inventory_sha256"],
    }
    if set(provenance) != REQUIRED_PROVENANCE_FIELDS:
        raise RuntimeError("generated provenance fields drifted from runner contract")
    details = {
        "canonicalization": "UTF-8 canonical JSON; sorted keys; compact separators",
        "environment": {"payload": environment, "sha256": environment_sha256},
        "evaluation_code": evaluation,
        "git": {"source_commit": source_commit, "tracked_checkout_clean": True},
        "hash_algorithm": "sha256",
        "kind": AUDIT_KIND,
        "model": {"path": str(model_path), **model},
        "provenance": provenance,
        "schema_version": SCHEMA_VERSION,
        "statistical_addendum": statistical_addendum,
        "tokenizer": {"path": str(model_path), **tokenizer},
    }
    return provenance, details


def verify_current_provenance(
    *,
    root: Path,
    provenance: dict[str, Any],
    expected_model_path: Path | None = None,
    environment_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute every runtime binding before a causal cell allocates a model.

    A provenance file is only a snapshot.  Comparing ``git rev-parse HEAD`` is
    insufficient because tracked files (or the model directory) can change
    without moving HEAD.  This intentionally repeats the content hashes at
    consumption time so a stale or hand-written provenance JSON fails closed.
    """

    if not isinstance(provenance, dict) or set(provenance) != (
        REQUIRED_PROVENANCE_FIELDS
    ):
        raise RuntimeError(
            "runtime provenance field schema differs from runner contract"
        )
    model_path_value = provenance.get("model_path")
    if not isinstance(model_path_value, str) or not model_path_value:
        raise RuntimeError("runtime provenance model_path is invalid")
    model_path = Path(model_path_value)
    if expected_model_path is not None and model_path_value != str(expected_model_path):
        raise RuntimeError("runtime model path differs from registered cell config")

    current, _details = create_provenance_bundle(
        root=root,
        model_path=model_path,
        environment_payload=environment_payload,
    )
    mismatched = sorted(
        key
        for key in REQUIRED_PROVENANCE_FIELDS
        if _canonical_bytes(provenance[key]) != _canonical_bytes(current[key])
    )
    if mismatched:
        raise RuntimeError(
            "runtime provenance differs from current audited state: "
            + ", ".join(mismatched)
        )
    return current


def _publish_atomic_no_overwrite(path: Path, payload: bytes) -> None:
    try:
        _publish_no_overwrite(path, payload)
    except FileExistsError as exc:
        raise FileExistsError(
            f"refusing to overwrite provenance artifact: {path}"
        ) from exc


def write_provenance_bundle(
    *,
    output: Path,
    details_output: Path,
    provenance: dict[str, Any],
    details: dict[str, Any],
) -> None:
    """Publish sidecar then consumer JSON; the consumer file is the commit marker."""

    output = output.resolve()
    details_output = details_output.resolve()
    if output == details_output:
        raise ValueError("provenance and details outputs must differ")
    existing = [path for path in (output, details_output) if path.exists()]
    if existing:
        raise FileExistsError(
            f"refusing to overwrite provenance artifact(s): {existing}"
        )
    details_payload = _canonical_bytes(details) + b"\n"
    provenance_payload = _canonical_bytes(provenance) + b"\n"
    _publish_atomic_no_overwrite(details_output, details_payload)
    _publish_atomic_no_overwrite(output, provenance_payload)


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

    output = args.output.resolve()
    details_output = (
        args.details_output.resolve()
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
