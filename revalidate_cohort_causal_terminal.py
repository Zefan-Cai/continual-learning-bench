#!/usr/bin/env python3
"""Independently revalidate the completed Cohort causal terminal snapshot.

This verifier is deliberately downstream of the completion attestation.  It
does not semantically open the original decision until the current inventory,
PID file, and zero exit file still match the attested terminal snapshot.  It
then rebuilds the formal manifest from raw registered inputs, recomputes the
formal decision, and publishes only a byte-identical revalidation artifact and
a redacted classification receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from build_cohort_structured_state_execution_seal import (
    ExecutionSealError,
    load_and_validate_execution_plan_stage,
)

ATTESTATION_PROTOCOL = "cohort_causal_terminal_completion_attestation_v1"
LAUNCH_EXPECTATION_PROTOCOL = "cohort_causal_formal_launch_expectation_v1"
PROTOCOL = "cohort_qonly_frozen_tape_weight_update_ablation_v1"
SCHEMA_VERSION = 1
EXPERIMENT = "cohort_qonly_frozen_tape_causal_formal"
PREREGISTRATION_FILENAME = "COHORT_QONLY_CAUSAL_PREREG.md"
STATISTICAL_ADDENDUM_FILENAME = "COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md"
PREREGISTERED_PARENT_COMMIT = "2d79ec6cd6ce4520ed36e2f68e0afd49fe73d350"
REQUIRED_PROVENANCE_FIELDS = {
    "adapter_init_seed",
    "environment_lock_sha256",
    "evaluation_code_sha256",
    "model_path",
    "model_sha256",
    "preregistered_parent_commit",
    "source_commit",
    "statistical_addendum_sha256",
    "tokenizer_sha256",
}
RECEIPT_KEYS = {
    "decision",
    "decision_scope",
    "execution_plan_path",
    "execution_plan_sha256",
    "formal_decision_file_sha256",
    "formal_manifest_file_sha256",
    "status",
}
REVALIDATED_FILENAME = "causal_formal.revalidated.json"
RECEIPT_FILENAME = "causal_formal.revalidation_receipt.json"

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_PID_RE = re.compile(rb"[1-9][0-9]*\n?\Z")
_ASCII_WHITESPACE = b" \t\n\r\v\f"

_ATTESTATION_KEYS = {
    "causal_pre_attestation_inventory_sha256",
    "completed_at_utc",
    "execution_plan_path",
    "execution_plan_sha256",
    "expected_launcher",
    "no_live_or_temporary",
    "pid_exit",
    "process_absence",
    "protocol",
    "registered_counts",
    "schema_version",
    "snapshots",
    "stability",
    "status",
}
_EXPECTED_LAUNCHER_KEYS = {
    "formal_grid_file_sha256",
    "launch_expectation_path",
    "launch_expectation_sha256",
    "launcher_file_sha256",
    "provenance_file_sha256",
    "source_commit",
    "wrapper_cmdline_sha256_at_registration",
}
_REGISTERED_COUNTS_KEYS = {
    "cell_final_traces",
    "cell_manifests",
    "collector_final_traces",
    "collector_manifests",
    "formal_decisions",
    "formal_manifests",
    "tapes",
    "total",
}
_EXPECTED_REGISTERED_COUNTS = {
    "cell_final_traces": 6,
    "cell_manifests": 6,
    "collector_final_traces": 3,
    "collector_manifests": 3,
    "formal_decisions": 1,
    "formal_manifests": 1,
    "tapes": 3,
    "total": 23,
}
_PID_EXIT_KEYS = {
    "exit_after_outputs_status",
    "exit_file_mtime_ns",
    "exit_file_path",
    "exit_file_sha256",
    "exit_file_size_bytes",
    "exit_zero_status",
    "pid_ascii_status",
    "pid_file_mtime_ns",
    "pid_file_path",
    "pid_file_sha256",
    "pid_file_size_bytes",
    "pid_liveness_status",
}
_STABILITY_KEYS = {
    "minimum_interval_seconds",
    "observed_interval_seconds",
    "snapshots_identical",
}
_SNAPSHOT_KEYS = {
    "captured_at_utc",
    "file_count",
    "files",
    "inventory_sha256",
    "sequence",
}
_FILE_RECORD_KEYS = {
    "device",
    "inode",
    "mtime_ns",
    "path",
    "roles",
    "sha256",
    "size_bytes",
}
_LAUNCH_EXPECTATION_KEYS = {
    "artifact_root",
    "attempt_id",
    "boot_id",
    "checkout_root",
    "collector_gpus",
    "created_at_utc",
    "durable_attempt_root",
    "eval_gpus",
    "expected_final_inventory",
    "exit_file",
    "formal_grid_file_sha256",
    "launch_mode",
    "launcher_file_sha256",
    "max_used_memory_mib",
    "node_hostname",
    "pid_file",
    "pid_file_sha256_at_registration",
    "protocol",
    "provenance_file_sha256",
    "schema_version",
    "source_commit",
    "wrapper_cmdline_sha256_at_registration",
    "wrapper_pid",
    "wrapper_start_ticks",
}
_PROCESS_ABSENCE_KEYS = {
    "artifact_root_path",
    "attempt_checkout_path",
    "audit_sha256",
    "method",
    "status",
}
_NO_LIVE_OR_TEMPORARY_KEYS = {
    "audit_sha256",
    "forbidden_match_count",
    "roots",
    "status",
}
_DETAIL_KEYS = {
    "canonicalization",
    "environment",
    "evaluation_code",
    "git",
    "hash_algorithm",
    "kind",
    "model",
    "provenance",
    "schema_version",
    "statistical_addendum",
    "tokenizer",
}
_EVALUATION_KEYS = {"allowlist", "files", "inventory_sha256"}
_EVALUATION_FILE_KEYS = {"path", "role", "sha256", "size_bytes"}


class RevalidationError(RuntimeError):
    """A fail-closed terminal revalidation failure."""


class DuplicateKeyError(ValueError):
    """A JSON object contained a duplicate key."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _compact_file_bytes(value: Any) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _pretty_report_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _load_json_bytes(payload: bytes, *, label: str) -> Any:
    try:
        text = payload.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        raise RevalidationError(f"strict JSON load failed for {label}: {exc}") from exc


def _read_stable_file(path: Path) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RevalidationError(f"cannot open attested regular file: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RevalidationError(f"attested path is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after:
        raise RevalidationError(f"file changed while reading: {path}")
    return b"".join(chunks), after


def _hash_stable_file(path: Path) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RevalidationError(f"cannot open attested regular file: {path}: {exc}") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RevalidationError(f"attested path is not a regular file: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise RevalidationError(f"file changed while hashing: {path}")
    return digest.hexdigest(), after


def _current_file_record(attested: dict[str, Any]) -> dict[str, Any]:
    path = Path(attested["path"])
    digest, metadata = _hash_stable_file(path)
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mtime_ns": metadata.st_mtime_ns,
        "path": str(path),
        "roles": attested["roles"],
        "sha256": digest,
        "size_bytes": metadata.st_size,
    }


def _expect_exact_keys(value: Any, keys: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise RevalidationError(
            f"{label} must contain exact keys {sorted(keys)!r}; observed {observed!r}"
        )
    return value


def _validate_file_record(value: Any, *, label: str) -> dict[str, Any]:
    record = _expect_exact_keys(value, _FILE_RECORD_KEYS, label=label)
    path = record["path"]
    if not isinstance(path, str) or not path or not Path(path).is_absolute():
        raise RevalidationError(f"{label}.path must be an absolute path")
    roles = record["roles"]
    if (
        not isinstance(roles, list)
        or not roles
        or any(not isinstance(role, str) or not role for role in roles)
        or roles != sorted(set(roles))
    ):
        raise RevalidationError(f"{label}.roles must be sorted unique strings")
    for key in ("device", "inode", "mtime_ns", "size_bytes"):
        if not _is_int(record[key]) or record[key] < 0:
            raise RevalidationError(f"{label}.{key} must be a nonnegative integer")
    if not _is_sha256(record["sha256"]):
        raise RevalidationError(f"{label}.sha256 must be a lowercase SHA-256")
    return record


def _validate_snapshot(value: Any, *, position: int) -> dict[str, Any]:
    snapshot = _expect_exact_keys(value, _SNAPSHOT_KEYS, label=f"snapshots[{position}]")
    if snapshot["sequence"] != position + 1:
        raise RevalidationError("attestation snapshot sequence is not canonical")
    if not isinstance(snapshot["captured_at_utc"], str) or not snapshot["captured_at_utc"]:
        raise RevalidationError("snapshot captured_at_utc must be non-empty")
    files = snapshot["files"]
    if not isinstance(files, list) or not files:
        raise RevalidationError("attestation snapshot files must be non-empty")
    validated = [
        _validate_file_record(item, label=f"snapshots[{position}].files[{index}]")
        for index, item in enumerate(files)
    ]
    paths = [item["path"] for item in validated]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise RevalidationError("attestation inventory paths must be sorted and unique")
    if snapshot["file_count"] != len(validated):
        raise RevalidationError("attestation snapshot file_count mismatch")
    expected_digest = _sha256_bytes(_canonical_bytes(validated))
    if snapshot["inventory_sha256"] != expected_digest:
        raise RevalidationError("attestation snapshot inventory digest mismatch")
    return snapshot


def _validate_attestation(attestation: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    value = _expect_exact_keys(attestation, _ATTESTATION_KEYS, label="attestation")
    if value["protocol"] != ATTESTATION_PROTOCOL or value["schema_version"] != 1:
        raise RevalidationError("unexpected completion-attestation protocol or schema")
    if value["status"] != "complete":
        raise RevalidationError("completion attestation is not terminal-valid")
    if not isinstance(value["completed_at_utc"], str) or not value["completed_at_utc"]:
        raise RevalidationError("attestation completed_at_utc must be non-empty")
    if (
        not isinstance(value["execution_plan_path"], str)
        or not Path(value["execution_plan_path"]).is_absolute()
        or not _is_sha256(value["execution_plan_sha256"])
    ):
        raise RevalidationError("attestation execution-plan binding is invalid")

    expected_launcher = _expect_exact_keys(
        value["expected_launcher"],
        _EXPECTED_LAUNCHER_KEYS,
        label="attestation.expected_launcher",
    )
    for key in (
        "formal_grid_file_sha256",
        "launch_expectation_sha256",
        "launcher_file_sha256",
        "provenance_file_sha256",
        "wrapper_cmdline_sha256_at_registration",
    ):
        if not _is_sha256(expected_launcher[key]):
            raise RevalidationError(f"attestation.expected_launcher.{key} is invalid")
    if not isinstance(expected_launcher["launch_expectation_path"], str):
        raise RevalidationError("launch expectation path must be a string")
    source_commit = expected_launcher["source_commit"]
    if (
        not isinstance(source_commit, str)
        or len(source_commit) != 40
        or any(character not in "0123456789abcdef" for character in source_commit)
    ):
        raise RevalidationError("attested source_commit is invalid")

    counts = _expect_exact_keys(
        value["registered_counts"],
        _REGISTERED_COUNTS_KEYS,
        label="attestation.registered_counts",
    )
    if counts != _EXPECTED_REGISTERED_COUNTS:
        raise RevalidationError("attested registered artifact counts are not formal counts")

    pid_exit = _expect_exact_keys(value["pid_exit"], _PID_EXIT_KEYS, label="attestation.pid_exit")
    for key in ("pid_file_path", "exit_file_path"):
        if not isinstance(pid_exit[key], str) or not Path(pid_exit[key]).is_absolute():
            raise RevalidationError(f"attestation.pid_exit.{key} must be absolute")
    for key in ("pid_file_sha256", "exit_file_sha256"):
        if not _is_sha256(pid_exit[key]):
            raise RevalidationError(f"attestation.pid_exit.{key} is invalid")
    for key in (
        "pid_file_size_bytes",
        "pid_file_mtime_ns",
        "exit_file_size_bytes",
        "exit_file_mtime_ns",
    ):
        if not _is_int(pid_exit[key]) or pid_exit[key] < 0:
            raise RevalidationError(f"attestation.pid_exit.{key} is invalid")
    if {
        "pid_ascii_status": pid_exit["pid_ascii_status"],
        "pid_liveness_status": pid_exit["pid_liveness_status"],
        "exit_zero_status": pid_exit["exit_zero_status"],
        "exit_after_outputs_status": pid_exit["exit_after_outputs_status"],
    } != {
        "pid_ascii_status": "pass",
        "pid_liveness_status": "dead",
        "exit_zero_status": "pass",
        "exit_after_outputs_status": "pass",
    }:
        raise RevalidationError("attested PID/exit status fields are not terminal-valid")

    stability = _expect_exact_keys(
        value["stability"], _STABILITY_KEYS, label="attestation.stability"
    )
    if stability["snapshots_identical"] is not True:
        raise RevalidationError("attestation did not establish identical snapshots")
    minimum = stability["minimum_interval_seconds"]
    observed = stability["observed_interval_seconds"]
    if (
        isinstance(minimum, bool)
        or not isinstance(minimum, (int, float))
        or isinstance(observed, bool)
        or not isinstance(observed, (int, float))
        or minimum < 1.0
        or observed < minimum
    ):
        raise RevalidationError("attestation stability interval is invalid")

    snapshots_value = value["snapshots"]
    if not isinstance(snapshots_value, list) or len(snapshots_value) != 2:
        raise RevalidationError("attestation must contain exactly two snapshots")
    snapshots = [
        _validate_snapshot(snapshot, position=position)
        for position, snapshot in enumerate(snapshots_value)
    ]
    if _canonical_bytes(snapshots[0]["files"]) != _canonical_bytes(snapshots[1]["files"]):
        raise RevalidationError("attestation stable snapshots differ")
    inventory_digest = snapshots[0]["inventory_sha256"]
    if (
        snapshots[1]["inventory_sha256"] != inventory_digest
        or value["causal_pre_attestation_inventory_sha256"] != inventory_digest
    ):
        raise RevalidationError("attestation inventory digest bindings disagree")

    process_audit = _expect_exact_keys(
        value["process_absence"],
        _PROCESS_ABSENCE_KEYS,
        label="attestation.process_absence",
    )
    if (
        process_audit["status"] != "pass"
        or process_audit["method"] != "linux_procfs_cmdline_and_cwd"
        or not isinstance(process_audit["attempt_checkout_path"], str)
        or not Path(process_audit["attempt_checkout_path"]).is_absolute()
        or not isinstance(process_audit["artifact_root_path"], str)
        or not Path(process_audit["artifact_root_path"]).is_absolute()
    ):
        raise RevalidationError("attestation process-absence audit is invalid")
    process_payload = {
        key: process_audit[key] for key in _PROCESS_ABSENCE_KEYS - {"audit_sha256"}
    }
    if process_audit["audit_sha256"] != _sha256_bytes(
        _canonical_bytes(process_payload)
    ):
        raise RevalidationError("attestation process-absence digest mismatch")

    temporary_audit = _expect_exact_keys(
        value["no_live_or_temporary"],
        _NO_LIVE_OR_TEMPORARY_KEYS,
        label="attestation.no_live_or_temporary",
    )
    roots = temporary_audit["roots"]
    temporary_payload = {
        key: temporary_audit[key]
        for key in _NO_LIVE_OR_TEMPORARY_KEYS - {"audit_sha256"}
    }
    if (
        temporary_audit["status"] != "pass"
        or temporary_audit["forbidden_match_count"] != 0
        or not isinstance(roots, list)
        or not roots
        or roots != sorted(set(roots))
        or any(not isinstance(root, str) or not Path(root).is_absolute() for root in roots)
        or temporary_audit["audit_sha256"]
        != _sha256_bytes(_canonical_bytes(temporary_payload))
    ):
        raise RevalidationError("attestation no-live/no-temporary audit is invalid")
    return value, snapshots[0]["files"]


def _verify_current_inventory(files: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    current = [_current_file_record(record) for record in files]
    if _canonical_bytes(current) != _canonical_bytes(files):
        raise RevalidationError("current causal inventory differs from completion attestation")
    return {record["path"]: record for record in current}


def _path_key(path: Path) -> str:
    return str(path.expanduser().resolve())


def _require_inventory_paths(
    inventory: dict[str, dict[str, Any]], paths: Iterable[Path], *, label: str
) -> None:
    missing = sorted({_path_key(path) for path in paths} - set(inventory))
    if missing:
        raise RevalidationError(f"attested inventory omits registered {label}: {missing}")


def _unique_path_for_role(files: list[dict[str, Any]], role: str) -> Path:
    matches = [Path(record["path"]) for record in files if role in record["roles"]]
    if len(matches) != 1:
        raise RevalidationError(f"attested inventory must contain exactly one {role}")
    return matches[0]


def _load_strict_json_file(path: Path, *, label: str) -> tuple[Any, bytes]:
    payload, _ = _read_stable_file(path)
    return _load_json_bytes(payload, label=label), payload


def _strict_scan_inventory_json(
    files: list[dict[str, Any]], *, deferred_paths: Iterable[Path] = ()
) -> None:
    deferred = {_path_key(path) for path in deferred_paths}
    for record in files:
        path = Path(record["path"])
        if path.suffix.lower() == ".json" and _path_key(path) not in deferred:
            _load_strict_json_file(path, label=record["path"])


def _validate_registered_grid(
    value: Any, *, make_grid_fn: Callable[..., dict[str, Any]]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RevalidationError("formal grid must be a JSON object")
    expected = make_grid_fn(smoke=False)
    if _canonical_bytes(value) != _canonical_bytes(expected):
        raise RevalidationError("formal grid differs from the registered generator output")
    return value


def _validate_registered_provenance(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REQUIRED_PROVENANCE_FIELDS:
        raise RevalidationError("causal provenance has a non-exact schema")
    digest_fields = {
        key
        for key in REQUIRED_PROVENANCE_FIELDS
        if key.endswith("_sha256")
        or key in {"source_commit", "preregistered_parent_commit"}
    }
    for key in digest_fields:
        expected_length = 40 if key in {"source_commit", "preregistered_parent_commit"} else 64
        item = value[key]
        if (
            not isinstance(item, str)
            or len(item) != expected_length
            or any(character not in "0123456789abcdef" for character in item)
        ):
            raise RevalidationError(f"invalid causal provenance field: {key}")
    if value["preregistered_parent_commit"] != PREREGISTERED_PARENT_COMMIT:
        raise RevalidationError("causal provenance preregistered parent mismatch")
    return value


def _validate_detailed_provenance(
    *,
    root: Path,
    details: Any,
    provenance: dict[str, Any],
    inventory: dict[str, dict[str, Any]],
) -> set[Path]:
    details_object = _expect_exact_keys(details, _DETAIL_KEYS, label="detailed provenance")
    if details_object["provenance"] != provenance:
        raise RevalidationError("detailed provenance does not bind compact provenance")
    evaluation = _expect_exact_keys(
        details_object["evaluation_code"],
        _EVALUATION_KEYS,
        label="detailed provenance evaluation_code",
    )
    allowlist = evaluation["allowlist"]
    records = evaluation["files"]
    if (
        not isinstance(allowlist, list)
        or not allowlist
        or allowlist != sorted(set(allowlist))
        or any(not isinstance(path, str) or not path for path in allowlist)
        or not isinstance(records, list)
        or len(records) != len(allowlist)
    ):
        raise RevalidationError("detailed provenance evaluation allowlist is invalid")
    if evaluation["inventory_sha256"] != _sha256_bytes(_canonical_bytes(records)):
        raise RevalidationError("detailed provenance evaluation inventory digest mismatch")
    if provenance["evaluation_code_sha256"] != evaluation["inventory_sha256"]:
        raise RevalidationError("compact/detailed evaluation inventory digest mismatch")
    paths: set[Path] = set()
    observed_relative: list[str] = []
    for position, item in enumerate(records):
        record = _expect_exact_keys(
            item,
            _EVALUATION_FILE_KEYS,
            label=f"detailed provenance evaluation files[{position}]",
        )
        if record["role"] != "evaluation_code":
            raise RevalidationError("detailed provenance evaluation role mismatch")
        relative_text = record["path"]
        relative = Path(relative_text) if isinstance(relative_text, str) else Path("/")
        if (
            not isinstance(relative_text, str)
            or not relative_text
            or relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != relative_text
        ):
            raise RevalidationError("detailed provenance evaluation path is unsafe")
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise RevalidationError("evaluation-code path escapes registered root") from exc
        key = _path_key(path)
        if key not in inventory or "evaluation_code" not in inventory[key]["roles"]:
            raise RevalidationError("evaluation-code file is absent from attested inventory")
        if (
            inventory[key]["sha256"] != record["sha256"]
            or inventory[key]["size_bytes"] != record["size_bytes"]
        ):
            raise RevalidationError("evaluation-code metadata differs from provenance")
        observed_relative.append(relative_text)
        paths.add(path)
    if observed_relative != allowlist:
        raise RevalidationError("evaluation-code records differ from exact allowlist")
    return paths


def _load_registered_runtime(
    root: Path,
) -> tuple[
    Callable[..., dict[str, Any]],
    Callable[[Any], dict[str, Any]],
    Callable[..., dict[str, Any]],
]:
    """Load assembler, evaluator, and grid generator from the attested checkout."""

    isolated_names = (
        "assemble_cohort_causal_manifest",
        "generate_cohort_causal_grid",
        "run_cohort_causal",
        "validate_cohort_causal_results",
    )
    requested_names = (
        "assemble_cohort_causal_manifest",
        "validate_cohort_causal_results",
        "generate_cohort_causal_grid",
    )
    previous_modules = {
        name: sys.modules[name] for name in isolated_names if name in sys.modules
    }
    for name in isolated_names:
        sys.modules.pop(name, None)
    root_text = str(root)
    sys.path.insert(0, root_text)
    previous_dont_write = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        importlib.invalidate_caches()
        modules = [importlib.import_module(name) for name in requested_names]
    finally:
        sys.dont_write_bytecode = previous_dont_write
        if sys.path[0] == root_text:
            sys.path.pop(0)
        for name in isolated_names:
            sys.modules.pop(name, None)
        sys.modules.update(previous_modules)
    expected_files = [
        root / "assemble_cohort_causal_manifest.py",
        root / "validate_cohort_causal_results.py",
        root / "generate_cohort_causal_grid.py",
    ]
    for module, expected in zip(modules, expected_files, strict=True):
        module_file = getattr(module, "__file__", None)
        if module_file is None or Path(module_file).resolve() != expected.resolve():
            raise RevalidationError("registered runtime module resolved outside attested root")
    return modules[0].assemble_manifest, modules[1].evaluate, modules[2].make_grid


def _validate_launch_expectation(value: Any) -> dict[str, Any]:
    expectation = _expect_exact_keys(value, _LAUNCH_EXPECTATION_KEYS, label="launch expectation")
    if (
        expectation["protocol"] != LAUNCH_EXPECTATION_PROTOCOL
        or expectation["schema_version"] != 1
        or expectation["launch_mode"] != "formal"
    ):
        raise RevalidationError("unexpected causal launch expectation")
    if expectation["expected_final_inventory"] != {
        "cell_final_traces": 6,
        "cell_manifests": 6,
        "collector_final_traces": 3,
        "collector_manifests": 3,
        "formal_decisions": 1,
        "formal_manifests": 1,
        "tapes": 3,
        "total": 23,
    }:
        raise RevalidationError("launch expectation final inventory counts drifted")
    for key in (
        "formal_grid_file_sha256",
        "launcher_file_sha256",
        "pid_file_sha256_at_registration",
        "provenance_file_sha256",
        "wrapper_cmdline_sha256_at_registration",
    ):
        if not _is_sha256(expectation[key]):
            raise RevalidationError(f"launch expectation field is not SHA-256: {key}")
    return expectation


def _resolve_registered(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _artifact_from_grid(path: str | Path, *, artifact_root: Path) -> Path:
    relative = Path(path)
    prefix = Path("artifacts/cohort_causal")
    try:
        suffix = relative.relative_to(prefix)
    except ValueError as exc:
        raise RevalidationError("formal grid artifact path has an invalid prefix") from exc
    return (artifact_root / suffix).resolve()


def _registered_assembler_inputs(
    *,
    root: Path,
    artifact_root: Path,
    grid: dict[str, Any],
    dataset_manifests: dict[str, dict[str, Any]],
) -> set[Path]:
    paths: set[Path] = set()
    for role in ("adaptation", "heldout"):
        dataset = grid["datasets"][role]
        dataset_root = _resolve_registered(root, dataset["path"]).resolve()
        manifest_path = dataset_root / "manifest.json"
        paths.add(manifest_path)
        manifest = dataset_manifests[role]
        schedule_id = manifest.get("schedule_id")
        if schedule_id != dataset.get("schedule"):
            raise RevalidationError(f"{role} dataset schedule binding mismatch")
        paths.add(
            (root / "src/tasks/cohort_studies/schedules" / f"{schedule_id}.json").resolve()
        )
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise RevalidationError(f"{role} dataset manifest has no artifacts")
        for position, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "size_bytes"}:
                raise RevalidationError(
                    f"{role} dataset artifact {position} has a non-exact schema"
                )
            relative = artifact["path"]
            if not isinstance(relative, str) or not relative:
                raise RevalidationError(f"{role} dataset artifact path is invalid")
            artifact_path = (dataset_root / relative).resolve()
            try:
                artifact_path.relative_to(dataset_root)
            except ValueError as exc:
                raise RevalidationError(f"{role} dataset artifact escapes dataset root") from exc
            paths.add(artifact_path)

    for collector in grid["collectors"]:
        cfg_id = collector["cfg_id"]
        paths.add(_artifact_from_grid(collector["tape_path"], artifact_root=artifact_root))
        paths.add((artifact_root / "collectors" / f"{cfg_id}.manifest.json").resolve())
        paths.add((artifact_root / "traces" / f"{cfg_id}.trace.json").resolve())
    for cell in grid["evaluation_cells"]:
        cfg_id = cell["cfg_id"]
        paths.add(
            _artifact_from_grid(cell["cell_manifest_path"], artifact_root=artifact_root)
        )
        paths.add((artifact_root / "traces" / f"{cfg_id}.trace.json").resolve())
    return paths


def _verify_assembler_artifact_aliases(
    *,
    root: Path,
    artifact_root: Path,
    grid: dict[str, Any],
    inventory: dict[str, dict[str, Any]],
) -> None:
    """Prove the pure assembler's root-relative reads are attested files."""

    aliases: list[tuple[Path, Path]] = []
    for collector in grid["collectors"]:
        cfg_id = collector["cfg_id"]
        aliases.extend(
            [
                (
                    _resolve_registered(root, collector["tape_path"]),
                    _artifact_from_grid(
                        collector["tape_path"], artifact_root=artifact_root
                    ),
                ),
                (
                    root
                    / "artifacts/cohort_causal/collectors"
                    / f"{cfg_id}.manifest.json",
                    artifact_root / "collectors" / f"{cfg_id}.manifest.json",
                ),
                (
                    root / "artifacts/cohort_causal/traces" / f"{cfg_id}.trace.json",
                    artifact_root / "traces" / f"{cfg_id}.trace.json",
                ),
            ]
        )
    for cell in grid["evaluation_cells"]:
        cfg_id = cell["cfg_id"]
        aliases.extend(
            [
                (
                    _resolve_registered(root, cell["cell_manifest_path"]),
                    _artifact_from_grid(
                        cell["cell_manifest_path"], artifact_root=artifact_root
                    ),
                ),
                (
                    root / "artifacts/cohort_causal/traces" / f"{cfg_id}.trace.json",
                    artifact_root / "traces" / f"{cfg_id}.trace.json",
                ),
            ]
        )
    for alias, registered in aliases:
        registered_key = _path_key(registered)
        if registered_key not in inventory:
            raise RevalidationError("assembler artifact is absent from attested inventory")
        digest, metadata = _hash_stable_file(alias)
        record = inventory[registered_key]
        if (
            metadata.st_dev != record["device"]
            or metadata.st_ino != record["inode"]
            or metadata.st_size != record["size_bytes"]
            or metadata.st_mtime_ns != record["mtime_ns"]
            or digest != record["sha256"]
        ):
            raise RevalidationError(
                "pure assembler would read an unregistered artifact alias"
            )


def _validate_pid_exit_gate(
    *,
    attestation: dict[str, Any],
    inventory: dict[str, dict[str, Any]],
    formal_manifest: Path,
    formal_decision: Path,
) -> None:
    binding = attestation["pid_exit"]
    pid_path = Path(binding["pid_file_path"])
    exit_path = Path(binding["exit_file_path"])
    _require_inventory_paths(inventory, (pid_path, exit_path), label="PID/exit files")
    pid_payload, pid_metadata = _read_stable_file(pid_path)
    exit_payload, exit_metadata = _read_stable_file(exit_path)
    for prefix, payload, metadata in (
        ("pid", pid_payload, pid_metadata),
        ("exit", exit_payload, exit_metadata),
    ):
        if binding[f"{prefix}_file_sha256"] != _sha256_bytes(payload):
            raise RevalidationError(f"current {prefix} file digest differs from attestation")
        if binding[f"{prefix}_file_size_bytes"] != metadata.st_size:
            raise RevalidationError(f"current {prefix} file size differs from attestation")
        if binding[f"{prefix}_file_mtime_ns"] != metadata.st_mtime_ns:
            raise RevalidationError(f"current {prefix} file mtime differs from attestation")
    if _PID_RE.fullmatch(pid_payload) is None:
        raise RevalidationError("PID file is not canonical positive base-10 ASCII")
    pid = int(pid_payload.rstrip(b"\n").decode("ascii"), 10)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        raise RevalidationError("registered wrapper PID liveness is not disproven") from exc
    else:
        raise RevalidationError("registered wrapper PID is currently live")
    if exit_payload.strip(_ASCII_WHITESPACE) != b"0":
        raise RevalidationError("causal launcher exit file is nonzero or malformed")
    output_mtime = max(
        inventory[_path_key(formal_manifest)]["mtime_ns"],
        inventory[_path_key(formal_decision)]["mtime_ns"],
    )
    if exit_metadata.st_mtime_ns <= output_mtime:
        raise RevalidationError("causal launcher exit file does not postdate formal outputs")


def _validate_classification(report: Any) -> tuple[str, str]:
    if not isinstance(report, dict):
        raise RevalidationError("recomputed causal report is not an object")
    if report.get("decision") == "invalid" or report.get("status") != "valid":
        raise RevalidationError("recomputed causal decision is invalid")
    required = {
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "status": "valid",
        "errors": [],
        "publication_grade": False,
    }
    for key, expected in required.items():
        if report.get(key) != expected:
            raise RevalidationError(f"recomputed causal report violates {key} contract")
    branch = (report.get("decision"), report.get("decision_scope"))
    if branch not in {
        ("pass", "internal_gate_pass"),
        ("valid_no_go", "internal_gate_no_go"),
    }:
        raise RevalidationError("recomputed causal report has an unknown valid branch")
    return branch


def _path_lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _normalized_absolute_output(path: Path, *, label: str) -> Path:
    expanded = path.expanduser()
    text = os.fspath(expanded)
    if (
        not expanded.is_absolute()
        or ".." in expanded.parts
        or os.path.normpath(text) != text
    ):
        raise RevalidationError(f"{label} must be a normalized absolute path")
    return expanded


def _require_fixed_output_parent(
    *, path: Path, durable_root: Path, expected_name: str, label: str
) -> None:
    expected_parent = durable_root / "prep"
    if path != expected_parent / expected_name:
        raise RevalidationError("revalidation outputs differ from fixed durable/prep paths")
    for directory in (durable_root, expected_parent):
        try:
            mode = os.lstat(directory).st_mode
        except OSError as exc:
            raise RevalidationError(f"{label} parent is unavailable: {directory}") from exc
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise RevalidationError(f"{label} parent may not be a symlink: {directory}")


def _stage_payload(path: Path, payload: bytes) -> Path:
    try:
        parent_mode = os.lstat(path.parent).st_mode
    except OSError as exc:
        raise RevalidationError(f"revalidation output parent is unavailable: {path.parent}") from exc
    if stat.S_ISLNK(parent_mode) or not stat.S_ISDIR(parent_mode):
        raise RevalidationError("revalidation output parent must be a real directory")
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.tmp.")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _fsync_directories(paths: Iterable[Path]) -> None:
    for directory in sorted({path.parent for path in paths}, key=str):
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _publish_pair_no_overwrite(outputs: list[tuple[Path, bytes]]) -> None:
    normalized = [
        _normalized_absolute_output(path, label="revalidation output")
        for path, _ in outputs
    ]
    if len({_path_key(path) for path in normalized}) != len(normalized):
        raise RevalidationError("revalidation output paths must be distinct")
    existing = [str(path) for path in normalized if _path_lexists(path)]
    if existing:
        raise FileExistsError("refusing to overwrite revalidation artifact(s): " + ", ".join(existing))
    staged: list[tuple[Path, Path]] = []
    linked: list[Path] = []
    try:
        for (requested, payload), path in zip(outputs, normalized, strict=True):
            staged.append((_stage_payload(path, payload), path))
        for temporary, path in staged:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise FileExistsError(f"refusing to overwrite revalidation artifact: {path}") from exc
            linked.append(path)
        _fsync_directories(linked)
    except BaseException:
        # Publication is monotonic.  A final hard link may have become visible
        # to another process immediately after link(2) returned.  Never unlink
        # it on a later failure: leave the partial evidence in place so every
        # retry fails the no-overwrite preflight instead of opening a replace
        # race or silently manufacturing an all-or-nothing history.
        if linked:
            _fsync_directories(linked)
        raise
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)


def revalidate_terminal(
    *,
    root: Path,
    execution_plan_path: Path,
    attestation_path: Path,
    launch_expectation_path: Path,
    grid_path: Path,
    provenance_path: Path,
    formal_manifest_path: Path,
    formal_decision_path: Path,
    revalidated_output: Path,
    receipt_output: Path,
    preregistration_path: Path | None = None,
    statistical_addendum_path: Path | None = None,
    assemble_fn: Callable[..., dict[str, Any]] | None = None,
    evaluate_fn: Callable[[Any], dict[str, Any]] | None = None,
    make_grid_fn: Callable[..., dict[str, Any]] | None = None,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
) -> dict[str, Any]:
    """Revalidate and publish one attested terminal causal result."""

    root = root.expanduser().resolve()
    execution_plan_path = execution_plan_path.expanduser().resolve()
    attestation_path = attestation_path.expanduser().resolve()
    launch_expectation_path = launch_expectation_path.expanduser().resolve()
    grid_path = grid_path.expanduser().resolve()
    provenance_path = provenance_path.expanduser().resolve()
    formal_manifest_path = formal_manifest_path.expanduser().resolve()
    formal_decision_path = formal_decision_path.expanduser().resolve()
    revalidated_output = _normalized_absolute_output(
        revalidated_output, label="revalidated decision output"
    )
    receipt_output = _normalized_absolute_output(
        receipt_output, label="classification receipt output"
    )
    preregistration_path = (
        (root / PREREGISTRATION_FILENAME).resolve()
        if preregistration_path is None
        else preregistration_path.expanduser().resolve()
    )
    statistical_addendum_path = (
        (root / STATISTICAL_ADDENDUM_FILENAME).resolve()
        if statistical_addendum_path is None
        else statistical_addendum_path.expanduser().resolve()
    )
    output_paths = {revalidated_output, receipt_output}
    protected_inputs = {
        attestation_path,
        launch_expectation_path,
        grid_path,
        provenance_path,
        formal_manifest_path,
        formal_decision_path,
        preregistration_path,
        statistical_addendum_path,
    }
    if {_path_key(path) for path in output_paths} & {_path_key(path) for path in protected_inputs}:
        raise RevalidationError("revalidation outputs may not alias registered inputs")
    if any(_path_lexists(path) for path in output_paths):
        raise FileExistsError("refusing pre-existing revalidation output")

    try:
        _, execution_plan_raw = load_and_validate_execution_plan_stage(
            execution_plan_path=execution_plan_path,
            stage="revalidator",
            expected_inputs={
                "execution_plan": execution_plan_path,
                "root": root,
                "attestation": attestation_path,
                "launch_expectation": launch_expectation_path,
                "grid": grid_path,
                "provenance": provenance_path,
                "formal_manifest": formal_manifest_path,
                "formal_decision": formal_decision_path,
                "preregistration": preregistration_path,
                "statistical_addendum": statistical_addendum_path,
            },
            expected_outputs={
                "revalidated_decision": revalidated_output,
                "revalidation_receipt": receipt_output,
            },
            expected_parameters={},
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    except ExecutionSealError as exc:
        raise RevalidationError(
            f"terminal verifier execution plan is invalid: {exc}"
        ) from exc
    execution_plan_sha256 = _sha256_bytes(execution_plan_raw)

    attestation_raw, _ = _read_stable_file(attestation_path)
    attestation_object = _load_json_bytes(attestation_raw, label="completion attestation")
    if attestation_raw != _canonical_bytes(attestation_object):
        raise RevalidationError("completion attestation is not canonical JSON bytes")
    attestation, attested_files = _validate_attestation(attestation_object)
    if (
        attestation["execution_plan_path"] != execution_plan_path.as_posix()
        or attestation["execution_plan_sha256"] != execution_plan_sha256
    ):
        raise RevalidationError("completion attestation execution-plan binding differs")

    # First terminal gate: hash-only inventory verification is allowed, but the
    # decision has not yet been parsed, decoded, or classified.
    current_inventory = _verify_current_inventory(attested_files)
    _require_inventory_paths(
        current_inventory,
        protected_inputs - {attestation_path},
        label="revalidation inputs",
    )
    _validate_pid_exit_gate(
        attestation=attestation,
        inventory=current_inventory,
        formal_manifest=formal_manifest_path,
        formal_decision=formal_decision_path,
    )

    # Semantic opening starts only after the zero-exit and inventory gate.
    _strict_scan_inventory_json(
        attested_files,
        deferred_paths=(formal_manifest_path, formal_decision_path),
    )
    launch_expectation_object, launch_expectation_raw = _load_strict_json_file(
        launch_expectation_path, label="launch expectation"
    )
    expectation = _validate_launch_expectation(launch_expectation_object)
    expectation_artifact_root = Path(expectation["artifact_root"])
    expectation_durable_root = Path(expectation["durable_attempt_root"])
    _require_fixed_output_parent(
        path=revalidated_output,
        durable_root=expectation_durable_root,
        expected_name=REVALIDATED_FILENAME,
        label="revalidated decision output",
    )
    _require_fixed_output_parent(
        path=receipt_output,
        durable_root=expectation_durable_root,
        expected_name=RECEIPT_FILENAME,
        label="classification receipt output",
    )
    if root != Path(expectation["checkout_root"]):
        raise RevalidationError("revalidation root differs from sealed checkout root")
    if (
        formal_manifest_path != expectation_artifact_root / "formal_manifest.json"
        or formal_decision_path != expectation_artifact_root / "formal_decision.json"
        or expectation_artifact_root
        != expectation_durable_root / "artifacts" / "cohort_causal"
    ):
        raise RevalidationError("formal output paths differ from launch expectation")
    provenance_object, provenance_raw = _load_strict_json_file(
        provenance_path, label="causal provenance"
    )
    provenance = _validate_registered_provenance(provenance_object)

    details_path = _unique_path_for_role(attested_files, "detailed_provenance")
    details_object, _ = _load_strict_json_file(
        details_path, label="detailed causal provenance"
    )
    required_code = _validate_detailed_provenance(
        root=root,
        details=details_object,
        provenance=provenance,
        inventory=current_inventory,
    )
    if assemble_fn is None or evaluate_fn is None or make_grid_fn is None:
        if any(item is not None for item in (assemble_fn, evaluate_fn, make_grid_fn)):
            raise RevalidationError("registered runtime overrides must be supplied together")
        assemble_fn, evaluate_fn, make_grid_fn = _load_registered_runtime(root)
    grid_object, grid_raw = _load_strict_json_file(grid_path, label="formal grid")
    grid = _validate_registered_grid(grid_object, make_grid_fn=make_grid_fn)

    launcher_path = (root / "launch_cohort_causal.sh").resolve()
    expected_launcher = attestation["expected_launcher"]
    expected_bindings = {
        "launch_expectation_path": _path_key(launch_expectation_path),
        "launch_expectation_sha256": _sha256_bytes(launch_expectation_raw),
        "launcher_file_sha256": expectation["launcher_file_sha256"],
        "formal_grid_file_sha256": _sha256_bytes(grid_raw),
        "provenance_file_sha256": _sha256_bytes(provenance_raw),
        "source_commit": expectation["source_commit"],
        "wrapper_cmdline_sha256_at_registration": expectation[
            "wrapper_cmdline_sha256_at_registration"
        ],
    }
    if expected_launcher != expected_bindings:
        raise RevalidationError("completion attestation launch bindings drifted")
    if expectation["formal_grid_file_sha256"] != _sha256_bytes(grid_raw):
        raise RevalidationError("launch expectation formal-grid digest mismatch")
    if expectation["provenance_file_sha256"] != _sha256_bytes(provenance_raw):
        raise RevalidationError("launch expectation provenance digest mismatch")
    if expectation["source_commit"] != provenance["source_commit"]:
        raise RevalidationError("launch expectation/provenance source commit mismatch")
    if expectation["pid_file"] != attestation["pid_exit"]["pid_file_path"]:
        raise RevalidationError("launch expectation/attestation PID path mismatch")
    if expectation["exit_file"] != attestation["pid_exit"]["exit_file_path"]:
        raise RevalidationError("launch expectation/attestation exit path mismatch")
    pid_payload, _ = _read_stable_file(Path(expectation["pid_file"]))
    if int(pid_payload.rstrip(b"\n").decode("ascii"), 10) != expectation["wrapper_pid"]:
        raise RevalidationError("launch expectation/current wrapper PID mismatch")
    if expectation["pid_file_sha256_at_registration"] != _sha256_bytes(pid_payload):
        raise RevalidationError("wrapper PID bytes differ from launch registration")
    if attestation["process_absence"] != {
        "status": "pass",
        "attempt_checkout_path": root.as_posix(),
        "artifact_root_path": expectation_artifact_root.as_posix(),
        "method": "linux_procfs_cmdline_and_cwd",
        "audit_sha256": attestation["process_absence"]["audit_sha256"],
    }:
        raise RevalidationError("process-absence audit paths differ from expectation")
    expected_temporary_roots = sorted(
        [
            expectation_artifact_root.as_posix(),
            (expectation_durable_root / "prep").as_posix(),
        ]
    )
    if attestation["no_live_or_temporary"]["roots"] != expected_temporary_roots:
        raise RevalidationError("temporary-audit roots differ from expectation")
    launcher_raw, _ = _read_stable_file(launcher_path)
    if expectation["launcher_file_sha256"] != _sha256_bytes(launcher_raw):
        raise RevalidationError("launch expectation launcher digest mismatch")

    dataset_manifests: dict[str, dict[str, Any]] = {}
    for role in ("adaptation", "heldout"):
        dataset_manifest_path = (
            _resolve_registered(root, grid["datasets"][role]["path"]).resolve()
            / "manifest.json"
        )
        item, _ = _load_strict_json_file(
            dataset_manifest_path, label=f"{role} dataset manifest"
        )
        if not isinstance(item, dict):
            raise RevalidationError(f"{role} dataset manifest must be an object")
        dataset_manifests[role] = item
    assembler_inputs = _registered_assembler_inputs(
        root=root,
        artifact_root=formal_manifest_path.parent,
        grid=grid,
        dataset_manifests=dataset_manifests,
    )
    _require_inventory_paths(
        current_inventory,
        {
            *assembler_inputs,
            *required_code,
            launcher_path,
            launch_expectation_path,
            grid_path,
            provenance_path,
            preregistration_path,
            statistical_addendum_path,
            formal_manifest_path,
            formal_decision_path,
        },
        label="formal causal inventory",
    )
    _verify_assembler_artifact_aliases(
        root=root,
        artifact_root=formal_manifest_path.parent,
        grid=grid,
        inventory=current_inventory,
    )

    # Second current-state recheck occurs immediately before independent
    # reconstruction, and therefore independently re-hashes every raw input.
    _verify_current_inventory(attested_files)
    rebuilt_manifest = assemble_fn(
        root=root,
        grid=grid,
        provenance=provenance,
        preregistration_path=preregistration_path,
        statistical_addendum_path=statistical_addendum_path,
    )
    rebuilt_manifest_bytes = _compact_file_bytes(rebuilt_manifest)
    original_manifest_bytes, _ = _read_stable_file(formal_manifest_path)
    _load_json_bytes(original_manifest_bytes, label="sealed formal manifest")
    if original_manifest_bytes != rebuilt_manifest_bytes:
        raise RevalidationError("sealed formal manifest differs from independent rebuild")

    report = evaluate_fn(rebuilt_manifest)
    decision, decision_scope = _validate_classification(report)
    rebuilt_decision_bytes = _pretty_report_bytes(report)
    original_decision_bytes, _ = _read_stable_file(formal_decision_path)
    _load_json_bytes(original_decision_bytes, label="sealed formal decision")
    if original_decision_bytes != rebuilt_decision_bytes:
        raise RevalidationError("sealed formal decision differs from independent recomputation")

    receipt = {
        "decision": decision,
        "decision_scope": decision_scope,
        "execution_plan_path": execution_plan_path.as_posix(),
        "execution_plan_sha256": execution_plan_sha256,
        "formal_decision_file_sha256": _sha256_bytes(original_decision_bytes),
        "formal_manifest_file_sha256": _sha256_bytes(original_manifest_bytes),
        "status": "valid",
    }
    if set(receipt) != RECEIPT_KEYS:
        raise AssertionError("redacted receipt schema drift")

    # Third recheck closes the reconstruction/publication window.  Only after
    # it passes may either no-overwrite output become visible.
    _verify_current_inventory(attested_files)
    _publish_pair_no_overwrite(
        [
            (revalidated_output, original_decision_bytes),
            (receipt_output, _pretty_report_bytes(receipt)),
        ]
    )
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path)
    parser.add_argument("--grid", type=Path)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--formal-manifest", type=Path)
    parser.add_argument("--formal-decision", type=Path)
    parser.add_argument("--preregistration", type=Path)
    parser.add_argument("--statistical-addendum", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    receipt = revalidate_terminal(
        root=root,
        execution_plan_path=args.execution_plan,
        attestation_path=args.attestation,
        launch_expectation_path=(
            args.launch_expectation
            if args.launch_expectation is not None
            else root / "CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json"
        ),
        grid_path=(
            args.grid if args.grid is not None else root / "grid_cohort_causal_formal.json"
        ),
        provenance_path=args.provenance,
        formal_manifest_path=(
            args.formal_manifest
            if args.formal_manifest is not None
            else root / "artifacts/cohort_causal/formal_manifest.json"
        ),
        formal_decision_path=(
            args.formal_decision
            if args.formal_decision is not None
            else root / "artifacts/cohort_causal/formal_decision.json"
        ),
        revalidated_output=args.output,
        receipt_output=args.receipt,
        preregistration_path=args.preregistration,
        statistical_addendum_path=args.statistical_addendum,
    )
    print(_pretty_report_bytes(receipt).decode("utf-8"), end="")


if __name__ == "__main__":
    try:
        main()
    except (RevalidationError, FileExistsError) as exc:
        raise SystemExit(f"causal terminal revalidation failed: {exc}") from exc
