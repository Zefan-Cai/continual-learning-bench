#!/usr/bin/env python3
"""Publish an outcome-blind terminal-completion attestation for Cohort causal.

This verifier deliberately does not parse or decode formal manifests, decisions,
tapes, traces, or cell manifests.  Those files are treated as opaque byte strings:
only path safety, stat metadata, length, and SHA-256 are observed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from build_cohort_structured_state_execution_seal import (
    ExecutionSealError,
    load_and_validate_execution_plan_stage,
)


ROOT = Path(__file__).resolve().parent
PROTOCOL = "cohort_causal_terminal_completion_attestation_v1"
SCHEMA_VERSION = 1
MINIMUM_STABILITY_SECONDS = 1.0

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_PID_BYTES_RE = re.compile(rb"[1-9][0-9]*\n?\Z")
_BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)

_EXPECTATION_KEYS = frozenset(
    {
        "artifact_root",
        "attempt_id",
        "boot_id",
        "checkout_root",
        "collector_gpus",
        "created_at_utc",
        "durable_attempt_root",
        "eval_gpus",
        "exit_file",
        "expected_final_inventory",
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
)
_EXPECTED_INVENTORY = {
    "cell_final_traces": 6,
    "cell_manifests": 6,
    "collector_final_traces": 3,
    "collector_manifests": 3,
    "formal_decisions": 1,
    "formal_manifests": 1,
    "sealed_cell_log_receipts": 9,
    "sealed_cell_log_start_receipts": 9,
    "sealed_cell_logs": 9,
    "tapes": 3,
    "total": 50,
}
_PROVENANCE_KEYS = frozenset(
    {
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
)
_DETAIL_KEYS = frozenset(
    {
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
)
_EVALUATION_KEYS = frozenset({"allowlist", "files", "inventory_sha256"})
_EVALUATION_FILE_KEYS = frozenset({"path", "role", "sha256", "size_bytes"})
ATTESTATION_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "completed_at_utc",
        "execution_plan_path",
        "execution_plan_sha256",
        "expected_launcher",
        "registered_counts",
        "pid_exit",
        "process_absence",
        "no_live_or_temporary",
        "stability",
        "causal_pre_attestation_inventory_sha256",
        "snapshots",
    }
)
EXPECTED_LAUNCHER_KEYS = frozenset(
    {
        "launch_expectation_path",
        "launch_expectation_sha256",
        "launcher_file_sha256",
        "formal_grid_file_sha256",
        "provenance_file_sha256",
        "source_commit",
        "wrapper_cmdline_sha256_at_registration",
    }
)
PROCESS_AUDIT_KEYS = frozenset(
    {
        "status",
        "attempt_checkout_path",
        "artifact_root_path",
        "method",
        "audit_sha256",
    }
)
TEMPORARY_AUDIT_KEYS = frozenset(
    {"status", "roots", "forbidden_match_count", "audit_sha256"}
)
SNAPSHOT_KEYS = frozenset(
    {"sequence", "captured_at_utc", "file_count", "inventory_sha256", "files"}
)
FILE_RECORD_KEYS = frozenset(
    {"path", "roles", "device", "inode", "size_bytes", "mtime_ns", "sha256"}
)


class AttestationError(RuntimeError):
    """A fail-closed completion-attestation error."""


def canonical_bytes(value: Any) -> bytes:
    """Return the protocol's unique JSON encoding (without a trailing newline)."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def inventory_sha256(files: list[dict[str, Any]]) -> str:
    """Digest formula shared with terminal revalidation."""

    return canonical_sha256(files)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError("control JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> None:
    raise AttestationError(f"control JSON contains non-finite constant {value}")


def _read_opaque_bytes(
    path: Path, *, permitted_roots: Iterable[Path] | None = None
) -> bytes:
    """Read one regular file by descriptor without decoding or following its leaf."""

    if permitted_roots is not None:
        _assert_no_symlink_components(path, permitted_roots)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AttestationError("opaque input is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
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
        raise AttestationError("file changed while reading")
    linked = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(linked.st_mode) or (
        linked.st_dev,
        linked.st_ino,
        linked.st_size,
        linked.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise AttestationError("file path changed while reading")
    return b"".join(chunks)


def _load_control_json_with_bytes(
    path: Path, *, permitted_roots: Iterable[Path] | None = None
) -> tuple[dict[str, Any], bytes]:
    """Parse only registered control metadata, never formal/result artifacts."""

    try:
        raw = _read_opaque_bytes(path, permitted_roots=permitted_roots)
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError("registered control JSON cannot be loaded") from exc
    if not isinstance(value, dict):
        raise AttestationError("registered control JSON must be an object")
    return value, raw


def _load_control_json(
    path: Path, *, permitted_roots: Iterable[Path] | None = None
) -> dict[str, Any]:
    value, _ = _load_control_json_with_bytes(path, permitted_roots=permitted_roots)
    return value


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AttestationError(f"{field} is not a lowercase SHA-256")
    return value


def _require_size(value: Any, field: str) -> int:
    if not _is_plain_int(value) or value < 0:
        raise AttestationError(f"{field} is not a non-negative integer size")
    return value


def _require_absolute_path(value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise AttestationError(f"{field} must be a nonempty absolute path")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise AttestationError(f"{field} must be a normalized absolute path")
    return path


def _require_exact_keys(value: dict[str, Any], keys: frozenset[str], label: str) -> None:
    if set(value) != keys:
        raise AttestationError(f"{label} exact-key schema differs")


def _require_gpu_list(value: Any, *, count: int, label: str) -> list[int]:
    if (
        not isinstance(value, list)
        or len(value) != count
        or any(not _is_plain_int(item) or item < 0 for item in value)
        or len(set(value)) != len(value)
    ):
        raise AttestationError(f"{label} must contain {count} unique GPU indexes")
    return value


def _load_launch_expectation(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_opaque_bytes(path, permitted_roots=(path.parent,))
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError("launch expectation is not duplicate-free JSON") from exc
    if not isinstance(value, dict):
        raise AttestationError("launch expectation must be an object")
    _require_exact_keys(value, _EXPECTATION_KEYS, "launch expectation")
    if value["protocol"] != "cohort_causal_formal_launch_expectation_v1":
        raise AttestationError("launch expectation protocol differs")
    if value["schema_version"] != 1 or value["launch_mode"] != "formal":
        raise AttestationError("launch expectation version or mode differs")
    if value["attempt_id"] != "attempt-002":
        raise AttestationError("launch expectation attempt ID differs")
    if not isinstance(value["created_at_utc"], str) or not value[
        "created_at_utc"
    ].endswith("Z"):
        raise AttestationError("launch expectation creation time is invalid")
    if not isinstance(value["node_hostname"], str) or not value["node_hostname"]:
        raise AttestationError("launch expectation hostname is invalid")
    if not isinstance(value["boot_id"], str) or _BOOT_ID_RE.fullmatch(
        value["boot_id"]
    ) is None:
        raise AttestationError("launch expectation boot ID is invalid")
    if not isinstance(value["source_commit"], str) or _COMMIT_RE.fullmatch(
        value["source_commit"]
    ) is None:
        raise AttestationError("launch expectation source commit is invalid")
    for key in (
        "formal_grid_file_sha256",
        "launcher_file_sha256",
        "pid_file_sha256_at_registration",
        "provenance_file_sha256",
        "wrapper_cmdline_sha256_at_registration",
    ):
        _require_sha256(value[key], key)
    for key in (
        "artifact_root",
        "checkout_root",
        "durable_attempt_root",
        "exit_file",
        "pid_file",
    ):
        _require_absolute_path(value[key], key)
    if (
        not _is_plain_int(value["wrapper_pid"])
        or value["wrapper_pid"] <= 0
        or not _is_plain_int(value["wrapper_start_ticks"])
        or value["wrapper_start_ticks"] <= 0
        or not _is_plain_int(value["max_used_memory_mib"])
        or value["max_used_memory_mib"] < 0
    ):
        raise AttestationError("launch expectation numeric field is invalid")
    _require_gpu_list(value["collector_gpus"], count=3, label="collector_gpus")
    _require_gpu_list(value["eval_gpus"], count=6, label="eval_gpus")
    inventory = value["expected_final_inventory"]
    if not isinstance(inventory, dict) or inventory != _EXPECTED_INVENTORY:
        raise AttestationError("launch expectation final inventory differs")

    durable_root = Path(value["durable_attempt_root"])
    artifact_root = Path(value["artifact_root"])
    if artifact_root != durable_root / "artifacts" / "cohort_causal":
        raise AttestationError("launch expectation artifact root is inconsistent")
    if Path(value["pid_file"]) != durable_root / "prep" / "causal_formal.pid":
        raise AttestationError("launch expectation PID path is inconsistent")
    if Path(value["exit_file"]) != durable_root / "prep" / "causal_formal.exit":
        raise AttestationError("launch expectation exit path is inconsistent")
    if durable_root.name != value["attempt_id"]:
        raise AttestationError("launch expectation durable attempt path differs")
    return value, payload


def _safe_registered_relative(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise AttestationError(f"{label} must be a nonempty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise AttestationError(f"{label} is not a normalized registered path")
    return path


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _absolute_without_following(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _assert_no_symlink_components(path: Path, roots: Iterable[Path]) -> None:
    absolute = _absolute_without_following(path)
    selected: Path | None = None
    for root in roots:
        root_abs = _absolute_without_following(root)
        if _is_relative_to(absolute, root_abs):
            if selected is None or len(root_abs.parts) > len(selected.parts):
                selected = root_abs
    if selected is None:
        raise AttestationError("registered path escapes all permitted roots")
    current = selected
    try:
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise AttestationError("permitted root may not be a symlink")
        for part in absolute.relative_to(selected).parts:
            current = current / part
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise AttestationError("registered path has a symlink component")
    except FileNotFoundError as exc:
        raise AttestationError("registered path is missing") from exc


class _InventoryBuilder:
    def __init__(self, *, permitted_roots: Iterable[Path]) -> None:
        self.permitted_roots = tuple(
            _absolute_without_following(path) for path in permitted_roots
        )
        self._entries: dict[Path, dict[str, Any]] = {}

    def add(
        self,
        path: Path,
        *,
        role: str,
        expected_sha256: str | None = None,
        expected_size: int | None = None,
    ) -> None:
        absolute = _absolute_without_following(path)
        _assert_no_symlink_components(absolute, self.permitted_roots)
        entry = self._entries.setdefault(
            absolute,
            {
                "roles": set(),
                "expected_sha256": None,
                "expected_size": None,
            },
        )
        if role in entry["roles"]:
            raise AttestationError("registered inventory repeats a path in one role")
        entry["roles"].add(role)
        if expected_sha256 is not None:
            _require_sha256(expected_sha256, f"{role}.sha256")
            existing = entry["expected_sha256"]
            if existing is not None and existing != expected_sha256:
                raise AttestationError("registered SHA-256 constraints conflict")
            entry["expected_sha256"] = expected_sha256
        if expected_size is not None:
            if not _is_plain_int(expected_size) or expected_size < 0:
                raise AttestationError("registered size constraint is invalid")
            existing_size = entry["expected_size"]
            if existing_size is not None and existing_size != expected_size:
                raise AttestationError("registered size constraints conflict")
            entry["expected_size"] = expected_size

    @property
    def entries(self) -> dict[Path, dict[str, Any]]:
        return self._entries


def _artifact_from_grid(path: Path, *, artifact_root: Path) -> Path:
    prefix = Path("artifacts/cohort_causal")
    if not _is_relative_to(path, prefix):
        raise AttestationError("formal grid artifact path has the wrong prefix")
    return artifact_root / path.relative_to(prefix)


def _add_formal_inventory(
    *,
    root: Path,
    artifact_root: Path,
    grid: dict[str, Any],
    builder: _InventoryBuilder,
) -> dict[str, int]:
    if grid.get("kind") != "formal":
        raise AttestationError("causal grid is not the formal grid")
    collectors = grid.get("collectors")
    cells = grid.get("evaluation_cells")
    if not isinstance(collectors, list) or len(collectors) != 3:
        raise AttestationError("formal grid must register exactly three collectors")
    if not isinstance(cells, list) or len(cells) != 6:
        raise AttestationError("formal grid must register exactly six cells")
    cfg_ids: set[str] = set()
    registered_paths: set[Path] = set()

    def claim_cfg(row: Any, label: str) -> str:
        if not isinstance(row, dict):
            raise AttestationError(f"{label} grid row must be an object")
        cfg_id = row.get("cfg_id")
        if not isinstance(cfg_id, str) or not cfg_id or cfg_id in cfg_ids:
            raise AttestationError("formal grid cfg_id is missing or duplicated")
        if "/" in cfg_id or "\\" in cfg_id or cfg_id in {".", ".."}:
            raise AttestationError("formal grid cfg_id is path-unsafe")
        cfg_ids.add(cfg_id)
        return cfg_id

    def add_unique(path: Path, role: str) -> None:
        absolute = _absolute_without_following(path)
        if absolute in registered_paths:
            raise AttestationError("formal grid registers a duplicate final path")
        registered_paths.add(absolute)
        builder.add(absolute, role=role)

    def add_sealed_log(cfg_id: str) -> None:
        sealed_root = artifact_root / "sealed_logs" / "formal"
        add_unique(
            sealed_root / f"{cfg_id}.stdout_stderr.age", "sealed_cell_log"
        )
        add_unique(
            sealed_root / f"{cfg_id}.start.json",
            "sealed_cell_log_start_receipt",
        )
        add_unique(
            sealed_root / f"{cfg_id}.receipt.json", "sealed_cell_log_receipt"
        )

    for row in collectors:
        cfg_id = claim_cfg(row, "collector")
        tape_relative = _safe_registered_relative(row.get("tape_path"), "tape_path")
        add_unique(
            _artifact_from_grid(tape_relative, artifact_root=artifact_root),
            "formal_tape",
        )
        add_unique(
            artifact_root / "collectors" / f"{cfg_id}.manifest.json",
            "collector_manifest",
        )
        add_unique(
            artifact_root / "traces" / f"{cfg_id}.trace.json",
            "collector_final_trace",
        )
        add_sealed_log(cfg_id)
    for row in cells:
        cfg_id = claim_cfg(row, "cell")
        manifest_relative = _safe_registered_relative(
            row.get("cell_manifest_path"), "cell_manifest_path"
        )
        add_unique(
            _artifact_from_grid(manifest_relative, artifact_root=artifact_root),
            "cell_manifest",
        )
        add_unique(
            artifact_root / "traces" / f"{cfg_id}.trace.json",
            "cell_final_trace",
        )
        add_sealed_log(cfg_id)

    add_unique(artifact_root / "formal_manifest.json", "formal_manifest")
    add_unique(artifact_root / "formal_decision.json", "formal_decision")
    return dict(_EXPECTED_INVENTORY)


def _add_corpus_inventory(
    *, root: Path, grid: dict[str, Any], builder: _InventoryBuilder
) -> None:
    datasets = grid.get("datasets")
    if not isinstance(datasets, dict) or set(datasets) != {"adaptation", "heldout"}:
        raise AttestationError("formal grid dataset schema differs")
    for role in ("adaptation", "heldout"):
        grid_dataset = datasets[role]
        if not isinstance(grid_dataset, dict):
            raise AttestationError("formal grid dataset entry must be an object")
        dataset_relative = _safe_registered_relative(
            grid_dataset.get("path"), f"{role}.dataset_path"
        )
        dataset_root = root / dataset_relative
        manifest_path = dataset_root / "manifest.json"
        manifest, manifest_bytes = _load_control_json_with_bytes(
            manifest_path, permitted_roots=builder.permitted_roots
        )
        builder.add(
            manifest_path,
            role=f"{role}_corpus_manifest",
            expected_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            expected_size=len(manifest_bytes),
        )
        if manifest.get("corpus_sha256") != grid_dataset.get("corpus_sha256"):
            raise AttestationError("corpus digest differs between grid and manifest")
        if manifest.get("schedule_sha256") != grid_dataset.get("schedule_sha256"):
            raise AttestationError("schedule digest differs between grid and manifest")
        schedule_id = manifest.get("schedule_id")
        if not isinstance(schedule_id, str) or not schedule_id:
            raise AttestationError("corpus manifest schedule ID is invalid")
        schedule_relative = _safe_registered_relative(
            f"src/tasks/cohort_studies/schedules/{schedule_id}.json",
            f"{role}.schedule_path",
        )
        builder.add(
            root / schedule_relative,
            role=f"{role}_schedule",
            expected_sha256=_require_sha256(
                manifest.get("schedule_sha256"), f"{role}.schedule_sha256"
            ),
        )
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise AttestationError("corpus manifest artifact inventory is empty")
        seen: set[Path] = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise AttestationError("corpus artifact record is not an object")
            relative = _safe_registered_relative(
                artifact.get("path"), f"{role}.artifact_path"
            )
            if relative in seen or relative == Path("manifest.json"):
                raise AttestationError("corpus artifact path is duplicated or reserved")
            seen.add(relative)
            builder.add(
                dataset_root / relative,
                role=f"{role}_corpus_artifact",
                expected_sha256=_require_sha256(
                artifact.get("sha256"), f"{role}.artifact_sha256"
                ),
                expected_size=_require_size(
                    artifact.get("size_bytes"), f"{role}.artifact_size_bytes"
                ),
            )
        actual_files: set[Path] = set()
        for path in dataset_root.rglob("*"):
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                raise AttestationError("corpus inventory contains a symlink")
            if stat.S_ISREG(mode):
                actual_files.add(path.relative_to(dataset_root))
            elif not stat.S_ISDIR(mode):
                raise AttestationError("corpus inventory contains a special file")
        expected_files = seen | {Path("manifest.json")}
        if actual_files != expected_files:
            raise AttestationError("corpus directory differs from its exact manifest")


def _add_provenance_inventory(
    *,
    root: Path,
    provenance_path: Path,
    details_path: Path,
    expectation: dict[str, Any],
    builder: _InventoryBuilder,
) -> None:
    provenance, provenance_bytes = _load_control_json_with_bytes(
        provenance_path, permitted_roots=builder.permitted_roots
    )
    details, details_bytes = _load_control_json_with_bytes(
        details_path, permitted_roots=builder.permitted_roots
    )
    _require_exact_keys(provenance, _PROVENANCE_KEYS, "causal provenance")
    _require_exact_keys(details, _DETAIL_KEYS, "causal provenance details")
    if details.get("provenance") != provenance:
        raise AttestationError("provenance sidecar does not bind compact provenance")
    if provenance.get("source_commit") != expectation["source_commit"]:
        raise AttestationError("provenance source commit differs from expectation")
    provenance_sha256 = hashlib.sha256(provenance_bytes).hexdigest()
    if provenance_sha256 != expectation["provenance_file_sha256"]:
        raise AttestationError("provenance file bytes differ from expectation")
    if (
        details.get("canonicalization")
        != "UTF-8 canonical JSON; sorted keys; compact separators"
        or details.get("hash_algorithm") != "sha256"
        or details.get("kind") != "cohort_causal_provenance_audit"
        or details.get("schema_version") != 1
    ):
        raise AttestationError("provenance sidecar header differs")
    git_record = details.get("git")
    if not isinstance(git_record, dict) or set(git_record) != {
        "source_commit",
        "tracked_checkout_clean",
    }:
        raise AttestationError("provenance git record differs")
    if (
        git_record["source_commit"] != expectation["source_commit"]
        or git_record["tracked_checkout_clean"] is not True
    ):
        raise AttestationError("provenance git binding differs")
    environment = details.get("environment")
    if not isinstance(environment, dict) or set(environment) != {"payload", "sha256"}:
        raise AttestationError("provenance environment record differs")
    if (
        canonical_sha256(environment["payload"]) != environment["sha256"]
        or environment["sha256"] != provenance["environment_lock_sha256"]
    ):
        raise AttestationError("provenance environment digest differs")
    for role in ("model", "tokenizer"):
        record = details.get(role)
        if not isinstance(record, dict) or set(record) != {
            "path",
            "files",
            "inventory_sha256",
        }:
            raise AttestationError(f"provenance {role} record differs")
        if (
            record["path"] != provenance["model_path"]
            or not isinstance(record["files"], list)
            or canonical_sha256(record["files"]) != record["inventory_sha256"]
            or record["inventory_sha256"] != provenance[f"{role}_sha256"]
        ):
            raise AttestationError(f"provenance {role} digest differs")

    evaluation = details.get("evaluation_code")
    if not isinstance(evaluation, dict):
        raise AttestationError("provenance evaluation-code inventory is missing")
    _require_exact_keys(evaluation, _EVALUATION_KEYS, "evaluation-code inventory")
    allowlist = evaluation.get("allowlist")
    files = evaluation.get("files")
    if (
        not isinstance(allowlist, list)
        or not allowlist
        or any(not isinstance(item, str) for item in allowlist)
        or len(set(allowlist)) != len(allowlist)
        or allowlist != sorted(allowlist)
        or not isinstance(files, list)
        or len(files) != len(allowlist)
    ):
        raise AttestationError("evaluation-code allowlist is malformed")
    if canonical_sha256(files) != evaluation.get("inventory_sha256"):
        raise AttestationError("evaluation-code inventory digest differs")
    if provenance.get("evaluation_code_sha256") != evaluation.get(
        "inventory_sha256"
    ):
        raise AttestationError("compact provenance evaluation digest differs")
    file_paths: list[str] = []
    for record in files:
        if not isinstance(record, dict):
            raise AttestationError("evaluation-code record must be an object")
        _require_exact_keys(record, _EVALUATION_FILE_KEYS, "evaluation-code record")
        if record.get("role") != "evaluation_code":
            raise AttestationError("evaluation-code record role differs")
        relative = _safe_registered_relative(record.get("path"), "evaluation_code.path")
        file_paths.append(relative.as_posix())
        builder.add(
            root / relative,
            role="evaluation_code",
            expected_sha256=_require_sha256(
                record.get("sha256"), "evaluation_code.sha256"
            ),
            expected_size=_require_size(
                record.get("size_bytes"), "evaluation_code.size_bytes"
            ),
        )
    if file_paths != allowlist:
        raise AttestationError("evaluation-code records differ from exact allowlist")
    addendum = details.get("statistical_addendum")
    if not isinstance(addendum, dict):
        raise AttestationError("statistical addendum record is missing")
    addendum_relative = _safe_registered_relative(
        addendum.get("path"), "statistical_addendum.path"
    )
    addendum_sha256 = _require_sha256(
        addendum.get("sha256"), "statistical_addendum.sha256"
    )
    if provenance.get("statistical_addendum_sha256") != addendum_sha256:
        raise AttestationError("statistical addendum digest differs")
    builder.add(
        root / addendum_relative,
        role="statistical_addendum",
        expected_sha256=addendum_sha256,
        expected_size=_require_size(
            addendum.get("size_bytes"), "statistical_addendum.size_bytes"
        ),
    )
    builder.add(
        provenance_path,
        role="compact_provenance",
        expected_sha256=provenance_sha256,
        expected_size=len(provenance_bytes),
    )
    builder.add(
        details_path,
        role="detailed_provenance",
        expected_sha256=hashlib.sha256(details_bytes).hexdigest(),
        expected_size=len(details_bytes),
    )


def _hash_file_record(
    path: Path, constraints: dict[str, Any], *, permitted_roots: Iterable[Path]
) -> dict[str, Any]:
    _assert_no_symlink_components(path, permitted_roots)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AttestationError("registered file cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AttestationError("registered inventory entry is not a regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AttestationError("registered file cannot be hashed") from exc
    finally:
        os.close(descriptor)
    try:
        linked = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise AttestationError("registered file path cannot be stated") from exc
    if not stat.S_ISREG(linked.st_mode):
        raise AttestationError("registered file path is not a regular file")
    if (
        linked.st_dev,
        linked.st_ino,
        linked.st_size,
        linked.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise AttestationError("registered file path changed while hashing")
    metadata = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if metadata != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ):
        raise AttestationError("registered file changed while hashing")
    if after.st_size <= 0:
        raise AttestationError("registered final inventory contains an empty file")
    hexdigest = digest.hexdigest()
    if constraints["expected_sha256"] is not None and hexdigest != constraints[
        "expected_sha256"
    ]:
        raise AttestationError("registered file SHA-256 differs")
    if constraints["expected_size"] is not None and after.st_size != constraints[
        "expected_size"
    ]:
        raise AttestationError("registered file size differs")
    return {
        "path": path.as_posix(),
        "roles": sorted(constraints["roles"]),
        "device": after.st_dev,
        "inode": after.st_ino,
        "size_bytes": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "sha256": hexdigest,
    }


def _take_snapshot(
    builder: _InventoryBuilder,
    *,
    sequence: int,
    now_fn: Callable[[], str],
) -> dict[str, Any]:
    records = [
        _hash_file_record(
            path, builder.entries[path], permitted_roots=builder.permitted_roots
        )
        for path in sorted(builder.entries, key=lambda item: item.as_posix())
    ]
    inode_owners: dict[tuple[int, int], str] = {}
    for record in records:
        key = (record["device"], record["inode"])
        if key in inode_owners and inode_owners[key] != record["path"]:
            raise AttestationError("two registered paths alias one inode")
        inode_owners[key] = record["path"]
    return {
        "sequence": sequence,
        "captured_at_utc": now_fn(),
        "file_count": len(records),
        "inventory_sha256": inventory_sha256(records),
        "files": records,
    }


def _record_by_role(snapshot: dict[str, Any], role: str) -> dict[str, Any]:
    matches = [record for record in snapshot["files"] if role in record["roles"]]
    if len(matches) != 1:
        raise AttestationError(f"snapshot must contain exactly one {role}")
    return matches[0]


def _validate_pid_exit(
    *,
    expectation: dict[str, Any],
    snapshot: dict[str, Any],
    pid_is_live_fn: Callable[[int], bool],
) -> tuple[int, dict[str, Any]]:
    pid_record = _record_by_role(snapshot, "wrapper_pid_file")
    exit_record = _record_by_role(snapshot, "wrapper_exit_file")
    manifest_record = _record_by_role(snapshot, "formal_manifest")
    decision_record = _record_by_role(snapshot, "formal_decision")
    durable_root = Path(expectation["durable_attempt_root"])
    pid_bytes = _read_opaque_bytes(
        Path(pid_record["path"]), permitted_roots=(durable_root,)
    )
    exit_bytes = _read_opaque_bytes(
        Path(exit_record["path"]), permitted_roots=(durable_root,)
    )
    if _PID_BYTES_RE.fullmatch(pid_bytes) is None:
        raise AttestationError("wrapper PID file is not canonical ASCII")
    try:
        pid = int(pid_bytes.rstrip(b"\n").decode("ascii"), 10)
        exit_text = exit_bytes.decode("ascii")
    except (UnicodeDecodeError, ValueError) as exc:
        raise AttestationError("wrapper PID/exit file is not ASCII") from exc
    if pid != expectation["wrapper_pid"]:
        raise AttestationError("wrapper PID differs from launch expectation")
    if pid_record["sha256"] != expectation["pid_file_sha256_at_registration"]:
        raise AttestationError("wrapper PID bytes changed after registration")
    if exit_text.strip(" \t\r\n\v\f") != "0":
        raise AttestationError("wrapper exit file is not exact zero after strip")
    if exit_record["mtime_ns"] <= max(
        manifest_record["mtime_ns"], decision_record["mtime_ns"]
    ):
        raise AttestationError("wrapper exit mtime is not later than formal outputs")
    if pid_is_live_fn(pid):
        raise AttestationError("registered wrapper PID is still live")
    return pid, {
        "pid_file_path": pid_record["path"],
        "pid_file_sha256": pid_record["sha256"],
        "pid_file_size_bytes": pid_record["size_bytes"],
        "pid_file_mtime_ns": pid_record["mtime_ns"],
        "exit_file_path": exit_record["path"],
        "exit_file_sha256": exit_record["sha256"],
        "exit_file_size_bytes": exit_record["size_bytes"],
        "exit_file_mtime_ns": exit_record["mtime_ns"],
        "pid_ascii_status": "pass",
        "pid_liveness_status": "dead",
        "exit_zero_status": "pass",
        "exit_after_outputs_status": "pass",
    }


def _pid_is_live(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _path_contains(candidate: Path, root: Path) -> bool:
    candidate_abs = _absolute_without_following(candidate)
    root_abs = _absolute_without_following(root)
    return candidate_abs == root_abs or _is_relative_to(candidate_abs, root_abs)


def _scan_process_references(
    *, attempt_checkout: Path, artifact_root: Path
) -> dict[str, Any]:
    """Fail closed unless Linux procfs proves no other process references roots."""

    proc_root = Path("/proc")
    if not proc_root.is_dir():
        raise AttestationError("Linux procfs is required for process-absence audit")
    self_pid = os.getpid()
    unreadable = 0
    references: list[tuple[int, str]] = []
    targets = (
        _absolute_without_following(attempt_checkout),
        _absolute_without_following(artifact_root),
    )
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == self_pid:
            continue
        try:
            cmdline_bytes = (entry / "cmdline").read_bytes()
            cwd = Path(os.readlink(entry / "cwd"))
        except FileNotFoundError:
            continue
        except (PermissionError, OSError):
            unreadable += 1
            continue
        cmdline = cmdline_bytes.replace(b"\0", b" ").decode(
            "utf-8", errors="surrogateescape"
        )
        for target in targets:
            if target.as_posix() in cmdline:
                references.append((pid, "cmdline"))
            if _path_contains(cwd, target):
                references.append((pid, "cwd"))
    if unreadable:
        raise AttestationError("process-absence audit could not inspect every process")
    if references:
        raise AttestationError("a live process still references the attempt")
    payload = {
        "status": "pass",
        "attempt_checkout_path": targets[0].as_posix(),
        "artifact_root_path": targets[1].as_posix(),
        "method": "linux_procfs_cmdline_and_cwd",
    }
    return {**payload, "audit_sha256": canonical_sha256(payload)}


def _scan_live_or_temporary(*, roots: Iterable[Path]) -> dict[str, Any]:
    normalized = sorted(
        {_absolute_without_following(path).as_posix() for path in roots}
    )
    forbidden: list[str] = []
    for root_text in normalized:
        root = Path(root_text)
        if not root.is_dir():
            raise AttestationError("temporary-audit root is missing")
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(directory)
            for name in [*dirnames, *filenames]:
                path = base / name
                try:
                    mode = os.lstat(path).st_mode
                except FileNotFoundError:
                    forbidden.append(path.as_posix())
                    continue
                if stat.S_ISLNK(mode):
                    forbidden.append(path.as_posix())
                    continue
                if (
                    name.endswith(".live.json")
                    or (name.startswith(".") and ".tmp." in name)
                    or name.endswith(".partial")
                    or name.endswith(".part")
                ):
                    forbidden.append(path.as_posix())
    if forbidden:
        raise AttestationError("live, temporary, partial, or symlink artifact remains")
    payload = {
        "status": "pass",
        "roots": normalized,
        "forbidden_match_count": 0,
    }
    return {**payload, "audit_sha256": canonical_sha256(payload)}


def _validate_process_audit(
    value: dict[str, Any], *, attempt_checkout: Path, artifact_root: Path
) -> None:
    if not isinstance(value, dict) or set(value) != PROCESS_AUDIT_KEYS:
        raise AttestationError("process-absence audit schema differs")
    payload = {key: value[key] for key in value if key != "audit_sha256"}
    if (
        value["status"] != "pass"
        or value["attempt_checkout_path"] != attempt_checkout.as_posix()
        or value["artifact_root_path"] != artifact_root.as_posix()
        or not isinstance(value["method"], str)
        or not value["method"]
        or value["audit_sha256"] != canonical_sha256(payload)
    ):
        raise AttestationError("process-absence audit did not validate")


def _validate_temporary_audit(value: dict[str, Any], *, roots: Iterable[Path]) -> None:
    if not isinstance(value, dict) or set(value) != TEMPORARY_AUDIT_KEYS:
        raise AttestationError("temporary-artifact audit schema differs")
    expected_roots = sorted(
        {_absolute_without_following(path).as_posix() for path in roots}
    )
    payload = {key: value[key] for key in value if key != "audit_sha256"}
    if (
        value["status"] != "pass"
        or value["roots"] != expected_roots
        or value["forbidden_match_count"] != 0
        or value["audit_sha256"] != canonical_sha256(payload)
    ):
        raise AttestationError("temporary-artifact audit did not validate")


def _current_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError as exc:
        raise AttestationError("current boot ID cannot be read") from exc


def _current_source_commit(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AttestationError("attempt checkout source commit cannot be read") from exc
    return completed.stdout.strip()


def _atomic_publish_no_overwrite(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        raise FileExistsError("refusing to overwrite completion attestation")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise FileExistsError(
                "refusing to overwrite completion attestation"
            ) from exc
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        temporary.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def build_and_publish_attestation(
    *,
    root: Path,
    execution_plan_path: Path,
    launch_expectation_path: Path,
    provenance_path: Path,
    provenance_details_path: Path,
    output: Path,
    stability_seconds: float = MINIMUM_STABILITY_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
    now_fn: Callable[[], str] = _utc_now,
    pid_is_live_fn: Callable[[int], bool] = _pid_is_live,
    process_audit_fn: Callable[..., dict[str, Any]] = _scan_process_references,
    temporary_audit_fn: Callable[..., dict[str, Any]] = _scan_live_or_temporary,
    boot_id_fn: Callable[[], str] = _current_boot_id,
    hostname_fn: Callable[[], str] = socket.gethostname,
    source_commit_fn: Callable[[Path], str] = _current_source_commit,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
) -> dict[str, Any]:
    """Verify terminal completion and atomically publish its attestation."""

    if stability_seconds < MINIMUM_STABILITY_SECONDS:
        raise AttestationError("stability interval must be at least one second")
    root = _absolute_without_following(root)
    execution_plan_path = _absolute_without_following(execution_plan_path)
    launch_expectation_path = _absolute_without_following(launch_expectation_path)
    provenance_path = _absolute_without_following(provenance_path)
    provenance_details_path = _absolute_without_following(provenance_details_path)
    output = _absolute_without_following(output)
    if os.path.lexists(output):
        raise FileExistsError("refusing to overwrite completion attestation")

    try:
        _, execution_plan_bytes = load_and_validate_execution_plan_stage(
            execution_plan_path=execution_plan_path,
            stage="attester",
            expected_inputs={
                "execution_plan": execution_plan_path,
                "root": root,
                "launch_expectation": launch_expectation_path,
                "provenance": provenance_path,
                "provenance_details": provenance_details_path,
            },
            expected_outputs={"attestation": output},
            expected_parameters={"stability_seconds": str(stability_seconds)},
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    except ExecutionSealError as exc:
        raise AttestationError(f"terminal verifier execution plan is invalid: {exc}") from exc
    execution_plan_sha256 = hashlib.sha256(execution_plan_bytes).hexdigest()

    expectation, expectation_bytes = _load_launch_expectation(
        launch_expectation_path
    )
    checkout_root = Path(expectation["checkout_root"])
    durable_root = Path(expectation["durable_attempt_root"])
    artifact_root = Path(expectation["artifact_root"])
    pid_path = Path(expectation["pid_file"])
    exit_path = Path(expectation["exit_file"])
    if root != checkout_root:
        raise AttestationError("--root differs from sealed checkout root")
    if not _is_relative_to(output, durable_root):
        raise AttestationError("attestation output must stay inside durable attempt root")
    if output in {pid_path, exit_path, launch_expectation_path}:
        raise AttestationError("attestation output aliases a registered input")
    if hostname_fn() != expectation["node_hostname"]:
        raise AttestationError("current hostname differs from launch expectation")
    if boot_id_fn() != expectation["boot_id"]:
        raise AttestationError("current boot ID differs from launch expectation")
    if source_commit_fn(root) != expectation["source_commit"]:
        raise AttestationError("attempt checkout source commit differs")

    grid_path = root / "grid_cohort_causal_formal.json"
    launcher_path = root / "launch_cohort_causal.sh"
    grid, grid_bytes = _load_control_json_with_bytes(
        grid_path, permitted_roots=(checkout_root,)
    )
    if hashlib.sha256(grid_bytes).hexdigest() != expectation["formal_grid_file_sha256"]:
        raise AttestationError("formal grid file differs from launch expectation")
    launcher_bytes = _read_opaque_bytes(
        launcher_path, permitted_roots=(checkout_root,)
    )
    if hashlib.sha256(launcher_bytes).hexdigest() != expectation["launcher_file_sha256"]:
        raise AttestationError("launcher source differs from launch expectation")

    permitted_roots = (checkout_root, durable_root, launch_expectation_path.parent)
    builder = _InventoryBuilder(permitted_roots=permitted_roots)
    builder.add(
        launch_expectation_path,
        role="launch_expectation",
        expected_sha256=hashlib.sha256(expectation_bytes).hexdigest(),
        expected_size=len(expectation_bytes),
    )
    builder.add(
        grid_path,
        role="formal_grid",
        expected_sha256=expectation["formal_grid_file_sha256"],
    )
    builder.add(
        launcher_path,
        role="launcher_source",
        expected_sha256=expectation["launcher_file_sha256"],
    )
    builder.add(pid_path, role="wrapper_pid_file")
    builder.add(exit_path, role="wrapper_exit_file")
    builder.add(artifact_root / "smoke_gate.json", role="causal_smoke_gate")
    builder.add(root / "COHORT_QONLY_CAUSAL_PREREG.md", role="causal_prereg")

    _add_provenance_inventory(
        root=root,
        provenance_path=provenance_path,
        details_path=provenance_details_path,
        expectation=expectation,
        builder=builder,
    )
    _add_corpus_inventory(root=root, grid=grid, builder=builder)
    counts = _add_formal_inventory(
        root=root,
        artifact_root=artifact_root,
        grid=grid,
        builder=builder,
    )
    if counts != expectation["expected_final_inventory"]:
        raise AttestationError("derived formal inventory differs from expectation")
    if output in builder.entries:
        raise AttestationError("completion attestation is recursively inventoried")

    first_process_audit = process_audit_fn(
        attempt_checkout=checkout_root, artifact_root=artifact_root
    )
    first_temporary_audit = temporary_audit_fn(
        roots=(artifact_root, durable_root / "prep")
    )
    _validate_process_audit(
        first_process_audit,
        attempt_checkout=checkout_root,
        artifact_root=artifact_root,
    )
    _validate_temporary_audit(
        first_temporary_audit, roots=(artifact_root, durable_root / "prep")
    )

    snapshot_1 = _take_snapshot(builder, sequence=1, now_fn=now_fn)
    pid, pid_exit = _validate_pid_exit(
        expectation=expectation,
        snapshot=snapshot_1,
        pid_is_live_fn=pid_is_live_fn,
    )
    start = monotonic_fn()
    sleep_fn(stability_seconds)
    observed_interval = monotonic_fn() - start
    if observed_interval < stability_seconds:
        raise AttestationError("stable-snapshot interval was shorter than requested")
    snapshot_2 = _take_snapshot(builder, sequence=2, now_fn=now_fn)
    if snapshot_1["files"] != snapshot_2["files"]:
        raise AttestationError("registered inventory changed between snapshots")
    if snapshot_1["inventory_sha256"] != snapshot_2["inventory_sha256"]:
        raise AttestationError("registered inventory digest changed between snapshots")

    if pid_is_live_fn(pid):
        raise AttestationError("registered wrapper PID became live")
    second_process_audit = process_audit_fn(
        attempt_checkout=checkout_root, artifact_root=artifact_root
    )
    second_temporary_audit = temporary_audit_fn(
        roots=(artifact_root, durable_root / "prep")
    )
    _validate_process_audit(
        second_process_audit,
        attempt_checkout=checkout_root,
        artifact_root=artifact_root,
    )
    _validate_temporary_audit(
        second_temporary_audit, roots=(artifact_root, durable_root / "prep")
    )
    if first_process_audit != second_process_audit:
        raise AttestationError("process-absence audit changed across snapshots")
    if first_temporary_audit != second_temporary_audit:
        raise AttestationError("temporary-artifact audit changed across snapshots")
    # Re-read the two small completion files and bind them to snapshot 2.  This
    # never opens any efficacy-bearing formal artifact semantically.
    latest_pid_sha = hashlib.sha256(
        _read_opaque_bytes(pid_path, permitted_roots=(durable_root,))
    ).hexdigest()
    latest_exit_sha = hashlib.sha256(
        _read_opaque_bytes(exit_path, permitted_roots=(durable_root,))
    ).hexdigest()
    if latest_pid_sha != pid_exit["pid_file_sha256"] or latest_exit_sha != pid_exit[
        "exit_file_sha256"
    ]:
        raise AttestationError("wrapper PID/exit bytes drifted after snapshot")

    expectation_sha256 = hashlib.sha256(expectation_bytes).hexdigest()
    expected_launcher = {
        "launch_expectation_path": launch_expectation_path.as_posix(),
        "launch_expectation_sha256": expectation_sha256,
        "launcher_file_sha256": expectation["launcher_file_sha256"],
        "formal_grid_file_sha256": expectation["formal_grid_file_sha256"],
        "provenance_file_sha256": expectation["provenance_file_sha256"],
        "source_commit": expectation["source_commit"],
        "wrapper_cmdline_sha256_at_registration": expectation[
            "wrapper_cmdline_sha256_at_registration"
        ],
    }
    attestation = {
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "completed_at_utc": now_fn(),
        "execution_plan_path": execution_plan_path.as_posix(),
        "execution_plan_sha256": execution_plan_sha256,
        "expected_launcher": expected_launcher,
        "registered_counts": counts,
        "pid_exit": pid_exit,
        "process_absence": first_process_audit,
        "no_live_or_temporary": first_temporary_audit,
        "stability": {
            "minimum_interval_seconds": stability_seconds,
            "observed_interval_seconds": observed_interval,
            "snapshots_identical": True,
        },
        "causal_pre_attestation_inventory_sha256": snapshot_1[
            "inventory_sha256"
        ],
        "snapshots": [snapshot_1, snapshot_2],
    }
    payload = canonical_bytes(attestation)
    _assert_no_symlink_components(output.parent, (durable_root,))
    _atomic_publish_no_overwrite(output, payload)
    return {
        "status": "complete",
        "path": output.as_posix(),
        "attestation_sha256": hashlib.sha256(payload).hexdigest(),
        "causal_pre_attestation_inventory_sha256": attestation[
            "causal_pre_attestation_inventory_sha256"
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--provenance-details", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--stability-seconds", type=float, default=MINIMUM_STABILITY_SECONDS
    )
    args = parser.parse_args()
    try:
        result = build_and_publish_attestation(
            root=args.root,
            execution_plan_path=args.execution_plan,
            launch_expectation_path=args.launch_expectation,
            provenance_path=args.provenance,
            provenance_details_path=args.provenance_details,
            output=args.output,
            stability_seconds=args.stability_seconds,
        )
    except (AttestationError, FileExistsError, OSError, ValueError):
        print(canonical_bytes({"status": "invalid"}).decode("utf-8"), file=sys.stderr)
        raise SystemExit(1)
    print(canonical_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
