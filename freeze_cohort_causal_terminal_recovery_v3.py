#!/usr/bin/env python3
"""Freeze the outcome-blind V2 failure closure and V3 completion fence.

The recovery is deliberately limited to the observed integer-second timestamp
incident.  Formal manifest and decision bytes are always opaque: this module
hashes and stats them, but never decodes them as JSON or text.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import attest_cohort_causal_completion as v1
import attest_cohort_causal_completion_v2 as attester_v2
import build_cohort_structured_state_execution_seal_v2 as seal_v2


FAILURE_CLOSURE_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V2_FAILURE_CLOSURE_V1.json"
COMPLETION_FENCE_FILENAME = "CAUSAL_TERMINAL_VERIFIER_COMPLETION_FENCE_V3.json"
FAILURE_CLOSURE_PROTOCOL = "cohort_causal_terminal_verifier_v2_failure_closure_v1"
FAILURE_CLOSURE_SCHEMA_VERSION = 1
FAILURE_CLOSURE_STATUS = "closed_equal_second_false_negative"
COMPLETION_FENCE_PROTOCOL = "cohort_causal_terminal_verifier_completion_fence_v3"
COMPLETION_FENCE_SCHEMA_VERSION = 3
COMPLETION_FENCE_STATUS = "frozen_terminal_quiescence"
MINIMUM_STABILITY_SECONDS = 1.0
NANOSECONDS_PER_SECOND = 1_000_000_000
CANONICAL_ZERO_EXIT = b"0\n"

INCIDENT_CLASSIFICATION = "v2_equal_second_strict_mtime_false_negative"
MTIME_RELATION = "formal_manifest_before_formal_decision_equal_wrapper_exit"
COMPLETION_METHOD = "post-wrapper-death two-snapshot fence"
PUBLICATION_MODE = "single_no_overwrite_exact_path"

DOWNSTREAM_FILENAMES = (
    "causal_trigger_completion_attestation.json",
    "causal_formal.revalidated.json",
    "causal_formal.revalidation_receipt.json",
    "cohort_closed_loop_structured_state.execution_seal.json",
    "causal_trigger_completion_attestation.v2.json",
    "causal_formal.revalidated.v2.json",
    "causal_formal.revalidation_receipt.v2.json",
    "cohort_closed_loop_structured_state.execution_seal.v2.json",
    "causal_trigger_completion_attestation.v3.json",
    "causal_formal.revalidated.v3.json",
    "causal_formal.revalidation_receipt.v3.json",
    "cohort_closed_loop_structured_state.execution_seal.v3.json",
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

BINDING_KEYS = frozenset({"path", "sha256"})
FILE_BINDING_KEYS = frozenset({"mtime_ns", "path", "sha256", "size_bytes"})
INVENTORY_BINDING_KEYS = frozenset(
    {
        "dynamic_policy_sha256",
        "inventory_sha256",
        "path",
        "sha256",
        "static_record_count",
        "static_records_sha256",
    }
)
RECEIPT_BINDING_KEYS = frozenset(
    {"path", "pid", "process_identity_status", "process_start_ticks", "sha256"}
)
WRAPPER_KEYS = frozenset(
    {"exit_file", "pid", "pid_file", "process_identity_status", "start_ticks"}
)
INCIDENT_KEYS = frozenset(
    {
        "classification",
        "completion_method",
        "decision_exit_exact_mtime_tie",
        "decision_exit_integer_second_boundary",
        "decision_manifest_semantics_opened",
        "decision_mtime_ns",
        "exit_canonical_zero",
        "exit_mtime_ns",
        "formal_decision",
        "formal_manifest",
        "historical_exit_order_claimed",
        "legacy_strict_mtime_proof",
        "manifest_before_decision",
        "manifest_mtime_ns",
        "mtime_relation",
    }
)
DOWNSTREAM_ABSENCE_KEYS = frozenset({"paths", "status"})
FENCE_AUTHORIZATION_KEYS = frozenset(
    {
        "maximum_successful_publications",
        "path",
        "protocol",
        "publication_mode",
        "schema_version",
    }
)
STABILITY_KEYS = frozenset(
    {
        "boottime_interval_ns",
        "minimum_interval_seconds",
        "observed_interval_seconds",
        "process_audits_identical",
        "runtime_namespace_identical",
        "snapshots_identical",
        "temporary_audits_identical",
    }
)

FAILURE_CLOSURE_KEYS = frozenset(
    {
        "authorized_completion_fence",
        "closed_at_utc",
        "incident",
        "launch_expectation",
        "outcome_blind",
        "protocol",
        "recovery_freezer",
        "schema_version",
        "semantic_artifacts_opened",
        "status",
        "v2_detached_launch_receipt",
        "v2_downstream_absence",
        "v2_execution_plan",
        "v2_procfs_exception_inventory",
        "wrapper",
    }
)

COMPLETION_FENCE_KEYS = frozenset(
    {
        "causal_pre_attestation_inventory_sha256",
        "failure_closure",
        "frozen_at_utc",
        "incident",
        "incident_sha256",
        "launch_expectation",
        "no_live_or_temporary",
        "outcome_blind",
        "process_absence",
        "protocol",
        "recovery_freezer",
        "runtime_namespace",
        "schema_version",
        "semantic_artifacts_opened",
        "snapshots",
        "stability",
        "status",
        "v2_detached_launch_receipt",
        "v2_downstream_absence",
        "v2_execution_plan",
        "v2_procfs_exception_inventory",
        "wrapper",
    }
)


class RecoveryV3Error(RuntimeError):
    """A fail-closed V3 recovery boundary error."""


def canonical_bytes(value: Any) -> bytes:
    """Return the unique wire encoding used by both recovery documents."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_exact(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RecoveryV3Error(f"{label} schema differs")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise RecoveryV3Error(f"{label} is not canonical SHA-256")
    return value


def _absolute(path: str | Path, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
        raise RecoveryV3Error(f"{label} is not normalized absolute")
    return candidate


def _validate_binding(value: Any, label: str) -> dict[str, Any]:
    binding = _require_exact(value, BINDING_KEYS, label)
    _absolute(binding["path"], f"{label}.path")
    _require_sha256(binding["sha256"], f"{label}.sha256")
    return binding


def _validate_file_binding(value: Any, label: str) -> dict[str, Any]:
    binding = _require_exact(value, FILE_BINDING_KEYS, label)
    _absolute(binding["path"], f"{label}.path")
    _require_sha256(binding["sha256"], f"{label}.sha256")
    for key in ("size_bytes", "mtime_ns"):
        if not _is_int(binding[key]) or binding[key] < 0:
            raise RecoveryV3Error(f"{label}.{key} is invalid")
    if binding["size_bytes"] <= 0:
        raise RecoveryV3Error(f"{label} is empty")
    return binding


def _validate_inventory_binding(value: Any) -> dict[str, Any]:
    binding = _require_exact(
        value, INVENTORY_BINDING_KEYS, "V2 procfs exception inventory binding"
    )
    _absolute(binding["path"], "V2 inventory path")
    for key in (
        "sha256",
        "inventory_sha256",
        "static_records_sha256",
        "dynamic_policy_sha256",
    ):
        _require_sha256(binding[key], f"V2 inventory {key}")
    if (
        not _is_int(binding["static_record_count"])
        or binding["static_record_count"] <= 0
    ):
        raise RecoveryV3Error("V2 inventory static record count is invalid")
    return binding


def _validate_receipt_binding(value: Any) -> dict[str, Any]:
    binding = _require_exact(value, RECEIPT_BINDING_KEYS, "V2 receipt binding")
    _absolute(binding["path"], "V2 receipt path")
    _require_sha256(binding["sha256"], "V2 receipt SHA-256")
    if (
        not _is_int(binding["pid"])
        or binding["pid"] <= 1
        or not _is_int(binding["process_start_ticks"])
        or binding["process_start_ticks"] <= 0
        or binding["process_identity_status"] != "gone"
    ):
        raise RecoveryV3Error("V2 receipt process identity is not gone")
    return binding


def _validate_wrapper(value: Any, *, durable: Path) -> dict[str, Any]:
    wrapper = _require_exact(value, WRAPPER_KEYS, "wrapper binding")
    if (
        not _is_int(wrapper["pid"])
        or wrapper["pid"] <= 1
        or not _is_int(wrapper["start_ticks"])
        or wrapper["start_ticks"] <= 0
        or wrapper["process_identity_status"] != "gone"
    ):
        raise RecoveryV3Error("wrapper process identity is not gone")
    pid_file = _validate_file_binding(wrapper["pid_file"], "wrapper PID file")
    exit_file = _validate_file_binding(wrapper["exit_file"], "wrapper exit file")
    if (
        Path(pid_file["path"]) != durable / "prep" / "causal_formal.pid"
        or Path(exit_file["path"]) != durable / "prep" / "causal_formal.exit"
    ):
        raise RecoveryV3Error("wrapper completion paths are not fixed")
    return wrapper


def _validate_incident(
    value: Any, *, wrapper: dict[str, Any], durable: Path
) -> dict[str, Any]:
    incident = _require_exact(value, INCIDENT_KEYS, "equal-second incident")
    for key in ("manifest_mtime_ns", "decision_mtime_ns", "exit_mtime_ns"):
        if not _is_int(incident[key]) or incident[key] <= 0:
            raise RecoveryV3Error(f"incident {key} is invalid")
    manifest = incident["manifest_mtime_ns"]
    decision = incident["decision_mtime_ns"]
    exit_mtime = incident["exit_mtime_ns"]
    manifest_file = _validate_file_binding(
        incident["formal_manifest"], "opaque formal manifest"
    )
    decision_file = _validate_file_binding(
        incident["formal_decision"], "opaque formal decision"
    )
    if (
        incident["classification"] != INCIDENT_CLASSIFICATION
        or incident["completion_method"] != COMPLETION_METHOD
        or incident["mtime_relation"] != MTIME_RELATION
        or incident["legacy_strict_mtime_proof"] is not False
        or incident["historical_exit_order_claimed"] is not False
        or incident["decision_manifest_semantics_opened"] is not False
        or incident["manifest_before_decision"] is not True
        or incident["decision_exit_exact_mtime_tie"] is not True
        or incident["decision_exit_integer_second_boundary"] is not True
        or incident["exit_canonical_zero"] is not True
        or not (manifest < decision == exit_mtime)
        or decision % NANOSECONDS_PER_SECOND != 0
        or exit_mtime % NANOSECONDS_PER_SECOND != 0
        or Path(manifest_file["path"])
        != durable / "artifacts" / "cohort_causal" / "formal_manifest.json"
        or Path(decision_file["path"])
        != durable / "artifacts" / "cohort_causal" / "formal_decision.json"
        or manifest_file["mtime_ns"] != manifest
        or decision_file["mtime_ns"] != decision
        or exit_mtime != wrapper["exit_file"]["mtime_ns"]
    ):
        raise RecoveryV3Error("document is outside the exact equal-second incident")
    return incident


def _expected_downstream_paths(durable: Path) -> list[str]:
    return sorted((durable / "prep" / name).as_posix() for name in DOWNSTREAM_FILENAMES)


def _validate_downstream_absence(value: Any, *, durable: Path) -> dict[str, Any]:
    record = _require_exact(value, DOWNSTREAM_ABSENCE_KEYS, "V2 downstream absence")
    if record["status"] != "all_absent" or record[
        "paths"
    ] != _expected_downstream_paths(durable):
        raise RecoveryV3Error("V2 downstream absence record differs")
    return record


def validate_failure_closure_document(
    value: Any, *, durable_attempt_root: Path, expected_path: Path
) -> dict[str, Any]:
    """Purely validate the exact failure-closure wire document."""

    durable = _absolute(durable_attempt_root, "durable attempt root")
    path = _absolute(expected_path, "failure closure path")
    if path != durable / "control" / FAILURE_CLOSURE_FILENAME:
        raise RecoveryV3Error("failure closure path is not fixed")
    closure = _require_exact(
        copy.deepcopy(value), FAILURE_CLOSURE_KEYS, "V2 failure closure"
    )
    if (
        closure["protocol"] != FAILURE_CLOSURE_PROTOCOL
        or closure["schema_version"] != FAILURE_CLOSURE_SCHEMA_VERSION
        or closure["status"] != FAILURE_CLOSURE_STATUS
        or closure["outcome_blind"] is not True
        or closure["semantic_artifacts_opened"] is not False
    ):
        raise RecoveryV3Error("failure closure header differs")
    seal_v2._parse_utc(closure["closed_at_utc"], "failure closure time")
    _validate_binding(closure["launch_expectation"], "launch expectation")
    _validate_binding(closure["v2_execution_plan"], "V2 execution plan")
    _validate_binding(closure["recovery_freezer"], "recovery freezer")
    inventory = _validate_inventory_binding(closure["v2_procfs_exception_inventory"])
    receipt = _validate_receipt_binding(closure["v2_detached_launch_receipt"])
    wrapper = _validate_wrapper(closure["wrapper"], durable=durable)
    incident = _validate_incident(closure["incident"], wrapper=wrapper, durable=durable)
    _validate_downstream_absence(closure["v2_downstream_absence"], durable=durable)
    authorization = _require_exact(
        closure["authorized_completion_fence"],
        FENCE_AUTHORIZATION_KEYS,
        "completion fence authorization",
    )
    if (
        closure["launch_expectation"]["path"]
        != (durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME).as_posix()
        or closure["v2_execution_plan"]["path"]
        != (durable / "control" / seal_v2.PLAN_FILENAME).as_posix()
        or inventory["path"]
        != (durable / "control" / seal_v2.EXCEPTION_INVENTORY_FILENAME).as_posix()
        or receipt["path"]
        != (durable / "control" / seal_v2.DETACHED_RECEIPT_FILENAME).as_posix()
        or authorization["path"]
        != (durable / "control" / COMPLETION_FENCE_FILENAME).as_posix()
        or authorization["protocol"] != COMPLETION_FENCE_PROTOCOL
        or authorization["schema_version"] != COMPLETION_FENCE_SCHEMA_VERSION
        or authorization["publication_mode"] != PUBLICATION_MODE
        or authorization["maximum_successful_publications"] != 1
        or receipt["process_start_ticks"] <= wrapper["start_ticks"]
        or not isinstance(incident, dict)
        or not isinstance(inventory, dict)
    ):
        raise RecoveryV3Error("completion fence authorization differs")
    return closure


def _validate_snapshot(value: Any, *, sequence: int) -> dict[str, Any]:
    snapshot = _require_exact(value, v1.SNAPSHOT_KEYS, f"fence snapshot {sequence}")
    if snapshot["sequence"] != sequence:
        raise RecoveryV3Error("fence snapshot sequence differs")
    seal_v2._parse_utc(snapshot["captured_at_utc"], "fence snapshot time")
    files = snapshot["files"]
    if not isinstance(files, list) or snapshot["file_count"] != len(files):
        raise RecoveryV3Error("fence snapshot file count differs")
    paths: list[str] = []
    inodes: set[tuple[int, int]] = set()
    for index, raw_record in enumerate(files):
        record = _require_exact(
            raw_record, v1.FILE_RECORD_KEYS, f"fence file record {index}"
        )
        path = _absolute(record["path"], f"fence file record {index} path")
        roles = record["roles"]
        if (
            not isinstance(roles, list)
            or not roles
            or roles != sorted(roles)
            or len(set(roles)) != len(roles)
            or any(not isinstance(role, str) or not role for role in roles)
        ):
            raise RecoveryV3Error("fence file roles differ")
        for key in ("device", "inode", "size_bytes", "mtime_ns"):
            if not _is_int(record[key]) or record[key] < 0:
                raise RecoveryV3Error(f"fence file {key} is invalid")
        if record["size_bytes"] <= 0:
            raise RecoveryV3Error("fence inventory contains an empty file")
        _require_sha256(record["sha256"], "fence file SHA-256")
        identity = (record["device"], record["inode"])
        if identity in inodes:
            raise RecoveryV3Error("fence inventory aliases one inode")
        inodes.add(identity)
        paths.append(path.as_posix())
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise RecoveryV3Error("fence file paths are not sorted unique")
    if snapshot["inventory_sha256"] != canonical_sha256(files):
        raise RecoveryV3Error("fence snapshot inventory digest differs")
    return snapshot


def _require_role_binding(
    files: list[dict[str, Any]],
    *,
    role: str,
    path: str,
    sha256: str,
    mtime_ns: int | None = None,
    size_bytes: int | None = None,
) -> None:
    matches = [record for record in files if role in record["roles"]]
    if len(matches) != 1:
        raise RecoveryV3Error(f"fence inventory needs exactly one {role}")
    record = matches[0]
    if (
        record["path"] != path
        or record["sha256"] != sha256
        or (mtime_ns is not None and record["mtime_ns"] != mtime_ns)
        or (size_bytes is not None and record["size_bytes"] != size_bytes)
    ):
        raise RecoveryV3Error(f"fence inventory {role} binding differs")


def _validate_fence_inventory_bindings(
    fence: Mapping[str, Any],
    *,
    files: list[dict[str, Any]],
    failure_closure_path: Path,
    failure_closure_sha256: str,
) -> None:
    """Bind every recovery-critical opaque file to one snapshot role."""

    simple = {
        "launch_expectation": fence["launch_expectation"],
        "v2_execution_plan": fence["v2_execution_plan"],
        "v2_procfs_exception_inventory": fence["v2_procfs_exception_inventory"],
        "v2_detached_launch_receipt": fence["v2_detached_launch_receipt"],
        "v3_recovery_freezer_source": fence["recovery_freezer"],
    }
    for role, binding in simple.items():
        _require_role_binding(
            files, role=role, path=binding["path"], sha256=binding["sha256"]
        )
    _require_role_binding(
        files,
        role="v2_failure_closure",
        path=failure_closure_path.as_posix(),
        sha256=failure_closure_sha256,
    )
    for role, binding in (
        ("wrapper_pid_file", fence["wrapper"]["pid_file"]),
        ("wrapper_exit_file", fence["wrapper"]["exit_file"]),
        ("formal_manifest", fence["incident"]["formal_manifest"]),
        ("formal_decision", fence["incident"]["formal_decision"]),
    ):
        _require_role_binding(
            files,
            role=role,
            path=binding["path"],
            sha256=binding["sha256"],
            mtime_ns=binding["mtime_ns"],
            size_bytes=binding["size_bytes"],
        )


def validate_completion_fence_document(
    value: Any,
    *,
    durable_attempt_root: Path,
    expected_path: Path,
    failure_closure_path: Path,
    failure_closure_sha256: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate the fence and return it with its bound opaque inventory."""

    durable = _absolute(durable_attempt_root, "durable attempt root")
    path = _absolute(expected_path, "completion fence path")
    closure_path = _absolute(failure_closure_path, "failure closure path")
    closure_sha = _require_sha256(failure_closure_sha256, "failure closure SHA-256")
    if path != durable / "control" / COMPLETION_FENCE_FILENAME:
        raise RecoveryV3Error("completion fence path is not fixed")
    fence = _require_exact(
        copy.deepcopy(value), COMPLETION_FENCE_KEYS, "V3 completion fence"
    )
    if (
        fence["protocol"] != COMPLETION_FENCE_PROTOCOL
        or fence["schema_version"] != COMPLETION_FENCE_SCHEMA_VERSION
        or fence["status"] != COMPLETION_FENCE_STATUS
        or fence["outcome_blind"] is not True
        or fence["semantic_artifacts_opened"] is not False
        or fence["failure_closure"]
        != {"path": closure_path.as_posix(), "sha256": closure_sha}
    ):
        raise RecoveryV3Error("completion fence header or closure binding differs")
    seal_v2._parse_utc(fence["frozen_at_utc"], "completion fence time")
    _validate_binding(fence["launch_expectation"], "launch expectation")
    _validate_binding(fence["v2_execution_plan"], "V2 execution plan")
    _validate_binding(fence["recovery_freezer"], "recovery freezer")
    inventory = _validate_inventory_binding(fence["v2_procfs_exception_inventory"])
    receipt = _validate_receipt_binding(fence["v2_detached_launch_receipt"])
    if (
        fence["launch_expectation"]["path"]
        != (durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME).as_posix()
        or fence["v2_execution_plan"]["path"]
        != (durable / "control" / seal_v2.PLAN_FILENAME).as_posix()
        or inventory["path"]
        != (durable / "control" / seal_v2.EXCEPTION_INVENTORY_FILENAME).as_posix()
        or receipt["path"]
        != (durable / "control" / seal_v2.DETACHED_RECEIPT_FILENAME).as_posix()
    ):
        raise RecoveryV3Error("completion fence fixed V2 bindings differ")
    wrapper = _validate_wrapper(fence["wrapper"], durable=durable)
    incident = _validate_incident(fence["incident"], wrapper=wrapper, durable=durable)
    if fence["incident_sha256"] != canonical_sha256(incident):
        raise RecoveryV3Error("completion fence incident digest differs")
    _validate_downstream_absence(fence["v2_downstream_absence"], durable=durable)
    try:
        namespace = seal_v2._validate_runtime_namespace(
            fence["runtime_namespace"], label="completion fence runtime namespace"
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise RecoveryV3Error("completion fence namespace differs") from exc
    snapshots = fence["snapshots"]
    if not isinstance(snapshots, list) or len(snapshots) != 2:
        raise RecoveryV3Error("completion fence needs exactly two snapshots")
    snapshot_1 = _validate_snapshot(snapshots[0], sequence=1)
    snapshot_2 = _validate_snapshot(snapshots[1], sequence=2)
    snapshot_time_1 = seal_v2._parse_utc(
        snapshot_1["captured_at_utc"], "completion fence snapshot one time"
    )
    snapshot_time_2 = seal_v2._parse_utc(
        snapshot_2["captured_at_utc"], "completion fence snapshot two time"
    )
    if (
        canonical_bytes(snapshot_1["files"]) != canonical_bytes(snapshot_2["files"])
        or (snapshot_time_2 - snapshot_time_1).total_seconds()
        < MINIMUM_STABILITY_SECONDS
    ):
        raise RecoveryV3Error("completion fence snapshots differ")
    _validate_fence_inventory_bindings(
        fence,
        files=snapshot_1["files"],
        failure_closure_path=closure_path,
        failure_closure_sha256=closure_sha,
    )
    stability = _require_exact(fence["stability"], STABILITY_KEYS, "fence stability")
    if (
        not isinstance(stability["minimum_interval_seconds"], (int, float))
        or isinstance(stability["minimum_interval_seconds"], bool)
        or stability["minimum_interval_seconds"] < MINIMUM_STABILITY_SECONDS
        or not isinstance(stability["observed_interval_seconds"], (int, float))
        or isinstance(stability["observed_interval_seconds"], bool)
        or stability["observed_interval_seconds"]
        < stability["minimum_interval_seconds"]
        or not _is_int(stability["boottime_interval_ns"])
        or stability["boottime_interval_ns"] < NANOSECONDS_PER_SECOND
        or any(
            stability[key] is not True
            for key in (
                "snapshots_identical",
                "process_audits_identical",
                "temporary_audits_identical",
                "runtime_namespace_identical",
            )
        )
        or fence["causal_pre_attestation_inventory_sha256"]
        != snapshot_1["inventory_sha256"]
    ):
        raise RecoveryV3Error("completion fence stability proof differs")
    process = _require_exact(
        fence["process_absence"], seal_v2.PROCESS_AUDIT_KEYS, "V3 process audit"
    )
    process_payload = {key: process[key] for key in process if key != "audit_sha256"}
    if (
        process["status"] != "pass"
        or process["method"] != seal_v2.PROCESS_AUDIT_METHOD
        or process["dynamic_policy_enforced"] is not True
        or process["dynamic_policy_sha256"] != inventory["dynamic_policy_sha256"]
        or process["exception_inventory_sha256"] != inventory["sha256"]
        or process["durable_attempt_root_path"] != durable.as_posix()
        or process["artifact_root_path"]
        != (durable / "artifacts" / "cohort_causal").as_posix()
        or process["observed_exception_count"] != inventory["static_record_count"]
        or process["observed_exceptions_sha256"] != inventory["static_records_sha256"]
        or process["audit_sha256"] != canonical_sha256(process_payload)
    ):
        raise RecoveryV3Error("completion fence process audit differs")
    try:
        v1._validate_temporary_audit(
            fence["no_live_or_temporary"],
            roots=(durable / "artifacts" / "cohort_causal", durable / "prep"),
        )
    except v1.AttestationError as exc:
        raise RecoveryV3Error("completion fence temporary audit differs") from exc
    if (
        receipt["process_start_ticks"] <= wrapper["start_ticks"]
        or namespace != fence["runtime_namespace"]
    ):
        raise RecoveryV3Error("completion fence receipt/namespace binding differs")
    return fence, snapshot_1["files"]


def extract_completion_fence_inventory(
    fence: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Return a defensive copy of the first opaque snapshot inventory."""

    snapshots = fence.get("snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != 2:
        raise RecoveryV3Error("completion fence snapshots are unavailable")
    files = snapshots[0].get("files") if isinstance(snapshots[0], dict) else None
    if not isinstance(files, list):
        raise RecoveryV3Error("completion fence inventory is unavailable")
    return copy.deepcopy(files)


def _read_canonical_control(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = v1._read_opaque_bytes(path, permitted_roots=(path.parent,))
    try:
        value = seal_v2._strict_json_bytes(raw, label)
    except seal_v2.ExecutionSealV2Error as exc:
        raise RecoveryV3Error(f"{label} is not strict JSON") from exc
    if canonical_bytes(value) != raw:
        raise RecoveryV3Error(f"{label} is not canonical JSON")
    return value, raw


def _file_binding(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "mtime_ns": record["mtime_ns"],
        "path": record["path"],
        "sha256": record["sha256"],
        "size_bytes": record["size_bytes"],
    }


def _assert_identity_gone(
    pid: int, start_ticks: int, *, proc_root: Path = Path("/proc")
) -> None:
    try:
        seal_v2._assert_process_start_gone(
            pid=pid,
            start_ticks=start_ticks,
            label="recovery-bound",
            proc_root=proc_root,
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise RecoveryV3Error("a recovery-bound process identity remains live") from exc


def _assert_absent_outputs(paths: Iterable[Path], *, durable: Path) -> dict[str, Any]:
    v1._assert_no_symlink_components(durable / "prep", (durable,))
    normalized = sorted(Path(path).as_posix() for path in paths)
    if normalized != _expected_downstream_paths(durable):
        raise RecoveryV3Error("V2 downstream path set differs")
    if any(os.path.lexists(path) for path in paths):
        raise RecoveryV3Error("a V2 downstream output already exists")
    return {"paths": normalized, "status": "all_absent"}


def _opaque_record(
    path: Path, *, role: str, permitted_roots: Iterable[Path]
) -> dict[str, Any]:
    return v1._hash_file_record(
        path,
        {"roles": {role}, "expected_sha256": None, "expected_size": None},
        permitted_roots=permitted_roots,
    )


def _load_recovery_context(
    *,
    root: Path,
    launch_expectation_path: Path,
    v2_execution_plan_path: Path,
    v2_procfs_exception_inventory_path: Path,
    v2_detached_launch_receipt_path: Path,
    process_identity_gone_fn: Callable[[int, int], None] = _assert_identity_gone,
) -> dict[str, Any]:
    """Load control bytes while keeping manifest and decision fully opaque."""

    root = v1._absolute_without_following(root)
    expectation_path = v1._absolute_without_following(launch_expectation_path)
    plan_path = v1._absolute_without_following(v2_execution_plan_path)
    inventory_path = v1._absolute_without_following(v2_procfs_exception_inventory_path)
    receipt_path = v1._absolute_without_following(v2_detached_launch_receipt_path)
    expectation, expectation_raw = v1._load_launch_expectation(expectation_path)
    durable = Path(expectation["durable_attempt_root"])
    artifact = Path(expectation["artifact_root"])
    if (
        root != Path(expectation["checkout_root"])
        or expectation_path != durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME
        or plan_path != durable / "control" / seal_v2.PLAN_FILENAME
        or inventory_path != durable / "control" / seal_v2.EXCEPTION_INVENTORY_FILENAME
    ):
        raise RecoveryV3Error("recovery roots or fixed V2 paths differ")
    plan, plan_raw = _read_canonical_control(plan_path, "V2 execution plan")
    invocation = plan.get("invocations", {}).get("attester")
    runtime = plan.get("runtime")
    if not isinstance(invocation, dict) or not isinstance(runtime, dict):
        raise RecoveryV3Error("V2 plan lacks the frozen attester invocation")
    try:
        validated_plan, validated_plan_raw = (
            seal_v2.load_and_validate_execution_plan_stage(
                execution_plan_path=plan_path,
                stage="attester",
                expected_inputs=invocation["inputs"],
                expected_outputs=invocation["outputs"],
                expected_parameters=invocation["parameters"],
                actual_argv=invocation["argv"],
                runtime_python_path=runtime["python_path"],
                runtime_python_version=runtime["python_version"],
            )
        )
    except (KeyError, seal_v2.ExecutionSealV2Error) as exc:
        raise RecoveryV3Error("V2 plan does not revalidate statically") from exc
    if validated_plan_raw != plan_raw or validated_plan != plan:
        raise RecoveryV3Error("V2 plan changed during recovery load")
    inventory, inventory_raw = _read_canonical_control(
        inventory_path, "V2 procfs exception inventory"
    )
    try:
        validated_inventory, static_records = seal_v2.validate_exception_inventory(
            inventory,
            launch_expectation_path=expectation_path,
            launch_expectation_sha256=hashlib.sha256(expectation_raw).hexdigest(),
            wrapper_pid=expectation["wrapper_pid"],
            wrapper_start_ticks=expectation["wrapper_start_ticks"],
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise RecoveryV3Error("V2 procfs inventory does not revalidate") from exc
    inventory_binding = plan.get("procfs_exception_inventory")
    expected_inventory_binding = {
        "path": inventory_path.as_posix(),
        "sha256": hashlib.sha256(inventory_raw).hexdigest(),
    }
    if inventory_binding != expected_inventory_binding:
        raise RecoveryV3Error("V2 plan is not bound to the current procfs inventory")
    if receipt_path != Path(plan["detached_transport"]["receipt_path"]):
        raise RecoveryV3Error("V2 detached receipt path differs from plan")
    receipt, receipt_raw = _read_canonical_control(
        receipt_path, "V2 detached launch receipt"
    )
    try:
        validated_receipt = seal_v2.validate_detached_receipt_document(
            receipt,
            plan=plan,
            execution_plan_path=plan_path,
            execution_plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
            runtime_namespace=validated_inventory["runtime_namespace"],
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise RecoveryV3Error("V2 detached receipt does not revalidate") from exc
    if validated_receipt != receipt:
        raise RecoveryV3Error("V2 detached receipt normalization differs")
    wrapper_pid = expectation["wrapper_pid"]
    wrapper_start = expectation["wrapper_start_ticks"]
    if receipt["process_start_ticks"] <= wrapper_start:
        raise RecoveryV3Error("V2 receipt does not postdate wrapper start")
    process_identity_gone_fn(wrapper_pid, wrapper_start)
    process_identity_gone_fn(receipt["pid"], receipt["process_start_ticks"])

    permitted_roots = (root, durable, expectation_path.parent)
    pid_path = Path(expectation["pid_file"])
    exit_path = Path(expectation["exit_file"])
    manifest_path = artifact / "formal_manifest.json"
    decision_path = artifact / "formal_decision.json"
    pid_record = _opaque_record(
        pid_path, role="wrapper_pid_file", permitted_roots=permitted_roots
    )
    exit_record = _opaque_record(
        exit_path, role="wrapper_exit_file", permitted_roots=permitted_roots
    )
    manifest_record = _opaque_record(
        manifest_path, role="formal_manifest", permitted_roots=permitted_roots
    )
    decision_record = _opaque_record(
        decision_path, role="formal_decision", permitted_roots=permitted_roots
    )
    pid_raw = v1._read_opaque_bytes(pid_path, permitted_roots=(durable,))
    exit_raw = v1._read_opaque_bytes(exit_path, permitted_roots=(durable,))
    if (
        pid_raw != f"{wrapper_pid}\n".encode("ascii")
        or hashlib.sha256(pid_raw).hexdigest()
        != expectation["pid_file_sha256_at_registration"]
        or exit_raw != CANONICAL_ZERO_EXIT
    ):
        raise RecoveryV3Error("wrapper PID or exit bytes are not canonical")
    manifest_mtime = manifest_record["mtime_ns"]
    decision_mtime = decision_record["mtime_ns"]
    exit_mtime = exit_record["mtime_ns"]
    if (
        not (manifest_mtime < decision_mtime == exit_mtime)
        or decision_mtime % NANOSECONDS_PER_SECOND != 0
        or exit_mtime % NANOSECONDS_PER_SECOND != 0
    ):
        raise RecoveryV3Error(
            "terminal files are outside the exact equal-second incident"
        )
    incident = {
        "classification": INCIDENT_CLASSIFICATION,
        "completion_method": COMPLETION_METHOD,
        "decision_exit_exact_mtime_tie": True,
        "decision_exit_integer_second_boundary": True,
        "decision_manifest_semantics_opened": False,
        "decision_mtime_ns": decision_mtime,
        "exit_canonical_zero": True,
        "exit_mtime_ns": exit_mtime,
        "formal_decision": _file_binding(decision_record),
        "formal_manifest": _file_binding(manifest_record),
        "historical_exit_order_claimed": False,
        "legacy_strict_mtime_proof": False,
        "manifest_before_decision": True,
        "manifest_mtime_ns": manifest_mtime,
        "mtime_relation": MTIME_RELATION,
    }
    wrapper = {
        "exit_file": _file_binding(exit_record),
        "pid": wrapper_pid,
        "pid_file": _file_binding(pid_record),
        "process_identity_status": "gone",
        "start_ticks": wrapper_start,
    }
    return {
        "artifact": artifact,
        "durable": durable,
        "expectation": expectation,
        "expectation_raw": expectation_raw,
        "incident": incident,
        "inventory": validated_inventory,
        "inventory_path": inventory_path,
        "inventory_raw": inventory_raw,
        "plan": plan,
        "plan_path": plan_path,
        "plan_raw": plan_raw,
        "receipt": receipt,
        "receipt_path": receipt_path,
        "receipt_raw": receipt_raw,
        "root": root,
        "static_records": static_records,
        "wrapper": wrapper,
    }


def _source_binding(source_path: Path) -> tuple[dict[str, str], bytes]:
    source = v1._absolute_without_following(source_path)
    raw = v1._read_opaque_bytes(source, permitted_roots=(source.parent,))
    return {"path": source.as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}, raw


def _context_bindings(context: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "launch_expectation": {
            "path": Path(context["durable"])
            .joinpath("control", seal_v2.LAUNCH_EXPECTATION_FILENAME)
            .as_posix(),
            "sha256": hashlib.sha256(context["expectation_raw"]).hexdigest(),
        },
        "v2_execution_plan": {
            "path": Path(context["plan_path"]).as_posix(),
            "sha256": hashlib.sha256(context["plan_raw"]).hexdigest(),
        },
        "v2_procfs_exception_inventory": {
            "dynamic_policy_sha256": context["inventory"]["dynamic_policy_sha256"],
            "inventory_sha256": context["inventory"]["inventory_sha256"],
            "path": Path(context["inventory_path"]).as_posix(),
            "sha256": hashlib.sha256(context["inventory_raw"]).hexdigest(),
            "static_record_count": len(context["static_records"]),
            "static_records_sha256": context["inventory"]["static_records_sha256"],
        },
        "v2_detached_launch_receipt": {
            "path": Path(context["receipt_path"]).as_posix(),
            "pid": context["receipt"]["pid"],
            "process_identity_status": "gone",
            "process_start_ticks": context["receipt"]["process_start_ticks"],
            "sha256": hashlib.sha256(context["receipt_raw"]).hexdigest(),
        },
    }


def _assert_context_identities_gone(
    context: Mapping[str, Any],
    process_identity_gone_fn: Callable[[int, int], None],
) -> None:
    """Recheck both exact PID/start identities without trusting PID absence alone."""

    process_identity_gone_fn(
        context["wrapper"]["pid"], context["wrapper"]["start_ticks"]
    )
    process_identity_gone_fn(
        context["receipt"]["pid"], context["receipt"]["process_start_ticks"]
    )


def _publish_no_overwrite(path: Path, payload: bytes) -> None:
    if os.path.lexists(path):
        raise FileExistsError("refusing to overwrite V3 recovery output")
    v1._atomic_publish_no_overwrite(path, payload)


def build_and_publish_failure_closure(
    *,
    root: Path,
    launch_expectation_path: Path,
    v2_execution_plan_path: Path,
    v2_procfs_exception_inventory_path: Path,
    v2_detached_launch_receipt_path: Path,
    output: Path,
    completion_fence_path: Path,
    source_path: Path | None = None,
    now_fn: Callable[[], str] = v1._utc_now,
    context_loader_fn: Callable[..., dict[str, Any]] = _load_recovery_context,
    publish_fn: Callable[[Path, bytes], None] = _publish_no_overwrite,
) -> dict[str, Any]:
    """Publish the one-shot, outcome-blind closure of the V2 incident."""

    output = v1._absolute_without_following(output)
    fence_path = v1._absolute_without_following(completion_fence_path)
    if os.path.lexists(output) or os.path.lexists(fence_path):
        raise FileExistsError("V3 recovery output already exists")
    context = context_loader_fn(
        root=root,
        launch_expectation_path=launch_expectation_path,
        v2_execution_plan_path=v2_execution_plan_path,
        v2_procfs_exception_inventory_path=v2_procfs_exception_inventory_path,
        v2_detached_launch_receipt_path=v2_detached_launch_receipt_path,
    )
    durable = Path(context["durable"])
    if (
        output != durable / "control" / FAILURE_CLOSURE_FILENAME
        or fence_path != durable / "control" / COMPLETION_FENCE_FILENAME
    ):
        raise RecoveryV3Error("V3 recovery outputs are not fixed")
    downstream = _assert_absent_outputs(
        (durable / "prep" / name for name in DOWNSTREAM_FILENAMES),
        durable=durable,
    )
    source_binding, source_raw = _source_binding(
        Path(__file__).absolute() if source_path is None else source_path
    )
    bindings = _context_bindings(context)
    closure = {
        "authorized_completion_fence": {
            "maximum_successful_publications": 1,
            "path": fence_path.as_posix(),
            "protocol": COMPLETION_FENCE_PROTOCOL,
            "publication_mode": PUBLICATION_MODE,
            "schema_version": COMPLETION_FENCE_SCHEMA_VERSION,
        },
        "closed_at_utc": now_fn(),
        "incident": copy.deepcopy(context["incident"]),
        "launch_expectation": bindings["launch_expectation"],
        "outcome_blind": True,
        "protocol": FAILURE_CLOSURE_PROTOCOL,
        "recovery_freezer": source_binding,
        "schema_version": FAILURE_CLOSURE_SCHEMA_VERSION,
        "semantic_artifacts_opened": False,
        "status": FAILURE_CLOSURE_STATUS,
        "v2_detached_launch_receipt": bindings["v2_detached_launch_receipt"],
        "v2_downstream_absence": downstream,
        "v2_execution_plan": bindings["v2_execution_plan"],
        "v2_procfs_exception_inventory": bindings["v2_procfs_exception_inventory"],
        "wrapper": copy.deepcopy(context["wrapper"]),
    }
    validate_failure_closure_document(
        closure, durable_attempt_root=durable, expected_path=output
    )
    bound_source = Path(source_binding["path"])
    if (
        v1._read_opaque_bytes(bound_source, permitted_roots=(bound_source.parent,))
        != source_raw
    ):
        raise RecoveryV3Error("recovery freezer source drifted before closure publish")
    v1._assert_no_symlink_components(output.parent, (durable,))
    publish_fn(output, canonical_bytes(closure))
    return {
        "path": output.as_posix(),
        "sha256": canonical_sha256(closure),
        "status": FAILURE_CLOSURE_STATUS,
    }


def _build_full_inventory(
    *,
    context: Mapping[str, Any],
    provenance_path: Path,
    provenance_details_path: Path,
    closure_path: Path,
    source_path: Path,
) -> v1._InventoryBuilder:
    root = Path(context["root"])
    durable = Path(context["durable"])
    artifact = Path(context["artifact"])
    expectation = context["expectation"]
    expectation_path = durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME
    permitted = (root, durable, expectation_path.parent, source_path.parent)
    builder = v1._InventoryBuilder(permitted_roots=permitted)
    builder.add(
        expectation_path,
        role="launch_expectation",
        expected_sha256=hashlib.sha256(context["expectation_raw"]).hexdigest(),
        expected_size=len(context["expectation_raw"]),
    )
    grid_path = root / "grid_cohort_causal_formal.json"
    grid, grid_raw = v1._load_control_json_with_bytes(
        grid_path, permitted_roots=(root,)
    )
    if hashlib.sha256(grid_raw).hexdigest() != expectation["formal_grid_file_sha256"]:
        raise RecoveryV3Error("formal grid differs from launch expectation")
    builder.add(
        grid_path,
        role="formal_grid",
        expected_sha256=expectation["formal_grid_file_sha256"],
    )
    launcher = root / "launch_cohort_causal.sh"
    builder.add(
        launcher,
        role="launcher_source",
        expected_sha256=expectation["launcher_file_sha256"],
    )
    builder.add(Path(expectation["pid_file"]), role="wrapper_pid_file")
    builder.add(Path(expectation["exit_file"]), role="wrapper_exit_file")
    builder.add(artifact / "smoke_gate.json", role="causal_smoke_gate")
    builder.add(root / "COHORT_QONLY_CAUSAL_PREREG.md", role="causal_prereg")
    v1._add_provenance_inventory(
        root=root,
        provenance_path=provenance_path,
        details_path=provenance_details_path,
        expectation=expectation,
        builder=builder,
    )
    v1._add_corpus_inventory(root=root, grid=grid, builder=builder)
    counts = v1._add_formal_inventory(
        root=root, artifact_root=artifact, grid=grid, builder=builder
    )
    if counts != expectation["expected_final_inventory"]:
        raise RecoveryV3Error("formal inventory count differs")
    for path, role, digest in (
        (
            Path(context["plan_path"]),
            "v2_execution_plan",
            hashlib.sha256(context["plan_raw"]).hexdigest(),
        ),
        (
            Path(context["inventory_path"]),
            "v2_procfs_exception_inventory",
            hashlib.sha256(context["inventory_raw"]).hexdigest(),
        ),
        (
            Path(context["receipt_path"]),
            "v2_detached_launch_receipt",
            hashlib.sha256(context["receipt_raw"]).hexdigest(),
        ),
    ):
        builder.add(path, role=role, expected_sha256=digest)
    builder.add(closure_path, role="v2_failure_closure")
    builder.add(source_path, role="v3_recovery_freezer_source")
    return builder


def build_and_publish_completion_fence(
    *,
    root: Path,
    launch_expectation_path: Path,
    v2_execution_plan_path: Path,
    v2_procfs_exception_inventory_path: Path,
    v2_detached_launch_receipt_path: Path,
    provenance_path: Path,
    provenance_details_path: Path,
    failure_closure_path: Path,
    output: Path,
    source_path: Path | None = None,
    stability_seconds: float = MINIMUM_STABILITY_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
    boottime_ns_fn: Callable[[], int] = lambda: time.clock_gettime_ns(
        time.CLOCK_BOOTTIME
    ),
    now_fn: Callable[[], str] = v1._utc_now,
    context_loader_fn: Callable[..., dict[str, Any]] = _load_recovery_context,
    inventory_builder_fn: Callable[..., v1._InventoryBuilder] = _build_full_inventory,
    process_audit_fn: Callable[
        ..., dict[str, Any]
    ] = attester_v2._scan_process_references,
    temporary_audit_fn: Callable[..., dict[str, Any]] = v1._scan_live_or_temporary,
    runtime_namespace_fn: Callable[[], dict[str, Any]] = (
        attester_v2._current_runtime_namespace
    ),
    process_identity_gone_fn: Callable[[int, int], None] = _assert_identity_gone,
    publish_fn: Callable[[Path, bytes], None] = _publish_no_overwrite,
) -> dict[str, Any]:
    """Publish the one authorized terminal-quiescence fence."""

    if stability_seconds < MINIMUM_STABILITY_SECONDS:
        raise RecoveryV3Error("stability interval must be at least one second")
    closure_path = v1._absolute_without_following(failure_closure_path)
    output = v1._absolute_without_following(output)
    if os.path.lexists(output):
        raise FileExistsError("refusing to overwrite V3 completion fence")
    context = context_loader_fn(
        root=root,
        launch_expectation_path=launch_expectation_path,
        v2_execution_plan_path=v2_execution_plan_path,
        v2_procfs_exception_inventory_path=v2_procfs_exception_inventory_path,
        v2_detached_launch_receipt_path=v2_detached_launch_receipt_path,
    )
    durable = Path(context["durable"])
    artifact = Path(context["artifact"])
    if (
        closure_path != durable / "control" / FAILURE_CLOSURE_FILENAME
        or output != durable / "control" / COMPLETION_FENCE_FILENAME
    ):
        raise RecoveryV3Error("V3 recovery paths are not fixed")
    closure_value, closure_raw = _read_canonical_control(
        closure_path, "V2 failure closure"
    )
    closure = validate_failure_closure_document(
        closure_value, durable_attempt_root=durable, expected_path=closure_path
    )
    bindings = _context_bindings(context)
    for key in (
        "launch_expectation",
        "v2_execution_plan",
        "v2_procfs_exception_inventory",
        "v2_detached_launch_receipt",
    ):
        if closure[key] != bindings[key]:
            raise RecoveryV3Error(f"failure closure {key} drifted")
    if (
        closure["wrapper"] != context["wrapper"]
        or closure["incident"] != context["incident"]
    ):
        raise RecoveryV3Error("failure closure incident/wrapper drifted")
    downstream_1 = _assert_absent_outputs(
        (durable / "prep" / name for name in DOWNSTREAM_FILENAMES),
        durable=durable,
    )
    source = Path(__file__).absolute() if source_path is None else source_path
    source_binding, source_raw = _source_binding(source)
    if closure["recovery_freezer"] != source_binding:
        raise RecoveryV3Error("failure closure freezer binding differs")
    builder = inventory_builder_fn(
        context=context,
        provenance_path=v1._absolute_without_following(provenance_path),
        provenance_details_path=v1._absolute_without_following(provenance_details_path),
        closure_path=closure_path,
        source_path=v1._absolute_without_following(source),
    )

    def process_audit() -> dict[str, Any]:
        return process_audit_fn(
            attempt_checkout=Path(context["root"]),
            artifact_root=artifact,
            exception_records=context["static_records"],
            dynamic_policy=context["inventory"]["dynamic_policy"],
            dynamic_policy_sha256=context["inventory"]["dynamic_policy_sha256"],
            wrapper_start_ticks=context["expectation"]["wrapper_start_ticks"],
            exception_file_sha256=hashlib.sha256(context["inventory_raw"]).hexdigest(),
        )

    namespace_1 = runtime_namespace_fn()
    if namespace_1 != context["inventory"]["runtime_namespace"]:
        raise RecoveryV3Error("runtime namespace differs from V2 inventory")
    process_1 = process_audit()
    temporary_1 = temporary_audit_fn(roots=(artifact, durable / "prep"))
    try:
        v1._validate_temporary_audit(temporary_1, roots=(artifact, durable / "prep"))
    except v1.AttestationError as exc:
        raise RecoveryV3Error("first temporary audit failed") from exc
    _assert_context_identities_gone(context, process_identity_gone_fn)
    snapshot_1 = v1._take_snapshot(builder, sequence=1, now_fn=now_fn)
    boottime_1 = boottime_ns_fn()
    monotonic_start = monotonic_fn()
    sleep_fn(stability_seconds)
    observed_interval = monotonic_fn() - monotonic_start
    boottime_2 = boottime_ns_fn()
    snapshot_2 = v1._take_snapshot(builder, sequence=2, now_fn=now_fn)
    _assert_context_identities_gone(context, process_identity_gone_fn)
    namespace_2 = runtime_namespace_fn()
    process_2 = process_audit()
    temporary_2 = temporary_audit_fn(roots=(artifact, durable / "prep"))
    downstream_2 = _assert_absent_outputs(
        (durable / "prep" / name for name in DOWNSTREAM_FILENAMES),
        durable=durable,
    )
    if (
        observed_interval < stability_seconds
        or boottime_2 - boottime_1 < NANOSECONDS_PER_SECOND
        or snapshot_1["files"] != snapshot_2["files"]
        or snapshot_1["inventory_sha256"] != snapshot_2["inventory_sha256"]
        or process_1 != process_2
        or temporary_1 != temporary_2
        or namespace_1 != namespace_2
        or downstream_1 != downstream_2
    ):
        raise RecoveryV3Error("terminal quiescence changed across snapshots")
    try:
        v1._validate_temporary_audit(temporary_2, roots=(artifact, durable / "prep"))
    except v1.AttestationError as exc:
        raise RecoveryV3Error("second temporary audit failed") from exc
    process_payload = {
        key: process_1[key] for key in process_1 if key != "audit_sha256"
    }
    if (
        set(process_1) != seal_v2.PROCESS_AUDIT_KEYS
        or process_1["status"] != "pass"
        or process_1["method"] != seal_v2.PROCESS_AUDIT_METHOD
        or process_1["dynamic_policy_enforced"] is not True
        or process_1["dynamic_policy_sha256"]
        != context["inventory"]["dynamic_policy_sha256"]
        or process_1["exception_inventory_sha256"]
        != hashlib.sha256(context["inventory_raw"]).hexdigest()
        or process_1["audit_sha256"] != canonical_sha256(process_payload)
    ):
        raise RecoveryV3Error("V2 dynamic process audit does not bind the inventory")
    if v1._read_opaque_bytes(closure_path, permitted_roots=(durable,)) != closure_raw:
        raise RecoveryV3Error("failure closure drifted before fence publish")
    bound_source = Path(source_binding["path"])
    if (
        v1._read_opaque_bytes(bound_source, permitted_roots=(bound_source.parent,))
        != source_raw
    ):
        raise RecoveryV3Error("recovery freezer source drifted before fence publish")
    fence = {
        "causal_pre_attestation_inventory_sha256": snapshot_1["inventory_sha256"],
        "failure_closure": {
            "path": closure_path.as_posix(),
            "sha256": hashlib.sha256(closure_raw).hexdigest(),
        },
        "frozen_at_utc": now_fn(),
        "incident": copy.deepcopy(context["incident"]),
        "incident_sha256": canonical_sha256(context["incident"]),
        "launch_expectation": bindings["launch_expectation"],
        "no_live_or_temporary": temporary_1,
        "outcome_blind": True,
        "process_absence": process_1,
        "protocol": COMPLETION_FENCE_PROTOCOL,
        "recovery_freezer": source_binding,
        "runtime_namespace": namespace_1,
        "schema_version": COMPLETION_FENCE_SCHEMA_VERSION,
        "semantic_artifacts_opened": False,
        "snapshots": [snapshot_1, snapshot_2],
        "stability": {
            "boottime_interval_ns": boottime_2 - boottime_1,
            "minimum_interval_seconds": stability_seconds,
            "observed_interval_seconds": observed_interval,
            "process_audits_identical": True,
            "runtime_namespace_identical": True,
            "snapshots_identical": True,
            "temporary_audits_identical": True,
        },
        "status": COMPLETION_FENCE_STATUS,
        "v2_detached_launch_receipt": bindings["v2_detached_launch_receipt"],
        "v2_downstream_absence": downstream_1,
        "v2_execution_plan": bindings["v2_execution_plan"],
        "v2_procfs_exception_inventory": bindings["v2_procfs_exception_inventory"],
        "wrapper": copy.deepcopy(context["wrapper"]),
    }
    validate_completion_fence_document(
        fence,
        durable_attempt_root=durable,
        expected_path=output,
        failure_closure_path=closure_path,
        failure_closure_sha256=hashlib.sha256(closure_raw).hexdigest(),
    )
    v1._assert_no_symlink_components(output.parent, (durable,))
    _assert_context_identities_gone(context, process_identity_gone_fn)
    publish_fn(output, canonical_bytes(fence))
    return {
        "causal_pre_attestation_inventory_sha256": snapshot_1["inventory_sha256"],
        "path": output.as_posix(),
        "sha256": canonical_sha256(fence),
        "status": COMPLETION_FENCE_STATUS,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase", choices=("failure-closure", "completion-fence"), required=True
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--v2-execution-plan", type=Path, required=True)
    parser.add_argument("--v2-procfs-exception-inventory", type=Path, required=True)
    parser.add_argument("--v2-detached-launch-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--completion-fence", type=Path)
    parser.add_argument("--failure-closure", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--provenance-details", type=Path)
    parser.add_argument("--stability-seconds", type=float, default=1.0)
    args = parser.parse_args()
    common = {
        "root": args.root,
        "launch_expectation_path": args.launch_expectation,
        "v2_execution_plan_path": args.v2_execution_plan,
        "v2_procfs_exception_inventory_path": args.v2_procfs_exception_inventory,
        "v2_detached_launch_receipt_path": args.v2_detached_launch_receipt,
        "output": args.output,
    }
    try:
        if args.phase == "failure-closure":
            if (
                args.completion_fence is None
                or args.failure_closure is not None
                or args.provenance is not None
                or args.provenance_details is not None
            ):
                raise RecoveryV3Error("failure-closure phase arguments differ")
            result = build_and_publish_failure_closure(
                **common, completion_fence_path=args.completion_fence
            )
        else:
            if (
                args.failure_closure is None
                or args.provenance is None
                or args.provenance_details is None
                or args.completion_fence is not None
            ):
                raise RecoveryV3Error("completion-fence phase arguments differ")
            result = build_and_publish_completion_fence(
                **common,
                provenance_path=args.provenance,
                provenance_details_path=args.provenance_details,
                failure_closure_path=args.failure_closure,
                stability_seconds=args.stability_seconds,
            )
    except (
        FileExistsError,
        OSError,
        RecoveryV3Error,
        seal_v2.ExecutionSealV2Error,
        v1.AttestationError,
    ):
        print(canonical_bytes({"status": "invalid"}).decode("utf-8"), file=sys.stderr)
        raise SystemExit(1) from None
    print(canonical_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
