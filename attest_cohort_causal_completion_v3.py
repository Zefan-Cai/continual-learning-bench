#!/usr/bin/env python3
"""Publish the one-shot, outcome-blind causal completion attestation V3.

V3 is a narrowly scoped recovery overlay for the observed SenseiFS timestamp
tie.  It never claims that the wrapper exit file strictly postdated the formal
decision.  Instead it requires the immutable V2 failure closure, the V3
post-wrapper-death completion fence, and a fresh same-PID detached transport
receipt before reusing the unchanged V1 opaque inventory engine.  The only
legacy ``pass`` view is an in-memory compatibility projection; it is never
published as evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import attest_cohort_causal_completion as v1
import attest_cohort_causal_completion_v2 as attester_v2
import build_cohort_causal_terminal_execution_v3 as execution_v3
import build_cohort_structured_state_execution_seal as seal_v1
import build_cohort_structured_state_execution_seal_v2 as seal_v2
import freeze_cohort_causal_terminal_recovery_v3 as recovery_v3


PROTOCOL = "cohort_causal_terminal_completion_attestation_v3"
SCHEMA_VERSION = 3
ATTESTATION_FILENAME = "causal_trigger_completion_attestation.v3.json"
MINIMUM_STABILITY_SECONDS = v1.MINIMUM_STABILITY_SECONDS
PID_EXIT_TIE_STATUS = "not_proven_equal_second"
COMPLETION_METHOD = "post-wrapper-death two-snapshot fence"
MTIME_RELATION = "formal_manifest_before_formal_decision_equal_wrapper_exit"
CANONICAL_ZERO_EXIT = b"0\n"
CANONICAL_ZERO_EXIT_SHA256 = hashlib.sha256(CANONICAL_ZERO_EXIT).hexdigest()
SEMANTIC_OPEN_SENTINEL = {
    "efficacy_artifacts_semantically_opened": False,
    "formal_decision_json_decoded": False,
    "formal_manifest_json_decoded": False,
}
CONTROL_CHAIN_SENTINEL = {
    "base_v2_receipt_live_validated": False,
    "efficacy_artifacts_parsed": False,
    "fresh_v3_receipt_same_pid_validated": True,
    "recovery_controls_validated": True,
}

CONTROL_BINDING_KEYS = frozenset({"path", "sha256"})
COMPLETION_PROOF_KEYS = frozenset(
    {
        "completion_fence_sha256",
        "completion_method",
        "formal_decision_mtime_ns",
        "formal_manifest_mtime_ns",
        "historical_exit_order_claimed",
        "legacy_strict_mtime_proof",
        "mtime_relation",
        "wrapper_exit_exact_zero_newline",
        "wrapper_exit_mtime_ns",
        "wrapper_pid_dead",
    }
)
ATTESTATION_KEYS = frozenset(
    set(seal_v2.ATTESTATION_KEYS)
    | {
        "completion_fence",
        "completion_proof",
        "outcome_blind",
        "semantic_open_sentinel",
        "v2_failure_closure",
    }
)


class AttestationV3Error(v1.AttestationError):
    """A fail-closed V3 completion-attestation error."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _binding(path: Path, payload: bytes) -> dict[str, str]:
    return {"path": path.as_posix(), "sha256": _sha256(payload)}


def _role_record(snapshot: Mapping[str, Any], role: str) -> dict[str, Any]:
    files = snapshot.get("files")
    if not isinstance(files, list):
        raise AttestationV3Error("attestation snapshot has no file inventory")
    matches = [
        record
        for record in files
        if isinstance(record, dict)
        and isinstance(record.get("roles"), list)
        and role in record["roles"]
    ]
    if len(matches) != 1:
        raise AttestationV3Error(f"snapshot must contain exactly one {role}")
    return matches[0]


def _validate_equal_second_pid_exit(
    *,
    expectation: dict[str, Any],
    snapshot: dict[str, Any],
    pid_is_live_fn: Callable[[int], bool],
) -> tuple[int, dict[str, Any]]:
    """Validate only the preregistered equal-second incident class."""

    pid_record = _role_record(snapshot, "wrapper_pid_file")
    exit_record = _role_record(snapshot, "wrapper_exit_file")
    manifest_record = _role_record(snapshot, "formal_manifest")
    decision_record = _role_record(snapshot, "formal_decision")
    durable_root = Path(expectation["durable_attempt_root"])
    pid_bytes = v1._read_opaque_bytes(
        Path(pid_record["path"]), permitted_roots=(durable_root,)
    )
    exit_bytes = v1._read_opaque_bytes(
        Path(exit_record["path"]), permitted_roots=(durable_root,)
    )
    if v1._PID_BYTES_RE.fullmatch(pid_bytes) is None:
        raise AttestationV3Error("wrapper PID file is not canonical ASCII")
    try:
        pid = int(pid_bytes.rstrip(b"\n").decode("ascii"), 10)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AttestationV3Error("wrapper PID file is not ASCII") from exc
    if pid != expectation["wrapper_pid"]:
        raise AttestationV3Error("wrapper PID differs from launch expectation")
    if pid_record["sha256"] != expectation["pid_file_sha256_at_registration"]:
        raise AttestationV3Error("wrapper PID bytes changed after registration")
    if exit_bytes != CANONICAL_ZERO_EXIT:
        raise AttestationV3Error("wrapper exit file is not exact zero-newline bytes")

    manifest_ns = manifest_record["mtime_ns"]
    decision_ns = decision_record["mtime_ns"]
    exit_ns = exit_record["mtime_ns"]
    if not (
        isinstance(manifest_ns, int)
        and not isinstance(manifest_ns, bool)
        and isinstance(decision_ns, int)
        and not isinstance(decision_ns, bool)
        and isinstance(exit_ns, int)
        and not isinstance(exit_ns, bool)
        and manifest_ns < decision_ns == exit_ns
        and decision_ns % 1_000_000_000 == 0
        and exit_ns % 1_000_000_000 == 0
        and exit_record["size_bytes"] == len(CANONICAL_ZERO_EXIT)
        and exit_record["sha256"] == CANONICAL_ZERO_EXIT_SHA256
    ):
        raise AttestationV3Error(
            "formal outputs are outside the exact equal-second incident"
        )
    if pid_is_live_fn(pid):
        raise AttestationV3Error("registered wrapper PID is still live")
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
        "exit_after_outputs_status": PID_EXIT_TIE_STATUS,
    }


@contextmanager
def _capture_v1_attestation_as_v3(
    *,
    stage_extra_inputs: Mapping[str, Path],
) -> Iterable[dict[str, Any]]:
    captured: dict[str, Any] = {}

    def plan_adapter(**kwargs: Any):
        inputs = dict(kwargs["expected_inputs"])
        if set(inputs).intersection(stage_extra_inputs):
            raise AttestationV3Error("V3 stage input names collide with V1 inputs")
        inputs.update(stage_extra_inputs)
        kwargs["expected_inputs"] = inputs
        return execution_v3.load_and_validate_execution_plan_stage(**kwargs)

    def capture_publish(path: Path, payload: bytes) -> None:
        if captured:
            raise AttestationV3Error("V1 engine attempted multiple publications")
        captured["path"] = path
        captured["payload"] = payload

    replacements = {
        "PROTOCOL": PROTOCOL,
        "SCHEMA_VERSION": SCHEMA_VERSION,
        "PROCESS_AUDIT_KEYS": seal_v2.PROCESS_AUDIT_KEYS,
        "load_and_validate_execution_plan_stage": plan_adapter,
        "_validate_pid_exit": _validate_equal_second_pid_exit,
        "_atomic_publish_no_overwrite": capture_publish,
    }
    previous = {name: getattr(v1, name) for name in replacements}
    try:
        for name, item in replacements.items():
            setattr(v1, name, item)
        yield captured
    finally:
        for name, item in previous.items():
            setattr(v1, name, item)


def _validate_control_chain(
    *,
    execution_plan_path: Path,
    base_v2_execution_plan_path: Path,
    base_v2_detached_receipt_path: Path,
    base_v2_procfs_exception_inventory_path: Path,
    v2_failure_closure_path: Path,
    completion_fence_path: Path,
    detached_launch_receipt_path: Path,
) -> dict[str, Any]:
    """Single adapter for the transport module's authoritative chain API."""

    chain = execution_v3.validate_authoritative_v3_control_chain(
        execution_plan_path=execution_plan_path,
        base_v2_execution_plan_path=base_v2_execution_plan_path,
        base_v2_detached_receipt_path=base_v2_detached_receipt_path,
        base_v2_procfs_exception_inventory_path=(
            base_v2_procfs_exception_inventory_path
        ),
        v2_failure_closure_path=v2_failure_closure_path,
        completion_fence_path=completion_fence_path,
        detached_launch_receipt_path=detached_launch_receipt_path,
    )
    required = {
        "base_v2_detached_receipt",
        "base_v2_detached_receipt_raw",
        "base_v2_execution_plan",
        "base_v2_execution_plan_raw",
        "base_v2_procfs_exception_inventory",
        "base_v2_procfs_exception_inventory_raw",
        "closure",
        "closure_raw",
        "fence",
        "fence_inventory_files",
        "fence_raw",
        "plan",
        "plan_raw",
        "receipt",
        "receipt_raw",
        "semantic_open_sentinel",
    }
    if not isinstance(chain, dict) or not required.issubset(chain):
        raise AttestationV3Error("authoritative V3 control-chain schema differs")
    for key in (
        "base_v2_detached_receipt_raw",
        "base_v2_execution_plan_raw",
        "base_v2_procfs_exception_inventory_raw",
        "closure_raw",
        "fence_raw",
        "plan_raw",
        "receipt_raw",
    ):
        if not isinstance(chain[key], bytes) or not chain[key]:
            raise AttestationV3Error(f"authoritative V3 {key} is not frozen bytes")
    for key in (
        "base_v2_detached_receipt",
        "base_v2_execution_plan",
        "base_v2_procfs_exception_inventory",
        "closure",
        "fence",
        "plan",
        "receipt",
    ):
        if not isinstance(chain[key], dict):
            raise AttestationV3Error(f"authoritative V3 {key} is not a document")
    if (
        chain["semantic_open_sentinel"] != CONTROL_CHAIN_SENTINEL
        or chain["plan"].get("outcome_blind") is not True
        or chain["plan"].get("semantic_artifacts_opened") is not False
        or chain["closure"].get("outcome_blind") is not True
        or chain["closure"].get("semantic_artifacts_opened") is not False
        or chain["fence"].get("outcome_blind") is not True
        or chain["fence"].get("semantic_artifacts_opened") is not False
        or chain["receipt"].get("outcome_blind") is not True
        or chain["receipt"].get("semantic_artifacts_opened") is not False
        or not isinstance(chain["fence_inventory_files"], list)
    ):
        raise AttestationV3Error("authoritative V3 semantic-open boundary differs")
    return chain


def _validate_base_exception_inventory(
    *,
    raw: bytes,
    launch_expectation_path: Path,
    launch_expectation_raw: bytes,
    expectation: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    value = seal_v2._strict_json_bytes(raw, "base V2 procfs exception inventory")
    return seal_v2.validate_exception_inventory(
        value,
        launch_expectation_path=launch_expectation_path,
        launch_expectation_sha256=_sha256(launch_expectation_raw),
        wrapper_pid=expectation["wrapper_pid"],
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
    )


def _completion_proof(
    attestation: Mapping[str, Any], fence_sha256: str
) -> dict[str, Any]:
    snapshots = attestation.get("snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != 2:
        raise AttestationV3Error("V3 attestation does not contain two snapshots")
    manifest = _role_record(snapshots[0], "formal_manifest")
    decision = _role_record(snapshots[0], "formal_decision")
    wrapper_exit = _role_record(snapshots[0], "wrapper_exit_file")
    proof = {
        "completion_fence_sha256": fence_sha256,
        "completion_method": COMPLETION_METHOD,
        "formal_decision_mtime_ns": decision["mtime_ns"],
        "formal_manifest_mtime_ns": manifest["mtime_ns"],
        "historical_exit_order_claimed": False,
        "legacy_strict_mtime_proof": False,
        "mtime_relation": MTIME_RELATION,
        "wrapper_exit_exact_zero_newline": True,
        "wrapper_exit_mtime_ns": wrapper_exit["mtime_ns"],
        "wrapper_pid_dead": True,
    }
    if set(proof) != COMPLETION_PROOF_KEYS or not (
        proof["formal_manifest_mtime_ns"]
        < proof["formal_decision_mtime_ns"]
        == proof["wrapper_exit_mtime_ns"]
        and proof["formal_decision_mtime_ns"] % 1_000_000_000 == 0
        and wrapper_exit["sha256"] == CANONICAL_ZERO_EXIT_SHA256
        and wrapper_exit["size_bytes"] == len(CANONICAL_ZERO_EXIT)
    ):
        raise AttestationV3Error(
            "V3 completion proof differs from equal-second contract"
        )
    return proof


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_sha256(value: Any, label: str) -> str:
    try:
        return seal_v2._require_sha256(value, label)
    except seal_v2.ExecutionSealV2Error as exc:
        raise AttestationV3Error(f"{label} is not canonical SHA-256") from exc


def _validate_snapshot_document(value: Any, *, sequence: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != v1.SNAPSHOT_KEYS:
        raise AttestationV3Error(f"V3 snapshot {sequence} schema differs")
    snapshot = copy.deepcopy(value)
    if snapshot["sequence"] != sequence:
        raise AttestationV3Error("V3 snapshot sequence differs")
    seal_v2._parse_utc(snapshot["captured_at_utc"], "V3 snapshot time")
    files = snapshot["files"]
    if not isinstance(files, list) or snapshot["file_count"] != len(files):
        raise AttestationV3Error("V3 snapshot file count differs")
    paths: list[str] = []
    inode_identities: set[tuple[int, int]] = set()
    for index, record in enumerate(files):
        if not isinstance(record, dict) or set(record) != v1.FILE_RECORD_KEYS:
            raise AttestationV3Error(f"V3 snapshot file {index} schema differs")
        path = v1._require_absolute_path(record["path"], "V3 snapshot file path")
        roles = record["roles"]
        if (
            not isinstance(roles, list)
            or not roles
            or any(not isinstance(role, str) or not role for role in roles)
            or roles != sorted(roles)
            or len(set(roles)) != len(roles)
        ):
            raise AttestationV3Error("V3 snapshot file roles differ")
        for key in ("device", "inode", "size_bytes", "mtime_ns"):
            if not _is_int(record[key]) or record[key] < 0:
                raise AttestationV3Error(f"V3 snapshot file {key} is invalid")
        if record["size_bytes"] <= 0:
            raise AttestationV3Error("V3 snapshot contains an empty file")
        _require_sha256(record["sha256"], "V3 snapshot file digest")
        identity = (record["device"], record["inode"])
        if identity in inode_identities:
            raise AttestationV3Error("V3 snapshot aliases one inode")
        inode_identities.add(identity)
        paths.append(path.as_posix())
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise AttestationV3Error("V3 snapshot paths are not sorted unique")
    if snapshot["inventory_sha256"] != seal_v2.canonical_sha256(files):
        raise AttestationV3Error("V3 snapshot inventory digest differs")
    return snapshot


def _validate_inherited_public_fields(
    attestation: Mapping[str, Any], *, durable_attempt_root: Path | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate all public V1/V2 fields without creating a legacy view."""

    seal_v2._parse_utc(attestation["completed_at_utc"], "V3 completion time")
    if attestation["registered_counts"] != v1._EXPECTED_INVENTORY:
        raise AttestationV3Error("V3 registered formal counts differ")
    launcher = attestation["expected_launcher"]
    if not isinstance(launcher, dict) or set(launcher) != v1.EXPECTED_LAUNCHER_KEYS:
        raise AttestationV3Error("V3 expected-launcher schema differs")
    for key in (
        "launch_expectation_sha256",
        "launcher_file_sha256",
        "formal_grid_file_sha256",
        "provenance_file_sha256",
        "wrapper_cmdline_sha256_at_registration",
    ):
        _require_sha256(launcher[key], f"V3 expected launcher {key}")
    try:
        seal_v2._require_commit(launcher["source_commit"], "V3 source commit")
    except seal_v2.ExecutionSealV2Error as exc:
        raise AttestationV3Error("V3 source commit is invalid") from exc
    launch_path = v1._require_absolute_path(
        launcher["launch_expectation_path"], "V3 launch expectation path"
    )

    stability = attestation["stability"]
    if not isinstance(stability, dict) or set(stability) != seal_v1.STABILITY_KEYS:
        raise AttestationV3Error("V3 stability schema differs")
    minimum = stability["minimum_interval_seconds"]
    observed = stability["observed_interval_seconds"]
    if (
        not isinstance(minimum, (int, float))
        or isinstance(minimum, bool)
        or not math.isfinite(minimum)
        or minimum < MINIMUM_STABILITY_SECONDS
        or not isinstance(observed, (int, float))
        or isinstance(observed, bool)
        or not math.isfinite(observed)
        or observed < minimum
        or stability["snapshots_identical"] is not True
    ):
        raise AttestationV3Error("V3 stability proof differs")

    snapshots = attestation["snapshots"]
    if not isinstance(snapshots, list) or len(snapshots) != 2:
        raise AttestationV3Error("V3 completion attestation needs two snapshots")
    snapshot_1 = _validate_snapshot_document(snapshots[0], sequence=1)
    snapshot_2 = _validate_snapshot_document(snapshots[1], sequence=2)
    captured_1 = seal_v2._parse_utc(
        snapshot_1["captured_at_utc"], "V3 snapshot one time"
    )
    captured_2 = seal_v2._parse_utc(
        snapshot_2["captured_at_utc"], "V3 snapshot two time"
    )
    if (
        seal_v2.canonical_bytes(snapshot_1["files"])
        != seal_v2.canonical_bytes(snapshot_2["files"])
        or snapshot_1["inventory_sha256"] != snapshot_2["inventory_sha256"]
        or (captured_2 - captured_1).total_seconds() < minimum
        or attestation["causal_pre_attestation_inventory_sha256"]
        != snapshot_1["inventory_sha256"]
    ):
        raise AttestationV3Error("V3 opaque snapshots are not stably identical")

    process = attestation["process_absence"]
    if not isinstance(process, dict) or set(process) != seal_v2.PROCESS_AUDIT_KEYS:
        raise AttestationV3Error("V3 process-audit schema differs")
    process_payload = {key: process[key] for key in process if key != "audit_sha256"}
    for key in (
        "dynamic_policy_sha256",
        "exception_inventory_sha256",
        "observed_exceptions_sha256",
    ):
        _require_sha256(process[key], f"V3 process audit {key}")
    for key in (
        "attempt_checkout_path",
        "artifact_root_path",
        "durable_attempt_root_path",
    ):
        v1._require_absolute_path(process[key], f"V3 process audit {key}")
    if (
        process["status"] != "pass"
        or process["method"] != seal_v2.PROCESS_AUDIT_METHOD
        or process["dynamic_policy_enforced"] is not True
        or not _is_int(process["observed_exception_count"])
        or process["observed_exception_count"] <= 0
        or process["audit_sha256"] != seal_v2.canonical_sha256(process_payload)
        or process["exception_inventory_sha256"]
        != attestation["procfs_exception_inventory"]["sha256"]
    ):
        raise AttestationV3Error("V3 process audit differs")

    temporary = attestation["no_live_or_temporary"]
    if not isinstance(temporary, dict) or set(temporary) != v1.TEMPORARY_AUDIT_KEYS:
        raise AttestationV3Error("V3 temporary-audit schema differs")
    temporary_payload = {
        key: temporary[key] for key in temporary if key != "audit_sha256"
    }
    roots = temporary["roots"]
    if (
        temporary["status"] != "pass"
        or temporary["forbidden_match_count"] != 0
        or not isinstance(roots, list)
        or any(not isinstance(root, str) for root in roots)
        or roots != sorted(set(roots))
        or temporary["audit_sha256"] != seal_v2.canonical_sha256(temporary_payload)
    ):
        raise AttestationV3Error("V3 temporary audit differs")
    for root in roots:
        v1._require_absolute_path(root, "V3 temporary-audit root")

    if durable_attempt_root is not None:
        durable = v1._absolute_without_following(durable_attempt_root)
        if (
            launch_path != durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME
            or process["durable_attempt_root_path"] != durable.as_posix()
            or process["artifact_root_path"]
            != (durable / "artifacts" / "cohort_causal").as_posix()
            or roots
            != sorted(
                [
                    (durable / "artifacts" / "cohort_causal").as_posix(),
                    (durable / "prep").as_posix(),
                ]
            )
        ):
            raise AttestationV3Error("V3 durable-root audit bindings differ")
    return snapshot_1, snapshot_2


def _normalized_validated_document(value: Any, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, tuple) and len(value) == 2:
        value = value[0]
    if not isinstance(value, dict):
        raise AttestationV3Error(f"{label} validator result is not a document")
    return value


def _artifact_binding_context(
    *,
    artifact_paths: Mapping[str, str] | None,
    artifact_bytes: Mapping[str, bytes] | None,
    name: str,
) -> tuple[Path | None, str | None]:
    if artifact_paths is None and artifact_bytes is None:
        return None, None
    if (
        not isinstance(artifact_paths, Mapping)
        or not isinstance(artifact_bytes, Mapping)
        or name not in artifact_paths
        or name not in artifact_bytes
        or not isinstance(artifact_bytes[name], bytes)
    ):
        raise AttestationV3Error(f"authoritative {name} context is incomplete")
    return Path(artifact_paths[name]), _sha256(artifact_bytes[name])


def _validate_static_plan_and_fresh_receipt_context(
    *,
    artifact_paths: Mapping[str, str],
    artifact_bytes: Mapping[str, bytes],
    attestation: Mapping[str, Any],
) -> None:
    """Validate immutable receipt semantics without claiming it is still live."""

    try:
        plan = execution_v3._strict_json(
            artifact_bytes["execution_plan"], "authoritative V3 execution plan"
        )
        receipt = execution_v3._strict_json(
            artifact_bytes["detached_receipt"], "authoritative fresh V3 receipt"
        )
    except (KeyError, execution_v3.CausalExecutionV3Error) as exc:
        raise AttestationV3Error("authoritative V3 plan/receipt is invalid") from exc
    if (
        execution_v3.canonical_bytes(plan) != artifact_bytes["execution_plan"]
        or execution_v3.canonical_bytes(receipt) != artifact_bytes["detached_receipt"]
        or set(plan) != execution_v3.PLAN_KEYS
        or set(receipt) != execution_v3.launcher_v3.RECEIPT_KEYS
        or plan["protocol"] != execution_v3.PLAN_PROTOCOL
        or plan["schema_version"] != execution_v3.PLAN_SCHEMA_VERSION
        or plan["status"] != execution_v3.PLAN_STATUS
        or plan["outcome_blind"] is not True
        or plan["semantic_artifacts_opened"] is not False
        or receipt["protocol"] != execution_v3.DETACHED_RECEIPT_PROTOCOL
        or receipt["schema_version"] != 1
        or receipt["status"] != "ready_to_same_pid_exec_exact_v3_attester"
        or receipt["outcome_blind"] is not True
        or receipt["semantic_artifacts_opened"] is not False
    ):
        raise AttestationV3Error("authoritative V3 plan/receipt header differs")
    plan_path = Path(artifact_paths["execution_plan"])
    receipt_path = Path(artifact_paths["detached_receipt"])
    plan_binding = {
        "path": plan_path.as_posix(),
        "sha256": _sha256(artifact_bytes["execution_plan"]),
    }
    receipt_binding = attestation["detached_launch_receipt"]
    invocation = plan.get("invocations", {}).get("attester")
    if (
        receipt["plan"] != plan_binding
        or receipt_path.as_posix() != receipt_binding["path"]
        or _sha256(artifact_bytes["detached_receipt"]) != receipt_binding["sha256"]
        or receipt["pid"] != receipt_binding["pid"]
        or receipt["process_start_ticks"] != receipt_binding["process_start_ticks"]
        or not isinstance(invocation, dict)
        or receipt["exec_argv_sha256"]
        != execution_v3.canonical_sha256(invocation.get("argv"))
        or invocation.get("outputs", {}).get("attestation")
        != artifact_paths["completion_attestation"]
    ):
        raise AttestationV3Error("fresh V3 receipt is not bound to plan/attestation")


def validate_attestation_document(
    value: Any,
    *,
    failure_closure: Any = None,
    completion_fence: Any = None,
    artifact_paths: Mapping[str, str] | None = None,
    artifact_bytes: Mapping[str, bytes] | None = None,
    durable_attempt_root: Path | None = None,
    completion_attestation_path: Path | None = None,
    execution_plan_path: Path | None = None,
    execution_plan_sha256: str | None = None,
    failure_closure_path: Path | None = None,
    failure_closure_sha256: str | None = None,
    completion_fence_path: Path | None = None,
    completion_fence_sha256: str | None = None,
    detached_receipt_path: Path | None = None,
    detached_receipt_sha256: str | None = None,
    procfs_exception_inventory_path: Path | None = None,
    procfs_exception_inventory_sha256: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Validate the public V3 truth claims without making a legacy projection."""

    if not isinstance(value, dict) or set(value) != ATTESTATION_KEYS:
        raise AttestationV3Error("V3 completion attestation schema differs")
    attestation = copy.deepcopy(value)
    context_bindings = {
        "completion_attestation": _artifact_binding_context(
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            name="completion_attestation",
        ),
        "execution_plan": _artifact_binding_context(
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            name="execution_plan",
        ),
        "failure_closure": _artifact_binding_context(
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            name="failure_closure",
        ),
        "completion_fence": _artifact_binding_context(
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            name="completion_fence",
        ),
        "detached_receipt": _artifact_binding_context(
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            name="detached_receipt",
        ),
    }
    if artifact_paths is not None or artifact_bytes is not None:
        completion_raw = artifact_bytes["completion_attestation"]  # type: ignore[index]
        if completion_raw != seal_v2.canonical_bytes(attestation):
            raise AttestationV3Error(
                "authoritative completion attestation is not canonical current bytes"
            )
    completion_attestation_path = (
        completion_attestation_path or context_bindings["completion_attestation"][0]
    )
    execution_plan_path = execution_plan_path or context_bindings["execution_plan"][0]
    execution_plan_sha256 = (
        execution_plan_sha256 or context_bindings["execution_plan"][1]
    )
    failure_closure_path = (
        failure_closure_path or context_bindings["failure_closure"][0]
    )
    failure_closure_sha256 = (
        failure_closure_sha256 or context_bindings["failure_closure"][1]
    )
    completion_fence_path = (
        completion_fence_path or context_bindings["completion_fence"][0]
    )
    completion_fence_sha256 = (
        completion_fence_sha256 or context_bindings["completion_fence"][1]
    )
    detached_receipt_path = (
        detached_receipt_path or context_bindings["detached_receipt"][0]
    )
    detached_receipt_sha256 = (
        detached_receipt_sha256 or context_bindings["detached_receipt"][1]
    )
    pid_exit = attestation["pid_exit"]
    if not isinstance(pid_exit, dict) or set(pid_exit) != seal_v1.PID_EXIT_KEYS:
        raise AttestationV3Error("V3 pid_exit schema differs")
    if (
        attestation["protocol"] != PROTOCOL
        or attestation["schema_version"] != SCHEMA_VERSION
        or attestation["status"] != "complete"
        or attestation["outcome_blind"] is not True
        or attestation["semantic_open_sentinel"] != SEMANTIC_OPEN_SENTINEL
        or pid_exit["exit_after_outputs_status"] != PID_EXIT_TIE_STATUS
        or pid_exit["exit_zero_status"] != "pass"
        or pid_exit["pid_ascii_status"] != "pass"
        or pid_exit["pid_liveness_status"] != "dead"
    ):
        raise AttestationV3Error("V3 completion attestation status differs")
    try:
        plan_path = v1._require_absolute_path(
            attestation["execution_plan_path"], "V3 execution plan path"
        )
        seal_v2._require_sha256(
            attestation["execution_plan_sha256"], "V3 execution plan SHA-256"
        )
    except (v1.AttestationError, seal_v2.ExecutionSealV2Error) as exc:
        raise AttestationV3Error("V3 execution-plan binding is invalid") from exc
    if execution_plan_path is not None and (
        plan_path != execution_plan_path
        or attestation["execution_plan_sha256"] != execution_plan_sha256
    ):
        raise AttestationV3Error("V3 attestation execution-plan binding differs")
    if durable_attempt_root is not None and plan_path != (
        v1._absolute_without_following(durable_attempt_root)
        / "control"
        / execution_v3.PLAN_FILENAME
    ):
        raise AttestationV3Error("V3 execution-plan path is not fixed")

    expected_bindings = {
        "completion_fence": (completion_fence_path, completion_fence_sha256),
        "v2_failure_closure": (failure_closure_path, failure_closure_sha256),
    }
    for name, (path, digest) in expected_bindings.items():
        binding = attestation[name]
        if not isinstance(binding, dict) or set(binding) != CONTROL_BINDING_KEYS:
            raise AttestationV3Error(f"V3 attestation {name} binding schema differs")
        try:
            v1._require_absolute_path(binding["path"], f"V3 {name} path")
            seal_v2._require_sha256(binding["sha256"], f"V3 {name} SHA-256")
        except (v1.AttestationError, seal_v2.ExecutionSealV2Error) as exc:
            raise AttestationV3Error(
                f"V3 attestation {name} binding is invalid"
            ) from exc
        if path is not None and binding != {"path": path.as_posix(), "sha256": digest}:
            raise AttestationV3Error(f"V3 attestation {name} binding differs")
    if durable_attempt_root is not None:
        durable = v1._absolute_without_following(durable_attempt_root)
        if (
            Path(attestation["completion_fence"]["path"])
            != durable / "control" / recovery_v3.COMPLETION_FENCE_FILENAME
            or Path(attestation["v2_failure_closure"]["path"])
            != durable / "control" / recovery_v3.FAILURE_CLOSURE_FILENAME
        ):
            raise AttestationV3Error("V3 recovery-control paths are not fixed")

    receipt = attestation["detached_launch_receipt"]
    if (
        not isinstance(receipt, dict)
        or set(receipt) != seal_v2.ATTESTATION_RECEIPT_BINDING_KEYS
        or not isinstance(receipt["pid"], int)
        or isinstance(receipt["pid"], bool)
        or receipt["pid"] <= 1
        or not isinstance(receipt["process_start_ticks"], int)
        or isinstance(receipt["process_start_ticks"], bool)
        or receipt["process_start_ticks"] <= 0
    ):
        raise AttestationV3Error("V3 detached receipt binding schema differs")
    try:
        v1._require_absolute_path(receipt["path"], "V3 detached receipt path")
        seal_v2._require_sha256(receipt["sha256"], "V3 detached receipt SHA-256")
    except (v1.AttestationError, seal_v2.ExecutionSealV2Error) as exc:
        raise AttestationV3Error("V3 detached receipt binding is invalid") from exc
    if detached_receipt_path is not None and (
        receipt["path"] != detached_receipt_path.as_posix()
        or receipt["sha256"] != detached_receipt_sha256
    ):
        raise AttestationV3Error("V3 detached receipt binding differs")
    if durable_attempt_root is not None and Path(receipt["path"]) != (
        v1._absolute_without_following(durable_attempt_root)
        / "control"
        / execution_v3.DETACHED_RECEIPT_FILENAME
    ):
        raise AttestationV3Error("fresh V3 detached receipt path is not fixed")

    inventory = attestation["procfs_exception_inventory"]
    if not isinstance(inventory, dict) or set(inventory) != (
        seal_v2.ATTESTATION_EXCEPTION_BINDING_KEYS
    ):
        raise AttestationV3Error("V3 procfs inventory binding schema differs")
    try:
        v1._require_absolute_path(inventory["path"], "V3 procfs inventory path")
        seal_v2._require_sha256(inventory["sha256"], "V3 procfs inventory SHA-256")
        seal_v2._require_sha256(
            inventory["inventory_sha256"], "V3 procfs content SHA-256"
        )
    except (v1.AttestationError, seal_v2.ExecutionSealV2Error) as exc:
        raise AttestationV3Error("V3 procfs inventory binding is invalid") from exc
    if procfs_exception_inventory_path is not None and (
        inventory["path"] != procfs_exception_inventory_path.as_posix()
        or inventory["sha256"] != procfs_exception_inventory_sha256
    ):
        raise AttestationV3Error("V3 procfs inventory binding differs")
    if durable_attempt_root is not None and Path(inventory["path"]) != (
        v1._absolute_without_following(durable_attempt_root)
        / "control"
        / seal_v2.EXCEPTION_INVENTORY_FILENAME
    ):
        raise AttestationV3Error("base V2 procfs inventory path is not fixed")

    snapshot_1, snapshot_2 = _validate_inherited_public_fields(
        attestation,
        durable_attempt_root=(
            None
            if durable_attempt_root is None
            else v1._absolute_without_following(durable_attempt_root)
        ),
    )

    proof = attestation["completion_proof"]
    if not isinstance(proof, dict) or set(proof) != COMPLETION_PROOF_KEYS:
        raise AttestationV3Error("V3 completion-proof schema differs")
    for key in (
        "formal_decision_mtime_ns",
        "formal_manifest_mtime_ns",
        "wrapper_exit_mtime_ns",
    ):
        if (
            not isinstance(proof[key], int)
            or isinstance(proof[key], bool)
            or proof[key] <= 0
        ):
            raise AttestationV3Error(f"V3 completion proof {key} is invalid")
    try:
        seal_v2._require_sha256(
            proof["completion_fence_sha256"], "V3 completion fence SHA-256"
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise AttestationV3Error("V3 completion fence proof digest is invalid") from exc
    if (
        proof["completion_method"] != COMPLETION_METHOD
        or proof["mtime_relation"] != MTIME_RELATION
        or proof["legacy_strict_mtime_proof"] is not False
        or proof["historical_exit_order_claimed"] is not False
        or proof["wrapper_exit_exact_zero_newline"] is not True
        or proof["wrapper_pid_dead"] is not True
        or proof["formal_manifest_mtime_ns"] >= proof["formal_decision_mtime_ns"]
        or proof["formal_decision_mtime_ns"] != proof["wrapper_exit_mtime_ns"]
        or proof["formal_decision_mtime_ns"] % 1_000_000_000 != 0
    ):
        raise AttestationV3Error("V3 completion-proof truth claims differ")
    if proof["completion_fence_sha256"] != attestation["completion_fence"][
        "sha256"
    ] or (
        completion_fence_sha256 is not None
        and proof["completion_fence_sha256"] != completion_fence_sha256
    ):
        raise AttestationV3Error("V3 completion proof does not bind the fence")

    for key in (
        "pid_file_size_bytes",
        "pid_file_mtime_ns",
        "exit_file_size_bytes",
        "exit_file_mtime_ns",
    ):
        if not _is_int(pid_exit[key]) or pid_exit[key] < 0:
            raise AttestationV3Error(f"V3 pid_exit {key} is invalid")
    for key in ("pid_file_path", "exit_file_path"):
        v1._require_absolute_path(pid_exit[key], f"V3 pid_exit {key}")
    _require_sha256(pid_exit["pid_file_sha256"], "V3 wrapper PID digest")
    _require_sha256(pid_exit["exit_file_sha256"], "V3 wrapper exit digest")
    if pid_exit["exit_file_sha256"] != CANONICAL_ZERO_EXIT_SHA256 or pid_exit[
        "exit_file_size_bytes"
    ] != len(CANONICAL_ZERO_EXIT):
        raise AttestationV3Error("V3 public exit binding is not exact zero-newline")

    for snapshot in (snapshot_1, snapshot_2):
        manifest = _role_record(snapshot, "formal_manifest")
        decision = _role_record(snapshot, "formal_decision")
        wrapper_exit = _role_record(snapshot, "wrapper_exit_file")
        wrapper_pid = _role_record(snapshot, "wrapper_pid_file")
        if (
            manifest["mtime_ns"] != proof["formal_manifest_mtime_ns"]
            or decision["mtime_ns"] != proof["formal_decision_mtime_ns"]
            or wrapper_exit["mtime_ns"] != proof["wrapper_exit_mtime_ns"]
            or wrapper_exit["mtime_ns"] != pid_exit["exit_file_mtime_ns"]
            or wrapper_exit["sha256"] != pid_exit["exit_file_sha256"]
            or wrapper_exit["size_bytes"] != pid_exit["exit_file_size_bytes"]
            or wrapper_exit["path"] != pid_exit["exit_file_path"]
            or wrapper_pid["mtime_ns"] != pid_exit["pid_file_mtime_ns"]
            or wrapper_pid["sha256"] != pid_exit["pid_file_sha256"]
            or wrapper_pid["size_bytes"] != pid_exit["pid_file_size_bytes"]
            or wrapper_pid["path"] != pid_exit["pid_file_path"]
            or not (
                manifest["mtime_ns"] < decision["mtime_ns"] == wrapper_exit["mtime_ns"]
            )
            or decision["mtime_ns"] % 1_000_000_000 != 0
        ):
            raise AttestationV3Error("V3 completion proof differs from snapshots")

    validated_fence = _normalized_validated_document(
        completion_fence, "completion fence"
    )
    validated_closure = _normalized_validated_document(
        failure_closure, "failure closure"
    )
    if validated_fence is not None:
        incident = validated_fence.get("incident")
        wrapper = validated_fence.get("wrapper")
        if (
            validated_fence.get("protocol") != recovery_v3.COMPLETION_FENCE_PROTOCOL
            or validated_fence.get("status") != recovery_v3.COMPLETION_FENCE_STATUS
            or validated_fence.get("outcome_blind") is not True
            or validated_fence.get("semantic_artifacts_opened") is not False
            or not isinstance(incident, dict)
            or not isinstance(wrapper, dict)
            or incident.get("completion_method") != proof["completion_method"]
            or incident.get("mtime_relation") != proof["mtime_relation"]
            or incident.get("manifest_mtime_ns") != proof["formal_manifest_mtime_ns"]
            or incident.get("decision_mtime_ns") != proof["formal_decision_mtime_ns"]
            or incident.get("exit_mtime_ns") != proof["wrapper_exit_mtime_ns"]
            or incident.get("legacy_strict_mtime_proof") is not False
            or incident.get("historical_exit_order_claimed") is not False
            or wrapper.get("exit_file", {}).get("sha256")
            != pid_exit["exit_file_sha256"]
            or wrapper.get("exit_file", {}).get("mtime_ns")
            != pid_exit["exit_file_mtime_ns"]
        ):
            raise AttestationV3Error("V3 attestation differs from completion fence")
    if validated_closure is not None:
        if (
            validated_closure.get("protocol") != recovery_v3.FAILURE_CLOSURE_PROTOCOL
            or validated_closure.get("status") != recovery_v3.FAILURE_CLOSURE_STATUS
            or validated_closure.get("outcome_blind") is not True
            or validated_closure.get("semantic_artifacts_opened") is not False
            or (
                validated_fence is not None
                and validated_closure.get("incident") != validated_fence.get("incident")
            )
        ):
            raise AttestationV3Error("V3 attestation failure closure differs")
    if completion_attestation_path is not None and (
        completion_attestation_path.name != ATTESTATION_FILENAME
        or completion_attestation_path.parent.name != "prep"
    ):
        raise AttestationV3Error("V3 completion attestation path is not fixed")
    if durable_attempt_root is not None and completion_attestation_path != (
        v1._absolute_without_following(durable_attempt_root)
        / "prep"
        / ATTESTATION_FILENAME
    ):
        raise AttestationV3Error("V3 completion attestation durable path differs")
    if artifact_paths is not None and artifact_bytes is not None:
        _validate_static_plan_and_fresh_receipt_context(
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            attestation=attestation,
        )
    return attestation


def _project_attestation_for_v1(
    value: Any,
    *,
    execution_plan_path: Path,
    execution_plan_sha256: str,
    expectation: dict[str, Any],
    launch_expectation_path: Path,
    launch_expectation_sha256: str,
    **validation: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build an in-memory-only legacy view; callers must never serialize it."""

    attestation = validate_attestation_document(
        value,
        execution_plan_path=execution_plan_path,
        execution_plan_sha256=execution_plan_sha256,
        **validation,
    )
    legacy = copy.deepcopy(attestation)
    for key in (
        "completion_fence",
        "completion_proof",
        "detached_launch_receipt",
        "outcome_blind",
        "procfs_exception_inventory",
        "semantic_open_sentinel",
        "v2_failure_closure",
    ):
        del legacy[key]
    legacy["protocol"] = seal_v1.ATTESTATION_PROTOCOL
    legacy["schema_version"] = 1
    legacy["pid_exit"]["exit_after_outputs_status"] = "pass"
    process = attestation["process_absence"]
    process_payload = {
        "artifact_root_path": process["artifact_root_path"],
        "attempt_checkout_path": process["attempt_checkout_path"],
        "method": "linux_procfs_cmdline_and_cwd",
        "status": "pass",
    }
    legacy["process_absence"] = {
        **process_payload,
        "audit_sha256": seal_v1._sha256(seal_v1._canonical_bytes(process_payload)),
    }
    validated, files = seal_v1._validate_attestation(
        legacy,
        execution_plan_path=execution_plan_path,
        execution_plan_sha256=execution_plan_sha256,
        expectation=copy.deepcopy(expectation),
        launch_expectation_path=launch_expectation_path,
        launch_expectation_sha256=launch_expectation_sha256,
    )
    return validated, files


def _validate_fixed_build_paths(
    *, paths: Mapping[str, Path], plan: Mapping[str, Any]
) -> Path:
    """Bind the V1 inventory engine to the exact V3 attempt topology."""

    durable = Path(plan["durable_attempt_root"])
    if (
        paths["root"] != Path(plan["causal_checkout_root"])
        or paths["execution_plan"] != durable / "control" / execution_v3.PLAN_FILENAME
        or paths["launch_expectation"]
        != durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME
        or paths["output"] != durable / "prep" / ATTESTATION_FILENAME
    ):
        raise AttestationV3Error("V3 plan, attempt roots, or output path differ")
    return durable


def build_and_publish_attestation(
    *,
    root: Path,
    execution_plan_path: Path,
    base_v2_execution_plan_path: Path,
    base_v2_detached_receipt_path: Path,
    base_v2_procfs_exception_inventory_path: Path,
    v2_failure_closure_path: Path,
    completion_fence_path: Path,
    detached_launch_receipt_path: Path,
    launch_expectation_path: Path,
    provenance_path: Path,
    provenance_details_path: Path,
    output: Path,
    stability_seconds: float = MINIMUM_STABILITY_SECONDS,
    sleep_fn: Callable[[float], None] = __import__("time").sleep,
    monotonic_fn: Callable[[], float] = __import__("time").monotonic,
    now_fn: Callable[[], str] = v1._utc_now,
    pid_is_live_fn: Callable[[int], bool] = v1._pid_is_live,
    temporary_audit_fn: Callable[..., dict[str, Any]] = v1._scan_live_or_temporary,
    boot_id_fn: Callable[[], str] = v1._current_boot_id,
    hostname_fn: Callable[[], str] = __import__("socket").gethostname,
    source_commit_fn: Callable[[Path], str] = v1._current_source_commit,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
    proc_root: Path = Path("/proc"),
    self_pid: int | None = None,
) -> dict[str, Any]:
    """Run the exact inventory engine only after the authoritative V3 chain."""

    paths = {
        "execution_plan": v1._absolute_without_following(execution_plan_path),
        "base_v2_execution_plan": v1._absolute_without_following(
            base_v2_execution_plan_path
        ),
        "base_v2_detached_receipt": v1._absolute_without_following(
            base_v2_detached_receipt_path
        ),
        "base_v2_procfs_exception_inventory": v1._absolute_without_following(
            base_v2_procfs_exception_inventory_path
        ),
        "v2_failure_closure": v1._absolute_without_following(v2_failure_closure_path),
        "completion_fence": v1._absolute_without_following(completion_fence_path),
        "detached_launch_receipt": v1._absolute_without_following(
            detached_launch_receipt_path
        ),
        "launch_expectation": v1._absolute_without_following(launch_expectation_path),
        "provenance": v1._absolute_without_following(provenance_path),
        "provenance_details": v1._absolute_without_following(provenance_details_path),
        "root": v1._absolute_without_following(root),
        "output": v1._absolute_without_following(output),
    }
    if os.path.lexists(paths["output"]):
        raise FileExistsError("refusing to overwrite V3 completion attestation")
    chain = _validate_control_chain(
        execution_plan_path=paths["execution_plan"],
        base_v2_execution_plan_path=paths["base_v2_execution_plan"],
        base_v2_detached_receipt_path=paths["base_v2_detached_receipt"],
        base_v2_procfs_exception_inventory_path=paths[
            "base_v2_procfs_exception_inventory"
        ],
        v2_failure_closure_path=paths["v2_failure_closure"],
        completion_fence_path=paths["completion_fence"],
        detached_launch_receipt_path=paths["detached_launch_receipt"],
    )
    plan = chain["plan"]
    durable = _validate_fixed_build_paths(paths=paths, plan=plan)
    expectation, expectation_raw = v1._load_launch_expectation(
        paths["launch_expectation"]
    )
    if (
        expectation["checkout_root"] != paths["root"].as_posix()
        or expectation["durable_attempt_root"] != durable.as_posix()
    ):
        raise AttestationV3Error("V3 plan and launch expectation roots differ")
    inventory_raw = chain["base_v2_procfs_exception_inventory_raw"]
    exception, records = _validate_base_exception_inventory(
        raw=inventory_raw,
        launch_expectation_path=paths["launch_expectation"],
        launch_expectation_raw=expectation_raw,
        expectation=expectation,
    )
    inventory_sha = _sha256(inventory_raw)

    def process_audit_fn(*, attempt_checkout: Path, artifact_root: Path):
        return attester_v2._scan_process_references(
            attempt_checkout=attempt_checkout,
            artifact_root=artifact_root,
            exception_records=records,
            dynamic_policy=exception["dynamic_policy"],
            dynamic_policy_sha256=exception["dynamic_policy_sha256"],
            wrapper_start_ticks=expectation["wrapper_start_ticks"],
            exception_file_sha256=inventory_sha,
            proc_root=proc_root,
            self_pid=self_pid,
        )

    extra_inputs = {
        key: paths[key]
        for key in (
            "base_v2_execution_plan",
            "base_v2_detached_receipt",
            "base_v2_procfs_exception_inventory",
            "v2_failure_closure",
            "completion_fence",
            "detached_launch_receipt",
        )
    }
    with _capture_v1_attestation_as_v3(stage_extra_inputs=extra_inputs) as captured:
        v1.build_and_publish_attestation(
            root=paths["root"],
            execution_plan_path=paths["execution_plan"],
            launch_expectation_path=paths["launch_expectation"],
            provenance_path=paths["provenance"],
            provenance_details_path=paths["provenance_details"],
            output=paths["output"],
            stability_seconds=stability_seconds,
            sleep_fn=sleep_fn,
            monotonic_fn=monotonic_fn,
            now_fn=now_fn,
            pid_is_live_fn=pid_is_live_fn,
            process_audit_fn=process_audit_fn,
            temporary_audit_fn=temporary_audit_fn,
            boot_id_fn=boot_id_fn,
            hostname_fn=hostname_fn,
            source_commit_fn=source_commit_fn,
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    if captured.get("path") != paths["output"] or not isinstance(
        captured.get("payload"), bytes
    ):
        raise AttestationV3Error("V1 terminal engine produced no captured payload")
    try:
        attestation = seal_v2._strict_json_bytes(
            captured["payload"], "captured V3 completion attestation"
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise AttestationV3Error("captured V3 attestation is not strict JSON") from exc
    if captured["payload"] != seal_v2.canonical_bytes(attestation):
        raise AttestationV3Error("captured V3 attestation is not canonical JSON")
    receipt = chain["receipt"]
    receipt_raw = chain["receipt_raw"]
    closure_raw = chain["closure_raw"]
    fence_raw = chain["fence_raw"]
    attestation["detached_launch_receipt"] = {
        "path": paths["detached_launch_receipt"].as_posix(),
        "pid": receipt["pid"],
        "process_start_ticks": receipt["process_start_ticks"],
        "sha256": _sha256(receipt_raw),
    }
    attestation["procfs_exception_inventory"] = {
        "inventory_sha256": exception["inventory_sha256"],
        "path": paths["base_v2_procfs_exception_inventory"].as_posix(),
        "sha256": inventory_sha,
    }
    attestation["v2_failure_closure"] = _binding(
        paths["v2_failure_closure"], closure_raw
    )
    attestation["completion_fence"] = _binding(paths["completion_fence"], fence_raw)
    attestation["completion_proof"] = _completion_proof(attestation, _sha256(fence_raw))
    attestation["outcome_blind"] = True
    attestation["semantic_open_sentinel"] = copy.deepcopy(SEMANTIC_OPEN_SENTINEL)
    if set(attestation) != ATTESTATION_KEYS:
        raise AssertionError("V3 attestation exact schema drift")

    final_chain = _validate_control_chain(
        execution_plan_path=paths["execution_plan"],
        base_v2_execution_plan_path=paths["base_v2_execution_plan"],
        base_v2_detached_receipt_path=paths["base_v2_detached_receipt"],
        base_v2_procfs_exception_inventory_path=paths[
            "base_v2_procfs_exception_inventory"
        ],
        v2_failure_closure_path=paths["v2_failure_closure"],
        completion_fence_path=paths["completion_fence"],
        detached_launch_receipt_path=paths["detached_launch_receipt"],
    )
    raw_keys = {
        key
        for key, item in chain.items()
        if key.endswith("_raw") and isinstance(item, bytes)
    }
    if not raw_keys or raw_keys != {
        key
        for key, item in final_chain.items()
        if key.endswith("_raw") and isinstance(item, bytes)
    }:
        raise AttestationV3Error("authoritative V3 raw-control set drifted")
    for key in raw_keys:
        if final_chain[key] != chain[key]:
            raise AttestationV3Error("authoritative V3 control chain drifted")
    if final_chain["semantic_open_sentinel"] != CONTROL_CHAIN_SENTINEL:
        raise AttestationV3Error("authoritative V3 semantic sentinel drifted")
    payload = seal_v2.canonical_bytes(attestation)
    validate_attestation_document(
        attestation,
        failure_closure=chain["closure"],
        completion_fence=chain["fence"],
        artifact_paths={
            "completion_attestation": paths["output"].as_posix(),
            "completion_fence": paths["completion_fence"].as_posix(),
            "detached_receipt": paths["detached_launch_receipt"].as_posix(),
            "execution_plan": paths["execution_plan"].as_posix(),
            "failure_closure": paths["v2_failure_closure"].as_posix(),
        },
        artifact_bytes={
            "completion_attestation": payload,
            "completion_fence": fence_raw,
            "detached_receipt": receipt_raw,
            "execution_plan": chain["plan_raw"],
            "failure_closure": closure_raw,
        },
        durable_attempt_root=durable,
        completion_attestation_path=paths["output"],
        execution_plan_path=paths["execution_plan"],
        execution_plan_sha256=_sha256(chain["plan_raw"]),
        failure_closure_path=paths["v2_failure_closure"],
        failure_closure_sha256=_sha256(closure_raw),
        completion_fence_path=paths["completion_fence"],
        completion_fence_sha256=_sha256(fence_raw),
        detached_receipt_path=paths["detached_launch_receipt"],
        detached_receipt_sha256=_sha256(receipt_raw),
        procfs_exception_inventory_path=paths["base_v2_procfs_exception_inventory"],
        procfs_exception_inventory_sha256=inventory_sha,
    )
    v1._assert_no_symlink_components(
        paths["output"].parent, (Path(expectation["durable_attempt_root"]),)
    )
    publish_chain = _validate_control_chain(
        execution_plan_path=paths["execution_plan"],
        base_v2_execution_plan_path=paths["base_v2_execution_plan"],
        base_v2_detached_receipt_path=paths["base_v2_detached_receipt"],
        base_v2_procfs_exception_inventory_path=paths[
            "base_v2_procfs_exception_inventory"
        ],
        v2_failure_closure_path=paths["v2_failure_closure"],
        completion_fence_path=paths["completion_fence"],
        detached_launch_receipt_path=paths["detached_launch_receipt"],
    )
    for key in raw_keys:
        if publish_chain[key] != chain[key]:
            raise AttestationV3Error("V3 control chain drifted before publication")
    if publish_chain["semantic_open_sentinel"] != CONTROL_CHAIN_SENTINEL:
        raise AttestationV3Error("V3 semantic sentinel drifted before publication")
    v1._atomic_publish_no_overwrite(paths["output"], payload)
    return {
        "attestation_sha256": _sha256(payload),
        "causal_pre_attestation_inventory_sha256": attestation[
            "causal_pre_attestation_inventory_sha256"
        ],
        "path": paths["output"].as_posix(),
        "status": "complete",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--base-v2-execution-plan", type=Path, required=True)
    parser.add_argument("--base-v2-detached-receipt", type=Path, required=True)
    parser.add_argument(
        "--base-v2-procfs-exception-inventory", type=Path, required=True
    )
    parser.add_argument("--v2-failure-closure", type=Path, required=True)
    parser.add_argument("--completion-fence", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--provenance-details", type=Path, required=True)
    parser.add_argument("--detached-launch-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stability-seconds", type=float, default=1.0)
    args = parser.parse_args()
    try:
        result = build_and_publish_attestation(
            root=args.root,
            execution_plan_path=args.execution_plan,
            base_v2_execution_plan_path=args.base_v2_execution_plan,
            base_v2_detached_receipt_path=args.base_v2_detached_receipt,
            base_v2_procfs_exception_inventory_path=(
                args.base_v2_procfs_exception_inventory
            ),
            v2_failure_closure_path=args.v2_failure_closure,
            completion_fence_path=args.completion_fence,
            detached_launch_receipt_path=args.detached_launch_receipt,
            launch_expectation_path=args.launch_expectation,
            provenance_path=args.provenance,
            provenance_details_path=args.provenance_details,
            output=args.output,
            stability_seconds=args.stability_seconds,
        )
    except (
        AttestationV3Error,
        execution_v3.CausalExecutionV3Error,
        recovery_v3.RecoveryV3Error,
        v1.AttestationError,
        seal_v1.ExecutionSealError,
        seal_v2.ExecutionSealV2Error,
        FileExistsError,
    ):
        # Completion failure text is intentionally suppressed at the formal edge.
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
