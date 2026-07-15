#!/usr/bin/env python3
"""Revalidate the V3 equal-second terminal through the unchanged V1 engine.

The V3 recovery controls are validated before the formal manifest or decision
is semantically opened.  V1's statistical reconstruction remains unchanged;
only its control adapters, equal-second PID/exit gate, and publication sink are
temporarily replaced.  The legacy receipt is retained only as private in-memory
evidence and is represented publicly by its SHA-256 digest.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable, Mapping, Sequence

import attest_cohort_causal_completion as completion_v1
import revalidate_cohort_causal_terminal as v1


PROTOCOL = "cohort_causal_terminal_revalidation_receipt_v3"
SCHEMA_VERSION = 3
REVALIDATED_FILENAME = "causal_formal.revalidated.v3.json"
RECEIPT_FILENAME = "causal_formal.revalidation_receipt.v3.json"
ATTESTATION_FILENAME = "causal_trigger_completion_attestation.v3.json"
FAILURE_CLOSURE_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V2_FAILURE_CLOSURE_V1.json"
COMPLETION_FENCE_FILENAME = "CAUSAL_TERMINAL_VERIFIER_COMPLETION_FENCE_V3.json"

COMPLETION_METHOD = "post-wrapper-death two-snapshot fence"
MTIME_RELATION = "formal_manifest_before_formal_decision_equal_wrapper_exit"
LEGACY_STRICT_MTIME_PROOF = False
HISTORICAL_EXIT_ORDER_CLAIMED = False
LEGACY_PUBLICATION = False

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_PID_RE = re.compile(rb"[1-9][0-9]*\n\Z")
_BINDING_KEYS = frozenset({"path", "sha256"})
_RECEIPT_KEYS = frozenset(
    {
        "completion_attestation",
        "completion_fence",
        "completion_method",
        "decision",
        "decision_scope",
        "execution_plan",
        "formal_decision",
        "formal_manifest",
        "historical_exit_order_claimed",
        "legacy_publication",
        "legacy_strict_mtime_proof",
        "mtime_relation",
        "private_legacy_receipt_sha256",
        "protocol",
        "revalidated_decision",
        "revalidated_decision_byte_identical",
        "schema_version",
        "status",
        "v2_failure_closure",
    }
)


class RevalidationV3Error(v1.RevalidationError):
    """A fail-closed V3 control, compatibility, or publication failure."""


@dataclass(frozen=True)
class _ControlContext:
    plan: dict[str, Any]
    plan_raw: bytes
    closure: dict[str, Any]
    closure_raw: bytes
    fence: dict[str, Any]
    fence_raw: bytes
    attestation: dict[str, Any]
    attestation_raw: bytes
    projected_v1_attestation: dict[str, Any]
    attested_files: list[dict[str, Any]]
    expectation: dict[str, Any]
    expectation_raw: bytes


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _normalized_absolute(path: str | Path, *, label: str) -> Path:
    candidate = Path(path).expanduser()
    text = os.fspath(candidate)
    if (
        not candidate.is_absolute()
        or ".." in candidate.parts
        or os.path.normpath(text) != text
    ):
        raise RevalidationV3Error(f"{label} is not normalized absolute")
    return candidate


def _binding(path: Path, payload: bytes) -> dict[str, str]:
    return {"path": path.as_posix(), "sha256": _sha256(payload)}


def _validate_binding(value: Any, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _BINDING_KEYS:
        raise RevalidationV3Error(f"{label} binding schema differs")
    path = _normalized_absolute(value["path"], label=f"{label} path")
    if not _is_sha256(value["sha256"]):
        raise RevalidationV3Error(f"{label} binding digest differs")
    return {"path": path.as_posix(), "sha256": value["sha256"]}


def _strict_control(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    raw, _ = v1._read_stable_file(path)
    value = v1._load_json_bytes(raw, label=label)
    if not isinstance(value, dict) or v1._canonical_bytes(value) != raw:
        raise RevalidationV3Error(f"{label} is not canonical JSON")
    return value, raw


def _load_v3_modules() -> tuple[ModuleType, ModuleType, ModuleType]:
    """Lazily import the V3 modules so an incomplete deployment fails closed."""

    try:
        execution = importlib.import_module("build_cohort_causal_terminal_execution_v3")
        recovery = importlib.import_module("freeze_cohort_causal_terminal_recovery_v3")
        attester = importlib.import_module("attest_cohort_causal_completion_v3")
    except (ImportError, SyntaxError) as exc:
        raise RevalidationV3Error("authoritative V3 modules are unavailable") from exc
    return execution, recovery, attester


def _record_for_role(
    files: Iterable[Mapping[str, Any]], role: str
) -> Mapping[str, Any]:
    matches = [record for record in files if role in record.get("roles", ())]
    if len(matches) != 1:
        raise RevalidationV3Error(f"inventory needs exactly one {role}")
    return matches[0]


def _pid_is_dead(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _validate_equal_second_current_gate(
    *,
    attestation: Mapping[str, Any],
    inventory: Mapping[str, Mapping[str, Any]],
    formal_manifest: Path,
    formal_decision: Path,
    expected_wrapper_pid: int | None = None,
) -> None:
    """Re-prove the exact equal-second class against current opaque bytes."""

    proof = attestation.get("completion_proof")
    pid_exit = attestation.get("pid_exit")
    files = attestation.get("snapshots", [{}])[0].get("files", [])
    if not isinstance(proof, dict) or not isinstance(pid_exit, dict):
        raise RevalidationV3Error("V3 completion proof is unavailable")
    pid_record = _record_for_role(files, "wrapper_pid_file")
    exit_record = _record_for_role(files, "wrapper_exit_file")
    manifest_record = _record_for_role(files, "formal_manifest")
    decision_record = _record_for_role(files, "formal_decision")
    if (
        Path(manifest_record["path"]) != formal_manifest
        or Path(decision_record["path"]) != formal_decision
    ):
        raise RevalidationV3Error("formal paths differ from V3 completion proof")

    for record in (pid_record, exit_record, manifest_record, decision_record):
        current = inventory.get(record["path"])
        if current is None or v1._canonical_bytes(current) != v1._canonical_bytes(
            record
        ):
            raise RevalidationV3Error("current inventory differs from V3 attestation")

    pid_path = Path(pid_record["path"])
    exit_path = Path(exit_record["path"])
    pid_raw, pid_stat = v1._read_stable_file(pid_path)
    exit_raw, exit_stat = v1._read_stable_file(exit_path)
    if _PID_RE.fullmatch(pid_raw) is None:
        raise RevalidationV3Error("wrapper PID is not canonical positive ASCII")
    pid = int(pid_raw[:-1].decode("ascii"), 10)
    if pid <= 1 or (expected_wrapper_pid is not None and pid != expected_wrapper_pid):
        raise RevalidationV3Error("wrapper PID differs from registered identity")
    if exit_raw != b"0\n":
        raise RevalidationV3Error("wrapper exit is not exact zero-newline")
    if not _pid_is_dead(pid):
        raise RevalidationV3Error("registered wrapper PID is currently live")

    for prefix, raw, metadata, record in (
        ("pid", pid_raw, pid_stat, pid_record),
        ("exit", exit_raw, exit_stat, exit_record),
    ):
        if (
            pid_exit.get(f"{prefix}_file_path") != record["path"]
            or pid_exit.get(f"{prefix}_file_sha256") != _sha256(raw)
            or pid_exit.get(f"{prefix}_file_size_bytes") != metadata.st_size
            or pid_exit.get(f"{prefix}_file_mtime_ns") != metadata.st_mtime_ns
        ):
            raise RevalidationV3Error(f"current {prefix} binding differs")

    manifest_ns = manifest_record["mtime_ns"]
    decision_ns = decision_record["mtime_ns"]
    exit_ns = exit_record["mtime_ns"]
    if not (
        manifest_ns < decision_ns == exit_ns
        and decision_ns % 1_000_000_000 == 0
        and proof.get("formal_manifest_mtime_ns") == manifest_ns
        and proof.get("formal_decision_mtime_ns") == decision_ns
        and proof.get("wrapper_exit_mtime_ns") == exit_ns
        and proof.get("completion_method") == COMPLETION_METHOD
        and proof.get("mtime_relation") == MTIME_RELATION
        and proof.get("legacy_strict_mtime_proof") is False
        and proof.get("historical_exit_order_claimed") is False
        and proof.get("wrapper_exit_exact_zero_newline") is True
        and proof.get("wrapper_pid_dead") is True
        and pid_exit.get("exit_after_outputs_status") == "not_proven_equal_second"
        and pid_exit.get("exit_zero_status") == "pass"
        and pid_exit.get("pid_ascii_status") == "pass"
        and pid_exit.get("pid_liveness_status") == "dead"
    ):
        raise RevalidationV3Error(
            "current state is outside the exact equal-second class"
        )


def _validate_revalidator_control_chain(
    *,
    execution: ModuleType,
    recovery: ModuleType,
    attester: ModuleType,
    root: Path,
    execution_plan_path: Path,
    failure_closure_path: Path,
    completion_fence_path: Path,
    attestation_path: Path,
    launch_expectation_path: Path,
    grid_path: Path,
    provenance_path: Path,
    formal_manifest_path: Path,
    formal_decision_path: Path,
    preregistration_path: Path,
    statistical_addendum_path: Path,
    revalidated_output: Path,
    receipt_output: Path,
    actual_argv: Sequence[str] | None,
    runtime_python_path: str | None,
    runtime_python_version: str | None,
) -> _ControlContext:
    """Validate the complete static V3 chain without the attester live-PID API."""

    expected_inputs = {
        "execution_plan": execution_plan_path,
        "v2_failure_closure": failure_closure_path,
        "completion_fence": completion_fence_path,
        "root": root,
        "attestation": attestation_path,
        "launch_expectation": launch_expectation_path,
        "grid": grid_path,
        "provenance": provenance_path,
        "formal_manifest": formal_manifest_path,
        "formal_decision": formal_decision_path,
        "preregistration": preregistration_path,
        "statistical_addendum": statistical_addendum_path,
    }
    try:
        plan, plan_raw = execution.load_and_validate_execution_plan_stage(
            execution_plan_path=execution_plan_path,
            stage="revalidator",
            expected_inputs=expected_inputs,
            expected_outputs={
                "revalidated_decision": revalidated_output,
                "revalidation_receipt": receipt_output,
            },
            expected_parameters={},
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    except Exception as exc:
        raise RevalidationV3Error("V3 revalidator execution plan is invalid") from exc

    try:
        expectation, expectation_raw = completion_v1._load_launch_expectation(
            launch_expectation_path
        )
    except Exception as exc:
        raise RevalidationV3Error("launch expectation is invalid") from exc
    durable = Path(expectation["durable_attempt_root"])
    closure, closure_raw = _strict_control(
        failure_closure_path, label="V2 failure closure"
    )
    try:
        closure = recovery.validate_failure_closure_document(
            closure,
            durable_attempt_root=durable,
            expected_path=failure_closure_path,
        )
    except Exception as exc:
        raise RevalidationV3Error("V2 failure closure is invalid") from exc
    fence, fence_raw = _strict_control(
        completion_fence_path, label="V3 completion fence"
    )
    try:
        fence, fence_files = recovery.validate_completion_fence_document(
            fence,
            durable_attempt_root=durable,
            expected_path=completion_fence_path,
            failure_closure_path=failure_closure_path,
            failure_closure_sha256=_sha256(closure_raw),
        )
    except Exception as exc:
        raise RevalidationV3Error("V3 completion fence is invalid") from exc

    attestation, attestation_raw = _strict_control(
        attestation_path, label="V3 completion attestation"
    )
    plan_sha = _sha256(plan_raw)
    try:
        preliminary_attestation = attester.validate_attestation_document(
            attestation,
            failure_closure=closure,
            completion_fence=fence,
            durable_attempt_root=durable,
            completion_attestation_path=attestation_path,
            execution_plan_path=execution_plan_path,
            execution_plan_sha256=plan_sha,
            failure_closure_path=failure_closure_path,
            failure_closure_sha256=_sha256(closure_raw),
            completion_fence_path=completion_fence_path,
            completion_fence_sha256=_sha256(fence_raw),
        )

        base_v2 = plan["base_v2"]
        base = execution._load_base_v2_controls(
            durable_root=durable,
            plan_path=Path(base_v2["execution_plan"]["path"]),
            receipt_path=Path(base_v2["detached_receipt"]["path"]),
            inventory_path=Path(base_v2["procfs_exception_inventory"]["path"]),
        )
        base_inventory = base["base_v2_procfs_exception_inventory"]
        base_inventory_raw = base["base_v2_procfs_exception_inventory_raw"]
        base_inventory_path = Path(base_v2["procfs_exception_inventory"]["path"])
        detached_receipt_path = Path(
            preliminary_attestation["detached_launch_receipt"]["path"]
        )
        detached_receipt, detached_receipt_raw = (
            execution.validate_detached_receipt_static_document(
                path=detached_receipt_path,
                plan=plan,
                plan_raw=plan_raw,
                expected_runtime_namespace=base_inventory["runtime_namespace"],
            )
        )
        artifact_paths = {
            "completion_attestation": attestation_path.as_posix(),
            "completion_fence": completion_fence_path.as_posix(),
            "detached_receipt": detached_receipt_path.as_posix(),
            "execution_plan": execution_plan_path.as_posix(),
            "failure_closure": failure_closure_path.as_posix(),
        }
        artifact_bytes = {
            "completion_attestation": attestation_raw,
            "completion_fence": fence_raw,
            "detached_receipt": detached_receipt_raw,
            "execution_plan": plan_raw,
            "failure_closure": closure_raw,
        }
        validated_attestation = attester.validate_attestation_document(
            preliminary_attestation,
            failure_closure=closure,
            completion_fence=fence,
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            durable_attempt_root=durable,
            completion_attestation_path=attestation_path,
            execution_plan_path=execution_plan_path,
            execution_plan_sha256=plan_sha,
            failure_closure_path=failure_closure_path,
            failure_closure_sha256=_sha256(closure_raw),
            completion_fence_path=completion_fence_path,
            completion_fence_sha256=_sha256(fence_raw),
            detached_receipt_path=detached_receipt_path,
            detached_receipt_sha256=_sha256(detached_receipt_raw),
            procfs_exception_inventory_path=base_inventory_path,
            procfs_exception_inventory_sha256=_sha256(base_inventory_raw),
        )
        if (
            detached_receipt["pid"]
            != validated_attestation["detached_launch_receipt"]["pid"]
            or detached_receipt["process_start_ticks"]
            != validated_attestation["detached_launch_receipt"]["process_start_ticks"]
        ):
            raise RevalidationV3Error("V3 detached receipt identity binding differs")
        projected, files = attester._project_attestation_for_v1(
            validated_attestation,
            failure_closure=closure,
            completion_fence=fence,
            durable_attempt_root=durable,
            execution_plan_path=execution_plan_path,
            execution_plan_sha256=plan_sha,
            expectation=expectation,
            launch_expectation_path=launch_expectation_path,
            launch_expectation_sha256=_sha256(expectation_raw),
            completion_attestation_path=attestation_path,
            failure_closure_path=failure_closure_path,
            failure_closure_sha256=_sha256(closure_raw),
            completion_fence_path=completion_fence_path,
            completion_fence_sha256=_sha256(fence_raw),
        )
    except Exception as exc:
        raise RevalidationV3Error("V3 completion attestation is invalid") from exc

    fence_by_path = {record["path"]: record for record in fence_files}
    if len(fence_by_path) != len(fence_files) or any(
        record["path"] not in fence_by_path
        or v1._canonical_bytes(record)
        != v1._canonical_bytes(fence_by_path[record["path"]])
        for record in files
    ):
        raise RevalidationV3Error(
            "V3 attestation inventory differs from completion fence"
        )

    current = v1._verify_current_inventory(files)
    v1._require_inventory_paths(
        current,
        {
            launch_expectation_path,
            grid_path,
            provenance_path,
            formal_manifest_path,
            formal_decision_path,
            preregistration_path,
            statistical_addendum_path,
        },
        label="V3 revalidation inputs",
    )
    _validate_equal_second_current_gate(
        attestation=validated_attestation,
        inventory=current,
        formal_manifest=formal_manifest_path,
        formal_decision=formal_decision_path,
        expected_wrapper_pid=expectation["wrapper_pid"],
    )
    return _ControlContext(
        plan=copy.deepcopy(plan),
        plan_raw=plan_raw,
        closure=copy.deepcopy(closure),
        closure_raw=closure_raw,
        fence=copy.deepcopy(fence),
        fence_raw=fence_raw,
        attestation=copy.deepcopy(validated_attestation),
        attestation_raw=attestation_raw,
        projected_v1_attestation=copy.deepcopy(projected),
        attested_files=copy.deepcopy(files),
        expectation=copy.deepcopy(expectation),
        expectation_raw=expectation_raw,
    )


@contextmanager
def _v1_revalidation_engine_as_v3(
    *,
    context: _ControlContext,
    execution: ModuleType,
    execution_plan_path: Path,
    failure_closure_path: Path,
    completion_fence_path: Path,
    revalidated_output: Path,
    receipt_output: Path,
) -> Iterable[dict[str, Any]]:
    """Install private V3 projections and capture V1's publication pair."""

    captured: dict[str, Any] = {}
    public_attestation = v1._canonical_bytes(context.attestation)
    projected_attestation = v1._canonical_bytes(context.projected_v1_attestation)

    def plan_adapter(**kwargs: Any):
        inputs = dict(kwargs["expected_inputs"])
        inputs.update(
            {
                "v2_failure_closure": failure_closure_path,
                "completion_fence": completion_fence_path,
            }
        )
        kwargs["expected_inputs"] = inputs
        result = execution.load_and_validate_execution_plan_stage(**kwargs)
        if result[1] != context.plan_raw:
            raise RevalidationV3Error("V3 execution plan drifted at engine entry")
        return result

    def attestation_adapter(value: Any):
        if v1._canonical_bytes(value) != public_attestation:
            raise RevalidationV3Error("V3 attestation drifted at engine entry")
        if (
            v1._canonical_bytes(context.projected_v1_attestation)
            != projected_attestation
        ):
            raise RevalidationV3Error("private V1 attestation projection drifted")
        return (
            copy.deepcopy(context.projected_v1_attestation),
            copy.deepcopy(context.attested_files),
        )

    def equal_second_adapter(
        *,
        attestation: Mapping[str, Any],
        inventory: Mapping[str, Mapping[str, Any]],
        formal_manifest: Path,
        formal_decision: Path,
    ) -> None:
        if v1._canonical_bytes(attestation) != projected_attestation:
            raise RevalidationV3Error("V1 engine received a foreign projection")
        _validate_equal_second_current_gate(
            attestation=context.attestation,
            inventory=inventory,
            formal_manifest=formal_manifest,
            formal_decision=formal_decision,
            expected_wrapper_pid=context.expectation["wrapper_pid"],
        )

    def capture_pair(outputs: list[tuple[Path, bytes]]) -> None:
        if captured:
            raise RevalidationV3Error("V1 engine attempted multiple publications")
        if len(outputs) != 2 or [path for path, _ in outputs] != [
            revalidated_output,
            receipt_output,
        ]:
            raise RevalidationV3Error("V1 engine publication paths differ")
        if any(not isinstance(payload, bytes) for _, payload in outputs):
            raise RevalidationV3Error("V1 engine publication payload differs")
        captured["decision"] = outputs[0][1]
        captured["legacy_receipt"] = outputs[1][1]

    replacements = {
        "load_and_validate_execution_plan_stage": plan_adapter,
        "_validate_attestation": attestation_adapter,
        "_validate_pid_exit_gate": equal_second_adapter,
        "_publish_pair_no_overwrite": capture_pair,
        "REVALIDATED_FILENAME": REVALIDATED_FILENAME,
        "RECEIPT_FILENAME": RECEIPT_FILENAME,
    }
    previous = {name: getattr(v1, name) for name in replacements}
    try:
        for name, value in replacements.items():
            setattr(v1, name, value)
        yield captured
    finally:
        for name, value in previous.items():
            setattr(v1, name, value)


def _same_control_context(first: _ControlContext, second: _ControlContext) -> bool:
    return all(
        getattr(first, name) == getattr(second, name)
        for name in (
            "plan_raw",
            "closure_raw",
            "fence_raw",
            "attestation_raw",
            "expectation_raw",
        )
    ) and v1._canonical_bytes(first.attested_files) == v1._canonical_bytes(
        second.attested_files
    )


def _expected_receipt_binding(
    *,
    value: Mapping[str, Any],
    key: str,
    expected_path: Path,
    expected_payload: bytes | None = None,
) -> None:
    binding = value[key]
    if binding["path"] != expected_path.as_posix():
        raise RevalidationV3Error(f"{key} path differs")
    if expected_payload is not None and binding["sha256"] != _sha256(expected_payload):
        raise RevalidationV3Error(f"{key} digest differs")


def validate_revalidation_receipt_document(
    value: Any,
    *,
    durable_attempt_root: Path | None = None,
    artifact_bytes: Mapping[str, bytes] | None = None,
    artifact_paths: Mapping[str, str] | None = None,
    execution_plan_path: Path | None = None,
    execution_plan_sha256: str | None = None,
    failure_closure_path: Path | None = None,
    failure_closure_sha256: str | None = None,
    completion_fence_path: Path | None = None,
    completion_fence_sha256: str | None = None,
    completion_attestation_path: Path | None = None,
    completion_attestation_sha256: str | None = None,
    formal_manifest_path: Path | None = None,
    formal_decision_path: Path | None = None,
    revalidated_decision_path: Path | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Validate the exact public V3 receipt and all available byte bindings."""

    if not isinstance(value, dict) or set(value) != _RECEIPT_KEYS:
        raise RevalidationV3Error("V3 revalidation receipt schema differs")
    receipt = copy.deepcopy(value)
    for key in (
        "execution_plan",
        "v2_failure_closure",
        "completion_fence",
        "completion_attestation",
        "formal_manifest",
        "formal_decision",
        "revalidated_decision",
    ):
        receipt[key] = _validate_binding(receipt[key], label=key)
    if (
        receipt["protocol"] != PROTOCOL
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["status"] != "valid"
        or (receipt["decision"], receipt["decision_scope"])
        not in {
            ("pass", "internal_gate_pass"),
            ("valid_no_go", "internal_gate_no_go"),
        }
        or receipt["completion_method"] != COMPLETION_METHOD
        or receipt["mtime_relation"] != MTIME_RELATION
        or receipt["legacy_strict_mtime_proof"] is not False
        or receipt["historical_exit_order_claimed"] is not False
        or receipt["legacy_publication"] is not False
        or receipt["revalidated_decision_byte_identical"] is not True
        or receipt["revalidated_decision"]["sha256"]
        != receipt["formal_decision"]["sha256"]
        or not _is_sha256(receipt["private_legacy_receipt_sha256"])
    ):
        raise RevalidationV3Error("V3 revalidation receipt truth fields differ")

    if durable_attempt_root is not None:
        durable = _normalized_absolute(
            durable_attempt_root, label="durable attempt root"
        )
        fixed = {
            "execution_plan": durable
            / "control"
            / "CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V3.json",
            "v2_failure_closure": durable / "control" / FAILURE_CLOSURE_FILENAME,
            "completion_fence": durable / "control" / COMPLETION_FENCE_FILENAME,
            "completion_attestation": durable / "prep" / ATTESTATION_FILENAME,
            "formal_manifest": durable / "artifacts/cohort_causal/formal_manifest.json",
            "formal_decision": durable / "artifacts/cohort_causal/formal_decision.json",
            "revalidated_decision": durable / "prep" / REVALIDATED_FILENAME,
        }
        for key, path in fixed.items():
            _expected_receipt_binding(value=receipt, key=key, expected_path=path)

    explicit_paths = {
        "execution_plan": execution_plan_path,
        "v2_failure_closure": failure_closure_path,
        "completion_fence": completion_fence_path,
        "completion_attestation": completion_attestation_path,
        "formal_manifest": formal_manifest_path,
        "formal_decision": formal_decision_path,
        "revalidated_decision": revalidated_decision_path,
    }
    for key, path in explicit_paths.items():
        if path is not None:
            _expected_receipt_binding(
                value=receipt,
                key=key,
                expected_path=_normalized_absolute(path, label=f"{key} path"),
            )

    explicit_digests = {
        "execution_plan": execution_plan_sha256,
        "v2_failure_closure": failure_closure_sha256,
        "completion_fence": completion_fence_sha256,
        "completion_attestation": completion_attestation_sha256,
    }
    for key, digest in explicit_digests.items():
        if digest is not None and (
            not _is_sha256(digest) or receipt[key]["sha256"] != digest
        ):
            raise RevalidationV3Error(f"{key} digest differs")

    artifact_key_map = {
        "execution_plan": "execution_plan",
        "v2_failure_closure": "failure_closure",
        "completion_fence": "completion_fence",
        "completion_attestation": "completion_attestation",
        "revalidated_decision": "revalidated_decision",
    }
    if artifact_bytes is not None:
        for receipt_key, artifact_key in artifact_key_map.items():
            if artifact_key in artifact_bytes:
                payload = artifact_bytes[artifact_key]
                if not isinstance(payload, bytes):
                    raise RevalidationV3Error("authoritative artifact bytes differ")
                _expected_receipt_binding(
                    value=receipt,
                    key=receipt_key,
                    expected_path=Path(receipt[receipt_key]["path"]),
                    expected_payload=payload,
                )
    if artifact_paths is not None:
        for receipt_key, artifact_key in artifact_key_map.items():
            if artifact_key in artifact_paths:
                _expected_receipt_binding(
                    value=receipt,
                    key=receipt_key,
                    expected_path=_normalized_absolute(
                        artifact_paths[artifact_key],
                        label=f"{artifact_key} artifact path",
                    ),
                )
    return receipt


def revalidate_terminal(
    *,
    root: Path,
    execution_plan_path: Path,
    v2_failure_closure_path: Path,
    completion_fence_path: Path,
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
    """Validate V3 controls, privately run V1, and publish only the V3 pair."""

    root = root.expanduser().resolve()
    execution_plan_path = execution_plan_path.expanduser().resolve()
    failure_closure_path = v2_failure_closure_path.expanduser().resolve()
    completion_fence_path = completion_fence_path.expanduser().resolve()
    attestation_path = attestation_path.expanduser().resolve()
    launch_expectation_path = launch_expectation_path.expanduser().resolve()
    grid_path = grid_path.expanduser().resolve()
    provenance_path = provenance_path.expanduser().resolve()
    formal_manifest_path = formal_manifest_path.expanduser().resolve()
    formal_decision_path = formal_decision_path.expanduser().resolve()
    revalidated_output = v1._normalized_absolute_output(
        revalidated_output, label="V3 revalidated decision output"
    )
    receipt_output = v1._normalized_absolute_output(
        receipt_output, label="V3 revalidation receipt output"
    )
    preregistration_path = (
        (root / v1.PREREGISTRATION_FILENAME).resolve()
        if preregistration_path is None
        else preregistration_path.expanduser().resolve()
    )
    statistical_addendum_path = (
        (root / v1.STATISTICAL_ADDENDUM_FILENAME).resolve()
        if statistical_addendum_path is None
        else statistical_addendum_path.expanduser().resolve()
    )
    outputs = (revalidated_output, receipt_output)
    protected = {
        execution_plan_path,
        failure_closure_path,
        completion_fence_path,
        attestation_path,
        launch_expectation_path,
        grid_path,
        provenance_path,
        formal_manifest_path,
        formal_decision_path,
        preregistration_path,
        statistical_addendum_path,
    }
    if len({_path.as_posix() for _path in outputs}) != 2:
        raise RevalidationV3Error("V3 output paths must be distinct")
    if set(outputs) & protected:
        raise RevalidationV3Error("V3 outputs may not alias registered inputs")
    if any(os.path.lexists(path) for path in outputs):
        raise FileExistsError("refusing pre-existing V3 revalidation output")

    execution, recovery, attester = _load_v3_modules()
    prepare_kwargs = {
        "execution": execution,
        "recovery": recovery,
        "attester": attester,
        "root": root,
        "execution_plan_path": execution_plan_path,
        "failure_closure_path": failure_closure_path,
        "completion_fence_path": completion_fence_path,
        "attestation_path": attestation_path,
        "launch_expectation_path": launch_expectation_path,
        "grid_path": grid_path,
        "provenance_path": provenance_path,
        "formal_manifest_path": formal_manifest_path,
        "formal_decision_path": formal_decision_path,
        "preregistration_path": preregistration_path,
        "statistical_addendum_path": statistical_addendum_path,
        "revalidated_output": revalidated_output,
        "receipt_output": receipt_output,
        "actual_argv": actual_argv,
        "runtime_python_path": runtime_python_path,
        "runtime_python_version": runtime_python_version,
    }
    context = _validate_revalidator_control_chain(**prepare_kwargs)
    with _v1_revalidation_engine_as_v3(
        context=context,
        execution=execution,
        execution_plan_path=execution_plan_path,
        failure_closure_path=failure_closure_path,
        completion_fence_path=completion_fence_path,
        revalidated_output=revalidated_output,
        receipt_output=receipt_output,
    ) as captured:
        legacy_receipt = v1.revalidate_terminal(
            root=root,
            execution_plan_path=execution_plan_path,
            attestation_path=attestation_path,
            launch_expectation_path=launch_expectation_path,
            grid_path=grid_path,
            provenance_path=provenance_path,
            formal_manifest_path=formal_manifest_path,
            formal_decision_path=formal_decision_path,
            revalidated_output=revalidated_output,
            receipt_output=receipt_output,
            preregistration_path=preregistration_path,
            statistical_addendum_path=statistical_addendum_path,
            assemble_fn=assemble_fn,
            evaluate_fn=evaluate_fn,
            make_grid_fn=make_grid_fn,
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    decision_raw = captured.get("decision")
    legacy_raw = captured.get("legacy_receipt")
    if not isinstance(decision_raw, bytes) or not isinstance(legacy_raw, bytes):
        raise RevalidationV3Error("V1 engine produced no captured publication pair")
    parsed_legacy = v1._load_json_bytes(legacy_raw, label="private legacy receipt")
    manifest_raw = v1._read_stable_file(formal_manifest_path)[0]
    if (
        not isinstance(legacy_receipt, dict)
        or parsed_legacy != legacy_receipt
        or legacy_raw != v1._pretty_report_bytes(legacy_receipt)
        or set(legacy_receipt) != v1.RECEIPT_KEYS
        or decision_raw != v1._read_stable_file(formal_decision_path)[0]
        or legacy_receipt.get("status") != "valid"
        or legacy_receipt.get("execution_plan_path") != execution_plan_path.as_posix()
        or legacy_receipt.get("execution_plan_sha256") != _sha256(context.plan_raw)
        or legacy_receipt.get("formal_decision_file_sha256") != _sha256(decision_raw)
        or legacy_receipt.get("formal_manifest_file_sha256") != _sha256(manifest_raw)
    ):
        raise RevalidationV3Error("private V1 revalidation evidence differs")

    receipt = {
        "completion_attestation": _binding(attestation_path, context.attestation_raw),
        "completion_fence": _binding(completion_fence_path, context.fence_raw),
        "completion_method": COMPLETION_METHOD,
        "decision": legacy_receipt["decision"],
        "decision_scope": legacy_receipt["decision_scope"],
        "execution_plan": _binding(execution_plan_path, context.plan_raw),
        "formal_decision": _binding(formal_decision_path, decision_raw),
        "formal_manifest": {
            "path": formal_manifest_path.as_posix(),
            "sha256": legacy_receipt["formal_manifest_file_sha256"],
        },
        "historical_exit_order_claimed": HISTORICAL_EXIT_ORDER_CLAIMED,
        "legacy_publication": LEGACY_PUBLICATION,
        "legacy_strict_mtime_proof": LEGACY_STRICT_MTIME_PROOF,
        "mtime_relation": MTIME_RELATION,
        "private_legacy_receipt_sha256": _sha256(legacy_raw),
        "protocol": PROTOCOL,
        "revalidated_decision": _binding(revalidated_output, decision_raw),
        "revalidated_decision_byte_identical": True,
        "schema_version": SCHEMA_VERSION,
        "status": "valid",
        "v2_failure_closure": _binding(failure_closure_path, context.closure_raw),
    }
    validate_revalidation_receipt_document(
        receipt,
        durable_attempt_root=Path(context.expectation["durable_attempt_root"]),
        execution_plan_path=execution_plan_path,
        failure_closure_path=failure_closure_path,
        completion_fence_path=completion_fence_path,
        completion_attestation_path=attestation_path,
        formal_manifest_path=formal_manifest_path,
        formal_decision_path=formal_decision_path,
        revalidated_decision_path=revalidated_output,
    )

    final_context = _validate_revalidator_control_chain(**prepare_kwargs)
    if not _same_control_context(context, final_context):
        raise RevalidationV3Error("V3 controls drifted before publication")
    if any(os.path.lexists(path) for path in outputs):
        raise FileExistsError("refusing pre-existing V3 revalidation output")
    v1._publish_pair_no_overwrite(
        [
            (revalidated_output, decision_raw),
            (receipt_output, v1._canonical_bytes(receipt)),
        ]
    )
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--v2-failure-closure", type=Path, required=True)
    parser.add_argument("--completion-fence", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--formal-manifest", type=Path, required=True)
    parser.add_argument("--formal-decision", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--statistical-addendum", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        revalidate_terminal(
            root=args.root,
            execution_plan_path=args.execution_plan,
            v2_failure_closure_path=args.v2_failure_closure,
            completion_fence_path=args.completion_fence,
            attestation_path=args.attestation,
            launch_expectation_path=args.launch_expectation,
            grid_path=args.grid,
            provenance_path=args.provenance,
            formal_manifest_path=args.formal_manifest,
            formal_decision_path=args.formal_decision,
            revalidated_output=args.output,
            receipt_output=args.receipt,
            preregistration_path=args.preregistration,
            statistical_addendum_path=args.statistical_addendum,
        )
    except Exception:
        # Neither branch labels nor internal failure details cross the CLI edge.
        raise SystemExit(1) from None
    print(json.dumps({"status": "complete"}, sort_keys=True))


if __name__ == "__main__":
    main()


__all__ = (
    "COMPLETION_METHOD",
    "HISTORICAL_EXIT_ORDER_CLAIMED",
    "LEGACY_PUBLICATION",
    "LEGACY_STRICT_MTIME_PROOF",
    "MTIME_RELATION",
    "PROTOCOL",
    "RECEIPT_FILENAME",
    "REVALIDATED_FILENAME",
    "RevalidationV3Error",
    "SCHEMA_VERSION",
    "revalidate_terminal",
    "validate_revalidation_receipt_document",
)
