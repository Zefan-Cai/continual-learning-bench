#!/usr/bin/env python3
"""Build the truthful V3 Trigger-A execution seal after semantic revalidation.

The public V3 seal never asserts the legacy strict-mtime proof.  It validates
the failure closure, completion fence, V3 attestation, and V3 revalidation
receipt first, then uses private in-memory projections solely to exercise the
unchanged V1 no-go branch engine.  The captured legacy-shaped seal is enriched
with the authoritative V3 controls and only that truthful V3 document may be
published.
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
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import attest_cohort_causal_completion as attester_v1
import attest_cohort_causal_completion_v3 as attester_v3
import build_cohort_causal_terminal_execution_v3 as execution_v3
import build_cohort_structured_state_execution_seal as v1
import freeze_cohort_causal_terminal_recovery_v3 as recovery_v3


SEAL_PROTOCOL = "cohort_closed_loop_structured_state_trigger_execution_seal_v3"
SEAL_SCHEMA_VERSION = 3
SEAL_FILENAME = "cohort_closed_loop_structured_state.execution_seal.v3.json"
ATTESTATION_FILENAME = attester_v3.ATTESTATION_FILENAME
REVALIDATED_FILENAME = execution_v3.REVALIDATED_FILENAME
REVALIDATION_RECEIPT_FILENAME = execution_v3.REVALIDATION_RECEIPT_FILENAME
PLAN_FILENAME = execution_v3.PLAN_FILENAME
PLAN_SCHEMA_VERSION = execution_v3.PLAN_SCHEMA_VERSION
PLAN_TOOL_NAMES = execution_v3.PLAN_TOOL_NAMES

COMPLETION_METHOD = attester_v3.COMPLETION_METHOD
MTIME_RELATION = attester_v3.MTIME_RELATION
TRUTH_FIELDS = {
    "completion_method": COMPLETION_METHOD,
    "historical_exit_order_claimed": False,
    "legacy_publication": False,
    "legacy_strict_mtime_proof": False,
    "mtime_relation": MTIME_RELATION,
}
CONTROL_BINDING_KEYS = frozenset({"path", "sha256"})
CLASSIFICATION_KEYS = frozenset({"decision", "decision_scope", "status"})
EXPECTED_NO_GO = {
    "decision": "valid_no_go",
    "decision_scope": "internal_gate_no_go",
    "status": "valid",
}
V3_EXTRA_SEAL_KEYS = frozenset(
    {
        "branch_adapter_contracts",
        "causal_classification",
        "completion_attestation_v3",
        "completion_fence",
        "completion_method",
        "completion_proof",
        "historical_exit_order_claimed",
        "legacy_publication",
        "legacy_strict_mtime_proof",
        "mtime_relation",
        "revalidation_receipt_v3",
        "semantic_revalidation_completed",
        "v2_failure_closure",
    }
)
BASE_SEAL_KEYS = frozenset(
    {
        "bindings",
        "causal_completion_attestation_sha256",
        "causal_decision_sha256",
        "causal_exit_file_sha256",
        "causal_inventory",
        "causal_inventory_recheck_matches_attestation",
        "causal_inventory_sha256",
        "causal_original_file_sha256",
        "causal_pid_file_sha256",
        "causal_pre_attestation_inventory_sha256",
        "causal_protocol_seal_sha256",
        "causal_protocol_seal_status",
        "causal_revalidation_file_sha256",
        "causal_source_commit",
        "created_at_utc",
        "online_icl_decision_sha256",
        "online_icl_inventory_recheck_matches_marker",
        "online_icl_inventory_sha256",
        "online_icl_original_file_sha256",
        "online_icl_protocol_seal_sha256",
        "online_icl_revalidation_file_sha256",
        "online_icl_wrapper_contract_sha256",
        "online_icl_wrapper_exit_marker_sha256",
        "protocol",
        "schema_version",
        "status",
        "terminal_verifier_execution_plan_path",
        "terminal_verifier_execution_plan_sha256",
        "tooling_source_commit",
        "trigger_branch",
        "verifier_execution",
    }
)
SEAL_KEYS = BASE_SEAL_KEYS | V3_EXTRA_SEAL_KEYS
BASE_BINDING_NAMES = frozenset(
    {
        "attester_code",
        "causal_original",
        "causal_revalidated",
        "causal_revalidation_receipt",
        "causal_trigger_completion_attestation",
        "execution_plan",
        "execution_seal_builder_code",
        "launch_expectation",
        "revalidator_code",
        "structured_preregistration",
    }
)
BASE_BINDING_KEYS = frozenset({"path", "sha256", "size_bytes"})
VERIFIER_EXECUTION_KEYS = frozenset(
    {"invocations", "invocations_sha256", "runtime", "tools"}
)
ONLINE_NULL_FIELDS = frozenset(
    {
        "online_icl_decision_sha256",
        "online_icl_inventory_recheck_matches_marker",
        "online_icl_inventory_sha256",
        "online_icl_original_file_sha256",
        "online_icl_protocol_seal_sha256",
        "online_icl_revalidation_file_sha256",
        "online_icl_wrapper_contract_sha256",
        "online_icl_wrapper_exit_marker_sha256",
    }
)
AUTHORITATIVE_RELATIVE_PATHS = {
    "failure_closure": Path(
        "control/CAUSAL_TERMINAL_VERIFIER_V2_FAILURE_CLOSURE_V1.json"
    ),
    "completion_fence": Path(
        "control/CAUSAL_TERMINAL_VERIFIER_COMPLETION_FENCE_V3.json"
    ),
    "execution_plan": Path("control/CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V3.json"),
    "launch_claim": Path("control/CAUSAL_TERMINAL_VERIFIER_V3_LAUNCH_CLAIM.json"),
    "detached_receipt": Path(
        "control/CAUSAL_TERMINAL_VERIFIER_V3_DETACHED_RECEIPT.json"
    ),
    "completion_attestation": Path(
        "prep/causal_trigger_completion_attestation.v3.json"
    ),
    "revalidated_decision": Path("prep/causal_formal.revalidated.v3.json"),
    "revalidation_receipt": Path("prep/causal_formal.revalidation_receipt.v3.json"),
    "execution_seal": Path(
        "prep/cohort_closed_loop_structured_state.execution_seal.v3.json"
    ),
}
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")


class ExecutionSealV3Error(v1.ExecutionSealError):
    """A fail-closed V3 execution-seal or projection error."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw, _ = v1._read_stable_file(path, label=label)
        value = v1._load_json_bytes(raw, label=label)
    except v1.ExecutionSealError as exc:
        raise ExecutionSealV3Error(f"{label} cannot be loaded") from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        raise ExecutionSealV3Error(f"{label} is not canonical JSON")
    return value, raw


def _strict_document_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=lambda pairs: _reject_duplicate_keys(pairs, label),
            parse_constant=lambda item: _reject_constant(item, label),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutionSealV3Error(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        raise ExecutionSealV3Error(f"{label} is not canonical object bytes")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionSealV3Error(f"{label} has a duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str, label: str) -> None:
    raise ExecutionSealV3Error(f"{label} has non-finite constant {value}")


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ExecutionSealV3Error(f"{label} is not SHA-256")
    return value


def _validate_public_binding(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != BASE_BINDING_KEYS:
        raise ExecutionSealV3Error(f"{label} binding schema differs")
    path = value["path"]
    size = value["size_bytes"]
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or os.path.normpath(path) != path
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
    ):
        raise ExecutionSealV3Error(f"{label} binding fields differ")
    _require_sha256(value["sha256"], f"{label} digest")
    return copy.deepcopy(value)


def _validate_control_binding(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != CONTROL_BINDING_KEYS:
        raise ExecutionSealV3Error(f"{label} binding schema differs")
    path = value["path"]
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or os.path.normpath(path) != path
    ):
        raise ExecutionSealV3Error(f"{label} binding path differs")
    return {"path": path, "sha256": _require_sha256(value["sha256"], label)}


def _binding(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": path.as_posix(), "sha256": _sha256(raw)}


def _project_plan_for_v1(
    plan: Mapping[str, Any],
    *,
    launch_expectation_path: Path,
    launch_expectation_raw: bytes,
    structured_preregistration_path: Path,
) -> dict[str, Any]:
    projected = copy.deepcopy(dict(plan))
    projected.update(
        {
            "causal_protocol_seal_sha256": None,
            "causal_protocol_seal_status": v1.CAUSAL_PROTOCOL_SEAL_STATUS,
            "launch_expectation": _binding(
                launch_expectation_path, launch_expectation_raw
            ),
            "online_icl": None,
            "structured_preregistration": _binding(
                structured_preregistration_path,
                v1._read_stable_file(
                    structured_preregistration_path,
                    label="structured preregistration",
                )[0],
            ),
        }
    )
    # This projection is private and intentionally need not match a published
    # legacy plan schema.  It contains only the fields read by the V1 engine.
    return projected


def _project_receipt_for_v1(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Create the sole private legacy receipt view before entering V1."""

    return {
        "decision": receipt["decision"],
        "decision_scope": receipt["decision_scope"],
        "execution_plan_path": receipt["execution_plan"]["path"],
        "execution_plan_sha256": receipt["execution_plan"]["sha256"],
        "formal_decision_file_sha256": receipt["formal_decision"]["sha256"],
        "formal_manifest_file_sha256": receipt["formal_manifest"]["sha256"],
        "status": receipt["status"],
    }


@contextmanager
def _v1_engine_as_v3(
    *,
    closure_path: Path,
    fence_path: Path,
    launch_expectation_path: Path,
    launch_expectation_raw: bytes,
    structured_preregistration_path: Path,
    validated_attestation: dict[str, Any],
    projected_attestation: dict[str, Any],
    attested_files: list[dict[str, Any]],
    validated_receipt: dict[str, Any],
    projected_receipt: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    captured: dict[str, Any] = {}

    def plan_loader(**kwargs: Any):
        inputs = dict(kwargs["expected_inputs"])
        inputs.update(
            {"completion_fence": fence_path, "v2_failure_closure": closure_path}
        )
        kwargs["expected_inputs"] = inputs
        plan, raw = execution_v3.load_and_validate_execution_plan_stage(**kwargs)
        return (
            _project_plan_for_v1(
                plan,
                launch_expectation_path=launch_expectation_path,
                launch_expectation_raw=launch_expectation_raw,
                structured_preregistration_path=structured_preregistration_path,
            ),
            raw,
        )

    def attestation_validator(value: Any, **_: Any):
        if canonical_bytes(value) != canonical_bytes(validated_attestation):
            raise ExecutionSealV3Error("V3 attestation drifted at V1 engine entry")
        return copy.deepcopy(projected_attestation), copy.deepcopy(attested_files)

    def receipt_validator(value: Any, **kwargs: Any):
        if canonical_bytes(value) != canonical_bytes(validated_receipt):
            raise ExecutionSealV3Error("V3 receipt drifted at V1 engine entry")
        expected = {
            "decision": kwargs.get("decision"),
            "decision_scope": kwargs.get("decision_scope"),
            "execution_plan_path": kwargs.get("execution_plan_path").as_posix(),
            "execution_plan_sha256": kwargs.get("execution_plan_sha256"),
            "formal_decision_file_sha256": kwargs.get("original_sha256"),
            "formal_manifest_file_sha256": kwargs.get("formal_manifest_sha256"),
            "status": "valid",
        }
        if projected_receipt != expected:
            raise ExecutionSealV3Error("private V1 receipt projection differs")
        return copy.deepcopy(projected_receipt)

    def capture_publish(path: Path, payload: bytes) -> None:
        if captured:
            raise ExecutionSealV3Error("V1 engine attempted multiple seal publications")
        captured["path"] = path
        captured["payload"] = payload

    replacements = {
        "PLAN_FILENAME": PLAN_FILENAME,
        "PLAN_SCHEMA_VERSION": PLAN_SCHEMA_VERSION,
        "ATTESTATION_FILENAME": ATTESTATION_FILENAME,
        "REVALIDATED_FILENAME": REVALIDATED_FILENAME,
        "REVALIDATION_RECEIPT_FILENAME": REVALIDATION_RECEIPT_FILENAME,
        "SEAL_FILENAME": SEAL_FILENAME,
        "SEAL_PROTOCOL": SEAL_PROTOCOL,
        "SEAL_SCHEMA_VERSION": SEAL_SCHEMA_VERSION,
        "PLAN_TOOL_NAMES": PLAN_TOOL_NAMES,
        "load_and_validate_execution_plan_stage": plan_loader,
        "_validate_attestation": attestation_validator,
        "_validate_receipt": receipt_validator,
        "_publish_no_overwrite": capture_publish,
    }
    previous = {name: getattr(v1, name) for name in replacements}
    try:
        for name, item in replacements.items():
            setattr(v1, name, item)
        yield captured
    finally:
        for name, item in previous.items():
            setattr(v1, name, item)


def _load_recovery_controls(
    *, durable: Path, closure_path: Path, fence_path: Path
) -> tuple[
    dict[str, Any],
    bytes,
    dict[str, Any],
    bytes,
    list[dict[str, Any]],
]:
    closure, closure_raw = _read_json(closure_path, "V2 failure closure")
    fence, fence_raw = _read_json(fence_path, "V3 completion fence")
    try:
        validated_closure = recovery_v3.validate_failure_closure_document(
            closure,
            durable_attempt_root=durable,
            expected_path=closure_path,
        )
        validated_fence, fence_files = recovery_v3.validate_completion_fence_document(
            fence,
            durable_attempt_root=durable,
            expected_path=fence_path,
            failure_closure_path=closure_path,
            failure_closure_sha256=_sha256(closure_raw),
        )
    except recovery_v3.RecoveryV3Error as exc:
        raise ExecutionSealV3Error("V3 recovery controls are invalid") from exc
    return (
        validated_closure,
        closure_raw,
        validated_fence,
        fence_raw,
        fence_files,
    )


def _load_revalidation_module():
    try:
        return importlib.import_module("revalidate_cohort_causal_terminal_v3")
    except (ImportError, SyntaxError) as exc:
        raise ExecutionSealV3Error("V3 revalidator module is unavailable") from exc


def _load_attestation_chain(
    *,
    plan: Mapping[str, Any],
    plan_raw: bytes,
    durable: Path,
    closure: dict[str, Any],
    closure_raw: bytes,
    fence: dict[str, Any],
    fence_raw: bytes,
    fence_files: list[dict[str, Any]],
    attestation_path: Path,
    execution_plan_path: Path,
    launch_expectation_path: Path,
    launch_expectation_raw: bytes,
    expectation: dict[str, Any],
) -> tuple[
    dict[str, Any],
    bytes,
    dict[str, Any],
    list[dict[str, Any]],
    bytes,
]:
    """Validate the same complete static V3 chain used by the revalidator."""

    attestation, attestation_raw = _read_json(
        attestation_path, "V3 completion attestation"
    )
    closure_path = durable / "control" / recovery_v3.FAILURE_CLOSURE_FILENAME
    fence_path = durable / "control" / recovery_v3.COMPLETION_FENCE_FILENAME
    plan_sha256 = _sha256(plan_raw)
    try:
        preliminary = attester_v3.validate_attestation_document(
            attestation,
            failure_closure=closure,
            completion_fence=fence,
            durable_attempt_root=durable,
            completion_attestation_path=attestation_path,
            execution_plan_path=execution_plan_path,
            execution_plan_sha256=plan_sha256,
            failure_closure_path=closure_path,
            failure_closure_sha256=_sha256(closure_raw),
            completion_fence_path=fence_path,
            completion_fence_sha256=_sha256(fence_raw),
        )
        base_v2 = plan["base_v2"]
        base = execution_v3._load_base_v2_controls(
            durable_root=durable,
            plan_path=Path(base_v2["execution_plan"]["path"]),
            receipt_path=Path(base_v2["detached_receipt"]["path"]),
            inventory_path=Path(base_v2["procfs_exception_inventory"]["path"]),
        )
        base_inventory = base["base_v2_procfs_exception_inventory"]
        base_inventory_raw = base["base_v2_procfs_exception_inventory_raw"]
        base_inventory_path = Path(base_v2["procfs_exception_inventory"]["path"])
        detached_receipt_path = Path(preliminary["detached_launch_receipt"]["path"])
        if detached_receipt_path != Path(plan["detached_transport"]["receipt_path"]):
            raise ExecutionSealV3Error(
                "V3 attestation detached-receipt path differs from the plan"
            )
        detached_receipt, detached_receipt_raw = (
            execution_v3.validate_detached_receipt_static_document(
                path=detached_receipt_path,
                plan=plan,
                plan_raw=plan_raw,
                expected_runtime_namespace=base_inventory["runtime_namespace"],
            )
        )
        artifact_paths = {
            "completion_attestation": attestation_path.as_posix(),
            "completion_fence": fence_path.as_posix(),
            "detached_receipt": detached_receipt_path.as_posix(),
            "execution_plan": execution_plan_path.as_posix(),
            "failure_closure": closure_path.as_posix(),
        }
        artifact_bytes = {
            "completion_attestation": attestation_raw,
            "completion_fence": fence_raw,
            "detached_receipt": detached_receipt_raw,
            "execution_plan": plan_raw,
            "failure_closure": closure_raw,
        }
        validated = attester_v3.validate_attestation_document(
            preliminary,
            failure_closure=closure,
            completion_fence=fence,
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            durable_attempt_root=durable,
            completion_attestation_path=attestation_path,
            execution_plan_path=execution_plan_path,
            execution_plan_sha256=plan_sha256,
            failure_closure_path=closure_path,
            failure_closure_sha256=_sha256(closure_raw),
            completion_fence_path=fence_path,
            completion_fence_sha256=_sha256(fence_raw),
            detached_receipt_path=detached_receipt_path,
            detached_receipt_sha256=_sha256(detached_receipt_raw),
            procfs_exception_inventory_path=base_inventory_path,
            procfs_exception_inventory_sha256=_sha256(base_inventory_raw),
        )
        if (
            detached_receipt["pid"] != validated["detached_launch_receipt"]["pid"]
            or detached_receipt["process_start_ticks"]
            != validated["detached_launch_receipt"]["process_start_ticks"]
        ):
            raise ExecutionSealV3Error(
                "V3 detached-receipt identity differs from the attestation"
            )
        projected, files = attester_v3._project_attestation_for_v1(
            validated,
            failure_closure=closure,
            completion_fence=fence,
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            durable_attempt_root=durable,
            execution_plan_path=execution_plan_path,
            execution_plan_sha256=plan_sha256,
            expectation=expectation,
            launch_expectation_path=launch_expectation_path,
            launch_expectation_sha256=_sha256(launch_expectation_raw),
            completion_attestation_path=attestation_path,
            failure_closure_path=closure_path,
            failure_closure_sha256=_sha256(closure_raw),
            completion_fence_path=fence_path,
            completion_fence_sha256=_sha256(fence_raw),
            detached_receipt_path=detached_receipt_path,
            detached_receipt_sha256=_sha256(detached_receipt_raw),
            procfs_exception_inventory_path=base_inventory_path,
            procfs_exception_inventory_sha256=_sha256(base_inventory_raw),
        )
    except ExecutionSealV3Error:
        raise
    except Exception as exc:
        raise ExecutionSealV3Error(
            "V3 completion-attestation control chain is invalid"
        ) from exc

    fence_by_path = {record["path"]: record for record in fence_files}
    if len(fence_by_path) != len(fence_files) or any(
        record["path"] not in fence_by_path
        or canonical_bytes(record) != canonical_bytes(fence_by_path[record["path"]])
        for record in files
    ):
        raise ExecutionSealV3Error(
            "V3 attestation inventory differs from the completion fence"
        )
    return validated, attestation_raw, projected, files, detached_receipt_raw


def _require_current_bytes(path: Path, expected: bytes, *, label: str) -> None:
    try:
        current, _ = v1._read_stable_file(path, label=label)
    except v1.ExecutionSealError as exc:
        raise ExecutionSealV3Error(f"{label} cannot be re-read") from exc
    if current != expected:
        raise ExecutionSealV3Error(f"{label} changed before V3 seal publication")


def build_and_publish_execution_seal(
    *,
    execution_plan_path: Path,
    v2_failure_closure_path: Path,
    completion_fence_path: Path,
    attestation_path: Path,
    launch_expectation_path: Path,
    causal_original_path: Path,
    causal_revalidated_path: Path,
    revalidation_receipt_path: Path,
    structured_preregistration_path: Path,
    output: Path,
    now_fn: Any = None,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
) -> dict[str, Any]:
    """Validate the V3 chain and publish only a truthful no-go seal."""

    requested_output = output.expanduser()
    if os.path.lexists(requested_output):
        raise FileExistsError("refusing pre-existing V3 execution seal")
    paths = {
        "execution_plan": execution_plan_path.expanduser().resolve(),
        "v2_failure_closure": v2_failure_closure_path.expanduser().resolve(),
        "completion_fence": completion_fence_path.expanduser().resolve(),
        "attestation": attestation_path.expanduser().resolve(),
        "launch_expectation": launch_expectation_path.expanduser().resolve(),
        "causal_original": causal_original_path.expanduser().resolve(),
        "causal_revalidated": causal_revalidated_path.expanduser().resolve(),
        "revalidation_receipt": revalidation_receipt_path.expanduser().resolve(),
        "structured_preregistration": structured_preregistration_path.expanduser().resolve(),
        "execution_seal": requested_output.resolve(),
    }
    if os.path.lexists(paths["execution_seal"]):
        raise FileExistsError("refusing pre-existing V3 execution seal")
    expected_inputs = {
        key: paths[key]
        for key in (
            "execution_plan",
            "v2_failure_closure",
            "completion_fence",
            "attestation",
            "launch_expectation",
            "causal_original",
            "causal_revalidated",
            "revalidation_receipt",
            "structured_preregistration",
        )
    }
    plan_load_kwargs = {
        "execution_plan_path": paths["execution_plan"],
        "stage": "execution_seal_builder",
        "expected_inputs": expected_inputs,
        "expected_outputs": {"execution_seal": paths["execution_seal"]},
        "expected_parameters": {},
        "actual_argv": actual_argv,
        "runtime_python_path": runtime_python_path,
        "runtime_python_version": runtime_python_version,
    }
    try:
        plan, plan_raw = execution_v3.load_and_validate_execution_plan_stage(
            **plan_load_kwargs
        )
    except Exception as exc:
        raise ExecutionSealV3Error("V3 execution-seal plan is invalid") from exc
    durable = Path(plan["durable_attempt_root"])
    if paths["execution_seal"] != durable / "prep" / SEAL_FILENAME:
        raise ExecutionSealV3Error("V3 execution-seal path is not fixed")
    closure, closure_raw, fence, fence_raw, fence_files = _load_recovery_controls(
        durable=durable,
        closure_path=paths["v2_failure_closure"],
        fence_path=paths["completion_fence"],
    )
    try:
        expectation, expectation_raw = attester_v1._load_launch_expectation(
            paths["launch_expectation"]
        )
        expectation = v1._validate_launch_expectation(expectation)
    except (attester_v1.AttestationError, v1.ExecutionSealError) as exc:
        raise ExecutionSealV3Error("causal launch expectation is invalid") from exc

    (
        validated_attestation,
        attestation_raw,
        projected_attestation,
        attested_files,
        detached_receipt_raw,
    ) = _load_attestation_chain(
        plan=plan,
        plan_raw=plan_raw,
        durable=durable,
        closure=closure,
        closure_raw=closure_raw,
        fence=fence,
        fence_raw=fence_raw,
        fence_files=fence_files,
        attestation_path=paths["attestation"],
        execution_plan_path=paths["execution_plan"],
        launch_expectation_path=paths["launch_expectation"],
        launch_expectation_raw=expectation_raw,
        expectation=expectation,
    )

    receipt_module = _load_revalidation_module()
    receipt, receipt_raw = _read_json(
        paths["revalidation_receipt"], "V3 revalidation receipt"
    )
    revalidated_raw, _ = v1._read_stable_file(
        paths["causal_revalidated"], label="V3 revalidated decision"
    )
    try:
        validated_receipt = receipt_module.validate_revalidation_receipt_document(
            receipt,
            durable_attempt_root=durable,
            artifact_bytes={
                "completion_attestation": attestation_raw,
                "completion_fence": fence_raw,
                "execution_plan": plan_raw,
                "failure_closure": closure_raw,
                "revalidated_decision": revalidated_raw,
            },
            artifact_paths={
                "completion_attestation": paths["attestation"].as_posix(),
                "completion_fence": paths["completion_fence"].as_posix(),
                "execution_plan": paths["execution_plan"].as_posix(),
                "failure_closure": paths["v2_failure_closure"].as_posix(),
                "revalidated_decision": paths["causal_revalidated"].as_posix(),
            },
            execution_plan_path=paths["execution_plan"],
            execution_plan_sha256=_sha256(plan_raw),
            failure_closure_path=paths["v2_failure_closure"],
            failure_closure_sha256=_sha256(closure_raw),
            completion_fence_path=paths["completion_fence"],
            completion_fence_sha256=_sha256(fence_raw),
            completion_attestation_path=paths["attestation"],
            completion_attestation_sha256=_sha256(attestation_raw),
            formal_manifest_path=Path(expectation["artifact_root"])
            / "formal_manifest.json",
            formal_decision_path=paths["causal_original"],
            revalidated_decision_path=paths["causal_revalidated"],
        )
    except Exception as exc:
        raise ExecutionSealV3Error("V3 revalidation receipt is invalid") from exc
    classification = {
        "decision": validated_receipt["decision"],
        "decision_scope": validated_receipt["decision_scope"],
        "status": validated_receipt["status"],
    }
    if classification != EXPECTED_NO_GO:
        # A pass is not an error in the causal result; it simply forbids a
        # Trigger-A seal.  The CLI intentionally reveals no branch detail.
        raise ExecutionSealV3Error("V3 structured execution seal is not authorized")
    projected_receipt = _project_receipt_for_v1(validated_receipt)

    # These semantically opened artifacts are snapshotted only after the V3
    # receipt has selected Trigger A.  They are rechecked immediately before
    # publication in addition to the V1 engine's own full inventory recheck.
    causal_original_raw, _ = v1._read_stable_file(
        paths["causal_original"], label="V3 original decision"
    )
    structured_preregistration_raw, _ = v1._read_stable_file(
        paths["structured_preregistration"], label="structured preregistration"
    )

    with _v1_engine_as_v3(
        closure_path=paths["v2_failure_closure"],
        fence_path=paths["completion_fence"],
        launch_expectation_path=paths["launch_expectation"],
        launch_expectation_raw=expectation_raw,
        structured_preregistration_path=paths["structured_preregistration"],
        validated_attestation=validated_attestation,
        projected_attestation=projected_attestation,
        attested_files=attested_files,
        validated_receipt=validated_receipt,
        projected_receipt=projected_receipt,
    ) as captured:
        v1.build_and_publish_execution_seal(
            execution_plan_path=paths["execution_plan"],
            attestation_path=paths["attestation"],
            launch_expectation_path=paths["launch_expectation"],
            causal_original_path=paths["causal_original"],
            causal_revalidated_path=paths["causal_revalidated"],
            revalidation_receipt_path=paths["revalidation_receipt"],
            structured_preregistration_path=paths["structured_preregistration"],
            output=paths["execution_seal"],
            now_fn=now_fn,
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    if captured.get("path") != paths["execution_seal"] or not isinstance(
        captured.get("payload"), bytes
    ):
        raise ExecutionSealV3Error("V1 engine produced no captured V3 seal")
    seal = _strict_document_bytes(captured["payload"], "captured private V1 seal")
    if (
        set(seal) != BASE_SEAL_KEYS
        or seal.get("protocol") != SEAL_PROTOCOL
        or seal.get("schema_version") != SEAL_SCHEMA_VERSION
        or seal.get("status") != "sealed"
        or seal.get("trigger_branch") != "causal_valid_no_go"
        or "outcome_blind" in seal
        or "semantic_open_sentinel" in seal
    ):
        raise ExecutionSealV3Error("captured private V1 seal schema differs")
    seal.update(
        {
            "branch_adapter_contracts": copy.deepcopy(plan["branch_adapter_contracts"]),
            "causal_classification": classification,
            "completion_attestation_v3": _binding(
                paths["attestation"], attestation_raw
            ),
            "completion_fence": _binding(paths["completion_fence"], fence_raw),
            "completion_method": COMPLETION_METHOD,
            "completion_proof": copy.deepcopy(
                validated_attestation["completion_proof"]
            ),
            "historical_exit_order_claimed": False,
            "legacy_publication": False,
            "legacy_strict_mtime_proof": False,
            "mtime_relation": MTIME_RELATION,
            "revalidation_receipt_v3": _binding(
                paths["revalidation_receipt"], receipt_raw
            ),
            "semantic_revalidation_completed": True,
            "v2_failure_closure": _binding(paths["v2_failure_closure"], closure_raw),
        }
    )
    validate_execution_seal_document(
        seal,
        execution_seal_path=paths["execution_seal"],
        execution_plan_path=paths["execution_plan"],
        execution_plan_sha256=_sha256(plan_raw),
        failure_closure_path=paths["v2_failure_closure"],
        failure_closure_sha256=_sha256(closure_raw),
        completion_fence_path=paths["completion_fence"],
        completion_fence_sha256=_sha256(fence_raw),
        completion_attestation_path=paths["attestation"],
        completion_attestation_sha256=_sha256(attestation_raw),
        revalidation_receipt_path=paths["revalidation_receipt"],
        revalidation_receipt_sha256=_sha256(receipt_raw),
    )

    # Final fail-closed control gate.  Re-run the registered V3 plan validator
    # (which re-hashes tools, dependencies, base V2 controls, recovery controls,
    # and transport files), then re-prove the static receipt/attestation chain.
    try:
        final_plan, final_plan_raw = (
            execution_v3.load_and_validate_execution_plan_stage(**plan_load_kwargs)
        )
    except Exception as exc:
        raise ExecutionSealV3Error(
            "V3 execution-seal plan changed before publication"
        ) from exc
    if final_plan != plan or final_plan_raw != plan_raw:
        raise ExecutionSealV3Error("V3 execution-seal plan drifted")
    (
        final_closure,
        final_closure_raw,
        final_fence,
        final_fence_raw,
        final_fence_files,
    ) = _load_recovery_controls(
        durable=durable,
        closure_path=paths["v2_failure_closure"],
        fence_path=paths["completion_fence"],
    )
    if (
        final_closure != closure
        or final_closure_raw != closure_raw
        or final_fence != fence
        or final_fence_raw != fence_raw
        or final_fence_files != fence_files
    ):
        raise ExecutionSealV3Error("V3 recovery controls drifted before publication")
    _require_current_bytes(
        paths["launch_expectation"],
        expectation_raw,
        label="causal launch expectation",
    )
    (
        final_attestation,
        final_attestation_raw,
        final_projected_attestation,
        final_attested_files,
        final_detached_receipt_raw,
    ) = _load_attestation_chain(
        plan=plan,
        plan_raw=plan_raw,
        durable=durable,
        closure=closure,
        closure_raw=closure_raw,
        fence=fence,
        fence_raw=fence_raw,
        fence_files=fence_files,
        attestation_path=paths["attestation"],
        execution_plan_path=paths["execution_plan"],
        launch_expectation_path=paths["launch_expectation"],
        launch_expectation_raw=expectation_raw,
        expectation=expectation,
    )
    if (
        final_attestation != validated_attestation
        or final_attestation_raw != attestation_raw
        or final_projected_attestation != projected_attestation
        or final_attested_files != attested_files
        or final_detached_receipt_raw != detached_receipt_raw
    ):
        raise ExecutionSealV3Error(
            "V3 completion-attestation chain drifted before publication"
        )
    final_receipt, final_receipt_raw = _read_json(
        paths["revalidation_receipt"], "V3 revalidation receipt"
    )
    if final_receipt != validated_receipt or final_receipt_raw != receipt_raw:
        raise ExecutionSealV3Error("V3 revalidation receipt drifted")
    _require_current_bytes(
        paths["causal_original"],
        causal_original_raw,
        label="V3 original decision",
    )
    _require_current_bytes(
        paths["causal_revalidated"],
        revalidated_raw,
        label="V3 revalidated decision",
    )
    _require_current_bytes(
        paths["structured_preregistration"],
        structured_preregistration_raw,
        label="structured preregistration",
    )
    payload = canonical_bytes(seal)
    v1._publish_no_overwrite(paths["execution_seal"], payload)
    return {
        "path": paths["execution_seal"].as_posix(),
        "seal_sha256": _sha256(payload),
        "status": "sealed",
        "trigger_branch": "causal_valid_no_go",
    }


def validate_execution_seal_document(
    value: Any,
    *,
    durable_attempt_root: Path | None = None,
    artifact_bytes: Mapping[str, bytes] | None = None,
    artifact_paths: Mapping[str, str] | None = None,
    execution_seal_path: Path | None = None,
    execution_plan_path: Path | None = None,
    execution_plan_sha256: str | None = None,
    failure_closure_path: Path | None = None,
    failure_closure_sha256: str | None = None,
    completion_fence_path: Path | None = None,
    completion_fence_sha256: str | None = None,
    completion_attestation_path: Path | None = None,
    completion_attestation_sha256: str | None = None,
    revalidation_receipt_path: Path | None = None,
    revalidation_receipt_sha256: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Validate the truthful V3 seal envelope without making a projection."""

    if not isinstance(value, dict) or set(value) != SEAL_KEYS:
        raise ExecutionSealV3Error("V3 execution seal schema differs")
    seal = copy.deepcopy(value)
    if (
        seal.get("protocol") != SEAL_PROTOCOL
        or seal.get("schema_version") != SEAL_SCHEMA_VERSION
        or seal.get("status") != "sealed"
        or seal.get("trigger_branch") != "causal_valid_no_go"
        or seal["causal_classification"] != EXPECTED_NO_GO
        or seal["completion_method"] != COMPLETION_METHOD
        or seal["mtime_relation"] != MTIME_RELATION
        or seal["legacy_strict_mtime_proof"] is not False
        or seal["historical_exit_order_claimed"] is not False
        or seal["legacy_publication"] is not False
        or seal["semantic_revalidation_completed"] is not True
    ):
        raise ExecutionSealV3Error("V3 execution seal truth claims differ")

    if (
        any(seal[name] is not None for name in ONLINE_NULL_FIELDS)
        or seal["causal_protocol_seal_sha256"] is not None
        or seal["causal_protocol_seal_status"] != v1.CAUSAL_PROTOCOL_SEAL_STATUS
        or seal["causal_inventory_recheck_matches_attestation"] is not True
        or not isinstance(seal["created_at_utc"], str)
        or not seal["created_at_utc"].endswith("Z")
        or not isinstance(seal["causal_source_commit"], str)
        or _COMMIT_RE.fullmatch(seal["causal_source_commit"]) is None
        or not isinstance(seal["tooling_source_commit"], str)
        or _COMMIT_RE.fullmatch(seal["tooling_source_commit"]) is None
    ):
        raise ExecutionSealV3Error("V3 base seal truth fields differ")
    for name in (
        "causal_completion_attestation_sha256",
        "causal_decision_sha256",
        "causal_exit_file_sha256",
        "causal_inventory_sha256",
        "causal_original_file_sha256",
        "causal_pid_file_sha256",
        "causal_pre_attestation_inventory_sha256",
        "causal_revalidation_file_sha256",
        "terminal_verifier_execution_plan_sha256",
    ):
        _require_sha256(seal[name], name)
    inventory = seal["causal_inventory"]
    if not isinstance(inventory, list) or not inventory:
        raise ExecutionSealV3Error("V3 causal inventory binding differs")
    try:
        inventory = [
            v1._validate_file_record(record, label=f"causal_inventory[{index}]")
            for index, record in enumerate(inventory)
        ]
    except v1.ExecutionSealError as exc:
        raise ExecutionSealV3Error("V3 causal inventory record differs") from exc
    inventory_paths = [record["path"] for record in inventory]
    if (
        inventory_paths != sorted(inventory_paths)
        or len(inventory_paths) != len(set(inventory_paths))
        or _sha256(canonical_bytes(inventory)) != seal["causal_inventory_sha256"]
    ):
        raise ExecutionSealV3Error("V3 causal inventory binding differs")
    bindings = seal["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != BASE_BINDING_NAMES:
        raise ExecutionSealV3Error("V3 base seal binding names differ")
    for name, binding in bindings.items():
        _validate_public_binding(binding, f"base seal {name}")
    expected_base_digests = {
        "causal_original": seal["causal_original_file_sha256"],
        "causal_revalidated": seal["causal_revalidation_file_sha256"],
        "causal_trigger_completion_attestation": seal[
            "causal_completion_attestation_sha256"
        ],
        "execution_plan": seal["terminal_verifier_execution_plan_sha256"],
    }
    if any(
        bindings[name]["sha256"] != digest
        for name, digest in expected_base_digests.items()
    ) or (
        bindings["execution_plan"]["path"]
        != seal["terminal_verifier_execution_plan_path"]
    ):
        raise ExecutionSealV3Error("V3 base seal digest projection differs")

    role_records: dict[str, list[dict[str, Any]]] = {
        role: [record for record in inventory if role in record["roles"]]
        for role in (
            "causal_trigger_completion_attestation",
            "formal_decision",
            "wrapper_exit_file",
            "wrapper_pid_file",
        )
    }
    if any(len(records) != 1 for records in role_records.values()):
        raise ExecutionSealV3Error("V3 causal inventory role projection differs")
    attestation_record = role_records["causal_trigger_completion_attestation"][0]
    original_record = role_records["formal_decision"][0]
    exit_record = role_records["wrapper_exit_file"][0]
    pid_record = role_records["wrapper_pid_file"][0]
    if (
        {
            "path": attestation_record["path"],
            "sha256": attestation_record["sha256"],
            "size_bytes": attestation_record["size_bytes"],
        }
        != bindings["causal_trigger_completion_attestation"]
        or original_record["path"] != bindings["causal_original"]["path"]
        or original_record["sha256"] != seal["causal_original_file_sha256"]
        or exit_record["sha256"] != seal["causal_exit_file_sha256"]
        or pid_record["sha256"] != seal["causal_pid_file_sha256"]
        or _sha256(
            canonical_bytes(
                [record for record in inventory if record is not attestation_record]
            )
        )
        != seal["causal_pre_attestation_inventory_sha256"]
    ):
        raise ExecutionSealV3Error("V3 causal inventory role binding differs")

    verifier = seal["verifier_execution"]
    if not isinstance(verifier, dict) or set(verifier) != VERIFIER_EXECUTION_KEYS:
        raise ExecutionSealV3Error("V3 verifier execution schema differs")
    if (
        not isinstance(verifier["invocations"], dict)
        or not isinstance(verifier["runtime"], dict)
        or not isinstance(verifier["tools"], dict)
        or _sha256(canonical_bytes(verifier["invocations"]))
        != verifier["invocations_sha256"]
    ):
        raise ExecutionSealV3Error("V3 verifier execution binding differs")
    _require_sha256(verifier["invocations_sha256"], "verifier invocation digest")

    expected = {
        "v2_failure_closure": (failure_closure_path, failure_closure_sha256),
        "completion_fence": (completion_fence_path, completion_fence_sha256),
        "completion_attestation_v3": (
            completion_attestation_path,
            completion_attestation_sha256,
        ),
        "revalidation_receipt_v3": (
            revalidation_receipt_path,
            revalidation_receipt_sha256,
        ),
    }
    for key, (path, digest) in expected.items():
        binding = _validate_control_binding(seal[key], f"V3 execution seal {key}")
        if path is not None and binding != {"path": path.as_posix(), "sha256": digest}:
            raise ExecutionSealV3Error(f"V3 execution seal {key} binding drifted")
    plan_path = seal.get("terminal_verifier_execution_plan_path")
    if (
        not isinstance(plan_path, str)
        or not Path(plan_path).is_absolute()
        or os.path.normpath(plan_path) != plan_path
    ):
        raise ExecutionSealV3Error("V3 execution seal plan path differs")
    if execution_plan_path is not None:
        if (
            plan_path != execution_plan_path.as_posix()
            or seal.get("terminal_verifier_execution_plan_sha256")
            != execution_plan_sha256
        ):
            raise ExecutionSealV3Error("V3 execution seal plan binding differs")
    if execution_seal_path is not None and (
        execution_seal_path.name != SEAL_FILENAME
        or execution_seal_path.parent.name != "prep"
    ):
        raise ExecutionSealV3Error("V3 execution seal path is not fixed")
    proof = seal["completion_proof"]
    if (
        not isinstance(proof, dict)
        or set(proof) != attester_v3.COMPLETION_PROOF_KEYS
        or proof.get("completion_method") != COMPLETION_METHOD
        or proof.get("historical_exit_order_claimed") is not False
        or proof.get("legacy_strict_mtime_proof") is not False
        or proof.get("mtime_relation") != MTIME_RELATION
        or proof.get("completion_fence_sha256") != seal["completion_fence"]["sha256"]
    ):
        raise ExecutionSealV3Error("V3 execution seal completion proof differs")
    if (
        not isinstance(seal["branch_adapter_contracts"], dict)
        or not seal["branch_adapter_contracts"]
    ):
        raise ExecutionSealV3Error("V3 branch adapter contracts are absent")

    if artifact_bytes is not None or artifact_paths is not None:
        if not isinstance(artifact_bytes, Mapping) or not isinstance(
            artifact_paths, Mapping
        ):
            raise ExecutionSealV3Error("V3 authoritative artifact maps are incomplete")
        if set(artifact_bytes) != set(AUTHORITATIVE_RELATIVE_PATHS) or set(
            artifact_paths
        ) != set(AUTHORITATIVE_RELATIVE_PATHS):
            raise ExecutionSealV3Error("V3 authoritative artifact names differ")
        if durable_attempt_root is None:
            raise ExecutionSealV3Error("V3 durable root is absent")
        durable = Path(durable_attempt_root)
        if (
            not durable.is_absolute()
            or durable != Path(os.path.normpath(durable.as_posix()))
            or durable.name != "attempt-002"
        ):
            raise ExecutionSealV3Error("V3 durable root differs")
        for name, relative in AUTHORITATIVE_RELATIVE_PATHS.items():
            raw = artifact_bytes[name]
            path = artifact_paths[name]
            if (
                not isinstance(raw, bytes)
                or not isinstance(path, str)
                or path != (durable / relative).as_posix()
            ):
                raise ExecutionSealV3Error(
                    f"V3 authoritative artifact binding differs: {name}"
                )
        if artifact_bytes["execution_seal"] != canonical_bytes(seal):
            raise ExecutionSealV3Error("V3 authoritative seal bytes differ")

        plan = _strict_document_bytes(
            artifact_bytes["execution_plan"], "V3 authoritative execution plan"
        )
        receipt = _strict_document_bytes(
            artifact_bytes["revalidation_receipt"],
            "V3 authoritative revalidation receipt",
        )
        attestation = _strict_document_bytes(
            artifact_bytes["completion_attestation"],
            "V3 authoritative completion attestation",
        )
        if (
            plan.get("protocol") != execution_v3.PLAN_PROTOCOL
            or plan.get("schema_version") != execution_v3.PLAN_SCHEMA_VERSION
            or plan.get("durable_attempt_root") != durable.as_posix()
            or seal["tooling_source_commit"] != plan.get("tooling_source_commit")
            or seal["branch_adapter_contracts"] != plan.get("branch_adapter_contracts")
            or seal["terminal_verifier_execution_plan_path"]
            != artifact_paths["execution_plan"]
            or seal["terminal_verifier_execution_plan_sha256"]
            != _sha256(artifact_bytes["execution_plan"])
            or verifier["invocations"] != plan.get("invocations")
            or verifier["runtime"] != plan.get("runtime")
            or verifier["tools"] != plan.get("tools")
        ):
            raise ExecutionSealV3Error("V3 seal execution-plan projection differs")
        receipt_classification = {
            "decision": receipt.get("decision"),
            "decision_scope": receipt.get("decision_scope"),
            "status": receipt.get("status"),
        }
        if (
            receipt_classification != EXPECTED_NO_GO
            or seal["causal_classification"] != receipt_classification
            or seal["completion_proof"] != attestation.get("completion_proof")
            or seal["completion_attestation_v3"]
            != {
                "path": artifact_paths["completion_attestation"],
                "sha256": _sha256(artifact_bytes["completion_attestation"]),
            }
            or seal["revalidation_receipt_v3"]
            != {
                "path": artifact_paths["revalidation_receipt"],
                "sha256": _sha256(artifact_bytes["revalidation_receipt"]),
            }
            or seal["completion_fence"]
            != {
                "path": artifact_paths["completion_fence"],
                "sha256": _sha256(artifact_bytes["completion_fence"]),
            }
            or seal["v2_failure_closure"]
            != {
                "path": artifact_paths["failure_closure"],
                "sha256": _sha256(artifact_bytes["failure_closure"]),
            }
            or seal["causal_completion_attestation_sha256"]
            != _sha256(artifact_bytes["completion_attestation"])
            or seal["causal_revalidation_file_sha256"]
            != _sha256(artifact_bytes["revalidated_decision"])
            or receipt.get("revalidated_decision")
            != {
                "path": artifact_paths["revalidated_decision"],
                "sha256": _sha256(artifact_bytes["revalidated_decision"]),
            }
        ):
            raise ExecutionSealV3Error("V3 authoritative seal projection differs")
        bound_artifacts = {
            "causal_trigger_completion_attestation": "completion_attestation",
            "causal_revalidated": "revalidated_decision",
            "causal_revalidation_receipt": "revalidation_receipt",
            "execution_plan": "execution_plan",
        }
        for binding_name, artifact_name in bound_artifacts.items():
            raw = artifact_bytes[artifact_name]
            if bindings[binding_name] != {
                "path": artifact_paths[artifact_name],
                "sha256": _sha256(raw),
                "size_bytes": len(raw),
            }:
                raise ExecutionSealV3Error(
                    f"V3 base seal artifact binding differs: {binding_name}"
                )
    return seal


def build_downstream_private_projection(
    *, adapter_kind: str, artifacts: Mapping[str, Any], **context: Any
) -> dict[str, Any]:
    """Validate the selected branch, then fail closed before future evidence.

    The frozen V3 plan registers adapters but does not register either the
    structured absence-evidence projection or an online-ICL child plan.  In
    particular, callers cannot smuggle an arbitrary ``plan_bound`` mapping
    through this hook.  A later prospective plan must replace this function's
    fail-closed endpoint with an exact schema and source-bound constructor.
    """

    expected = {
        "structured_trigger_no_go": EXPECTED_NO_GO,
        "online_icl_future_pass": {
            "decision": "pass",
            "decision_scope": "internal_gate_pass",
            "status": "valid",
        },
    }
    if adapter_kind not in expected:
        raise ExecutionSealV3Error("unknown V3 downstream adapter kind")

    require_seal = adapter_kind == "structured_trigger_no_go"
    expected_names = set(AUTHORITATIVE_RELATIVE_PATHS)
    if not require_seal:
        expected_names.remove("execution_seal")
    artifact_bytes = context.get("artifact_bytes")
    artifact_paths = context.get("artifact_paths")
    durable = context.get("durable_attempt_root")
    if (
        not isinstance(artifacts, Mapping)
        or set(artifacts) != expected_names
        or not isinstance(artifact_bytes, Mapping)
        or set(artifact_bytes) != expected_names
        or not isinstance(artifact_paths, Mapping)
        or set(artifact_paths) != expected_names
        or not isinstance(durable, Path)
        or not durable.is_absolute()
        or durable != Path(os.path.normpath(durable.as_posix()))
    ):
        raise ExecutionSealV3Error("V3 downstream authoritative context differs")
    for name in sorted(expected_names):
        raw = artifact_bytes[name]
        path = artifact_paths[name]
        document = artifacts[name]
        if (
            not isinstance(raw, bytes)
            or not isinstance(path, str)
            or path != (durable / AUTHORITATIVE_RELATIVE_PATHS[name]).as_posix()
            or not isinstance(document, dict)
            or raw != canonical_bytes(document)
        ):
            raise ExecutionSealV3Error(
                f"V3 downstream authoritative artifact differs: {name}"
            )

    plan = artifacts["execution_plan"]
    receipt = artifacts["revalidation_receipt"]
    validated_receipt = context.get("revalidation_receipt")
    if (
        plan.get("protocol") != execution_v3.PLAN_PROTOCOL
        or plan.get("schema_version") != execution_v3.PLAN_SCHEMA_VERSION
        or plan.get("durable_attempt_root") != durable.as_posix()
        or validated_receipt != receipt
    ):
        raise ExecutionSealV3Error("V3 downstream plan or receipt differs")
    classification = {
        "decision": receipt.get("decision"),
        "decision_scope": receipt.get("decision_scope"),
        "status": receipt.get("status"),
    }
    if classification != expected[adapter_kind]:
        raise ExecutionSealV3Error("V3 downstream branch classification differs")

    seal = context.get("execution_seal")
    if require_seal:
        if (
            not isinstance(seal, dict)
            or seal != artifacts["execution_seal"]
            or seal.get("causal_classification") != classification
            or seal.get("tooling_source_commit") != plan.get("tooling_source_commit")
        ):
            raise ExecutionSealV3Error("V3 structured branch seal differs")
    elif seal is not None or "execution_seal" in artifacts:
        raise ExecutionSealV3Error("V3 pass branch unexpectedly has a Trigger-A seal")

    if "plan_bound_private_projection" in context:
        raise ExecutionSealV3Error(
            "unregistered downstream private projection input is forbidden"
        )
    if require_seal:
        raise ExecutionSealV3Error(
            "structured future absence-evidence projection is not preregistered"
        )
    raise ExecutionSealV3Error("online-ICL future child plan is not preregistered")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--v2-failure-closure", type=Path, required=True)
    parser.add_argument("--completion-fence", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--causal-original", type=Path, required=True)
    parser.add_argument("--causal-revalidated", type=Path, required=True)
    parser.add_argument("--revalidation-receipt", type=Path, required=True)
    parser.add_argument("--structured-preregistration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build_and_publish_execution_seal(
            execution_plan_path=args.execution_plan,
            v2_failure_closure_path=args.v2_failure_closure,
            completion_fence_path=args.completion_fence,
            attestation_path=args.attestation,
            launch_expectation_path=args.launch_expectation,
            causal_original_path=args.causal_original,
            causal_revalidated_path=args.causal_revalidated,
            revalidation_receipt_path=args.revalidation_receipt,
            structured_preregistration_path=args.structured_preregistration,
            output=args.output,
        )
    except (
        ExecutionSealV3Error,
        v1.ExecutionSealError,
        FileExistsError,
        OSError,
    ):
        raise SystemExit(1) from None
    print(json.dumps({"status": "complete"}, sort_keys=True))


if __name__ == "__main__":
    main()
