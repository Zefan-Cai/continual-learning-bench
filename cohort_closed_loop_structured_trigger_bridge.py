"""Strict Trigger-A bridge for the structured closed-loop protocol.

The bridge has no trigger builder and no seal-only compatibility path.  Every
successful call delegates the scientific decision to the independently
implemented strict receipt revalidator, binds every full-byte argument exposed
by that revalidator, and returns a non-authorizing canonical bridge artifact.

This module performs no filesystem, process, model, scorer, or result I/O.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import cohort_closed_loop_structured_trigger_receipt_revalidator as strict_revalidator

__all__ = (
    "STRICT_RAW_EVIDENCE_EDGE_NAMES",
    "StructuredTriggerBridgeError",
    "StructuredTriggerBridgeValidation",
    "revalidate_and_bind_trigger_a_receipt",
    "validate_structured_trigger_bridge_bytes",
)


class StructuredTriggerBridgeError(ValueError):
    """Raised when the strict-trigger bridge fails closed."""


@dataclass(frozen=True, slots=True)
class StructuredTriggerBridgeValidation:
    """Exact bridge result; this object never grants operational authority."""

    attempt_id: str
    trigger_branch: str
    tooling_source_commit: str
    trigger_receipt_file_sha256: str
    trigger_receipt_sha256: str
    causal_decision_sha256: str
    bridge_receipt_sha256: str
    bridge_receipt_bytes: bytes
    raw_evidence_edge_count: int
    model_calls_authorized: bool = False
    operational_authorization: bool = False

    @property
    def bridge_binding(self) -> dict[str, object]:
        """Return the exact full-byte binding used by downstream pure seals."""

        return {
            "sha256": hashlib.sha256(self.bridge_receipt_bytes).hexdigest(),
            "size_bytes": len(self.bridge_receipt_bytes),
        }


SCHEMA_VERSION = 1
BRIDGE_PROTOCOL = "cohort_structured_strict_trigger_bridge_v1"
BRIDGE_STATUS = "strict_trigger_revalidated_non_authorizing"

# These are exactly the full-byte keyword edges in the independent
# ``validate_trigger_a_receipt_bytes`` API.  The strict receipt itself is a
# separate full-byte input, so a bridge invocation binds 22 byte strings in
# total.  Attempt id and creation time are reconstructed from the strict
# receipt by the independent revalidator and are intentionally not accepted as
# weaker caller-supplied substitutes.
STRICT_RAW_EVIDENCE_EDGE_NAMES: tuple[str, ...] = (
    "attester_source_bytes",
    "causal_completion_attestation_bytes",
    "causal_exit_file_bytes",
    "causal_inventory_bytes",
    "causal_launch_expectation_bytes",
    "causal_original_decision_bytes",
    "causal_pid_file_bytes",
    "causal_revalidated_decision_bytes",
    "causal_revalidation_receipt_bytes",
    "causal_revalidator_source_bytes",
    "execution_seal_builder_source_bytes",
    "pretrigger_absence_adapter_source_bytes",
    "pretrigger_absence_evidence_bytes",
    "structured_atomic_publisher_source_bytes",
    "structured_preregistration_bytes",
    "terminal_verifier_execution_plan_bytes",
    "trigger_execution_seal_bytes",
    "trigger_receipt_builder_source_bytes",
    "trigger_receipt_publisher_source_bytes",
    "trigger_receipt_revalidator_source_bytes",
    "trigger_validator_inventory_bytes",
)

_BINDING_KEYS = frozenset({"binding_id", "sha256", "size_bytes"})
_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "attempt_id",
        "trigger_branch",
        "trigger_receipt",
        "strict_raw_evidence_bindings",
        "strict_raw_evidence_edge_count",
        "strict_revalidation",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_ALL_KEYS = _UNSIGNED_KEYS | {"bridge_receipt_sha256"}
_TRIGGER_BINDING_KEYS = frozenset({"file_sha256", "receipt_sha256", "size_bytes"})
_REVALIDATION_KEYS = frozenset(
    {
        "causal_decision_sha256",
        "independent_revalidator_called",
        "tooling_source_commit",
    }
)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StructuredTriggerBridgeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise StructuredTriggerBridgeError(f"non-finite JSON constant: {value}")


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic ASCII JSON or fail closed."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise StructuredTriggerBridgeError("value is not canonical JSON") from exc


def _parse_canonical_object(raw: object, label: str) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise StructuredTriggerBridgeError(f"{label} must be exact canonical bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StructuredTriggerBridgeError(f"{label} is not strict ASCII JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise StructuredTriggerBridgeError(f"{label} is not exact canonical JSON")
    return value


def _exact_object(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise StructuredTriggerBridgeError(f"{label} schema differs")
    return value


def _raw(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        raise StructuredTriggerBridgeError(f"{label} must be exact bytes")
    return value


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _evidence_map(
    *,
    trigger_execution_seal_bytes: object,
    causal_original_decision_bytes: object,
    causal_revalidated_decision_bytes: object,
    causal_completion_attestation_bytes: object,
    causal_revalidation_receipt_bytes: object,
    causal_pid_file_bytes: object,
    causal_exit_file_bytes: object,
    terminal_verifier_execution_plan_bytes: object,
    causal_launch_expectation_bytes: object,
    causal_inventory_bytes: object,
    structured_preregistration_bytes: object,
    trigger_validator_inventory_bytes: object,
    attester_source_bytes: object,
    causal_revalidator_source_bytes: object,
    execution_seal_builder_source_bytes: object,
    structured_atomic_publisher_source_bytes: object,
    trigger_receipt_builder_source_bytes: object,
    trigger_receipt_publisher_source_bytes: object,
    trigger_receipt_revalidator_source_bytes: object,
    pretrigger_absence_adapter_source_bytes: object,
    pretrigger_absence_evidence_bytes: object,
) -> dict[str, bytes]:
    edges = {
        "trigger_execution_seal_bytes": trigger_execution_seal_bytes,
        "causal_original_decision_bytes": causal_original_decision_bytes,
        "causal_revalidated_decision_bytes": causal_revalidated_decision_bytes,
        "causal_completion_attestation_bytes": causal_completion_attestation_bytes,
        "causal_revalidation_receipt_bytes": causal_revalidation_receipt_bytes,
        "causal_pid_file_bytes": causal_pid_file_bytes,
        "causal_exit_file_bytes": causal_exit_file_bytes,
        "terminal_verifier_execution_plan_bytes": (
            terminal_verifier_execution_plan_bytes
        ),
        "causal_launch_expectation_bytes": causal_launch_expectation_bytes,
        "causal_inventory_bytes": causal_inventory_bytes,
        "structured_preregistration_bytes": structured_preregistration_bytes,
        "trigger_validator_inventory_bytes": trigger_validator_inventory_bytes,
        "attester_source_bytes": attester_source_bytes,
        "causal_revalidator_source_bytes": causal_revalidator_source_bytes,
        "execution_seal_builder_source_bytes": execution_seal_builder_source_bytes,
        "structured_atomic_publisher_source_bytes": (
            structured_atomic_publisher_source_bytes
        ),
        "trigger_receipt_builder_source_bytes": trigger_receipt_builder_source_bytes,
        "trigger_receipt_publisher_source_bytes": (
            trigger_receipt_publisher_source_bytes
        ),
        "trigger_receipt_revalidator_source_bytes": (
            trigger_receipt_revalidator_source_bytes
        ),
        "pretrigger_absence_adapter_source_bytes": (
            pretrigger_absence_adapter_source_bytes
        ),
        "pretrigger_absence_evidence_bytes": pretrigger_absence_evidence_bytes,
    }
    if tuple(sorted(edges)) != STRICT_RAW_EVIDENCE_EDGE_NAMES:
        raise AssertionError("strict revalidator evidence API drift")
    return {name: _raw(value, name) for name, value in edges.items()}


def _revalidate_and_render(
    trigger_receipt_bytes: object,
    *,
    trigger_execution_seal_bytes: object,
    causal_original_decision_bytes: object,
    causal_revalidated_decision_bytes: object,
    causal_completion_attestation_bytes: object,
    causal_revalidation_receipt_bytes: object,
    causal_pid_file_bytes: object,
    causal_exit_file_bytes: object,
    terminal_verifier_execution_plan_bytes: object,
    causal_launch_expectation_bytes: object,
    causal_inventory_bytes: object,
    structured_preregistration_bytes: object,
    trigger_validator_inventory_bytes: object,
    attester_source_bytes: object,
    causal_revalidator_source_bytes: object,
    execution_seal_builder_source_bytes: object,
    structured_atomic_publisher_source_bytes: object,
    trigger_receipt_builder_source_bytes: object,
    trigger_receipt_publisher_source_bytes: object,
    trigger_receipt_revalidator_source_bytes: object,
    pretrigger_absence_adapter_source_bytes: object,
    pretrigger_absence_evidence_bytes: object,
) -> StructuredTriggerBridgeValidation:
    receipt_raw = _raw(trigger_receipt_bytes, "trigger_receipt_bytes")
    edges = _evidence_map(
        trigger_execution_seal_bytes=trigger_execution_seal_bytes,
        causal_original_decision_bytes=causal_original_decision_bytes,
        causal_revalidated_decision_bytes=causal_revalidated_decision_bytes,
        causal_completion_attestation_bytes=causal_completion_attestation_bytes,
        causal_revalidation_receipt_bytes=causal_revalidation_receipt_bytes,
        causal_pid_file_bytes=causal_pid_file_bytes,
        causal_exit_file_bytes=causal_exit_file_bytes,
        terminal_verifier_execution_plan_bytes=terminal_verifier_execution_plan_bytes,
        causal_launch_expectation_bytes=causal_launch_expectation_bytes,
        causal_inventory_bytes=causal_inventory_bytes,
        structured_preregistration_bytes=structured_preregistration_bytes,
        trigger_validator_inventory_bytes=trigger_validator_inventory_bytes,
        attester_source_bytes=attester_source_bytes,
        causal_revalidator_source_bytes=causal_revalidator_source_bytes,
        execution_seal_builder_source_bytes=execution_seal_builder_source_bytes,
        structured_atomic_publisher_source_bytes=(
            structured_atomic_publisher_source_bytes
        ),
        trigger_receipt_builder_source_bytes=trigger_receipt_builder_source_bytes,
        trigger_receipt_publisher_source_bytes=(trigger_receipt_publisher_source_bytes),
        trigger_receipt_revalidator_source_bytes=(
            trigger_receipt_revalidator_source_bytes
        ),
        pretrigger_absence_adapter_source_bytes=(
            pretrigger_absence_adapter_source_bytes
        ),
        pretrigger_absence_evidence_bytes=pretrigger_absence_evidence_bytes,
    )
    try:
        result = strict_revalidator.validate_trigger_a_receipt_bytes(
            receipt_raw, **edges
        )
    except strict_revalidator.TriggerReceiptError as exc:
        raise StructuredTriggerBridgeError(
            "independent strict trigger revalidation failed"
        ) from exc
    if result.model_calls_authorized or result.operational_authorization:
        raise StructuredTriggerBridgeError(
            "strict revalidator returned forbidden authority"
        )
    bindings = [
        {
            "binding_id": name,
            "sha256": _sha(edges[name]),
            "size_bytes": len(edges[name]),
        }
        for name in STRICT_RAW_EVIDENCE_EDGE_NAMES
    ]
    unsigned = {
        "protocol": BRIDGE_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": BRIDGE_STATUS,
        "attempt_id": result.attempt_id,
        "trigger_branch": result.trigger_branch,
        "trigger_receipt": {
            "file_sha256": _sha(receipt_raw),
            "receipt_sha256": result.trigger_receipt_sha256,
            "size_bytes": len(receipt_raw),
        },
        "strict_raw_evidence_bindings": bindings,
        "strict_raw_evidence_edge_count": len(bindings),
        "strict_revalidation": {
            "causal_decision_sha256": result.causal_decision_sha256,
            "independent_revalidator_called": True,
            "tooling_source_commit": result.tooling_source_commit,
        },
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    payload = dict(unsigned)
    payload["bridge_receipt_sha256"] = _sha(canonical_json_bytes(unsigned))
    bridge_raw = canonical_json_bytes(payload)
    return StructuredTriggerBridgeValidation(
        attempt_id=result.attempt_id,
        trigger_branch=result.trigger_branch,
        tooling_source_commit=result.tooling_source_commit,
        trigger_receipt_file_sha256=_sha(receipt_raw),
        trigger_receipt_sha256=result.trigger_receipt_sha256,
        causal_decision_sha256=result.causal_decision_sha256,
        bridge_receipt_sha256=payload["bridge_receipt_sha256"],
        bridge_receipt_bytes=bridge_raw,
        raw_evidence_edge_count=len(bindings),
    )


def revalidate_and_bind_trigger_a_receipt(
    trigger_receipt_bytes: object,
    *,
    trigger_execution_seal_bytes: object,
    causal_original_decision_bytes: object,
    causal_revalidated_decision_bytes: object,
    causal_completion_attestation_bytes: object,
    causal_revalidation_receipt_bytes: object,
    causal_pid_file_bytes: object,
    causal_exit_file_bytes: object,
    terminal_verifier_execution_plan_bytes: object,
    causal_launch_expectation_bytes: object,
    causal_inventory_bytes: object,
    structured_preregistration_bytes: object,
    trigger_validator_inventory_bytes: object,
    attester_source_bytes: object,
    causal_revalidator_source_bytes: object,
    execution_seal_builder_source_bytes: object,
    structured_atomic_publisher_source_bytes: object,
    trigger_receipt_builder_source_bytes: object,
    trigger_receipt_publisher_source_bytes: object,
    trigger_receipt_revalidator_source_bytes: object,
    pretrigger_absence_adapter_source_bytes: object,
    pretrigger_absence_evidence_bytes: object,
) -> StructuredTriggerBridgeValidation:
    """Strictly revalidate Trigger A and return a non-authorizing binding."""

    return _revalidate_and_render(
        trigger_receipt_bytes,
        trigger_execution_seal_bytes=trigger_execution_seal_bytes,
        causal_original_decision_bytes=causal_original_decision_bytes,
        causal_revalidated_decision_bytes=causal_revalidated_decision_bytes,
        causal_completion_attestation_bytes=causal_completion_attestation_bytes,
        causal_revalidation_receipt_bytes=causal_revalidation_receipt_bytes,
        causal_pid_file_bytes=causal_pid_file_bytes,
        causal_exit_file_bytes=causal_exit_file_bytes,
        terminal_verifier_execution_plan_bytes=terminal_verifier_execution_plan_bytes,
        causal_launch_expectation_bytes=causal_launch_expectation_bytes,
        causal_inventory_bytes=causal_inventory_bytes,
        structured_preregistration_bytes=structured_preregistration_bytes,
        trigger_validator_inventory_bytes=trigger_validator_inventory_bytes,
        attester_source_bytes=attester_source_bytes,
        causal_revalidator_source_bytes=causal_revalidator_source_bytes,
        execution_seal_builder_source_bytes=execution_seal_builder_source_bytes,
        structured_atomic_publisher_source_bytes=(
            structured_atomic_publisher_source_bytes
        ),
        trigger_receipt_builder_source_bytes=trigger_receipt_builder_source_bytes,
        trigger_receipt_publisher_source_bytes=(trigger_receipt_publisher_source_bytes),
        trigger_receipt_revalidator_source_bytes=(
            trigger_receipt_revalidator_source_bytes
        ),
        pretrigger_absence_adapter_source_bytes=(
            pretrigger_absence_adapter_source_bytes
        ),
        pretrigger_absence_evidence_bytes=pretrigger_absence_evidence_bytes,
    )


def validate_structured_trigger_bridge_bytes(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    trigger_execution_seal_bytes: object,
    causal_original_decision_bytes: object,
    causal_revalidated_decision_bytes: object,
    causal_completion_attestation_bytes: object,
    causal_revalidation_receipt_bytes: object,
    causal_pid_file_bytes: object,
    causal_exit_file_bytes: object,
    terminal_verifier_execution_plan_bytes: object,
    causal_launch_expectation_bytes: object,
    causal_inventory_bytes: object,
    structured_preregistration_bytes: object,
    trigger_validator_inventory_bytes: object,
    attester_source_bytes: object,
    causal_revalidator_source_bytes: object,
    execution_seal_builder_source_bytes: object,
    structured_atomic_publisher_source_bytes: object,
    trigger_receipt_builder_source_bytes: object,
    trigger_receipt_publisher_source_bytes: object,
    trigger_receipt_revalidator_source_bytes: object,
    pretrigger_absence_adapter_source_bytes: object,
    pretrigger_absence_evidence_bytes: object,
) -> StructuredTriggerBridgeValidation:
    """Re-run strict validation and compare the exact reconstructed bridge."""

    observed = _parse_canonical_object(raw, "structured_trigger_bridge_bytes")
    _exact_object(observed, _ALL_KEYS, "structured trigger bridge")
    expected = _revalidate_and_render(
        trigger_receipt_bytes,
        trigger_execution_seal_bytes=trigger_execution_seal_bytes,
        causal_original_decision_bytes=causal_original_decision_bytes,
        causal_revalidated_decision_bytes=causal_revalidated_decision_bytes,
        causal_completion_attestation_bytes=causal_completion_attestation_bytes,
        causal_revalidation_receipt_bytes=causal_revalidation_receipt_bytes,
        causal_pid_file_bytes=causal_pid_file_bytes,
        causal_exit_file_bytes=causal_exit_file_bytes,
        terminal_verifier_execution_plan_bytes=terminal_verifier_execution_plan_bytes,
        causal_launch_expectation_bytes=causal_launch_expectation_bytes,
        causal_inventory_bytes=causal_inventory_bytes,
        structured_preregistration_bytes=structured_preregistration_bytes,
        trigger_validator_inventory_bytes=trigger_validator_inventory_bytes,
        attester_source_bytes=attester_source_bytes,
        causal_revalidator_source_bytes=causal_revalidator_source_bytes,
        execution_seal_builder_source_bytes=execution_seal_builder_source_bytes,
        structured_atomic_publisher_source_bytes=(
            structured_atomic_publisher_source_bytes
        ),
        trigger_receipt_builder_source_bytes=trigger_receipt_builder_source_bytes,
        trigger_receipt_publisher_source_bytes=(trigger_receipt_publisher_source_bytes),
        trigger_receipt_revalidator_source_bytes=(
            trigger_receipt_revalidator_source_bytes
        ),
        pretrigger_absence_adapter_source_bytes=(
            pretrigger_absence_adapter_source_bytes
        ),
        pretrigger_absence_evidence_bytes=pretrigger_absence_evidence_bytes,
    )
    if raw != expected.bridge_receipt_bytes:
        raise StructuredTriggerBridgeError(
            "structured trigger bridge differs from strict reconstruction"
        )
    trigger = _exact_object(
        observed["trigger_receipt"], _TRIGGER_BINDING_KEYS, "trigger receipt binding"
    )
    revalidation = _exact_object(
        observed["strict_revalidation"],
        _REVALIDATION_KEYS,
        "strict revalidation",
    )
    bindings = observed["strict_raw_evidence_bindings"]
    if type(bindings) is not list or len(bindings) != len(
        STRICT_RAW_EVIDENCE_EDGE_NAMES
    ):
        raise StructuredTriggerBridgeError("strict raw evidence binding count differs")
    for index, binding in enumerate(bindings):
        row = _exact_object(binding, _BINDING_KEYS, f"binding[{index}]")
        if row["binding_id"] != STRICT_RAW_EVIDENCE_EDGE_NAMES[index]:
            raise StructuredTriggerBridgeError("strict evidence binding order differs")
    if (
        observed["protocol"] != BRIDGE_PROTOCOL
        or observed["schema_version"] != SCHEMA_VERSION
        or observed["status"] != BRIDGE_STATUS
        or observed["model_calls_authorized"] is not False
        or observed["operational_authorization"] is not False
        or revalidation["independent_revalidator_called"] is not True
        or revalidation["tooling_source_commit"] != expected.tooling_source_commit
        or trigger["file_sha256"] != expected.trigger_receipt_file_sha256
    ):
        raise StructuredTriggerBridgeError("structured trigger bridge contract differs")
    return expected
