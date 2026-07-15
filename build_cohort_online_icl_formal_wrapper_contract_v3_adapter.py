"""Truthful V3 adapter for the future online-ICL pass branch.

This module freezes the pass-branch bridge before causal reveal.  It validates
the authoritative V3 closure/fence/control chain before a private compatibility
projection may enter the existing online-ICL contract builder.  The legacy
contract is never returned or published; its digest is bound into a public V3
envelope with all authorization flags false.
"""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import cohort_closed_loop_structured_trigger_receipt_v3_adapter as common


PROTOCOL = "cohort_online_icl_formal_wrapper_contract_v3_adapter_v1"
SCHEMA_VERSION = 1
STATUS = "validated_non_authorizing"
BRANCH = "online_icl_future_pass"
LEGACY_CONTRACT_PROTOCOL = "cohort_online_icl_formal_wrapper_contract_v1"

EXPECTED_CLASSIFICATION = {
    "decision": "pass",
    "decision_scope": "internal_gate_pass",
    "status": "valid",
}

AuthoritativeValidator = Callable[..., Mapping[str, Any]]
LegacyContractBuilder = Callable[..., Mapping[str, Any]]


class V3OnlineICLAdapterError(RuntimeError):
    """Raised when the pre-reveal V3 pass-branch adapter fails closed."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_online_context(
    value: Mapping[str, Any], *, attempt_id: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != common._VALIDATED_CONTEXT_KEYS:
        raise V3OnlineICLAdapterError(
            "authoritative online adapter context schema differs"
        )
    context = dict(value)
    if context["attempt_id"] != attempt_id:
        raise V3OnlineICLAdapterError("authoritative online adapter attempt differs")
    commit = context["tooling_source_commit"]
    if not isinstance(commit, str) or common._COMMIT_RE.fullmatch(commit) is None:
        raise V3OnlineICLAdapterError("authoritative online adapter commit is invalid")
    classification = context["causal_classification"]
    if (
        not isinstance(classification, Mapping)
        or set(classification) != common._CLASSIFICATION_KEYS
        or dict(classification) != EXPECTED_CLASSIFICATION
    ):
        raise V3OnlineICLAdapterError("online adapter causal branch differs")
    if context["truth_fields"] != common.TRUTH_FIELDS:
        raise V3OnlineICLAdapterError("authoritative V3 truth fields differ")
    projection = context["private_projection"]
    if (
        not isinstance(projection, Mapping)
        or set(projection) != {"contract_kwargs"}
        or not isinstance(projection["contract_kwargs"], Mapping)
        or not projection["contract_kwargs"]
        or any(
            not isinstance(key, str) or not key for key in projection["contract_kwargs"]
        )
    ):
        raise V3OnlineICLAdapterError("private online contract projection is missing")
    context["causal_classification"] = dict(classification)
    context["private_projection"] = {
        "contract_kwargs": dict(projection["contract_kwargs"])
    }
    return context


def build_online_icl_formal_wrapper_contract_v3_adapter_bytes(
    *,
    durable_attempt_root: str | Path,
    authoritative_artifacts: Mapping[str, object],
    authoritative_paths: Mapping[str, object],
    authoritative_validator: AuthoritativeValidator | None = None,
    legacy_contract_builder: LegacyContractBuilder | None = None,
) -> bytes:
    """Validate the V3 pass branch and return only its non-authorizing envelope."""

    try:
        root, raws, paths, bindings = common._normalize_artifacts(
            durable_attempt_root=durable_attempt_root,
            authoritative_artifacts=authoritative_artifacts,
            authoritative_paths=authoritative_paths,
            require_execution_seal=False,
        )
        common._protocol_precheck(raws)
    except common.V3TriggerAdapterError as exc:
        raise V3OnlineICLAdapterError(
            "online adapter authoritative V3 inputs are invalid"
        ) from exc
    validate = authoritative_validator or common._default_authoritative_validator
    try:
        raw_context = validate(
            authoritative_artifacts=raws,
            authoritative_paths=paths,
            durable_attempt_root=root,
            require_execution_seal=False,
            adapter_kind=BRANCH,
        )
        context = _validate_online_context(raw_context, attempt_id=root.name)
    except V3OnlineICLAdapterError:
        raise
    except Exception as exc:
        raise V3OnlineICLAdapterError(
            "authoritative V3 online branch validation failed"
        ) from exc

    projection = context["private_projection"]
    projection_sha = common.canonical_sha256(common._projection_manifest(projection))
    # Resolve and enter the legacy builder only after authoritative V3 closure.
    if legacy_contract_builder is None:
        legacy_contract_builder = importlib.import_module(
            "build_cohort_online_icl_formal_wrapper_contract"
        ).create_contract
    try:
        legacy_contract = legacy_contract_builder(**projection["contract_kwargs"])
    except Exception as exc:
        raise V3OnlineICLAdapterError(
            "private legacy online-ICL contract engine rejected projection"
        ) from exc
    if (
        not isinstance(legacy_contract, Mapping)
        or legacy_contract.get("protocol") != LEGACY_CONTRACT_PROTOCOL
        or legacy_contract.get("schema_version") != 1
    ):
        raise V3OnlineICLAdapterError("private legacy online-ICL proof is invalid")
    legacy_contract_proof = common.canonical_sha256(dict(legacy_contract))

    unsigned = {
        "attempt_id": root.name,
        "authoritative_v3_artifacts": bindings,
        "branch": BRANCH,
        "causal_classification": context["causal_classification"],
        "completion_method": common.COMPLETION_METHOD,
        "historical_exit_order_claimed": common.HISTORICAL_EXIT_ORDER_CLAIMED,
        "legacy_contract_proof_sha256": legacy_contract_proof,
        "legacy_publication": common.LEGACY_PUBLICATION,
        "legacy_strict_mtime_proof": common.LEGACY_STRICT_MTIME_PROOF,
        "model_calls_authorized": False,
        "mtime_relation": common.MTIME_RELATION,
        "operational_authorization": False,
        "outcome_blind_adapter_registration": True,
        "private_projection_sha256": projection_sha,
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tooling_source_commit": context["tooling_source_commit"],
    }
    envelope = dict(unsigned)
    envelope["adapter_contract_sha256"] = common.canonical_sha256(unsigned)
    return common.canonical_bytes(envelope)


def validate_online_icl_adapter_envelope_bytes(payload: bytes) -> dict[str, Any]:
    try:
        value = common.strict_json_object(payload, "V3 online-ICL adapter envelope")
    except common.V3TriggerAdapterError as exc:
        raise V3OnlineICLAdapterError(
            "V3 online-ICL adapter envelope is not strict JSON"
        ) from exc
    unsigned_keys = {
        "attempt_id",
        "authoritative_v3_artifacts",
        "branch",
        "causal_classification",
        "completion_method",
        "historical_exit_order_claimed",
        "legacy_contract_proof_sha256",
        "legacy_publication",
        "legacy_strict_mtime_proof",
        "model_calls_authorized",
        "mtime_relation",
        "operational_authorization",
        "outcome_blind_adapter_registration",
        "private_projection_sha256",
        "protocol",
        "schema_version",
        "status",
        "tooling_source_commit",
    }
    if set(value) != unsigned_keys | {"adapter_contract_sha256"}:
        raise V3OnlineICLAdapterError("V3 online-ICL adapter envelope schema differs")
    if payload != common.canonical_bytes(value):
        raise V3OnlineICLAdapterError("V3 online-ICL adapter envelope is not canonical")
    if (
        value["protocol"] != PROTOCOL
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] != STATUS
        or value["branch"] != BRANCH
        or value["causal_classification"] != EXPECTED_CLASSIFICATION
        or value["completion_method"] != common.COMPLETION_METHOD
        or value["historical_exit_order_claimed"] is not False
        or value["legacy_publication"] is not False
        or value["legacy_strict_mtime_proof"] is not False
        or value["model_calls_authorized"] is not False
        or value["mtime_relation"] != common.MTIME_RELATION
        or value["operational_authorization"] is not False
        or value["outcome_blind_adapter_registration"] is not True
    ):
        raise V3OnlineICLAdapterError("V3 online-ICL adapter public claims differ")
    if (
        not isinstance(value["attempt_id"], str)
        or common._ATTEMPT_RE.fullmatch(value["attempt_id"]) is None
        or not isinstance(value["tooling_source_commit"], str)
        or common._COMMIT_RE.fullmatch(value["tooling_source_commit"]) is None
    ):
        raise V3OnlineICLAdapterError("V3 online-ICL adapter identity differs")
    try:
        common._validate_public_bindings(
            value["authoritative_v3_artifacts"],
            attempt_id=value["attempt_id"],
            require_execution_seal=False,
        )
    except common.V3TriggerAdapterError as exc:
        raise V3OnlineICLAdapterError(
            "V3 online-ICL authoritative bindings differ"
        ) from exc
    for key in (
        "adapter_contract_sha256",
        "legacy_contract_proof_sha256",
        "private_projection_sha256",
    ):
        item = value[key]
        if not isinstance(item, str) or common._SHA256_RE.fullmatch(item) is None:
            raise V3OnlineICLAdapterError(
                f"V3 online-ICL adapter digest is invalid: {key}"
            )
    if value["adapter_contract_sha256"] != common.canonical_sha256(
        {key: value[key] for key in unsigned_keys}
    ):
        raise V3OnlineICLAdapterError("V3 online-ICL adapter self digest differs")
    return value


def build_online_icl_formal_wrapper_contract_v3_adapter_from_root(
    *,
    durable_attempt_root: str | Path,
    prospective_output_path: str | Path,
    authoritative_validator: AuthoritativeValidator | None = None,
    legacy_contract_builder: LegacyContractBuilder | None = None,
) -> bytes:
    """Load fixed V3 files without symlinks, return envelope bytes, publish nothing."""

    root = common._normalized_root(durable_attempt_root)
    common.assert_prospective_output_absent(prospective_output_path)
    relatives = {
        name: relative
        for name, relative in common.AUTHORITATIVE_RELATIVE_PATHS.items()
        if name != "execution_seal"
    }
    paths = {name: (root / relative).as_posix() for name, relative in relatives.items()}
    control_names = ("failure_closure", "completion_fence", "execution_plan")
    raws = {
        name: common._read_stable_no_symlink(Path(paths[name]))
        for name in control_names
    }
    common._protocol_precheck(raws)
    raws.update(
        {
            name: common._read_stable_no_symlink(Path(path))
            for name, path in paths.items()
            if name not in raws
        }
    )
    result = build_online_icl_formal_wrapper_contract_v3_adapter_bytes(
        durable_attempt_root=root,
        authoritative_artifacts=raws,
        authoritative_paths=paths,
        authoritative_validator=authoritative_validator,
        legacy_contract_builder=legacy_contract_builder,
    )
    for name, path in paths.items():
        if common._read_stable_no_symlink(Path(path)) != raws[name]:
            raise V3OnlineICLAdapterError(
                f"authoritative input drifted before online adapter return: {name}"
            )
    common.assert_prospective_output_absent(prospective_output_path)
    return result


__all__ = (
    "BRANCH",
    "EXPECTED_CLASSIFICATION",
    "PROTOCOL",
    "SCHEMA_VERSION",
    "V3OnlineICLAdapterError",
    "build_online_icl_formal_wrapper_contract_v3_adapter_bytes",
    "build_online_icl_formal_wrapper_contract_v3_adapter_from_root",
    "validate_online_icl_adapter_envelope_bytes",
)
