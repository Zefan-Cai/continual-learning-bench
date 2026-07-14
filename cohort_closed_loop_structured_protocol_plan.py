"""Pure raw-byte protocol-plan seal for the structured closed-loop pivot.

The plan is deliberately pre-operational.  It re-runs the strict Trigger-A
bridge, revalidates a clean deployment snapshot against every supplied source
and asset byte string, and binds the committed execution contract and
preregistration.  It never accepts an embedded path/hash inventory without the
corresponding raw bytes and never authorizes DGP generation, model calls,
scorer calls, or a launch.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping

import cohort_closed_loop_structured_deployment_snapshot as deployment
import cohort_closed_loop_structured_trigger_bridge as trigger_bridge

__all__ = (
    "StructuredProtocolPlanError",
    "StructuredProtocolPlanValidation",
    "seal_structured_protocol_plan_bytes",
    "validate_structured_protocol_plan_bytes",
)


class StructuredProtocolPlanError(ValueError):
    """Raised when the raw-byte protocol-plan closure fails closed."""


@dataclass(frozen=True, slots=True)
class StructuredProtocolPlanValidation:
    source_commit: str
    attempt_id: str
    checkout_root: str
    durable_root: str
    protocol_plan_seal_sha256: str
    trigger_receipt_file_sha256: str
    deployment_snapshot_file_sha256: str
    deployment_lease_file_sha256: str
    deployment_observation_file_sha256s: tuple[str, str]
    source_inventory_file_sha256: str
    source_bindings: tuple[tuple[str, str], ...]
    asset_inventory_bindings: tuple[tuple[str, str], ...]
    dgp_generation_authorized: bool = False
    model_calls_authorized: bool = False
    scorer_calls_authorized: bool = False
    operational_authorization: bool = False


SCHEMA_VERSION = 1
PROTOCOL_PLAN = "cohort_structured_raw_byte_protocol_plan_v1"
STATUS = "sealed_pre_dgp_non_authorizing"
EXECUTION_CONTRACT_SHA256 = (
    "447048660d396799f32c6b2ba55acb5b9ac6cf91eb761c7a455a56e64a41cfc1"
)
STRUCTURED_PREREGISTRATION_SHA256 = (
    "d6b1cd92df243a5f2ccfa11ad4613ce5425c6a83ed5abc9337900988a0ea7533"
)
DURABLE_BASE = "/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state"

_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_BINDING_KEYS = frozenset({"sha256", "size_bytes"})
_NAMED_BINDING_KEYS = frozenset({"binding_id", "sha256", "size_bytes"})
_ORDINAL_BINDING_KEYS = frozenset({"ordinal", "sha256", "size_bytes"})
_ASSET_BINDING_KEYS = frozenset({"role", "sha256", "size_bytes"})
_DGP_BINDING_KEYS = frozenset(
    {
        "dgp_context_validation_source_sha256",
        "dgp_generator_source_sha256",
        "dgp_generation_authorized",
        "deployment_snapshot_fresh_consumer_revalidation_required",
        "deployment_snapshot_fresh_consumer_revalidation_available",
        "future_dgp_claim_adapter_required",
    }
)
_PATH_KEYS = frozenset(
    {
        "asset_inventory_directory",
        "checkout_root",
        "durable_root",
        "protocol_plan_seal_path",
        "deployment_capture_lease_path",
        "deployment_observation_paths",
        "deployment_snapshot_path",
        "source_inventory_path",
        "trigger_bridge_path",
        "trigger_receipt_path",
    }
)
_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "attempt_id",
        "strict_trigger_bridge",
        "strict_trigger_receipt",
        "strict_trigger_raw_evidence",
        "deployment_snapshot",
        "deployment_capture_lease",
        "deployment_observations",
        "git_index",
        "source_inventory",
        "source_files",
        "asset_inventories",
        "asset_files",
        "execution_contract",
        "structured_preregistration",
        "raw_input_closure_sha256",
        "dgp_binding",
        "paths",
        "dgp_generation_authorized",
        "model_calls_authorized",
        "scorer_calls_authorized",
        "operational_authorization",
    }
)
_KEYS = _UNSIGNED_KEYS | {"protocol_plan_seal_sha256"}


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise StructuredProtocolPlanError("value is not canonical ASCII JSON") from exc


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StructuredProtocolPlanError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise StructuredProtocolPlanError(f"non-finite JSON constant: {value}")


def _parse(raw: object, label: str) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise StructuredProtocolPlanError(f"{label} must be exact bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StructuredProtocolPlanError(f"{label} is not strict ASCII JSON") from exc
    if type(value) is not dict or _canonical(value) != raw:
        raise StructuredProtocolPlanError(f"{label} is not exact canonical JSON")
    return value


def _object(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise StructuredProtocolPlanError(f"{label} schema differs")
    return value


def _raw(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        raise StructuredProtocolPlanError(f"{label} must be exact bytes")
    return value


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _binding(raw: bytes) -> dict[str, object]:
    return {"sha256": _sha(raw), "size_bytes": len(raw)}


def _exact_role_mapping(
    value: Mapping[str, object], expected: tuple[str, ...], label: str
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(expected):
        raise StructuredProtocolPlanError(f"{label} role set differs")
    return {role: value[role] for role in expected}


def _strict_evidence(
    value: Mapping[str, object],
) -> dict[str, bytes]:
    rows = _exact_role_mapping(
        value,
        trigger_bridge.STRICT_RAW_EVIDENCE_EDGE_NAMES,
        "strict_trigger_evidence_bytes",
    )
    return {name: _raw(rows[name], name) for name in rows}


def _asset_inventory_raws(value: Mapping[str, object]) -> dict[str, bytes]:
    rows = _exact_role_mapping(
        value, deployment.ASSET_ROLE_IDS, "asset_inventory_bytes_by_role"
    )
    return {role: _raw(rows[role], f"asset inventory {role}") for role in rows}


def _source_raws(value: Mapping[str, object]) -> dict[str, bytes]:
    rows = _exact_role_mapping(
        value, deployment.SOURCE_ROLE_IDS, "source_file_bytes_by_role"
    )
    return {role: _raw(rows[role], f"source file {role}") for role in rows}


def _asset_file_raws(
    value: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, bytes]]:
    rows = _exact_role_mapping(
        value, deployment.ASSET_ROLE_IDS, "asset_file_bytes_by_role"
    )
    result: dict[str, dict[str, bytes]] = {}
    for role in deployment.ASSET_ROLE_IDS:
        files = rows[role]
        if not isinstance(files, Mapping) or not files:
            raise StructuredProtocolPlanError(f"asset {role} raw file map differs")
        normalized: dict[str, bytes] = {}
        for relative, raw in files.items():
            if (
                type(relative) is not str
                or not relative
                or relative.startswith("/")
                or posixpath.normpath(relative) != relative
                or any(part in {"", ".", ".."} for part in relative.split("/"))
            ):
                raise StructuredProtocolPlanError(f"asset {role} relative path differs")
            normalized[relative] = _raw(raw, f"asset {role}:{relative}")
        result[role] = normalized
    return result


def _named_bindings(raws: Mapping[str, bytes]) -> list[dict[str, object]]:
    return [
        {
            "binding_id": binding_id,
            "sha256": _sha(raws[binding_id]),
            "size_bytes": len(raws[binding_id]),
        }
        for binding_id in sorted(raws)
    ]


def _asset_file_bindings(
    asset_files: Mapping[str, Mapping[str, bytes]],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for role in deployment.ASSET_ROLE_IDS:
        files = [
            {
                "relative_path": relative,
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
            for relative, raw in sorted(asset_files[role].items())
        ]
        result.append(
            {
                "role": role,
                "file_count": len(files),
                "files": files,
                "closed_inventory_sha256": _sha(_canonical(files)),
            }
        )
    return result


def _paths(source_commit: str, attempt_id: str, checkout_root: str) -> dict[str, str]:
    durable_root = str(
        PurePosixPath(DURABLE_BASE, source_commit, "attempts", attempt_id)
    )
    return {
        "checkout_root": checkout_root,
        "durable_root": durable_root,
        "source_inventory_path": f"{durable_root}/control/source_inventory.json",
        "asset_inventory_directory": f"{durable_root}/control/asset_inventories",
        "trigger_receipt_path": f"{durable_root}/control/trigger_receipt.json",
        "trigger_bridge_path": f"{durable_root}/control/trigger_bridge.json",
        "deployment_capture_lease_path": (
            f"{durable_root}/{deployment.LEASE_RELATIVE_PATH}"
        ),
        "deployment_observation_paths": [
            f"{durable_root}/{relative}"
            for relative in deployment.OBSERVATION_RELATIVE_PATHS
        ],
        "deployment_snapshot_path": (
            f"{durable_root}/{deployment.SNAPSHOT_RELATIVE_PATH}"
        ),
        "protocol_plan_seal_path": (
            f"{durable_root}/control/structured_protocol_plan_seal.json"
        ),
    }


def _assemble(
    *,
    strict_trigger_bridge_bytes: object,
    strict_trigger_receipt_bytes: object,
    strict_trigger_evidence_bytes: Mapping[str, object],
    deployment_snapshot_bytes: object,
    lease_receipt_bytes: object,
    observation_bytes: object,
    git_index_bytes: object,
    source_inventory_bytes: object,
    asset_inventory_bytes_by_role: Mapping[str, object],
    source_file_bytes_by_role: Mapping[str, object],
    asset_file_bytes_by_role: Mapping[str, Mapping[str, object]],
    execution_contract_bytes: object,
    structured_preregistration_bytes: object,
) -> tuple[bytes, StructuredProtocolPlanValidation]:
    bridge_raw = _raw(strict_trigger_bridge_bytes, "strict_trigger_bridge_bytes")
    receipt_raw = _raw(strict_trigger_receipt_bytes, "strict_trigger_receipt_bytes")
    evidence = _strict_evidence(strict_trigger_evidence_bytes)
    try:
        bridge_validation = trigger_bridge.validate_structured_trigger_bridge_bytes(
            bridge_raw,
            trigger_receipt_bytes=receipt_raw,
            **evidence,
        )
    except trigger_bridge.StructuredTriggerBridgeError as exc:
        raise StructuredProtocolPlanError("strict trigger bridge failed") from exc
    if (
        bridge_validation.model_calls_authorized
        or bridge_validation.operational_authorization
    ):
        raise StructuredProtocolPlanError("strict trigger bridge carried authority")

    snapshot_raw = _raw(deployment_snapshot_bytes, "deployment_snapshot_bytes")
    lease_raw = _raw(lease_receipt_bytes, "lease_receipt_bytes")
    if (
        type(observation_bytes) is not tuple
        or len(observation_bytes) != 2
        or any(type(value) is not bytes for value in observation_bytes)
    ):
        raise StructuredProtocolPlanError(
            "observation_bytes must be an exact byte pair"
        )
    observation_raws = observation_bytes
    git_index_raw = _raw(git_index_bytes, "git_index_bytes")
    source_inventory_raw = _raw(source_inventory_bytes, "source_inventory_bytes")
    asset_inventory_raws = _asset_inventory_raws(asset_inventory_bytes_by_role)
    source_raws = _source_raws(source_file_bytes_by_role)
    asset_raws = _asset_file_raws(asset_file_bytes_by_role)
    contract_raw = _raw(execution_contract_bytes, "execution_contract_bytes")
    prereg_raw = _raw(
        structured_preregistration_bytes, "structured_preregistration_bytes"
    )
    try:
        snapshot_validation = deployment.validate_deployment_snapshot_bytes(
            snapshot_raw,
            source_inventory_bytes=source_inventory_raw,
            asset_inventory_bytes_by_role=asset_inventory_raws,
            source_file_bytes_by_role=source_raws,
            asset_file_bytes_by_role=asset_raws,
            execution_contract_bytes=contract_raw,
            structured_preregistration_bytes=prereg_raw,
            git_index_bytes=git_index_raw,
            lease_receipt_bytes=lease_raw,
            observation_bytes=observation_raws,
        )
    except deployment.DeploymentSnapshotError as exc:
        raise StructuredProtocolPlanError("deployment snapshot failed") from exc
    if (
        snapshot_validation.model_calls_authorized
        or snapshot_validation.operational_authorization
        or snapshot_validation.dgp_generation_authorized
        or not snapshot_validation.fresh_consumer_revalidation_required
    ):
        raise StructuredProtocolPlanError("deployment snapshot carried authority")
    if _sha(contract_raw) != EXECUTION_CONTRACT_SHA256:
        raise StructuredProtocolPlanError("execution contract bytes are not registered")
    if _sha(prereg_raw) != STRUCTURED_PREREGISTRATION_SHA256:
        raise StructuredProtocolPlanError(
            "structured preregistration bytes are not registered"
        )
    if bridge_validation.attempt_id != snapshot_validation.attempt_id:
        raise StructuredProtocolPlanError("trigger/deployment attempt join differs")
    if bridge_validation.tooling_source_commit != snapshot_validation.source_commit:
        raise StructuredProtocolPlanError(
            "trigger tooling/deployment source commit join differs"
        )

    source_files = _named_bindings(source_raws)
    evidence_bindings = _named_bindings(evidence)
    asset_inventories = [
        {
            "role": role,
            "sha256": _sha(asset_inventory_raws[role]),
            "size_bytes": len(asset_inventory_raws[role]),
        }
        for role in deployment.ASSET_ROLE_IDS
    ]
    asset_files = _asset_file_bindings(asset_raws)
    closure = {
        "strict_trigger_bridge": _binding(bridge_raw),
        "strict_trigger_receipt": _binding(receipt_raw),
        "strict_trigger_raw_evidence": evidence_bindings,
        "deployment_snapshot": _binding(snapshot_raw),
        "deployment_capture_lease": _binding(lease_raw),
        "deployment_observations": [
            {"ordinal": index + 1, **_binding(raw)}
            for index, raw in enumerate(observation_raws)
        ],
        "git_index": _binding(git_index_raw),
        "source_inventory": _binding(source_inventory_raw),
        "source_files": source_files,
        "asset_inventories": asset_inventories,
        "asset_files": asset_files,
        "execution_contract": _binding(contract_raw),
        "structured_preregistration": _binding(prereg_raw),
    }
    source_digest_map = dict(snapshot_validation.source_bindings)
    dgp_binding = {
        "dgp_context_validation_source_sha256": source_digest_map[
            "structured_dgp_context_validation"
        ],
        "dgp_generator_source_sha256": source_digest_map["dgp_generator"],
        "dgp_generation_authorized": False,
        "deployment_snapshot_fresh_consumer_revalidation_required": True,
        "deployment_snapshot_fresh_consumer_revalidation_available": False,
        "future_dgp_claim_adapter_required": True,
    }
    paths = _paths(
        snapshot_validation.source_commit,
        snapshot_validation.attempt_id,
        snapshot_validation.checkout_root,
    )
    unsigned = {
        "protocol": PROTOCOL_PLAN,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "source_commit": snapshot_validation.source_commit,
        "attempt_id": snapshot_validation.attempt_id,
        **closure,
        "raw_input_closure_sha256": _sha(_canonical(closure)),
        "dgp_binding": dgp_binding,
        "paths": paths,
        "dgp_generation_authorized": False,
        "model_calls_authorized": False,
        "scorer_calls_authorized": False,
        "operational_authorization": False,
    }
    payload = dict(unsigned)
    payload["protocol_plan_seal_sha256"] = _sha(_canonical(unsigned))
    raw = _canonical(payload)
    validation = StructuredProtocolPlanValidation(
        source_commit=snapshot_validation.source_commit,
        attempt_id=snapshot_validation.attempt_id,
        checkout_root=snapshot_validation.checkout_root,
        durable_root=paths["durable_root"],
        protocol_plan_seal_sha256=payload["protocol_plan_seal_sha256"],
        trigger_receipt_file_sha256=_sha(receipt_raw),
        deployment_snapshot_file_sha256=_sha(snapshot_raw),
        deployment_lease_file_sha256=_sha(lease_raw),
        deployment_observation_file_sha256s=tuple(
            _sha(raw) for raw in observation_raws
        ),
        source_inventory_file_sha256=_sha(source_inventory_raw),
        source_bindings=snapshot_validation.source_bindings,
        asset_inventory_bindings=snapshot_validation.asset_inventory_bindings,
    )
    return raw, validation


def seal_structured_protocol_plan_bytes(
    *,
    strict_trigger_bridge_bytes: object,
    strict_trigger_receipt_bytes: object,
    strict_trigger_evidence_bytes: Mapping[str, object],
    deployment_snapshot_bytes: object,
    lease_receipt_bytes: object,
    observation_bytes: object,
    git_index_bytes: object,
    source_inventory_bytes: object,
    asset_inventory_bytes_by_role: Mapping[str, object],
    source_file_bytes_by_role: Mapping[str, object],
    asset_file_bytes_by_role: Mapping[str, Mapping[str, object]],
    execution_contract_bytes: object,
    structured_preregistration_bytes: object,
) -> bytes:
    """Create a canonical non-authorizing plan from the complete raw closure."""

    raw, _ = _assemble(
        strict_trigger_bridge_bytes=strict_trigger_bridge_bytes,
        strict_trigger_receipt_bytes=strict_trigger_receipt_bytes,
        strict_trigger_evidence_bytes=strict_trigger_evidence_bytes,
        deployment_snapshot_bytes=deployment_snapshot_bytes,
        lease_receipt_bytes=lease_receipt_bytes,
        observation_bytes=observation_bytes,
        git_index_bytes=git_index_bytes,
        source_inventory_bytes=source_inventory_bytes,
        asset_inventory_bytes_by_role=asset_inventory_bytes_by_role,
        source_file_bytes_by_role=source_file_bytes_by_role,
        asset_file_bytes_by_role=asset_file_bytes_by_role,
        execution_contract_bytes=execution_contract_bytes,
        structured_preregistration_bytes=structured_preregistration_bytes,
    )
    return raw


def validate_structured_protocol_plan_bytes(
    raw: object,
    *,
    strict_trigger_bridge_bytes: object,
    strict_trigger_receipt_bytes: object,
    strict_trigger_evidence_bytes: Mapping[str, object],
    deployment_snapshot_bytes: object,
    lease_receipt_bytes: object,
    observation_bytes: object,
    git_index_bytes: object,
    source_inventory_bytes: object,
    asset_inventory_bytes_by_role: Mapping[str, object],
    source_file_bytes_by_role: Mapping[str, object],
    asset_file_bytes_by_role: Mapping[str, Mapping[str, object]],
    execution_contract_bytes: object,
    structured_preregistration_bytes: object,
) -> StructuredProtocolPlanValidation:
    """Rebuild the plan from raw inputs and require exact byte equality."""

    observed_raw = _raw(raw, "protocol_plan_seal_bytes")
    observed = _object(
        _parse(observed_raw, "protocol_plan_seal_bytes"),
        _KEYS,
        "protocol plan",
    )
    expected_raw, validation = _assemble(
        strict_trigger_bridge_bytes=strict_trigger_bridge_bytes,
        strict_trigger_receipt_bytes=strict_trigger_receipt_bytes,
        strict_trigger_evidence_bytes=strict_trigger_evidence_bytes,
        deployment_snapshot_bytes=deployment_snapshot_bytes,
        lease_receipt_bytes=lease_receipt_bytes,
        observation_bytes=observation_bytes,
        git_index_bytes=git_index_bytes,
        source_inventory_bytes=source_inventory_bytes,
        asset_inventory_bytes_by_role=asset_inventory_bytes_by_role,
        source_file_bytes_by_role=source_file_bytes_by_role,
        asset_file_bytes_by_role=asset_file_bytes_by_role,
        execution_contract_bytes=execution_contract_bytes,
        structured_preregistration_bytes=structured_preregistration_bytes,
    )
    if observed_raw != expected_raw:
        raise StructuredProtocolPlanError(
            "protocol plan differs from complete raw-byte reconstruction"
        )
    if (
        observed["protocol"] != PROTOCOL_PLAN
        or observed["schema_version"] != SCHEMA_VERSION
        or observed["status"] != STATUS
        or observed["dgp_generation_authorized"] is not False
        or observed["model_calls_authorized"] is not False
        or observed["scorer_calls_authorized"] is not False
        or observed["operational_authorization"] is not False
    ):
        raise StructuredProtocolPlanError("protocol plan authority contract differs")
    _object(observed["dgp_binding"], _DGP_BINDING_KEYS, "dgp binding")
    _object(observed["paths"], _PATH_KEYS, "paths")
    for key in (
        "strict_trigger_bridge",
        "strict_trigger_receipt",
        "deployment_snapshot",
        "deployment_capture_lease",
        "git_index",
        "source_inventory",
        "execution_contract",
        "structured_preregistration",
    ):
        _object(observed[key], _BINDING_KEYS, key)
    observations = observed["deployment_observations"]
    if type(observations) is not list or len(observations) != 2:
        raise StructuredProtocolPlanError("deployment observation bindings differ")
    for index, row in enumerate(observations):
        binding = _object(
            row, _ORDINAL_BINDING_KEYS, f"deployment observation[{index}]"
        )
        if type(binding["ordinal"]) is not int or binding["ordinal"] != index + 1:
            raise StructuredProtocolPlanError("deployment observation order differs")
    for index, row in enumerate(observed["strict_trigger_raw_evidence"]):
        _object(row, _NAMED_BINDING_KEYS, f"strict evidence[{index}]")
    for index, row in enumerate(observed["source_files"]):
        _object(row, _NAMED_BINDING_KEYS, f"source file[{index}]")
    for index, row in enumerate(observed["asset_inventories"]):
        _object(row, _ASSET_BINDING_KEYS, f"asset inventory[{index}]")
    if (
        type(observed["raw_input_closure_sha256"]) is not str
        or _SHA_RE.fullmatch(observed["raw_input_closure_sha256"]) is None
        or type(observed["protocol_plan_seal_sha256"]) is not str
        or _SHA_RE.fullmatch(observed["protocol_plan_seal_sha256"]) is None
    ):
        raise StructuredProtocolPlanError("protocol plan digest type differs")
    return validation
