"""Strict, raw-byte v2 stage-plan bridge for the pre-DGP boundary.

This module consumes the complete v1 protocol-plan reconstruction inputs and
revalidates them before deriving one stage-attempt namespace.  It intentionally
does not make a DGP generator importable or runnable: the job, GPU, runtime,
closed-environment, claim, completion, and private-boundary providers are not
implemented here and are recorded as unavailable.

Only the smoke plan can currently be sealed, with an exactly empty parent
transition tuple.  Internal and confirmation plans fail closed until their
semantic parent-transition validators exist.  Legacy v1 stage plans are never
accepted by this module.
"""

from __future__ import annotations

import errno
import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Mapping

import cohort_closed_loop_structured_protocol_plan as protocol_plan
from cohort_closed_loop_structured_atomic_publish import (
    publication_sidecar_relative_paths,
)
from cohort_closed_loop_structured_dgp_context import (
    EXPECTED_STAGE_SEEDS,
    STAGE_SHAPES,
    StageKind,
)

__all__ = (
    "INITIAL_PRIVATE_PROBE_IDS",
    "SEALED_PRIVATE_PROBE_IDS",
    "StructuredStagePlanError",
    "StructuredStagePlanValidation",
    "seal_structured_stage_plan_bytes",
    "validate_structured_stage_plan_bytes",
)


class StructuredStagePlanError(ValueError):
    """Raised when the v2 pre-DGP stage-plan closure differs."""


@dataclass(frozen=True, slots=True)
class StructuredStagePlanValidation:
    source_commit: str
    experiment_attempt_id: str
    stage_kind: str
    stage_attempt_id: str
    stage_root: str
    private_context_root: str
    stage_plan_sha256: str
    upstream_raw_closure_sha256: str
    dgp_output_inventory_sha256: str
    registry_v2_mapping_sha256: str
    dgp_output_count: int
    private_record_count: int
    missing_provider_ids: tuple[str, ...]
    dgp_generation_claim_eligible: bool = False
    dgp_generator_import_authorized: bool = False
    dgp_generation_authorized: bool = False
    model_calls_authorized: bool = False
    scorer_calls_authorized: bool = False
    launch_authorized: bool = False
    operational_authorization: bool = False


SCHEMA_VERSION = 2
PROTOCOL = "cohort_structured_stage_plan_v2"
STATUS = "sealed_smoke_pre_dgp_amendment_missing_providers_non_authorizing"
PRIVATE_BASE = "/sensei-fs/private/zcai/TTT-RL/cohort-closed-loop-structured-state"
SETUID_ADAPTER_PATH = (
    "/usr/local/libexec/cohort-structured-private-context-access-probe"
)
ATTESTER_UID = 41001
REGISTRAR_UID = 41011
PURE_SCORER_UID = 41012
PRIVATE_VALIDATOR_UID = 41013
LAUNCHER_UID = 41014
OPERATOR_UID = 41015
PRIVATE_READ_GID = 41016

ATTESTER_SERVICE_IDENTITY = "cohort-structured-private-boundary-v1"
REGISTRAR_SERVICE_IDENTITY = "cohort-structured-context-registrar-v1"
PURE_SCORER_SERVICE_IDENTITY = "cohort-structured-pure-scorer-v1"
PRIVATE_VALIDATOR_SERVICE_IDENTITY = "cohort-structured-private-validator-v1"
LAUNCHER_SERVICE_IDENTITY = "cohort-structured-launcher-v1"
OPERATOR_SERVICE_IDENTITY = "cohort-structured-operator-v1"

INITIAL_PRIVATE_PROBE_IDS: tuple[str, ...] = (
    "01_registrar_create_probe",
    "02_registrar_read_probe",
    "03_private_validator_read_probe",
    "04_private_validator_write_denied",
    "05_private_validator_create_denied",
    "06_scorer_read_probe",
    "07_scorer_write_denied",
    "08_scorer_create_denied",
    "09_launcher_enumerate",
    "10_launcher_read_probe",
    "11_operator_enumerate",
    "12_operator_read_probe",
    "13_registrar_remove_probe",
    "14_registrar_verify_no_leftover",
)
SEALED_PRIVATE_PROBE_IDS: tuple[str, ...] = (
    "01_private_validator_read_record",
    "02_scorer_read_record",
    "03_registrar_read_record",
    "04_launcher_enumerate",
    "05_launcher_read_record",
    "06_operator_enumerate",
    "07_operator_read_record",
    "08_registrar_create_denied",
    "09_registrar_write_denied",
)

_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_REQUIRED_PROVIDER_IDS: tuple[str, ...] = (
    "closed_environment_attester",
    "controlled_process_launcher",
    "dgp_claim_atomic_adapter",
    "dgp_completion_adapter",
    "dgp_generator_invocation",
    "gpu_inventory_attester",
    "job_identity_attester",
    "network_isolation_attester",
    "node_identity_attester",
    "private_boundary_v2",
    "python_runtime_attester",
    "stdio_provider",
)
_REQUIRED_SOURCE_ROLES: tuple[str, ...] = (
    "context_registrar",
    "dgp_completion_validator",
    "dgp_generator",
    "private_access_probe_source",
    "private_context_access_boundary",
    "stage_plan_builder",
    "structured_atomic_publisher",
    "structured_deployment_snapshot",
    "structured_dgp_claim_adapter",
    "structured_dgp_completion_adapter",
    "structured_dgp_context_validation",
    "structured_protocol_plan",
    "structured_trigger_bridge",
)
_AUTHORITY_KEYS = (
    "dgp_generation_claim_eligible",
    "dgp_generator_import_authorized",
    "dgp_generation_authorized",
    "model_calls_authorized",
    "scorer_calls_authorized",
    "launch_authorized",
    "operational_authorization",
)
_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "experiment_attempt_id",
        "stage_kind",
        "stage_attempt_id",
        "upstream_raw_bindings",
        "upstream_raw_closure_sha256",
        "source_role_bindings",
        "stage_shape",
        "seeds",
        "parent_transition",
        "paths",
        "generator_invocation",
        "closed_environment_policy",
        "resource_policy",
        "atomic_claim_protocol",
        "completion_protocol",
        "dgp_output_inventory",
        "dgp_output_inventory_sha256",
        "registry_v2_mapping",
        "registry_v2_mapping_sha256",
        "private_boundary_plan",
        "provider_status",
        "legacy_stage_plan_accepted",
        *_AUTHORITY_KEYS,
    }
)
_KEYS = _UNSIGNED_KEYS | {"stage_plan_sha256"}


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
        raise StructuredStagePlanError("value is not canonical ASCII JSON") from exc


def _private_service_identities() -> dict[str, object]:
    return {
        "attester": {
            "gid": ATTESTER_UID,
            "identity": ATTESTER_SERVICE_IDENTITY,
            "supplementary_gids": [PRIVATE_READ_GID],
            "uid": ATTESTER_UID,
        },
        "launcher": {
            "gid": LAUNCHER_UID,
            "identity": LAUNCHER_SERVICE_IDENTITY,
            "supplementary_gids": [],
            "uid": LAUNCHER_UID,
        },
        "operator": {
            "gid": OPERATOR_UID,
            "identity": OPERATOR_SERVICE_IDENTITY,
            "supplementary_gids": [],
            "uid": OPERATOR_UID,
        },
        "private_validator": {
            "gid": PRIVATE_VALIDATOR_UID,
            "identity": PRIVATE_VALIDATOR_SERVICE_IDENTITY,
            "supplementary_gids": [PRIVATE_READ_GID],
            "uid": PRIVATE_VALIDATOR_UID,
        },
        "pure_scorer": {
            "gid": PURE_SCORER_UID,
            "identity": PURE_SCORER_SERVICE_IDENTITY,
            "supplementary_gids": [PRIVATE_READ_GID],
            "uid": PURE_SCORER_UID,
        },
        "registrar": {
            "gid": PRIVATE_READ_GID,
            "identity": REGISTRAR_SERVICE_IDENTITY,
            "supplementary_gids": [],
            "uid": REGISTRAR_UID,
        },
    }


def _private_access_policy(stage: str) -> dict[str, object]:
    denied = {
        "launcher": {
            "gid": LAUNCHER_UID,
            "operations": ["enumerate_root", "read_probe_or_record"],
            "required_raw_errno": errno.EACCES,
            "supplementary_gids": [],
            "uid": LAUNCHER_UID,
        },
        "operator": {
            "gid": OPERATOR_UID,
            "operations": ["enumerate_root", "read_probe_or_record"],
            "required_raw_errno": errno.EACCES,
            "supplementary_gids": [],
            "uid": OPERATOR_UID,
        },
    }
    common: dict[str, object] = {
        "adapter_credential_transition": (
            "setgroups_then_setresgid_then_setresuid_no_active_capabilities"
        ),
        "adapter_exec_gid": ATTESTER_UID,
        "adapter_invoker_uid": ATTESTER_UID,
        "adapter_mode": 0o4750,
        "attester": {
            "gid": ATTESTER_UID,
            "supplementary_gids": [PRIVATE_READ_GID],
            "uid": ATTESTER_UID,
        },
        "denied": denied,
        "directory_group_gid": PRIVATE_READ_GID,
        "directory_mode": 0o750,
        "record_group_gid": PRIVATE_READ_GID,
        "record_mode": 0o440,
        "root_owner_uid": REGISTRAR_UID,
        "stage": stage,
    }
    if stage == "initial_registration_boundary":
        return {
            **common,
            "mount_mode": "rw",
            "read_only_consumers": {
                "private_validator": {
                    "denied_operations": ["create_record", "write_exact_probe"],
                    "gid": PRIVATE_VALIDATOR_UID,
                    "required_raw_errno": errno.EACCES,
                    "supplementary_gids": [PRIVATE_READ_GID],
                    "uid": PRIVATE_VALIDATOR_UID,
                },
                "pure_scorer": {
                    "denied_operations": ["create_record", "write_exact_probe"],
                    "gid": PURE_SCORER_UID,
                    "required_raw_errno": errno.EACCES,
                    "supplementary_gids": [PRIVATE_READ_GID],
                    "uid": PURE_SCORER_UID,
                },
            },
            "registrar": {
                "gid": PRIVATE_READ_GID,
                "operations": [
                    "create_exact_probe",
                    "read_exact_probe",
                    "remove_exact_probe",
                    "verify_probe_absent",
                ],
                "supplementary_gids": [],
                "uid": REGISTRAR_UID,
            },
            "schema_version": 1,
        }
    if stage == "sealed_prelaunch_boundary":
        return {
            **common,
            "mount_mode": "ro",
            "permitted_readers": {
                "private_validator": {
                    "gid": PRIVATE_VALIDATOR_UID,
                    "supplementary_gids": [PRIVATE_READ_GID],
                    "uid": PRIVATE_VALIDATOR_UID,
                },
                "pure_scorer": {
                    "gid": PURE_SCORER_UID,
                    "supplementary_gids": [PRIVATE_READ_GID],
                    "uid": PURE_SCORER_UID,
                },
                "registrar": {
                    "gid": PRIVATE_READ_GID,
                    "supplementary_gids": [],
                    "uid": REGISTRAR_UID,
                },
            },
            "registrar_mutation_denied": {
                "accepted_raw_errnos": sorted({errno.EACCES, errno.EROFS}),
                "gid": PRIVATE_READ_GID,
                "operations": ["create_probe_record", "write_registered_record"],
                "supplementary_gids": [],
                "uid": REGISTRAR_UID,
            },
            "schema_version": 2,
        }
    raise StructuredStagePlanError("private access-policy stage differs")


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StructuredStagePlanError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise StructuredStagePlanError(f"non-finite JSON constant: {value}")


def _parse(raw: object, label: str) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise StructuredStagePlanError(f"{label} must be exact bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StructuredStagePlanError(f"{label} is not strict ASCII JSON") from exc
    if type(value) is not dict or _canonical(value) != raw:
        raise StructuredStagePlanError(f"{label} is not exact canonical JSON")
    return value


def _raw(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        raise StructuredStagePlanError(f"{label} must be exact bytes")
    return value


def _freeze_raw_map(value: object, label: str) -> dict[str, bytes]:
    """Take one immutable snapshot of a caller-owned raw-byte mapping."""

    if type(value) is not dict:
        raise StructuredStagePlanError(f"{label} must be an exact dict")
    frozen: dict[str, bytes] = {}
    for key, item in value.items():
        if type(key) is not str:
            raise StructuredStagePlanError(f"{label} key must be exact text")
        frozen[key] = _raw(item, f"{label}.{key}")
    return frozen


def _freeze_nested_raw_map(
    value: object, label: str
) -> dict[str, dict[str, bytes]]:
    """Take one immutable snapshot of role-to-file raw-byte mappings."""

    if type(value) is not dict:
        raise StructuredStagePlanError(f"{label} must be an exact dict")
    frozen: dict[str, dict[str, bytes]] = {}
    for role, files in value.items():
        if type(role) is not str:
            raise StructuredStagePlanError(f"{label} role must be exact text")
        frozen[role] = _freeze_raw_map(files, f"{label}.{role}")
    return frozen


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _binding(raw: bytes) -> dict[str, object]:
    return {"sha256": _sha(raw), "size_bytes": len(raw)}


def _attempt(value: object, label: str) -> str:
    if type(value) is not str or _ATTEMPT_RE.fullmatch(value) is None:
        raise StructuredStagePlanError(f"{label} must match attempt-[0-9]{{3}}")
    return value


def _stage(value: object) -> StageKind:
    if type(value) is not str:
        raise StructuredStagePlanError("stage_kind must be exact text")
    try:
        return StageKind(value)
    except ValueError as exc:
        raise StructuredStagePlanError("stage_kind is not registered") from exc


def _absolute_join(root: str, *parts: str) -> str:
    value = posixpath.join(root, *parts)
    if not value.startswith("/") or posixpath.normpath(value) != value:
        raise StructuredStagePlanError("derived path is not normalized absolute text")
    return value


def _named_raw_bindings(
    value: Mapping[str, object], label: str
) -> list[dict[str, object]]:
    if not isinstance(value, Mapping):
        raise StructuredStagePlanError(f"{label} must be a mapping")
    result: list[dict[str, object]] = []
    for binding_id in sorted(value):
        if type(binding_id) is not str:
            raise StructuredStagePlanError(f"{label} key differs")
        raw = _raw(value[binding_id], f"{label}.{binding_id}")
        result.append({"binding_id": binding_id, **_binding(raw)})
    return result


def _asset_file_bindings(
    value: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    if not isinstance(value, Mapping):
        raise StructuredStagePlanError("asset_file_bytes_by_role must be a mapping")
    result: list[dict[str, object]] = []
    for role in sorted(value):
        files = value[role]
        if type(role) is not str or not isinstance(files, Mapping):
            raise StructuredStagePlanError("asset raw file map differs")
        for relative in sorted(files):
            if (
                type(relative) is not str
                or not relative
                or relative.startswith("/")
                or posixpath.normpath(relative) != relative
            ):
                raise StructuredStagePlanError("asset relative path differs")
            raw = _raw(files[relative], f"asset {role}:{relative}")
            result.append({"role": role, "relative_path": relative, **_binding(raw)})
    return result


def _upstream_bindings(
    *,
    strict_trigger_bridge_bytes: bytes,
    strict_trigger_receipt_bytes: bytes,
    strict_trigger_evidence_bytes: Mapping[str, object],
    protocol_plan_seal_bytes: bytes,
    deployment_snapshot_bytes: bytes,
    lease_receipt_bytes: bytes,
    observation_bytes: tuple[bytes, bytes],
    git_index_bytes: bytes,
    source_inventory_bytes: bytes,
    asset_inventory_bytes_by_role: Mapping[str, object],
    source_file_bytes_by_role: Mapping[str, object],
    asset_file_bytes_by_role: Mapping[str, Mapping[str, object]],
    execution_contract_bytes: bytes,
    structured_preregistration_bytes: bytes,
) -> dict[str, object]:
    return {
        "strict_trigger_bridge": _binding(strict_trigger_bridge_bytes),
        "strict_trigger_receipt": _binding(strict_trigger_receipt_bytes),
        "strict_trigger_evidence": _named_raw_bindings(
            strict_trigger_evidence_bytes, "strict_trigger_evidence_bytes"
        ),
        "protocol_plan_seal": _binding(protocol_plan_seal_bytes),
        "deployment_snapshot": _binding(deployment_snapshot_bytes),
        "deployment_capture_lease": _binding(lease_receipt_bytes),
        "deployment_observations": [
            {"ordinal": index + 1, **_binding(raw)}
            for index, raw in enumerate(observation_bytes)
        ],
        "git_index": _binding(git_index_bytes),
        "source_inventory": _binding(source_inventory_bytes),
        "asset_inventories": _named_raw_bindings(
            asset_inventory_bytes_by_role, "asset_inventory_bytes_by_role"
        ),
        "source_files": _named_raw_bindings(
            source_file_bytes_by_role, "source_file_bytes_by_role"
        ),
        "asset_files": _asset_file_bindings(asset_file_bytes_by_role),
        "execution_contract": _binding(execution_contract_bytes),
        "structured_preregistration": _binding(structured_preregistration_bytes),
    }


def _source_records(source_inventory_raw: bytes) -> dict[str, dict[str, Any]]:
    inventory = _parse(source_inventory_raw, "source_inventory_bytes")
    rows = inventory.get("records")
    if type(rows) is not list:
        raise StructuredStagePlanError("source inventory records differ")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if type(row) is not dict or type(row.get("role")) is not str:
            raise StructuredStagePlanError("source inventory record differs")
        result[row["role"]] = row
    if set(_REQUIRED_SOURCE_ROLES) - set(result):
        raise StructuredStagePlanError("stage-plan source role closure is incomplete")
    return result


def _source_role_bindings(
    records: Mapping[str, Mapping[str, object]],
    validation: protocol_plan.StructuredProtocolPlanValidation,
) -> list[dict[str, object]]:
    digest_map = dict(validation.source_bindings)
    result: list[dict[str, object]] = []
    for role in _REQUIRED_SOURCE_ROLES:
        row = records[role]
        if (
            row.get("sha256") != digest_map.get(role)
            or type(row.get("path")) is not str
            or type(row.get("size_bytes")) is not int
        ):
            raise StructuredStagePlanError(f"source role binding differs: {role}")
        result.append(
            {
                "role": role,
                "path": row["path"],
                "sha256": row["sha256"],
                "size_bytes": row["size_bytes"],
            }
        )
    return sorted(result, key=lambda row: str(row["role"]))


def _stage_shape(stage: StageKind) -> dict[str, int]:
    shape = STAGE_SHAPES[stage]
    return {
        "blocks": shape.blocks,
        "items_per_phase": shape.items_per_phase,
        "phase_count": 2,
        "dgp_row_count": shape.blocks * shape.items_per_phase * 2,
    }


def _seeds(stage: StageKind) -> list[dict[str, object]]:
    return [
        {
            "block_id": row.block_id,
            "block_index": row.block_index,
            "run_seed": row.run_seed,
            "adaptation_dgp_seed": row.adaptation_dgp_seed,
            "held_out_dgp_seed": row.held_out_dgp_seed,
        }
        for row in EXPECTED_STAGE_SEEDS[stage]
    ]


def _paths(
    *,
    durable_root: str,
    source_commit: str,
    experiment_attempt_id: str,
    stage: StageKind,
    stage_attempt_id: str,
) -> dict[str, object]:
    stage_root = _absolute_join(durable_root, "stages", stage.value, stage_attempt_id)
    stage_plan_path = _absolute_join(stage_root, "control", "stage_plan.json")
    completion_path = _absolute_join(
        stage_root, "control", "dgp_completion_receipt.json"
    )
    stage_plan_publication = _publication_paths(
        path=stage_plan_path, durable_root=durable_root
    )
    completion_publication = _publication_paths(
        path=completion_path, durable_root=durable_root
    )
    private_root = _absolute_join(
        PRIVATE_BASE,
        source_commit,
        "attempts",
        experiment_attempt_id,
        "stages",
        stage.value,
        stage_attempt_id,
        "private-context",
    )
    evidence_root = _absolute_join(stage_root, "control", "private_boundary")
    initial_probe_paths = [
        {
            "probe_id": probe_id,
            "path": _absolute_join(
                evidence_root, "initial", "probes", f"{probe_id}.json"
            ),
        }
        for probe_id in INITIAL_PRIVATE_PROBE_IDS
    ]
    sealed_probe_paths = [
        {
            "probe_id": probe_id,
            "path": _absolute_join(
                evidence_root, "sealed", "probes", f"{probe_id}.json"
            ),
        }
        for probe_id in SEALED_PRIVATE_PROBE_IDS
    ]
    return {
        "durable_root": durable_root,
        "stage_root": stage_root,
        "dgp_output_root": _absolute_join(stage_root, "dgp"),
        "stage_plan_path": stage_plan_path,
        "stage_plan_publication_intent_path": stage_plan_publication[
            "publication_intent_path"
        ],
        "stage_plan_publication_pending_path": stage_plan_publication[
            "publication_pending_path"
        ],
        "dgp_generation_claim_path": _absolute_join(
            stage_root, "control", "dgp_generation.claim.json"
        ),
        "dgp_completion_receipt_path": completion_path,
        "dgp_completion_publication_intent_path": completion_publication[
            "publication_intent_path"
        ],
        "dgp_completion_publication_pending_path": completion_publication[
            "publication_pending_path"
        ],
        "dgp_manifest_path": _absolute_join(stage_root, "dgp", "stage_manifest.json"),
        "private_context_root": private_root,
        "private_record_root": _absolute_join(private_root, "records"),
        "private_evidence_root": evidence_root,
        "initial_boundary_attestation_path": _absolute_join(
            evidence_root, "initial", "attestation.json"
        ),
        "sealed_boundary_attestation_path": _absolute_join(
            evidence_root, "sealed", "attestation.json"
        ),
        "registry_completion_receipt_path": _absolute_join(
            evidence_root, "registry", "registry_completion.v2.json"
        ),
        "initial_probe_receipt_paths": initial_probe_paths,
        "sealed_probe_receipt_paths": sealed_probe_paths,
    }


def _pre_dgp_rows(
    *,
    source_commit: str,
    experiment_attempt_id: str,
    stage: StageKind,
    stage_attempt_id: str,
    paths: Mapping[str, object],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    durable_root = str(paths["durable_root"])
    dgp_output_root = str(paths["dgp_output_root"])
    private_record_root = str(paths["private_record_root"])

    def output(
        relative_path: str, *, role: str, writer_service: str
    ) -> dict[str, object]:
        path = _absolute_join(dgp_output_root, relative_path)
        return {
            "path": path,
            "relative_path": relative_path,
            "role": role,
            "writer_service": writer_service,
            **_publication_paths(path=path, durable_root=durable_root),
        }

    outputs: list[dict[str, object]] = [
        output(
            "stage_manifest.json",
            role="dgp_stage_manifest",
            writer_service="dgp_completion_adapter",
        )
    ]
    mapping_entries: list[dict[str, object]] = []
    for seed in EXPECTED_STAGE_SEEDS[stage]:
        for phase in ("adaptation", "held_out"):
            outputs.append(
                output(
                    f"corpora/{seed.block_id}/{phase}/corpus_inventory.json",
                    role="dgp_corpus_inventory",
                    writer_service="dgp_generator",
                )
            )
            for item_id in range(1, STAGE_SHAPES[stage].items_per_phase + 1):
                prefix = f"{seed.block_id}/{phase}/{item_id}"
                row_relative = f"corpora/{seed.block_id}/{phase}/rows/{item_id}.json"
                attestation_relative = f"contexts/{prefix}/public_attestation.json"
                registry_relative = f"contexts/{prefix}/registry_digest_record.json"
                outputs.extend(
                    (
                        output(
                            row_relative,
                            role="dgp_row_identity",
                            writer_service="dgp_generator",
                        ),
                        output(
                            attestation_relative,
                            role="public_context_attestation",
                            writer_service="context_registrar",
                        ),
                        output(
                            registry_relative,
                            role="context_registry_digest_record",
                            writer_service="context_registrar",
                        ),
                    )
                )
                private_relative = posixpath.join(
                    "records", seed.block_id, phase, f"{item_id}.json"
                )
                mapping_entries.append(
                    {
                        "stage_kind": stage.value,
                        "block_id": seed.block_id,
                        "block_index": seed.block_index,
                        "phase": phase,
                        "item_id": item_id,
                        "instance_index": item_id - 1,
                        "dgp_row_path": _absolute_join(dgp_output_root, row_relative),
                        "public_registry_digest_path": _absolute_join(
                            dgp_output_root, registry_relative
                        ),
                        "public_attestation_path": _absolute_join(
                            dgp_output_root, attestation_relative
                        ),
                        "private_record_relative_path": private_relative,
                        "private_record_path": _absolute_join(
                            private_record_root,
                            seed.block_id,
                            phase,
                            f"{item_id}.json",
                        ),
                        "completion_values_pending": [
                            "hidden_sha256",
                            "instance_id",
                            "opaque_handle_sha256",
                            "public_context_identity_sha256",
                            "size_bytes",
                        ],
                    }
                )
    outputs.sort(key=lambda row: str(row["path"]))
    mapping_entries.sort(
        key=lambda row: (str(row["block_id"]), str(row["phase"]), int(row["item_id"]))
    )
    if len({row["path"] for row in outputs}) != len(outputs):
        raise StructuredStagePlanError("DGP output inventory path collision")
    output_publication_paths = [
        str(row[key])
        for row in outputs
        for key in (
            "path",
            "publication_intent_path",
            "publication_pending_path",
        )
    ]
    if len(set(output_publication_paths)) != len(output_publication_paths):
        raise StructuredStagePlanError("DGP publication path collision")
    if len({row["private_record_path"] for row in mapping_entries}) != len(
        mapping_entries
    ):
        raise StructuredStagePlanError("private registry mapping path collision")
    mapping_plan: dict[str, object] = {
        "protocol": "cohort_structured_private_registry_mapping_plan_v2",
        "schema_version": 2,
        "status": "pre_dgp_completion_values_pending",
        "source_commit": source_commit,
        "experiment_attempt_id": experiment_attempt_id,
        "stage_kind": stage.value,
        "stage_attempt_id": stage_attempt_id,
        "private_context_root": paths["private_context_root"],
        "completion_receipt_path": paths["registry_completion_receipt_path"],
        "completion_receipt_protocol": (
            "cohort_structured_private_context_registry_completion_receipt_v2"
        ),
        "completion_receipt_schema_version": 2,
        "plan_entry_fields": [
            "stage_kind",
            "block_id",
            "block_index",
            "phase",
            "item_id",
            "instance_index",
            "dgp_row_path",
            "public_attestation_path",
            "public_registry_digest_path",
            "private_record_relative_path",
            "private_record_path",
            "completion_values_pending",
        ],
        "completion_entry_fields": [
            "stage_kind",
            "block_id",
            "block_index",
            "phase",
            "item_id",
            "instance_index",
            "instance_id",
            "public_context_identity_sha256",
            "opaque_handle_sha256",
            "relative_path",
            "hidden_sha256",
            "size_bytes",
        ],
        "planned_entry_count": len(mapping_entries),
        "completion_value_derivation": {
            "stage_kind": "exact_stage_plan_stage_kind",
            "block_id": "exact_mapping_entry_block_id",
            "block_index": "exact_mapping_entry_block_index",
            "phase": "exact_mapping_entry_phase",
            "item_id": "exact_mapping_entry_item_id",
            "instance_index": (
                "validated_dgp_row_instance_index_equal_exact_mapping_entry_"
                "instance_index"
            ),
            "instance_id": "validated_dgp_row_instance_id",
            "public_context_identity_sha256": (
                "recomputed_validated_public_context_identity_sha256"
            ),
            "opaque_handle_sha256": (
                "validated_public_attestation_opaque_handle_sha256"
            ),
            "relative_path": "exact_mapping_entry_private_record_relative_path",
            "hidden_sha256": "sha256_exact_private_record_raw_bytes",
            "size_bytes": "length_exact_private_record_raw_bytes",
        },
        "planned_entries": mapping_entries,
    }
    return outputs, mapping_plan


def _asset_binary_binding(
    asset_file_bytes_by_role: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    try:
        files = asset_file_bytes_by_role["private_access_probe_binary"]
    except (KeyError, TypeError) as exc:
        raise StructuredStagePlanError(
            "private access-probe binary asset is missing"
        ) from exc
    if not isinstance(files, Mapping) or len(files) != 1:
        raise StructuredStagePlanError(
            "private access-probe binary asset must contain exactly one file"
        )
    relative, value = next(iter(files.items()))
    if type(relative) is not str:
        raise StructuredStagePlanError("private access-probe asset path differs")
    raw = _raw(value, "private access-probe binary")
    return {
        "asset_role": "private_access_probe_binary",
        "relative_path": relative,
        "install_path": SETUID_ADAPTER_PATH,
        **_binding(raw),
    }


def _publication_paths(*, path: str, durable_root: str) -> dict[str, str]:
    relative = posixpath.relpath(path, durable_root)
    if relative.startswith("../") or relative == "..":
        raise StructuredStagePlanError("public evidence path escapes durable root")
    intent_relative, pending_relative = publication_sidecar_relative_paths(relative)
    return {
        "publication_intent_path": _absolute_join(durable_root, intent_relative),
        "publication_pending_path": _absolute_join(durable_root, pending_relative),
    }


def _private_evidence_inventory(
    *, paths: Mapping[str, object], durable_root: str
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for boundary_phase, key in (
        ("initial", "initial_probe_receipt_paths"),
        ("sealed", "sealed_probe_receipt_paths"),
    ):
        records = paths[key]
        if type(records) is not list:
            raise StructuredStagePlanError("private probe path inventory differs")
        for record in records:
            if type(record) is not dict:
                raise StructuredStagePlanError("private probe path record differs")
            path = str(record["path"])
            result.append(
                {
                    "path": path,
                    "role": f"{boundary_phase}_private_probe_receipt",
                    "probe_id": record["probe_id"],
                    "writer_service": "private_boundary_v2",
                    **_publication_paths(path=path, durable_root=durable_root),
                }
            )
    for path_key, role in (
        ("initial_boundary_attestation_path", "initial_private_boundary_attestation"),
        ("registry_completion_receipt_path", "private_registry_completion_v2"),
        ("sealed_boundary_attestation_path", "sealed_private_boundary_attestation"),
    ):
        path = str(paths[path_key])
        result.append(
            {
                "path": path,
                "role": role,
                "probe_id": None,
                "writer_service": "private_boundary_v2",
                **_publication_paths(path=path, durable_root=durable_root),
            }
        )
    result.sort(key=lambda row: str(row["path"]))
    if len({row["path"] for row in result}) != len(result):
        raise StructuredStagePlanError("private evidence inventory path collision")
    publication_paths = [
        str(row[key])
        for row in result
        for key in (
            "path",
            "publication_intent_path",
            "publication_pending_path",
        )
    ]
    if len(set(publication_paths)) != len(publication_paths):
        raise StructuredStagePlanError("private evidence publication path collision")
    return result


def _assert_publication_inventory_disjoint(
    *,
    paths: Mapping[str, object],
    dgp_outputs: list[dict[str, object]],
    private_evidence: list[dict[str, object]],
) -> None:
    """Require every registered final, intent, and pending path to be unique."""

    durable_root = str(paths["durable_root"])
    claim_publication = _publication_paths(
        path=str(paths["dgp_generation_claim_path"]), durable_root=durable_root
    )
    triples: list[tuple[str, str, str]] = [
        (
            str(paths["stage_plan_path"]),
            str(paths["stage_plan_publication_intent_path"]),
            str(paths["stage_plan_publication_pending_path"]),
        ),
        (
            str(paths["dgp_generation_claim_path"]),
            claim_publication["publication_intent_path"],
            claim_publication["publication_pending_path"],
        ),
        (
            str(paths["dgp_completion_receipt_path"]),
            str(paths["dgp_completion_publication_intent_path"]),
            str(paths["dgp_completion_publication_pending_path"]),
        ),
    ]
    for row in (*dgp_outputs, *private_evidence):
        triples.append(
            (
                str(row["path"]),
                str(row["publication_intent_path"]),
                str(row["publication_pending_path"]),
            )
        )
    flattened = [path for triple in triples for path in triple]
    if len(flattened) != len(set(flattened)):
        raise StructuredStagePlanError("global publication path closure collides")


def _assemble(
    *,
    protocol_plan_seal_bytes: object,
    stage_kind: object,
    stage_attempt_id: object,
    parent_transition_receipt_bytes: object,
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
) -> tuple[bytes, StructuredStagePlanValidation]:
    stage = _stage(stage_kind)
    stage_attempt = _attempt(stage_attempt_id, "stage_attempt_id")
    if type(parent_transition_receipt_bytes) is not tuple:
        raise StructuredStagePlanError(
            "parent_transition_receipt_bytes must be an exact tuple"
        )
    if stage is StageKind.SMOKE:
        if parent_transition_receipt_bytes:
            raise StructuredStagePlanError("smoke parent transition must be empty")
    else:
        raise StructuredStagePlanError(
            "internal and confirmation parent semantic validators are unavailable"
        )

    # Every map is caller-owned and is consumed by both the upstream validator
    # and this builder.  Snapshot once so a stateful Mapping cannot return
    # validated bytes on one read and different bytes on the binding read.
    frozen_trigger_evidence = _freeze_raw_map(
        strict_trigger_evidence_bytes, "strict_trigger_evidence_bytes"
    )
    frozen_asset_inventories = _freeze_raw_map(
        asset_inventory_bytes_by_role, "asset_inventory_bytes_by_role"
    )
    frozen_source_files = _freeze_raw_map(
        source_file_bytes_by_role, "source_file_bytes_by_role"
    )
    frozen_asset_files = _freeze_nested_raw_map(
        asset_file_bytes_by_role, "asset_file_bytes_by_role"
    )

    plan_raw = _raw(protocol_plan_seal_bytes, "protocol_plan_seal_bytes")
    bridge_raw = _raw(strict_trigger_bridge_bytes, "strict_trigger_bridge_bytes")
    receipt_raw = _raw(strict_trigger_receipt_bytes, "strict_trigger_receipt_bytes")
    snapshot_raw = _raw(deployment_snapshot_bytes, "deployment_snapshot_bytes")
    lease_raw = _raw(lease_receipt_bytes, "lease_receipt_bytes")
    if (
        type(observation_bytes) is not tuple
        or len(observation_bytes) != 2
        or any(type(value) is not bytes for value in observation_bytes)
    ):
        raise StructuredStagePlanError("observation_bytes must be an exact byte pair")
    observation_raws = observation_bytes
    git_index_raw = _raw(git_index_bytes, "git_index_bytes")
    source_inventory_raw = _raw(source_inventory_bytes, "source_inventory_bytes")
    contract_raw = _raw(execution_contract_bytes, "execution_contract_bytes")
    prereg_raw = _raw(
        structured_preregistration_bytes, "structured_preregistration_bytes"
    )
    try:
        upstream = protocol_plan.validate_structured_protocol_plan_bytes(
            plan_raw,
            strict_trigger_bridge_bytes=bridge_raw,
            strict_trigger_receipt_bytes=receipt_raw,
            strict_trigger_evidence_bytes=frozen_trigger_evidence,
            deployment_snapshot_bytes=snapshot_raw,
            lease_receipt_bytes=lease_raw,
            observation_bytes=observation_raws,
            git_index_bytes=git_index_raw,
            source_inventory_bytes=source_inventory_raw,
            asset_inventory_bytes_by_role=frozen_asset_inventories,
            source_file_bytes_by_role=frozen_source_files,
            asset_file_bytes_by_role=frozen_asset_files,
            execution_contract_bytes=contract_raw,
            structured_preregistration_bytes=prereg_raw,
        )
    except protocol_plan.StructuredProtocolPlanError as exc:
        raise StructuredStagePlanError(
            "upstream raw protocol-plan reconstruction failed"
        ) from exc
    if any(
        (
            upstream.dgp_generation_authorized,
            upstream.model_calls_authorized,
            upstream.scorer_calls_authorized,
            upstream.operational_authorization,
        )
    ):
        raise StructuredStagePlanError("upstream protocol plan carried authority")

    records = _source_records(source_inventory_raw)
    source_bindings = _source_role_bindings(records, upstream)
    source_by_role = {str(row["role"]): row for row in source_bindings}
    paths = _paths(
        durable_root=upstream.durable_root,
        source_commit=upstream.source_commit,
        experiment_attempt_id=upstream.attempt_id,
        stage=stage,
        stage_attempt_id=stage_attempt,
    )
    outputs, registry_mapping = _pre_dgp_rows(
        source_commit=upstream.source_commit,
        experiment_attempt_id=upstream.attempt_id,
        stage=stage,
        stage_attempt_id=stage_attempt,
        paths=paths,
    )
    registry_entries = registry_mapping["planned_entries"]
    if type(registry_entries) is not list:
        raise StructuredStagePlanError("registry mapping-plan entries differ")
    output_sha = _sha(_canonical(outputs))
    mapping_sha = _sha(_canonical(registry_mapping))
    private_evidence_inventory = _private_evidence_inventory(
        paths=paths, durable_root=upstream.durable_root
    )
    _assert_publication_inventory_disjoint(
        paths=paths,
        dgp_outputs=outputs,
        private_evidence=private_evidence_inventory,
    )
    raw_bindings = _upstream_bindings(
        strict_trigger_bridge_bytes=bridge_raw,
        strict_trigger_receipt_bytes=receipt_raw,
        strict_trigger_evidence_bytes=frozen_trigger_evidence,
        protocol_plan_seal_bytes=plan_raw,
        deployment_snapshot_bytes=snapshot_raw,
        lease_receipt_bytes=lease_raw,
        observation_bytes=observation_raws,
        git_index_bytes=git_index_raw,
        source_inventory_bytes=source_inventory_raw,
        asset_inventory_bytes_by_role=frozen_asset_inventories,
        source_file_bytes_by_role=frozen_source_files,
        asset_file_bytes_by_role=frozen_asset_files,
        execution_contract_bytes=contract_raw,
        structured_preregistration_bytes=prereg_raw,
    )

    claim_path = str(paths["dgp_generation_claim_path"])
    claim_relative = posixpath.relpath(claim_path, upstream.durable_root)
    intent_relative, pending_relative = publication_sidecar_relative_paths(
        claim_relative
    )
    exact_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    generator_source = source_by_role["dgp_generator"]
    generator_invocation = {
        "provider_id": "dgp_generator_invocation",
        "provider_available": False,
        "runtime_executable_provider_id": "python_runtime_attester",
        "runtime_executable_provider_available": False,
        "runtime_executable_path": None,
        "generator_source_path": generator_source["path"],
        "generator_source_sha256": generator_source["sha256"],
        "argv_after_runtime": [
            "-I",
            "-B",
            generator_source["path"],
            "--protocol-plan-seal",
            _absolute_join(
                upstream.durable_root,
                "control",
                "structured_protocol_plan_seal.json",
            ),
            "--stage-plan",
            paths["stage_plan_path"],
            "--dgp-generation-claim",
            claim_path,
            "--dgp-completion-receipt",
            paths["dgp_completion_receipt_path"],
            "--stage-kind",
            stage.value,
            "--experiment-attempt-id",
            upstream.attempt_id,
            "--stage-attempt-id",
            stage_attempt,
            "--output-root",
            paths["dgp_output_root"],
        ],
        "cwd": upstream.checkout_root,
        "stdin": "devnull",
        "stdio_provider_id": "stdio_provider",
        "stdio_provider_available": False,
        "controlled_process_launcher_provider_id": "controlled_process_launcher",
        "controlled_process_launcher_provider_available": False,
        "generator_import_requires_committed_claim": True,
    }
    private_binary = _asset_binary_binding(frozen_asset_files)
    service_identities = _private_service_identities()
    initial_access_policy = _private_access_policy("initial_registration_boundary")
    sealed_access_policy = _private_access_policy("sealed_prelaunch_boundary")
    private_plan = {
        "epoch_id": _sha(
            _canonical(
                {
                    "source_commit": upstream.source_commit,
                    "experiment_attempt_id": upstream.attempt_id,
                    "stage_kind": stage.value,
                    "stage_attempt_id": stage_attempt,
                }
            )
        ),
        "root": paths["private_context_root"],
        "record_root": paths["private_record_root"],
        "root_owner_uid": REGISTRAR_UID,
        "root_group_gid": PRIVATE_READ_GID,
        "directory_mode": 0o750,
        "record_mode": 0o440,
        "initial_mount_mode": "rw",
        "sealed_mount_mode": "ro",
        "same_root_device_inode_mount_namespace_boot_required": True,
        "reuse_after_seal_forbidden": True,
        "service_identities": service_identities,
        "service_identities_sha256": _sha(_canonical(service_identities)),
        "protocol_schema_bindings": {
            "initial_attestation": {
                "protocol": (
                    "cohort_structured_private_context_"
                    "initial_registration_boundary_v1"
                ),
                "schema_version": 1,
            },
            "initial_probe": {
                "protocol": (
                    "cohort_structured_private_context_initial_access_probe_v1"
                ),
                "schema_version": 1,
            },
            "registry_completion": {
                "protocol": (
                    "cohort_structured_private_context_"
                    "registry_completion_receipt_v2"
                ),
                "schema_version": 2,
            },
            "sealed_attestation": {
                "protocol": (
                    "cohort_structured_private_context_"
                    "sealed_prelaunch_boundary_v2"
                ),
                "schema_version": 2,
            },
            "sealed_probe": {
                "protocol": (
                    "cohort_structured_private_context_sealed_access_probe_v1"
                ),
                "schema_version": 1,
            },
        },
        "initial_access_policy": initial_access_policy,
        "initial_access_policy_sha256": _sha(_canonical(initial_access_policy)),
        "sealed_access_policy": sealed_access_policy,
        "sealed_access_policy_sha256": _sha(_canonical(sealed_access_policy)),
        "transient_probe_path": _absolute_join(
            str(paths["private_context_root"]),
            ".private-boundary-registration-probe",
        ),
        "sealed_probe_record_path": registry_entries[0]["private_record_path"],
        "private_record_paths": [
            row["private_record_path"] for row in registry_entries
        ],
        "initial_attestation_path": paths["initial_boundary_attestation_path"],
        "sealed_attestation_path": paths["sealed_boundary_attestation_path"],
        "registry_completion_receipt_path": paths["registry_completion_receipt_path"],
        "initial_probe_receipt_paths": paths["initial_probe_receipt_paths"],
        "sealed_probe_receipt_paths": paths["sealed_probe_receipt_paths"],
        "evidence_output_inventory": private_evidence_inventory,
        "evidence_output_inventory_sha256": _sha(
            _canonical(private_evidence_inventory)
        ),
        "probe_publication_order": {
            "initial": {
                "probe_ids": list(INITIAL_PRIVATE_PROBE_IDS),
                "attestation_last": paths["initial_boundary_attestation_path"],
            },
            "sealed": {
                "probe_ids": list(SEALED_PRIVATE_PROBE_IDS),
                "attestation_last": paths["sealed_boundary_attestation_path"],
            },
        },
        "all_record_content_sha256_join_required": True,
        "single_use_poison_policy": {
            "changed_epoch_identity_is_poison": True,
            "existing_intent_is_poison": True,
            "missing_attestation_is_poison": True,
            "missing_probe_receipt_is_poison": True,
            "missing_registry_completion_receipt_is_poison": True,
            "partial_phase_is_poison": True,
            "path_collision_is_poison": True,
            "present_pending_path_is_poison": True,
            "reuse_attempt_is_poison": True,
            "poison_grants_authority": False,
        },
        "lifecycle": [
            {
                "ordinal": 1,
                "event": "create_unique_empty_stage_epoch_rw",
                "required_mount_mode": "rw",
            },
            {
                "ordinal": 2,
                "event": "publish_14_initial_probe_receipts_then_attestation",
                "required_mount_mode": "rw",
            },
            {
                "ordinal": 3,
                "event": "registrar_write_exact_mapped_private_records",
                "required_mount_mode": "rw",
            },
            {
                "ordinal": 4,
                "event": "publish_registry_completion_v2",
                "required_mount_mode": "rw",
            },
            {
                "ordinal": 5,
                "event": "remount_same_epoch_read_only",
                "required_mount_mode": "ro",
            },
            {
                "ordinal": 6,
                "event": "publish_9_sealed_probe_receipts_then_attestation",
                "required_mount_mode": "ro",
            },
        ],
        "access_probe_source": source_by_role["private_access_probe_source"],
        "access_probe_binary": private_binary,
        "access_probe_execution_policy": {
            "installed_owner_uid": 0,
            "installed_group_gid": ATTESTER_UID,
            "installed_mode": 0o4750,
            "installed_link_count": 1,
            "acl_absent_required": True,
            "extended_attributes_empty_required": True,
            "file_capabilities_absent_required": True,
            "suid_enabled_mount_required": True,
            "trusted_ancestors_owner_uid": 0,
            "trusted_ancestors_group_or_other_writable_forbidden": True,
            "verified_open_descriptor_required": True,
            "pathname_execution_forbidden": True,
            "execution_method": "fexecve_or_execveat_at_empty_path",
            "proc_self_exe_identity_revalidation_required": True,
            "pre_transition_real_uid": ATTESTER_UID,
            "pre_transition_effective_uid": 0,
            "pre_transition_saved_uid": 0,
            "pre_transition_real_gid": ATTESTER_UID,
            "pre_transition_effective_gid": ATTESTER_UID,
            "pre_transition_saved_gid": ATTESTER_UID,
            "pre_transition_supplementary_gids": [PRIVATE_READ_GID],
            "credential_transition": (
                "setgroups_then_setresgid_then_setresuid_no_active_capabilities"
            ),
            "all_capability_sets_zero_required": True,
            "no_new_privs_required": True,
            "locked_securebits_required": 63,
            "unregistered_inherited_file_descriptors_forbidden": True,
        },
        "provider_id": "private_boundary_v2",
        "provider_available": False,
    }
    provider_status = {
        "required_provider_ids": list(_REQUIRED_PROVIDER_IDS),
        "providers": [
            {"provider_id": provider_id, "available": False}
            for provider_id in _REQUIRED_PROVIDER_IDS
        ],
        "available_provider_ids": [],
        "missing_provider_ids": list(_REQUIRED_PROVIDER_IDS),
        "all_required_providers_available": False,
    }
    unsigned = {
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "source_commit": upstream.source_commit,
        "experiment_attempt_id": upstream.attempt_id,
        "stage_kind": stage.value,
        "stage_attempt_id": stage_attempt,
        "upstream_raw_bindings": raw_bindings,
        "upstream_raw_closure_sha256": _sha(_canonical(raw_bindings)),
        "source_role_bindings": source_bindings,
        "stage_shape": _stage_shape(stage),
        "seeds": _seeds(stage),
        "parent_transition": {
            "required_stage_kinds": [],
            "receipt_bindings": [],
        },
        "paths": paths,
        "generator_invocation": generator_invocation,
        "closed_environment_policy": {
            "exact_environment": exact_environment,
            "allowed_names": sorted(exact_environment),
            "unlisted_names_forbidden": True,
            "secret_environment_forbidden": True,
            "attester_provider_id": "closed_environment_attester",
            "provider_available": False,
        },
        "resource_policy": {
            "job_identity_required": True,
            "job_identity_provider_id": "job_identity_attester",
            "job_identity_provider_available": False,
            "node_identity_required": True,
            "node_identity_provider_id": "node_identity_attester",
            "node_identity_provider_available": False,
            "gpu_inventory_required": True,
            "gpu_inventory_provider_id": "gpu_inventory_attester",
            "gpu_inventory_provider_available": False,
            "registered_job_id": None,
            "registered_node_id": None,
            "registered_gpu_type": None,
            "registered_gpu_count": None,
            "network_access_allowed": False,
            "network_isolation_provider_id": "network_isolation_attester",
            "network_isolation_provider_available": False,
        },
        "atomic_claim_protocol": {
            "claim_path": claim_path,
            "publication_intent_path": _absolute_join(
                upstream.durable_root, intent_relative
            ),
            "publication_pending_path": _absolute_join(
                upstream.durable_root, pending_relative
            ),
            "intent_o_excl_is_concurrency_serialization_point": True,
            "pending_created_with_o_excl": True,
            "pending_full_payload_write_required": True,
            "pending_fsync_before_chmod_required": True,
            "pending_chmod_mode": 0o444,
            "pending_fsync_after_chmod_required": True,
            "final_created_by_no_replace_hardlink": True,
            "precommit_final_and_pending_link_count": 2,
            "parent_fsync_after_final_hardlink_required": True,
            "fresh_precommit_ancestor_retraversal_required": True,
            "fresh_precommit_intent_full_bytes_required": True,
            "fresh_precommit_pending_final_same_inode_required": True,
            "fresh_precommit_final_full_bytes_required": True,
            "final_hardlink_visibility_is_not_commit_or_authorization": True,
            "pending_unlink_is_filesystem_commit_point": True,
            "parent_fsync_after_pending_unlink_required": True,
            "committed_final_link_count": 1,
            "committed_final_mode": 0o444,
            "fresh_committed_intent_present_required": True,
            "fresh_committed_pending_absent_required": True,
            "fresh_committed_final_full_bytes_required": True,
            "fresh_committed_full_path_observation_count": 2,
            "fresh_committed_full_path_observations_must_match": True,
            "direct_final_o_excl_forbidden": True,
            "rename_publication_forbidden": True,
            "fresh_semantically_validated_committed_final_required_before_generator_import": True,
            "generator_import_authorization_boundary": (
                "fresh_semantically_validated_intent_present_pending_absent_"
                "single_link_final"
            ),
            "adapter_source_sha256": source_by_role["structured_dgp_claim_adapter"][
                "sha256"
            ],
            "atomic_publisher_source_sha256": source_by_role[
                "structured_atomic_publisher"
            ]["sha256"],
            "provider_id": "dgp_claim_atomic_adapter",
            "provider_available": False,
        },
        "completion_protocol": {
            "receipt_path": paths["dgp_completion_receipt_path"],
            "publication_intent_path": paths[
                "dgp_completion_publication_intent_path"
            ],
            "publication_pending_path": paths[
                "dgp_completion_publication_pending_path"
            ],
            "common_atomic_publication_contract_required": True,
            "committed_final_mode": 0o444,
            "committed_final_link_count": 1,
            "fresh_committed_full_path_observation_count": 2,
            "fresh_committed_full_path_observations_must_match": True,
            "adapter_source_sha256": source_by_role[
                "structured_dgp_completion_adapter"
            ]["sha256"],
            "dgp_output_inventory_sha256": output_sha,
            "provider_id": "dgp_completion_adapter",
            "provider_available": False,
        },
        "dgp_output_inventory": outputs,
        "dgp_output_inventory_sha256": output_sha,
        "registry_v2_mapping": registry_mapping,
        "registry_v2_mapping_sha256": mapping_sha,
        "private_boundary_plan": private_plan,
        "provider_status": provider_status,
        "legacy_stage_plan_accepted": False,
        "dgp_generation_claim_eligible": False,
        "dgp_generator_import_authorized": False,
        "dgp_generation_authorized": False,
        "model_calls_authorized": False,
        "scorer_calls_authorized": False,
        "launch_authorized": False,
        "operational_authorization": False,
    }
    if set(unsigned) != _UNSIGNED_KEYS:
        raise StructuredStagePlanError("stage-plan builder schema differs")
    payload = dict(unsigned)
    payload["stage_plan_sha256"] = _sha(_canonical(unsigned))
    raw = _canonical(payload)
    validation = StructuredStagePlanValidation(
        source_commit=upstream.source_commit,
        experiment_attempt_id=upstream.attempt_id,
        stage_kind=stage.value,
        stage_attempt_id=stage_attempt,
        stage_root=str(paths["stage_root"]),
        private_context_root=str(paths["private_context_root"]),
        stage_plan_sha256=str(payload["stage_plan_sha256"]),
        upstream_raw_closure_sha256=str(unsigned["upstream_raw_closure_sha256"]),
        dgp_output_inventory_sha256=output_sha,
        registry_v2_mapping_sha256=mapping_sha,
        dgp_output_count=len(outputs),
        private_record_count=len(registry_entries),
        missing_provider_ids=_REQUIRED_PROVIDER_IDS,
    )
    return raw, validation


def seal_structured_stage_plan_bytes(
    *,
    protocol_plan_seal_bytes: object,
    stage_kind: object,
    stage_attempt_id: object,
    parent_transition_receipt_bytes: object,
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
    """Seal one non-authorizing smoke-stage v2 amendment."""

    raw, _ = _assemble(
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
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


def validate_structured_stage_plan_bytes(
    raw: object,
    *,
    protocol_plan_seal_bytes: object,
    stage_kind: object,
    stage_attempt_id: object,
    parent_transition_receipt_bytes: object,
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
) -> StructuredStagePlanValidation:
    """Reconstruct the complete v2 plan and require exact byte equality."""

    observed_raw = _raw(raw, "stage_plan_bytes")
    observed = _parse(observed_raw, "stage_plan_bytes")
    if set(observed) != _KEYS:
        raise StructuredStagePlanError("stage plan exact schema differs")
    expected_raw, validation = _assemble(
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
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
        raise StructuredStagePlanError(
            "stage plan differs from complete raw-byte reconstruction"
        )
    if (
        observed["protocol"] != PROTOCOL
        or observed["schema_version"] != SCHEMA_VERSION
        or observed["status"] != STATUS
        or observed["legacy_stage_plan_accepted"] is not False
        or any(observed[key] is not False for key in _AUTHORITY_KEYS)
        or type(observed["stage_plan_sha256"]) is not str
        or _SHA_RE.fullmatch(observed["stage_plan_sha256"]) is None
    ):
        raise StructuredStagePlanError("stage plan non-authority contract differs")
    return validation
