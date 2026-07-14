"""Non-authorizing pre-registrar DGP generation receipt boundary.

The public surface in this module is deliberately split in two.  Four pure
validators accept only exact canonical byte strings and explicit upstream byte
strings.  The production producer remains unavailable and fails before it
examines a path, byte string, mapping, or runtime object.

The private test seam publishes explicit synthetic bytes through the common
atomic publisher.  It never imports or executes a DGP generator, model, task,
scorer, registrar, or launcher.  Its stage-completion receipt closes only the
generator-owned row and corpus-inventory files.  Public context attestations,
registry digest records, and the stage manifest remain future outputs and must
be absent at this boundary, avoiding a registrar/completion dependency cycle.

The stage-plan parser below reconstructs every nested section consumed by this
boundary and all provider/authority switches, but it is not a replacement for
the upstream full raw-input stage-plan reconstruction.  Production enablement
therefore still requires the versioned stage-plan/provider amendment and its
official upstream validator; none of the public validation records here claim
that complete-plan authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

import cohort_closed_loop_structured_atomic_publish as atomic_publish
import cohort_closed_loop_structured_stage_plan as structured_stage_plan
from cohort_closed_loop_structured_dgp_context import (
    EXPECTED_STAGE_SEEDS,
    STAGE_SHAPES,
    CorpusInventory,
    DgpContextIntegrityError,
    PhaseKind,
    StageKind,
    canonical_json_bytes,
    load_corpus_inventory,
    load_dgp_row_identity,
)


class DgpGenerationBoundaryError(RuntimeError):
    """Raised when an exact pre-registrar generation boundary differs."""


PROVIDER_AVAILABLE = False

CLAIM_PROTOCOL = "cohort_structured_dgp_generation_claim_v2"
CLAIM_SCHEMA_VERSION = 2
CLAIM_STATUS = "sealed_test_injected_pre_import_non_authorizing"

INVOCATION_PROTOCOL = "cohort_structured_dgp_invocation_receipt_v1"
INVOCATION_SCHEMA_VERSION = 1
INVOCATION_STATUS = "sealed_test_injected_no_execution_non_authorizing"

CORPUS_COMPLETION_PROTOCOL = "cohort_structured_dgp_corpus_completion_receipt_v1"
CORPUS_COMPLETION_SCHEMA_VERSION = 1
CORPUS_COMPLETION_STATUS = "sealed_generator_corpus_integrity_non_authorizing"

STAGE_COMPLETION_PROTOCOL = "cohort_structured_dgp_completion_receipt_v2"
STAGE_COMPLETION_SCHEMA_VERSION = 2
STAGE_COMPLETION_STATUS = (
    "sealed_pre_registrar_generator_stage_integrity_non_authorizing"
)

_AUTHORITY_KEYS = (
    "dgp_generator_import_authorized",
    "dgp_generation_authorized",
    "model_calls_authorized",
    "scorer_calls_authorized",
    "launch_authorized",
    "operational_authorization",
)
_STAGE_AUTHORITY_KEYS = (
    "dgp_generation_claim_eligible",
    *_AUTHORITY_KEYS,
)
_SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}\Z")
_OUTPUT_ROW_KEYS = frozenset(
    {
        "path",
        "publication_intent_path",
        "publication_pending_path",
        "relative_path",
        "role",
        "writer_service",
    }
)
_CORPUS_EVIDENCE_KEYS = frozenset(
    {
        "block_id",
        "block_index",
        "path",
        "phase",
        "publication_intent_path",
        "publication_pending_path",
        "stage_kind",
    }
)
_OBSERVED_OUTPUT_KEYS = frozenset(
    {"file_sha256", "path", "relative_path", "size_bytes"}
)
_CORPUS_BINDING_KEYS = frozenset(
    {
        "corpus_inventory_sha256",
        "file_sha256",
        "path",
        "relative_path",
        "size_bytes",
    }
)
_ROW_BINDING_KEYS = frozenset(
    {
        "composite_row_identity_sha256",
        "file_sha256",
        "instance_index",
        "item_id",
        "path",
        "relative_path",
        "size_bytes",
    }
)
_CORPUS_COMPLETION_BINDING_KEYS = frozenset(
    {
        "block_id",
        "block_index",
        "dgp_corpus_completion_receipt_sha256",
        "file_sha256",
        "path",
        "phase",
        "size_bytes",
        "stage_kind",
    }
)
_PRIOR_CORPUS_BINDING_KEYS = frozenset(
    {
        "block_id",
        "block_index",
        "corpus_inventory_sha256",
        "file_sha256",
        "phase",
        "size_bytes",
        "stage_kind",
    }
)
_INTEGRITY_KEYS = frozenset(
    {
        "exact_seed_shape_and_aggregates_validated",
        "future_output_paths_absent",
        "generator_uniformity_validated",
        "ordered_corpora_validated",
        "prior_stage_disjointness_validated",
        "row_files_equal_embedded_corpus_rows",
    }
)
_GENERATOR_INVOCATION_KEYS = frozenset(
    {
        "argv_after_runtime",
        "controlled_process_launcher_provider_available",
        "controlled_process_launcher_provider_id",
        "cwd",
        "generator_import_requires_committed_claim",
        "generator_source_path",
        "generator_source_sha256",
        "provider_available",
        "provider_id",
        "runtime_executable_path",
        "runtime_executable_provider_available",
        "runtime_executable_provider_id",
        "stdin",
        "stdio_provider_available",
        "stdio_provider_id",
    }
)
_CLOSED_ENVIRONMENT_KEYS = frozenset(
    {
        "allowed_names",
        "attester_provider_id",
        "exact_environment",
        "provider_available",
        "secret_environment_forbidden",
        "unlisted_names_forbidden",
    }
)
_RESOURCE_POLICY_KEYS = frozenset(
    {
        "gpu_inventory_provider_available",
        "gpu_inventory_provider_id",
        "gpu_inventory_required",
        "job_identity_provider_available",
        "job_identity_provider_id",
        "job_identity_required",
        "network_access_allowed",
        "network_isolation_provider_available",
        "network_isolation_provider_id",
        "node_identity_provider_available",
        "node_identity_provider_id",
        "node_identity_required",
        "registered_gpu_count",
        "registered_gpu_type",
        "registered_job_id",
        "registered_node_id",
    }
)
_ATOMIC_CLAIM_KEYS = frozenset(
    {
        "adapter_source_sha256",
        "atomic_publisher_source_sha256",
        "claim_path",
        "committed_final_link_count",
        "committed_final_mode",
        "direct_final_o_excl_forbidden",
        "final_created_by_no_replace_hardlink",
        "final_hardlink_visibility_is_not_commit_or_authorization",
        "fresh_committed_final_full_bytes_required",
        "fresh_committed_full_path_observation_count",
        "fresh_committed_full_path_observations_must_match",
        "fresh_committed_intent_present_required",
        "fresh_committed_pending_absent_required",
        "fresh_precommit_ancestor_retraversal_required",
        "fresh_precommit_final_full_bytes_required",
        "fresh_precommit_intent_full_bytes_required",
        "fresh_precommit_pending_final_same_inode_required",
        "fresh_semantically_validated_committed_final_required_before_generator_import",
        "generator_import_authorization_boundary",
        "intent_o_excl_is_concurrency_serialization_point",
        "parent_fsync_after_final_hardlink_required",
        "parent_fsync_after_pending_unlink_required",
        "pending_chmod_mode",
        "pending_created_with_o_excl",
        "pending_fsync_after_chmod_required",
        "pending_fsync_before_chmod_required",
        "pending_full_payload_write_required",
        "pending_unlink_is_filesystem_commit_point",
        "precommit_final_and_pending_link_count",
        "provider_available",
        "provider_id",
        "publication_intent_path",
        "publication_pending_path",
        "rename_publication_forbidden",
    }
)
_COMPLETION_CONTRACT_KEYS = frozenset(
    {
        "adapter_source_sha256",
        "committed_final_link_count",
        "committed_final_mode",
        "common_atomic_publication_contract_required",
        "dgp_output_inventory_sha256",
        "fresh_committed_full_path_observation_count",
        "fresh_committed_full_path_observations_must_match",
        "provider_available",
        "provider_id",
        "publication_intent_path",
        "publication_pending_path",
        "receipt_path",
    }
)

_CLAIM_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "experiment_attempt_id",
        "stage_kind",
        "stage_attempt_id",
        "stage_plan_path",
        "stage_plan_file_sha256",
        "stage_plan_sha256",
        "generator_source_path",
        "generator_source_file_sha256",
        "resolved_invocation_sha256",
        "stage_dgp_output_inventory_sha256",
        "generator_output_inventory",
        "generator_output_inventory_sha256",
        "future_output_inventory",
        "future_output_inventory_sha256",
        "corpus_completion_inventory",
        "corpus_completion_inventory_sha256",
        "claim_path",
        "claim_publication_intent_path",
        "claim_publication_pending_path",
        "invocation_receipt_path",
        "invocation_publication_intent_path",
        "invocation_publication_pending_path",
        "stage_completion_receipt_path",
        "stage_completion_publication_intent_path",
        "stage_completion_publication_pending_path",
        *_AUTHORITY_KEYS,
    }
)
_CLAIM_KEYS = _CLAIM_UNSIGNED_KEYS | {"dgp_generation_claim_sha256"}

_INVOCATION_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "experiment_attempt_id",
        "stage_kind",
        "stage_attempt_id",
        "stage_plan_file_sha256",
        "stage_plan_sha256",
        "dgp_generation_claim_file_sha256",
        "dgp_generation_claim_sha256",
        "generator_source_file_sha256",
        "resolved_invocation_sha256",
        "generator_output_inventory_sha256",
        "future_output_inventory_sha256",
        "corpus_completion_inventory_sha256",
        "observed_generator_output_bindings",
        "observed_generator_output_inventory_sha256",
        "invocation_receipt_path",
        "invocation_publication_intent_path",
        "invocation_publication_pending_path",
        "test_runtime_injected",
        "generator_import_performed",
        "generator_execution_performed",
        *_AUTHORITY_KEYS,
    }
)
_INVOCATION_KEYS = _INVOCATION_UNSIGNED_KEYS | {"dgp_invocation_receipt_sha256"}

_CORPUS_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "experiment_attempt_id",
        "stage_kind",
        "stage_attempt_id",
        "block_id",
        "block_index",
        "phase",
        "run_seed",
        "dgp_seed",
        "stage_plan_file_sha256",
        "stage_plan_sha256",
        "dgp_generation_claim_file_sha256",
        "dgp_generation_claim_sha256",
        "dgp_invocation_receipt_file_sha256",
        "dgp_invocation_receipt_sha256",
        "dgp_generator_source_sha256",
        "dgp_arguments_sha256",
        "cohort_layer_inventory_sha256",
        "corpus_inventory_binding",
        "row_bindings",
        "artifact_set_sha256",
        "dgp_sha256",
        "aggregate_corpus_sha256",
        "integrity_validation",
        "corpus_completion_path",
        "corpus_completion_publication_intent_path",
        "corpus_completion_publication_pending_path",
        "hidden_registry_contents_validated",
        "scorer_reexecution_performed",
        *_AUTHORITY_KEYS,
    }
)
_CORPUS_KEYS = _CORPUS_UNSIGNED_KEYS | {"dgp_corpus_completion_receipt_sha256"}

_STAGE_COMPLETION_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "experiment_attempt_id",
        "stage_kind",
        "stage_attempt_id",
        "stage_plan_file_sha256",
        "stage_plan_sha256",
        "dgp_generation_claim_file_sha256",
        "dgp_generation_claim_sha256",
        "dgp_invocation_receipt_file_sha256",
        "dgp_invocation_receipt_sha256",
        "dgp_generator_source_sha256",
        "generator_output_inventory_sha256",
        "future_output_inventory_sha256",
        "completed_generator_output_bindings",
        "completed_generator_output_inventory_sha256",
        "corpus_completion_bindings",
        "corpus_completion_inventory_sha256",
        "prior_stage_corpus_bindings",
        "prior_stage_corpus_inventory_sha256",
        "integrity_validation",
        "stage_completion_receipt_path",
        "stage_completion_publication_intent_path",
        "stage_completion_publication_pending_path",
        "registrar_outputs_present",
        "stage_manifest_present",
        "hidden_registry_contents_validated",
        "scorer_reexecution_performed",
        *_AUTHORITY_KEYS,
    }
)
_STAGE_COMPLETION_KEYS = _STAGE_COMPLETION_UNSIGNED_KEYS | {
    "dgp_completion_receipt_sha256"
}

_REQUIRED_PRIOR_STAGES: Mapping[StageKind, tuple[StageKind, ...]] = {
    StageKind.SMOKE: (),
    StageKind.INTERNAL: (StageKind.SMOKE,),
    StageKind.CONFIRMATION: (StageKind.SMOKE, StageKind.INTERNAL),
}


@dataclass(frozen=True, slots=True)
class DgpGenerationClaimValidation:
    source_commit: str
    stage_kind: str
    stage_attempt_id: str
    generator_output_count: int
    future_output_count: int
    corpus_count: int
    dgp_generation_claim_sha256: str
    dgp_generator_import_authorized: bool = False
    dgp_generation_authorized: bool = False


@dataclass(frozen=True, slots=True)
class DgpInvocationValidation:
    source_commit: str
    stage_kind: str
    stage_attempt_id: str
    observed_generator_output_count: int
    dgp_invocation_receipt_sha256: str
    generator_import_performed: bool = False
    generator_execution_performed: bool = False


@dataclass(frozen=True, slots=True)
class DgpCorpusCompletionValidation:
    stage_kind: str
    block_id: str
    phase: str
    row_count: int
    dgp_corpus_completion_receipt_sha256: str
    hidden_registry_contents_validated: bool = False
    scorer_reexecution_performed: bool = False


@dataclass(frozen=True, slots=True)
class DgpStageCompletionValidation:
    stage_kind: str
    corpus_count: int
    row_count: int
    prior_corpus_count: int
    dgp_completion_receipt_sha256: str
    registrar_outputs_present: bool = False
    stage_manifest_present: bool = False
    hidden_registry_contents_validated: bool = False
    scorer_reexecution_performed: bool = False


@dataclass(frozen=True, slots=True)
class _StagePlanView:
    raw: bytes
    payload: dict[str, object]
    source_commit: str
    experiment_attempt_id: str
    stage_kind: StageKind
    stage_attempt_id: str
    durable_root: str
    stage_root: str
    stage_plan_path: str
    dgp_output_root: str
    claim_path: str
    invocation_receipt_path: str
    stage_completion_receipt_path: str
    generator_source_path: str
    generator_source_sha256: str
    resolved_invocation_sha256: str
    generator_outputs: tuple[dict[str, object], ...]
    future_outputs: tuple[dict[str, object], ...]
    corpus_completion_inventory: tuple[dict[str, object], ...]
    dgp_output_inventory_sha256: str
    stage_plan_sha256: str


@dataclass(frozen=True, slots=True)
class _CorpusClosure:
    corpus: CorpusInventory
    corpus_relative_path: str
    corpus_raw: bytes
    row_relative_paths: tuple[str, ...]
    row_raws: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class _DgpGenerationBoundaryTestRuntime:
    publish: Callable[..., atomic_publish.PublishedArtifactObservation] = (
        atomic_publish.publish_readonly_no_overwrite
    )
    read: Callable[..., tuple[bytes, atomic_publish.PublishedArtifactObservation]] = (
        atomic_publish.read_and_validate_readonly_artifact
    )
    before_stage_completion: Callable[[], None] = lambda: None
    before_final_revalidation: Callable[[], None] = lambda: None


@dataclass(frozen=True, slots=True)
class _DgpGenerationBoundaryTestArtifacts:
    claim_bytes: bytes
    invocation_receipt_bytes: bytes
    corpus_completion_receipt_bytes: tuple[bytes, ...]
    stage_completion_receipt_bytes: bytes


@dataclass(frozen=True, slots=True)
class _RootIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class _RetainedTestRoot:
    descriptor: int
    identity: _RootIdentity


@dataclass(frozen=True, slots=True)
class _FrozenParentDirectory:
    path: str
    identity: _RootIdentity


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
        raise DgpGenerationBoundaryError("value is not canonical ASCII JSON") from exc


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DgpGenerationBoundaryError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise DgpGenerationBoundaryError(f"non-finite JSON constant is forbidden: {value}")


def _raw(value: object, label: str) -> bytes:
    if type(value) is not bytes or not value:
        raise DgpGenerationBoundaryError(f"{label} must be nonempty exact bytes")
    return value


def _parse_canonical(value: object, label: str) -> dict[str, object]:
    raw = _raw(value, label)
    try:
        parsed = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DgpGenerationBoundaryError(f"{label} is not canonical JSON") from exc
    if type(parsed) is not dict:
        raise DgpGenerationBoundaryError(f"{label} must be a JSON object")
    if raw != _canonical(parsed):
        raise DgpGenerationBoundaryError(f"{label} is not canonical ASCII JSON")
    return parsed


def _exact_object(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise DgpGenerationBoundaryError(f"{label} exact schema differs")
    return value


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DgpGenerationBoundaryError(f"{label} must be lowercase SHA-256")
    return value


def _sha1(value: object, label: str) -> str:
    if type(value) is not str or _SHA1_RE.fullmatch(value) is None:
        raise DgpGenerationBoundaryError(f"{label} must be lowercase Git SHA-1")
    return value


def _safe_id(value: object, label: str) -> str:
    if type(value) is not str or _SAFE_ID_RE.fullmatch(value) is None:
        raise DgpGenerationBoundaryError(f"{label} is not a safe identifier")
    return value


def _exact_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise DgpGenerationBoundaryError(f"{label} must be an exact integer")
    return value


def _absolute_path(value: object, label: str) -> str:
    if type(value) is not str or not value.startswith("/"):
        raise DgpGenerationBoundaryError(f"{label} must be an absolute POSIX path")
    pure = PurePosixPath(value)
    if pure.as_posix() != value or any(part in {"", ".", ".."} for part in pure.parts):
        raise DgpGenerationBoundaryError(f"{label} is not normalized POSIX text")
    return value


def _relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise DgpGenerationBoundaryError(f"{label} must be a relative POSIX path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise DgpGenerationBoundaryError(f"{label} is not normalized POSIX text")
    return value


def _join(root: str, *parts: str) -> str:
    return PurePosixPath(root, *parts).as_posix()


def _relative_to(path: str, root: str, label: str) -> str:
    relative = posixpath.relpath(path, root)
    if relative == ".." or relative.startswith("../"):
        raise DgpGenerationBoundaryError(f"{label} escapes the durable root")
    return _relative_path(relative, label)


def _publication_paths(path: str, durable_root: str) -> tuple[str, str]:
    relative = _relative_to(path, durable_root, "publication path")
    intent, pending = atomic_publish.publication_sidecar_relative_paths(relative)
    return _join(durable_root, intent), _join(durable_root, pending)


def _assert_no_true_authority(value: object, label: str = "receipt") -> None:
    if type(value) is dict:
        for key, child in value.items():
            authority_like = (
                type(key) is str
                and key
                not in {"final_hardlink_visibility_is_not_commit_or_authorization"}
                and (
                    "authority" in key
                    or key == "available"
                    or key.endswith(
                        (
                            "_available",
                            "_eligible",
                            "_authorized",
                            "_authorization",
                            "_authority",
                        )
                    )
                )
            )
            if authority_like and child is not False:
                raise DgpGenerationBoundaryError(f"{label}.{key} must be exactly false")
            _assert_no_true_authority(child, f"{label}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _assert_no_true_authority(child, f"{label}[{index}]")


def _seal(unsigned: dict[str, object], digest_key: str) -> bytes:
    payload = dict(unsigned)
    payload[digest_key] = _sha256_bytes(_canonical(unsigned))
    return _canonical(payload)


def _parse_receipt(
    raw: object,
    *,
    keys: frozenset[str],
    unsigned_keys: frozenset[str],
    protocol: str,
    schema_version: int,
    status: str,
    digest_key: str,
    label: str,
) -> dict[str, object]:
    payload = _exact_object(_parse_canonical(raw, label), keys, label)
    if (
        payload["protocol"] != protocol
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != schema_version
        or payload["status"] != status
    ):
        raise DgpGenerationBoundaryError(f"{label} header differs")
    for key in _AUTHORITY_KEYS:
        if payload[key] is not False:
            raise DgpGenerationBoundaryError(f"{label}.{key} must be exactly false")
    _assert_no_true_authority(payload, label)
    embedded = _sha256(payload[digest_key], f"{label}.{digest_key}")
    unsigned = {key: payload[key] for key in unsigned_keys}
    if embedded != _sha256_bytes(_canonical(unsigned)):
        raise DgpGenerationBoundaryError(f"{label} self digest differs")
    return payload


def _stage_shape(stage: StageKind) -> dict[str, int]:
    shape = STAGE_SHAPES[stage]
    return {
        "blocks": shape.blocks,
        "items_per_phase": shape.items_per_phase,
        "phase_count": 2,
        "dgp_row_count": shape.blocks * shape.items_per_phase * 2,
    }


def _stage_seeds(stage: StageKind) -> list[dict[str, object]]:
    return [
        {
            "block_id": seed.block_id,
            "block_index": seed.block_index,
            "run_seed": seed.run_seed,
            "adaptation_dgp_seed": seed.adaptation_dgp_seed,
            "held_out_dgp_seed": seed.held_out_dgp_seed,
        }
        for seed in EXPECTED_STAGE_SEEDS[stage]
    ]


def _expected_corpus_coordinates(
    stage: StageKind,
) -> tuple[tuple[str, int, PhaseKind], ...]:
    return tuple(
        (seed.block_id, seed.block_index, phase)
        for seed in EXPECTED_STAGE_SEEDS[stage]
        for phase in (PhaseKind.ADAPTATION, PhaseKind.HELD_OUT)
    )


def _expected_output_inventory(
    *, durable_root: str, stage_root: str, stage: StageKind
) -> list[dict[str, object]]:
    output_root = _join(stage_root, "dgp")

    def row(relative: str, *, role: str, writer: str) -> dict[str, object]:
        path = _join(output_root, relative)
        intent, pending = _publication_paths(path, durable_root)
        return {
            "path": path,
            "publication_intent_path": intent,
            "publication_pending_path": pending,
            "relative_path": relative,
            "role": role,
            "writer_service": writer,
        }

    result = [
        row(
            "stage_manifest.json",
            role="dgp_stage_manifest",
            writer="dgp_completion_adapter",
        )
    ]
    for seed in EXPECTED_STAGE_SEEDS[stage]:
        for phase in (PhaseKind.ADAPTATION, PhaseKind.HELD_OUT):
            prefix = f"corpora/{seed.block_id}/{phase.value}"
            result.append(
                row(
                    f"{prefix}/corpus_inventory.json",
                    role="dgp_corpus_inventory",
                    writer="dgp_generator",
                )
            )
            for item_id in range(1, STAGE_SHAPES[stage].items_per_phase + 1):
                result.extend(
                    (
                        row(
                            f"{prefix}/rows/{item_id}.json",
                            role="dgp_row_identity",
                            writer="dgp_generator",
                        ),
                        row(
                            f"contexts/{seed.block_id}/{phase.value}/{item_id}/public_attestation.json",
                            role="public_context_attestation",
                            writer="context_registrar",
                        ),
                        row(
                            f"contexts/{seed.block_id}/{phase.value}/{item_id}/registry_digest_record.json",
                            role="context_registry_digest_record",
                            writer="context_registrar",
                        ),
                    )
                )
    return sorted(result, key=lambda item: str(item["path"]))


def _corpus_completion_inventory(
    *, durable_root: str, stage_root: str, stage: StageKind
) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    for block_id, block_index, phase in _expected_corpus_coordinates(stage):
        path = _join(
            stage_root,
            "control",
            "dgp_generation",
            "corpora",
            block_id,
            phase.value,
            "completion.v1.json",
        )
        intent, pending = _publication_paths(path, durable_root)
        rows.append(
            {
                "block_id": block_id,
                "block_index": block_index,
                "path": path,
                "phase": phase.value,
                "publication_intent_path": intent,
                "publication_pending_path": pending,
                "stage_kind": stage.value,
            }
        )
    return tuple(rows)


def _parse_stage_plan(stage_plan_bytes: object) -> _StagePlanView:
    raw = _raw(stage_plan_bytes, "stage_plan_bytes")
    payload = _parse_canonical(raw, "stage_plan_bytes")
    if set(payload) != structured_stage_plan._KEYS:  # noqa: SLF001
        raise DgpGenerationBoundaryError("stage plan exact top-level schema differs")
    if (
        payload["protocol"] != structured_stage_plan.PROTOCOL
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != structured_stage_plan.SCHEMA_VERSION
        or payload["status"] != structured_stage_plan.STATUS
    ):
        raise DgpGenerationBoundaryError("stage plan header differs")
    for key in _STAGE_AUTHORITY_KEYS:
        if payload[key] is not False:
            raise DgpGenerationBoundaryError(f"stage plan {key} must be false")
    if payload["legacy_stage_plan_accepted"] is not False:
        raise DgpGenerationBoundaryError("legacy stage plan must remain rejected")
    provider_status = payload["provider_status"]
    provider_keys = frozenset(
        {
            "all_required_providers_available",
            "available_provider_ids",
            "missing_provider_ids",
            "providers",
            "required_provider_ids",
        }
    )
    _exact_object(provider_status, provider_keys, "stage plan provider status")
    required_providers = list(
        structured_stage_plan._REQUIRED_PROVIDER_IDS  # noqa: SLF001
    )
    expected_providers = [
        {"available": False, "provider_id": provider_id}
        for provider_id in required_providers
    ]
    providers = provider_status["providers"]
    if type(providers) is not list or len(providers) != len(expected_providers):
        raise DgpGenerationBoundaryError("stage plan provider closure differs")
    for index, (observed_provider, expected_provider) in enumerate(
        zip(providers, expected_providers, strict=True)
    ):
        row = _exact_object(
            observed_provider,
            frozenset({"available", "provider_id"}),
            f"provider_status.providers[{index}]",
        )
        if (
            row["available"] is not False
            or type(row["provider_id"]) is not str
            or row["provider_id"] != expected_provider["provider_id"]
        ):
            raise DgpGenerationBoundaryError("stage plan provider closure differs")
    if (
        provider_status["required_provider_ids"] != required_providers
        or provider_status["available_provider_ids"] != []
        or provider_status["missing_provider_ids"] != required_providers
        or provider_status["all_required_providers_available"] is not False
    ):
        raise DgpGenerationBoundaryError("stage plan provider closure differs")
    closed_environment = _exact_object(
        payload["closed_environment_policy"],
        _CLOSED_ENVIRONMENT_KEYS,
        "stage plan closed_environment_policy",
    )
    exact_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    if (
        closed_environment["exact_environment"] != exact_environment
        or closed_environment["allowed_names"] != sorted(exact_environment)
        or closed_environment["unlisted_names_forbidden"] is not True
        or closed_environment["secret_environment_forbidden"] is not True
        or closed_environment["attester_provider_id"] != "closed_environment_attester"
        or closed_environment["provider_available"] is not False
    ):
        raise DgpGenerationBoundaryError("stage plan closed environment differs")
    resource_policy = _exact_object(
        payload["resource_policy"],
        _RESOURCE_POLICY_KEYS,
        "stage plan resource_policy",
    )
    expected_resource_policy: dict[str, object] = {
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
    }
    for key, expected in expected_resource_policy.items():
        actual = resource_policy[key]
        if type(expected) is bool:
            matches = actual is expected
        elif expected is None:
            matches = actual is None
        else:
            matches = type(actual) is str and actual == expected
        if not matches:
            raise DgpGenerationBoundaryError("stage plan resource policy differs")
    _assert_no_true_authority(payload, "stage_plan")
    source_commit = _sha1(payload["source_commit"], "stage plan source_commit")
    experiment_attempt = _safe_id(
        payload["experiment_attempt_id"], "stage plan experiment_attempt_id"
    )
    try:
        stage = StageKind(payload["stage_kind"])
    except (TypeError, ValueError) as exc:
        raise DgpGenerationBoundaryError("stage plan stage_kind differs") from exc
    stage_attempt = _safe_id(payload["stage_attempt_id"], "stage plan stage_attempt_id")
    stage_shape = _exact_object(
        payload["stage_shape"],
        frozenset({"blocks", "dgp_row_count", "items_per_phase", "phase_count"}),
        "stage plan stage_shape",
    )
    expected_shape = _stage_shape(stage)
    for key, expected in expected_shape.items():
        actual = _exact_int(stage_shape[key], f"stage_shape.{key}")
        if actual != expected:
            raise DgpGenerationBoundaryError("stage plan stage shape differs")
    seeds = payload["seeds"]
    expected_seeds = _stage_seeds(stage)
    seed_keys = frozenset(
        {
            "adaptation_dgp_seed",
            "block_id",
            "block_index",
            "held_out_dgp_seed",
            "run_seed",
        }
    )
    if type(seeds) is not list or len(seeds) != len(expected_seeds):
        raise DgpGenerationBoundaryError("stage plan seed table differs")
    for index, (observed_seed, expected_seed) in enumerate(
        zip(seeds, expected_seeds, strict=True)
    ):
        row = _exact_object(observed_seed, seed_keys, f"seeds[{index}]")
        if (
            type(row["block_id"]) is not str
            or row["block_id"] != expected_seed["block_id"]
        ):
            raise DgpGenerationBoundaryError("stage plan seed block differs")
        for key in (
            "block_index",
            "run_seed",
            "adaptation_dgp_seed",
            "held_out_dgp_seed",
        ):
            actual = _exact_int(row[key], f"seeds[{index}].{key}")
            if actual != expected_seed[key]:
                raise DgpGenerationBoundaryError("stage plan seed table differs")

    paths = payload["paths"]
    if type(paths) is not dict:
        raise DgpGenerationBoundaryError("stage plan paths must be an exact object")
    expected_paths = structured_stage_plan._paths(  # noqa: SLF001
        durable_root=_absolute_path(paths.get("durable_root"), "durable_root"),
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt,
        stage=stage,
        stage_attempt_id=stage_attempt,
    )
    if paths != expected_paths:
        raise DgpGenerationBoundaryError("stage plan exact paths object differs")
    durable_root = _absolute_path(paths.get("durable_root"), "durable_root")
    stage_root = _absolute_path(paths.get("stage_root"), "stage_root")
    expected_stage_root = _join(durable_root, "stages", stage.value, stage_attempt)
    if stage_root != expected_stage_root:
        raise DgpGenerationBoundaryError("stage root is not the fixed attempt path")
    stage_plan_path = _absolute_path(paths.get("stage_plan_path"), "stage_plan_path")
    dgp_output_root = _absolute_path(paths.get("dgp_output_root"), "dgp_output_root")
    claim_path = _absolute_path(
        paths.get("dgp_generation_claim_path"), "dgp_generation_claim_path"
    )
    stage_completion_path = _absolute_path(
        paths.get("dgp_completion_receipt_path"), "dgp_completion_receipt_path"
    )
    fixed_paths = (
        (stage_plan_path, _join(stage_root, "control", "stage_plan.json")),
        (dgp_output_root, _join(stage_root, "dgp")),
        (claim_path, _join(stage_root, "control", "dgp_generation.claim.json")),
        (
            stage_completion_path,
            _join(stage_root, "control", "dgp_completion_receipt.json"),
        ),
    )
    if any(actual != expected for actual, expected in fixed_paths):
        raise DgpGenerationBoundaryError("stage plan fixed output path differs")
    invocation_path = _join(
        stage_root, "control", "dgp_generation", "invocation_receipt.v1.json"
    )

    claim_contract = payload["atomic_claim_protocol"]
    completion_contract = payload["completion_protocol"]
    claim_contract = _exact_object(
        claim_contract, _ATOMIC_CLAIM_KEYS, "stage plan atomic_claim_protocol"
    )
    completion_contract = _exact_object(
        completion_contract,
        _COMPLETION_CONTRACT_KEYS,
        "stage plan completion_protocol",
    )
    claim_intent, claim_pending = _publication_paths(claim_path, durable_root)
    completion_intent, completion_pending = _publication_paths(
        stage_completion_path, durable_root
    )
    if (
        claim_contract.get("claim_path") != claim_path
        or claim_contract.get("publication_intent_path") != claim_intent
        or claim_contract.get("publication_pending_path") != claim_pending
        or completion_contract.get("receipt_path") != stage_completion_path
        or completion_contract.get("publication_intent_path") != completion_intent
        or completion_contract.get("publication_pending_path") != completion_pending
    ):
        raise DgpGenerationBoundaryError("stage plan publication path triple differs")
    claim_true_keys = _ATOMIC_CLAIM_KEYS - {
        "adapter_source_sha256",
        "atomic_publisher_source_sha256",
        "claim_path",
        "committed_final_link_count",
        "committed_final_mode",
        "fresh_committed_full_path_observation_count",
        "generator_import_authorization_boundary",
        "pending_chmod_mode",
        "precommit_final_and_pending_link_count",
        "provider_available",
        "provider_id",
        "publication_intent_path",
        "publication_pending_path",
    }
    if any(claim_contract[key] is not True for key in claim_true_keys):
        raise DgpGenerationBoundaryError("stage plan atomic claim booleans differ")
    for key, expected in (
        ("pending_chmod_mode", 0o444),
        ("precommit_final_and_pending_link_count", 2),
        ("committed_final_link_count", 1),
        ("committed_final_mode", 0o444),
        ("fresh_committed_full_path_observation_count", 2),
    ):
        if _exact_int(claim_contract[key], f"atomic_claim_protocol.{key}") != expected:
            raise DgpGenerationBoundaryError("stage plan atomic claim integer differs")
    if (
        claim_contract["generator_import_authorization_boundary"]
        != "fresh_semantically_validated_intent_present_pending_absent_single_link_final"
        or claim_contract["provider_id"] != "dgp_claim_atomic_adapter"
        or claim_contract["provider_available"] is not False
    ):
        raise DgpGenerationBoundaryError("stage plan atomic claim provider differs")
    _sha256(
        claim_contract["adapter_source_sha256"],
        "atomic claim adapter source digest",
    )
    _sha256(
        claim_contract["atomic_publisher_source_sha256"],
        "atomic publisher source digest",
    )
    completion_true_keys = {
        "common_atomic_publication_contract_required",
        "fresh_committed_full_path_observations_must_match",
    }
    if any(completion_contract[key] is not True for key in completion_true_keys):
        raise DgpGenerationBoundaryError("stage plan completion booleans differ")
    for key, expected in (
        ("committed_final_mode", 0o444),
        ("committed_final_link_count", 1),
        ("fresh_committed_full_path_observation_count", 2),
    ):
        if (
            _exact_int(completion_contract[key], f"completion_protocol.{key}")
            != expected
        ):
            raise DgpGenerationBoundaryError("stage plan completion integer differs")
    if (
        completion_contract["provider_id"] != "dgp_completion_adapter"
        or completion_contract["provider_available"] is not False
        or completion_contract["dgp_output_inventory_sha256"]
        != payload["dgp_output_inventory_sha256"]
    ):
        raise DgpGenerationBoundaryError("stage plan completion provider differs")
    _sha256(
        completion_contract["adapter_source_sha256"],
        "completion adapter source digest",
    )

    generator_invocation = payload["generator_invocation"]
    generator_invocation = _exact_object(
        generator_invocation,
        _GENERATOR_INVOCATION_KEYS,
        "stage plan generator_invocation",
    )
    generator_source_path = _absolute_path(
        generator_invocation.get("generator_source_path"), "generator_source_path"
    )
    generator_source_sha = _sha256(
        generator_invocation.get("generator_source_sha256"),
        "generator_source_sha256",
    )
    argv = generator_invocation.get("argv_after_runtime")
    expected_argv = [
        "-I",
        "-B",
        generator_source_path,
        "--protocol-plan-seal",
        _join(durable_root, "control", "structured_protocol_plan_seal.json"),
        "--stage-plan",
        stage_plan_path,
        "--dgp-generation-claim",
        claim_path,
        "--dgp-completion-receipt",
        stage_completion_path,
        "--stage-kind",
        stage.value,
        "--experiment-attempt-id",
        experiment_attempt,
        "--stage-attempt-id",
        stage_attempt,
        "--output-root",
        dgp_output_root,
    ]
    if argv != expected_argv:
        raise DgpGenerationBoundaryError("generator argv differs")
    generator_cwd = _absolute_path(generator_invocation.get("cwd"), "generator cwd")
    if not PurePosixPath(generator_source_path).is_relative_to(generator_cwd):
        raise DgpGenerationBoundaryError("generator source escapes generator cwd")
    if (
        generator_invocation["provider_id"] != "dgp_generator_invocation"
        or generator_invocation["provider_available"] is not False
        or generator_invocation["runtime_executable_provider_id"]
        != "python_runtime_attester"
        or generator_invocation["runtime_executable_provider_available"] is not False
        or generator_invocation["runtime_executable_path"] is not None
        or generator_invocation["stdin"] != "devnull"
        or generator_invocation["stdio_provider_id"] != "stdio_provider"
        or generator_invocation["stdio_provider_available"] is not False
        or generator_invocation["controlled_process_launcher_provider_id"]
        != "controlled_process_launcher"
        or generator_invocation["controlled_process_launcher_provider_available"]
        is not False
        or generator_invocation["generator_import_requires_committed_claim"] is not True
    ):
        raise DgpGenerationBoundaryError("stage plan generator invocation differs")
    source_bindings = payload["source_role_bindings"]
    if type(source_bindings) is not list:
        raise DgpGenerationBoundaryError("stage plan source bindings differ")
    generator_bindings = [
        row
        for row in source_bindings
        if type(row) is dict and row.get("role") == "dgp_generator"
    ]
    if len(generator_bindings) != 1:
        raise DgpGenerationBoundaryError("stage plan generator source binding differs")
    generator_binding = generator_bindings[0]
    if (
        generator_binding.get("path") != generator_source_path
        or generator_binding.get("sha256") != generator_source_sha
        or type(generator_binding.get("size_bytes")) is not int
        or generator_binding["size_bytes"] <= 0
    ):
        raise DgpGenerationBoundaryError("stage plan generator binding differs")

    expected_outputs = _expected_output_inventory(
        durable_root=durable_root, stage_root=stage_root, stage=stage
    )
    observed_outputs = payload["dgp_output_inventory"]
    if type(observed_outputs) is not list:
        raise DgpGenerationBoundaryError("stage plan DGP output inventory differs")
    for index, row in enumerate(observed_outputs):
        _exact_object(row, _OUTPUT_ROW_KEYS, f"dgp_output_inventory[{index}]")
    if observed_outputs != expected_outputs:
        raise DgpGenerationBoundaryError(
            "stage plan DGP output paths or ownership differ"
        )
    inventory_sha = _sha256(
        payload["dgp_output_inventory_sha256"],
        "stage plan dgp_output_inventory_sha256",
    )
    if inventory_sha != _sha256_bytes(_canonical(observed_outputs)):
        raise DgpGenerationBoundaryError(
            "stage plan DGP output inventory digest differs"
        )

    generator_outputs = tuple(
        dict(row)
        for row in observed_outputs
        if row["writer_service"] == "dgp_generator"
    )
    future_outputs = tuple(
        dict(row)
        for row in observed_outputs
        if row["writer_service"] != "dgp_generator"
    )
    if any(
        row["role"] not in {"dgp_row_identity", "dgp_corpus_inventory"}
        for row in generator_outputs
    ) or any(
        row["role"]
        not in {
            "public_context_attestation",
            "context_registry_digest_record",
            "dgp_stage_manifest",
        }
        for row in future_outputs
    ):
        raise DgpGenerationBoundaryError("DGP output ownership split differs")

    stage_plan_sha = _sha256(payload["stage_plan_sha256"], "stage_plan_sha256")
    unsigned_plan = dict(payload)
    del unsigned_plan["stage_plan_sha256"]
    if stage_plan_sha != _sha256_bytes(_canonical(unsigned_plan)):
        raise DgpGenerationBoundaryError("stage plan self digest differs")
    return _StagePlanView(
        raw=raw,
        payload=payload,
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt,
        stage_kind=stage,
        stage_attempt_id=stage_attempt,
        durable_root=durable_root,
        stage_root=stage_root,
        stage_plan_path=stage_plan_path,
        dgp_output_root=dgp_output_root,
        claim_path=claim_path,
        invocation_receipt_path=invocation_path,
        stage_completion_receipt_path=stage_completion_path,
        generator_source_path=generator_source_path,
        generator_source_sha256=generator_source_sha,
        resolved_invocation_sha256=_sha256_bytes(_canonical(generator_invocation)),
        generator_outputs=generator_outputs,
        future_outputs=future_outputs,
        corpus_completion_inventory=_corpus_completion_inventory(
            durable_root=durable_root, stage_root=stage_root, stage=stage
        ),
        dgp_output_inventory_sha256=inventory_sha,
        stage_plan_sha256=stage_plan_sha,
    )


def _generator_source(view: _StagePlanView, source_bytes: object) -> bytes:
    raw = _raw(source_bytes, "generator_source_bytes")
    if _sha256_bytes(raw) != view.generator_source_sha256:
        raise DgpGenerationBoundaryError("generator source raw-file digest differs")
    bindings = view.payload["source_role_bindings"]
    generator = next(
        row
        for row in bindings
        if type(row) is dict and row.get("role") == "dgp_generator"
    )
    if generator["size_bytes"] != len(raw):
        raise DgpGenerationBoundaryError("generator source raw-file size differs")
    return raw


def _snapshot_output_bytes(view: _StagePlanView, value: object) -> dict[str, bytes]:
    if type(value) is not dict:
        raise DgpGenerationBoundaryError(
            "generator_output_bytes_by_relative_path must be an exact dict"
        )
    expected = {str(row["relative_path"]) for row in view.generator_outputs}
    if set(value) != expected or any(
        type(key) is not str or type(raw) is not bytes or not raw
        for key, raw in value.items()
    ):
        raise DgpGenerationBoundaryError("generator output byte inventory differs")
    return {key: value[key] for key in sorted(value)}


def _output_bindings(
    view: _StagePlanView, outputs: Mapping[str, bytes]
) -> list[dict[str, object]]:
    by_relative = {str(row["relative_path"]): row for row in view.generator_outputs}
    return [
        {
            "file_sha256": _sha256_bytes(outputs[relative]),
            "path": by_relative[relative]["path"],
            "relative_path": relative,
            "size_bytes": len(outputs[relative]),
        }
        for relative in sorted(outputs, key=lambda item: str(by_relative[item]["path"]))
    ]


def _expected_seed(stage: StageKind, block_id: str) -> tuple[int, int, int, int]:
    matches = [
        seed for seed in EXPECTED_STAGE_SEEDS[stage] if seed.block_id == block_id
    ]
    if len(matches) != 1:
        raise DgpGenerationBoundaryError("corpus block is not preregistered")
    seed = matches[0]
    return (
        seed.block_index,
        seed.run_seed,
        seed.adaptation_dgp_seed,
        seed.held_out_dgp_seed,
    )


def _load_corpus(raw: bytes, label: str) -> CorpusInventory:
    try:
        return load_corpus_inventory(raw)
    except DgpContextIntegrityError as exc:
        raise DgpGenerationBoundaryError(f"{label} is not a valid corpus") from exc


def _current_corpus_closures(
    view: _StagePlanView,
    outputs: Mapping[str, bytes],
    *,
    expected_generator_sha256: str,
) -> tuple[_CorpusClosure, ...]:
    closures: list[_CorpusClosure] = []
    expected_coordinates = _expected_corpus_coordinates(view.stage_kind)
    for block_id, block_index, phase in expected_coordinates:
        prefix = f"corpora/{block_id}/{phase.value}"
        corpus_relative = f"{prefix}/corpus_inventory.json"
        corpus_raw = outputs[corpus_relative]
        corpus = _load_corpus(corpus_raw, corpus_relative)
        seed_block_index, run_seed, adaptation_seed, held_out_seed = _expected_seed(
            view.stage_kind, block_id
        )
        expected_dgp_seed = (
            adaptation_seed if phase is PhaseKind.ADAPTATION else held_out_seed
        )
        if (
            corpus.stage_kind is not view.stage_kind
            or corpus.block_id != block_id
            or corpus.block_index != block_index
            or block_index != seed_block_index
            or corpus.phase is not phase
            or corpus.run_seed != run_seed
            or corpus.dgp_seed != expected_dgp_seed
            or corpus.dgp_generator_sha256 != expected_generator_sha256
        ):
            raise DgpGenerationBoundaryError(
                "corpus stage, seed, or frozen generator binding differs"
            )
        row_relatives = tuple(
            f"{prefix}/rows/{item_id}.json"
            for item_id in range(1, STAGE_SHAPES[view.stage_kind].items_per_phase + 1)
        )
        row_raws = tuple(outputs[relative] for relative in row_relatives)
        for index, (row_raw, embedded) in enumerate(
            zip(row_raws, corpus.rows, strict=True)
        ):
            try:
                standalone = load_dgp_row_identity(row_raw)
            except DgpContextIntegrityError as exc:
                raise DgpGenerationBoundaryError(
                    f"standalone row {row_relatives[index]} differs"
                ) from exc
            if standalone != embedded or row_raw != canonical_json_bytes(
                embedded.to_payload()
            ):
                raise DgpGenerationBoundaryError(
                    "standalone row bytes differ from embedded corpus row"
                )
        closures.append(
            _CorpusClosure(
                corpus=corpus,
                corpus_relative_path=corpus_relative,
                corpus_raw=corpus_raw,
                row_relative_paths=row_relatives,
                row_raws=row_raws,
            )
        )
    return tuple(closures)


def _identity_sets(corpus: CorpusInventory) -> dict[str, frozenset[str]]:
    return {
        "instance_id": frozenset(row.instance_id for row in corpus.rows),
        "database": frozenset(row.database_sha256 for row in corpus.rows),
        "ground_truth": frozenset(row.ground_truth_sha256 for row in corpus.rows),
        "reference_survival": frozenset(
            row.reference_survival_sha256 for row in corpus.rows
        ),
        "composite_row_identity": frozenset(
            row.composite_row_identity_sha256 for row in corpus.rows
        ),
    }


def _assert_pairwise_disjoint(corpora: Sequence[CorpusInventory]) -> None:
    aggregate_fields = (
        "aggregate_database_sha256",
        "aggregate_ground_truth_sha256",
        "aggregate_schedule_sha256",
        "aggregate_order_sha256",
        "aggregate_corpus_sha256",
    )
    for index, left in enumerate(corpora):
        left_sets = _identity_sets(left)
        for right in corpora[index + 1 :]:
            if left.dgp_seed == right.dgp_seed:
                raise DgpGenerationBoundaryError("DGP seed collision across corpora")
            same_block = (
                left.stage_kind is right.stage_kind
                and left.block_id == right.block_id
                and left.block_index == right.block_index
            )
            if (left.run_seed == right.run_seed) != same_block:
                raise DgpGenerationBoundaryError("run-seed block relation differs")
            right_sets = _identity_sets(right)
            for component, values in left_sets.items():
                if values & right_sets[component]:
                    raise DgpGenerationBoundaryError(
                        f"cross-corpus {component} collision"
                    )
            for field in aggregate_fields:
                if getattr(left, field) == getattr(right, field):
                    raise DgpGenerationBoundaryError(f"cross-corpus {field} collision")


def _prior_corpora(
    view: _StagePlanView, value: object
) -> tuple[tuple[bytes, CorpusInventory], ...]:
    if type(value) is not tuple or any(type(raw) is not bytes for raw in value):
        raise DgpGenerationBoundaryError(
            "prior_stage_corpus_inventory_bytes must be an exact tuple of bytes"
        )
    expected_coordinates = tuple(
        (stage, *coordinate)
        for stage in _REQUIRED_PRIOR_STAGES[view.stage_kind]
        for coordinate in _expected_corpus_coordinates(stage)
    )
    if len(value) != len(expected_coordinates):
        raise DgpGenerationBoundaryError("required prior-stage corpus closure differs")
    result: list[tuple[bytes, CorpusInventory]] = []
    for index, (raw, (stage, block_id, block_index, phase)) in enumerate(
        zip(value, expected_coordinates, strict=True)
    ):
        corpus = _load_corpus(raw, f"prior corpus {index}")
        seed_index, run_seed, adaptation_seed, held_out_seed = _expected_seed(
            stage, block_id
        )
        expected_dgp_seed = (
            adaptation_seed if phase is PhaseKind.ADAPTATION else held_out_seed
        )
        if (
            corpus.stage_kind is not stage
            or corpus.block_id != block_id
            or corpus.block_index != block_index
            or block_index != seed_index
            or corpus.phase is not phase
            or corpus.run_seed != run_seed
            or corpus.dgp_seed != expected_dgp_seed
        ):
            raise DgpGenerationBoundaryError("prior corpus order or seed differs")
        result.append((raw, corpus))
    return tuple(result)


def _validate_stage_corpora(
    view: _StagePlanView,
    outputs: Mapping[str, bytes],
    prior_stage_corpus_inventory_bytes: object,
) -> tuple[tuple[_CorpusClosure, ...], tuple[tuple[bytes, CorpusInventory], ...]]:
    current = _current_corpus_closures(
        view, outputs, expected_generator_sha256=view.generator_source_sha256
    )
    prior = _prior_corpora(view, prior_stage_corpus_inventory_bytes)
    all_corpora = tuple(corpus for _, corpus in prior) + tuple(
        closure.corpus for closure in current
    )
    if {corpus.dgp_generator_sha256 for corpus in all_corpora} != {
        view.generator_source_sha256
    }:
        raise DgpGenerationBoundaryError("current/prior generator digest drift")
    _assert_pairwise_disjoint(all_corpora)
    return current, prior


def _claim_bytes(*, stage_plan_bytes: object, generator_source_bytes: object) -> bytes:
    view = _parse_stage_plan(stage_plan_bytes)
    _generator_source(view, generator_source_bytes)
    claim_intent, claim_pending = _publication_paths(view.claim_path, view.durable_root)
    invocation_intent, invocation_pending = _publication_paths(
        view.invocation_receipt_path, view.durable_root
    )
    completion_intent, completion_pending = _publication_paths(
        view.stage_completion_receipt_path, view.durable_root
    )
    generator_outputs = [dict(row) for row in view.generator_outputs]
    future_outputs = [dict(row) for row in view.future_outputs]
    corpus_evidence = [dict(row) for row in view.corpus_completion_inventory]
    all_paths: list[str] = [
        view.stage_plan_path,
        *_publication_paths(view.stage_plan_path, view.durable_root),
        view.claim_path,
        claim_intent,
        claim_pending,
        view.invocation_receipt_path,
        invocation_intent,
        invocation_pending,
        view.stage_completion_receipt_path,
        completion_intent,
        completion_pending,
    ]
    all_paths.extend(
        str(row[key])
        for row in (*view.generator_outputs, *view.future_outputs)
        for key in ("path", "publication_intent_path", "publication_pending_path")
    )
    all_paths.extend(
        str(row[key])
        for row in view.corpus_completion_inventory
        for key in ("path", "publication_intent_path", "publication_pending_path")
    )
    if len(all_paths) != len(set(all_paths)):
        raise DgpGenerationBoundaryError(
            "registered final/intent/pending paths collide"
        )
    unsigned: dict[str, object] = {
        "protocol": CLAIM_PROTOCOL,
        "schema_version": CLAIM_SCHEMA_VERSION,
        "status": CLAIM_STATUS,
        "source_commit": view.source_commit,
        "experiment_attempt_id": view.experiment_attempt_id,
        "stage_kind": view.stage_kind.value,
        "stage_attempt_id": view.stage_attempt_id,
        "stage_plan_path": view.stage_plan_path,
        "stage_plan_file_sha256": _sha256_bytes(view.raw),
        "stage_plan_sha256": view.stage_plan_sha256,
        "generator_source_path": view.generator_source_path,
        "generator_source_file_sha256": view.generator_source_sha256,
        "resolved_invocation_sha256": view.resolved_invocation_sha256,
        "stage_dgp_output_inventory_sha256": view.dgp_output_inventory_sha256,
        "generator_output_inventory": generator_outputs,
        "generator_output_inventory_sha256": _sha256_bytes(
            _canonical(generator_outputs)
        ),
        "future_output_inventory": future_outputs,
        "future_output_inventory_sha256": _sha256_bytes(_canonical(future_outputs)),
        "corpus_completion_inventory": corpus_evidence,
        "corpus_completion_inventory_sha256": _sha256_bytes(
            _canonical(corpus_evidence)
        ),
        "claim_path": view.claim_path,
        "claim_publication_intent_path": claim_intent,
        "claim_publication_pending_path": claim_pending,
        "invocation_receipt_path": view.invocation_receipt_path,
        "invocation_publication_intent_path": invocation_intent,
        "invocation_publication_pending_path": invocation_pending,
        "stage_completion_receipt_path": view.stage_completion_receipt_path,
        "stage_completion_publication_intent_path": completion_intent,
        "stage_completion_publication_pending_path": completion_pending,
        **{key: False for key in _AUTHORITY_KEYS},
    }
    if set(unsigned) != _CLAIM_UNSIGNED_KEYS:
        raise DgpGenerationBoundaryError("claim builder schema differs")
    return _seal(unsigned, "dgp_generation_claim_sha256")


def _parse_claim(raw: object) -> dict[str, object]:
    payload = _parse_receipt(
        raw,
        keys=_CLAIM_KEYS,
        unsigned_keys=_CLAIM_UNSIGNED_KEYS,
        protocol=CLAIM_PROTOCOL,
        schema_version=CLAIM_SCHEMA_VERSION,
        status=CLAIM_STATUS,
        digest_key="dgp_generation_claim_sha256",
        label="DGP generation claim",
    )
    _sha1(payload["source_commit"], "claim source_commit")
    _safe_id(payload["experiment_attempt_id"], "claim experiment_attempt_id")
    _safe_id(payload["stage_attempt_id"], "claim stage_attempt_id")
    _sha256(payload["stage_plan_file_sha256"], "claim stage-plan file digest")
    _sha256(payload["stage_plan_sha256"], "claim stage-plan self digest")
    _sha256(payload["generator_source_file_sha256"], "claim generator source digest")
    for label, key, row_keys in (
        ("generator output inventory", "generator_output_inventory", _OUTPUT_ROW_KEYS),
        ("future output inventory", "future_output_inventory", _OUTPUT_ROW_KEYS),
        (
            "corpus completion inventory",
            "corpus_completion_inventory",
            _CORPUS_EVIDENCE_KEYS,
        ),
    ):
        rows = payload[key]
        if type(rows) is not list:
            raise DgpGenerationBoundaryError(f"claim {label} differs")
        for index, row in enumerate(rows):
            _exact_object(row, row_keys, f"claim {label}[{index}]")
    return payload


def validate_dgp_generation_claim_bytes(
    raw: object, *, stage_plan_bytes: object, generator_source_bytes: object
) -> DgpGenerationClaimValidation:
    """Purely reconstruct and validate one exact non-authorizing claim."""

    observed_raw = _raw(raw, "claim_bytes")
    payload = _parse_claim(observed_raw)
    expected = _claim_bytes(
        stage_plan_bytes=stage_plan_bytes,
        generator_source_bytes=generator_source_bytes,
    )
    if observed_raw != expected:
        raise DgpGenerationBoundaryError(
            "DGP generation claim differs from raw-byte reconstruction"
        )
    return DgpGenerationClaimValidation(
        source_commit=str(payload["source_commit"]),
        stage_kind=str(payload["stage_kind"]),
        stage_attempt_id=str(payload["stage_attempt_id"]),
        generator_output_count=len(payload["generator_output_inventory"]),
        future_output_count=len(payload["future_output_inventory"]),
        corpus_count=len(payload["corpus_completion_inventory"]),
        dgp_generation_claim_sha256=str(payload["dgp_generation_claim_sha256"]),
    )


def _invocation_bytes(
    *,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    claim_bytes: object,
    generator_output_bytes_by_relative_path: object,
) -> bytes:
    view = _parse_stage_plan(stage_plan_bytes)
    _generator_source(view, generator_source_bytes)
    expected_claim = _claim_bytes(
        stage_plan_bytes=stage_plan_bytes, generator_source_bytes=generator_source_bytes
    )
    claim_raw = _raw(claim_bytes, "claim_bytes")
    if claim_raw != expected_claim:
        raise DgpGenerationBoundaryError("invocation claim edge differs")
    claim = _parse_claim(claim_raw)
    outputs = _snapshot_output_bytes(view, generator_output_bytes_by_relative_path)
    _current_corpus_closures(
        view, outputs, expected_generator_sha256=view.generator_source_sha256
    )
    bindings = _output_bindings(view, outputs)
    intent, pending = _publication_paths(
        view.invocation_receipt_path, view.durable_root
    )
    unsigned: dict[str, object] = {
        "protocol": INVOCATION_PROTOCOL,
        "schema_version": INVOCATION_SCHEMA_VERSION,
        "status": INVOCATION_STATUS,
        "source_commit": view.source_commit,
        "experiment_attempt_id": view.experiment_attempt_id,
        "stage_kind": view.stage_kind.value,
        "stage_attempt_id": view.stage_attempt_id,
        "stage_plan_file_sha256": _sha256_bytes(view.raw),
        "stage_plan_sha256": view.stage_plan_sha256,
        "dgp_generation_claim_file_sha256": _sha256_bytes(claim_raw),
        "dgp_generation_claim_sha256": claim["dgp_generation_claim_sha256"],
        "generator_source_file_sha256": view.generator_source_sha256,
        "resolved_invocation_sha256": view.resolved_invocation_sha256,
        "generator_output_inventory_sha256": claim["generator_output_inventory_sha256"],
        "future_output_inventory_sha256": claim["future_output_inventory_sha256"],
        "corpus_completion_inventory_sha256": claim[
            "corpus_completion_inventory_sha256"
        ],
        "observed_generator_output_bindings": bindings,
        "observed_generator_output_inventory_sha256": _sha256_bytes(
            _canonical(bindings)
        ),
        "invocation_receipt_path": view.invocation_receipt_path,
        "invocation_publication_intent_path": intent,
        "invocation_publication_pending_path": pending,
        "test_runtime_injected": True,
        "generator_import_performed": False,
        "generator_execution_performed": False,
        **{key: False for key in _AUTHORITY_KEYS},
    }
    if set(unsigned) != _INVOCATION_UNSIGNED_KEYS:
        raise DgpGenerationBoundaryError("invocation builder schema differs")
    return _seal(unsigned, "dgp_invocation_receipt_sha256")


def _parse_invocation(raw: object) -> dict[str, object]:
    payload = _parse_receipt(
        raw,
        keys=_INVOCATION_KEYS,
        unsigned_keys=_INVOCATION_UNSIGNED_KEYS,
        protocol=INVOCATION_PROTOCOL,
        schema_version=INVOCATION_SCHEMA_VERSION,
        status=INVOCATION_STATUS,
        digest_key="dgp_invocation_receipt_sha256",
        label="DGP invocation receipt",
    )
    if (
        payload["test_runtime_injected"] is not True
        or payload["generator_import_performed"] is not False
        or payload["generator_execution_performed"] is not False
    ):
        raise DgpGenerationBoundaryError("invocation execution claims differ")
    bindings = payload["observed_generator_output_bindings"]
    if type(bindings) is not list:
        raise DgpGenerationBoundaryError("invocation output bindings differ")
    for index, row in enumerate(bindings):
        _exact_object(row, _OBSERVED_OUTPUT_KEYS, f"invocation outputs[{index}]")
    return payload


def validate_dgp_invocation_receipt_bytes(
    raw: object,
    *,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    claim_bytes: object,
    generator_output_bytes_by_relative_path: object,
) -> DgpInvocationValidation:
    """Purely validate the injected no-execution invocation receipt."""

    observed_raw = _raw(raw, "invocation_receipt_bytes")
    payload = _parse_invocation(observed_raw)
    expected = _invocation_bytes(
        stage_plan_bytes=stage_plan_bytes,
        generator_source_bytes=generator_source_bytes,
        claim_bytes=claim_bytes,
        generator_output_bytes_by_relative_path=(
            generator_output_bytes_by_relative_path
        ),
    )
    if observed_raw != expected:
        raise DgpGenerationBoundaryError(
            "DGP invocation receipt differs from raw-byte reconstruction"
        )
    return DgpInvocationValidation(
        source_commit=str(payload["source_commit"]),
        stage_kind=str(payload["stage_kind"]),
        stage_attempt_id=str(payload["stage_attempt_id"]),
        observed_generator_output_count=len(
            payload["observed_generator_output_bindings"]
        ),
        dgp_invocation_receipt_sha256=str(payload["dgp_invocation_receipt_sha256"]),
    )


def _corpus_binding(view: _StagePlanView, closure: _CorpusClosure) -> dict[str, object]:
    return {
        "corpus_inventory_sha256": closure.corpus.corpus_inventory_sha256,
        "file_sha256": _sha256_bytes(closure.corpus_raw),
        "path": _join(view.dgp_output_root, closure.corpus_relative_path),
        "relative_path": closure.corpus_relative_path,
        "size_bytes": len(closure.corpus_raw),
    }


def _row_bindings(
    view: _StagePlanView, closure: _CorpusClosure
) -> list[dict[str, object]]:
    return [
        {
            "composite_row_identity_sha256": row.composite_row_identity_sha256,
            "file_sha256": _sha256_bytes(raw),
            "instance_index": row.instance_index,
            "item_id": row.item_id,
            "path": _join(view.dgp_output_root, relative),
            "relative_path": relative,
            "size_bytes": len(raw),
        }
        for row, relative, raw in zip(
            closure.corpus.rows,
            closure.row_relative_paths,
            closure.row_raws,
            strict=True,
        )
    ]


def _corpus_completion_bytes(
    *,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    claim_bytes: object,
    invocation_receipt_bytes: object,
    generator_output_bytes_by_relative_path: object,
    corpus_inventory_relative_path: object,
) -> bytes:
    view = _parse_stage_plan(stage_plan_bytes)
    _generator_source(view, generator_source_bytes)
    outputs = _snapshot_output_bytes(view, generator_output_bytes_by_relative_path)
    closures = _current_corpus_closures(
        view, outputs, expected_generator_sha256=view.generator_source_sha256
    )
    relative = _relative_path(
        corpus_inventory_relative_path, "corpus_inventory_relative_path"
    )
    matches = [item for item in closures if item.corpus_relative_path == relative]
    if len(matches) != 1:
        raise DgpGenerationBoundaryError("corpus completion target differs")
    closure = matches[0]
    expected_claim = _claim_bytes(
        stage_plan_bytes=stage_plan_bytes, generator_source_bytes=generator_source_bytes
    )
    claim_raw = _raw(claim_bytes, "claim_bytes")
    if claim_raw != expected_claim:
        raise DgpGenerationBoundaryError("corpus completion claim edge differs")
    claim = _parse_claim(claim_raw)
    expected_invocation = _invocation_bytes(
        stage_plan_bytes=stage_plan_bytes,
        generator_source_bytes=generator_source_bytes,
        claim_bytes=claim_raw,
        generator_output_bytes_by_relative_path=outputs,
    )
    invocation_raw = _raw(invocation_receipt_bytes, "invocation_receipt_bytes")
    if invocation_raw != expected_invocation:
        raise DgpGenerationBoundaryError("corpus completion invocation edge differs")
    invocation = _parse_invocation(invocation_raw)
    evidence_matches = [
        row
        for row in view.corpus_completion_inventory
        if row["block_id"] == closure.corpus.block_id
        and row["phase"] == closure.corpus.phase.value
    ]
    if len(evidence_matches) != 1:
        raise DgpGenerationBoundaryError("corpus evidence path differs")
    evidence = evidence_matches[0]
    corpus_binding = _corpus_binding(view, closure)
    row_bindings = _row_bindings(view, closure)
    artifact_set = [corpus_binding, *row_bindings]
    unsigned: dict[str, object] = {
        "protocol": CORPUS_COMPLETION_PROTOCOL,
        "schema_version": CORPUS_COMPLETION_SCHEMA_VERSION,
        "status": CORPUS_COMPLETION_STATUS,
        "source_commit": view.source_commit,
        "experiment_attempt_id": view.experiment_attempt_id,
        "stage_kind": view.stage_kind.value,
        "stage_attempt_id": view.stage_attempt_id,
        "block_id": closure.corpus.block_id,
        "block_index": closure.corpus.block_index,
        "phase": closure.corpus.phase.value,
        "run_seed": closure.corpus.run_seed,
        "dgp_seed": closure.corpus.dgp_seed,
        "stage_plan_file_sha256": _sha256_bytes(view.raw),
        "stage_plan_sha256": view.stage_plan_sha256,
        "dgp_generation_claim_file_sha256": _sha256_bytes(claim_raw),
        "dgp_generation_claim_sha256": claim["dgp_generation_claim_sha256"],
        "dgp_invocation_receipt_file_sha256": _sha256_bytes(invocation_raw),
        "dgp_invocation_receipt_sha256": invocation["dgp_invocation_receipt_sha256"],
        "dgp_generator_source_sha256": closure.corpus.dgp_generator_sha256,
        "dgp_arguments_sha256": closure.corpus.dgp_arguments_sha256,
        "cohort_layer_inventory_sha256": (closure.corpus.cohort_layer_inventory_sha256),
        "corpus_inventory_binding": corpus_binding,
        "row_bindings": row_bindings,
        "artifact_set_sha256": _sha256_bytes(_canonical(artifact_set)),
        "dgp_sha256": closure.corpus.dgp_sha256,
        "aggregate_corpus_sha256": closure.corpus.aggregate_corpus_sha256,
        "integrity_validation": {
            "exact_seed_shape_and_aggregates_validated": True,
            "row_files_equal_embedded_corpus_rows": True,
        },
        "corpus_completion_path": evidence["path"],
        "corpus_completion_publication_intent_path": evidence[
            "publication_intent_path"
        ],
        "corpus_completion_publication_pending_path": evidence[
            "publication_pending_path"
        ],
        "hidden_registry_contents_validated": False,
        "scorer_reexecution_performed": False,
        **{key: False for key in _AUTHORITY_KEYS},
    }
    if set(unsigned) != _CORPUS_UNSIGNED_KEYS:
        raise DgpGenerationBoundaryError("corpus completion builder schema differs")
    return _seal(unsigned, "dgp_corpus_completion_receipt_sha256")


def _parse_corpus_completion(raw: object) -> dict[str, object]:
    payload = _parse_receipt(
        raw,
        keys=_CORPUS_KEYS,
        unsigned_keys=_CORPUS_UNSIGNED_KEYS,
        protocol=CORPUS_COMPLETION_PROTOCOL,
        schema_version=CORPUS_COMPLETION_SCHEMA_VERSION,
        status=CORPUS_COMPLETION_STATUS,
        digest_key="dgp_corpus_completion_receipt_sha256",
        label="DGP corpus completion receipt",
    )
    _exact_object(
        payload["corpus_inventory_binding"],
        _CORPUS_BINDING_KEYS,
        "corpus inventory binding",
    )
    rows = payload["row_bindings"]
    if type(rows) is not list or not rows:
        raise DgpGenerationBoundaryError("corpus row bindings differ")
    for index, row in enumerate(rows):
        _exact_object(row, _ROW_BINDING_KEYS, f"row_bindings[{index}]")
    integrity = _exact_object(
        payload["integrity_validation"],
        frozenset(
            {
                "exact_seed_shape_and_aggregates_validated",
                "row_files_equal_embedded_corpus_rows",
            }
        ),
        "corpus integrity validation",
    )
    if set(integrity.values()) != {True}:
        raise DgpGenerationBoundaryError("corpus integrity flags differ")
    if (
        payload["hidden_registry_contents_validated"] is not False
        or payload["scorer_reexecution_performed"] is not False
    ):
        raise DgpGenerationBoundaryError("corpus hidden/scorer claims differ")
    return payload


def validate_dgp_corpus_completion_receipt_bytes(
    raw: object,
    *,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    claim_bytes: object,
    invocation_receipt_bytes: object,
    generator_output_bytes_by_relative_path: object,
) -> DgpCorpusCompletionValidation:
    """Purely validate one ordered row-to-corpus completion receipt."""

    observed_raw = _raw(raw, "corpus_completion_receipt_bytes")
    payload = _parse_corpus_completion(observed_raw)
    binding = payload["corpus_inventory_binding"]
    expected = _corpus_completion_bytes(
        stage_plan_bytes=stage_plan_bytes,
        generator_source_bytes=generator_source_bytes,
        claim_bytes=claim_bytes,
        invocation_receipt_bytes=invocation_receipt_bytes,
        generator_output_bytes_by_relative_path=(
            generator_output_bytes_by_relative_path
        ),
        corpus_inventory_relative_path=binding["relative_path"],
    )
    if observed_raw != expected:
        raise DgpGenerationBoundaryError(
            "DGP corpus completion differs from raw-byte reconstruction"
        )
    return DgpCorpusCompletionValidation(
        stage_kind=str(payload["stage_kind"]),
        block_id=str(payload["block_id"]),
        phase=str(payload["phase"]),
        row_count=len(payload["row_bindings"]),
        dgp_corpus_completion_receipt_sha256=str(
            payload["dgp_corpus_completion_receipt_sha256"]
        ),
    )


def _prior_bindings(
    prior: Sequence[tuple[bytes, CorpusInventory]],
) -> list[dict[str, object]]:
    return [
        {
            "block_id": corpus.block_id,
            "block_index": corpus.block_index,
            "corpus_inventory_sha256": corpus.corpus_inventory_sha256,
            "file_sha256": _sha256_bytes(raw),
            "phase": corpus.phase.value,
            "size_bytes": len(raw),
            "stage_kind": corpus.stage_kind.value,
        }
        for raw, corpus in prior
    ]


def _stage_completion_bytes(
    *,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    claim_bytes: object,
    invocation_receipt_bytes: object,
    corpus_completion_receipt_bytes: object,
    generator_output_bytes_by_relative_path: object,
    prior_stage_corpus_inventory_bytes: object,
) -> bytes:
    view = _parse_stage_plan(stage_plan_bytes)
    _generator_source(view, generator_source_bytes)
    outputs = _snapshot_output_bytes(view, generator_output_bytes_by_relative_path)
    current, prior = _validate_stage_corpora(
        view, outputs, prior_stage_corpus_inventory_bytes
    )
    expected_claim = _claim_bytes(
        stage_plan_bytes=stage_plan_bytes, generator_source_bytes=generator_source_bytes
    )
    claim_raw = _raw(claim_bytes, "claim_bytes")
    if claim_raw != expected_claim:
        raise DgpGenerationBoundaryError("stage completion claim edge differs")
    claim = _parse_claim(claim_raw)
    expected_invocation = _invocation_bytes(
        stage_plan_bytes=stage_plan_bytes,
        generator_source_bytes=generator_source_bytes,
        claim_bytes=claim_raw,
        generator_output_bytes_by_relative_path=outputs,
    )
    invocation_raw = _raw(invocation_receipt_bytes, "invocation_receipt_bytes")
    if invocation_raw != expected_invocation:
        raise DgpGenerationBoundaryError("stage completion invocation edge differs")
    invocation = _parse_invocation(invocation_raw)
    if type(corpus_completion_receipt_bytes) is not tuple or any(
        type(raw) is not bytes for raw in corpus_completion_receipt_bytes
    ):
        raise DgpGenerationBoundaryError(
            "corpus_completion_receipt_bytes must be an exact tuple of bytes"
        )
    if len(corpus_completion_receipt_bytes) != len(current):
        raise DgpGenerationBoundaryError("corpus completion receipt count differs")
    completion_bindings: list[dict[str, object]] = []
    for raw, closure in zip(corpus_completion_receipt_bytes, current, strict=True):
        expected = _corpus_completion_bytes(
            stage_plan_bytes=stage_plan_bytes,
            generator_source_bytes=generator_source_bytes,
            claim_bytes=claim_raw,
            invocation_receipt_bytes=invocation_raw,
            generator_output_bytes_by_relative_path=outputs,
            corpus_inventory_relative_path=closure.corpus_relative_path,
        )
        if raw != expected:
            raise DgpGenerationBoundaryError(
                "corpus completion receipt order or raw-file edge differs"
            )
        payload = _parse_corpus_completion(raw)
        completion_bindings.append(
            {
                "block_id": closure.corpus.block_id,
                "block_index": closure.corpus.block_index,
                "dgp_corpus_completion_receipt_sha256": payload[
                    "dgp_corpus_completion_receipt_sha256"
                ],
                "file_sha256": _sha256_bytes(raw),
                "path": payload["corpus_completion_path"],
                "phase": closure.corpus.phase.value,
                "size_bytes": len(raw),
                "stage_kind": closure.corpus.stage_kind.value,
            }
        )
    prior_bindings = _prior_bindings(prior)
    output_bindings = _output_bindings(view, outputs)
    completion_intent, completion_pending = _publication_paths(
        view.stage_completion_receipt_path, view.durable_root
    )
    integrity = {
        "exact_seed_shape_and_aggregates_validated": True,
        "future_output_paths_absent": True,
        "generator_uniformity_validated": True,
        "ordered_corpora_validated": True,
        "prior_stage_disjointness_validated": True,
        "row_files_equal_embedded_corpus_rows": True,
    }
    unsigned: dict[str, object] = {
        "protocol": STAGE_COMPLETION_PROTOCOL,
        "schema_version": STAGE_COMPLETION_SCHEMA_VERSION,
        "status": STAGE_COMPLETION_STATUS,
        "source_commit": view.source_commit,
        "experiment_attempt_id": view.experiment_attempt_id,
        "stage_kind": view.stage_kind.value,
        "stage_attempt_id": view.stage_attempt_id,
        "stage_plan_file_sha256": _sha256_bytes(view.raw),
        "stage_plan_sha256": view.stage_plan_sha256,
        "dgp_generation_claim_file_sha256": _sha256_bytes(claim_raw),
        "dgp_generation_claim_sha256": claim["dgp_generation_claim_sha256"],
        "dgp_invocation_receipt_file_sha256": _sha256_bytes(invocation_raw),
        "dgp_invocation_receipt_sha256": invocation["dgp_invocation_receipt_sha256"],
        "dgp_generator_source_sha256": view.generator_source_sha256,
        "generator_output_inventory_sha256": claim["generator_output_inventory_sha256"],
        "future_output_inventory_sha256": claim["future_output_inventory_sha256"],
        "completed_generator_output_bindings": output_bindings,
        "completed_generator_output_inventory_sha256": _sha256_bytes(
            _canonical(output_bindings)
        ),
        "corpus_completion_bindings": completion_bindings,
        "corpus_completion_inventory_sha256": _sha256_bytes(
            _canonical(completion_bindings)
        ),
        "prior_stage_corpus_bindings": prior_bindings,
        "prior_stage_corpus_inventory_sha256": _sha256_bytes(
            _canonical(prior_bindings)
        ),
        "integrity_validation": integrity,
        "stage_completion_receipt_path": view.stage_completion_receipt_path,
        "stage_completion_publication_intent_path": completion_intent,
        "stage_completion_publication_pending_path": completion_pending,
        "registrar_outputs_present": False,
        "stage_manifest_present": False,
        "hidden_registry_contents_validated": False,
        "scorer_reexecution_performed": False,
        **{key: False for key in _AUTHORITY_KEYS},
    }
    if set(unsigned) != _STAGE_COMPLETION_UNSIGNED_KEYS:
        raise DgpGenerationBoundaryError("stage completion builder schema differs")
    return _seal(unsigned, "dgp_completion_receipt_sha256")


def _parse_stage_completion(raw: object) -> dict[str, object]:
    payload = _parse_receipt(
        raw,
        keys=_STAGE_COMPLETION_KEYS,
        unsigned_keys=_STAGE_COMPLETION_UNSIGNED_KEYS,
        protocol=STAGE_COMPLETION_PROTOCOL,
        schema_version=STAGE_COMPLETION_SCHEMA_VERSION,
        status=STAGE_COMPLETION_STATUS,
        digest_key="dgp_completion_receipt_sha256",
        label="DGP stage completion receipt",
    )
    for label, key, keys in (
        (
            "completed generator outputs",
            "completed_generator_output_bindings",
            _OBSERVED_OUTPUT_KEYS,
        ),
        (
            "corpus completion bindings",
            "corpus_completion_bindings",
            _CORPUS_COMPLETION_BINDING_KEYS,
        ),
        (
            "prior corpus bindings",
            "prior_stage_corpus_bindings",
            _PRIOR_CORPUS_BINDING_KEYS,
        ),
    ):
        rows = payload[key]
        if type(rows) is not list:
            raise DgpGenerationBoundaryError(f"stage {label} differ")
        for index, row in enumerate(rows):
            _exact_object(row, keys, f"stage {label}[{index}]")
    integrity = _exact_object(
        payload["integrity_validation"], _INTEGRITY_KEYS, "stage integrity validation"
    )
    if set(integrity.values()) != {True}:
        raise DgpGenerationBoundaryError("stage integrity flags differ")
    for key in (
        "registrar_outputs_present",
        "stage_manifest_present",
        "hidden_registry_contents_validated",
        "scorer_reexecution_performed",
    ):
        if payload[key] is not False:
            raise DgpGenerationBoundaryError(f"stage completion {key} must be false")
    return payload


def validate_dgp_stage_completion_receipt_bytes(
    raw: object,
    *,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    claim_bytes: object,
    invocation_receipt_bytes: object,
    corpus_completion_receipt_bytes: object,
    generator_output_bytes_by_relative_path: object,
    prior_stage_corpus_inventory_bytes: object = (),
) -> DgpStageCompletionValidation:
    """Purely validate the pre-registrar generator-owned stage closure."""

    observed_raw = _raw(raw, "stage_completion_receipt_bytes")
    payload = _parse_stage_completion(observed_raw)
    expected = _stage_completion_bytes(
        stage_plan_bytes=stage_plan_bytes,
        generator_source_bytes=generator_source_bytes,
        claim_bytes=claim_bytes,
        invocation_receipt_bytes=invocation_receipt_bytes,
        corpus_completion_receipt_bytes=corpus_completion_receipt_bytes,
        generator_output_bytes_by_relative_path=(
            generator_output_bytes_by_relative_path
        ),
        prior_stage_corpus_inventory_bytes=prior_stage_corpus_inventory_bytes,
    )
    if observed_raw != expected:
        raise DgpGenerationBoundaryError(
            "DGP stage completion differs from raw-byte reconstruction"
        )
    return DgpStageCompletionValidation(
        stage_kind=str(payload["stage_kind"]),
        corpus_count=len(payload["corpus_completion_bindings"]),
        row_count=sum(
            STAGE_SHAPES[StageKind(str(payload["stage_kind"]))].items_per_phase
            for _ in payload["corpus_completion_bindings"]
        ),
        prior_corpus_count=len(payload["prior_stage_corpus_bindings"]),
        dgp_completion_receipt_sha256=str(payload["dgp_completion_receipt_sha256"]),
    )


def produce_dgp_generation_boundary(
    *,
    root: object,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    generator_output_bytes_by_relative_path: object,
    prior_stage_corpus_inventory_bytes: object = (),
    runtime: object = None,
) -> None:
    """Production is unavailable and fails before input, FS, or runtime access."""

    del (
        root,
        stage_plan_bytes,
        generator_source_bytes,
        generator_output_bytes_by_relative_path,
        prior_stage_corpus_inventory_bytes,
        runtime,
    )
    raise DgpGenerationBoundaryError(
        "production DGP generation-boundary provider is unavailable"
    )


def _test_root(root: object, view: _StagePlanView) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise DgpGenerationBoundaryError("test root must be an absolute pathlib.Path")
    normalized = Path(os.path.normpath(os.fspath(root)))
    if normalized != root or root == Path("/") or root.as_posix() != view.durable_root:
        raise DgpGenerationBoundaryError("test root differs from the stage plan")
    try:
        metadata = os.lstat(root)
    except OSError as exc:
        raise DgpGenerationBoundaryError("test root is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise DgpGenerationBoundaryError("test root is not a private service directory")
    return root


def _root_identity(metadata: os.stat_result) -> _RootIdentity:
    return _RootIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _retain_test_root(root: Path) -> _RetainedTestRoot:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise DgpGenerationBoundaryError("test root retention failed") from exc
    try:
        retained = _root_identity(os.fstat(descriptor))
        path_identity = _root_identity(os.lstat(root))
        if retained != path_identity:
            raise DgpGenerationBoundaryError("test root changed during retention")
        return _RetainedTestRoot(descriptor=descriptor, identity=retained)
    except BaseException:
        os.close(descriptor)
        raise


def _validate_retained_test_root(
    root: Path, retained: _RetainedTestRoot, label: str
) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    fresh = -1
    try:
        descriptor_identity = _root_identity(os.fstat(retained.descriptor))
        path_metadata = os.lstat(root)
        if not stat.S_ISDIR(path_metadata.st_mode):
            raise DgpGenerationBoundaryError(f"test root is not a directory at {label}")
        path_identity = _root_identity(path_metadata)
        fresh = os.open(root, flags)
        fresh_identity = _root_identity(os.fstat(fresh))
    except DgpGenerationBoundaryError:
        raise
    except OSError as exc:
        raise DgpGenerationBoundaryError(
            f"test root revalidation failed at {label}"
        ) from exc
    finally:
        if fresh >= 0:
            os.close(fresh)
    if not (
        descriptor_identity == path_identity == fresh_identity == retained.identity
    ):
        raise DgpGenerationBoundaryError(f"test root identity changed at {label}")


def _freeze_parent_directory_closure(
    root: Path, registered_paths: Sequence[str]
) -> tuple[_FrozenParentDirectory, ...]:
    parents: set[Path] = set()
    for registered in registered_paths:
        current = Path(registered).parent
        if not current.is_relative_to(root):
            raise DgpGenerationBoundaryError("registered parent escapes test root")
        while current != root:
            parents.add(current)
            current = current.parent
    root_device = os.lstat(root).st_dev
    result: list[_FrozenParentDirectory] = []
    for parent in sorted(parents, key=lambda path: (len(path.parts), path.as_posix())):
        try:
            metadata = os.lstat(parent)
        except OSError as exc:
            raise DgpGenerationBoundaryError(
                "registered parent directory is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_dev != root_device
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise DgpGenerationBoundaryError("registered parent directory is unsafe")
        result.append(
            _FrozenParentDirectory(
                path=parent.as_posix(), identity=_root_identity(metadata)
            )
        )
    return tuple(result)


def _validate_parent_directory_closure(
    closure: Sequence[_FrozenParentDirectory], label: str
) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    for parent in closure:
        descriptor = -1
        try:
            path_identity = _root_identity(os.lstat(parent.path))
            descriptor = os.open(parent.path, flags)
            descriptor_identity = _root_identity(os.fstat(descriptor))
        except OSError as exc:
            raise DgpGenerationBoundaryError(
                f"registered parent revalidation failed at {label}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if path_identity != descriptor_identity or path_identity != parent.identity:
            raise DgpGenerationBoundaryError(
                f"registered parent identity changed at {label}"
            )


def _all_registered_paths(view: _StagePlanView) -> tuple[str, ...]:
    paths: list[str] = []
    for final in (
        view.stage_plan_path,
        view.claim_path,
        view.invocation_receipt_path,
        view.stage_completion_receipt_path,
    ):
        paths.extend((final, *_publication_paths(final, view.durable_root)))
    for row in (
        *view.generator_outputs,
        *view.future_outputs,
        *view.corpus_completion_inventory,
    ):
        paths.extend(
            str(row[key])
            for key in ("path", "publication_intent_path", "publication_pending_path")
        )
    if len(paths) != len(set(paths)):
        raise DgpGenerationBoundaryError("test path inventory collides")
    return tuple(paths)


def _prepare_directories(
    root: Path,
    absolute_paths: Sequence[str],
    retained_root: _RetainedTestRoot,
) -> None:
    parent_components: set[tuple[str, ...]] = set()
    for value in absolute_paths:
        path = Path(value)
        if not path.is_relative_to(root):
            raise DgpGenerationBoundaryError("test artifact path escapes root")
        relative = path.relative_to(root)
        parent_components.add(relative.parent.parts)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    for components in sorted(parent_components, key=lambda item: (len(item), item)):
        current = os.dup(retained_root.descriptor)
        try:
            for component in components:
                try:
                    os.mkdir(component, mode=0o755, dir_fd=current)
                except FileExistsError:
                    pass
                next_descriptor = os.open(component, flags, dir_fd=current)
                try:
                    metadata = os.fstat(next_descriptor)
                    if (
                        not stat.S_ISDIR(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                        or metadata.st_dev != retained_root.identity.device
                        or stat.S_IMODE(metadata.st_mode) & 0o022
                    ):
                        raise DgpGenerationBoundaryError(
                            "test artifact parent is unsafe"
                        )
                except BaseException:
                    os.close(next_descriptor)
                    raise
                os.close(current)
                current = next_descriptor
        except DgpGenerationBoundaryError:
            raise
        except OSError as exc:
            raise DgpGenerationBoundaryError(
                "anchored test directory preparation failed"
            ) from exc
        finally:
            os.close(current)


def _assert_absent(paths: Sequence[str], label: str) -> None:
    for value in paths:
        try:
            os.lstat(value)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise DgpGenerationBoundaryError(f"{label} path inspection failed") from exc
        raise DgpGenerationBoundaryError(f"{label} path is already present")


def _publish(
    runtime: _DgpGenerationBoundaryTestRuntime,
    *,
    root: Path,
    relative_path: str,
    raw: bytes,
    retained_root: _RetainedTestRoot,
    parent_closure: Sequence[_FrozenParentDirectory],
) -> atomic_publish.PublishedArtifactObservation:
    _validate_retained_test_root(root, retained_root, "before injected publish")
    _validate_parent_directory_closure(parent_closure, "before injected publish")
    try:
        try:
            observation = runtime.publish(
                root=root, relative_path=relative_path, payload=raw
            )
        except (atomic_publish.AtomicPublicationError, FileExistsError, OSError) as exc:
            raise DgpGenerationBoundaryError("test atomic publication failed") from exc
    finally:
        _validate_retained_test_root(root, retained_root, "after injected publish")
        _validate_parent_directory_closure(parent_closure, "after injected publish")
    if not isinstance(observation, atomic_publish.PublishedArtifactObservation):
        raise DgpGenerationBoundaryError(
            "test publisher returned an invalid observation"
        )
    return observation


def _canonical_read_and_match(
    *,
    root: Path,
    relative_path: str,
    raw: bytes,
    original: atomic_publish.PublishedArtifactObservation,
    retained_root: _RetainedTestRoot,
    parent_closure: Sequence[_FrozenParentDirectory],
) -> None:
    _validate_retained_test_root(root, retained_root, "before canonical read")
    _validate_parent_directory_closure(parent_closure, "before canonical read")
    try:
        canonical_raw, canonical_observation = (
            atomic_publish.read_and_validate_readonly_artifact(
                root=root,
                relative_path=relative_path,
                expected_payload=raw,
            )
        )
    except (atomic_publish.AtomicPublicationError, OSError) as exc:
        raise DgpGenerationBoundaryError(
            "canonical durable-tree revalidation failed"
        ) from exc
    finally:
        _validate_retained_test_root(root, retained_root, "after canonical read")
        _validate_parent_directory_closure(parent_closure, "after canonical read")
    if canonical_raw != raw or canonical_observation != original:
        raise DgpGenerationBoundaryError(
            "canonical durable-tree observation differs from publication"
        )


def _read_and_match(
    runtime: _DgpGenerationBoundaryTestRuntime,
    *,
    root: Path,
    relative_path: str,
    raw: bytes,
    original: atomic_publish.PublishedArtifactObservation,
    retained_root: _RetainedTestRoot,
    parent_closure: Sequence[_FrozenParentDirectory],
) -> None:
    _validate_retained_test_root(root, retained_root, "before injected read")
    _validate_parent_directory_closure(parent_closure, "before injected read")
    try:
        try:
            observed_raw, observation = runtime.read(
                root=root, relative_path=relative_path, expected_payload=raw
            )
        except (atomic_publish.AtomicPublicationError, OSError) as exc:
            raise DgpGenerationBoundaryError("test atomic revalidation failed") from exc
    finally:
        _validate_retained_test_root(root, retained_root, "after injected read")
        _validate_parent_directory_closure(parent_closure, "after injected read")
    if observed_raw != raw or observation != original:
        raise DgpGenerationBoundaryError(
            "test artifact identity changed after initial publication"
        )
    _canonical_read_and_match(
        root=root,
        relative_path=relative_path,
        raw=raw,
        original=original,
        retained_root=retained_root,
        parent_closure=parent_closure,
    )


def _scan_exact_stage_tree(
    *,
    root: Path,
    stage_root: str,
    registered_paths: Sequence[str],
    allowed_files: frozenset[str],
) -> None:
    stage = Path(stage_root)
    allowed_directories = {stage}
    observed_files: set[str] = set()
    for registered in registered_paths:
        current = Path(registered).parent
        while current != root and current.is_relative_to(stage):
            allowed_directories.add(current)
            current = current.parent
    for current, directories, files in os.walk(stage, followlinks=False):
        current_path = Path(current)
        if current_path not in allowed_directories:
            raise DgpGenerationBoundaryError("unexpected DGP boundary directory")
        for name in directories:
            path = current_path / name
            metadata = os.lstat(path)
            if not stat.S_ISDIR(metadata.st_mode) or path not in allowed_directories:
                raise DgpGenerationBoundaryError("unexpected or linked directory")
        for name in files:
            path = current_path / name
            metadata = os.lstat(path)
            relative = path.relative_to(root).as_posix()
            if not stat.S_ISREG(metadata.st_mode) or relative not in allowed_files:
                raise DgpGenerationBoundaryError("unexpected or linked boundary file")
            observed_files.add(relative)
    if observed_files != set(allowed_files):
        raise DgpGenerationBoundaryError(
            "durable boundary file set differs from exact allowed files"
        )


def _execute_dgp_generation_boundary_for_test(
    *,
    root: object,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    generator_output_bytes_by_relative_path: object,
    prior_stage_corpus_inventory_bytes: object = (),
    runtime: _DgpGenerationBoundaryTestRuntime = _DgpGenerationBoundaryTestRuntime(),
    retained_root: _RetainedTestRoot,
) -> _DgpGenerationBoundaryTestArtifacts:
    if not isinstance(runtime, _DgpGenerationBoundaryTestRuntime):
        raise DgpGenerationBoundaryError("test runtime differs")
    view = _parse_stage_plan(stage_plan_bytes)
    source_raw = _generator_source(view, generator_source_bytes)
    outputs = _snapshot_output_bytes(view, generator_output_bytes_by_relative_path)
    current, _ = _validate_stage_corpora(
        view, outputs, prior_stage_corpus_inventory_bytes
    )
    claim_raw = _claim_bytes(
        stage_plan_bytes=view.raw, generator_source_bytes=source_raw
    )
    invocation_raw = _invocation_bytes(
        stage_plan_bytes=view.raw,
        generator_source_bytes=source_raw,
        claim_bytes=claim_raw,
        generator_output_bytes_by_relative_path=outputs,
    )
    corpus_raws = tuple(
        _corpus_completion_bytes(
            stage_plan_bytes=view.raw,
            generator_source_bytes=source_raw,
            claim_bytes=claim_raw,
            invocation_receipt_bytes=invocation_raw,
            generator_output_bytes_by_relative_path=outputs,
            corpus_inventory_relative_path=closure.corpus_relative_path,
        )
        for closure in current
    )
    completion_raw = _stage_completion_bytes(
        stage_plan_bytes=view.raw,
        generator_source_bytes=source_raw,
        claim_bytes=claim_raw,
        invocation_receipt_bytes=invocation_raw,
        corpus_completion_receipt_bytes=corpus_raws,
        generator_output_bytes_by_relative_path=outputs,
        prior_stage_corpus_inventory_bytes=prior_stage_corpus_inventory_bytes,
    )
    test_root = _test_root(root, view)
    _validate_retained_test_root(test_root, retained_root, "entry")
    all_paths = _all_registered_paths(view)
    _prepare_directories(test_root, all_paths, retained_root)
    parent_closure = _freeze_parent_directory_closure(test_root, all_paths)
    _assert_absent(all_paths, "registered boundary")
    _validate_retained_test_root(
        test_root, retained_root, "after prepare and absence checks"
    )
    _validate_parent_directory_closure(
        parent_closure, "after prepare and absence checks"
    )
    _scan_exact_stage_tree(
        root=test_root,
        stage_root=view.stage_root,
        registered_paths=all_paths,
        allowed_files=frozenset(),
    )

    published: dict[str, tuple[bytes, atomic_publish.PublishedArtifactObservation]] = {}

    def publish_absolute(path: str, raw: bytes) -> None:
        relative = _relative_to(path, view.durable_root, "test publication path")
        observation = _publish(
            runtime,
            root=test_root,
            relative_path=relative,
            raw=raw,
            retained_root=retained_root,
            parent_closure=parent_closure,
        )
        published[relative] = (raw, observation)

    publish_absolute(view.stage_plan_path, view.raw)
    publish_absolute(view.claim_path, claim_raw)
    for closure in current:
        for relative, raw in zip(
            closure.row_relative_paths, closure.row_raws, strict=True
        ):
            publish_absolute(_join(view.dgp_output_root, relative), raw)
        publish_absolute(
            _join(view.dgp_output_root, closure.corpus_relative_path),
            closure.corpus_raw,
        )
    publish_absolute(view.invocation_receipt_path, invocation_raw)
    for receipt, evidence in zip(
        corpus_raws, view.corpus_completion_inventory, strict=True
    ):
        publish_absolute(str(evidence["path"]), receipt)

    _validate_retained_test_root(
        test_root, retained_root, "before stage-completion callback"
    )
    _validate_parent_directory_closure(
        parent_closure, "before stage-completion callback"
    )
    runtime.before_stage_completion()
    _validate_retained_test_root(
        test_root, retained_root, "after stage-completion callback"
    )
    _validate_parent_directory_closure(
        parent_closure, "after stage-completion callback"
    )
    future_paths = tuple(
        str(row[key])
        for row in view.future_outputs
        for key in ("path", "publication_intent_path", "publication_pending_path")
    )
    _assert_absent(future_paths, "future registrar/context/manifest")
    allowed_before = frozenset(
        relative
        for relative in published
        for relative in (
            relative,
            _relative_to(
                published[relative][1].publication_intent_path,
                view.durable_root,
                "published intent",
            ),
        )
    )
    _scan_exact_stage_tree(
        root=test_root,
        stage_root=view.stage_root,
        registered_paths=all_paths,
        allowed_files=allowed_before,
    )
    for relative, (expected_raw, observation) in published.items():
        _canonical_read_and_match(
            root=test_root,
            relative_path=relative,
            raw=expected_raw,
            original=observation,
            retained_root=retained_root,
            parent_closure=parent_closure,
        )
    publish_absolute(view.stage_completion_receipt_path, completion_raw)
    _validate_retained_test_root(
        test_root, retained_root, "after stage-completion publication"
    )
    _validate_parent_directory_closure(
        parent_closure, "after stage-completion publication"
    )
    _validate_retained_test_root(
        test_root, retained_root, "before final-revalidation callback"
    )
    _validate_parent_directory_closure(
        parent_closure, "before final-revalidation callback"
    )
    runtime.before_final_revalidation()
    _validate_retained_test_root(
        test_root, retained_root, "after final-revalidation callback"
    )
    _validate_parent_directory_closure(
        parent_closure, "after final-revalidation callback"
    )

    allowed_after = frozenset(
        relative
        for relative in published
        for relative in (
            relative,
            _relative_to(
                published[relative][1].publication_intent_path,
                view.durable_root,
                "published intent",
            ),
        )
    )
    _scan_exact_stage_tree(
        root=test_root,
        stage_root=view.stage_root,
        registered_paths=all_paths,
        allowed_files=allowed_after,
    )
    _assert_absent(future_paths, "future registrar/context/manifest")
    for relative, (expected_raw, observation) in published.items():
        _read_and_match(
            runtime,
            root=test_root,
            relative_path=relative,
            raw=expected_raw,
            original=observation,
            retained_root=retained_root,
            parent_closure=parent_closure,
        )

    _scan_exact_stage_tree(
        root=test_root,
        stage_root=view.stage_root,
        registered_paths=all_paths,
        allowed_files=allowed_after,
    )
    for relative, (expected_raw, observation) in published.items():
        _canonical_read_and_match(
            root=test_root,
            relative_path=relative,
            raw=expected_raw,
            original=observation,
            retained_root=retained_root,
            parent_closure=parent_closure,
        )

    validate_dgp_generation_claim_bytes(
        claim_raw,
        stage_plan_bytes=view.raw,
        generator_source_bytes=source_raw,
    )
    validate_dgp_invocation_receipt_bytes(
        invocation_raw,
        stage_plan_bytes=view.raw,
        generator_source_bytes=source_raw,
        claim_bytes=claim_raw,
        generator_output_bytes_by_relative_path=outputs,
    )
    for receipt in corpus_raws:
        validate_dgp_corpus_completion_receipt_bytes(
            receipt,
            stage_plan_bytes=view.raw,
            generator_source_bytes=source_raw,
            claim_bytes=claim_raw,
            invocation_receipt_bytes=invocation_raw,
            generator_output_bytes_by_relative_path=outputs,
        )
    validate_dgp_stage_completion_receipt_bytes(
        completion_raw,
        stage_plan_bytes=view.raw,
        generator_source_bytes=source_raw,
        claim_bytes=claim_raw,
        invocation_receipt_bytes=invocation_raw,
        corpus_completion_receipt_bytes=corpus_raws,
        generator_output_bytes_by_relative_path=outputs,
        prior_stage_corpus_inventory_bytes=prior_stage_corpus_inventory_bytes,
    )
    _validate_retained_test_root(test_root, retained_root, "terminal revalidation")
    _validate_parent_directory_closure(parent_closure, "terminal revalidation")
    return _DgpGenerationBoundaryTestArtifacts(
        claim_bytes=claim_raw,
        invocation_receipt_bytes=invocation_raw,
        corpus_completion_receipt_bytes=corpus_raws,
        stage_completion_receipt_bytes=completion_raw,
    )


def _run_dgp_generation_boundary_for_test(
    *,
    root: object,
    stage_plan_bytes: object,
    generator_source_bytes: object,
    generator_output_bytes_by_relative_path: object,
    prior_stage_corpus_inventory_bytes: object = (),
    runtime: _DgpGenerationBoundaryTestRuntime = _DgpGenerationBoundaryTestRuntime(),
) -> _DgpGenerationBoundaryTestArtifacts:
    """Private atomic byte-injection seam; never executes the generator."""

    view = _parse_stage_plan(stage_plan_bytes)
    test_root = _test_root(root, view)
    retained = _retain_test_root(test_root)
    try:
        return _execute_dgp_generation_boundary_for_test(
            root=test_root,
            stage_plan_bytes=view.raw,
            generator_source_bytes=generator_source_bytes,
            generator_output_bytes_by_relative_path=(
                generator_output_bytes_by_relative_path
            ),
            prior_stage_corpus_inventory_bytes=prior_stage_corpus_inventory_bytes,
            runtime=runtime,
            retained_root=retained,
        )
    finally:
        os.close(retained.descriptor)


__all__ = [
    "CLAIM_PROTOCOL",
    "CORPUS_COMPLETION_PROTOCOL",
    "DgpCorpusCompletionValidation",
    "DgpGenerationBoundaryError",
    "DgpGenerationClaimValidation",
    "DgpInvocationValidation",
    "DgpStageCompletionValidation",
    "INVOCATION_PROTOCOL",
    "PROVIDER_AVAILABLE",
    "STAGE_COMPLETION_PROTOCOL",
    "produce_dgp_generation_boundary",
    "validate_dgp_corpus_completion_receipt_bytes",
    "validate_dgp_generation_claim_bytes",
    "validate_dgp_invocation_receipt_bytes",
    "validate_dgp_stage_completion_receipt_bytes",
]
