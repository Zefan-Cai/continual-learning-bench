"""Outcome-blind DGP and public scoring-context integrity contracts.

This module is intentionally pure.  It performs no filesystem I/O, has no
model/task/scorer access, cannot resolve an opaque scoring-context handle, and
does not accept or return rewards, scores, deltas, or efficacy summaries.

The schemas below make the DGP-disjointness and public-attestation portions of
``COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md`` machine-checkable before
any structured-state model call.  A successful validation means only that
public digest metadata is internally consistent and prospectively disjoint.
It does *not* validate the contents of a hidden registry entry or rescore an
action; those operations remain the responsibility of a sealed runtime and an
independent private validator.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from cohort_closed_loop_structured_commitments import (
    SCORING_CONTEXT_PROTOCOL,
    ValidatedPrecommit,
    validate_precommit_bytes,
)


class DgpContextIntegrityError(ValueError):
    """Raised when an exact DGP/context integrity contract fails closed."""


class StageKind(str, Enum):
    """The only three registered structured-state execution stages."""

    SMOKE = "smoke"
    INTERNAL = "internal"
    CONFIRMATION = "confirmation"


class PhaseKind(str, Enum):
    """The two registered corpora in every execution block."""

    ADAPTATION = "adaptation"
    HELD_OUT = "held_out"


@dataclass(frozen=True, slots=True)
class StageShape:
    blocks: int
    items_per_phase: int


@dataclass(frozen=True, slots=True)
class BlockSeedSpec:
    block_id: str
    block_index: int
    run_seed: int
    adaptation_dgp_seed: int
    held_out_dgp_seed: int


PREREG_DOCUMENT_SHA256 = (
    "d6b1cd92df243a5f2ccfa11ad4613ce5425c6a83ed5abc9337900988a0ea7533"
)
SCHEMA_VERSION = 1
CORPUS_PROTOCOL = "cohort_closed_loop_dgp_corpus_inventory_v1"
ROW_PROTOCOL = "cohort_closed_loop_dgp_row_identity_v1"
AGGREGATE_PROTOCOL = "cohort_closed_loop_dgp_aggregate_v1"
CONTEXT_RECORD_PROTOCOL = "cohort_closed_loop_context_registry_digest_record_v1"
CONTEXT_INVENTORY_PROTOCOL = (
    "cohort_closed_loop_public_context_attestation_inventory_v1"
)
STAGE_MANIFEST_PROTOCOL = "cohort_closed_loop_dgp_context_stage_manifest_v1"
PUBLIC_CONTEXT_IDENTITY_PROTOCOL = "cohort_closed_loop_public_context_identity_v1"

STAGE_SHAPES: Mapping[StageKind, StageShape] = {
    StageKind.SMOKE: StageShape(blocks=1, items_per_phase=5),
    StageKind.INTERNAL: StageShape(blocks=3, items_per_phase=20),
    StageKind.CONFIRMATION: StageShape(blocks=8, items_per_phase=20),
}

# These are protocol constants copied exactly from the preregistration.  Block
# identifiers are the implementation-v1 canonical names for its numbered rows.
EXPECTED_STAGE_SEEDS: Mapping[StageKind, tuple[BlockSeedSpec, ...]] = {
    StageKind.SMOKE: (
        BlockSeedSpec("smoke_block_01", 0, 2026071598, 2026071596, 2026071597),
    ),
    StageKind.INTERNAL: (
        BlockSeedSpec("internal_block_01", 0, 2026071501, 2026071511, 2026071512),
        BlockSeedSpec("internal_block_02", 1, 2026071502, 2026071521, 2026071522),
        BlockSeedSpec("internal_block_03", 2, 2026071503, 2026071531, 2026071532),
    ),
    StageKind.CONFIRMATION: tuple(
        BlockSeedSpec(
            f"confirmation_block_{block_index + 1:02d}",
            block_index,
            2026081001 + block_index,
            2026081101 + block_index,
            2026081201 + block_index,
        )
        for block_index in range(8)
    ),
}

_REQUIRED_PRIOR_STAGES: Mapping[StageKind, tuple[StageKind, ...]] = {
    StageKind.SMOKE: (),
    StageKind.INTERNAL: (StageKind.SMOKE,),
    StageKind.CONFIRMATION: (StageKind.SMOKE, StageKind.INTERNAL),
}

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}\Z")

_ROW_KEYS = frozenset(
    {
        "row_protocol",
        "item_id",
        "instance_index",
        "instance_id",
        "query_sha256",
        "database_sha256",
        "ground_truth_sha256",
        "reference_survival_sha256",
        "schedule_entry_sha256",
        "composite_row_identity_sha256",
    }
)
_CORPUS_UNSIGNED_KEYS = frozenset(
    {
        "corpus_protocol",
        "schema_version",
        "stage_kind",
        "block_id",
        "block_index",
        "phase",
        "run_seed",
        "dgp_seed",
        "item_count",
        "dgp_generator_sha256",
        "dgp_arguments_sha256",
        "cohort_layer_inventory_sha256",
        "rows",
        "aggregate_database_sha256",
        "aggregate_ground_truth_sha256",
        "aggregate_schedule_sha256",
        "aggregate_order_sha256",
        "dgp_sha256",
        "aggregate_corpus_sha256",
    }
)
_CORPUS_KEYS = _CORPUS_UNSIGNED_KEYS | {"corpus_inventory_sha256"}
_PUBLIC_ATTESTATION_KEYS = frozenset(
    {
        "scoring_context_protocol",
        "opaque_handle_sha256",
        "scoring_context_sha256",
        "hidden_registry_entry_sha256",
    }
)
_CONTEXT_RECORD_KEYS = frozenset(
    {
        "context_record_protocol",
        "stage_kind",
        "block_id",
        "block_index",
        "phase",
        "item_id",
        "instance_index",
        "instance_id",
        "query_sha256",
        "scorer_source_sha256",
        "dataset_ground_truth_sha256",
        "reference_survival_sha256",
        "opaque_handle_sha256",
        "hidden_registry_entry_sha256",
        "scoring_context_sha256",
        "public_context_identity_sha256",
    }
)
_CONTEXT_ENTRY_KEYS = frozenset(
    {
        "context_registry_record",
        "public_attestation",
        "scoring_context_attestation_sha256",
    }
)
_CONTEXT_INVENTORY_UNSIGNED_KEYS = frozenset(
    {
        "context_inventory_protocol",
        "schema_version",
        "stage_kind",
        "records",
        "hidden_registry_inventory_sha256",
        "attestation_inventory_sha256",
    }
)
_CONTEXT_INVENTORY_KEYS = _CONTEXT_INVENTORY_UNSIGNED_KEYS | {
    "context_inventory_sha256"
}
_STAGE_MANIFEST_UNSIGNED_KEYS = frozenset(
    {
        "stage_manifest_protocol",
        "schema_version",
        "prereg_document_sha256",
        "stage_kind",
        "prior_stage_manifest_sha256s",
        "corpora",
        "context_attestation_inventory",
    }
)
_STAGE_MANIFEST_KEYS = _STAGE_MANIFEST_UNSIGNED_KEYS | {"stage_manifest_sha256"}
_PRIOR_STAGE_BINDING_KEYS = frozenset(
    {"stage_kind", "stage_manifest_file_sha256"}
)

_PRECOMMIT_CORPUS_INVENTORY_KEYS = (
    "dgp_sha256",
    "schedule_sha256",
    "condition_order_sha256",
    "cohort_layer_inventory_sha256",
)
_CROSS_FAMILY_SHARED_INVENTORY_KEYS = (
    "model_sha256",
    "tokenizer_sha256",
    "environment_sha256",
    "task_sha256",
    "schema_sha256",
    "dgp_sha256",
    "schedule_sha256",
    "condition_order_sha256",
    "cohort_layer_inventory_sha256",
)


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole canonical public JSON encoding used by this module."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DgpContextIntegrityError("value is not canonical-JSON encodable") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _reject_constant(value: str) -> None:
    raise DgpContextIntegrityError(f"non-finite JSON number is forbidden: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DgpContextIntegrityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_canonical_object(raw: object, label: str) -> dict[str, object]:
    if type(raw) is not bytes:
        raise DgpContextIntegrityError(f"{label} must be exact bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DgpContextIntegrityError(f"{label} is not UTF-8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DgpContextIntegrityError(f"{label} is not valid JSON") from exc
    if type(parsed) is not dict:
        raise DgpContextIntegrityError(f"{label} must be a JSON object")
    if canonical_json_bytes(parsed) != raw:
        raise DgpContextIntegrityError(f"{label} bytes are not canonical")
    return parsed


def _exact_keys(value: object, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise DgpContextIntegrityError(f"{label} must be an object")
    keys = frozenset(value)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        raise DgpContextIntegrityError(
            f"{label} keys differ: missing={missing}, extra={extra}"
        )
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DgpContextIntegrityError(f"{label} must be lowercase SHA256")
    return value


def _safe_id(value: object, label: str) -> str:
    if type(value) is not str or _SAFE_ID_RE.fullmatch(value) is None:
        raise DgpContextIntegrityError(f"{label} must be a safe nonempty identifier")
    return value


def _exact_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise DgpContextIntegrityError(f"{label} must be an integer >= {minimum}")
    return value


def _stage_kind(value: object, label: str = "stage_kind") -> StageKind:
    if type(value) is not str:
        raise DgpContextIntegrityError(f"{label} must be a registered string")
    try:
        return StageKind(value)
    except ValueError as exc:
        raise DgpContextIntegrityError(f"{label} is not registered") from exc


def _phase_kind(value: object, label: str = "phase") -> PhaseKind:
    if type(value) is not str:
        raise DgpContextIntegrityError(f"{label} must be a registered string")
    try:
        return PhaseKind(value)
    except ValueError as exc:
        raise DgpContextIntegrityError(f"{label} is not registered") from exc


def _schema_version(value: object, label: str) -> None:
    if type(value) is not int or value != SCHEMA_VERSION:
        raise DgpContextIntegrityError(f"{label} schema version drift")


def _hash_component(component: str, ordered_records: object) -> str:
    return canonical_sha256(
        {
            "aggregate_protocol": AGGREGATE_PROTOCOL,
            "component": component,
            "ordered_records": ordered_records,
        }
    )


def compute_composite_row_identity_sha256(
    *,
    instance_id: str,
    database_sha256: str,
    ground_truth_sha256: str,
    reference_survival_sha256: str,
) -> str:
    """Hash the preregistered four-field composite row identity."""

    return canonical_sha256(
        {
            "instance_id": _safe_id(instance_id, "instance_id"),
            "database_sha256": _sha256(database_sha256, "database_sha256"),
            "ground_truth_sha256": _sha256(
                ground_truth_sha256, "ground_truth_sha256"
            ),
            "reference_survival_sha256": _sha256(
                reference_survival_sha256, "reference_survival_sha256"
            ),
        }
    )


@dataclass(frozen=True, slots=True)
class DgpRowIdentity:
    item_id: int
    instance_index: int
    instance_id: str
    query_sha256: str
    database_sha256: str
    ground_truth_sha256: str
    reference_survival_sha256: str
    schedule_entry_sha256: str
    composite_row_identity_sha256: str

    def to_payload(self) -> dict[str, object]:
        return {
            "row_protocol": ROW_PROTOCOL,
            "item_id": self.item_id,
            "instance_index": self.instance_index,
            "instance_id": self.instance_id,
            "query_sha256": self.query_sha256,
            "database_sha256": self.database_sha256,
            "ground_truth_sha256": self.ground_truth_sha256,
            "reference_survival_sha256": self.reference_survival_sha256,
            "schedule_entry_sha256": self.schedule_entry_sha256,
            "composite_row_identity_sha256": self.composite_row_identity_sha256,
        }


def _load_row(value: object, label: str) -> DgpRowIdentity:
    obj = _exact_keys(value, _ROW_KEYS, label)
    if obj["row_protocol"] != ROW_PROTOCOL:
        raise DgpContextIntegrityError(f"{label} protocol drift")
    item_id = _exact_int(obj["item_id"], f"{label}.item_id", minimum=1)
    instance_index = _exact_int(
        obj["instance_index"], f"{label}.instance_index"
    )
    if instance_index != item_id - 1:
        raise DgpContextIntegrityError(f"{label} index must equal item_id - 1")
    instance_id = _safe_id(obj["instance_id"], f"{label}.instance_id")
    query = _sha256(obj["query_sha256"], f"{label}.query_sha256")
    database = _sha256(obj["database_sha256"], f"{label}.database_sha256")
    ground_truth = _sha256(
        obj["ground_truth_sha256"], f"{label}.ground_truth_sha256"
    )
    reference = _sha256(
        obj["reference_survival_sha256"],
        f"{label}.reference_survival_sha256",
    )
    schedule_entry = _sha256(
        obj["schedule_entry_sha256"], f"{label}.schedule_entry_sha256"
    )
    composite = _sha256(
        obj["composite_row_identity_sha256"],
        f"{label}.composite_row_identity_sha256",
    )
    expected_composite = compute_composite_row_identity_sha256(
        instance_id=instance_id,
        database_sha256=database,
        ground_truth_sha256=ground_truth,
        reference_survival_sha256=reference,
    )
    if composite != expected_composite:
        raise DgpContextIntegrityError(f"{label} composite row digest mismatch")
    return DgpRowIdentity(
        item_id=item_id,
        instance_index=instance_index,
        instance_id=instance_id,
        query_sha256=query,
        database_sha256=database,
        ground_truth_sha256=ground_truth,
        reference_survival_sha256=reference,
        schedule_entry_sha256=schedule_entry,
        composite_row_identity_sha256=composite,
    )


def load_dgp_row_identity(raw: bytes) -> DgpRowIdentity:
    """Strictly load one canonical row-identity byte string."""

    obj = _parse_canonical_object(raw, "DGP row identity")
    return _load_row(obj, "DGP row identity")


def compute_corpus_hashes(
    *,
    stage_kind: StageKind,
    block_id: str,
    block_index: int,
    phase: PhaseKind,
    run_seed: int,
    dgp_seed: int,
    dgp_generator_sha256: str,
    dgp_arguments_sha256: str,
    cohort_layer_inventory_sha256: str,
    rows: Sequence[DgpRowIdentity],
) -> dict[str, str]:
    """Recompute every aggregate and shared precommit digest for a corpus."""

    row_order = [
        {
            "item_id": row.item_id,
            "instance_index": row.instance_index,
            "instance_id": row.instance_id,
            "query_sha256": row.query_sha256,
        }
        for row in rows
    ]
    database_order = [
        {
            "item_id": row.item_id,
            "instance_index": row.instance_index,
            "database_sha256": row.database_sha256,
        }
        for row in rows
    ]
    ground_truth_order = [
        {
            "item_id": row.item_id,
            "instance_index": row.instance_index,
            "ground_truth_sha256": row.ground_truth_sha256,
        }
        for row in rows
    ]
    schedule_order = [
        {
            "item_id": row.item_id,
            "instance_index": row.instance_index,
            "schedule_entry_sha256": row.schedule_entry_sha256,
        }
        for row in rows
    ]
    complete_rows = [row.to_payload() for row in rows]
    aggregate_database = _hash_component("database", database_order)
    aggregate_ground_truth = _hash_component("ground_truth", ground_truth_order)
    aggregate_schedule = _hash_component("schedule", schedule_order)
    aggregate_order = _hash_component("condition_order", row_order)
    dgp_digest = canonical_sha256(
        {
            "aggregate_protocol": AGGREGATE_PROTOCOL,
            "component": "dgp",
            "stage_kind": stage_kind.value,
            "block_id": block_id,
            "block_index": block_index,
            "phase": phase.value,
            "run_seed": run_seed,
            "dgp_seed": dgp_seed,
            "dgp_generator_sha256": dgp_generator_sha256,
            "dgp_arguments_sha256": dgp_arguments_sha256,
            "aggregate_database_sha256": aggregate_database,
            "aggregate_ground_truth_sha256": aggregate_ground_truth,
            "aggregate_schedule_sha256": aggregate_schedule,
            "aggregate_order_sha256": aggregate_order,
        }
    )
    aggregate_corpus = canonical_sha256(
        {
            "aggregate_protocol": AGGREGATE_PROTOCOL,
            "component": "corpus",
            "stage_kind": stage_kind.value,
            "block_id": block_id,
            "block_index": block_index,
            "phase": phase.value,
            "run_seed": run_seed,
            "dgp_seed": dgp_seed,
            "dgp_sha256": dgp_digest,
            "cohort_layer_inventory_sha256": cohort_layer_inventory_sha256,
            "rows": complete_rows,
        }
    )
    return {
        "aggregate_database_sha256": aggregate_database,
        "aggregate_ground_truth_sha256": aggregate_ground_truth,
        "aggregate_schedule_sha256": aggregate_schedule,
        "aggregate_order_sha256": aggregate_order,
        "dgp_sha256": dgp_digest,
        "aggregate_corpus_sha256": aggregate_corpus,
    }


@dataclass(frozen=True, slots=True)
class CorpusInventory:
    stage_kind: StageKind
    block_id: str
    block_index: int
    phase: PhaseKind
    run_seed: int
    dgp_seed: int
    dgp_generator_sha256: str
    dgp_arguments_sha256: str
    cohort_layer_inventory_sha256: str
    rows: tuple[DgpRowIdentity, ...]
    aggregate_database_sha256: str
    aggregate_ground_truth_sha256: str
    aggregate_schedule_sha256: str
    aggregate_order_sha256: str
    dgp_sha256: str
    aggregate_corpus_sha256: str
    corpus_inventory_sha256: str

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "corpus_protocol": CORPUS_PROTOCOL,
            "schema_version": SCHEMA_VERSION,
            "stage_kind": self.stage_kind.value,
            "block_id": self.block_id,
            "block_index": self.block_index,
            "phase": self.phase.value,
            "run_seed": self.run_seed,
            "dgp_seed": self.dgp_seed,
            "item_count": len(self.rows),
            "dgp_generator_sha256": self.dgp_generator_sha256,
            "dgp_arguments_sha256": self.dgp_arguments_sha256,
            "cohort_layer_inventory_sha256": self.cohort_layer_inventory_sha256,
            "rows": [row.to_payload() for row in self.rows],
            "aggregate_database_sha256": self.aggregate_database_sha256,
            "aggregate_ground_truth_sha256": self.aggregate_ground_truth_sha256,
            "aggregate_schedule_sha256": self.aggregate_schedule_sha256,
            "aggregate_order_sha256": self.aggregate_order_sha256,
            "dgp_sha256": self.dgp_sha256,
            "aggregate_corpus_sha256": self.aggregate_corpus_sha256,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self.unsigned_payload()
        payload["corpus_inventory_sha256"] = self.corpus_inventory_sha256
        return payload

    def row_for_item(self, item_id: int) -> DgpRowIdentity:
        if type(item_id) is not int or not 1 <= item_id <= len(self.rows):
            raise DgpContextIntegrityError("item_id is outside this corpus")
        return self.rows[item_id - 1]


def _load_corpus_object(value: object, label: str) -> CorpusInventory:
    obj = _exact_keys(value, _CORPUS_KEYS, label)
    if obj["corpus_protocol"] != CORPUS_PROTOCOL:
        raise DgpContextIntegrityError(f"{label} protocol drift")
    _schema_version(obj["schema_version"], label)
    stage = _stage_kind(obj["stage_kind"], f"{label}.stage_kind")
    block_id = _safe_id(obj["block_id"], f"{label}.block_id")
    block_index = _exact_int(obj["block_index"], f"{label}.block_index")
    phase = _phase_kind(obj["phase"], f"{label}.phase")
    run_seed = _exact_int(obj["run_seed"], f"{label}.run_seed")
    dgp_seed = _exact_int(obj["dgp_seed"], f"{label}.dgp_seed")
    item_count = _exact_int(obj["item_count"], f"{label}.item_count", minimum=1)
    dgp_generator = _sha256(
        obj["dgp_generator_sha256"], f"{label}.dgp_generator_sha256"
    )
    dgp_arguments = _sha256(
        obj["dgp_arguments_sha256"], f"{label}.dgp_arguments_sha256"
    )
    cohort_layers = _sha256(
        obj["cohort_layer_inventory_sha256"],
        f"{label}.cohort_layer_inventory_sha256",
    )
    if type(obj["rows"]) is not list:
        raise DgpContextIntegrityError(f"{label}.rows must be a list")
    rows = tuple(
        _load_row(row, f"{label}.rows[{index}]")
        for index, row in enumerate(obj["rows"])
    )
    expected_n = STAGE_SHAPES[stage].items_per_phase
    if item_count != expected_n or len(rows) != expected_n:
        raise DgpContextIntegrityError(
            f"{label} must contain exactly {expected_n} registered rows"
        )
    expected_positions = tuple(range(1, expected_n + 1))
    if tuple(row.item_id for row in rows) != expected_positions:
        raise DgpContextIntegrityError(f"{label} rows are not in exact item order")
    uniqueness_components: tuple[tuple[str, tuple[object, ...]], ...] = (
        ("instance_id", tuple(row.instance_id for row in rows)),
        ("database", tuple(row.database_sha256 for row in rows)),
        ("ground_truth", tuple(row.ground_truth_sha256 for row in rows)),
        (
            "reference_survival",
            tuple(row.reference_survival_sha256 for row in rows),
        ),
        (
            "composite_row_identity",
            tuple(row.composite_row_identity_sha256 for row in rows),
        ),
    )
    for component, values in uniqueness_components:
        if len(set(values)) != len(values):
            raise DgpContextIntegrityError(
                f"{label} contains duplicate {component} identity"
            )
    hashes = compute_corpus_hashes(
        stage_kind=stage,
        block_id=block_id,
        block_index=block_index,
        phase=phase,
        run_seed=run_seed,
        dgp_seed=dgp_seed,
        dgp_generator_sha256=dgp_generator,
        dgp_arguments_sha256=dgp_arguments,
        cohort_layer_inventory_sha256=cohort_layers,
        rows=rows,
    )
    for key, expected in hashes.items():
        actual = _sha256(obj[key], f"{label}.{key}")
        if actual != expected:
            raise DgpContextIntegrityError(f"{label}.{key} mismatch")
    unsigned = {key: obj[key] for key in _CORPUS_UNSIGNED_KEYS}
    inventory_digest = _sha256(
        obj["corpus_inventory_sha256"], f"{label}.corpus_inventory_sha256"
    )
    if inventory_digest != canonical_sha256(unsigned):
        raise DgpContextIntegrityError(f"{label} self digest mismatch")
    return CorpusInventory(
        stage_kind=stage,
        block_id=block_id,
        block_index=block_index,
        phase=phase,
        run_seed=run_seed,
        dgp_seed=dgp_seed,
        dgp_generator_sha256=dgp_generator,
        dgp_arguments_sha256=dgp_arguments,
        cohort_layer_inventory_sha256=cohort_layers,
        rows=rows,
        aggregate_database_sha256=hashes["aggregate_database_sha256"],
        aggregate_ground_truth_sha256=hashes["aggregate_ground_truth_sha256"],
        aggregate_schedule_sha256=hashes["aggregate_schedule_sha256"],
        aggregate_order_sha256=hashes["aggregate_order_sha256"],
        dgp_sha256=hashes["dgp_sha256"],
        aggregate_corpus_sha256=hashes["aggregate_corpus_sha256"],
        corpus_inventory_sha256=inventory_digest,
    )


def load_corpus_inventory(raw: bytes) -> CorpusInventory:
    """Strictly load one canonical corpus-inventory byte string."""

    return _load_corpus_object(_parse_canonical_object(raw, "corpus inventory"), "corpus")


@dataclass(frozen=True, slots=True)
class PublicScoringContextAttestation:
    opaque_handle_sha256: str
    scoring_context_sha256: str
    hidden_registry_entry_sha256: str

    def to_payload(self) -> dict[str, str]:
        return {
            "scoring_context_protocol": SCORING_CONTEXT_PROTOCOL,
            "opaque_handle_sha256": self.opaque_handle_sha256,
            "scoring_context_sha256": self.scoring_context_sha256,
            "hidden_registry_entry_sha256": self.hidden_registry_entry_sha256,
        }

    @property
    def file_sha256(self) -> str:
        return canonical_sha256(self.to_payload())


def _load_public_attestation(
    value: object, label: str
) -> PublicScoringContextAttestation:
    obj = _exact_keys(value, _PUBLIC_ATTESTATION_KEYS, label)
    if obj["scoring_context_protocol"] != SCORING_CONTEXT_PROTOCOL:
        raise DgpContextIntegrityError(f"{label} protocol drift")
    return PublicScoringContextAttestation(
        opaque_handle_sha256=_sha256(
            obj["opaque_handle_sha256"], f"{label}.opaque_handle_sha256"
        ),
        scoring_context_sha256=_sha256(
            obj["scoring_context_sha256"], f"{label}.scoring_context_sha256"
        ),
        hidden_registry_entry_sha256=_sha256(
            obj["hidden_registry_entry_sha256"],
            f"{label}.hidden_registry_entry_sha256",
        ),
    )


def load_public_scoring_context_attestation(
    raw: bytes,
) -> PublicScoringContextAttestation:
    """Load the preregistered four-key public attestation exactly."""

    obj = _parse_canonical_object(raw, "public scoring-context attestation")
    return _load_public_attestation(obj, "public scoring-context attestation")


def compute_scoring_context_sha256(
    *,
    scorer_source_sha256: str,
    dataset_ground_truth_sha256: str,
    instance_id: str,
    instance_index: int,
    reference_survival_sha256: str,
) -> str:
    """Rebuild the preregistered context identity from public digest metadata."""

    return canonical_sha256(
        {
            "scoring_context_protocol": SCORING_CONTEXT_PROTOCOL,
            "scorer_source_sha256": _sha256(
                scorer_source_sha256, "scorer_source_sha256"
            ),
            "dataset_ground_truth_sha256": _sha256(
                dataset_ground_truth_sha256, "dataset_ground_truth_sha256"
            ),
            "instance_id": _safe_id(instance_id, "instance_id"),
            "instance_index": _exact_int(instance_index, "instance_index"),
            "reference_survival_sha256": _sha256(
                reference_survival_sha256, "reference_survival_sha256"
            ),
        }
    )


def compute_public_context_identity_sha256(
    *,
    stage_kind: StageKind,
    block_id: str,
    block_index: int,
    phase: PhaseKind,
    item_id: int,
    instance_index: int,
    instance_id: str,
    query_sha256: str,
    opaque_handle_sha256: str,
    hidden_registry_entry_sha256: str,
    scoring_context_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "public_context_identity_protocol": PUBLIC_CONTEXT_IDENTITY_PROTOCOL,
            "stage_kind": stage_kind.value,
            "block_id": block_id,
            "block_index": block_index,
            "phase": phase.value,
            "item_id": item_id,
            "instance_index": instance_index,
            "instance_id": instance_id,
            "query_sha256": query_sha256,
            "opaque_handle_sha256": opaque_handle_sha256,
            "hidden_registry_entry_sha256": hidden_registry_entry_sha256,
            "scoring_context_sha256": scoring_context_sha256,
        }
    )


@dataclass(frozen=True, slots=True)
class ContextRegistryRecord:
    """Public digest record; it intentionally contains no hidden GT contents."""

    stage_kind: StageKind
    block_id: str
    block_index: int
    phase: PhaseKind
    item_id: int
    instance_index: int
    instance_id: str
    query_sha256: str
    scorer_source_sha256: str
    dataset_ground_truth_sha256: str
    reference_survival_sha256: str
    opaque_handle_sha256: str
    hidden_registry_entry_sha256: str
    scoring_context_sha256: str
    public_context_identity_sha256: str

    @property
    def key(self) -> tuple[object, ...]:
        return (
            self.stage_kind.value,
            self.block_id,
            self.block_index,
            self.phase.value,
            self.item_id,
            self.instance_index,
            self.instance_id,
            self.query_sha256,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "context_record_protocol": CONTEXT_RECORD_PROTOCOL,
            "stage_kind": self.stage_kind.value,
            "block_id": self.block_id,
            "block_index": self.block_index,
            "phase": self.phase.value,
            "item_id": self.item_id,
            "instance_index": self.instance_index,
            "instance_id": self.instance_id,
            "query_sha256": self.query_sha256,
            "scorer_source_sha256": self.scorer_source_sha256,
            "dataset_ground_truth_sha256": self.dataset_ground_truth_sha256,
            "reference_survival_sha256": self.reference_survival_sha256,
            "opaque_handle_sha256": self.opaque_handle_sha256,
            "hidden_registry_entry_sha256": self.hidden_registry_entry_sha256,
            "scoring_context_sha256": self.scoring_context_sha256,
            "public_context_identity_sha256": self.public_context_identity_sha256,
        }


def _load_context_record(value: object, label: str) -> ContextRegistryRecord:
    obj = _exact_keys(value, _CONTEXT_RECORD_KEYS, label)
    if obj["context_record_protocol"] != CONTEXT_RECORD_PROTOCOL:
        raise DgpContextIntegrityError(f"{label} protocol drift")
    stage = _stage_kind(obj["stage_kind"], f"{label}.stage_kind")
    block_id = _safe_id(obj["block_id"], f"{label}.block_id")
    block_index = _exact_int(obj["block_index"], f"{label}.block_index")
    phase = _phase_kind(obj["phase"], f"{label}.phase")
    item_id = _exact_int(obj["item_id"], f"{label}.item_id", minimum=1)
    instance_index = _exact_int(
        obj["instance_index"], f"{label}.instance_index"
    )
    if instance_index != item_id - 1:
        raise DgpContextIntegrityError(f"{label} index must equal item_id - 1")
    instance_id = _safe_id(obj["instance_id"], f"{label}.instance_id")
    query = _sha256(obj["query_sha256"], f"{label}.query_sha256")
    scorer = _sha256(obj["scorer_source_sha256"], f"{label}.scorer_source_sha256")
    ground_truth = _sha256(
        obj["dataset_ground_truth_sha256"],
        f"{label}.dataset_ground_truth_sha256",
    )
    reference = _sha256(
        obj["reference_survival_sha256"],
        f"{label}.reference_survival_sha256",
    )
    opaque = _sha256(obj["opaque_handle_sha256"], f"{label}.opaque_handle_sha256")
    hidden = _sha256(
        obj["hidden_registry_entry_sha256"],
        f"{label}.hidden_registry_entry_sha256",
    )
    scoring = _sha256(
        obj["scoring_context_sha256"], f"{label}.scoring_context_sha256"
    )
    expected_scoring = compute_scoring_context_sha256(
        scorer_source_sha256=scorer,
        dataset_ground_truth_sha256=ground_truth,
        instance_id=instance_id,
        instance_index=instance_index,
        reference_survival_sha256=reference,
    )
    if scoring != expected_scoring:
        raise DgpContextIntegrityError(f"{label} scoring-context digest mismatch")
    identity = _sha256(
        obj["public_context_identity_sha256"],
        f"{label}.public_context_identity_sha256",
    )
    expected_identity = compute_public_context_identity_sha256(
        stage_kind=stage,
        block_id=block_id,
        block_index=block_index,
        phase=phase,
        item_id=item_id,
        instance_index=instance_index,
        instance_id=instance_id,
        query_sha256=query,
        opaque_handle_sha256=opaque,
        hidden_registry_entry_sha256=hidden,
        scoring_context_sha256=scoring,
    )
    if identity != expected_identity:
        raise DgpContextIntegrityError(f"{label} public context identity mismatch")
    return ContextRegistryRecord(
        stage_kind=stage,
        block_id=block_id,
        block_index=block_index,
        phase=phase,
        item_id=item_id,
        instance_index=instance_index,
        instance_id=instance_id,
        query_sha256=query,
        scorer_source_sha256=scorer,
        dataset_ground_truth_sha256=ground_truth,
        reference_survival_sha256=reference,
        opaque_handle_sha256=opaque,
        hidden_registry_entry_sha256=hidden,
        scoring_context_sha256=scoring,
        public_context_identity_sha256=identity,
    )


def load_context_registry_record(raw: bytes) -> ContextRegistryRecord:
    """Strictly load one public, digest-only context registry record."""

    obj = _parse_canonical_object(raw, "context registry record")
    return _load_context_record(obj, "context registry record")


@dataclass(frozen=True, slots=True)
class ContextAttestationEntry:
    context_registry_record: ContextRegistryRecord
    public_attestation: PublicScoringContextAttestation
    scoring_context_attestation_sha256: str

    @property
    def key(self) -> tuple[object, ...]:
        return self.context_registry_record.key

    def to_payload(self) -> dict[str, object]:
        return {
            "context_registry_record": self.context_registry_record.to_payload(),
            "public_attestation": self.public_attestation.to_payload(),
            "scoring_context_attestation_sha256": (
                self.scoring_context_attestation_sha256
            ),
        }


def _load_context_entry(value: object, label: str) -> ContextAttestationEntry:
    obj = _exact_keys(value, _CONTEXT_ENTRY_KEYS, label)
    record = _load_context_record(
        obj["context_registry_record"], f"{label}.context_registry_record"
    )
    attestation = _load_public_attestation(
        obj["public_attestation"], f"{label}.public_attestation"
    )
    attestation_digest = _sha256(
        obj["scoring_context_attestation_sha256"],
        f"{label}.scoring_context_attestation_sha256",
    )
    if attestation_digest != attestation.file_sha256:
        raise DgpContextIntegrityError(f"{label} attestation file digest mismatch")
    if (
        record.opaque_handle_sha256 != attestation.opaque_handle_sha256
        or record.scoring_context_sha256 != attestation.scoring_context_sha256
        or record.hidden_registry_entry_sha256
        != attestation.hidden_registry_entry_sha256
    ):
        raise DgpContextIntegrityError(f"{label} attestation/record digest swap")
    return ContextAttestationEntry(
        context_registry_record=record,
        public_attestation=attestation,
        scoring_context_attestation_sha256=attestation_digest,
    )


@dataclass(frozen=True, slots=True)
class ContextAttestationInventory:
    stage_kind: StageKind
    records: tuple[ContextAttestationEntry, ...]
    hidden_registry_inventory_sha256: str
    attestation_inventory_sha256: str
    context_inventory_sha256: str

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "context_inventory_protocol": CONTEXT_INVENTORY_PROTOCOL,
            "schema_version": SCHEMA_VERSION,
            "stage_kind": self.stage_kind.value,
            "records": [record.to_payload() for record in self.records],
            "hidden_registry_inventory_sha256": (
                self.hidden_registry_inventory_sha256
            ),
            "attestation_inventory_sha256": self.attestation_inventory_sha256,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self.unsigned_payload()
        payload["context_inventory_sha256"] = self.context_inventory_sha256
        return payload

    def entry_for(
        self,
        *,
        block_id: str,
        phase: PhaseKind,
        item_id: int,
    ) -> ContextAttestationEntry:
        matches = tuple(
            entry
            for entry in self.records
            if entry.context_registry_record.block_id == block_id
            and entry.context_registry_record.phase is phase
            and entry.context_registry_record.item_id == item_id
        )
        if len(matches) != 1:
            raise DgpContextIntegrityError(
                "public context inventory does not have exactly one mapped entry"
            )
        return matches[0]


def _context_inventory_hashes(
    records: Sequence[ContextAttestationEntry],
) -> tuple[str, str]:
    hidden = canonical_sha256(
        {
            "context_inventory_protocol": CONTEXT_INVENTORY_PROTOCOL,
            "component": "hidden_registry_digest_metadata",
            "records": [
                {
                    "public_context_identity_sha256": (
                        entry.context_registry_record.public_context_identity_sha256
                    ),
                    "hidden_registry_entry_sha256": (
                        entry.context_registry_record.hidden_registry_entry_sha256
                    ),
                }
                for entry in records
            ],
        }
    )
    attestations = canonical_sha256(
        {
            "context_inventory_protocol": CONTEXT_INVENTORY_PROTOCOL,
            "component": "public_attestation_files",
            "records": [
                {
                    "public_context_identity_sha256": (
                        entry.context_registry_record.public_context_identity_sha256
                    ),
                    "scoring_context_attestation_sha256": (
                        entry.scoring_context_attestation_sha256
                    ),
                }
                for entry in records
            ],
        }
    )
    return hidden, attestations


def _load_context_inventory_object(
    value: object, label: str
) -> ContextAttestationInventory:
    obj = _exact_keys(value, _CONTEXT_INVENTORY_KEYS, label)
    if obj["context_inventory_protocol"] != CONTEXT_INVENTORY_PROTOCOL:
        raise DgpContextIntegrityError(f"{label} protocol drift")
    _schema_version(obj["schema_version"], label)
    stage = _stage_kind(obj["stage_kind"], f"{label}.stage_kind")
    if type(obj["records"]) is not list:
        raise DgpContextIntegrityError(f"{label}.records must be a list")
    records = tuple(
        _load_context_entry(record, f"{label}.records[{index}]")
        for index, record in enumerate(obj["records"])
    )
    if any(record.context_registry_record.stage_kind is not stage for record in records):
        raise DgpContextIntegrityError(f"{label} contains a different stage")
    keys = tuple(record.key for record in records)
    if len(keys) != len(set(keys)):
        raise DgpContextIntegrityError(f"{label} contains duplicate public contexts")
    public_identities = tuple(
        record.context_registry_record.public_context_identity_sha256
        for record in records
    )
    if len(public_identities) != len(set(public_identities)):
        raise DgpContextIntegrityError(f"{label} reuses a public context identity")
    unique_digest_components = {
        "opaque handle": tuple(
            record.context_registry_record.opaque_handle_sha256 for record in records
        ),
        "hidden registry entry": tuple(
            record.context_registry_record.hidden_registry_entry_sha256
            for record in records
        ),
        "scoring context": tuple(
            record.context_registry_record.scoring_context_sha256
            for record in records
        ),
        "attestation file": tuple(
            record.scoring_context_attestation_sha256 for record in records
        ),
    }
    for component, digests in unique_digest_components.items():
        if len(digests) != len(set(digests)):
            raise DgpContextIntegrityError(f"{label} reuses a {component} digest")
    scorer_sources = {
        record.context_registry_record.scorer_source_sha256 for record in records
    }
    if len(scorer_sources) > 1:
        raise DgpContextIntegrityError(f"{label} has multiple scorer sources")
    hidden, attestations = _context_inventory_hashes(records)
    actual_hidden = _sha256(
        obj["hidden_registry_inventory_sha256"],
        f"{label}.hidden_registry_inventory_sha256",
    )
    actual_attestations = _sha256(
        obj["attestation_inventory_sha256"],
        f"{label}.attestation_inventory_sha256",
    )
    if actual_hidden != hidden:
        raise DgpContextIntegrityError(f"{label} hidden digest inventory mismatch")
    if actual_attestations != attestations:
        raise DgpContextIntegrityError(f"{label} attestation inventory mismatch")
    unsigned = {key: obj[key] for key in _CONTEXT_INVENTORY_UNSIGNED_KEYS}
    self_digest = _sha256(
        obj["context_inventory_sha256"], f"{label}.context_inventory_sha256"
    )
    if self_digest != canonical_sha256(unsigned):
        raise DgpContextIntegrityError(f"{label} self digest mismatch")
    return ContextAttestationInventory(
        stage_kind=stage,
        records=records,
        hidden_registry_inventory_sha256=hidden,
        attestation_inventory_sha256=attestations,
        context_inventory_sha256=self_digest,
    )


def load_context_attestation_inventory(raw: bytes) -> ContextAttestationInventory:
    """Strictly load the complete public context/attestation inventory."""

    obj = _parse_canonical_object(raw, "context attestation inventory")
    return _load_context_inventory_object(obj, "context inventory")


@dataclass(frozen=True, slots=True)
class StageDgpContextManifest:
    stage_kind: StageKind
    prior_stage_manifest_sha256s: tuple[tuple[StageKind, str], ...]
    corpora: tuple[CorpusInventory, ...]
    context_attestation_inventory: ContextAttestationInventory
    stage_manifest_sha256: str

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "stage_manifest_protocol": STAGE_MANIFEST_PROTOCOL,
            "schema_version": SCHEMA_VERSION,
            "prereg_document_sha256": PREREG_DOCUMENT_SHA256,
            "stage_kind": self.stage_kind.value,
            "prior_stage_manifest_sha256s": [
                {
                    "stage_kind": stage_kind.value,
                    "stage_manifest_file_sha256": digest,
                }
                for stage_kind, digest in self.prior_stage_manifest_sha256s
            ],
            "corpora": [corpus.to_payload() for corpus in self.corpora],
            "context_attestation_inventory": (
                self.context_attestation_inventory.to_payload()
            ),
        }

    def to_payload(self) -> dict[str, object]:
        payload = self.unsigned_payload()
        payload["stage_manifest_sha256"] = self.stage_manifest_sha256
        return payload

    def corpus_for(self, *, block_id: str, phase: PhaseKind) -> CorpusInventory:
        matches = tuple(
            corpus
            for corpus in self.corpora
            if corpus.block_id == block_id and corpus.phase is phase
        )
        if len(matches) != 1:
            raise DgpContextIntegrityError(
                "stage manifest does not have exactly one requested corpus"
            )
        return matches[0]


def _expected_corpus_order(stage: StageKind) -> tuple[tuple[str, int, PhaseKind], ...]:
    return tuple(
        (seed.block_id, seed.block_index, phase)
        for seed in EXPECTED_STAGE_SEEDS[stage]
        for phase in (PhaseKind.ADAPTATION, PhaseKind.HELD_OUT)
    )


def _validate_stage_seed_table(
    stage: StageKind, corpora: Sequence[CorpusInventory]
) -> None:
    expected_by_block = {seed.block_id: seed for seed in EXPECTED_STAGE_SEEDS[stage]}
    for corpus in corpora:
        seed = expected_by_block.get(corpus.block_id)
        if seed is None or corpus.block_index != seed.block_index:
            raise DgpContextIntegrityError("stage block identity differs from prereg")
        expected_dgp_seed = (
            seed.adaptation_dgp_seed
            if corpus.phase is PhaseKind.ADAPTATION
            else seed.held_out_dgp_seed
        )
        if corpus.run_seed != seed.run_seed or corpus.dgp_seed != expected_dgp_seed:
            raise DgpContextIntegrityError("stage seed table differs from prereg")


def _expected_context_keys(
    corpora: Sequence[CorpusInventory],
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            corpus.stage_kind.value,
            corpus.block_id,
            corpus.block_index,
            corpus.phase.value,
            row.item_id,
            row.instance_index,
            row.instance_id,
            row.query_sha256,
        )
        for corpus in corpora
        for row in corpus.rows
    )


def _validate_context_coverage(
    corpora: Sequence[CorpusInventory], inventory: ContextAttestationInventory
) -> None:
    expected = _expected_context_keys(corpora)
    actual = tuple(entry.key for entry in inventory.records)
    if actual != expected:
        if set(actual) == set(expected):
            raise DgpContextIntegrityError(
                "public context inventory is reordered relative to corpora"
            )
        raise DgpContextIntegrityError(
            "public context inventory has missing, extra, or swapped rows"
        )
    row_by_key = {
        key: row
        for corpus in corpora
        for row, key in zip(corpus.rows, _expected_context_keys((corpus,)), strict=True)
    }
    for entry in inventory.records:
        row = row_by_key[entry.key]
        record = entry.context_registry_record
        if (
            record.dataset_ground_truth_sha256 != row.ground_truth_sha256
            or record.reference_survival_sha256 != row.reference_survival_sha256
        ):
            raise DgpContextIntegrityError(
                "public context digest record differs from its DGP row"
            )


def _load_prior_stage_bindings(
    value: object, *, current_stage: StageKind, label: str
) -> tuple[tuple[StageKind, str], ...]:
    if type(value) is not list:
        raise DgpContextIntegrityError(f"{label} must be an exact ordered list")
    required = _REQUIRED_PRIOR_STAGES[current_stage]
    if len(value) != len(required):
        raise DgpContextIntegrityError(
            f"{label} must bind exactly {[stage.value for stage in required]}"
        )
    result: list[tuple[StageKind, str]] = []
    for index, (entry_value, expected_stage) in enumerate(zip(value, required, strict=True)):
        entry = _exact_keys(
            entry_value, _PRIOR_STAGE_BINDING_KEYS, f"{label}[{index}]"
        )
        stage = _stage_kind(entry["stage_kind"], f"{label}[{index}].stage_kind")
        digest = _sha256(
            entry["stage_manifest_file_sha256"],
            f"{label}[{index}].stage_manifest_file_sha256",
        )
        if stage is not expected_stage:
            raise DgpContextIntegrityError(f"{label} stage order drift")
        result.append((stage, digest))
    return tuple(result)


def _load_stage_manifest_object(
    value: object, label: str
) -> StageDgpContextManifest:
    obj = _exact_keys(value, _STAGE_MANIFEST_KEYS, label)
    if obj["stage_manifest_protocol"] != STAGE_MANIFEST_PROTOCOL:
        raise DgpContextIntegrityError(f"{label} protocol drift")
    _schema_version(obj["schema_version"], label)
    prereg = _sha256(
        obj["prereg_document_sha256"], f"{label}.prereg_document_sha256"
    )
    if prereg != PREREG_DOCUMENT_SHA256:
        raise DgpContextIntegrityError(f"{label} preregistration digest drift")
    stage = _stage_kind(obj["stage_kind"], f"{label}.stage_kind")
    prior_bindings = _load_prior_stage_bindings(
        obj["prior_stage_manifest_sha256s"],
        current_stage=stage,
        label=f"{label}.prior_stage_manifest_sha256s",
    )
    if type(obj["corpora"]) is not list:
        raise DgpContextIntegrityError(f"{label}.corpora must be a list")
    corpora = tuple(
        _load_corpus_object(corpus, f"{label}.corpora[{index}]")
        for index, corpus in enumerate(obj["corpora"])
    )
    shape = STAGE_SHAPES[stage]
    if len(corpora) != shape.blocks * 2:
        raise DgpContextIntegrityError(
            f"{label} must contain exactly {shape.blocks * 2} corpora"
        )
    if any(corpus.stage_kind is not stage for corpus in corpora):
        raise DgpContextIntegrityError(f"{label} contains a different stage corpus")
    actual_order = tuple(
        (corpus.block_id, corpus.block_index, corpus.phase) for corpus in corpora
    )
    if actual_order != _expected_corpus_order(stage):
        raise DgpContextIntegrityError(f"{label} corpus order or block shape drift")
    _validate_stage_seed_table(stage, corpora)
    generator_digests = {corpus.dgp_generator_sha256 for corpus in corpora}
    if len(generator_digests) != 1:
        raise DgpContextIntegrityError(
            f"{label} corpora do not share one frozen DGP generator"
        )
    context_inventory = _load_context_inventory_object(
        obj["context_attestation_inventory"],
        f"{label}.context_attestation_inventory",
    )
    if context_inventory.stage_kind is not stage:
        raise DgpContextIntegrityError(f"{label} context stage mismatch")
    _validate_context_coverage(corpora, context_inventory)
    unsigned = {key: obj[key] for key in _STAGE_MANIFEST_UNSIGNED_KEYS}
    self_digest = _sha256(
        obj["stage_manifest_sha256"], f"{label}.stage_manifest_sha256"
    )
    if self_digest != canonical_sha256(unsigned):
        raise DgpContextIntegrityError(f"{label} self digest mismatch")
    manifest = StageDgpContextManifest(
        stage_kind=stage,
        prior_stage_manifest_sha256s=prior_bindings,
        corpora=corpora,
        context_attestation_inventory=context_inventory,
        stage_manifest_sha256=self_digest,
    )
    _validate_pairwise_disjoint(corpora)
    return manifest


def load_stage_manifest(raw: bytes) -> StageDgpContextManifest:
    """Strictly load and validate one canonical sealed-stage manifest."""

    obj = _parse_canonical_object(raw, "DGP/context stage manifest")
    return _load_stage_manifest_object(obj, "stage manifest")


def _corpus_identity_sets(corpus: CorpusInventory) -> Mapping[str, frozenset[str]]:
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


def _validate_pairwise_disjoint(corpora: Sequence[CorpusInventory]) -> int:
    comparisons = 0
    aggregate_names = (
        "aggregate_database_sha256",
        "aggregate_ground_truth_sha256",
        "aggregate_schedule_sha256",
        "aggregate_order_sha256",
        "aggregate_corpus_sha256",
    )
    for left_index, left in enumerate(corpora):
        left_sets = _corpus_identity_sets(left)
        for right in corpora[left_index + 1 :]:
            comparisons += 1
            if left.dgp_seed == right.dgp_seed:
                raise DgpContextIntegrityError("DGP seeds collide across corpora")
            same_block = (
                left.stage_kind is right.stage_kind
                and left.block_id == right.block_id
                and left.block_index == right.block_index
            )
            if (left.run_seed == right.run_seed) != same_block:
                raise DgpContextIntegrityError(
                    "run-seed equality does not exactly match one execution block"
                )
            right_sets = _corpus_identity_sets(right)
            for component, left_values in left_sets.items():
                if left_values & right_sets[component]:
                    raise DgpContextIntegrityError(
                        f"cross-corpus {component} collision"
                    )
            for aggregate in aggregate_names:
                if getattr(left, aggregate) == getattr(right, aggregate):
                    raise DgpContextIntegrityError(
                        f"cross-corpus {aggregate} collision"
                    )
    return comparisons


@dataclass(frozen=True, slots=True)
class StageIntegrityRecord:
    """Outcome-free receipt for public stage-integrity validation only."""

    stage_kind: StageKind
    stage_manifest_sha256: str
    prior_stage_manifest_sha256s: tuple[tuple[StageKind, str], ...]
    block_count: int
    corpus_count: int
    row_count: int
    public_context_count: int
    disjoint_pair_count: int
    prereg_seed_table_validated: bool
    public_context_identities_recomputed: bool
    hidden_registry_digest_metadata_bound: bool
    hidden_registry_contents_validated: bool
    scorer_reexecution_performed: bool


def _exact_bytes(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        raise DgpContextIntegrityError(f"{label} must be exact canonical bytes")
    return value


def _exact_bytes_tuple(value: object, label: str) -> tuple[bytes, ...]:
    if type(value) is not tuple:
        raise DgpContextIntegrityError(f"{label} must be an exact tuple of bytes")
    result: list[bytes] = []
    for index, item in enumerate(value):
        result.append(_exact_bytes(item, f"{label}[{index}]"))
    return tuple(result)


def _load_bound_stage_chain(
    *, current_manifest_bytes: bytes, prior_manifest_bytes: tuple[bytes, ...]
) -> tuple[StageDgpContextManifest, tuple[StageDgpContextManifest, ...], tuple[str, ...]]:
    current_raw = _exact_bytes(current_manifest_bytes, "current_manifest_bytes")
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    current = load_stage_manifest(current_raw)
    priors = tuple(load_stage_manifest(raw) for raw in prior_raws)
    required = _REQUIRED_PRIOR_STAGES[current.stage_kind]
    actual = tuple(prior.stage_kind for prior in priors)
    if actual != required:
        raise DgpContextIntegrityError(
            f"required prior stages are {[stage.value for stage in required]}"
        )
    prior_file_digests = tuple(
        hashlib.sha256(raw).hexdigest() for raw in prior_raws
    )
    expected_current_bindings = tuple(zip(required, prior_file_digests, strict=True))
    if current.prior_stage_manifest_sha256s != expected_current_bindings:
        raise DgpContextIntegrityError(
            "current manifest prior-stage file-digest binding mismatch"
        )
    for index, prior in enumerate(priors):
        expected_prior_kinds = _REQUIRED_PRIOR_STAGES[prior.stage_kind]
        expected_prior_digests = prior_file_digests[:index]
        expected_prior_bindings = tuple(
            zip(expected_prior_kinds, expected_prior_digests, strict=True)
        )
        if prior.prior_stage_manifest_sha256s != expected_prior_bindings:
            raise DgpContextIntegrityError(
                "supplied prior manifest does not bind the canonical earlier chain"
            )
    all_file_digests = (*prior_file_digests, hashlib.sha256(current_raw).hexdigest())
    if len(all_file_digests) != len(set(all_file_digests)):
        raise DgpContextIntegrityError("a canonical stage-manifest byte string was reused")
    return current, priors, prior_file_digests


def validate_stage_integrity(
    *,
    current_manifest_bytes: bytes,
    prior_manifest_bytes: tuple[bytes, ...],
) -> StageIntegrityRecord:
    """Validate one exact canonical stage byte string and its bound prior bytes.

    Dataclass objects are deliberately not accepted as trust credentials.
    Internal requires the exact sealed smoke bytes.  Confirmation requires the
    exact sealed smoke and internal bytes, in that order, and the internal bytes
    must themselves bind the supplied smoke file digest.
    """

    current, priors, prior_file_digests = _load_bound_stage_chain(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
    )
    all_manifests = (*priors, current)
    generator_digests = {
        corpus.dgp_generator_sha256
        for manifest in all_manifests
        for corpus in manifest.corpora
    }
    if len(generator_digests) != 1:
        raise DgpContextIntegrityError(
            "current/prior stages do not share one frozen DGP generator"
        )
    all_corpora = tuple(
        corpus for manifest in all_manifests for corpus in manifest.corpora
    )
    comparisons = _validate_pairwise_disjoint(all_corpora)
    shape = STAGE_SHAPES[current.stage_kind]
    return StageIntegrityRecord(
        stage_kind=current.stage_kind,
        stage_manifest_sha256=current.stage_manifest_sha256,
        prior_stage_manifest_sha256s=tuple(
            zip(_REQUIRED_PRIOR_STAGES[current.stage_kind], prior_file_digests, strict=True)
        ),
        block_count=shape.blocks,
        corpus_count=len(current.corpora),
        row_count=sum(len(corpus.rows) for corpus in current.corpora),
        public_context_count=len(current.context_attestation_inventory.records),
        disjoint_pair_count=comparisons,
        prereg_seed_table_validated=True,
        public_context_identities_recomputed=True,
        hidden_registry_digest_metadata_bound=True,
        hidden_registry_contents_validated=False,
        scorer_reexecution_performed=False,
    )


@dataclass(frozen=True, slots=True)
class PrecommitRowIntegrityRecord:
    precommit_sha256: str
    commitment_family: str
    stage_kind: StageKind
    block_id: str
    phase: PhaseKind
    item_id: int
    instance_index: int
    instance_id: str
    query_sha256: str
    corpus_inventory_sha256: str
    context_inventory_sha256: str
    public_context_identity_sha256: str
    scoring_context_sha256: str
    scoring_context_attestation_sha256: str
    hidden_registry_contents_validated: bool
    scorer_reexecution_performed: bool


def _precommit_inventory(precommit: ValidatedPrecommit) -> dict[str, str]:
    inventory = dict(precommit.inventory_sha256)
    if len(inventory) != len(precommit.inventory_sha256):
        raise DgpContextIntegrityError("precommit inventory contains duplicate keys")
    return inventory


def _map_validated_precommit_to_stage(
    precommit: ValidatedPrecommit,
    stage_manifest: StageDgpContextManifest,
) -> PrecommitRowIntegrityRecord:
    try:
        phase = PhaseKind(precommit.commitment_phase)
    except ValueError as exc:  # pragma: no cover - commitment validator owns it
        raise DgpContextIntegrityError("precommit phase is not registered") from exc
    corpus = stage_manifest.corpus_for(block_id=precommit.block_id, phase=phase)
    context_inventory = stage_manifest.context_attestation_inventory
    if precommit.commitment_phase != corpus.phase.value:
        raise DgpContextIntegrityError("precommit/corpus phase mismatch")
    if precommit.block_id != corpus.block_id:
        raise DgpContextIntegrityError("precommit/corpus block mismatch")
    row = corpus.row_for_item(precommit.item_id)
    if (
        precommit.instance_index != row.instance_index
        or precommit.instance_id != row.instance_id
        or precommit.query_sha256 != row.query_sha256
    ):
        raise DgpContextIntegrityError("precommit identity differs from DGP row")
    join = precommit.shared_join_key
    if (
        join.block_id != corpus.block_id
        or join.item_id != row.item_id
        or join.instance_index != row.instance_index
        or join.instance_id != row.instance_id
        or join.query_sha256 != row.query_sha256
    ):
        raise DgpContextIntegrityError("precommit shared join differs from DGP row")
    if context_inventory.stage_kind is not corpus.stage_kind:
        raise DgpContextIntegrityError("context/corpus stage mismatch")
    entry = context_inventory.entry_for(
        block_id=corpus.block_id,
        phase=corpus.phase,
        item_id=row.item_id,
    )
    record = entry.context_registry_record
    if (
        record.block_index != corpus.block_index
        or record.instance_index != row.instance_index
        or record.instance_id != row.instance_id
        or record.query_sha256 != row.query_sha256
        or record.dataset_ground_truth_sha256 != row.ground_truth_sha256
        or record.reference_survival_sha256 != row.reference_survival_sha256
    ):
        raise DgpContextIntegrityError("context record differs from DGP row")
    if (
        precommit.opaque_handle_sha256 != record.opaque_handle_sha256
        or precommit.scoring_context_sha256 != record.scoring_context_sha256
        or precommit.scoring_context_attestation_sha256
        != entry.scoring_context_attestation_sha256
        or join.scoring_context_sha256 != record.scoring_context_sha256
        or join.scoring_context_attestation_sha256
        != entry.scoring_context_attestation_sha256
    ):
        raise DgpContextIntegrityError("precommit context/attestation mismatch")
    inventory = _precommit_inventory(precommit)
    expected_inventory = {
        "dgp_sha256": corpus.dgp_sha256,
        "schedule_sha256": corpus.aggregate_schedule_sha256,
        "condition_order_sha256": corpus.aggregate_order_sha256,
        "cohort_layer_inventory_sha256": corpus.cohort_layer_inventory_sha256,
    }
    for key in _PRECOMMIT_CORPUS_INVENTORY_KEYS:
        if inventory.get(key) != expected_inventory[key]:
            raise DgpContextIntegrityError(
                f"precommit {key} differs from mapped corpus"
            )
    return PrecommitRowIntegrityRecord(
        precommit_sha256=precommit.precommit_sha256,
        commitment_family=precommit.commitment_family,
        stage_kind=corpus.stage_kind,
        block_id=corpus.block_id,
        phase=corpus.phase,
        item_id=row.item_id,
        instance_index=row.instance_index,
        instance_id=row.instance_id,
        query_sha256=row.query_sha256,
        corpus_inventory_sha256=corpus.corpus_inventory_sha256,
        context_inventory_sha256=context_inventory.context_inventory_sha256,
        public_context_identity_sha256=record.public_context_identity_sha256,
        scoring_context_sha256=record.scoring_context_sha256,
        scoring_context_attestation_sha256=(
            entry.scoring_context_attestation_sha256
        ),
        hidden_registry_contents_validated=False,
        scorer_reexecution_performed=False,
    )


def validate_precommit_to_row_mapping(
    *, precommit_bytes: bytes, stage_manifest_bytes: bytes
) -> PrecommitRowIntegrityRecord:
    """Bind exact canonical precommit bytes to one exact canonical stage row."""

    precommit_raw = _exact_bytes(precommit_bytes, "precommit_bytes")
    stage_raw = _exact_bytes(stage_manifest_bytes, "stage_manifest_bytes")
    try:
        precommit = validate_precommit_bytes(precommit_raw)
    except ValueError as exc:
        raise DgpContextIntegrityError("precommit bytes failed exact validation") from exc
    stage_manifest = load_stage_manifest(stage_raw)
    return _map_validated_precommit_to_stage(precommit, stage_manifest)


@dataclass(frozen=True, slots=True)
class CrossFamilyIntegrityRecord:
    structured_precommit_sha256: str
    canonical_online_icl_precommit_sha256: str
    stage_kind: StageKind
    block_id: str
    phase: PhaseKind
    item_id: int
    instance_index: int
    instance_id: str
    query_sha256: str
    scoring_context_sha256: str
    scoring_context_attestation_sha256: str
    shared_inventory_sha256: tuple[tuple[str, str], ...]
    raw_trajectory_or_action_equality_required: bool
    protocol_or_source_equality_required: bool
    hidden_registry_contents_validated: bool
    scorer_reexecution_performed: bool


def validate_cross_family_mapping(
    *,
    left_precommit_bytes: bytes,
    right_precommit_bytes: bytes,
    stage_manifest_bytes: bytes,
) -> CrossFamilyIntegrityRecord:
    """Validate the exact structured/online-ICL shared join.

    Protocol/source hashes and raw trajectory/action fields are deliberately
    *not* compared: the preregistration permits those family-specific values to
    differ.  All listed scientific/environment/DGP inventory fields are exact.
    """

    left_raw = _exact_bytes(left_precommit_bytes, "left_precommit_bytes")
    right_raw = _exact_bytes(right_precommit_bytes, "right_precommit_bytes")
    stage_raw = _exact_bytes(stage_manifest_bytes, "stage_manifest_bytes")
    try:
        left = validate_precommit_bytes(left_raw)
        right = validate_precommit_bytes(right_raw)
    except ValueError as exc:
        raise DgpContextIntegrityError("precommit bytes failed exact validation") from exc
    stage_manifest = load_stage_manifest(stage_raw)
    left_mapping = _map_validated_precommit_to_stage(left, stage_manifest)
    right_mapping = _map_validated_precommit_to_stage(right, stage_manifest)
    by_family = {left.commitment_family: left, right.commitment_family: right}
    if set(by_family) != {"structured", "canonical_online_icl"}:
        raise DgpContextIntegrityError(
            "cross-family mapping requires one structured and one canonical online ICL precommit"
        )
    structured = by_family["structured"]
    canonical = by_family["canonical_online_icl"]
    mapping_by_digest = {
        left_mapping.precommit_sha256: left_mapping,
        right_mapping.precommit_sha256: right_mapping,
    }
    if len(mapping_by_digest) != 2:
        raise DgpContextIntegrityError("cross-family mappings are not distinct")
    for precommit in (structured, canonical):
        mapping = mapping_by_digest.get(precommit.precommit_sha256)
        if mapping is None or mapping.commitment_family != precommit.commitment_family:
            raise DgpContextIntegrityError("mapping does not bind its precommit")
    identity_fields = (
        "commitment_phase",
        "block_id",
        "item_id",
        "instance_index",
        "instance_id",
        "query_sha256",
        "opaque_handle_sha256",
        "scoring_context_sha256",
        "scoring_context_attestation_sha256",
    )
    for field in identity_fields:
        if getattr(structured, field) != getattr(canonical, field):
            raise DgpContextIntegrityError(f"cross-family {field} mismatch")
    for precommit in (structured, canonical):
        mapping = mapping_by_digest[precommit.precommit_sha256]
        if (
            mapping.block_id != precommit.block_id
            or mapping.phase.value != precommit.commitment_phase
            or mapping.item_id != precommit.item_id
            or mapping.instance_index != precommit.instance_index
            or mapping.instance_id != precommit.instance_id
            or mapping.query_sha256 != precommit.query_sha256
            or mapping.scoring_context_sha256 != precommit.scoring_context_sha256
            or mapping.scoring_context_attestation_sha256
            != precommit.scoring_context_attestation_sha256
        ):
            raise DgpContextIntegrityError("mapping identity does not bind its precommit")
    structured_mapping = mapping_by_digest[structured.precommit_sha256]
    canonical_mapping = mapping_by_digest[canonical.precommit_sha256]
    mapping_identity_fields = (
        "stage_kind",
        "block_id",
        "phase",
        "item_id",
        "instance_index",
        "instance_id",
        "query_sha256",
        "corpus_inventory_sha256",
        "context_inventory_sha256",
        "public_context_identity_sha256",
        "scoring_context_sha256",
        "scoring_context_attestation_sha256",
    )
    for field in mapping_identity_fields:
        if getattr(structured_mapping, field) != getattr(canonical_mapping, field):
            raise DgpContextIntegrityError(f"cross-family mapped {field} mismatch")
    structured_inventory = _precommit_inventory(structured)
    canonical_inventory = _precommit_inventory(canonical)
    shared_inventory: list[tuple[str, str]] = []
    for key in _CROSS_FAMILY_SHARED_INVENTORY_KEYS:
        structured_value = structured_inventory.get(key)
        canonical_value = canonical_inventory.get(key)
        if structured_value is None or structured_value != canonical_value:
            raise DgpContextIntegrityError(f"cross-family {key} mismatch")
        shared_inventory.append((key, structured_value))
    return CrossFamilyIntegrityRecord(
        structured_precommit_sha256=structured.precommit_sha256,
        canonical_online_icl_precommit_sha256=canonical.precommit_sha256,
        stage_kind=structured_mapping.stage_kind,
        block_id=structured.block_id,
        phase=PhaseKind(structured.commitment_phase),
        item_id=structured.item_id,
        instance_index=structured.instance_index,
        instance_id=structured.instance_id,
        query_sha256=structured.query_sha256,
        scoring_context_sha256=structured.scoring_context_sha256,
        scoring_context_attestation_sha256=(
            structured.scoring_context_attestation_sha256
        ),
        shared_inventory_sha256=tuple(shared_inventory),
        raw_trajectory_or_action_equality_required=False,
        protocol_or_source_equality_required=False,
        hidden_registry_contents_validated=False,
        scorer_reexecution_performed=False,
    )


def build_corpus_inventory_bytes(
    *,
    stage_kind: StageKind,
    block_id: str,
    block_index: int,
    phase: PhaseKind,
    run_seed: int,
    dgp_seed: int,
    dgp_generator_sha256: str,
    dgp_arguments_sha256: str,
    cohort_layer_inventory_sha256: str,
    rows: Sequence[DgpRowIdentity],
) -> bytes:
    """Pure prospective builder that immediately round-trips its exact schema."""

    hashes = compute_corpus_hashes(
        stage_kind=stage_kind,
        block_id=block_id,
        block_index=block_index,
        phase=phase,
        run_seed=run_seed,
        dgp_seed=dgp_seed,
        dgp_generator_sha256=dgp_generator_sha256,
        dgp_arguments_sha256=dgp_arguments_sha256,
        cohort_layer_inventory_sha256=cohort_layer_inventory_sha256,
        rows=rows,
    )
    unsigned: dict[str, object] = {
        "corpus_protocol": CORPUS_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "stage_kind": stage_kind.value,
        "block_id": block_id,
        "block_index": block_index,
        "phase": phase.value,
        "run_seed": run_seed,
        "dgp_seed": dgp_seed,
        "item_count": len(rows),
        "dgp_generator_sha256": dgp_generator_sha256,
        "dgp_arguments_sha256": dgp_arguments_sha256,
        "cohort_layer_inventory_sha256": cohort_layer_inventory_sha256,
        "rows": [row.to_payload() for row in rows],
        **hashes,
    }
    payload = {**unsigned, "corpus_inventory_sha256": canonical_sha256(unsigned)}
    raw = canonical_json_bytes(payload)
    load_corpus_inventory(raw)
    return raw


def build_context_attestation_inventory_bytes(
    *, stage_kind: StageKind, records: Sequence[ContextAttestationEntry]
) -> bytes:
    """Pure prospective builder for the public digest-only context inventory."""

    record_tuple = tuple(records)
    hidden, attestations = _context_inventory_hashes(record_tuple)
    unsigned: dict[str, object] = {
        "context_inventory_protocol": CONTEXT_INVENTORY_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "stage_kind": stage_kind.value,
        "records": [record.to_payload() for record in record_tuple],
        "hidden_registry_inventory_sha256": hidden,
        "attestation_inventory_sha256": attestations,
    }
    payload = {**unsigned, "context_inventory_sha256": canonical_sha256(unsigned)}
    raw = canonical_json_bytes(payload)
    load_context_attestation_inventory(raw)
    return raw


def build_stage_manifest_bytes(
    *,
    stage_kind: StageKind,
    corpora: Sequence[CorpusInventory],
    context_attestation_inventory: ContextAttestationInventory,
    prior_stage_manifest_bytes: tuple[bytes, ...],
) -> bytes:
    """Build a stage that prospectively binds exact canonical prior bytes."""

    prior_raws = _exact_bytes_tuple(
        prior_stage_manifest_bytes, "prior_stage_manifest_bytes"
    )
    prior_manifests = tuple(load_stage_manifest(raw) for raw in prior_raws)
    required = _REQUIRED_PRIOR_STAGES[stage_kind]
    if tuple(manifest.stage_kind for manifest in prior_manifests) != required:
        raise DgpContextIntegrityError(
            f"builder prior stages must be {[stage.value for stage in required]}"
        )
    prior_file_digests = tuple(
        hashlib.sha256(raw).hexdigest() for raw in prior_raws
    )
    unsigned: dict[str, object] = {
        "stage_manifest_protocol": STAGE_MANIFEST_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "prereg_document_sha256": PREREG_DOCUMENT_SHA256,
        "stage_kind": stage_kind.value,
        "prior_stage_manifest_sha256s": [
            {
                "stage_kind": prior_kind.value,
                "stage_manifest_file_sha256": digest,
            }
            for prior_kind, digest in zip(required, prior_file_digests, strict=True)
        ],
        "corpora": [corpus.to_payload() for corpus in corpora],
        "context_attestation_inventory": context_attestation_inventory.to_payload(),
    }
    payload = {**unsigned, "stage_manifest_sha256": canonical_sha256(unsigned)}
    raw = canonical_json_bytes(payload)
    load_stage_manifest(raw)
    validate_stage_integrity(
        current_manifest_bytes=raw,
        prior_manifest_bytes=prior_raws,
    )
    return raw


def build_context_entry(
    *,
    corpus: CorpusInventory,
    row: DgpRowIdentity,
    scorer_source_sha256: str,
    opaque_handle_sha256: str,
    hidden_registry_entry_sha256: str,
) -> ContextAttestationEntry:
    """Build a public digest record without accepting hidden registry contents."""

    if row not in corpus.rows:
        raise DgpContextIntegrityError("row is not a member of the supplied corpus")
    scoring = compute_scoring_context_sha256(
        scorer_source_sha256=scorer_source_sha256,
        dataset_ground_truth_sha256=row.ground_truth_sha256,
        instance_id=row.instance_id,
        instance_index=row.instance_index,
        reference_survival_sha256=row.reference_survival_sha256,
    )
    identity = compute_public_context_identity_sha256(
        stage_kind=corpus.stage_kind,
        block_id=corpus.block_id,
        block_index=corpus.block_index,
        phase=corpus.phase,
        item_id=row.item_id,
        instance_index=row.instance_index,
        instance_id=row.instance_id,
        query_sha256=row.query_sha256,
        opaque_handle_sha256=opaque_handle_sha256,
        hidden_registry_entry_sha256=hidden_registry_entry_sha256,
        scoring_context_sha256=scoring,
    )
    record = ContextRegistryRecord(
        stage_kind=corpus.stage_kind,
        block_id=corpus.block_id,
        block_index=corpus.block_index,
        phase=corpus.phase,
        item_id=row.item_id,
        instance_index=row.instance_index,
        instance_id=row.instance_id,
        query_sha256=row.query_sha256,
        scorer_source_sha256=_sha256(
            scorer_source_sha256, "scorer_source_sha256"
        ),
        dataset_ground_truth_sha256=row.ground_truth_sha256,
        reference_survival_sha256=row.reference_survival_sha256,
        opaque_handle_sha256=_sha256(opaque_handle_sha256, "opaque_handle_sha256"),
        hidden_registry_entry_sha256=_sha256(
            hidden_registry_entry_sha256, "hidden_registry_entry_sha256"
        ),
        scoring_context_sha256=scoring,
        public_context_identity_sha256=identity,
    )
    attestation = PublicScoringContextAttestation(
        opaque_handle_sha256=record.opaque_handle_sha256,
        scoring_context_sha256=scoring,
        hidden_registry_entry_sha256=record.hidden_registry_entry_sha256,
    )
    entry = ContextAttestationEntry(
        context_registry_record=record,
        public_attestation=attestation,
        scoring_context_attestation_sha256=attestation.file_sha256,
    )
    _load_context_entry(entry.to_payload(), "context entry")
    return entry


def make_dgp_row_identity(
    *,
    item_id: int,
    instance_id: str,
    query_sha256: str,
    database_sha256: str,
    ground_truth_sha256: str,
    reference_survival_sha256: str,
    schedule_entry_sha256: str,
) -> DgpRowIdentity:
    """Construct and validate one exact row identity from digest metadata."""

    composite = compute_composite_row_identity_sha256(
        instance_id=instance_id,
        database_sha256=database_sha256,
        ground_truth_sha256=ground_truth_sha256,
        reference_survival_sha256=reference_survival_sha256,
    )
    row = DgpRowIdentity(
        item_id=item_id,
        instance_index=item_id - 1,
        instance_id=instance_id,
        query_sha256=query_sha256,
        database_sha256=database_sha256,
        ground_truth_sha256=ground_truth_sha256,
        reference_survival_sha256=reference_survival_sha256,
        schedule_entry_sha256=schedule_entry_sha256,
        composite_row_identity_sha256=composite,
    )
    return _load_row(row.to_payload(), "row")


__all__ = [
    "AGGREGATE_PROTOCOL",
    "BlockSeedSpec",
    "CONTEXT_INVENTORY_PROTOCOL",
    "CONTEXT_RECORD_PROTOCOL",
    "CORPUS_PROTOCOL",
    "ContextAttestationEntry",
    "ContextAttestationInventory",
    "ContextRegistryRecord",
    "CorpusInventory",
    "CrossFamilyIntegrityRecord",
    "DgpContextIntegrityError",
    "DgpRowIdentity",
    "EXPECTED_STAGE_SEEDS",
    "PREREG_DOCUMENT_SHA256",
    "PhaseKind",
    "PrecommitRowIntegrityRecord",
    "PublicScoringContextAttestation",
    "SCHEMA_VERSION",
    "STAGE_MANIFEST_PROTOCOL",
    "STAGE_SHAPES",
    "StageDgpContextManifest",
    "StageIntegrityRecord",
    "StageKind",
    "StageShape",
    "build_context_attestation_inventory_bytes",
    "build_context_entry",
    "build_corpus_inventory_bytes",
    "build_stage_manifest_bytes",
    "canonical_json_bytes",
    "canonical_sha256",
    "compute_composite_row_identity_sha256",
    "compute_corpus_hashes",
    "compute_public_context_identity_sha256",
    "compute_scoring_context_sha256",
    "load_context_attestation_inventory",
    "load_context_registry_record",
    "load_corpus_inventory",
    "load_dgp_row_identity",
    "load_public_scoring_context_attestation",
    "load_stage_manifest",
    "make_dgp_row_identity",
    "validate_cross_family_mapping",
    "validate_precommit_to_row_mapping",
    "validate_stage_integrity",
]
