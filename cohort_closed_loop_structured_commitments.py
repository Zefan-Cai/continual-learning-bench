"""Outcome-blind commitments for the Cohort structured-state protocol.

This module is deliberately narrower than a runner.  It has no model, DGP,
task, hidden-registry resolver, or scorer access.  It only validates and
publishes the public precommit/receipt boundary prospectively specified by
``COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md`` lines 756--1015.

Nothing in this module authorizes formal execution.  A future sealed
``validate_structured_stage_execution`` must additionally bind the real
attestation files; phase, DGP, grid, protocol-seal, unique-row, and cross-family
join inventories; and independently recompute state transitions from receipts
for active, reverse, LR0, rollback, and frozen held-out branches.  Receipt output
paths must likewise be derived and checked by that sealed runner; accepting a
``receipt_path`` here is only a filesystem publication primitive.

The concrete ``implementation_v1`` schema below resolves the preregistration's
``bind at least`` representation before any structured-state model call.  The
mechanism constants remain owned by :mod:`cohort_closed_loop_structured_state`.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import json
import math
import os
import platform
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from cohort_closed_loop_structured_state import (
    CANDIDATE_IDS,
    MAX_OFFICIAL_STATE_ABS,
    RHO,
    STATE_SCALE,
    U,
    StructuredStateProtocolError,
    candidate_probe_states,
    decode_scalar_reward_float_hex,
    is_positive_zero_state,
    semantic_action_sha256,
    state_from_payload,
    state_sha256,
    transform_action,
    validate_state,
)


class StructuredCommitmentError(ValueError):
    """Raised when a public commitment boundary fails closed."""


PRECOMMIT_PROTOCOL = "cohort_closed_loop_structured_commitment_implementation_v1"
SCHEMA_VERSION = 1
SCORING_CONTEXT_PROTOCOL = "cohort_closed_loop_scoring_context_v1"
CANONICAL_SERIALIZER_ID = "utf8_json_sorted_keys_compact_no_nan_v1"
FLOAT_HEX_CODEC_ID = "python_float_hex_fromhex_canonical_v1"
SHARED_RAW_ACTION_PROTOCOL = "cohort_shared_raw_terminal_action_v1"
GENESIS_PRECOMMIT_SHA256 = (
    "6834d252a3659b09bcb751348dd8085df99b1179190adca29ed268f2b8c70bfd"
)
_GENESIS_DOMAIN = (
    b"cohort_closed_loop_structured_commitment_implementation_v1:"
    b"adaptation:block_genesis"
)
if hashlib.sha256(_GENESIS_DOMAIN).hexdigest() != GENESIS_PRECOMMIT_SHA256:
    raise RuntimeError("structured precommit genesis domain digest drift")

REGISTERED_BRANCH_IDS: tuple[str, ...] = (
    "closed_loop_active",
    "closed_loop_lr0",
    "pair_sign_reverse",
    "closed_loop_rollback",
    "canonical_online_icl",
)
CANDIDATE_ACTION_IDS: tuple[str, ...] = tuple(
    f"{row_id}{sign}" for row_id, sign in CANDIDATE_IDS
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}\Z")

_ATTESTATION_KEYS = frozenset(
    {
        "scoring_context_protocol",
        "opaque_handle_sha256",
        "scoring_context_sha256",
        "hidden_registry_entry_sha256",
    }
)
_JOIN_KEYS = frozenset(
    {
        "block_id",
        "item_id",
        "instance_id",
        "instance_index",
        "query_sha256",
        "raw_trace_sha256",
        "raw_semantic_action_sha256",
        "raw_action_bytes_sha256",
        "scoring_context_sha256",
        "scoring_context_attestation_sha256",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "precommit_sha256",
        "shared_join_key",
        "branch_id",
        "item_id",
        "action_role",
        "action_id",
        "semantic_action_sha256",
        "action_bytes_sha256",
        "scoring_context_sha256",
        "scoring_context_attestation_sha256",
        "scalar_reward_float_hex",
    }
)
_INVENTORY_KEYS = frozenset(
    {
        "protocol_sha256",
        "source_sha256",
        "model_sha256",
        "tokenizer_sha256",
        "environment_sha256",
        "task_sha256",
        "schema_sha256",
        "dgp_sha256",
        "schedule_sha256",
        "condition_order_sha256",
        "cohort_layer_inventory_sha256",
    }
)
_BYTE_OBJECT_KEYS = frozenset(
    {"action_bytes_base64", "action_bytes_size", "action_bytes_sha256"}
)
_SHARED_RAW_ACTION_KEYS = frozenset(
    {
        "object_protocol",
        "action_bytes_base64",
        "action_bytes_size",
        "action_bytes_sha256",
        "semantic_action_sha256",
        "shared_raw_action_object_sha256",
    }
)
_SCORING_CONTEXT_KEYS = frozenset(
    {
        "opaque_handle_base64",
        "opaque_handle_size",
        "opaque_handle_sha256",
        "scoring_context_sha256",
        "scoring_context_attestation_sha256",
    }
)
_NUMERICAL_RUNTIME_KEYS = frozenset(
    {
        "canonical_serializer_id",
        "serializer_source_sha256",
        "python_implementation",
        "python_version",
        "float_hex_codec_id",
        "float_radix",
        "float_mant_dig",
        "float_max_exp",
    }
)
_PROBE_DESIGN_KEYS = frozenset({"d_float_hex", "rho_float_hex", "u"})
_INVOCATION_REF_KEYS = frozenset({"branch_id", "action_role", "action_id"})
_INVOCATION_KEYS = frozenset(
    {
        "branch_id",
        "item_id",
        "action_role",
        "action_id",
        "semantic_action_sha256",
        "action_bytes_base64",
        "action_bytes_size",
        "action_bytes_sha256",
    }
)
_PROBE_STATE_KEYS = frozenset({"action_id", "state", "state_sha256"})
_BRANCH_KEYS = frozenset(
    {
        "branch_id",
        "shared_raw_action_object_sha256",
        "state_before",
        "state_before_sha256",
        "official_invocation_ref",
        "candidate_invocation_refs",
        "probe_states",
    }
)
_PRECOMMIT_UNSIGNED_KEYS = frozenset(
    {
        "precommit_protocol",
        "schema_version",
        "commitment_family",
        "commitment_phase",
        "inventory_sha256",
        "block_id",
        "item_id",
        "instance_id",
        "instance_index",
        "query_sha256",
        "raw_trace_sha256",
        "shared_join_key",
        "shared_raw_action",
        "scoring_context",
        "numerical_runtime",
        "probe_design",
        "branch_records",
        "invocations",
        "previous_item_precommit_sha256",
    }
)
_PRECOMMIT_KEYS = _PRECOMMIT_UNSIGNED_KEYS | {"precommit_sha256"}


@dataclass(frozen=True)
class SharedJoinKey:
    """The sole cross-branch join identity registered by the preregistration."""

    block_id: str
    item_id: int
    instance_id: str
    instance_index: int
    query_sha256: str
    raw_trace_sha256: str
    raw_semantic_action_sha256: str
    raw_action_bytes_sha256: str
    scoring_context_sha256: str
    scoring_context_attestation_sha256: str


@dataclass(frozen=True)
class InvocationCommitment:
    """Public identity of exactly one precommitted scorer invocation."""

    branch_id: str
    item_id: int
    action_role: str
    action_id: str
    semantic_action_sha256: str
    action_bytes_sha256: str


@dataclass(frozen=True)
class ValidatedPrecommit:
    """Minimal public view; opaque-handle bytes are intentionally not exposed."""

    precommit_sha256: str
    commitment_family: str
    commitment_phase: str
    block_id: str
    item_id: int
    instance_index: int
    previous_item_precommit_sha256: str
    shared_join_key: SharedJoinKey
    opaque_handle_sha256: str
    scoring_context_sha256: str
    scoring_context_attestation_sha256: str
    invocations: tuple[InvocationCommitment, ...]


@dataclass(frozen=True)
class ValidatedReceiptRequest:
    """A scalar-only receipt request after its one canonical float decode."""

    precommit_sha256: str
    shared_join_key: SharedJoinKey
    branch_id: str
    item_id: int
    action_role: str
    action_id: str
    semantic_action_sha256: str
    action_bytes_sha256: str
    scoring_context_sha256: str
    scoring_context_attestation_sha256: str
    scalar_reward_float_hex: str
    scalar_reward: float


@dataclass(frozen=True)
class PublishedArtifact:
    """Verified identity of a no-overwrite publication."""

    path: Path
    size: int
    sha256: str
    device: int
    inode: int


@dataclass(frozen=True)
class _ValidatedBranchRecord:
    branch_id: str
    invocation_refs: tuple[tuple[str, str, str], ...]
    state_before: tuple[float, ...] | None
    probe_states: tuple[tuple[float, ...], ...]


def canonical_json_bytes(value: object) -> bytes:
    """Serialize the one implementation-v1 canonical public representation."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StructuredCommitmentError("canonical JSON serialization failed") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def implementation_source_sha256() -> str:
    """Hash the exact commitment/serializer implementation source."""

    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def numerical_runtime_identity() -> dict[str, object]:
    """Return the exact serializer and binary64 runtime identity to precommit."""

    return {
        "canonical_serializer_id": CANONICAL_SERIALIZER_ID,
        "serializer_source_sha256": implementation_source_sha256(),
        "python_implementation": sys.implementation.name,
        "python_version": platform.python_version(),
        "float_hex_codec_id": FLOAT_HEX_CODEC_ID,
        "float_radix": sys.float_info.radix,
        "float_mant_dig": sys.float_info.mant_dig,
        "float_max_exp": sys.float_info.max_exp,
    }


def _object_pairs_no_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StructuredCommitmentError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_canonical_json(raw: object, label: str) -> dict[str, object]:
    if type(raw) is not bytes:
        raise StructuredCommitmentError(f"{label} must be immutable UTF-8 bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StructuredCommitmentError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs_no_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                StructuredCommitmentError(
                    f"non-standard JSON constant is forbidden: {token}"
                )
            ),
        )
    except StructuredCommitmentError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StructuredCommitmentError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise StructuredCommitmentError(f"{label} must be one JSON object")
    if raw != canonical_json_bytes(value):
        raise StructuredCommitmentError(f"{label} is not canonical JSON bytes")
    return value


def _require_exact_keys(
    value: object, keys: frozenset[str], label: str
) -> dict[str, object]:
    if type(value) is not dict:
        raise StructuredCommitmentError(f"{label} must be one plain object")
    if len(value) != len(keys) or set(value) != keys:
        raise StructuredCommitmentError(f"{label} has missing or additional fields")
    return value


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise StructuredCommitmentError(f"{label} must be lowercase SHA256 hex")
    return value


def _require_safe_id(value: object, label: str) -> str:
    if type(value) is not str or _SAFE_ID_RE.fullmatch(value) is None:
        raise StructuredCommitmentError(f"{label} is not a sealed scalar identifier")
    return value


def _require_nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise StructuredCommitmentError(f"{label} must be a nonnegative integer")
    return value


def _require_positive_int(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        raise StructuredCommitmentError(f"{label} must be a positive integer")
    return value


def _decode_canonical_base64(value: object, label: str) -> bytes:
    if type(value) is not str or not value:
        raise StructuredCommitmentError(f"{label} must be nonempty padded base64")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StructuredCommitmentError(f"{label} must be ASCII base64") from exc
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StructuredCommitmentError(f"{label} is not valid RFC4648 base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise StructuredCommitmentError(f"{label} is not canonical padded base64")
    return decoded


def encode_action_bytes(raw: object) -> dict[str, object]:
    """Encode identity-bearing bytes as canonical padded RFC4648 base64."""

    if type(raw) is not bytes or not raw:
        raise StructuredCommitmentError("action bytes must be nonempty immutable bytes")
    return {
        "action_bytes_base64": base64.b64encode(raw).decode("ascii"),
        "action_bytes_size": len(raw),
        "action_bytes_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _validate_byte_object(value: object, label: str) -> tuple[dict[str, object], bytes]:
    obj = _require_exact_keys(value, _BYTE_OBJECT_KEYS, label)
    raw = _decode_canonical_base64(
        obj["action_bytes_base64"], f"{label}.action_bytes_base64"
    )
    size = _require_nonnegative_int(
        obj["action_bytes_size"], f"{label}.action_bytes_size"
    )
    digest = _require_sha256(obj["action_bytes_sha256"], f"{label}.action_bytes_sha256")
    if not raw or size != len(raw) or digest != hashlib.sha256(raw).hexdigest():
        raise StructuredCommitmentError(f"{label} byte identity mismatch")
    return obj, raw


def _validate_opaque_handle(context: dict[str, object]) -> str:
    """Hash opaque bytes without parsing or returning their hidden meaning."""

    encoded = context["opaque_handle_base64"]
    raw = _decode_canonical_base64(encoded, "scoring_context.opaque_handle_base64")
    size = _require_nonnegative_int(
        context["opaque_handle_size"], "scoring_context.opaque_handle_size"
    )
    digest = _require_sha256(
        context["opaque_handle_sha256"], "scoring_context.opaque_handle_sha256"
    )
    if not raw or size != len(raw) or hashlib.sha256(raw).hexdigest() != digest:
        raise StructuredCommitmentError("opaque handle byte identity mismatch")
    return digest


def validate_finite_float64_scalar(value: object) -> float:
    """Validate only the pure scorer's scalar return; no scorer object is accepted."""

    if type(value) is not float or not math.isfinite(value):
        raise StructuredCommitmentError("score must be one finite binary64 float")
    return value


def build_scoring_context_attestation(
    *,
    opaque_handle_sha256: str,
    scoring_context_sha256: str,
    hidden_registry_entry_sha256: str,
) -> bytes:
    payload = {
        "scoring_context_protocol": SCORING_CONTEXT_PROTOCOL,
        "opaque_handle_sha256": _require_sha256(
            opaque_handle_sha256, "opaque_handle_sha256"
        ),
        "scoring_context_sha256": _require_sha256(
            scoring_context_sha256, "scoring_context_sha256"
        ),
        "hidden_registry_entry_sha256": _require_sha256(
            hidden_registry_entry_sha256, "hidden_registry_entry_sha256"
        ),
    }
    return canonical_json_bytes(payload)


def validate_scoring_context_attestation(
    raw: object, *, expected_file_sha256: str | None = None
) -> dict[str, str]:
    obj = _require_exact_keys(
        _parse_canonical_json(raw, "scoring context attestation"),
        _ATTESTATION_KEYS,
        "scoring context attestation",
    )
    if obj["scoring_context_protocol"] != SCORING_CONTEXT_PROTOCOL:
        raise StructuredCommitmentError("scoring context protocol drift")
    for key in _ATTESTATION_KEYS - {"scoring_context_protocol"}:
        _require_sha256(obj[key], key)
    if expected_file_sha256 is not None:
        expected = _require_sha256(
            expected_file_sha256, "scoring_context_attestation_sha256"
        )
        if hashlib.sha256(raw).hexdigest() != expected:
            raise StructuredCommitmentError(
                "scoring context attestation digest mismatch"
            )
    return {key: str(obj[key]) for key in sorted(_ATTESTATION_KEYS)}


def _validate_shared_join_key(value: object) -> SharedJoinKey:
    obj = _require_exact_keys(value, _JOIN_KEYS, "shared_join_key")
    return SharedJoinKey(
        block_id=_require_safe_id(obj["block_id"], "shared_join_key.block_id"),
        item_id=_require_positive_int(obj["item_id"], "shared_join_key.item_id"),
        instance_id=_require_safe_id(obj["instance_id"], "shared_join_key.instance_id"),
        instance_index=_require_nonnegative_int(
            obj["instance_index"], "shared_join_key.instance_index"
        ),
        query_sha256=_require_sha256(
            obj["query_sha256"], "shared_join_key.query_sha256"
        ),
        raw_trace_sha256=_require_sha256(
            obj["raw_trace_sha256"], "shared_join_key.raw_trace_sha256"
        ),
        raw_semantic_action_sha256=_require_sha256(
            obj["raw_semantic_action_sha256"],
            "shared_join_key.raw_semantic_action_sha256",
        ),
        raw_action_bytes_sha256=_require_sha256(
            obj["raw_action_bytes_sha256"],
            "shared_join_key.raw_action_bytes_sha256",
        ),
        scoring_context_sha256=_require_sha256(
            obj["scoring_context_sha256"],
            "shared_join_key.scoring_context_sha256",
        ),
        scoring_context_attestation_sha256=_require_sha256(
            obj["scoring_context_attestation_sha256"],
            "shared_join_key.scoring_context_attestation_sha256",
        ),
    )


def _join_object(join: SharedJoinKey) -> dict[str, object]:
    return {
        "block_id": join.block_id,
        "item_id": join.item_id,
        "instance_id": join.instance_id,
        "instance_index": join.instance_index,
        "query_sha256": join.query_sha256,
        "raw_trace_sha256": join.raw_trace_sha256,
        "raw_semantic_action_sha256": join.raw_semantic_action_sha256,
        "raw_action_bytes_sha256": join.raw_action_bytes_sha256,
        "scoring_context_sha256": join.scoring_context_sha256,
        "scoring_context_attestation_sha256": (join.scoring_context_attestation_sha256),
    }


def _validate_inventory(value: object) -> None:
    obj = _require_exact_keys(value, _INVENTORY_KEYS, "inventory_sha256")
    for key in _INVENTORY_KEYS:
        _require_sha256(obj[key], f"inventory_sha256.{key}")


def _validate_numerical_runtime(value: object) -> None:
    obj = _require_exact_keys(value, _NUMERICAL_RUNTIME_KEYS, "numerical_runtime")
    if obj != numerical_runtime_identity():
        raise StructuredCommitmentError(
            "serializer or numerical runtime identity drift"
        )


def _validate_probe_design(value: object) -> None:
    obj = _require_exact_keys(value, _PROBE_DESIGN_KEYS, "probe_design")
    expected = {
        "d_float_hex": [component.hex() for component in STATE_SCALE],
        "rho_float_hex": RHO.hex(),
        "u": [list(row) for row in U],
    }
    if obj != expected:
        raise StructuredCommitmentError("probe design differs from sealed primitives")


def _validate_invocation_ref(value: object, label: str) -> tuple[str, str, str]:
    obj = _require_exact_keys(value, _INVOCATION_REF_KEYS, label)
    branch_id = obj["branch_id"]
    if type(branch_id) is not str or branch_id not in REGISTERED_BRANCH_IDS:
        raise StructuredCommitmentError(f"{label}.branch_id is not registered")
    action_role = obj["action_role"]
    if action_role not in ("official", "candidate"):
        raise StructuredCommitmentError(f"{label}.action_role is not registered")
    action_id = _require_safe_id(obj["action_id"], f"{label}.action_id")
    if action_role == "official" and action_id != "official":
        raise StructuredCommitmentError(
            "official invocation action_id must be official"
        )
    if action_role == "candidate" and action_id not in CANDIDATE_ACTION_IDS:
        raise StructuredCommitmentError(
            "candidate invocation action_id is not registered"
        )
    return branch_id, action_role, action_id


def _validate_invocation(
    value: object, *, expected_item_id: int, label: str
) -> tuple[InvocationCommitment, tuple[str, str, str], bytes]:
    obj = _require_exact_keys(value, _INVOCATION_KEYS, label)
    ref = _validate_invocation_ref(
        {key: obj[key] for key in _INVOCATION_REF_KEYS}, label
    )
    item_id = _require_positive_int(obj["item_id"], f"{label}.item_id")
    if item_id != expected_item_id:
        raise StructuredCommitmentError(f"{label}.item_id differs from precommit")
    byte_obj = {key: obj[key] for key in _BYTE_OBJECT_KEYS}
    _, action_bytes = _validate_byte_object(byte_obj, label)
    semantic_digest = _require_sha256(
        obj["semantic_action_sha256"], f"{label}.semantic_action_sha256"
    )
    try:
        recomputed_semantic = semantic_action_sha256(action_bytes)
    except StructuredStateProtocolError as exc:
        raise StructuredCommitmentError(f"{label} action schema is invalid") from exc
    if semantic_digest != recomputed_semantic:
        raise StructuredCommitmentError(f"{label} semantic action digest mismatch")
    commitment = InvocationCommitment(
        branch_id=ref[0],
        item_id=item_id,
        action_role=ref[1],
        action_id=ref[2],
        semantic_action_sha256=semantic_digest,
        action_bytes_sha256=str(obj["action_bytes_sha256"]),
    )
    return commitment, ref, action_bytes


def _validate_branch_record(
    value: object,
    *,
    shared_raw_object_sha256: str,
    label: str,
) -> _ValidatedBranchRecord:
    obj = _require_exact_keys(value, _BRANCH_KEYS, label)
    branch_id = obj["branch_id"]
    if type(branch_id) is not str or branch_id not in REGISTERED_BRANCH_IDS:
        raise StructuredCommitmentError(f"{label}.branch_id is not registered")
    if obj["shared_raw_action_object_sha256"] != shared_raw_object_sha256:
        raise StructuredCommitmentError(f"{label} raw action reference mismatch")

    official_ref = _validate_invocation_ref(
        obj["official_invocation_ref"], f"{label}.official_invocation_ref"
    )
    if official_ref != (branch_id, "official", "official"):
        raise StructuredCommitmentError(f"{label} official reference mismatch")

    candidate_values = obj["candidate_invocation_refs"]
    if type(candidate_values) is not list:
        raise StructuredCommitmentError(
            f"{label}.candidate_invocation_refs must be a list"
        )
    candidate_refs = [
        _validate_invocation_ref(entry, f"{label}.candidate_invocation_refs[{index}]")
        for index, entry in enumerate(candidate_values)
    ]
    expected_candidate_refs = [
        (branch_id, "candidate", action_id) for action_id in CANDIDATE_ACTION_IDS
    ]
    if candidate_refs not in ([], expected_candidate_refs):
        raise StructuredCommitmentError(
            f"{label} candidates must be absent or the exact sealed order"
        )

    state_value = obj["state_before"]
    state_digest_value = obj["state_before_sha256"]
    probe_values = obj["probe_states"]
    state: tuple[float, ...] | None = None
    recorded_probe_states: list[tuple[float, ...]] = []
    if type(probe_values) is not list:
        raise StructuredCommitmentError(f"{label}.probe_states must be a list")
    if state_value is None or state_digest_value is None:
        if not (state_value is None and state_digest_value is None):
            raise StructuredCommitmentError(f"{label} has a partial null state")
        if candidate_refs or probe_values:
            raise StructuredCommitmentError(
                f"{label} cannot carry probes without a structured state"
            )
    else:
        try:
            state = state_from_payload(state_value)
            state = validate_state(state, max_abs=MAX_OFFICIAL_STATE_ABS)
            expected_state_digest = state_sha256(state)
        except StructuredStateProtocolError as exc:
            raise StructuredCommitmentError(f"{label}.state_before is invalid") from exc
        if (
            _require_sha256(state_digest_value, f"{label}.state_before_sha256")
            != expected_state_digest
        ):
            raise StructuredCommitmentError(f"{label} state digest mismatch")
        if candidate_refs:
            expected_probes = candidate_probe_states(state)
            if len(probe_values) != len(expected_probes):
                raise StructuredCommitmentError(f"{label} probe count mismatch")
            for index, (probe_obj, expected_probe) in enumerate(
                zip(probe_values, expected_probes)
            ):
                record = _require_exact_keys(
                    probe_obj,
                    _PROBE_STATE_KEYS,
                    f"{label}.probe_states[{index}]",
                )
                action_id = CANDIDATE_ACTION_IDS[index]
                if record["action_id"] != action_id:
                    raise StructuredCommitmentError(f"{label} probe order mismatch")
                try:
                    recorded_state = state_from_payload(record["state"])
                except StructuredStateProtocolError as exc:
                    raise StructuredCommitmentError(
                        f"{label} probe state invalid"
                    ) from exc
                if recorded_state != expected_probe[1]:
                    raise StructuredCommitmentError(f"{label} probe state mismatch")
                recorded_probe_states.append(recorded_state)
                expected_digest = state_sha256(recorded_state)
                if (
                    _require_sha256(
                        record["state_sha256"],
                        f"{label}.probe_states[{index}].state_sha256",
                    )
                    != expected_digest
                ):
                    raise StructuredCommitmentError(f"{label} probe digest mismatch")
        elif probe_values:
            raise StructuredCommitmentError(f"{label} has probes without candidates")
    return _ValidatedBranchRecord(
        branch_id=branch_id,
        invocation_refs=tuple([official_ref, *candidate_refs]),
        state_before=state,
        probe_states=tuple(recorded_probe_states),
    )


def _validate_precommit_object(
    obj: object, *, require_digest: bool
) -> ValidatedPrecommit:
    expected_keys = _PRECOMMIT_KEYS if require_digest else _PRECOMMIT_UNSIGNED_KEYS
    payload = _require_exact_keys(obj, expected_keys, "precommit")
    if payload["precommit_protocol"] != PRECOMMIT_PROTOCOL:
        raise StructuredCommitmentError("precommit protocol drift")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
    ):
        raise StructuredCommitmentError("precommit schema version drift")
    commitment_family = payload["commitment_family"]
    if commitment_family not in ("structured", "canonical_online_icl"):
        raise StructuredCommitmentError("precommit commitment_family is not registered")
    commitment_phase = payload["commitment_phase"]
    if commitment_phase not in ("adaptation", "held_out"):
        raise StructuredCommitmentError("precommit commitment_phase is not registered")
    _validate_inventory(payload["inventory_sha256"])

    block_id = _require_safe_id(payload["block_id"], "precommit.block_id")
    item_id = _require_positive_int(payload["item_id"], "precommit.item_id")
    if item_id > 20:
        raise StructuredCommitmentError("precommit.item_id must be in [1,20]")
    instance_id = _require_safe_id(payload["instance_id"], "precommit.instance_id")
    instance_index = _require_nonnegative_int(
        payload["instance_index"], "precommit.instance_index"
    )
    if instance_index != item_id - 1:
        raise StructuredCommitmentError(
            "precommit.instance_index must equal item_id - 1"
        )
    query_sha256 = _require_sha256(payload["query_sha256"], "precommit.query_sha256")
    raw_trace_sha256 = _require_sha256(
        payload["raw_trace_sha256"], "precommit.raw_trace_sha256"
    )
    previous_item_precommit_sha256 = _require_sha256(
        payload["previous_item_precommit_sha256"],
        "precommit.previous_item_precommit_sha256",
    )
    is_adaptation_genesis = commitment_phase == "adaptation" and item_id == 1
    if is_adaptation_genesis:
        if previous_item_precommit_sha256 != GENESIS_PRECOMMIT_SHA256:
            raise StructuredCommitmentError(
                "adaptation item 1 must bind the registered genesis digest"
            )
    elif previous_item_precommit_sha256 == GENESIS_PRECOMMIT_SHA256:
        raise StructuredCommitmentError(
            "genesis digest is forbidden outside adaptation item 1"
        )

    raw_obj = _require_exact_keys(
        payload["shared_raw_action"],
        _SHARED_RAW_ACTION_KEYS,
        "shared_raw_action",
    )
    if raw_obj["object_protocol"] != SHARED_RAW_ACTION_PROTOCOL:
        raise StructuredCommitmentError("shared raw action protocol drift")
    raw_byte_obj = {key: raw_obj[key] for key in _BYTE_OBJECT_KEYS}
    _, raw_action = _validate_byte_object(raw_byte_obj, "shared_raw_action")
    raw_semantic_sha256 = _require_sha256(
        raw_obj["semantic_action_sha256"], "shared_raw_action.semantic_action_sha256"
    )
    try:
        computed_raw_semantic = semantic_action_sha256(raw_action)
    except StructuredStateProtocolError as exc:
        raise StructuredCommitmentError("shared raw action schema is invalid") from exc
    if raw_semantic_sha256 != computed_raw_semantic:
        raise StructuredCommitmentError("shared raw action semantic digest mismatch")
    raw_unsigned = {
        key: raw_obj[key]
        for key in _SHARED_RAW_ACTION_KEYS - {"shared_raw_action_object_sha256"}
    }
    raw_object_digest = _require_sha256(
        raw_obj["shared_raw_action_object_sha256"],
        "shared_raw_action.shared_raw_action_object_sha256",
    )
    if raw_object_digest != canonical_sha256(raw_unsigned):
        raise StructuredCommitmentError("shared raw action object digest mismatch")

    context = _require_exact_keys(
        payload["scoring_context"], _SCORING_CONTEXT_KEYS, "scoring_context"
    )
    opaque_handle_sha256 = _validate_opaque_handle(context)
    scoring_context_sha256 = _require_sha256(
        context["scoring_context_sha256"], "scoring_context.scoring_context_sha256"
    )
    attestation_sha256 = _require_sha256(
        context["scoring_context_attestation_sha256"],
        "scoring_context.scoring_context_attestation_sha256",
    )

    join = _validate_shared_join_key(payload["shared_join_key"])
    expected_join = SharedJoinKey(
        block_id=block_id,
        item_id=item_id,
        instance_id=instance_id,
        instance_index=instance_index,
        query_sha256=query_sha256,
        raw_trace_sha256=raw_trace_sha256,
        raw_semantic_action_sha256=raw_semantic_sha256,
        raw_action_bytes_sha256=str(raw_obj["action_bytes_sha256"]),
        scoring_context_sha256=scoring_context_sha256,
        scoring_context_attestation_sha256=attestation_sha256,
    )
    if join != expected_join:
        raise StructuredCommitmentError(
            "shared join key differs from committed objects"
        )

    _validate_numerical_runtime(payload["numerical_runtime"])
    _validate_probe_design(payload["probe_design"])

    branch_values = payload["branch_records"]
    if type(branch_values) is not list or not branch_values:
        raise StructuredCommitmentError("branch_records must be a nonempty list")
    branch_ids: list[str] = []
    expected_refs: list[tuple[str, str, str]] = []
    validated_branches: list[_ValidatedBranchRecord] = []
    for index, branch_value in enumerate(branch_values):
        branch = _validate_branch_record(
            branch_value,
            shared_raw_object_sha256=raw_object_digest,
            label=f"branch_records[{index}]",
        )
        branch_id = branch.branch_id
        refs = branch.invocation_refs
        if branch_id in branch_ids:
            raise StructuredCommitmentError("duplicate branch record")
        candidate_count = len(refs) - 1
        expected_candidate_count = (
            16
            if commitment_phase == "adaptation"
            and branch_id
            in ("closed_loop_active", "closed_loop_lr0", "pair_sign_reverse")
            else 0
        )
        if candidate_count != expected_candidate_count:
            raise StructuredCommitmentError(
                "branch candidate inventory differs from commitment phase"
            )
        branch_ids.append(branch_id)
        expected_refs.extend(refs)
        validated_branches.append(branch)
    if commitment_family == "canonical_online_icl":
        expected_branch_ids = ["canonical_online_icl"]
    elif commitment_phase == "adaptation":
        expected_branch_ids = [
            "closed_loop_active",
            "closed_loop_lr0",
            "pair_sign_reverse",
        ]
    else:
        expected_branch_ids = [
            "closed_loop_active",
            "closed_loop_lr0",
            "pair_sign_reverse",
            "closed_loop_rollback",
        ]
    if branch_ids != expected_branch_ids:
        raise StructuredCommitmentError(
            "branch records are missing, additional, or not in registered order"
        )

    for branch in validated_branches:
        if commitment_family == "canonical_online_icl":
            if branch.state_before is not None or branch.probe_states:
                raise StructuredCommitmentError(
                    "canonical online ICL must have null state and no probes"
                )
            continue
        if branch.state_before is None:
            raise StructuredCommitmentError(
                "every structured branch must have a nonnull state"
            )
        if branch.branch_id == "closed_loop_lr0" and not is_positive_zero_state(
            branch.state_before
        ):
            raise StructuredCommitmentError("LR0 state must be six positive zeros")
        if branch.branch_id == "closed_loop_rollback":
            if commitment_phase != "held_out":
                raise StructuredCommitmentError(
                    "rollback is registered only for held-out commitments"
                )
            if not is_positive_zero_state(branch.state_before):
                raise StructuredCommitmentError(
                    "rollback held-out state must be six positive zeros"
                )
        if (
            commitment_phase == "adaptation"
            and item_id == 1
            and branch.branch_id
            in ("closed_loop_active", "closed_loop_lr0", "pair_sign_reverse")
            and not is_positive_zero_state(branch.state_before)
        ):
            raise StructuredCommitmentError(
                "every structured adaptation item-1 state must be six positive zeros"
            )

    invocation_values = payload["invocations"]
    if type(invocation_values) is not list or not invocation_values:
        raise StructuredCommitmentError("invocations must be a nonempty list")
    invocations: list[InvocationCommitment] = []
    actual_refs: list[tuple[str, str, str]] = []
    invocation_bytes: list[bytes] = []
    for index, invocation_value in enumerate(invocation_values):
        invocation, ref, action_bytes = _validate_invocation(
            invocation_value,
            expected_item_id=item_id,
            label=f"invocations[{index}]",
        )
        invocations.append(invocation)
        actual_refs.append(ref)
        invocation_bytes.append(action_bytes)
    if len(set(actual_refs)) != len(actual_refs):
        raise StructuredCommitmentError("duplicate committed invocation")
    if actual_refs != expected_refs:
        raise StructuredCommitmentError(
            "invocations do not exactly match branch references and order"
        )

    action_bytes_by_ref = dict(zip(actual_refs, invocation_bytes))
    for branch in validated_branches:
        official_ref = (branch.branch_id, "official", "official")
        if commitment_family == "canonical_online_icl":
            expected_official = raw_action
        else:
            if branch.state_before is None:
                raise AssertionError("structured state validation drift")
            try:
                expected_official = transform_action(raw_action, branch.state_before)
            except StructuredStateProtocolError as exc:
                raise StructuredCommitmentError(
                    f"{branch.branch_id} official transform failed"
                ) from exc
        if action_bytes_by_ref[official_ref] != expected_official:
            raise StructuredCommitmentError(
                f"{branch.branch_id} official action bytes differ from T_x"
            )

        candidate_refs = branch.invocation_refs[1:]
        if len(candidate_refs) != len(branch.probe_states):
            raise StructuredCommitmentError(
                f"{branch.branch_id} candidate/probe inventory mismatch"
            )
        for candidate_ref, probe_state in zip(candidate_refs, branch.probe_states):
            try:
                expected_candidate = transform_action(raw_action, probe_state)
            except StructuredStateProtocolError as exc:
                raise StructuredCommitmentError(
                    f"{branch.branch_id} candidate transform failed"
                ) from exc
            if action_bytes_by_ref[candidate_ref] != expected_candidate:
                raise StructuredCommitmentError(
                    f"{branch.branch_id} candidate action bytes differ from T_x"
                )

    if (
        commitment_family == "structured"
        and commitment_phase == "adaptation"
        and item_id == 1
    ):
        first_item_vectors = [
            tuple(action_bytes_by_ref[ref] for ref in branch.invocation_refs)
            for branch in validated_branches
        ]
        if any(vector[0] != raw_action for vector in first_item_vectors):
            raise StructuredCommitmentError(
                "item-1 official action is not the raw byte sentinel"
            )
        if any(vector != first_item_vectors[0] for vector in first_item_vectors[1:]):
            raise StructuredCommitmentError(
                "item-1 official/candidate action vectors differ across branches"
            )

    if require_digest:
        precommit_sha256 = _require_sha256(
            payload["precommit_sha256"], "precommit.precommit_sha256"
        )
        unsigned = {key: payload[key] for key in _PRECOMMIT_UNSIGNED_KEYS}
        if canonical_sha256(unsigned) != precommit_sha256:
            raise StructuredCommitmentError("precommit self digest mismatch")
    else:
        precommit_sha256 = canonical_sha256(payload)

    return ValidatedPrecommit(
        precommit_sha256=precommit_sha256,
        commitment_family=str(commitment_family),
        commitment_phase=str(commitment_phase),
        block_id=block_id,
        item_id=item_id,
        instance_index=instance_index,
        previous_item_precommit_sha256=previous_item_precommit_sha256,
        shared_join_key=join,
        opaque_handle_sha256=opaque_handle_sha256,
        scoring_context_sha256=scoring_context_sha256,
        scoring_context_attestation_sha256=attestation_sha256,
        invocations=tuple(invocations),
    )


def _validate_attestation_for_precommit(
    precommit: ValidatedPrecommit, scoring_context_attestation_bytes: object
) -> None:
    attestation = validate_scoring_context_attestation(
        scoring_context_attestation_bytes,
        expected_file_sha256=precommit.scoring_context_attestation_sha256,
    )
    if attestation["opaque_handle_sha256"] != precommit.opaque_handle_sha256:
        raise StructuredCommitmentError("attestation opaque handle digest mismatch")
    if attestation["scoring_context_sha256"] != precommit.scoring_context_sha256:
        raise StructuredCommitmentError("attestation scoring context digest mismatch")


def build_precommit_bytes(
    unsigned_payload: object, *, scoring_context_attestation_bytes: object
) -> bytes:
    """Validate schema/context before embedding the canonical self digest."""

    # Snapshot caller-owned nested containers before validation.  Every later
    # validation and digest operation uses only this strict parsed copy, never
    # aliases in the caller's potentially mutable object graph.
    unsigned_snapshot_bytes = canonical_json_bytes(unsigned_payload)
    unsigned_snapshot = _parse_canonical_json(
        unsigned_snapshot_bytes, "unsigned precommit snapshot"
    )
    unsigned = _validate_precommit_object(unsigned_snapshot, require_digest=False)
    _validate_attestation_for_precommit(unsigned, scoring_context_attestation_bytes)
    payload = dict(unsigned_snapshot)
    payload["precommit_sha256"] = canonical_sha256(unsigned_snapshot)
    raw = canonical_json_bytes(payload)
    validate_precommit_bytes(
        raw,
        scoring_context_attestation_bytes=scoring_context_attestation_bytes,
    )
    return raw


def validate_precommit_bytes(
    raw: object, *, scoring_context_attestation_bytes: object | None = None
) -> ValidatedPrecommit:
    obj = _parse_canonical_json(raw, "precommit")
    precommit = _validate_precommit_object(obj, require_digest=True)
    if scoring_context_attestation_bytes is not None:
        _validate_attestation_for_precommit(
            precommit, scoring_context_attestation_bytes
        )
    return precommit


def validate_precommit_parent_link(
    *, current_precommit_bytes: object, parent_precommit_bytes: object
) -> None:
    """Validate the prospective phase-local commitment-chain relationship.

    Adaptation and held-out item IDs are independently one-based positions in
    ``[1,20]``.  Held-out item 1 binds the complete adaptation stage's terminal
    commitment, not genesis.  The stage validator remains responsible for
    proving that the supplied adaptation parent is the sealed stage terminal
    (item 5 in smoke or item 20 in formal/confirmation).
    """

    current = validate_precommit_bytes(current_precommit_bytes)
    parent = validate_precommit_bytes(parent_precommit_bytes)
    if current.block_id != parent.block_id:
        raise StructuredCommitmentError("precommit parent block mismatch")
    if current.commitment_family != parent.commitment_family:
        raise StructuredCommitmentError("precommit parent family mismatch")
    if current.previous_item_precommit_sha256 != parent.precommit_sha256:
        raise StructuredCommitmentError("precommit parent digest mismatch")
    if current.commitment_phase == "adaptation":
        if current.item_id == 1:
            raise StructuredCommitmentError(
                "adaptation item 1 uses genesis and has no precommit parent"
            )
        if (
            parent.commitment_phase != "adaptation"
            or parent.item_id != current.item_id - 1
        ):
            raise StructuredCommitmentError("adaptation precommit chain mismatch")
    elif current.item_id == 1:
        if parent.commitment_phase != "adaptation":
            raise StructuredCommitmentError(
                "held-out item 1 must bind the adaptation phase parent"
            )
    elif parent.commitment_phase != "held_out" or parent.item_id != current.item_id - 1:
        raise StructuredCommitmentError("held-out precommit chain mismatch")


def validate_precommit_digest_sequence(
    *,
    adaptation_precommit_bytes: object,
    heldout_precommit_bytes: object,
    expected_items_per_phase: object,
) -> None:
    """Validate only a smoke/formal two-phase digest and ordering chain.

    Smoke has exactly five items per phase; formal and confirmation have exactly
    twenty.  This closes the held-out-item-1 phase-parent requirement by
    selecting the last member of the supplied adaptation inventory itself.

    Passing this function is never execution authorization.  It does not prove
    the real attestation-file set, DGP/grid/protocol seal, unique rows,
    cross-family joins, receipt provenance, or any state transition.
    """

    if type(expected_items_per_phase) is not int or expected_items_per_phase not in (
        5,
        20,
    ):
        raise StructuredCommitmentError(
            "expected_items_per_phase must be exactly 5 or 20"
        )
    if (
        type(adaptation_precommit_bytes) is not list
        or type(heldout_precommit_bytes) is not list
    ):
        raise StructuredCommitmentError(
            "precommit stage inventories must be plain lists"
        )
    if (
        len(adaptation_precommit_bytes) != expected_items_per_phase
        or len(heldout_precommit_bytes) != expected_items_per_phase
    ):
        raise StructuredCommitmentError("precommit stage inventory length mismatch")

    adaptation = [validate_precommit_bytes(raw) for raw in adaptation_precommit_bytes]
    heldout = [validate_precommit_bytes(raw) for raw in heldout_precommit_bytes]
    anchor = adaptation[0]
    for position, precommit in enumerate(adaptation, start=1):
        if precommit.commitment_phase != "adaptation":
            raise StructuredCommitmentError("adaptation stage contains wrong phase")
        if precommit.item_id != position:
            raise StructuredCommitmentError("adaptation stage item order mismatch")
        if (
            precommit.block_id != anchor.block_id
            or precommit.commitment_family != anchor.commitment_family
        ):
            raise StructuredCommitmentError("adaptation stage identity mismatch")
        if position > 1:
            validate_precommit_parent_link(
                current_precommit_bytes=adaptation_precommit_bytes[position - 1],
                parent_precommit_bytes=adaptation_precommit_bytes[position - 2],
            )
    for position, precommit in enumerate(heldout, start=1):
        if precommit.commitment_phase != "held_out":
            raise StructuredCommitmentError("held-out stage contains wrong phase")
        if precommit.item_id != position:
            raise StructuredCommitmentError("held-out stage item order mismatch")
        if (
            precommit.block_id != anchor.block_id
            or precommit.commitment_family != anchor.commitment_family
        ):
            raise StructuredCommitmentError("held-out stage identity mismatch")
        parent_bytes = (
            adaptation_precommit_bytes[-1]
            if position == 1
            else heldout_precommit_bytes[position - 2]
        )
        validate_precommit_parent_link(
            current_precommit_bytes=heldout_precommit_bytes[position - 1],
            parent_precommit_bytes=parent_bytes,
        )


def validate_receipt_request_bytes(raw: object) -> ValidatedReceiptRequest:
    """Validate an exact request and decode its scalar hex exactly once."""

    obj = _require_exact_keys(
        _parse_canonical_json(raw, "receipt request"),
        _RECEIPT_KEYS,
        "receipt request",
    )
    precommit_sha256 = _require_sha256(
        obj["precommit_sha256"], "receipt.precommit_sha256"
    )
    join = _validate_shared_join_key(obj["shared_join_key"])
    branch_id = obj["branch_id"]
    if type(branch_id) is not str or branch_id not in REGISTERED_BRANCH_IDS:
        raise StructuredCommitmentError("receipt branch_id is not registered")
    item_id = _require_positive_int(obj["item_id"], "receipt.item_id")
    if item_id > 20:
        raise StructuredCommitmentError("receipt.item_id must be in [1,20]")
    if item_id != join.item_id:
        raise StructuredCommitmentError(
            "receipt.item_id differs from shared_join_key.item_id"
        )
    action_role = obj["action_role"]
    if action_role not in ("official", "candidate"):
        raise StructuredCommitmentError("receipt action_role is not registered")
    action_id = _require_safe_id(obj["action_id"], "receipt.action_id")
    if action_role == "official" and action_id != "official":
        raise StructuredCommitmentError("official receipt action_id must be official")
    if action_role == "candidate" and action_id not in CANDIDATE_ACTION_IDS:
        raise StructuredCommitmentError("candidate receipt action_id is not registered")
    semantic_digest = _require_sha256(
        obj["semantic_action_sha256"], "receipt.semantic_action_sha256"
    )
    byte_digest = _require_sha256(
        obj["action_bytes_sha256"], "receipt.action_bytes_sha256"
    )
    context_digest = _require_sha256(
        obj["scoring_context_sha256"], "receipt.scoring_context_sha256"
    )
    attestation_digest = _require_sha256(
        obj["scoring_context_attestation_sha256"],
        "receipt.scoring_context_attestation_sha256",
    )
    if context_digest != join.scoring_context_sha256:
        raise StructuredCommitmentError(
            "receipt context digest differs from shared join key"
        )
    if attestation_digest != join.scoring_context_attestation_sha256:
        raise StructuredCommitmentError(
            "receipt attestation digest differs from shared join key"
        )
    # This is deliberately the only call to the primitive scalar decoder in
    # this request-validation path.
    try:
        scalar = decode_scalar_reward_float_hex(obj["scalar_reward_float_hex"])
    except StructuredStateProtocolError as exc:
        raise StructuredCommitmentError("receipt scalar hex is invalid") from exc
    return ValidatedReceiptRequest(
        precommit_sha256=precommit_sha256,
        shared_join_key=join,
        branch_id=branch_id,
        item_id=item_id,
        action_role=str(action_role),
        action_id=action_id,
        semantic_action_sha256=semantic_digest,
        action_bytes_sha256=byte_digest,
        scoring_context_sha256=context_digest,
        scoring_context_attestation_sha256=attestation_digest,
        scalar_reward_float_hex=str(obj["scalar_reward_float_hex"]),
        scalar_reward=scalar,
    )


def build_scalar_receipt_bytes(
    *,
    precommit_bytes: object,
    request_bytes: object,
    scoring_context_attestation_bytes: object,
    caller_held_invocation_id: object,
    caller_held_scalar_reward: object,
) -> bytes:
    """Join one real caller-held scorer scalar to one immutable invocation."""

    precommit = validate_precommit_bytes(precommit_bytes)
    request = validate_receipt_request_bytes(request_bytes)
    scalar_reward = validate_finite_float64_scalar(caller_held_scalar_reward)
    if scalar_reward.hex() != request.scalar_reward_float_hex:
        raise StructuredCommitmentError(
            "receipt scalar hex differs from caller-held scorer return"
        )
    if (
        type(caller_held_invocation_id) is not tuple
        or len(caller_held_invocation_id) != 4
    ):
        raise StructuredCommitmentError(
            "caller-held invocation ID must be one exact four-scalar tuple"
        )
    if not (
        type(caller_held_invocation_id[0]) is str
        and type(caller_held_invocation_id[1]) is int
        and type(caller_held_invocation_id[2]) is str
        and type(caller_held_invocation_id[3]) is str
    ):
        raise StructuredCommitmentError(
            "caller-held invocation ID fields must be primitive scalars"
        )
    expected_caller_id = (
        request.branch_id,
        request.item_id,
        request.action_role,
        request.action_id,
    )
    if caller_held_invocation_id != expected_caller_id:
        raise StructuredCommitmentError(
            "receipt request differs from the caller-held invocation ID"
        )
    attestation = validate_scoring_context_attestation(
        scoring_context_attestation_bytes,
        expected_file_sha256=precommit.scoring_context_attestation_sha256,
    )
    if attestation["opaque_handle_sha256"] != precommit.opaque_handle_sha256:
        raise StructuredCommitmentError("attestation opaque handle digest mismatch")
    if attestation["scoring_context_sha256"] != precommit.scoring_context_sha256:
        raise StructuredCommitmentError("attestation scoring context digest mismatch")
    if request.precommit_sha256 != precommit.precommit_sha256:
        raise StructuredCommitmentError("receipt precommit digest mismatch")
    if request.shared_join_key != precommit.shared_join_key:
        raise StructuredCommitmentError("receipt shared join key mismatch")
    if request.item_id != precommit.shared_join_key.item_id:
        raise StructuredCommitmentError("receipt item_id mismatch")
    if request.scoring_context_sha256 != precommit.scoring_context_sha256:
        raise StructuredCommitmentError("receipt scoring context digest mismatch")
    if (
        request.scoring_context_attestation_sha256
        != precommit.scoring_context_attestation_sha256
    ):
        raise StructuredCommitmentError("receipt context attestation digest mismatch")

    key = (
        request.branch_id,
        request.item_id,
        request.action_role,
        request.action_id,
    )
    matches = [
        invocation
        for invocation in precommit.invocations
        if (
            invocation.branch_id,
            invocation.item_id,
            invocation.action_role,
            invocation.action_id,
        )
        == key
    ]
    if len(matches) != 1:
        raise StructuredCommitmentError(
            "receipt metadata does not identify exactly one committed invocation"
        )
    invocation = matches[0]
    if request.semantic_action_sha256 != invocation.semantic_action_sha256:
        raise StructuredCommitmentError("receipt semantic action digest mismatch")
    if request.action_bytes_sha256 != invocation.action_bytes_sha256:
        raise StructuredCommitmentError("receipt action byte digest mismatch")
    if type(request_bytes) is not bytes:  # narrowed by request validator
        raise AssertionError("unreachable")
    return request_bytes


def validate_complete_receipt_inventory(
    *,
    precommit_bytes: object,
    receipt_bytes: object,
    scoring_context_attestation_bytes: object,
) -> tuple[ValidatedReceiptRequest, ...]:
    """Validate one exact, complete, registered-order receipt inventory.

    This is the set boundary at which a swapped, duplicate, missing, or
    cross-branch receipt is distinguishable even when two actions are
    semantically identical.  Every scalar is decoded exactly once.
    """

    precommit = validate_precommit_bytes(precommit_bytes)
    _validate_attestation_for_precommit(precommit, scoring_context_attestation_bytes)
    if type(receipt_bytes) is not list:
        raise StructuredCommitmentError("receipt inventory must be one plain list")
    if len(receipt_bytes) != len(precommit.invocations):
        raise StructuredCommitmentError("receipt inventory is missing or additional")

    validated: list[ValidatedReceiptRequest] = []
    seen: set[tuple[str, int, str, str]] = set()
    for index, (raw, invocation) in enumerate(
        zip(receipt_bytes, precommit.invocations)
    ):
        request = validate_receipt_request_bytes(raw)
        key = (
            request.branch_id,
            request.item_id,
            request.action_role,
            request.action_id,
        )
        expected_key = (
            invocation.branch_id,
            invocation.item_id,
            invocation.action_role,
            invocation.action_id,
        )
        if key in seen:
            raise StructuredCommitmentError("duplicate receipt invocation")
        seen.add(key)
        if key != expected_key:
            raise StructuredCommitmentError(
                f"receipt inventory invocation mismatch at index {index}"
            )
        if request.precommit_sha256 != precommit.precommit_sha256:
            raise StructuredCommitmentError("receipt inventory precommit mismatch")
        if request.shared_join_key != precommit.shared_join_key:
            raise StructuredCommitmentError("receipt inventory shared join mismatch")
        if (
            request.scoring_context_sha256 != precommit.scoring_context_sha256
            or request.scoring_context_attestation_sha256
            != precommit.scoring_context_attestation_sha256
        ):
            raise StructuredCommitmentError("receipt inventory context mismatch")
        if (
            request.semantic_action_sha256 != invocation.semantic_action_sha256
            or request.action_bytes_sha256 != invocation.action_bytes_sha256
        ):
            raise StructuredCommitmentError("receipt inventory action mismatch")
        validated.append(request)
    return tuple(validated)


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _file_open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _absolute_parts(path: Path) -> tuple[list[str], str]:
    if not path.is_absolute():
        raise StructuredCommitmentError("publication path must be absolute")
    parts = list(path.parts)
    if not parts or parts[0] != "/" or len(parts) < 2:
        raise StructuredCommitmentError("publication path has no final filename")
    components = parts[1:]
    if any(part in ("", ".", "..") or "/" in part for part in components):
        raise StructuredCommitmentError("publication path contains unsafe components")
    return components[:-1], components[-1]


def _open_parent_dirfd(path: Path) -> tuple[int, os.stat_result]:
    parent_parts, _ = _absolute_parts(path)
    current_fd = os.open("/", _directory_open_flags())
    try:
        for component in parent_parts:
            next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        parent_stat = os.fstat(current_fd)
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise StructuredCommitmentError("held parent is not a directory")
        return current_fd, parent_stat
    except BaseException:
        os.close(current_fd)
        raise


def _assert_parent_path_identity(path: Path, expected: os.stat_result) -> None:
    check_fd, check_stat = _open_parent_dirfd(path)
    try:
        if (check_stat.st_dev, check_stat.st_ino) != (expected.st_dev, expected.st_ino):
            raise StructuredCommitmentError("publication ancestor path was swapped")
    finally:
        os.close(check_fd)


def _read_fd_all(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _assert_regular(stat_result: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(stat_result.st_mode):
        raise StructuredCommitmentError(f"{label} is not a regular file")


def atomic_publish_no_overwrite(
    final_path: Path | str, payload: object
) -> PublishedArtifact:
    """Publish via same-FS O_EXCL temp + hard link, never replacing final.

    Any failure after a pathname is created leaves that pathname in place as
    permanent failure evidence.  The function never unlinks or mutates a final
    path and never follows a symlink in the parent walk or final open.
    """

    path = Path(final_path)
    if type(payload) is not bytes:
        raise StructuredCommitmentError("publication payload must be immutable bytes")
    parent_parts, final_name = _absolute_parts(path)
    del parent_parts
    parent_fd, parent_stat = _open_parent_dirfd(path)
    temp_fd: int | None = None
    temp_name: str | None = None
    expected_digest = hashlib.sha256(payload).hexdigest()
    try:
        _assert_parent_path_identity(path, parent_stat)
        for _ in range(32):
            candidate = f".{final_name}.commit-{secrets.token_hex(16)}.tmp"
            try:
                temp_fd = os.open(
                    candidate,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                continue
            temp_name = candidate
            break
        if temp_fd is None or temp_name is None:
            raise StructuredCommitmentError("could not allocate a unique temp name")

        initial_stat = os.fstat(temp_fd)
        _assert_regular(initial_stat, "temporary commitment")
        if initial_stat.st_nlink != 1:
            raise StructuredCommitmentError("temporary commitment has wrong link count")
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(temp_fd, view[written:])
            if count <= 0:
                raise StructuredCommitmentError("short commitment write")
            written += count
        os.fchmod(temp_fd, 0o444)
        os.fsync(temp_fd)
        complete_stat = os.fstat(temp_fd)
        if complete_stat.st_size != len(payload) or complete_stat.st_nlink != 1:
            raise StructuredCommitmentError("temporary commitment identity drift")
        _assert_regular(complete_stat, "temporary commitment")

        _assert_parent_path_identity(path, parent_stat)
        # Preserve the kernel's literal EEXIST/FileExistsError contract.  Do
        # not translate it into a generic validation failure.
        os.link(
            temp_name,
            final_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        linked_stat = os.fstat(temp_fd)
        if linked_stat.st_nlink != 2 or stat.S_IMODE(linked_stat.st_mode) != 0o444:
            raise StructuredCommitmentError(
                "published commitment link count or mode is invalid"
            )
        final_fd = os.open(final_name, _file_open_flags(), dir_fd=parent_fd)
        try:
            final_stat = os.fstat(final_fd)
            _assert_regular(final_stat, "published commitment")
            if (
                final_stat.st_dev,
                final_stat.st_ino,
                final_stat.st_nlink,
            ) != (linked_stat.st_dev, linked_stat.st_ino, 2):
                raise StructuredCommitmentError(
                    "published path/inode identity mismatch"
                )
        finally:
            os.close(final_fd)
        _assert_parent_path_identity(path, parent_stat)
        os.fsync(parent_fd)
        os.unlink(temp_name, dir_fd=parent_fd)
        temp_name = None
        os.fsync(parent_fd)

        _assert_parent_path_identity(path, parent_stat)
        final_fd = os.open(final_name, _file_open_flags(), dir_fd=parent_fd)
        try:
            reread = _read_fd_all(final_fd)
            final_stat = os.fstat(final_fd)
            _assert_regular(final_stat, "final commitment")
            path_stat = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                final_stat.st_dev,
                final_stat.st_ino,
                final_stat.st_nlink,
            ) != (path_stat.st_dev, path_stat.st_ino, 1):
                raise StructuredCommitmentError(
                    "final path/inode/link identity mismatch"
                )
            if stat.S_IMODE(final_stat.st_mode) != 0o444:
                raise StructuredCommitmentError("final commitment mode is not 0444")
            if (
                len(reread) != len(payload)
                or hashlib.sha256(reread).hexdigest() != expected_digest
            ):
                raise StructuredCommitmentError("final commitment reread mismatch")
        finally:
            os.close(final_fd)
        _assert_parent_path_identity(path, parent_stat)
        terminal_path_stat = os.stat(
            final_name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            terminal_path_stat.st_dev,
            terminal_path_stat.st_ino,
            terminal_path_stat.st_mode,
            terminal_path_stat.st_nlink,
            terminal_path_stat.st_ctime_ns,
        ) != (
            final_stat.st_dev,
            final_stat.st_ino,
            final_stat.st_mode,
            1,
            final_stat.st_ctime_ns,
        ):
            raise StructuredCommitmentError(
                "final basename identity changed after terminal parent check"
            )
        return PublishedArtifact(
            path=path,
            size=len(payload),
            sha256=expected_digest,
            device=final_stat.st_dev,
            inode=final_stat.st_ino,
        )
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise StructuredCommitmentError(
                "symlink encountered in publication path"
            ) from exc
        raise
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        # Deliberately do not clean a temp or final name on failure.  A linked
        # final is permanent evidence; an unlinked unique temp records an
        # incomplete attempt.  On success temp_name is already None.
        os.close(parent_fd)


def publish_precommit(
    final_path: Path | str,
    unsigned_payload: object,
    *,
    scoring_context_attestation_bytes: object,
) -> PublishedArtifact:
    return atomic_publish_no_overwrite(
        final_path,
        build_precommit_bytes(
            unsigned_payload,
            scoring_context_attestation_bytes=scoring_context_attestation_bytes,
        ),
    )


def _read_no_symlink_single_link(path: Path | str, label: str) -> bytes:
    file_path = Path(path)
    _, name = _absolute_parts(file_path)
    parent_fd, parent_stat = _open_parent_dirfd(file_path)
    try:
        _assert_parent_path_identity(file_path, parent_stat)
        fd = os.open(name, _file_open_flags(), dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            _assert_regular(before, label)
            if before.st_nlink != 1:
                raise StructuredCommitmentError(f"{label} must have exactly one link")
            if stat.S_IMODE(before.st_mode) != 0o444:
                raise StructuredCommitmentError(f"{label} mode must be exactly 0444")
            raw = _read_fd_all(fd)
            after = os.fstat(fd)
            path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
                before.st_mode,
                before.st_nlink,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_mode,
                after.st_nlink,
            ):
                raise StructuredCommitmentError(f"{label} changed while read")
            if (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_ctime_ns,
            ) != (
                path_stat.st_dev,
                path_stat.st_ino,
                path_stat.st_mode,
                path_stat.st_nlink,
                path_stat.st_ctime_ns,
            ):
                raise StructuredCommitmentError(f"{label} path/inode mismatch")
            if len(raw) != after.st_size:
                raise StructuredCommitmentError(f"{label} size mismatch")
            _assert_parent_path_identity(file_path, parent_stat)
            terminal_path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                terminal_path_stat.st_dev,
                terminal_path_stat.st_ino,
                terminal_path_stat.st_mode,
                terminal_path_stat.st_nlink,
                terminal_path_stat.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                1,
                after.st_ctime_ns,
            ):
                raise StructuredCommitmentError(
                    f"{label} basename identity changed after parent check"
                )
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def publish_scalar_receipt(
    *,
    precommit_path: Path | str,
    request_bytes: object,
    scoring_context_attestation_path: Path | str,
    receipt_path: Path | str,
    caller_held_invocation_id: object,
    caller_held_scalar_reward: object,
) -> PublishedArtifact:
    """Publish one bound receipt; this does not authorize its formal path.

    A future sealed runner must derive and verify ``receipt_path`` from its
    committed invocation inventory.  This low-level primitive intentionally
    cannot decide whether an arbitrary caller-supplied path is scientifically
    registered.
    """

    precommit_bytes = _read_no_symlink_single_link(precommit_path, "precommit")
    attestation_bytes = _read_no_symlink_single_link(
        scoring_context_attestation_path, "scoring context attestation"
    )
    receipt = build_scalar_receipt_bytes(
        precommit_bytes=precommit_bytes,
        request_bytes=request_bytes,
        scoring_context_attestation_bytes=attestation_bytes,
        caller_held_invocation_id=caller_held_invocation_id,
        caller_held_scalar_reward=caller_held_scalar_reward,
    )
    return atomic_publish_no_overwrite(receipt_path, receipt)


__all__ = [
    "CANONICAL_SERIALIZER_ID",
    "CANDIDATE_ACTION_IDS",
    "FLOAT_HEX_CODEC_ID",
    "GENESIS_PRECOMMIT_SHA256",
    "PRECOMMIT_PROTOCOL",
    "PublishedArtifact",
    "REGISTERED_BRANCH_IDS",
    "SCHEMA_VERSION",
    "SCORING_CONTEXT_PROTOCOL",
    "SHARED_RAW_ACTION_PROTOCOL",
    "SharedJoinKey",
    "StructuredCommitmentError",
    "ValidatedPrecommit",
    "ValidatedReceiptRequest",
    "atomic_publish_no_overwrite",
    "build_precommit_bytes",
    "build_scalar_receipt_bytes",
    "build_scoring_context_attestation",
    "canonical_json_bytes",
    "canonical_sha256",
    "encode_action_bytes",
    "implementation_source_sha256",
    "numerical_runtime_identity",
    "publish_precommit",
    "publish_scalar_receipt",
    "validate_finite_float64_scalar",
    "validate_complete_receipt_inventory",
    "validate_precommit_bytes",
    "validate_precommit_digest_sequence",
    "validate_precommit_parent_link",
    "validate_receipt_request_bytes",
    "validate_scoring_context_attestation",
]
