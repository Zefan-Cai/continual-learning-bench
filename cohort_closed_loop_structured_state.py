"""Deterministic primitives for the preregistered Cohort structured state.

This module intentionally contains no runner, task, scorer, DGP, model, or
artifact I/O.  It implements only the numerical and exact-schema boundaries
sealed in ``COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from fractions import Fraction
from typing import TypeAlias


class StructuredStateProtocolError(ValueError):
    """Raised when a structured-state protocol boundary fails closed."""


STATE_FIELD_NAMES: tuple[str, ...] = (
    "layer1_level",
    "layer1_slope",
    "layer2_level",
    "layer2_slope",
    "layer3_level",
    "layer3_slope",
)
HORIZONS: tuple[int, ...] = (12, 24, 36)
STATE_DIMENSION = 6
RHO = 1.0 / 4.0
ETA = 1.0 / 16.0
MAX_ADAPTATION_ITEMS = 20
MAX_OFFICIAL_STATE_ABS = 5.0 / 4.0
MAX_PROBE_STATE_ABS = 3.0 / 2.0
PROBABILITY_EPSILON = 1e-6

# The scale is sealed as these six operations, not a caller-provided vector.
STATE_SCALE: tuple[float, ...] = (
    7.0 / 20.0,
    7.0 / 60.0,
    7.0 / 20.0,
    7.0 / 60.0,
    7.0 / 20.0,
    7.0 / 60.0,
)

State: TypeAlias = tuple[float, float, float, float, float, float]
CandidateId: TypeAlias = tuple[str, str]

POSITIVE_ZERO_STATE: State = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

# Public schema information only.  This module deliberately does not import
# the Cohort task or scorer modules, which also contain hidden-state machinery.
COHORT_ID_AND_LAYER: tuple[tuple[str, int], ...] = (
    ("acron_high_hhbp_high_prb1_lt25", 3),
    ("acron_lt2", 1),
    ("acron_lt2_prb1_24_28", 2),
    ("age_40_60_voc_gte5", 2),
    ("age_gte55_acron_gte4", 2),
    ("age_gte60_gg3_education_gte16", 3),
    ("avoc_gte15_gg1", 2),
    ("avoc_gte15_gg1_age_gte55", 3),
    ("avoc_high_cognitive_low_family_history", 3),
    ("avoc_high_education_gte16", 2),
    ("avoc_high_family_history_prb1_gte28", 3),
    ("avoc_high_prb1_lt25", 2),
    ("avoc_low_voc_high_age_40_60", 3),
    ("cognitive_gte075_age_gte60_gg3", 3),
    ("cognitive_lt050_age_lt55", 2),
    ("cognitive_lt050_prb1_gte28_acron_lt2", 3),
    ("education_gte16_cognitive_lt050", 2),
    ("education_gte16_gg3", 2),
    ("education_high_voc_high_acron_low", 3),
    ("education_low_prb1_gte28_gg3", 3),
    ("education_lt13_gg1", 2),
    ("family_history_education_gte16_prb1_lt25", 3),
    ("family_history_gg3", 2),
    ("family_history_gg3_voc_gte5", 3),
    ("family_history_prb1_gte28", 2),
    ("family_history_yes", 1),
    ("gg1_family_history_cognitive_lt050", 3),
    ("gg3_education_gte16_voc_3_6", 3),
    ("gg3_voc_lt3", 2),
    ("hhbp_gte8", 1),
    ("hhbp_gte8_prb1_lt25", 2),
    ("prb1_gte28_acron_gte4", 2),
    ("prb1_gte30_acron_gte4_voc_lt3", 3),
    ("prb1_lt25_voc_gte5_acron_lt2", 3),
    ("voc_3_6", 1),
    ("voc_3_6_prb1_lt25", 2),
)
COHORT_IDS: tuple[str, ...] = tuple(row[0] for row in COHORT_ID_AND_LAYER)
ACTION_FIELD_NAMES: tuple[str, ...] = tuple(
    f"{cohort_id}__s{horizon}" for cohort_id in COHORT_IDS for horizon in HORIZONS
)

UPDATER_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "precommit_sha256",
        "branch_id",
        "item_id",
        "scoring_context_sha256",
        "candidate_rewards",
    }
)
CANDIDATE_BRANCH_IDS: frozenset[str] = frozenset(
    {"closed_loop_active", "closed_loop_lr0", "pair_sign_reverse"}
)
FORBIDDEN_BOUNDARY_FIELD_NAMES: tuple[str, ...] = (
    "cohort_gt",
    "ref_survival",
    "env_feedback_reward",
    "per_cohort_score_details",
    "terminal_observation",
    "task",
    "scorer",
    "scoring_handle_resolver",
)

_LOWER_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _require_binary64_runtime() -> None:
    if not (
        sys.float_info.radix == 2
        and sys.float_info.mant_dig == 53
        and sys.float_info.max_exp == 1024
    ):
        raise RuntimeError("the structured-state protocol requires IEEE-754 binary64")


_require_binary64_runtime()


def _canonical_json_bytes(value: object, *, sort_keys: bool = False) -> bytes:
    try:
        text = json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=sort_keys,
        )
    except (TypeError, ValueError) as exc:
        raise StructuredStateProtocolError(
            "canonical JSON serialization failed"
        ) from exc
    return text.encode("utf-8")


def _is_negative_zero(value: float) -> bool:
    return value == 0.0 and math.copysign(1.0, value) < 0.0


def validate_state(state: object, *, max_abs: float | None = None) -> State:
    """Validate and normalize the fixed-order six-float state.

    Only a plain list or tuple is accepted.  Mappings, named alternatives,
    reordered field/value pairs, booleans, integers, numpy scalars, and custom
    iterables are rejected rather than coerced at this protocol boundary.
    """

    if type(state) not in (list, tuple):
        raise StructuredStateProtocolError("state must be a plain ordered six-vector")
    if len(state) != STATE_DIMENSION:
        raise StructuredStateProtocolError("state must contain exactly six fields")

    values: list[float] = []
    for index, value in enumerate(state):
        if type(value) is not float:
            raise StructuredStateProtocolError(
                f"state field {STATE_FIELD_NAMES[index]} must be a binary64 float"
            )
        if not math.isfinite(value):
            raise StructuredStateProtocolError(
                f"state field {STATE_FIELD_NAMES[index]} must be finite"
            )
        if _is_negative_zero(value):
            raise StructuredStateProtocolError(
                f"state field {STATE_FIELD_NAMES[index]} must not be negative zero"
            )
        if max_abs is not None and abs(value) > max_abs:
            raise StructuredStateProtocolError(
                f"state field {STATE_FIELD_NAMES[index]} exceeds the sealed bound"
            )
        values.append(value)

    return (
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
    )


def is_positive_zero_state(state: object) -> bool:
    values = validate_state(state)
    return all(value == 0.0 and not _is_negative_zero(value) for value in values)


def state_payload(state: object) -> list[list[str]]:
    values = validate_state(state)
    return [
        [field_name, value.hex()]
        for field_name, value in zip(STATE_FIELD_NAMES, values)
    ]


def state_from_payload(payload: object) -> State:
    """Decode the registered ordered ``[field_name, float.hex()]`` array."""

    if type(payload) not in (list, tuple) or len(payload) != STATE_DIMENSION:
        raise StructuredStateProtocolError(
            "state payload must be one ordered six-element array"
        )
    values: list[float] = []
    for index, entry in enumerate(payload):
        if type(entry) not in (list, tuple) or len(entry) != 2:
            raise StructuredStateProtocolError(
                "each state payload entry must be one exact field/value pair"
            )
        field_name, float_hex = entry
        if type(field_name) is not str or field_name != STATE_FIELD_NAMES[index]:
            raise StructuredStateProtocolError("state payload fields are reordered")
        if type(float_hex) is not str:
            raise StructuredStateProtocolError(
                "state payload value must be float.hex text"
            )
        try:
            value = float.fromhex(float_hex)
        except (OverflowError, ValueError) as exc:
            raise StructuredStateProtocolError(
                "state payload float hex is invalid"
            ) from exc
        if not math.isfinite(value) or value.hex() != float_hex:
            raise StructuredStateProtocolError(
                "state payload float hex must be finite and canonical"
            )
        values.append(value)
    return validate_state(values)


def state_sha256(state: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(state_payload(state))).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StructuredStateProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json_number(token: str) -> float:
    try:
        return float(token)
    except (OverflowError, ValueError) as exc:
        raise StructuredStateProtocolError("invalid JSON numeric token") from exc


def _reject_json_constant(token: str) -> float:
    raise StructuredStateProtocolError(
        f"non-standard JSON constant is forbidden: {token}"
    )


def parse_semantic_action(raw_action_bytes: object) -> dict[str, float]:
    """Parse the exact 108-field action schema with signed-zero preservation."""

    if type(raw_action_bytes) is not bytes:
        raise StructuredStateProtocolError("action must be immutable UTF-8 bytes")
    try:
        text = raw_action_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StructuredStateProtocolError("action is not valid UTF-8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_parse_json_number,
            parse_int=_parse_json_number,
            parse_constant=_reject_json_constant,
        )
    except StructuredStateProtocolError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StructuredStateProtocolError("action is not valid strict JSON") from exc

    if type(parsed) is not dict:
        raise StructuredStateProtocolError("action must be one flat JSON object")
    if len(parsed) != len(ACTION_FIELD_NAMES) or set(parsed) != set(ACTION_FIELD_NAMES):
        raise StructuredStateProtocolError(
            "action must contain exactly the 108 registered terminal fields"
        )

    result: dict[str, float] = {}
    for field_name in ACTION_FIELD_NAMES:
        value = parsed[field_name]
        if type(value) is not float:
            raise StructuredStateProtocolError(
                f"action field {field_name} must be a JSON numeric token"
            )
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise StructuredStateProtocolError(
                f"action field {field_name} must be finite and in [0,1]"
            )
        result[field_name] = value
    return result


def semantic_action_payload(raw_action_bytes: object) -> list[list[str]]:
    action = parse_semantic_action(raw_action_bytes)
    return [[field_name, action[field_name].hex()] for field_name in ACTION_FIELD_NAMES]


def semantic_action_sha256(raw_action_bytes: object) -> str:
    payload = semantic_action_payload(raw_action_bytes)
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def action_bytes_sha256(raw_action_bytes: object) -> str:
    if type(raw_action_bytes) is not bytes:
        raise StructuredStateProtocolError("action must be immutable bytes")
    return hashlib.sha256(raw_action_bytes).hexdigest()


def _sigmoid(value: float) -> float:
    if value >= 0.0:
        return 1.0 / (1.0 + math.exp(-value))
    exp_value = math.exp(value)
    return exp_value / (1.0 + exp_value)


def _transform_probability(probability: float, delta: float) -> float:
    if probability == 0.0:
        return probability
    if delta == 0.0:
        return probability
    clamped = min(max(probability, PROBABILITY_EPSILON), 1.0 - PROBABILITY_EPSILON)
    logit = math.log(clamped / (1.0 - clamped))
    transformed = _sigmoid(logit + delta)
    if not math.isfinite(transformed) or not 0.0 <= transformed <= 1.0:
        raise StructuredStateProtocolError(
            "probability transform produced an invalid value"
        )
    return transformed


def transform_action(raw_action_bytes: object, state: object) -> bytes:
    """Apply the sealed ``T_x(raw_action_bytes, x)`` transformation."""

    if type(raw_action_bytes) is not bytes:
        raise StructuredStateProtocolError("action must be immutable bytes")
    values = validate_state(state, max_abs=MAX_PROBE_STATE_ABS)

    # This check deliberately precedes all parsing and canonicalization.
    if is_positive_zero_state(values):
        return raw_action_bytes

    action = parse_semantic_action(raw_action_bytes)
    z = tuple(scale * value for scale, value in zip(STATE_SCALE, values))
    if any(not math.isfinite(value) for value in z):
        raise StructuredStateProtocolError("scaled state is nonfinite")

    transformed: dict[str, float] = {}
    for cohort_id, layer in COHORT_ID_AND_LAYER:
        level = z[2 * (layer - 1)]
        slope = z[2 * (layer - 1) + 1]
        deltas = (level + slope, level, level - slope)
        if any(not math.isfinite(delta) for delta in deltas):
            raise StructuredStateProtocolError("field offset is nonfinite")
        for horizon, delta in zip(HORIZONS, deltas):
            field_name = f"{cohort_id}__s{horizon}"
            transformed[field_name] = _transform_probability(action[field_name], delta)

    # Sorted object keys are the registered nonzero-state byte serializer.  No
    # values are horizon-sorted, monotonicity-repaired, or rounded.
    return _canonical_json_bytes(transformed, sort_keys=True)


T_x = transform_action


def sylvester_hadamard_8() -> tuple[tuple[int, ...], ...]:
    matrix: tuple[tuple[int, ...], ...] = ((1,),)
    for _ in range(3):
        matrix = tuple(tuple(row) + tuple(row) for row in matrix) + tuple(
            tuple(row) + tuple(-value for value in row) for row in matrix
        )
    return matrix


H8: tuple[tuple[int, ...], ...] = sylvester_hadamard_8()
U: tuple[tuple[int, ...], ...] = tuple(tuple(row[:STATE_DIMENSION]) for row in H8)
CANDIDATE_IDS: tuple[CandidateId, ...] = tuple(
    (f"h{row_index}", sign) for row_index in range(8) for sign in ("+", "-")
)


def integer_matrix_rank(matrix: object) -> int:
    if type(matrix) not in (list, tuple) or not matrix:
        raise StructuredStateProtocolError("matrix must be a nonempty plain sequence")
    if any(type(row) not in (list, tuple) for row in matrix):
        raise StructuredStateProtocolError("matrix rows must be plain sequences")
    width = len(matrix[0])
    if width == 0 or any(len(row) != width for row in matrix):
        raise StructuredStateProtocolError("matrix must be rectangular")
    if any(
        type(value) is not int or type(value) is bool for row in matrix for value in row
    ):
        raise StructuredStateProtocolError("matrix entries must be integers")

    work = [[Fraction(value) for value in row] for row in matrix]
    rank = 0
    for column in range(width):
        pivot = next(
            (row for row in range(rank, len(work)) if work[row][column] != 0),
            None,
        )
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        pivot_value = work[rank][column]
        work[rank] = [value / pivot_value for value in work[rank]]
        for row in range(len(work)):
            if row == rank or work[row][column] == 0:
                continue
            multiplier = work[row][column]
            work[row] = [
                left - multiplier * right for left, right in zip(work[row], work[rank])
            ]
        rank += 1
        if rank == len(work) or rank == width:
            break
    return rank


def validate_candidate_design() -> None:
    if len(H8) != 8 or any(len(row) != 8 for row in H8):
        raise StructuredStateProtocolError("H8 has the wrong shape")
    if len(U) != 8 or any(len(row) != STATE_DIMENSION for row in U):
        raise StructuredStateProtocolError("U has the wrong shape")
    if any(value not in (-1, 1) for row in U for value in row):
        raise StructuredStateProtocolError("U must contain only signed unit entries")
    gram = tuple(
        tuple(
            sum(U[row][left] * U[row][right] for row in range(8)) for right in range(6)
        )
        for left in range(6)
    )
    expected = tuple(
        tuple(8 if left == right else 0 for right in range(6)) for left in range(6)
    )
    if gram != expected:
        raise StructuredStateProtocolError("U^T U must equal 8 I_6 exactly")
    if integer_matrix_rank(U) != STATE_DIMENSION:
        raise StructuredStateProtocolError("rank(U) must equal six")
    signed_balance = tuple(
        sum(sign * row[column] for row in U for sign in (1, -1))
        for column in range(STATE_DIMENSION)
    )
    if signed_balance != (0, 0, 0, 0, 0, 0):
        raise StructuredStateProtocolError("the sixteen signed probes must balance")
    if CANDIDATE_IDS != tuple(
        (f"h{row_index}", sign) for row_index in range(8) for sign in ("+", "-")
    ):
        raise StructuredStateProtocolError("candidate ID order drifted")


validate_candidate_design()


def candidate_probe_states(
    state_before: object,
) -> tuple[tuple[CandidateId, State], ...]:
    center = validate_state(state_before, max_abs=MAX_OFFICIAL_STATE_ABS)
    result: list[tuple[CandidateId, State]] = []
    for row_index, row in enumerate(U):
        for sign_name, sign in (("+", 1.0), ("-", -1.0)):
            values = tuple(
                center[column] + sign * RHO * float(row[column])
                for column in range(STATE_DIMENSION)
            )
            probe = validate_state(values, max_abs=MAX_PROBE_STATE_ABS)
            result.append(((f"h{row_index}", sign_name), probe))
    if tuple(candidate_id for candidate_id, _ in result) != CANDIDATE_IDS:
        raise StructuredStateProtocolError("candidate ID generation drifted")
    if len({state for _, state in result}) != 16:
        raise StructuredStateProtocolError("the sealed probe states must be unique")
    return tuple(result)


def encode_scalar_reward_float_hex(value: object) -> str:
    if type(value) is not float or not math.isfinite(value):
        raise StructuredStateProtocolError(
            "scalar reward must be one finite binary64 float"
        )
    return value.hex()


def decode_scalar_reward_float_hex(value: object) -> float:
    if type(value) is not str:
        raise StructuredStateProtocolError("scalar_reward_float_hex must be a string")
    try:
        decoded = float.fromhex(value)
    except (OverflowError, ValueError) as exc:
        raise StructuredStateProtocolError(
            "scalar reward is not valid hexadecimal float"
        ) from exc
    if not math.isfinite(decoded) or decoded.hex() != value:
        raise StructuredStateProtocolError(
            "scalar reward hex is not finite and canonical"
        )
    return decoded


def _validate_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _LOWER_SHA256_RE.fullmatch(value) is None:
        raise StructuredStateProtocolError(f"{field_name} must be lowercase SHA256 hex")
    return value


@dataclass(frozen=True)
class ValidatedUpdaterInput:
    precommit_sha256: str
    branch_id: str
    item_id: int
    scoring_context_sha256: str
    candidate_rewards: tuple[tuple[CandidateId, float], ...]


@dataclass(frozen=True)
class SignESUpdate:
    branch_id: str
    item_id: int
    state_before: State
    true_direction: State
    used_direction: State
    state_after: State


def validate_updater_input(payload: object) -> ValidatedUpdaterInput:
    """Validate the updater's exact five-field, scalar-only input schema."""

    if type(payload) is not dict:
        raise StructuredStateProtocolError("updater input must be one plain object")
    if set(payload) != UPDATER_FIELD_NAMES or len(payload) != len(UPDATER_FIELD_NAMES):
        raise StructuredStateProtocolError(
            "updater input has missing or additional fields"
        )

    precommit_sha256 = _validate_sha256(payload["precommit_sha256"], "precommit_sha256")
    scoring_context_sha256 = _validate_sha256(
        payload["scoring_context_sha256"], "scoring_context_sha256"
    )
    branch_id = payload["branch_id"]
    if type(branch_id) is not str or branch_id not in CANDIDATE_BRANCH_IDS:
        raise StructuredStateProtocolError("updater branch_id is not registered")
    item_id = payload["item_id"]
    if type(item_id) is not int or not 1 <= item_id <= MAX_ADAPTATION_ITEMS:
        raise StructuredStateProtocolError(
            "updater item_id must be an integer in [1,20]"
        )

    candidate_rewards = payload["candidate_rewards"]
    if type(candidate_rewards) not in (list, tuple) or len(candidate_rewards) != 16:
        raise StructuredStateProtocolError(
            "updater requires exactly sixteen candidate rewards"
        )
    validated_rewards: list[tuple[CandidateId, float]] = []
    for index, entry in enumerate(candidate_rewards):
        if type(entry) not in (list, tuple) or len(entry) != 2:
            raise StructuredStateProtocolError(
                "each candidate reward must be one exact two-element pair"
            )
        candidate_id, scalar_reward = entry
        if type(candidate_id) not in (list, tuple) or len(candidate_id) != 2:
            raise StructuredStateProtocolError(
                "candidate_id must be one exact two-element pair"
            )
        if type(candidate_id[0]) is not str or type(candidate_id[1]) is not str:
            raise StructuredStateProtocolError(
                "candidate_id components must be strings"
            )
        normalized_id = (candidate_id[0], candidate_id[1])
        if normalized_id != CANDIDATE_IDS[index]:
            raise StructuredStateProtocolError(
                "candidate IDs must use the sealed order"
            )
        if type(scalar_reward) is not float or not math.isfinite(scalar_reward):
            raise StructuredStateProtocolError(
                "candidate reward must be one finite float"
            )
        validated_rewards.append((normalized_id, scalar_reward))

    return ValidatedUpdaterInput(
        precommit_sha256=precommit_sha256,
        branch_id=branch_id,
        item_id=item_id,
        scoring_context_sha256=scoring_context_sha256,
        candidate_rewards=tuple(validated_rewards),
    )


def _sign_difference(plus_reward: float, minus_reward: float) -> int:
    if plus_reward > minus_reward:
        return 1
    if plus_reward < minus_reward:
        return -1
    return 0


def _direction_from_rewards(
    candidate_rewards: tuple[tuple[CandidateId, float], ...],
    *,
    pair_sign_reverse: bool,
) -> State:
    reward_by_id = {candidate_id: reward for candidate_id, reward in candidate_rewards}
    sums = [0, 0, 0, 0, 0, 0]
    for row_index, row in enumerate(U):
        plus = reward_by_id[(f"h{row_index}", "+")]
        minus = reward_by_id[(f"h{row_index}", "-")]
        if pair_sign_reverse:
            plus, minus = minus, plus
        reward_sign = _sign_difference(plus, minus)
        for column, direction in enumerate(row):
            sums[column] += reward_sign * direction
    values = tuple(float(total) / 8.0 for total in sums)
    return validate_state(values)


def sign_es_update(state_before: object, payload: object) -> SignESUpdate:
    """Compute the registered active, LR0, or pair-reverse sign-ES step."""

    updater_input = validate_updater_input(payload)
    before = validate_state(state_before, max_abs=MAX_OFFICIAL_STATE_ABS)
    prospective_before_bound = float(updater_input.item_id - 1) / 16.0
    if any(abs(value) > prospective_before_bound for value in before):
        raise StructuredStateProtocolError(
            "state_before exceeds its prospective item bound"
        )
    if updater_input.branch_id == "closed_loop_lr0" and not is_positive_zero_state(
        before
    ):
        raise StructuredStateProtocolError(
            "LR0 state_before must remain six positive zeros"
        )

    true_direction = _direction_from_rewards(
        updater_input.candidate_rewards,
        pair_sign_reverse=False,
    )
    used_direction = _direction_from_rewards(
        updater_input.candidate_rewards,
        pair_sign_reverse=updater_input.branch_id == "pair_sign_reverse",
    )

    if updater_input.branch_id == "closed_loop_lr0":
        after = POSITIVE_ZERO_STATE
    else:
        values = tuple(
            before[column] + ETA * used_direction[column]
            for column in range(STATE_DIMENSION)
        )
        after = validate_state(values, max_abs=MAX_OFFICIAL_STATE_ABS)

    prospective_after_bound = float(updater_input.item_id) / 16.0
    if any(abs(value) > prospective_after_bound for value in after):
        raise StructuredStateProtocolError(
            "state_after exceeds its prospective item bound"
        )
    return SignESUpdate(
        branch_id=updater_input.branch_id,
        item_id=updater_input.item_id,
        state_before=before,
        true_direction=true_direction,
        used_direction=used_direction,
        state_after=after,
    )


__all__ = [
    "ACTION_FIELD_NAMES",
    "CANDIDATE_BRANCH_IDS",
    "CANDIDATE_IDS",
    "COHORT_IDS",
    "COHORT_ID_AND_LAYER",
    "ETA",
    "FORBIDDEN_BOUNDARY_FIELD_NAMES",
    "H8",
    "HORIZONS",
    "MAX_ADAPTATION_ITEMS",
    "MAX_OFFICIAL_STATE_ABS",
    "MAX_PROBE_STATE_ABS",
    "POSITIVE_ZERO_STATE",
    "PROBABILITY_EPSILON",
    "RHO",
    "STATE_FIELD_NAMES",
    "STATE_SCALE",
    "SignESUpdate",
    "StructuredStateProtocolError",
    "T_x",
    "U",
    "ValidatedUpdaterInput",
    "action_bytes_sha256",
    "candidate_probe_states",
    "decode_scalar_reward_float_hex",
    "encode_scalar_reward_float_hex",
    "integer_matrix_rank",
    "is_positive_zero_state",
    "parse_semantic_action",
    "semantic_action_payload",
    "semantic_action_sha256",
    "sign_es_update",
    "state_from_payload",
    "state_payload",
    "state_sha256",
    "sylvester_hadamard_8",
    "transform_action",
    "validate_candidate_design",
    "validate_state",
    "validate_updater_input",
]
