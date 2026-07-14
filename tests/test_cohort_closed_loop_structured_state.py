from __future__ import annotations

import ast
import copy
import hashlib
import json
import math
from pathlib import Path

import pytest

import cohort_closed_loop_structured_state as state_protocol
from cohort_closed_loop_structured_state import (
    ACTION_FIELD_NAMES,
    CANDIDATE_IDS,
    COHORT_ID_AND_LAYER,
    ETA,
    FORBIDDEN_BOUNDARY_FIELD_NAMES,
    H8,
    MAX_OFFICIAL_STATE_ABS,
    MAX_PROBE_STATE_ABS,
    POSITIVE_ZERO_STATE,
    RHO,
    STATE_FIELD_NAMES,
    STATE_SCALE,
    U,
    StructuredStateProtocolError,
    action_bytes_sha256,
    candidate_probe_states,
    decode_scalar_reward_float_hex,
    encode_scalar_reward_float_hex,
    integer_matrix_rank,
    is_positive_zero_state,
    parse_semantic_action,
    semantic_action_payload,
    semantic_action_sha256,
    sign_es_update,
    state_from_payload,
    state_payload,
    state_sha256,
    transform_action,
    validate_state,
    validate_updater_input,
)


# Independent literal protocol oracles.  Do not derive these inventories from
# the module under test: their canonical SHA256 values were sealed separately.
_LITERAL_COHORT_ID_AND_LAYER: tuple[tuple[str, int], ...] = (
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
_LITERAL_ACTION_FIELD_NAMES: tuple[str, ...] = tuple(
    f"{cohort_id}__s{horizon}"
    for cohort_id, _ in _LITERAL_COHORT_ID_AND_LAYER
    for horizon in (12, 24, 36)
)
_ASYMMETRIC_CENTER = (0.125, -0.25, 0.375, -0.5, 0.625, -0.75)
_ASYMMETRIC_CANDIDATE_GOLDEN = (
    (
        ("h0", "+"),
        (
            "0x1.8000000000000p-2",
            "0x0.0p+0",
            "0x1.4000000000000p-1",
            "-0x1.0000000000000p-2",
            "0x1.c000000000000p-1",
            "-0x1.0000000000000p-1",
        ),
    ),
    (
        ("h0", "-"),
        (
            "-0x1.0000000000000p-3",
            "-0x1.0000000000000p-1",
            "0x1.0000000000000p-3",
            "-0x1.8000000000000p-1",
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p+0",
        ),
    ),
    (
        ("h1", "+"),
        (
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p-1",
            "0x1.4000000000000p-1",
            "-0x1.8000000000000p-1",
            "0x1.c000000000000p-1",
            "-0x1.0000000000000p+0",
        ),
    ),
    (
        ("h1", "-"),
        (
            "-0x1.0000000000000p-3",
            "0x0.0p+0",
            "0x1.0000000000000p-3",
            "-0x1.0000000000000p-2",
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p-1",
        ),
    ),
    (
        ("h2", "+"),
        (
            "0x1.8000000000000p-2",
            "0x0.0p+0",
            "0x1.0000000000000p-3",
            "-0x1.8000000000000p-1",
            "0x1.c000000000000p-1",
            "-0x1.0000000000000p-1",
        ),
    ),
    (
        ("h2", "-"),
        (
            "-0x1.0000000000000p-3",
            "-0x1.0000000000000p-1",
            "0x1.4000000000000p-1",
            "-0x1.0000000000000p-2",
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p+0",
        ),
    ),
    (
        ("h3", "+"),
        (
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p-1",
            "0x1.0000000000000p-3",
            "-0x1.0000000000000p-2",
            "0x1.c000000000000p-1",
            "-0x1.0000000000000p+0",
        ),
    ),
    (
        ("h3", "-"),
        (
            "-0x1.0000000000000p-3",
            "0x0.0p+0",
            "0x1.4000000000000p-1",
            "-0x1.8000000000000p-1",
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p-1",
        ),
    ),
    (
        ("h4", "+"),
        (
            "0x1.8000000000000p-2",
            "0x0.0p+0",
            "0x1.4000000000000p-1",
            "-0x1.0000000000000p-2",
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p+0",
        ),
    ),
    (
        ("h4", "-"),
        (
            "-0x1.0000000000000p-3",
            "-0x1.0000000000000p-1",
            "0x1.0000000000000p-3",
            "-0x1.8000000000000p-1",
            "0x1.c000000000000p-1",
            "-0x1.0000000000000p-1",
        ),
    ),
    (
        ("h5", "+"),
        (
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p-1",
            "0x1.4000000000000p-1",
            "-0x1.8000000000000p-1",
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p-1",
        ),
    ),
    (
        ("h5", "-"),
        (
            "-0x1.0000000000000p-3",
            "0x0.0p+0",
            "0x1.0000000000000p-3",
            "-0x1.0000000000000p-2",
            "0x1.c000000000000p-1",
            "-0x1.0000000000000p+0",
        ),
    ),
    (
        ("h6", "+"),
        (
            "0x1.8000000000000p-2",
            "0x0.0p+0",
            "0x1.0000000000000p-3",
            "-0x1.8000000000000p-1",
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p+0",
        ),
    ),
    (
        ("h6", "-"),
        (
            "-0x1.0000000000000p-3",
            "-0x1.0000000000000p-1",
            "0x1.4000000000000p-1",
            "-0x1.0000000000000p-2",
            "0x1.c000000000000p-1",
            "-0x1.0000000000000p-1",
        ),
    ),
    (
        ("h7", "+"),
        (
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p-1",
            "0x1.0000000000000p-3",
            "-0x1.0000000000000p-2",
            "0x1.8000000000000p-2",
            "-0x1.0000000000000p-1",
        ),
    ),
    (
        ("h7", "-"),
        (
            "-0x1.0000000000000p-3",
            "0x0.0p+0",
            "0x1.4000000000000p-1",
            "-0x1.8000000000000p-1",
            "0x1.c000000000000p-1",
            "-0x1.0000000000000p+0",
        ),
    ),
)


def _action_bytes(
    overrides: dict[str, str] | None = None,
    *,
    default_token: str = "0.5",
    reversed_fields: bool = False,
) -> bytes:
    overrides = overrides or {}
    fields = (
        tuple(reversed(ACTION_FIELD_NAMES)) if reversed_fields else ACTION_FIELD_NAMES
    )
    members = [
        f"{json.dumps(field_name)}:{overrides.get(field_name, default_token)}"
        for field_name in fields
    ]
    return ("{" + ",".join(members) + "}").encode("utf-8")


def _updater_payload(
    branch_id: str = "closed_loop_active",
    *,
    item_id: int = 1,
    pair_signs: tuple[int, ...] = (1, 1, 1, 1, 1, 1, 1, 1),
) -> dict[str, object]:
    rewards: list[tuple[tuple[str, str], float]] = []
    for row_index, pair_sign in enumerate(pair_signs):
        plus = 1.0 if pair_sign > 0 else (0.0 if pair_sign < 0 else 0.5)
        minus = 0.0 if pair_sign > 0 else (1.0 if pair_sign < 0 else 0.5)
        rewards.append(((f"h{row_index}", "+"), plus))
        rewards.append(((f"h{row_index}", "-"), minus))
    return {
        "precommit_sha256": "a" * 64,
        "branch_id": branch_id,
        "item_id": item_id,
        "scoring_context_sha256": "b" * 64,
        "candidate_rewards": rewards,
    }


def _negative_zero() -> float:
    return -0.0


def _is_positive_zero(value: float) -> bool:
    return value == 0.0 and math.copysign(1.0, value) > 0.0


def test_source_parses_as_python_310() -> None:
    source_path = Path(state_protocol.__file__)
    ast.parse(
        source_path.read_text(), filename=str(source_path), feature_version=(3, 10)
    )


def test_fixed_state_schema_and_positive_zero_golden_hash() -> None:
    assert STATE_FIELD_NAMES == (
        "layer1_level",
        "layer1_slope",
        "layer2_level",
        "layer2_slope",
        "layer3_level",
        "layer3_slope",
    )
    assert state_payload(POSITIVE_ZERO_STATE) == [
        [field_name, "0x0.0p+0"] for field_name in STATE_FIELD_NAMES
    ]
    assert state_sha256(POSITIVE_ZERO_STATE) == (
        "307c22f46dd0c5c6e9da9d099ab03e637b6144c8de1291f68b1cf9f5e35b7078"
    )
    assert is_positive_zero_state(POSITIVE_ZERO_STATE)
    assert all(_is_positive_zero(value) for value in POSITIVE_ZERO_STATE)
    assert tuple(value.hex() for value in STATE_SCALE) == (
        "0x1.6666666666666p-2",
        "0x1.ddddddddddddep-4",
        "0x1.6666666666666p-2",
        "0x1.ddddddddddddep-4",
        "0x1.6666666666666p-2",
        "0x1.ddddddddddddep-4",
    )
    assert tuple(
        (scale * value).hex() for scale, value in zip(STATE_SCALE, _ASYMMETRIC_CENTER)
    ) == (
        "0x1.6666666666666p-5",
        "-0x1.ddddddddddddep-6",
        "0x1.0ccccccccccccp-3",
        "-0x1.ddddddddddddep-5",
        "0x1.c000000000000p-3",
        "-0x1.6666666666666p-4",
    )

    # 21/40 is the mathematical probe-offset bound.  Binary64 first rounds
    # d=7/20 and then multiplies by 3/2, so these adjacent floats must not be
    # asserted bit-equal by an integrity validator.
    mathematical_level_probe_bound = 21 / 40
    runtime_level_probe_offset = STATE_SCALE[0] * MAX_PROBE_STATE_ABS
    assert mathematical_level_probe_bound.hex() == "0x1.0cccccccccccdp-1"
    assert runtime_level_probe_offset.hex() == "0x1.0ccccccccccccp-1"
    assert mathematical_level_probe_bound != runtime_level_probe_offset
    assert runtime_level_probe_offset < mathematical_level_probe_bound


@pytest.mark.parametrize(
    "bad_state",
    [
        (),
        (0.0,) * 5,
        (0.0,) * 7,
        [0.0, 0.0, 0.0, 0.0, 0.0, _negative_zero()],
        [0.0, 0.0, 0.0, 0.0, 0.0, math.nan],
        [0.0, 0.0, 0.0, 0.0, 0.0, math.inf],
        [0.0, 0.0, 0.0, 0.0, 0.0, -math.inf],
        [0.0, 0.0, 0.0, 0.0, 0.0, 0],
        [0.0, 0.0, 0.0, 0.0, 0.0, False],
        {field_name: 0.0 for field_name in STATE_FIELD_NAMES},
        list(zip(reversed(STATE_FIELD_NAMES), (0.0,) * 6)),
    ],
)
def test_state_validation_rejects_wrong_shape_reordering_and_nonbinary64(
    bad_state: object,
) -> None:
    with pytest.raises(StructuredStateProtocolError):
        validate_state(bad_state)


def test_state_hash_binds_field_order_and_float_hex() -> None:
    state = (0.25, -0.5, 0.75, -1.0, 1.25, -0.125)
    payload = [
        [field_name, value.hex()] for field_name, value in zip(STATE_FIELD_NAMES, state)
    ]
    expected = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
    assert state_sha256(state) == expected
    assert state_sha256(state) != state_sha256(tuple(reversed(state)))


def test_state_payload_roundtrip_rejects_reordering_extras_and_noncanonical_values() -> (
    None
):
    state = (0.25, -0.5, 0.75, -1.0, 1.25, -0.125)
    payload = state_payload(state)
    assert state_from_payload(payload) == state

    reordered = copy.deepcopy(payload)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(StructuredStateProtocolError, match="reordered"):
        state_from_payload(reordered)

    extra = copy.deepcopy(payload)
    extra.append(["task", "0x0.0p+0"])
    with pytest.raises(StructuredStateProtocolError):
        state_from_payload(extra)

    noncanonical = copy.deepcopy(payload)
    noncanonical[0][1] = "0x1p-2"
    with pytest.raises(StructuredStateProtocolError, match="canonical"):
        state_from_payload(noncanonical)

    negative_zero = copy.deepcopy(payload)
    negative_zero[0][1] = "-0x0.0p+0"
    with pytest.raises(StructuredStateProtocolError, match="negative zero"):
        state_from_payload(negative_zero)


def test_sealed_cohort_and_terminal_field_inventory() -> None:
    literal_mapping_bytes = json.dumps(
        _LITERAL_COHORT_ID_AND_LAYER,
        separators=(",", ":"),
    ).encode("utf-8")
    literal_field_order_bytes = json.dumps(
        _LITERAL_ACTION_FIELD_NAMES,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(literal_mapping_bytes).hexdigest() == (
        "dcd1324ad476683afd1ab5546907fde10cbf8539275a971cd474f4edb85465ac"
    )
    assert hashlib.sha256(literal_field_order_bytes).hexdigest() == (
        "233cac7b8d9ef3b109113c2d1295b067dc2d8f18d47c84514ccf6f8e51ea9f24"
    )
    assert COHORT_ID_AND_LAYER == _LITERAL_COHORT_ID_AND_LAYER
    assert ACTION_FIELD_NAMES == _LITERAL_ACTION_FIELD_NAMES
    assert len(COHORT_ID_AND_LAYER) == 36
    assert tuple(row[0] for row in COHORT_ID_AND_LAYER) == tuple(
        sorted(row[0] for row in COHORT_ID_AND_LAYER)
    )
    assert [layer for _, layer in COHORT_ID_AND_LAYER].count(1) == 4
    assert [layer for _, layer in COHORT_ID_AND_LAYER].count(2) == 16
    assert [layer for _, layer in COHORT_ID_AND_LAYER].count(3) == 16
    assert len(ACTION_FIELD_NAMES) == 108
    assert len(set(ACTION_FIELD_NAMES)) == 108
    for cohort_index, (cohort_id, _) in enumerate(COHORT_ID_AND_LAYER):
        assert ACTION_FIELD_NAMES[3 * cohort_index : 3 * cohort_index + 3] == (
            f"{cohort_id}__s12",
            f"{cohort_id}__s24",
            f"{cohort_id}__s36",
        )


def test_all_half_semantic_action_hash_golden() -> None:
    raw = _action_bytes(default_token="5e-1", reversed_fields=True)
    assert semantic_action_sha256(raw) == (
        "5ee0dae8def80e4f8f3e91b384b16f28c18d0591c826d86f599eb2a248dd7dd5"
    )


def test_semantic_hash_ignores_object_order_whitespace_and_equivalent_nonzero_tokens() -> (
    None
):
    plain = _action_bytes(default_token="0.5")
    lexical_variant = _action_bytes(
        default_token="5.0000000000000000e-1", reversed_fields=True
    )
    spaced = lexical_variant.replace(b":", b" : ").replace(b",", b",\n")
    assert semantic_action_sha256(plain) == semantic_action_sha256(lexical_variant)
    assert semantic_action_sha256(plain) == semantic_action_sha256(spaced)
    assert action_bytes_sha256(plain) != action_bytes_sha256(lexical_variant)


def test_semantic_hash_equates_integer_decimal_and_exponent_nonzero_tokens() -> None:
    integer = _action_bytes(default_token="1")
    decimal = _action_bytes(default_token="1.0")
    exponent = _action_bytes(default_token="1e0")
    assert semantic_action_sha256(integer) == semantic_action_sha256(decimal)
    assert semantic_action_sha256(integer) == semantic_action_sha256(exponent)


def test_semantic_hash_preserves_lexical_zero_sign_after_binary64_conversion() -> None:
    field = ACTION_FIELD_NAMES[0]
    positive_forms = ("0", "0.0", "1e-9999")
    negative_forms = ("-0", "-0.0", "-1e-9999")
    positive_hashes = {
        semantic_action_sha256(_action_bytes({field: token}))
        for token in positive_forms
    }
    negative_hashes = {
        semantic_action_sha256(_action_bytes({field: token}))
        for token in negative_forms
    }
    assert len(positive_hashes) == 1
    assert len(negative_hashes) == 1
    assert positive_hashes.isdisjoint(negative_hashes)
    negative_value = parse_semantic_action(_action_bytes({field: "-1e-9999"}))[field]
    assert negative_value == 0.0
    assert math.copysign(1.0, negative_value) < 0.0


def test_semantic_payload_is_fixed_field_order_and_hex_only() -> None:
    raw = _action_bytes(reversed_fields=True)
    payload = semantic_action_payload(raw)
    assert [entry[0] for entry in payload] == list(ACTION_FIELD_NAMES)
    assert {entry[1] for entry in payload} == {float(0.5).hex()}


def test_duplicate_keys_fail_closed() -> None:
    raw = _action_bytes()
    duplicate = raw[:-1] + b"," + json.dumps(ACTION_FIELD_NAMES[0]).encode() + b":0.5}"
    with pytest.raises(StructuredStateProtocolError, match="duplicate JSON key"):
        parse_semantic_action(duplicate)


@pytest.mark.parametrize(
    "bad_raw",
    [
        b"[]",
        b"not json",
        b"\xff",
        _action_bytes({ACTION_FIELD_NAMES[0]: "true"}),
        _action_bytes({ACTION_FIELD_NAMES[0]: "null"}),
        _action_bytes({ACTION_FIELD_NAMES[0]: '"0.5"'}),
        _action_bytes({ACTION_FIELD_NAMES[0]: "{}"}),
        _action_bytes({ACTION_FIELD_NAMES[0]: "[]"}),
        _action_bytes({ACTION_FIELD_NAMES[0]: "NaN"}),
        _action_bytes({ACTION_FIELD_NAMES[0]: "Infinity"}),
        _action_bytes({ACTION_FIELD_NAMES[0]: "-0.01"}),
        _action_bytes({ACTION_FIELD_NAMES[0]: "1.01"}),
        _action_bytes({ACTION_FIELD_NAMES[0]: "1e9999"}),
    ],
)
def test_action_schema_rejects_non_numeric_nested_nonfinite_and_out_of_range(
    bad_raw: bytes,
) -> None:
    with pytest.raises(StructuredStateProtocolError):
        parse_semantic_action(bad_raw)


def test_action_schema_rejects_missing_extra_and_forbidden_fields() -> None:
    valid = _action_bytes()
    first_member_end = valid.index(b",")
    missing = b"{" + valid[first_member_end + 1 :]
    with pytest.raises(StructuredStateProtocolError):
        parse_semantic_action(missing)

    for field_name in FORBIDDEN_BOUNDARY_FIELD_NAMES:
        extra = valid[:-1] + b"," + json.dumps(field_name).encode() + b":0.0}"
        with pytest.raises(StructuredStateProtocolError):
            parse_semantic_action(extra)


def test_zero_state_transform_is_byte_exact_and_bypasses_parse() -> None:
    malformed = b"not even JSON \x00 with task truth poison"
    transformed = transform_action(malformed, POSITIVE_ZERO_STATE)
    assert transformed is malformed
    assert transformed == malformed
    assert action_bytes_sha256(transformed) == action_bytes_sha256(malformed)


def test_nonzero_transform_rejects_schema_poison() -> None:
    raw = _action_bytes()
    poisoned = raw[:-1] + b',"cohort_gt":{"secret":1}}'
    with pytest.raises(StructuredStateProtocolError):
        transform_action(poisoned, (0.25, 0.0, 0.0, 0.0, 0.0, 0.0))


@pytest.mark.parametrize("poison_name", FORBIDDEN_BOUNDARY_FIELD_NAMES)
def test_transform_boundary_poison_top_level_and_nested_fail_closed(
    poison_name: str,
) -> None:
    raw = _action_bytes()
    state = (0.25, 0.0, 0.0, 0.0, 0.0, 0.0)

    top_level = raw[:-1] + b"," + json.dumps(poison_name).encode() + b':{"hidden":1}}'
    with pytest.raises(StructuredStateProtocolError):
        transform_action(top_level, state)

    nested = _action_bytes({ACTION_FIELD_NAMES[0]: json.dumps({poison_name: "hidden"})})
    with pytest.raises(StructuredStateProtocolError):
        transform_action(nested, state)

    # An unexpected call-level field is rejected by the sealed two-argument
    # Python API before the transform can parse or mutate anything.
    with pytest.raises(TypeError):
        transform_action(raw, state, **{poison_name: "hidden"})


@pytest.mark.parametrize("poison_name", FORBIDDEN_BOUNDARY_FIELD_NAMES)
def test_scalar_hex_decoder_rejects_poison_object_as_nonprimitive(
    poison_name: str,
) -> None:
    with pytest.raises(StructuredStateProtocolError):
        decode_scalar_reward_float_hex({poison_name: "hidden"})


def test_transform_preserves_each_positive_and_negative_zero_field() -> None:
    negative_field = "acron_lt2__s12"
    positive_field = "acron_lt2__s24"
    raw = _action_bytes({negative_field: "-0", positive_field: "0"})
    transformed = transform_action(raw, (0.25, 0.25, 0.0, 0.0, 0.0, 0.0))
    action = parse_semantic_action(transformed)
    assert action[negative_field] == 0.0
    assert math.copysign(1.0, action[negative_field]) < 0.0
    assert _is_positive_zero(action[positive_field])


def test_transform_delta_zero_is_field_identity_without_clamp_roundtrip() -> None:
    # layer-1 level is zero, so delta_24 is exactly zero despite nonzero slope.
    field = "acron_lt2__s24"
    raw = _action_bytes({field: "1"})
    transformed = transform_action(raw, (0.0, 0.25, 0.0, 0.0, 0.0, 0.0))
    assert parse_semantic_action(transformed)[field] == 1.0


@pytest.mark.parametrize(
    ("layer", "cohort_id"),
    (
        (1, "acron_lt2"),
        (2, "acron_lt2_prb1_24_28"),
        (3, "acron_high_hhbp_high_prb1_lt25"),
    ),
)
@pytest.mark.parametrize("horizon", (12, 24, 36))
@pytest.mark.parametrize("zero_token", ("0", "-0"))
def test_each_layer_horizon_preserves_each_signed_zero_before_offset(
    layer: int,
    cohort_id: str,
    horizon: int,
    zero_token: str,
) -> None:
    assert dict(_LITERAL_COHORT_ID_AND_LAYER)[cohort_id] == layer
    field_name = f"{cohort_id}__s{horizon}"
    transformed = transform_action(
        _action_bytes({field_name: zero_token}),
        _ASYMMETRIC_CENTER,
    )
    value = parse_semantic_action(transformed)[field_name]
    assert value == 0.0
    expected_sign = -1.0 if zero_token.startswith("-") else 1.0
    assert math.copysign(1.0, value) == expected_sign


@pytest.mark.parametrize(
    ("layer", "cohort_id"),
    (
        (1, "acron_lt2"),
        (2, "acron_lt2_prb1_24_28"),
        (3, "acron_high_hhbp_high_prb1_lt25"),
    ),
)
@pytest.mark.parametrize("horizon", (12, 24, 36))
def test_each_layer_horizon_exact_zero_delta_preserves_one_without_clamp(
    layer: int,
    cohort_id: str,
    horizon: int,
) -> None:
    values = [0.0] * 6
    level_index = 2 * (layer - 1)
    slope_index = level_index + 1
    if horizon == 12:
        values[level_index] = 0.25
        values[slope_index] = -0.75
    elif horizon == 24:
        values[level_index] = 0.0
        values[slope_index] = 0.25
    else:
        values[level_index] = 0.25
        values[slope_index] = 0.75
    state = tuple(values)
    level = STATE_SCALE[level_index] * state[level_index]
    slope = STATE_SCALE[slope_index] * state[slope_index]
    delta = {12: level + slope, 24: level, 36: level - slope}[horizon]
    assert delta.hex() == "0x0.0p+0"

    field_name = f"{cohort_id}__s{horizon}"
    transformed = transform_action(_action_bytes({field_name: "1"}), state)
    assert (
        parse_semantic_action(transformed)[field_name].hex() == "0x1.0000000000000p+0"
    )


def test_one_and_smallest_subnormal_take_registered_clamp_while_zero_does_not() -> None:
    field_name = "acron_lt2__s24"
    state = (0.25, 0.0, 0.0, 0.0, 0.0, 0.0)

    one = parse_semantic_action(
        transform_action(_action_bytes({field_name: "1"}), state)
    )[field_name]
    smallest_subnormal = parse_semantic_action(
        transform_action(_action_bytes({field_name: "5e-324"}), state)
    )[field_name]
    clamp_floor = parse_semantic_action(
        transform_action(_action_bytes({field_name: "0.000001"}), state)
    )[field_name]
    positive_zero = parse_semantic_action(
        transform_action(_action_bytes({field_name: "0"}), state)
    )[field_name]
    negative_zero = parse_semantic_action(
        transform_action(_action_bytes({field_name: "-0"}), state)
    )[field_name]

    assert one.hex() == "0x1.ffffe141bd39bp-1"
    assert smallest_subnormal.hex() == "0x1.24fb559df6f61p-20"
    assert smallest_subnormal == clamp_floor
    assert positive_zero.hex() == "0x0.0p+0"
    assert negative_zero.hex() == "-0x0.0p+0"


def test_equivalent_nonzero_lexical_spellings_transform_to_identical_bytes() -> None:
    state = (0.25, -0.125, 0.5, -0.25, 0.75, -0.375)
    transformed = {
        transform_action(
            _action_bytes(default_token=token, reversed_fields=True),
            state,
        )
        for token in ("0.5", "5e-1", "0.50000000000000000")
    }
    assert len(transformed) == 1


def test_adjacent_binary64_values_and_smallest_subnormal_have_distinct_semantic_hashes() -> (
    None
):
    field_name = ACTION_FIELD_NAMES[0]
    cases = {
        "0.5": "5ee0dae8def80e4f8f3e91b384b16f28c18d0591c826d86f599eb2a248dd7dd5",
        "0.5000000000000001": "f93dfbdd80f3cf0b580864578fb67c9b28b7c009988508ec0f2416ed3c1d8924",
        "0.49999999999999994": "30bcb69a9cec69cfbf28f0b3cac9f4d8132c24380dea3867e0a1cee688ce3574",
        "5e-324": "1b434a32bb23b14066c56f85eb77264646a9706e9bc2e5a90e9a83a0d3cdc862",
        "0": "acc54be309e6839e96c49439d7095e058c55d06b2b2a7b465fccbb2d583396ff",
    }
    observed = {
        token: semantic_action_sha256(_action_bytes({field_name: token}))
        for token in cases
    }
    assert observed == cases
    assert (
        parse_semantic_action(_action_bytes({field_name: "5e-324"}))[field_name].hex()
        == "0x0.0000000000001p-1022"
    )


def test_transform_uses_internal_scale_and_exact_horizon_offsets_without_sort_or_round() -> (
    None
):
    fields = {
        "acron_lt2__s12": "0.2",
        "acron_lt2__s24": "0.8",
        "acron_lt2__s36": "0.5",
    }
    raw = _action_bytes(fields, reversed_fields=True)
    x = (0.5, 0.25, 0.0, 0.0, 0.0, 0.0)
    transformed = transform_action(raw, x)
    action = parse_semantic_action(transformed)

    level = (7.0 / 20.0) * x[0]
    slope = (7.0 / 60.0) * x[1]
    for horizon, probability, delta in (
        (12, 0.2, level + slope),
        (24, 0.8, level),
        (36, 0.5, level - slope),
    ):
        clamped = min(max(probability, 1e-6), 1.0 - 1e-6)
        logit = math.log(clamped / (1.0 - clamped))
        expected = 1.0 / (1.0 + math.exp(-(logit + delta)))
        actual = action[f"acron_lt2__s{horizon}"]
        assert actual == expected
    assert action["acron_lt2__s12"] < action["acron_lt2__s24"]
    assert action["acron_lt2__s12"] != round(action["acron_lt2__s12"], 6)
    assert transformed.startswith(b'{"acron_high_hhbp_high_prb1_lt25__s12":')


def test_nonzero_transform_canonicalizes_but_does_not_mutate_input() -> None:
    raw = _action_bytes(reversed_fields=True)
    before = bytes(raw)
    transformed = transform_action(raw, (0.0, 0.0, 0.25, 0.0, 0.0, 0.0))
    assert raw == before
    assert transformed != raw
    assert len(parse_semantic_action(transformed)) == 108


def test_nonzero_transform_bytes_and_sha_match_independent_literal_golden() -> None:
    raw_token_overrides = {
        "acron_lt2__s12": "-0",
        "age_40_60_voc_gte5__s24": "1",
        "avoc_high_cognitive_low_family_history__s36": "5e-324",
        "family_history_yes__s24": "0.5000000000000001",
        "gg3_voc_lt3__s12": "0.49999999999999994",
    }
    raw = (
        "{"
        + ",".join(
            f'"{field_name}":{raw_token_overrides.get(field_name, "5e-1")}'
            for field_name in reversed(_LITERAL_ACTION_FIELD_NAMES)
        )
        + "}"
    ).encode("utf-8")

    default_value_text = {
        (1, 12): "0.5036457687203291",
        (1, 24): "0.5109357557456443",
        (1, 36): "0.5182210941613646",
        (2, 12): "0.5182210941613646",
        (2, 24): "0.53276547712076",
        (2, 36): "0.5472543839175282",
        (3, 12): "0.53276547712076",
        (3, 24): "0.5544704649604273",
        (3, 36): "0.5759696657584717",
    }
    output_exceptions = {
        "acron_lt2__s12": "-0.0",
        "age_40_60_voc_gte5__s24": "0.9999991230013947",
        "avoc_high_cognitive_low_family_history__s36": "1.3583213578488001e-06",
        "family_history_yes__s24": "0.5109357557456444",
        "gg3_voc_lt3__s12": "0.5182210941613646",
    }
    expected_members: list[str] = []
    for cohort_id, layer in _LITERAL_COHORT_ID_AND_LAYER:
        for horizon in (12, 24, 36):
            field_name = f"{cohort_id}__s{horizon}"
            value_text = output_exceptions.get(
                field_name,
                default_value_text[(layer, horizon)],
            )
            expected_members.append(f'"{field_name}":{value_text}')
    expected_bytes = ("{" + ",".join(expected_members) + "}").encode("utf-8")

    transformed = transform_action(raw, _ASYMMETRIC_CENTER)
    assert transformed == expected_bytes
    assert len(transformed) == 5416
    assert hashlib.sha256(transformed).hexdigest() == (
        "8cd12709e6454a9916292fedbca287c6ef13dc8356651e302f0c5cee544f90f7"
    )
    assert b'"acron_lt2__s12":-0.0' in transformed
    assert b" " not in transformed
    assert b"\n" not in transformed
    assert not transformed.endswith(b"\n")


@pytest.mark.parametrize(
    "bad_state",
    [
        (0.0, 0.0, 0.0, 0.0, 0.0, -0.0),
        (0.0, 0.0, 0.0, 0.0, 0.0, math.nan),
        (0.0, 0.0, 0.0, 0.0, 0.0, 1.5000000000000002),
    ],
)
def test_transform_rejects_invalid_or_out_of_probe_bound_state(
    bad_state: object,
) -> None:
    with pytest.raises(StructuredStateProtocolError):
        transform_action(_action_bytes(), bad_state)


def test_sylvester_h8_u_orthogonality_rank_balance_and_fixed_ids() -> None:
    assert H8 == (
        (1, 1, 1, 1, 1, 1, 1, 1),
        (1, -1, 1, -1, 1, -1, 1, -1),
        (1, 1, -1, -1, 1, 1, -1, -1),
        (1, -1, -1, 1, 1, -1, -1, 1),
        (1, 1, 1, 1, -1, -1, -1, -1),
        (1, -1, 1, -1, -1, 1, -1, 1),
        (1, 1, -1, -1, -1, -1, 1, 1),
        (1, -1, -1, 1, -1, 1, 1, -1),
    )
    assert U == tuple(tuple(row[:6]) for row in H8)
    gram = tuple(
        tuple(
            sum(U[row][left] * U[row][right] for row in range(8)) for right in range(6)
        )
        for left in range(6)
    )
    assert gram == tuple(
        tuple(8 if left == right else 0 for right in range(6)) for left in range(6)
    )
    assert integer_matrix_rank(U) == 6
    assert CANDIDATE_IDS == tuple(
        (f"h{row_index}", sign) for row_index in range(8) for sign in ("+", "-")
    )


def test_sixteen_probe_states_are_unique_centered_balanced_and_bounded() -> None:
    probes = candidate_probe_states(POSITIVE_ZERO_STATE)
    assert tuple(candidate_id for candidate_id, _ in probes) == CANDIDATE_IDS
    assert len({state for _, state in probes}) == 16
    assert all(max(abs(value) for value in state) == RHO for _, state in probes)
    coordinate_sums = tuple(
        sum(state[column] for _, state in probes) for column in range(6)
    )
    assert coordinate_sums == POSITIVE_ZERO_STATE
    assert all(_is_positive_zero(value) for value in coordinate_sums)

    edge = (MAX_OFFICIAL_STATE_ABS,) * 6
    edge_probes = candidate_probe_states(edge)
    assert (
        max(abs(value) for _, state in edge_probes for value in state)
        == MAX_PROBE_STATE_ABS
    )


def test_all_sixteen_asymmetric_candidate_ids_and_state_hex_match_literal_golden() -> (
    None
):
    observed = tuple(
        (candidate_id, tuple(value.hex() for value in state))
        for candidate_id, state in candidate_probe_states(_ASYMMETRIC_CENTER)
    )
    assert observed == _ASYMMETRIC_CANDIDATE_GOLDEN


def test_probe_center_bound_fails_closed_without_clipping() -> None:
    center = (MAX_OFFICIAL_STATE_ABS + ETA, 0.0, 0.0, 0.0, 0.0, 0.0)
    with pytest.raises(StructuredStateProtocolError, match="sealed bound"):
        candidate_probe_states(center)


@pytest.mark.parametrize(
    "value",
    [0.0, -0.0, 1.0, -1.0, math.pi, -123.25, float.fromhex("0x0.0000000000001p-1022")],
)
def test_scalar_reward_hex_roundtrip_is_canonical(value: float) -> None:
    encoded = encode_scalar_reward_float_hex(value)
    decoded = decode_scalar_reward_float_hex(encoded)
    assert decoded.hex() == encoded


@pytest.mark.parametrize(
    "bad_value",
    [
        1.0,
        None,
        {},
        "1.0",
        "0x1p+0",
        "0X1.0000000000000P+0",
        "+0x1.0000000000000p+0",
        " 0x1.0000000000000p+0",
        "0x1.0000000000000p+0 ",
        "nan",
        "inf",
        "-inf",
        "0x1.0000000000000p+999999999999999999999",
    ],
)
def test_scalar_reward_hex_rejects_nonstring_decimal_noncanonical_and_nonfinite(
    bad_value: object,
) -> None:
    with pytest.raises(StructuredStateProtocolError):
        decode_scalar_reward_float_hex(bad_value)


def test_active_lr0_and_pair_reverse_updates() -> None:
    active = sign_es_update(POSITIVE_ZERO_STATE, _updater_payload("closed_loop_active"))
    lr0 = sign_es_update(POSITIVE_ZERO_STATE, _updater_payload("closed_loop_lr0"))
    reverse = sign_es_update(POSITIVE_ZERO_STATE, _updater_payload("pair_sign_reverse"))

    expected_true_direction = (1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    assert active.true_direction == expected_true_direction
    assert active.used_direction == expected_true_direction
    assert active.state_after == (ETA, 0.0, 0.0, 0.0, 0.0, 0.0)
    assert lr0.true_direction == expected_true_direction
    assert lr0.used_direction == expected_true_direction
    assert lr0.state_after == POSITIVE_ZERO_STATE
    assert is_positive_zero_state(lr0.state_after)
    assert reverse.true_direction == expected_true_direction
    assert reverse.used_direction == (-1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    assert reverse.state_after == (-ETA, 0.0, 0.0, 0.0, 0.0, 0.0)


def test_pair_reverse_is_mathematical_negative_for_mixed_signs_and_ties() -> None:
    pair_signs = (1, -1, 0, 1, -1, 1, 0, -1)
    active = sign_es_update(
        POSITIVE_ZERO_STATE,
        _updater_payload("closed_loop_active", pair_signs=pair_signs),
    )
    reverse = sign_es_update(
        POSITIVE_ZERO_STATE,
        _updater_payload("pair_sign_reverse", pair_signs=pair_signs),
    )
    assert reverse.true_direction == active.true_direction
    assert all(
        reverse.used_direction[index] == -active.used_direction[index]
        for index in range(6)
    )
    assert all(
        reverse.state_after[index] == -active.state_after[index] for index in range(6)
    )


def test_six_coordinate_sign_es_direction_active_and_reverse_match_exact_hex_golden() -> (
    None
):
    pair_signs = (1, 1, 1, 1, 1, 0, 1, -1)
    active = sign_es_update(
        _ASYMMETRIC_CENTER,
        _updater_payload(
            "closed_loop_active",
            item_id=13,
            pair_signs=pair_signs,
        ),
    )
    reverse = sign_es_update(
        _ASYMMETRIC_CENTER,
        _updater_payload(
            "pair_sign_reverse",
            item_id=13,
            pair_signs=pair_signs,
        ),
    )
    expected_true_g_hex = (
        "0x1.4000000000000p-1",
        "0x1.8000000000000p-2",
        "0x1.0000000000000p-3",
        "-0x1.0000000000000p-3",
        "0x1.8000000000000p-2",
        "-0x1.8000000000000p-2",
    )
    expected_reverse_g_hex = (
        "-0x1.4000000000000p-1",
        "-0x1.8000000000000p-2",
        "-0x1.0000000000000p-3",
        "0x1.0000000000000p-3",
        "-0x1.8000000000000p-2",
        "0x1.8000000000000p-2",
    )
    expected_active_after_hex = (
        "0x1.5000000000000p-3",
        "-0x1.d000000000000p-3",
        "0x1.8800000000000p-2",
        "-0x1.0400000000000p-1",
        "0x1.4c00000000000p-1",
        "-0x1.8c00000000000p-1",
    )
    expected_reverse_after_hex = (
        "0x1.6000000000000p-4",
        "-0x1.1800000000000p-2",
        "0x1.7800000000000p-2",
        "-0x1.f800000000000p-2",
        "0x1.3400000000000p-1",
        "-0x1.7400000000000p-1",
    )
    assert tuple(value.hex() for value in active.true_direction) == expected_true_g_hex
    assert tuple(value.hex() for value in active.used_direction) == expected_true_g_hex
    assert tuple(value.hex() for value in reverse.true_direction) == expected_true_g_hex
    assert (
        tuple(value.hex() for value in reverse.used_direction) == expected_reverse_g_hex
    )
    assert (
        tuple(value.hex() for value in active.state_after) == expected_active_after_hex
    )
    assert (
        tuple(value.hex() for value in reverse.state_after)
        == expected_reverse_after_hex
    )


def test_exact_ties_produce_positive_zero_direction_without_tolerance() -> None:
    tied = sign_es_update(
        POSITIVE_ZERO_STATE,
        _updater_payload("closed_loop_active", pair_signs=(0,) * 8),
    )
    assert tied.true_direction == POSITIVE_ZERO_STATE
    assert tied.state_after == POSITIVE_ZERO_STATE
    assert is_positive_zero_state(tied.true_direction)

    # One smallest-subnormal difference is nonzero and must not be tolerated away.
    payload = _updater_payload("closed_loop_active")
    rewards = payload["candidate_rewards"]
    assert isinstance(rewards, list)
    rewards[0] = (CANDIDATE_IDS[0], float.fromhex("0x0.0000000000001p-1022"))
    rewards[1] = (CANDIDATE_IDS[1], 0.0)
    update = sign_es_update(POSITIVE_ZERO_STATE, payload)
    assert update.true_direction == (1.0, 0.0, 0.0, 0.0, 0.0, 0.0)


def test_twenty_worst_case_updates_reach_exact_bound_and_probes_reach_probe_bound() -> (
    None
):
    state = POSITIVE_ZERO_STATE
    for item_id in range(1, 21):
        update = sign_es_update(
            state,
            _updater_payload("closed_loop_active", item_id=item_id),
        )
        state = update.state_after
        assert max(abs(value) for value in state) <= item_id / 16.0
    assert state == (MAX_OFFICIAL_STATE_ABS, 0.0, 0.0, 0.0, 0.0, 0.0)
    probes = candidate_probe_states(state)
    assert (
        max(abs(value) for _, probe in probes for value in probe) == MAX_PROBE_STATE_ABS
    )


def test_update_rejects_prospective_bound_violation_instead_of_clipping() -> None:
    too_large_for_item_20 = (MAX_OFFICIAL_STATE_ABS, 0.0, 0.0, 0.0, 0.0, 0.0)
    with pytest.raises(StructuredStateProtocolError, match="prospective item bound"):
        sign_es_update(
            too_large_for_item_20,
            _updater_payload("closed_loop_active", item_id=20),
        )


def test_lr0_rejects_any_nonzero_state_before() -> None:
    with pytest.raises(StructuredStateProtocolError, match="LR0 state_before"):
        sign_es_update(
            (ETA, 0.0, 0.0, 0.0, 0.0, 0.0),
            _updater_payload("closed_loop_lr0", item_id=2),
        )


def test_updater_accepts_only_exact_five_field_schema_and_fixed_candidate_order() -> (
    None
):
    payload = _updater_payload()
    validated = validate_updater_input(payload)
    assert (
        tuple(candidate_id for candidate_id, _ in validated.candidate_rewards)
        == CANDIDATE_IDS
    )

    for field_name in tuple(payload):
        missing = dict(payload)
        del missing[field_name]
        with pytest.raises(StructuredStateProtocolError):
            validate_updater_input(missing)

    extra = dict(payload)
    extra["unexpected"] = 1.0
    with pytest.raises(StructuredStateProtocolError):
        validate_updater_input(extra)

    reordered = copy.deepcopy(payload)
    rewards = reordered["candidate_rewards"]
    assert isinstance(rewards, list)
    rewards[0], rewards[1] = rewards[1], rewards[0]
    with pytest.raises(StructuredStateProtocolError, match="sealed order"):
        validate_updater_input(reordered)


@pytest.mark.parametrize("poison_name", FORBIDDEN_BOUNDARY_FIELD_NAMES)
def test_updater_boundary_poison_top_level_and_nested_fail_closed(
    poison_name: str,
) -> None:
    payload = _updater_payload()
    original = copy.deepcopy(payload)

    top_level = copy.deepcopy(payload)
    top_level[poison_name] = {"hidden": "must not enter updater"}
    with pytest.raises(StructuredStateProtocolError):
        validate_updater_input(top_level)

    nested = copy.deepcopy(payload)
    rewards = nested["candidate_rewards"]
    assert isinstance(rewards, list)
    candidate_id, reward = rewards[0]
    rewards[0] = (candidate_id, reward, {poison_name: "hidden"})
    with pytest.raises(StructuredStateProtocolError):
        validate_updater_input(nested)

    assert payload == original


def test_boundary_poison_callable_is_rejected_without_invocation() -> None:
    called = False

    def poison_callable() -> None:
        nonlocal called
        called = True

    payload = _updater_payload()
    payload["scoring_handle_resolver"] = poison_callable
    with pytest.raises(StructuredStateProtocolError):
        validate_updater_input(payload)
    assert not called


@pytest.mark.parametrize(
    "mutator",
    [
        lambda payload: payload.update(branch_id="closed_loop_rollback"),
        lambda payload: payload.update(item_id=True),
        lambda payload: payload.update(item_id=0),
        lambda payload: payload.update(item_id=21),
        lambda payload: payload.update(precommit_sha256="A" * 64),
        lambda payload: payload.update(scoring_context_sha256="b" * 63),
        lambda payload: payload.update(candidate_rewards=[]),
        lambda payload: payload["candidate_rewards"].__setitem__(
            0, (CANDIDATE_IDS[0], 1)
        ),
        lambda payload: payload["candidate_rewards"].__setitem__(
            0, (CANDIDATE_IDS[0], True)
        ),
        lambda payload: payload["candidate_rewards"].__setitem__(
            0, (CANDIDATE_IDS[0], math.nan)
        ),
        lambda payload: payload["candidate_rewards"].__setitem__(
            0, (CANDIDATE_IDS[0], math.inf)
        ),
        lambda payload: payload["candidate_rewards"].__setitem__(
            0, {"candidate_id": CANDIDATE_IDS[0], "scalar_reward": 1.0}
        ),
        lambda payload: payload["candidate_rewards"].__setitem__(
            0, (("h0", "+", "extra"), 1.0)
        ),
        lambda payload: payload["candidate_rewards"].__setitem__(
            0, (CANDIDATE_IDS[2], 1.0)
        ),
    ],
)
def test_updater_rejects_wrong_types_ranges_hashes_nested_shapes_and_ids(
    mutator,
) -> None:
    payload = _updater_payload()
    mutator(payload)
    with pytest.raises(StructuredStateProtocolError):
        validate_updater_input(payload)


def test_protocol_module_has_no_task_scorer_dgp_or_runner_imports() -> None:
    source = Path(state_protocol.__file__).read_text()
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    assert imported_roots.isdisjoint(
        {"src", "tasks", "scorer", "dgp", "runner", "run_cohort_online_icl"}
    )


def test_pure_module_explicitly_leaves_integration_boundary_poison_to_integration_suite() -> (
    None
):
    """Do not misreport pure primitive tests as end-to-end isolation evidence.

    This suite covers action parsing, T_x arguments, canonical scalar decoding,
    and the updater's exact schema. Raw-policy input, scorer output/process
    isolation, receipt-builder joins, and published-receipt mismatch poison
    require the future runner/integration suite and are intentionally absent.
    """

    integration_only_apis = (
        "raw_policy_boundary",
        "pure_score",
        "build_scalar_receipt",
        "publish_scalar_receipt",
        "validate_receipt_join",
    )
    assert all(not hasattr(state_protocol, name) for name in integration_only_apis)
