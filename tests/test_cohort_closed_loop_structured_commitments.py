from __future__ import annotations

import ast
import base64
import copy
import errno
import hashlib
import json
import math
import os
import stat
from pathlib import Path

import pytest

import cohort_closed_loop_structured_commitments as commitments
from cohort_closed_loop_structured_commitments import (
    CANDIDATE_ACTION_IDS,
    GENESIS_PRECOMMIT_SHA256,
    PRECOMMIT_PROTOCOL,
    SCHEMA_VERSION,
    SHARED_RAW_ACTION_PROTOCOL,
    StructuredCommitmentError,
    atomic_publish_no_overwrite,
    build_precommit_bytes,
    build_scalar_receipt_bytes,
    build_scoring_context_attestation,
    canonical_json_bytes,
    canonical_sha256,
    encode_action_bytes,
    numerical_runtime_identity,
    publish_precommit,
    publish_scalar_receipt,
    validate_complete_receipt_inventory,
    validate_finite_float64_scalar,
    validate_precommit_bytes,
    validate_precommit_digest_sequence,
    validate_precommit_parent_link,
    validate_receipt_request_bytes,
    validate_scoring_context_attestation,
)
from cohort_closed_loop_structured_state import (
    ACTION_FIELD_NAMES,
    POSITIVE_ZERO_STATE,
    RHO,
    STATE_SCALE,
    U,
    candidate_probe_states,
    semantic_action_sha256,
    state_payload,
    state_sha256,
    transform_action,
)


def _sha(index: int) -> str:
    return f"{index:064x}"


def _raw_action() -> bytes:
    return json.dumps(
        {field: 0.5 for field in ACTION_FIELD_NAMES},
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _invocation(
    *,
    branch_id: str,
    item_id: int,
    action_role: str,
    action_id: str,
    action_bytes: bytes,
) -> dict[str, object]:
    return {
        "branch_id": branch_id,
        "item_id": item_id,
        "action_role": action_role,
        "action_id": action_id,
        "semantic_action_sha256": semantic_action_sha256(action_bytes),
        **encode_action_bytes(action_bytes),
    }


def _invocation_ref(branch_id: str, action_role: str, action_id: str) -> dict[str, str]:
    return {
        "branch_id": branch_id,
        "action_role": action_role,
        "action_id": action_id,
    }


def _fixture(
    *,
    family: str = "structured",
    phase: str = "adaptation",
    item_id: int = 1,
    previous_item_precommit_sha256: str | None = None,
    branches: tuple[str, ...] | None = None,
) -> tuple[dict[str, object], bytes, bytes]:
    if branches is None:
        if family == "canonical_online_icl":
            branches = ("canonical_online_icl",)
        elif phase == "adaptation":
            branches = (
                "closed_loop_active",
                "closed_loop_lr0",
                "pair_sign_reverse",
            )
        else:
            branches = (
                "closed_loop_active",
                "closed_loop_lr0",
                "pair_sign_reverse",
                "closed_loop_rollback",
            )
    raw_action = _raw_action()
    raw_unsigned = {
        "object_protocol": SHARED_RAW_ACTION_PROTOCOL,
        **encode_action_bytes(raw_action),
        "semantic_action_sha256": semantic_action_sha256(raw_action),
    }
    shared_raw = {
        **raw_unsigned,
        "shared_raw_action_object_sha256": canonical_sha256(raw_unsigned),
    }

    # Deliberately JSON-looking opaque bytes: the commitment code must hash but
    # never interpret these bytes as a hidden registry/task object.
    opaque_handle = b'{"ground_truth":"opaque-and-unparsed"}'
    opaque_handle_sha256 = hashlib.sha256(opaque_handle).hexdigest()
    scoring_context_sha256 = _sha(101)
    attestation = build_scoring_context_attestation(
        opaque_handle_sha256=opaque_handle_sha256,
        scoring_context_sha256=scoring_context_sha256,
        hidden_registry_entry_sha256=_sha(102),
    )
    attestation_sha256 = hashlib.sha256(attestation).hexdigest()
    context = {
        "opaque_handle_base64": base64.b64encode(opaque_handle).decode("ascii"),
        "opaque_handle_size": len(opaque_handle),
        "opaque_handle_sha256": opaque_handle_sha256,
        "scoring_context_sha256": scoring_context_sha256,
        "scoring_context_attestation_sha256": attestation_sha256,
    }
    join = {
        "block_id": "block-001",
        "item_id": item_id,
        "instance_id": "instance-001",
        "instance_index": item_id - 1,
        "query_sha256": _sha(103),
        "raw_trace_sha256": _sha(104),
        "raw_semantic_action_sha256": raw_unsigned["semantic_action_sha256"],
        "raw_action_bytes_sha256": raw_unsigned["action_bytes_sha256"],
        "scoring_context_sha256": scoring_context_sha256,
        "scoring_context_attestation_sha256": attestation_sha256,
    }

    branch_records: list[dict[str, object]] = []
    invocations: list[dict[str, object]] = []
    state_before = POSITIVE_ZERO_STATE
    probes = candidate_probe_states(state_before)
    for branch_id in branches:
        has_candidates = phase == "adaptation" and branch_id in {
            "closed_loop_active",
            "closed_loop_lr0",
            "pair_sign_reverse",
        }
        official_ref = _invocation_ref(branch_id, "official", "official")
        candidate_refs = (
            [
                _invocation_ref(branch_id, "candidate", action_id)
                for action_id in CANDIDATE_ACTION_IDS
            ]
            if has_candidates
            else []
        )
        probe_records = (
            [
                {
                    "action_id": action_id,
                    "state": state_payload(probe_state),
                    "state_sha256": state_sha256(probe_state),
                }
                for action_id, (_, probe_state) in zip(CANDIDATE_ACTION_IDS, probes)
            ]
            if has_candidates
            else []
        )
        branch_records.append(
            {
                "branch_id": branch_id,
                "shared_raw_action_object_sha256": shared_raw[
                    "shared_raw_action_object_sha256"
                ],
                "state_before": (
                    None
                    if branch_id == "canonical_online_icl"
                    else state_payload(state_before)
                ),
                "state_before_sha256": (
                    None
                    if branch_id == "canonical_online_icl"
                    else state_sha256(state_before)
                ),
                "official_invocation_ref": official_ref,
                "candidate_invocation_refs": candidate_refs,
                "probe_states": probe_records,
            }
        )
        invocations.append(
            _invocation(
                branch_id=branch_id,
                item_id=item_id,
                action_role="official",
                action_id="official",
                action_bytes=raw_action,
            )
        )
        if has_candidates:
            invocations.extend(
                _invocation(
                    branch_id=branch_id,
                    item_id=item_id,
                    action_role="candidate",
                    action_id=action_id,
                    action_bytes=transform_action(raw_action, probe_state),
                )
                for action_id, (_, probe_state) in zip(CANDIDATE_ACTION_IDS, probes)
            )

    inventory_names = (
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
    )
    unsigned: dict[str, object] = {
        "precommit_protocol": PRECOMMIT_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "commitment_family": family,
        "commitment_phase": phase,
        "inventory_sha256": {
            name: _sha(index + 1) for index, name in enumerate(inventory_names)
        },
        "block_id": join["block_id"],
        "item_id": join["item_id"],
        "instance_id": join["instance_id"],
        "instance_index": join["instance_index"],
        "query_sha256": join["query_sha256"],
        "raw_trace_sha256": join["raw_trace_sha256"],
        "shared_join_key": join,
        "shared_raw_action": shared_raw,
        "scoring_context": context,
        "numerical_runtime": numerical_runtime_identity(),
        "probe_design": {
            "d_float_hex": [component.hex() for component in STATE_SCALE],
            "rho_float_hex": RHO.hex(),
            "u": [list(row) for row in U],
        },
        "branch_records": branch_records,
        "invocations": invocations,
        "previous_item_precommit_sha256": (
            previous_item_precommit_sha256
            if previous_item_precommit_sha256 is not None
            else (
                GENESIS_PRECOMMIT_SHA256
                if phase == "adaptation" and item_id == 1
                else _sha(199)
            )
        ),
    }
    return (
        unsigned,
        build_precommit_bytes(unsigned, scoring_context_attestation_bytes=attestation),
        attestation,
    )


def _request(
    unsigned: dict[str, object],
    precommit_bytes: bytes,
    *,
    invocation_index: int = 0,
    reward: float = 1.25,
) -> dict[str, object]:
    precommit = json.loads(precommit_bytes)
    invocation = unsigned["invocations"][invocation_index]
    assert isinstance(invocation, dict)
    return {
        "precommit_sha256": precommit["precommit_sha256"],
        "shared_join_key": copy.deepcopy(unsigned["shared_join_key"]),
        "branch_id": invocation["branch_id"],
        "item_id": invocation["item_id"],
        "action_role": invocation["action_role"],
        "action_id": invocation["action_id"],
        "semantic_action_sha256": invocation["semantic_action_sha256"],
        "action_bytes_sha256": invocation["action_bytes_sha256"],
        "scoring_context_sha256": unsigned["scoring_context"]["scoring_context_sha256"],
        "scoring_context_attestation_sha256": unsigned["scoring_context"][
            "scoring_context_attestation_sha256"
        ],
        "scalar_reward_float_hex": reward.hex(),
    }


def _attestation_from_unsigned(unsigned: dict[str, object]) -> bytes:
    context = unsigned["scoring_context"]
    assert isinstance(context, dict)
    return build_scoring_context_attestation(
        opaque_handle_sha256=str(context["opaque_handle_sha256"]),
        scoring_context_sha256=str(context["scoring_context_sha256"]),
        hidden_registry_entry_sha256=_sha(102),
    )


def _rebuild(unsigned: dict[str, object]) -> bytes:
    return build_precommit_bytes(
        unsigned,
        scoring_context_attestation_bytes=_attestation_from_unsigned(unsigned),
    )


def _caller_id(request: dict[str, object]) -> tuple[object, object, object, object]:
    return (
        request["branch_id"],
        request["item_id"],
        request["action_role"],
        request["action_id"],
    )


def _caller_reward(request: dict[str, object]) -> float:
    return float.fromhex(str(request["scalar_reward_float_hex"]))


def _replace_invocation_action(
    invocation: dict[str, object], action_bytes: bytes
) -> None:
    invocation.update(encode_action_bytes(action_bytes))
    invocation["semantic_action_sha256"] = semantic_action_sha256(action_bytes)


def _set_branch_state(
    unsigned: dict[str, object], branch_id: str, state: tuple[float, ...]
) -> None:
    raw_object = unsigned["shared_raw_action"]
    assert isinstance(raw_object, dict)
    raw_action = base64.b64decode(str(raw_object["action_bytes_base64"]))
    branch = next(
        record
        for record in unsigned["branch_records"]
        if record["branch_id"] == branch_id
    )
    branch["state_before"] = state_payload(state)
    branch["state_before_sha256"] = state_sha256(state)
    candidate_refs = branch["candidate_invocation_refs"]
    probes = candidate_probe_states(state) if candidate_refs else ()
    branch["probe_states"] = [
        {
            "action_id": action_id,
            "state": state_payload(probe_state),
            "state_sha256": state_sha256(probe_state),
        }
        for action_id, (_, probe_state) in zip(CANDIDATE_ACTION_IDS, probes)
    ]
    invocations = [
        invocation
        for invocation in unsigned["invocations"]
        if invocation["branch_id"] == branch_id
    ]
    _replace_invocation_action(invocations[0], transform_action(raw_action, state))
    for invocation, (_, probe_state) in zip(invocations[1:], probes):
        _replace_invocation_action(
            invocation, transform_action(raw_action, probe_state)
        )


def _stage_sequence(item_count: int) -> tuple[list[bytes], list[bytes]]:
    adaptation: list[bytes] = []
    previous = GENESIS_PRECOMMIT_SHA256
    for item_id in range(1, item_count + 1):
        _, raw, _ = _fixture(
            item_id=item_id,
            previous_item_precommit_sha256=previous,
        )
        adaptation.append(raw)
        previous = json.loads(raw)["precommit_sha256"]
    heldout: list[bytes] = []
    for item_id in range(1, item_count + 1):
        _, raw, _ = _fixture(
            phase="held_out",
            item_id=item_id,
            previous_item_precommit_sha256=previous,
        )
        heldout.append(raw)
        previous = json.loads(raw)["precommit_sha256"]
    return adaptation, heldout


def test_source_parses_as_python_310() -> None:
    source = Path(commitments.__file__).read_text(encoding="utf-8")
    ast.parse(source, feature_version=(3, 10))


def test_precommit_and_official_receipt_happy_path_is_opaque() -> None:
    unsigned, precommit_bytes, attestation = _fixture()
    validated = validate_precommit_bytes(precommit_bytes)
    request = _request(unsigned, precommit_bytes)
    request_bytes = canonical_json_bytes(request)
    receipt = build_scalar_receipt_bytes(
        precommit_bytes=precommit_bytes,
        request_bytes=request_bytes,
        scoring_context_attestation_bytes=attestation,
        caller_held_invocation_id=_caller_id(request),
        caller_held_scalar_reward=_caller_reward(request),
    )
    assert receipt == request_bytes
    assert validated.precommit_sha256 == json.loads(precommit_bytes)["precommit_sha256"]
    assert (
        validated.opaque_handle_sha256
        == unsigned["scoring_context"]["opaque_handle_sha256"]
    )
    assert "ground_truth" not in repr(validated)


def test_candidate_receipt_identifies_one_registered_invocation() -> None:
    unsigned, precommit_bytes, attestation = _fixture()
    request = _request(unsigned, precommit_bytes, invocation_index=1)
    assert request["action_role"] == "candidate"
    result = build_scalar_receipt_bytes(
        precommit_bytes=precommit_bytes,
        request_bytes=canonical_json_bytes(request),
        scoring_context_attestation_bytes=attestation,
        caller_held_invocation_id=_caller_id(request),
        caller_held_scalar_reward=_caller_reward(request),
    )
    assert json.loads(result)["action_id"] == "h0+"


def test_precommit_self_digest_is_unsigned_payload_digest() -> None:
    unsigned, raw, _ = _fixture()
    obj = json.loads(raw)
    assert obj["precommit_sha256"] == canonical_sha256(unsigned)
    assert obj["precommit_sha256"] != hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("schema_version",), True),
        (("commitment_family",), "fragment"),
        (("commitment_phase",), "unknown"),
        (("item_id",), True),
        (("instance_index",), -1),
        (("inventory_sha256", "model_sha256"), "A" * 64),
        (("probe_design", "rho_float_hex"), "0x1.0p-1"),
        (("numerical_runtime", "float_mant_dig"), 52),
        (("shared_raw_action", "action_bytes_size"), 1),
        (("shared_raw_action", "semantic_action_sha256"), "f" * 64),
        (("scoring_context", "opaque_handle_size"), 1),
        (("branch_records", 0, "state_before_sha256"), "e" * 64),
        (("branch_records", 0, "probe_states", 0, "action_id"), "h7-"),
        (("invocations", 0, "item_id"), 2),
        (("invocations", 0, "action_bytes_sha256"), "d" * 64),
    ],
)
def test_precommit_typed_mutations_fail_closed(
    path: tuple[object, ...], replacement: object
) -> None:
    unsigned, _, _ = _fixture()
    cursor: object = unsigned
    for part in path[:-1]:
        cursor = cursor[part]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]
    with pytest.raises(StructuredCommitmentError):
        _rebuild(unsigned)


@pytest.mark.parametrize(
    "container_path",
    [
        (),
        ("inventory_sha256",),
        ("shared_join_key",),
        ("shared_raw_action",),
        ("scoring_context",),
        ("numerical_runtime",),
        ("probe_design",),
        ("branch_records", 0),
        ("branch_records", 0, "official_invocation_ref"),
        ("branch_records", 0, "probe_states", 0),
        ("invocations", 0),
    ],
)
def test_nested_extra_or_hidden_poison_fails_closed(
    container_path: tuple[object, ...],
) -> None:
    unsigned, _, _ = _fixture()
    cursor: object = unsigned
    for part in container_path:
        cursor = cursor[part]  # type: ignore[index]
    assert isinstance(cursor, dict)
    cursor["task"] = {"ground_truth": [1, 2, 3]}
    with pytest.raises(StructuredCommitmentError):
        _rebuild(unsigned)


def test_missing_precommit_field_fails_closed() -> None:
    unsigned, _, _ = _fixture()
    del unsigned["inventory_sha256"]["schedule_sha256"]
    with pytest.raises(StructuredCommitmentError):
        _rebuild(unsigned)


def test_duplicate_json_keys_fail_at_top_and_nested_levels() -> None:
    unsigned, raw, _ = _fixture()
    top = raw[:-1] + b',"schema_version":1}'
    with pytest.raises(StructuredCommitmentError, match="duplicate JSON key"):
        validate_precommit_bytes(top)

    nested = raw.replace(
        b'"dgp_sha256":"'
        + bytes(str(unsigned["inventory_sha256"]["dgp_sha256"]), "ascii")
        + b'"',
        b'"dgp_sha256":"'
        + bytes(str(unsigned["inventory_sha256"]["dgp_sha256"]), "ascii")
        + b'","dgp_sha256":"'
        + bytes(str(unsigned["inventory_sha256"]["dgp_sha256"]), "ascii")
        + b'"',
        1,
    )
    with pytest.raises(StructuredCommitmentError, match="duplicate JSON key"):
        validate_precommit_bytes(nested)


def test_noncanonical_precommit_and_receipt_json_fail_closed() -> None:
    unsigned, raw, _ = _fixture()
    pretty = json.dumps(json.loads(raw), indent=2, sort_keys=True).encode("utf-8")
    with pytest.raises(StructuredCommitmentError, match="not canonical"):
        validate_precommit_bytes(pretty)
    request = canonical_json_bytes(_request(unsigned, raw))
    with pytest.raises(StructuredCommitmentError, match="not canonical"):
        validate_receipt_request_bytes(request + b"\n")


def test_base64_must_be_canonical_padded_and_identity_bound() -> None:
    unsigned, _, _ = _fixture()
    encoded = unsigned["scoring_context"]["opaque_handle_base64"]
    assert isinstance(encoded, str) and encoded.endswith("=")
    unsigned["scoring_context"]["opaque_handle_base64"] = encoded.rstrip("=")
    with pytest.raises(StructuredCommitmentError, match="base64"):
        _rebuild(unsigned)


def test_context_attestation_duplicate_extra_and_digest_poison_fail_closed() -> None:
    _, _, attestation = _fixture()
    validate_scoring_context_attestation(
        attestation, expected_file_sha256=hashlib.sha256(attestation).hexdigest()
    )
    duplicate = attestation[:-1] + (
        b',"scoring_context_protocol":"cohort_closed_loop_scoring_context_v1"}'
    )
    with pytest.raises(StructuredCommitmentError, match="duplicate JSON key"):
        validate_scoring_context_attestation(duplicate)
    poisoned = json.loads(attestation)
    poisoned["task"] = {"reference_survival": [1, 2, 3]}
    with pytest.raises(StructuredCommitmentError):
        validate_scoring_context_attestation(canonical_json_bytes(poisoned))
    with pytest.raises(StructuredCommitmentError, match="digest mismatch"):
        validate_scoring_context_attestation(attestation, expected_file_sha256="f" * 64)


def test_shared_raw_action_is_single_object_referenced_by_digest() -> None:
    unsigned, _, _ = _fixture()
    unsigned["branch_records"][0]["shared_raw_action_object_sha256"] = "f" * 64
    with pytest.raises(StructuredCommitmentError, match="raw action reference"):
        _rebuild(unsigned)


def test_branch_and_invocation_order_duplicate_missing_fail_closed() -> None:
    unsigned, _, _ = _fixture()
    swapped = copy.deepcopy(unsigned)
    swapped["branch_records"].reverse()
    with pytest.raises(StructuredCommitmentError, match="registered order"):
        _rebuild(swapped)

    duplicate = copy.deepcopy(unsigned)
    duplicate["invocations"].insert(1, copy.deepcopy(duplicate["invocations"][0]))
    with pytest.raises(StructuredCommitmentError, match="duplicate committed"):
        _rebuild(duplicate)

    missing = copy.deepcopy(unsigned)
    del missing["invocations"][1]
    with pytest.raises(StructuredCommitmentError, match="exactly match"):
        _rebuild(missing)

    missing_branch = copy.deepcopy(unsigned)
    removed_id = missing_branch["branch_records"].pop()["branch_id"]
    missing_branch["invocations"] = [
        invocation
        for invocation in missing_branch["invocations"]
        if invocation["branch_id"] != removed_id
    ]
    with pytest.raises(StructuredCommitmentError, match="missing"):
        _rebuild(missing_branch)

    duplicate_branch = copy.deepcopy(unsigned)
    duplicate_branch["branch_records"].append(
        copy.deepcopy(duplicate_branch["branch_records"][0])
    )
    with pytest.raises(StructuredCommitmentError, match="duplicate branch"):
        _rebuild(duplicate_branch)


def test_phase_controls_exact_candidate_inventory() -> None:
    unsigned, _, _ = _fixture()
    unsigned["commitment_phase"] = "held_out"
    unsigned["previous_item_precommit_sha256"] = _sha(199)
    with pytest.raises(StructuredCommitmentError, match="candidate inventory"):
        _rebuild(unsigned)
    heldout, heldout_raw, _ = _fixture(phase="held_out")
    assert not heldout["branch_records"][0]["candidate_invocation_refs"]
    validate_precommit_bytes(heldout_raw)


def test_reordered_candidate_refs_probes_or_invocations_fail_closed() -> None:
    unsigned, _, _ = _fixture()
    refs = copy.deepcopy(unsigned)
    refs["branch_records"][0]["candidate_invocation_refs"][0:2] = reversed(
        refs["branch_records"][0]["candidate_invocation_refs"][0:2]
    )
    with pytest.raises(StructuredCommitmentError, match="sealed order"):
        _rebuild(refs)

    probes = copy.deepcopy(unsigned)
    probes["branch_records"][0]["probe_states"][0:2] = reversed(
        probes["branch_records"][0]["probe_states"][0:2]
    )
    with pytest.raises(StructuredCommitmentError, match="probe order"):
        _rebuild(probes)

    invocations = copy.deepcopy(unsigned)
    invocations["invocations"][1:3] = reversed(invocations["invocations"][1:3])
    with pytest.raises(StructuredCommitmentError, match="exactly match"):
        _rebuild(invocations)


def test_null_state_is_only_accepted_without_candidates_or_probes() -> None:
    unsigned, _, _ = _fixture()
    unsigned["branch_records"][0]["state_before"] = None
    unsigned["branch_records"][0]["state_before_sha256"] = None
    with pytest.raises(StructuredCommitmentError, match="without a structured state"):
        _rebuild(unsigned)
    _, online_raw, _ = _fixture(family="canonical_online_icl", phase="held_out")
    validate_precommit_bytes(online_raw)


def test_self_consistent_official_and_candidate_action_mutations_fail_tx_recompute() -> (
    None
):
    unsigned, _, _ = _fixture()
    changed_action = json.dumps(
        {
            field: (0.625 if index == 0 else 0.5)
            for index, field in enumerate(ACTION_FIELD_NAMES)
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    official = copy.deepcopy(unsigned)
    _replace_invocation_action(official["invocations"][0], changed_action)
    with pytest.raises(StructuredCommitmentError, match="official action bytes"):
        _rebuild(official)

    candidates = copy.deepcopy(unsigned)
    left = candidates["invocations"][1]
    right = candidates["invocations"][2]
    identity_fields = (
        "action_bytes_base64",
        "action_bytes_size",
        "action_bytes_sha256",
        "semantic_action_sha256",
    )
    left_values = {field: left[field] for field in identity_fields}
    right_values = {field: right[field] for field in identity_fields}
    left.update(right_values)
    right.update(left_values)
    with pytest.raises(StructuredCommitmentError, match="candidate action bytes"):
        _rebuild(candidates)


def test_structured_branch_state_constraints_hold_after_self_consistent_rebuild() -> (
    None
):
    nonzero = (0.125, 0.0, 0.0, 0.0, 0.0, 0.0)

    item1, _, _ = _fixture()
    _set_branch_state(item1, "closed_loop_active", nonzero)
    with pytest.raises(StructuredCommitmentError, match="item-1 state"):
        _rebuild(item1)

    item2, _, _ = _fixture(item_id=2)
    _set_branch_state(item2, "closed_loop_lr0", nonzero)
    with pytest.raises(StructuredCommitmentError, match="LR0 state"):
        _rebuild(item2)

    heldout, _, _ = _fixture(phase="held_out")
    _set_branch_state(heldout, "closed_loop_rollback", nonzero)
    with pytest.raises(StructuredCommitmentError, match="rollback held-out state"):
        _rebuild(heldout)


def test_canonical_online_icl_requires_null_state_no_probes_and_raw_official() -> None:
    unsigned, _, _ = _fixture(family="canonical_online_icl")
    with_state = copy.deepcopy(unsigned)
    branch = with_state["branch_records"][0]
    branch["state_before"] = state_payload(POSITIVE_ZERO_STATE)
    branch["state_before_sha256"] = state_sha256(POSITIVE_ZERO_STATE)
    with pytest.raises(StructuredCommitmentError, match="null state"):
        _rebuild(with_state)

    changed_action = json.dumps(
        {
            field: (0.625 if index == 0 else 0.5)
            for index, field in enumerate(ACTION_FIELD_NAMES)
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    changed = copy.deepcopy(unsigned)
    _replace_invocation_action(changed["invocations"][0], changed_action)
    with pytest.raises(StructuredCommitmentError, match="official action bytes"):
        _rebuild(changed)


def test_genesis_item_index_and_phase_parent_semantics() -> None:
    _, adaptation_item1, _ = _fixture()
    validated = validate_precommit_bytes(adaptation_item1)
    assert validated.previous_item_precommit_sha256 == GENESIS_PRECOMMIT_SHA256

    wrong_genesis, _, _ = _fixture()
    wrong_genesis["previous_item_precommit_sha256"] = _sha(199)
    with pytest.raises(StructuredCommitmentError, match="genesis"):
        _rebuild(wrong_genesis)

    item2, _, _ = _fixture(item_id=2)
    item2["previous_item_precommit_sha256"] = GENESIS_PRECOMMIT_SHA256
    with pytest.raises(StructuredCommitmentError, match="forbidden"):
        _rebuild(item2)

    heldout, _, _ = _fixture(phase="held_out")
    heldout["previous_item_precommit_sha256"] = GENESIS_PRECOMMIT_SHA256
    with pytest.raises(StructuredCommitmentError, match="forbidden"):
        _rebuild(heldout)

    bad_index, _, _ = _fixture()
    bad_index["instance_index"] = 1
    bad_index["shared_join_key"]["instance_index"] = 1
    with pytest.raises(StructuredCommitmentError, match="item_id - 1"):
        _rebuild(bad_index)

    out_of_range, _, _ = _fixture()
    out_of_range["item_id"] = 21
    out_of_range["instance_index"] = 20
    out_of_range["shared_join_key"]["item_id"] = 21
    out_of_range["shared_join_key"]["instance_index"] = 20
    for invocation in out_of_range["invocations"]:
        invocation["item_id"] = 21
    with pytest.raises(StructuredCommitmentError, match=r"\[1,20\]"):
        _rebuild(out_of_range)


def test_precommit_parent_link_adaptation_and_heldout_phase_parent() -> None:
    _, adaptation_item1, _ = _fixture()
    parent_digest = json.loads(adaptation_item1)["precommit_sha256"]
    _, adaptation_item2, _ = _fixture(
        item_id=2, previous_item_precommit_sha256=parent_digest
    )
    validate_precommit_parent_link(
        current_precommit_bytes=adaptation_item2,
        parent_precommit_bytes=adaptation_item1,
    )

    phase_parent_digest = json.loads(adaptation_item2)["precommit_sha256"]
    _, heldout_item1, _ = _fixture(
        phase="held_out", previous_item_precommit_sha256=phase_parent_digest
    )
    validate_precommit_parent_link(
        current_precommit_bytes=heldout_item1,
        parent_precommit_bytes=adaptation_item2,
    )
    heldout_parent_digest = json.loads(heldout_item1)["precommit_sha256"]
    _, heldout_item2, _ = _fixture(
        phase="held_out",
        item_id=2,
        previous_item_precommit_sha256=heldout_parent_digest,
    )
    validate_precommit_parent_link(
        current_precommit_bytes=heldout_item2,
        parent_precommit_bytes=heldout_item1,
    )
    with pytest.raises(StructuredCommitmentError, match="parent digest"):
        validate_precommit_parent_link(
            current_precommit_bytes=heldout_item2,
            parent_precommit_bytes=adaptation_item1,
        )


@pytest.mark.parametrize("item_count", [5, 20])
def test_complete_stage_sequence_validates_smoke_and_formal_terminal_parent(
    item_count: int,
) -> None:
    adaptation, heldout = _stage_sequence(item_count)
    validate_precommit_digest_sequence(
        adaptation_precommit_bytes=adaptation,
        heldout_precommit_bytes=heldout,
        expected_items_per_phase=item_count,
    )


def test_stage_sequence_rejects_wrong_terminal_parent_index_and_phase() -> None:
    adaptation, heldout = _stage_sequence(5)
    wrong_parent_digest = json.loads(adaptation[-2])["precommit_sha256"]
    _, wrong_first_heldout, _ = _fixture(
        phase="held_out",
        previous_item_precommit_sha256=wrong_parent_digest,
    )
    wrong_parent = [wrong_first_heldout, *heldout[1:]]
    with pytest.raises(StructuredCommitmentError, match="parent digest"):
        validate_precommit_digest_sequence(
            adaptation_precommit_bytes=adaptation,
            heldout_precommit_bytes=wrong_parent,
            expected_items_per_phase=5,
        )

    wrong_phase = [adaptation[-1], *heldout[1:]]
    with pytest.raises(StructuredCommitmentError, match="wrong phase"):
        validate_precommit_digest_sequence(
            adaptation_precommit_bytes=adaptation,
            heldout_precommit_bytes=wrong_phase,
            expected_items_per_phase=5,
        )


def test_expected_digest_layer_insufficiency_accepts_explicit_attack_chain() -> None:
    """EXPECTED: digest order alone cannot authorize structured execution.

    This chain contains three independently fatal scientific violations: an
    unreachable item-2 state jump, a held-out state that changes by item, and a
    repeated DGP row.  The digest validator intentionally accepts it because it
    checks only hashes/order.  The future execution validator must reject it.
    """

    adaptation: list[bytes] = []
    previous = GENESIS_PRECOMMIT_SHA256
    for item_id in range(1, 6):
        unsigned, _, _ = _fixture(
            item_id=item_id,
            previous_item_precommit_sha256=previous,
        )
        if item_id >= 2:
            _set_branch_state(
                unsigned,
                "closed_loop_active",
                (1.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            )
        raw = _rebuild(unsigned)
        adaptation.append(raw)
        previous = json.loads(raw)["precommit_sha256"]

    heldout: list[bytes] = []
    for item_id in range(1, 6):
        unsigned, _, _ = _fixture(
            phase="held_out",
            item_id=item_id,
            previous_item_precommit_sha256=previous,
        )
        active_level = 0.25 if item_id % 2 else 0.75
        _set_branch_state(
            unsigned,
            "closed_loop_active",
            (active_level, 0.0, 0.0, 0.0, 0.0, 0.0),
        )
        raw = _rebuild(unsigned)
        heldout.append(raw)
        previous = json.loads(raw)["precommit_sha256"]

    validate_precommit_digest_sequence(
        adaptation_precommit_bytes=adaptation,
        heldout_precommit_bytes=heldout,
        expected_items_per_phase=5,
    )
    adaptation_item2_state = json.loads(adaptation[1])["branch_records"][0][
        "state_before"
    ]
    heldout_active_state_hashes = [
        json.loads(raw)["branch_records"][0]["state_before_sha256"]
        for raw in heldout
    ]
    instance_ids = [
        json.loads(raw)["instance_id"] for raw in [*adaptation, *heldout]
    ]
    assert adaptation_item2_state[0][1] == 1.0.hex()
    assert len(set(heldout_active_state_hashes)) == 2
    assert set(instance_ids) == {"instance-001"}


def test_precommit_builder_requires_matching_attestation_before_publication() -> None:
    unsigned, _, attestation = _fixture()
    changed = json.loads(attestation)
    changed["scoring_context_sha256"] = "f" * 64
    with pytest.raises(StructuredCommitmentError):
        build_precommit_bytes(
            unsigned,
            scoring_context_attestation_bytes=canonical_json_bytes(changed),
        )


def test_precommit_builder_snapshots_nested_aliases_before_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsigned, _, attestation = _fixture()
    original_block = unsigned["block_id"]
    inventory_alias = unsigned["inventory_sha256"]
    original_model_digest = inventory_alias["model_sha256"]
    original_validator = commitments._validate_precommit_object
    calls = 0

    def mutate_caller_after_snapshot(
        value: object, *, require_digest: bool
    ) -> commitments.ValidatedPrecommit:
        nonlocal calls
        calls += 1
        if calls == 1:
            unsigned["block_id"] = "mutated-after-snapshot"
            inventory_alias["model_sha256"] = "f" * 64
        return original_validator(value, require_digest=require_digest)

    monkeypatch.setattr(
        commitments, "_validate_precommit_object", mutate_caller_after_snapshot
    )
    raw = build_precommit_bytes(unsigned, scoring_context_attestation_bytes=attestation)
    published_object = json.loads(raw)
    assert published_object["block_id"] == original_block
    assert published_object["inventory_sha256"]["model_sha256"] == original_model_digest
    unsigned_without_digest = dict(published_object)
    embedded_digest = unsigned_without_digest.pop("precommit_sha256")
    assert embedded_digest == canonical_sha256(unsigned_without_digest)


def test_receipt_scalar_decoder_is_called_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsigned, precommit, attestation = _fixture()
    request = canonical_json_bytes(_request(unsigned, precommit))
    calls = 0
    original = commitments.decode_scalar_reward_float_hex

    def counted(value: object) -> float:
        nonlocal calls
        calls += 1
        return original(value)

    monkeypatch.setattr(commitments, "decode_scalar_reward_float_hex", counted)
    build_scalar_receipt_bytes(
        precommit_bytes=precommit,
        request_bytes=request,
        scoring_context_attestation_bytes=attestation,
        caller_held_invocation_id=_caller_id(json.loads(request)),
        caller_held_scalar_reward=_caller_reward(json.loads(request)),
    )
    assert calls == 1


@pytest.mark.parametrize(
    "caller_reward",
    [0.0, -0.0, 1.2500000000000002, -7.5, 1e300],
)
def test_receipt_rejects_arbitrary_finite_caller_reward_mismatch(
    caller_reward: float,
) -> None:
    unsigned, precommit, attestation = _fixture()
    request = _request(unsigned, precommit, reward=1.25)
    assert caller_reward.hex() != request["scalar_reward_float_hex"]
    with pytest.raises(StructuredCommitmentError, match="caller-held scorer return"):
        build_scalar_receipt_bytes(
            precommit_bytes=precommit,
            request_bytes=canonical_json_bytes(request),
            scoring_context_attestation_bytes=attestation,
            caller_held_invocation_id=_caller_id(request),
            caller_held_scalar_reward=caller_reward,
        )


@pytest.mark.parametrize(
    "caller_id",
    [
        ["closed_loop_active", 1, "official", "official"],
        ("closed_loop_active", True, "official", "official"),
        ({"task": "hidden"}, 1, "official", "official"),
        ("closed_loop_active", 1, "official"),
    ],
)
def test_caller_held_invocation_id_is_exact_primitive_tuple(
    caller_id: object,
) -> None:
    unsigned, precommit, attestation = _fixture()
    request = canonical_json_bytes(_request(unsigned, precommit))
    with pytest.raises(StructuredCommitmentError, match="caller-held invocation ID"):
        build_scalar_receipt_bytes(
            precommit_bytes=precommit,
            request_bytes=request,
            scoring_context_attestation_bytes=attestation,
            caller_held_invocation_id=caller_id,
            caller_held_scalar_reward=_caller_reward(json.loads(request)),
        )


@pytest.mark.parametrize(
    "scalar",
    ["0x1.0p+0", "0X1.0000000000000P+0", "1.0", "nan", "inf", 1.0, None, {}],
)
def test_noncanonical_or_nonscalar_reward_fails_closed(scalar: object) -> None:
    unsigned, precommit, _ = _fixture()
    request = _request(unsigned, precommit)
    request["scalar_reward_float_hex"] = scalar
    with pytest.raises(StructuredCommitmentError):
        validate_receipt_request_bytes(canonical_json_bytes(request))


def test_receipt_duplicate_extra_missing_and_nested_poison_fail_closed() -> None:
    unsigned, precommit, _ = _fixture()
    request = _request(unsigned, precommit)
    raw = canonical_json_bytes(request)
    duplicate = raw[:-1] + b',"item_id":1}'
    with pytest.raises(StructuredCommitmentError, match="duplicate JSON key"):
        validate_receipt_request_bytes(duplicate)

    extra = copy.deepcopy(request)
    extra["task"] = {"ground_truth": 7}
    with pytest.raises(StructuredCommitmentError):
        validate_receipt_request_bytes(canonical_json_bytes(extra))
    missing = copy.deepcopy(request)
    del missing["action_id"]
    with pytest.raises(StructuredCommitmentError):
        validate_receipt_request_bytes(canonical_json_bytes(missing))
    nested = copy.deepcopy(request)
    nested["shared_join_key"]["reference_survival"] = [1, 2]
    with pytest.raises(StructuredCommitmentError):
        validate_receipt_request_bytes(canonical_json_bytes(nested))


@pytest.mark.parametrize(
    ("request_field", "join_field"),
    [
        ("item_id", "item_id"),
        ("scoring_context_sha256", "scoring_context_sha256"),
        (
            "scoring_context_attestation_sha256",
            "scoring_context_attestation_sha256",
        ),
    ],
)
def test_receipt_parser_directly_enforces_join_internal_consistency(
    request_field: str, join_field: str
) -> None:
    unsigned, precommit, _ = _fixture()
    request = _request(unsigned, precommit)
    request[request_field] = 2 if request_field == "item_id" else "f" * 64
    assert request[request_field] != request["shared_join_key"][join_field]
    with pytest.raises(StructuredCommitmentError, match="shared"):
        validate_receipt_request_bytes(canonical_json_bytes(request))


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("precommit_sha256",), "f" * 64),
        (("branch_id",), "closed_loop_lr0"),
        (("item_id",), 2),
        (("action_role",), "candidate"),
        (("action_id",), "h0+"),
        (("semantic_action_sha256",), "f" * 64),
        (("action_bytes_sha256",), "e" * 64),
        (("scoring_context_sha256",), "d" * 64),
        (("scoring_context_attestation_sha256",), "c" * 64),
        (("shared_join_key", "instance_id"), "instance-002"),
        (("shared_join_key", "item_id"), 2),
        (("shared_join_key", "scoring_context_sha256"), "b" * 64),
    ],
)
def test_receipt_metadata_hash_and_join_mutations_fail_closed(
    path: tuple[object, ...], replacement: object
) -> None:
    unsigned, precommit, attestation = _fixture()
    request = _request(unsigned, precommit)
    cursor: object = request
    for part in path[:-1]:
        cursor = cursor[part]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]
    with pytest.raises(StructuredCommitmentError):
        build_scalar_receipt_bytes(
            precommit_bytes=precommit,
            request_bytes=canonical_json_bytes(request),
            scoring_context_attestation_bytes=attestation,
            caller_held_invocation_id=(
                "closed_loop_active",
                1,
                "official",
                "official",
            ),
            caller_held_scalar_reward=_caller_reward(request),
        )


def test_swapped_candidate_receipt_does_not_join_by_duplicate_action_bytes() -> None:
    unsigned, precommit, attestation = _fixture()
    request = _request(unsigned, precommit, invocation_index=1)
    request["action_id"] = "h0-"
    with pytest.raises(StructuredCommitmentError, match="caller-held invocation ID"):
        build_scalar_receipt_bytes(
            precommit_bytes=precommit,
            request_bytes=canonical_json_bytes(request),
            scoring_context_attestation_bytes=attestation,
            caller_held_invocation_id=(
                "closed_loop_active",
                1,
                "candidate",
                "h0+",
            ),
            caller_held_scalar_reward=_caller_reward(request),
        )


def test_changed_context_attestation_fails_without_hidden_resolution() -> None:
    unsigned, precommit, attestation = _fixture()
    request = canonical_json_bytes(_request(unsigned, precommit))
    changed = bytearray(attestation)
    changed[-2] = ord("0") if changed[-2] != ord("0") else ord("1")
    with pytest.raises(StructuredCommitmentError):
        build_scalar_receipt_bytes(
            precommit_bytes=precommit,
            request_bytes=request,
            scoring_context_attestation_bytes=bytes(changed),
            caller_held_invocation_id=_caller_id(json.loads(request)),
            caller_held_scalar_reward=_caller_reward(json.loads(request)),
        )


def test_complete_receipt_inventory_rejects_missing_duplicate_and_swapped() -> None:
    unsigned, precommit, attestation = _fixture()
    receipts = [
        canonical_json_bytes(
            _request(unsigned, precommit, invocation_index=index, reward=float(index))
        )
        for index in range(len(unsigned["invocations"]))
    ]
    validated = validate_complete_receipt_inventory(
        precommit_bytes=precommit,
        receipt_bytes=receipts,
        scoring_context_attestation_bytes=attestation,
    )
    assert len(validated) == len(unsigned["invocations"])

    with pytest.raises(StructuredCommitmentError, match="missing"):
        validate_complete_receipt_inventory(
            precommit_bytes=precommit,
            receipt_bytes=receipts[:-1],
            scoring_context_attestation_bytes=attestation,
        )
    duplicate = list(receipts)
    duplicate[1] = duplicate[0]
    with pytest.raises(StructuredCommitmentError, match="duplicate"):
        validate_complete_receipt_inventory(
            precommit_bytes=precommit,
            receipt_bytes=duplicate,
            scoring_context_attestation_bytes=attestation,
        )
    swapped = list(receipts)
    swapped[0], swapped[17] = swapped[17], swapped[0]
    with pytest.raises(StructuredCommitmentError, match="invocation mismatch"):
        validate_complete_receipt_inventory(
            precommit_bytes=precommit,
            receipt_bytes=swapped,
            scoring_context_attestation_bytes=attestation,
        )


@pytest.mark.parametrize(
    "value", [1, True, math.nan, math.inf, -math.inf, {}, object()]
)
def test_pure_scalar_return_validator_exposes_no_scorer_surface(value: object) -> None:
    with pytest.raises(StructuredCommitmentError):
        validate_finite_float64_scalar(value)
    assert validate_finite_float64_scalar(-0.0) == 0.0


def test_atomic_publish_hard_link_contract_and_reread(tmp_path: Path) -> None:
    final = tmp_path / "commitment.json"
    payload = b'{"sealed":true}'
    published = atomic_publish_no_overwrite(final, payload)
    assert final.read_bytes() == payload
    result_stat = final.stat()
    assert result_stat.st_nlink == 1
    assert stat.S_IMODE(result_stat.st_mode) == 0o444
    assert published.inode == result_stat.st_ino
    assert published.sha256 == hashlib.sha256(payload).hexdigest()
    assert not list(tmp_path.glob(".*.tmp"))


def test_atomic_publish_never_overwrites_existing_final_and_leaves_evidence(
    tmp_path: Path,
) -> None:
    final = tmp_path / "commitment.json"
    final.write_bytes(b"original")
    with pytest.raises(FileExistsError) as error:
        atomic_publish_no_overwrite(final, b"replacement")
    assert error.value.errno == errno.EEXIST
    assert final.read_bytes() == b"original"
    temps = list(tmp_path.glob(".commitment.json.commit-*.tmp"))
    assert len(temps) == 1
    assert temps[0].read_bytes() == b"replacement"


def test_atomic_publish_post_link_failure_keeps_final_and_temp_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    final = tmp_path / "commitment.json"
    original_fsync = os.fsync
    calls = 0

    def fail_second_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected directory fsync failure")
        original_fsync(fd)

    monkeypatch.setattr(commitments.os, "fsync", fail_second_fsync)
    with pytest.raises(OSError, match="injected"):
        atomic_publish_no_overwrite(final, b"permanent evidence")
    assert final.read_bytes() == b"permanent evidence"
    temps = list(tmp_path.glob(".commitment.json.commit-*.tmp"))
    assert len(temps) == 1
    assert os.stat(final).st_ino == os.stat(temps[0]).st_ino
    assert os.stat(final).st_nlink == 2


def test_atomic_publish_detects_parent_identity_swap_before_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    final = tmp_path / "commitment.json"
    original = commitments._assert_parent_path_identity
    calls = 0

    def fail_second(path: Path, expected: os.stat_result) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise StructuredCommitmentError("publication ancestor path was swapped")
        original(path, expected)

    monkeypatch.setattr(commitments, "_assert_parent_path_identity", fail_second)
    with pytest.raises(StructuredCommitmentError, match="swapped"):
        atomic_publish_no_overwrite(final, b"evidence")
    assert not final.exists()
    assert len(list(tmp_path.glob(".commitment.json.commit-*.tmp"))) == 1


def test_atomic_publish_rechecks_parent_after_final_reread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    final = tmp_path / "commitment.json"
    original = commitments._assert_parent_path_identity
    calls = 0

    def mutate_after_last_parent_check(path: Path, expected: os.stat_result) -> None:
        nonlocal calls
        calls += 1
        original(path, expected)
        if calls == 5:
            path.chmod(0o644)

    monkeypatch.setattr(
        commitments,
        "_assert_parent_path_identity",
        mutate_after_last_parent_check,
    )
    with pytest.raises(StructuredCommitmentError, match="basename identity"):
        atomic_publish_no_overwrite(final, b"permanent-final-evidence")
    assert final.read_bytes() == b"permanent-final-evidence"
    assert not list(tmp_path.glob(".commitment.json.commit-*.tmp"))


def test_atomic_publish_rejects_relative_and_symlinked_ancestor(
    tmp_path: Path,
) -> None:
    with pytest.raises(StructuredCommitmentError, match="absolute"):
        atomic_publish_no_overwrite(Path("relative.json"), b"x")
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises((StructuredCommitmentError, OSError)):
        atomic_publish_no_overwrite(alias / "commitment.json", b"x")
    assert not (real / "commitment.json").exists()


def test_existing_final_symlink_is_not_followed_or_replaced(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"target")
    final = tmp_path / "commitment.json"
    final.symlink_to(target)
    with pytest.raises(FileExistsError):
        atomic_publish_no_overwrite(final, b"replacement")
    assert target.read_bytes() == b"target"
    assert final.is_symlink()


def test_publish_precommit_and_receipt_reread_immutable_inputs(tmp_path: Path) -> None:
    unsigned, precommit, attestation = _fixture()
    precommit_path = tmp_path / "precommit.json"
    attestation_path = tmp_path / "attestation.json"
    receipt_path = tmp_path / "receipt.json"
    published_precommit = publish_precommit(
        precommit_path,
        unsigned,
        scoring_context_attestation_bytes=attestation,
    )
    assert precommit_path.read_bytes() == precommit
    atomic_publish_no_overwrite(attestation_path, attestation)
    request = canonical_json_bytes(_request(unsigned, precommit))
    published_receipt = publish_scalar_receipt(
        precommit_path=precommit_path,
        request_bytes=request,
        scoring_context_attestation_path=attestation_path,
        receipt_path=receipt_path,
        caller_held_invocation_id=_caller_id(json.loads(request)),
        caller_held_scalar_reward=_caller_reward(json.loads(request)),
    )
    assert published_precommit.size == len(precommit)
    assert published_receipt.size == len(request)
    assert receipt_path.read_bytes() == request
    with pytest.raises(FileExistsError):
        publish_scalar_receipt(
            precommit_path=precommit_path,
            request_bytes=request,
            scoring_context_attestation_path=attestation_path,
            receipt_path=receipt_path,
            caller_held_invocation_id=_caller_id(json.loads(request)),
            caller_held_scalar_reward=_caller_reward(json.loads(request)),
        )


def test_receipt_input_symlink_is_rejected(tmp_path: Path) -> None:
    unsigned, precommit, attestation = _fixture()
    real_precommit = tmp_path / "precommit.real.json"
    atomic_publish_no_overwrite(real_precommit, precommit)
    symlink = tmp_path / "precommit.json"
    symlink.symlink_to(real_precommit)
    attestation_path = tmp_path / "attestation.json"
    atomic_publish_no_overwrite(attestation_path, attestation)
    with pytest.raises(OSError):
        publish_scalar_receipt(
            precommit_path=symlink,
            request_bytes=canonical_json_bytes(_request(unsigned, precommit)),
            scoring_context_attestation_path=attestation_path,
            receipt_path=tmp_path / "receipt.json",
            caller_held_invocation_id=(
                "closed_loop_active",
                1,
                "official",
                "official",
            ),
            caller_held_scalar_reward=1.25,
        )


def test_receipt_rejects_mutable_precommit_mode(tmp_path: Path) -> None:
    unsigned, precommit, attestation = _fixture()
    precommit_path = tmp_path / "precommit.json"
    attestation_path = tmp_path / "attestation.json"
    atomic_publish_no_overwrite(precommit_path, precommit)
    atomic_publish_no_overwrite(attestation_path, attestation)
    precommit_path.chmod(0o644)
    request = _request(unsigned, precommit)
    with pytest.raises(StructuredCommitmentError, match="mode"):
        publish_scalar_receipt(
            precommit_path=precommit_path,
            request_bytes=canonical_json_bytes(request),
            scoring_context_attestation_path=attestation_path,
            receipt_path=tmp_path / "receipt.json",
            caller_held_invocation_id=_caller_id(request),
            caller_held_scalar_reward=_caller_reward(request),
        )


def test_receipt_read_rechecks_parent_identity_after_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unsigned, precommit, attestation = _fixture()
    precommit_path = tmp_path / "precommit.json"
    attestation_path = tmp_path / "attestation.json"
    atomic_publish_no_overwrite(precommit_path, precommit)
    atomic_publish_no_overwrite(attestation_path, attestation)
    request = _request(unsigned, precommit)
    original = commitments._assert_parent_path_identity
    calls = 0

    def mutate_after_second_parent_check(path: Path, expected: os.stat_result) -> None:
        nonlocal calls
        calls += 1
        original(path, expected)
        if calls == 2:
            path.chmod(0o644)

    monkeypatch.setattr(
        commitments,
        "_assert_parent_path_identity",
        mutate_after_second_parent_check,
    )
    receipt_path = tmp_path / "receipt.json"
    with pytest.raises(StructuredCommitmentError, match="basename identity"):
        publish_scalar_receipt(
            precommit_path=precommit_path,
            request_bytes=canonical_json_bytes(request),
            scoring_context_attestation_path=attestation_path,
            receipt_path=receipt_path,
            caller_held_invocation_id=_caller_id(request),
            caller_held_scalar_reward=_caller_reward(request),
        )
    assert not receipt_path.exists()
