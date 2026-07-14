from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import math
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

import cohort_closed_loop_structured_execution_validation as execution
from cohort_closed_loop_structured_commitments import (
    CANDIDATE_ACTION_IDS,
    GENESIS_PRECOMMIT_SHA256,
    PRECOMMIT_PROTOCOL,
    SCHEMA_VERSION,
    SHARED_RAW_ACTION_PROTOCOL,
    StructuredCommitmentError,
    build_precommit_bytes,
    build_scoring_context_attestation,
    canonical_json_bytes,
    canonical_sha256,
    encode_action_bytes,
    numerical_runtime_identity,
)
from cohort_closed_loop_structured_execution_validation import (
    StructuredExecutionValidationError,
    validate_structured_stage_execution,
)
from cohort_closed_loop_structured_state import (
    ACTION_FIELD_NAMES,
    ETA,
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


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _raw_action(probability: float) -> bytes:
    return json.dumps(
        {field: probability for field in ACTION_FIELD_NAMES},
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _invocation_ref(branch_id: str, role: str, action_id: str) -> dict[str, str]:
    return {"branch_id": branch_id, "action_role": role, "action_id": action_id}


def _invocation(
    branch_id: str,
    item_id: int,
    role: str,
    action_id: str,
    action_bytes: bytes,
) -> dict[str, object]:
    return {
        "branch_id": branch_id,
        "item_id": item_id,
        "action_role": role,
        "action_id": action_id,
        "semantic_action_sha256": semantic_action_sha256(action_bytes),
        **encode_action_bytes(action_bytes),
    }


def _context(phase: str, item_id: int) -> tuple[dict[str, object], bytes]:
    opaque = f"opaque:{phase}:{item_id}".encode()
    opaque_sha = hashlib.sha256(opaque).hexdigest()
    context_sha = _sha(f"context:{phase}:{item_id}")
    attestation = build_scoring_context_attestation(
        opaque_handle_sha256=opaque_sha,
        scoring_context_sha256=context_sha,
        hidden_registry_entry_sha256=_sha(f"hidden:{phase}:{item_id}"),
    )
    return (
        {
            "opaque_handle_base64": base64.b64encode(opaque).decode("ascii"),
            "opaque_handle_size": len(opaque),
            "opaque_handle_sha256": opaque_sha,
            "scoring_context_sha256": context_sha,
            "scoring_context_attestation_sha256": hashlib.sha256(
                attestation
            ).hexdigest(),
        },
        attestation,
    )


def _precommit(
    *,
    family: str,
    phase: str,
    item_id: int,
    previous_sha256: str,
    states: dict[str, tuple[float, ...]],
    raw_action: bytes,
    context: dict[str, object],
    attestation: bytes,
    canonical_join_mismatch: bool = False,
    inventory_overrides: dict[str, str] | None = None,
) -> tuple[dict[str, object], bytes]:
    raw_unsigned = {
        "object_protocol": SHARED_RAW_ACTION_PROTOCOL,
        **encode_action_bytes(raw_action),
        "semantic_action_sha256": semantic_action_sha256(raw_action),
    }
    raw_object = {
        **raw_unsigned,
        "shared_raw_action_object_sha256": canonical_sha256(raw_unsigned),
    }
    block_id = "block-001"
    instance_id = f"instance-{phase}-{item_id:02d}"
    query_sha256 = _sha(f"query:{phase}:{item_id}")
    if canonical_join_mismatch:
        query_sha256 = _sha(f"wrong-query:{phase}:{item_id}")
    trace_family = "canonical" if family == "canonical_online_icl" else "structured"
    shared_join = {
        "block_id": block_id,
        "item_id": item_id,
        "instance_id": instance_id,
        "instance_index": item_id - 1,
        "query_sha256": query_sha256,
        "raw_trace_sha256": _sha(f"trace:{trace_family}:{phase}:{item_id}"),
        "raw_semantic_action_sha256": raw_unsigned["semantic_action_sha256"],
        "raw_action_bytes_sha256": raw_unsigned["action_bytes_sha256"],
        "scoring_context_sha256": context["scoring_context_sha256"],
        "scoring_context_attestation_sha256": context[
            "scoring_context_attestation_sha256"
        ],
    }
    if family == "canonical_online_icl":
        branches = ("canonical_online_icl",)
    elif phase == "adaptation":
        branches = execution.STRUCTURED_ADAPTATION_BRANCHES
    else:
        branches = execution.STRUCTURED_HELDOUT_BRANCHES

    branch_records: list[dict[str, object]] = []
    invocations: list[dict[str, object]] = []
    for branch_id in branches:
        is_canonical = branch_id == "canonical_online_icl"
        has_candidates = phase == "adaptation" and not is_canonical
        state = None if is_canonical else states[branch_id]
        probes = candidate_probe_states(state) if has_candidates else ()
        branch_records.append(
            {
                "branch_id": branch_id,
                "shared_raw_action_object_sha256": raw_object[
                    "shared_raw_action_object_sha256"
                ],
                "state_before": None if state is None else state_payload(state),
                "state_before_sha256": None if state is None else state_sha256(state),
                "official_invocation_ref": _invocation_ref(
                    branch_id, "official", "official"
                ),
                "candidate_invocation_refs": [
                    _invocation_ref(branch_id, "candidate", action_id)
                    for action_id in CANDIDATE_ACTION_IDS
                ]
                if has_candidates
                else [],
                "probe_states": [
                    {
                        "action_id": action_id,
                        "state": state_payload(probe_state),
                        "state_sha256": state_sha256(probe_state),
                    }
                    for action_id, (_, probe_state) in zip(
                        CANDIDATE_ACTION_IDS, probes
                    )
                ],
            }
        )
        official_action = raw_action if state is None else transform_action(raw_action, state)
        invocations.append(
            _invocation(branch_id, item_id, "official", "official", official_action)
        )
        invocations.extend(
            _invocation(
                branch_id,
                item_id,
                "candidate",
                action_id,
                transform_action(raw_action, probe_state),
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
    static_names = {
        "model_sha256",
        "tokenizer_sha256",
        "environment_sha256",
        "task_sha256",
        "schema_sha256",
        "cohort_layer_inventory_sha256",
    }
    phase_names = {"dgp_sha256", "schedule_sha256", "condition_order_sha256"}
    inventory: dict[str, str] = {}
    for name in inventory_names:
        if name in static_names:
            inventory[name] = _sha(name)
        elif name in phase_names:
            inventory[name] = _sha(f"{name}:{phase}")
        else:
            inventory[name] = _sha(f"{name}:{family}")
    if inventory_overrides is not None:
        inventory.update(inventory_overrides)
    unsigned: dict[str, object] = {
        "precommit_protocol": PRECOMMIT_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "commitment_family": family,
        "commitment_phase": phase,
        "inventory_sha256": inventory,
        "block_id": block_id,
        "item_id": item_id,
        "instance_id": instance_id,
        "instance_index": item_id - 1,
        "query_sha256": query_sha256,
        "raw_trace_sha256": shared_join["raw_trace_sha256"],
        "shared_join_key": shared_join,
        "shared_raw_action": raw_object,
        "scoring_context": copy.deepcopy(context),
        "numerical_runtime": numerical_runtime_identity(),
        "probe_design": {
            "d_float_hex": [value.hex() for value in STATE_SCALE],
            "rho_float_hex": RHO.hex(),
            "u": [list(row) for row in U],
        },
        "branch_records": branch_records,
        "invocations": invocations,
        "previous_item_precommit_sha256": previous_sha256,
    }
    return unsigned, build_precommit_bytes(
        unsigned, scoring_context_attestation_bytes=attestation
    )


def _reward_for_invocation(
    invocation: dict[str, object],
    *,
    phase: str,
    item_id: int,
    zero_signal: tuple[str, int] | None,
    official_reward: float,
) -> float:
    branch_id = str(invocation["branch_id"])
    if invocation["action_role"] == "official":
        if phase == "held_out" and branch_id in {
            "closed_loop_lr0",
            "closed_loop_rollback",
        }:
            return 0.75
        return official_reward
    if zero_signal == (branch_id, item_id):
        return 0.0
    action_id = str(invocation["action_id"])
    return 1.0 if action_id.endswith("+") else -1.0


def _receipts(
    *,
    unsigned: dict[str, object],
    precommit: bytes,
    phase: str,
    item_id: int,
    zero_signal: tuple[str, int] | None,
    official_reward: float,
) -> tuple[bytes, ...]:
    precommit_object = json.loads(precommit)
    result: list[bytes] = []
    for invocation in unsigned["invocations"]:
        reward = _reward_for_invocation(
            invocation,
            phase=phase,
            item_id=item_id,
            zero_signal=zero_signal,
            official_reward=official_reward,
        )
        result.append(
            canonical_json_bytes(
                {
                    "precommit_sha256": precommit_object["precommit_sha256"],
                    "shared_join_key": copy.deepcopy(unsigned["shared_join_key"]),
                    "branch_id": invocation["branch_id"],
                    "item_id": invocation["item_id"],
                    "action_role": invocation["action_role"],
                    "action_id": invocation["action_id"],
                    "semantic_action_sha256": invocation["semantic_action_sha256"],
                    "action_bytes_sha256": invocation["action_bytes_sha256"],
                    "scoring_context_sha256": unsigned["scoring_context"][
                        "scoring_context_sha256"
                    ],
                    "scoring_context_attestation_sha256": unsigned[
                        "scoring_context"
                    ]["scoring_context_attestation_sha256"],
                    "scalar_reward_float_hex": reward.hex(),
                }
            )
        )
    return tuple(result)


def _next_states(
    states: dict[str, tuple[float, ...]],
    *,
    item_id: int,
    zero_signal: tuple[str, int] | None,
) -> dict[str, tuple[float, ...]]:
    result: dict[str, tuple[float, ...]] = {}
    for branch_id in execution.STRUCTURED_ADAPTATION_BRANCHES:
        direction = 0.0 if zero_signal == (branch_id, item_id) else 1.0
        if branch_id == "closed_loop_lr0":
            result[branch_id] = POSITIVE_ZERO_STATE
        else:
            used = -direction if branch_id == "pair_sign_reverse" else direction
            result[branch_id] = (
                states[branch_id][0] + ETA * used,
                *states[branch_id][1:],
            )
    return result


def _build_stage(
    *,
    zero_signal: tuple[str, int] | None = None,
    zero_action_item: int | None = None,
    state_override: tuple[str, str, int, tuple[float, ...]] | None = None,
    canonical_join_mismatch: tuple[str, int] | None = None,
    official_reward: float = 0.25,
    family_inventory_overrides: dict[tuple[str, str], str] | None = None,
    item_inventory_overrides: dict[tuple[str, str, int, str], str] | None = None,
    phase_collision_keys: tuple[str, ...] = (),
) -> dict[str, object]:
    count = 5
    structured_precommits: dict[str, list[bytes]] = {
        "adaptation": [],
        "held_out": [],
    }
    structured_receipts: dict[str, list[tuple[bytes, ...]]] = {
        "adaptation": [],
        "held_out": [],
    }
    canonical_precommits: dict[str, list[bytes]] = {
        "adaptation": [],
        "held_out": [],
    }
    canonical_receipts: dict[str, list[tuple[bytes, ...]]] = {
        "adaptation": [],
        "held_out": [],
    }
    attestations: dict[str, list[bytes]] = {"adaptation": [], "held_out": []}

    def inventory_overrides(
        family: str, phase: str, item_id: int
    ) -> dict[str, str]:
        result = {
            key: value
            for (target_family, key), value in (family_inventory_overrides or {}).items()
            if target_family == family
        }
        result.update(
            {
                key: value
                for (
                    target_family,
                    target_phase,
                    target_item,
                    key,
                ), value in (item_inventory_overrides or {}).items()
                if (
                    target_family == family
                    and target_phase == phase
                    and target_item == item_id
                )
            }
        )
        if phase == "held_out":
            result.update(
                {key: _sha(f"{key}:adaptation") for key in phase_collision_keys}
            )
        return result

    states = {
        branch_id: POSITIVE_ZERO_STATE
        for branch_id in execution.STRUCTURED_ADAPTATION_BRANCHES
    }
    structured_previous = GENESIS_PRECOMMIT_SHA256
    canonical_previous = GENESIS_PRECOMMIT_SHA256
    for item_id in range(1, count + 1):
        context, attestation = _context("adaptation", item_id)
        attestations["adaptation"].append(attestation)
        item_states = dict(states)
        if state_override is not None and state_override[:3] == (
            "adaptation",
            state_override[1],
            item_id,
        ):
            item_states[state_override[1]] = state_override[3]
        raw_probability = 0.0 if zero_action_item == item_id else 0.5
        unsigned, precommit = _precommit(
            family="structured",
            phase="adaptation",
            item_id=item_id,
            previous_sha256=structured_previous,
            states=item_states,
            raw_action=_raw_action(raw_probability),
            context=context,
            attestation=attestation,
            inventory_overrides=inventory_overrides(
                "structured", "adaptation", item_id
            ),
        )
        structured_precommits["adaptation"].append(precommit)
        structured_receipts["adaptation"].append(
            _receipts(
                unsigned=unsigned,
                precommit=precommit,
                phase="adaptation",
                item_id=item_id,
                zero_signal=zero_signal,
                official_reward=official_reward,
            )
        )
        structured_previous = json.loads(precommit)["precommit_sha256"]

        canonical_unsigned, canonical_precommit = _precommit(
            family="canonical_online_icl",
            phase="adaptation",
            item_id=item_id,
            previous_sha256=canonical_previous,
            states={},
            raw_action=_raw_action(0.6),
            context=context,
            attestation=attestation,
            canonical_join_mismatch=canonical_join_mismatch == (
                "adaptation",
                item_id,
            ),
            inventory_overrides=inventory_overrides(
                "canonical_online_icl", "adaptation", item_id
            ),
        )
        canonical_precommits["adaptation"].append(canonical_precommit)
        canonical_receipts["adaptation"].append(
            _receipts(
                unsigned=canonical_unsigned,
                precommit=canonical_precommit,
                phase="adaptation",
                item_id=item_id,
                zero_signal=None,
                official_reward=official_reward,
            )
        )
        canonical_previous = json.loads(canonical_precommit)["precommit_sha256"]
        states = _next_states(states, item_id=item_id, zero_signal=zero_signal)

    terminal_states = dict(states)
    structured_previous = json.loads(structured_precommits["adaptation"][-1])[
        "precommit_sha256"
    ]
    canonical_previous = json.loads(canonical_precommits["adaptation"][-1])[
        "precommit_sha256"
    ]
    for item_id in range(1, count + 1):
        context, attestation = _context("held_out", item_id)
        attestations["held_out"].append(attestation)
        heldout_states = {
            "closed_loop_active": terminal_states["closed_loop_active"],
            "closed_loop_lr0": POSITIVE_ZERO_STATE,
            "pair_sign_reverse": terminal_states["pair_sign_reverse"],
            "closed_loop_rollback": POSITIVE_ZERO_STATE,
        }
        if state_override is not None and state_override[0] == "held_out" and state_override[2] == item_id:
            heldout_states[state_override[1]] = state_override[3]
        unsigned, precommit = _precommit(
            family="structured",
            phase="held_out",
            item_id=item_id,
            previous_sha256=structured_previous,
            states=heldout_states,
            raw_action=_raw_action(0.5),
            context=context,
            attestation=attestation,
            inventory_overrides=inventory_overrides(
                "structured", "held_out", item_id
            ),
        )
        structured_precommits["held_out"].append(precommit)
        structured_receipts["held_out"].append(
            _receipts(
                unsigned=unsigned,
                precommit=precommit,
                phase="held_out",
                item_id=item_id,
                zero_signal=None,
                official_reward=official_reward,
            )
        )
        structured_previous = json.loads(precommit)["precommit_sha256"]

        canonical_unsigned, canonical_precommit = _precommit(
            family="canonical_online_icl",
            phase="held_out",
            item_id=item_id,
            previous_sha256=canonical_previous,
            states={},
            raw_action=_raw_action(0.6),
            context=context,
            attestation=attestation,
            canonical_join_mismatch=canonical_join_mismatch == ("held_out", item_id),
            inventory_overrides=inventory_overrides(
                "canonical_online_icl", "held_out", item_id
            ),
        )
        canonical_precommits["held_out"].append(canonical_precommit)
        canonical_receipts["held_out"].append(
            _receipts(
                unsigned=canonical_unsigned,
                precommit=canonical_precommit,
                phase="held_out",
                item_id=item_id,
                zero_signal=None,
                official_reward=official_reward,
            )
        )
        canonical_previous = json.loads(canonical_precommit)["precommit_sha256"]

    return {
        "adaptation_precommit_bytes": tuple(structured_precommits["adaptation"]),
        "adaptation_receipt_bytes": tuple(structured_receipts["adaptation"]),
        "adaptation_attestation_bytes": tuple(attestations["adaptation"]),
        "heldout_precommit_bytes": tuple(structured_precommits["held_out"]),
        "heldout_receipt_bytes": tuple(structured_receipts["held_out"]),
        "heldout_attestation_bytes": tuple(attestations["held_out"]),
        "expected_items_per_phase": count,
        "canonical_adaptation_precommit_bytes": tuple(
            canonical_precommits["adaptation"]
        ),
        "canonical_adaptation_receipt_bytes": tuple(
            canonical_receipts["adaptation"]
        ),
        "canonical_adaptation_attestation_bytes": tuple(attestations["adaptation"]),
        "canonical_heldout_precommit_bytes": tuple(canonical_precommits["held_out"]),
        "canonical_heldout_receipt_bytes": tuple(canonical_receipts["held_out"]),
        "canonical_heldout_attestation_bytes": tuple(attestations["held_out"]),
    }


@pytest.fixture(scope="module")
def valid_stage() -> dict[str, object]:
    return _build_stage()


def test_source_is_python310_and_has_no_direct_io_or_authorization_surface() -> None:
    source = Path(execution.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, feature_version=(3, 10))
    forbidden_imports = {
        "os",
        "pathlib",
        "socket",
        "subprocess",
        "requests",
        "urllib",
    }
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports.isdisjoint(forbidden_imports)
    assert "path" not in fields(execution.StructuredStageExecutionValidation)
    assert "delta_h" not in source
    assert "confidence_interval" not in source
    assert "formal-execution authorization" in source


def test_valid_stage_recomputes_transitions_signal_and_cross_family_join(
    valid_stage: dict[str, object],
) -> None:
    report = validate_structured_stage_execution(**valid_stage)
    assert report.integrity_pass is True
    assert report.canonical_online_joined is True
    assert report.public_inventory_consistent is True
    assert report.dgp_seal_bound is False
    assert report.items_per_phase == 5
    assert len(report.adaptation_items) == 5
    assert report.signal_pass_item_count == 5
    assert report.signal_miss_item_count == 0
    assert report.all_scientific_signal_gates_pass is True
    assert all(
        branch.candidate_count == 16
        and branch.unique_candidate_semantic_action_count == 16
        and branch.candidate_semantic_action_equal_to_official_count == 0
        and branch.probability_pair_floor_pass_count == 8
        and branch.non_tied_reward_pair_count == 8
        and branch.signal_pass
        and branch.missed_gates == ()
        for item in report.adaptation_items
        for branch in item.branch_results
    )
    with pytest.raises(FrozenInstanceError):
        report.integrity_pass = False  # type: ignore[misc]


def test_strict_immutable_inputs_and_all_or_none_canonical(
    valid_stage: dict[str, object],
) -> None:
    mutable = dict(valid_stage)
    mutable["adaptation_precommit_bytes"] = list(
        mutable["adaptation_precommit_bytes"]
    )
    with pytest.raises(StructuredExecutionValidationError, match="immutable"):
        validate_structured_stage_execution(**mutable)

    partial = dict(valid_stage)
    partial["canonical_heldout_receipt_bytes"] = None
    with pytest.raises(StructuredExecutionValidationError, match="all present"):
        validate_structured_stage_execution(**partial)


def test_self_consistent_unreachable_adaptation_state_jump_is_invalid() -> None:
    stage = _build_stage(
        state_override=(
            "adaptation",
            "closed_loop_active",
            2,
            (0.125, 0.0, 0.0, 0.0, 0.0, 0.0),
        )
    )
    with pytest.raises(StructuredExecutionValidationError, match="unreachable"):
        validate_structured_stage_execution(**stage)


@pytest.mark.parametrize(
    ("branch_id", "state"),
    [
        ("closed_loop_active", (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)),
        ("pair_sign_reverse", (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)),
        ("closed_loop_lr0", (0.0625, 0.0, 0.0, 0.0, 0.0, 0.0)),
        ("closed_loop_rollback", (0.0625, 0.0, 0.0, 0.0, 0.0, 0.0)),
    ],
)
def test_heldout_active_reverse_lr0_and_rollback_state_drift_is_invalid(
    branch_id: str, state: tuple[float, ...]
) -> None:
    with pytest.raises((StructuredExecutionValidationError, StructuredCommitmentError)):
        stage = _build_stage(
            state_override=("held_out", branch_id, 3, state),
        )
        validate_structured_stage_execution(**stage)


def test_reverse_receipt_intervention_must_reach_exact_next_state(
    valid_stage: dict[str, object],
) -> None:
    stage = copy.deepcopy(valid_stage)
    matrix = list(stage["adaptation_receipt_bytes"])
    item_two = list(matrix[1])
    # Reverse branch starts after active and LR0: its h0+ receipt is index 35.
    receipt = json.loads(item_two[35])
    receipt["scalar_reward_float_hex"] = (-1.0).hex()
    item_two[35] = canonical_json_bytes(receipt)
    matrix[1] = tuple(item_two)
    stage["adaptation_receipt_bytes"] = tuple(matrix)
    with pytest.raises(StructuredExecutionValidationError, match="unreachable"):
        validate_structured_stage_execution(**stage)


def test_lr0_computes_changed_candidate_credit_but_retains_zero() -> None:
    stage = _build_stage(zero_signal=("closed_loop_lr0", 3))
    report = validate_structured_stage_execution(**stage)
    branch = report.adaptation_items[2].branch_results[1]
    assert branch.branch_id == "closed_loop_lr0"
    assert branch.signal_pass is False
    assert "reward_population_std_floor" in branch.missed_gates
    assert report.integrity_pass is True


def test_rollback_and_lr0_heldout_reward_mismatch_is_invalid(
    valid_stage: dict[str, object],
) -> None:
    stage = copy.deepcopy(valid_stage)
    matrix = list(stage["heldout_receipt_bytes"])
    item = list(matrix[0])
    # Held-out order is active, LR0, reverse, rollback official receipts.
    rollback = json.loads(item[3])
    rollback["scalar_reward_float_hex"] = 0.5.hex()
    item[3] = canonical_json_bytes(rollback)
    matrix[0] = tuple(item)
    stage["heldout_receipt_bytes"] = tuple(matrix)
    with pytest.raises(StructuredExecutionValidationError, match="reward identity"):
        validate_structured_stage_execution(**stage)


def test_swapped_receipts_fail_exact_invocation_join(
    valid_stage: dict[str, object],
) -> None:
    stage = copy.deepcopy(valid_stage)
    matrix = list(stage["adaptation_receipt_bytes"])
    item = list(matrix[2])
    item[1], item[2] = item[2], item[1]
    matrix[2] = tuple(item)
    stage["adaptation_receipt_bytes"] = tuple(matrix)
    with pytest.raises(StructuredExecutionValidationError):
        validate_structured_stage_execution(**stage)


def test_item1_branch_reward_vector_mismatch_is_invalid(
    valid_stage: dict[str, object],
) -> None:
    stage = copy.deepcopy(valid_stage)
    matrix = list(stage["adaptation_receipt_bytes"])
    item = list(matrix[0])
    lr0_official = json.loads(item[17])
    lr0_official["scalar_reward_float_hex"] = 0.5.hex()
    item[17] = canonical_json_bytes(lr0_official)
    matrix[0] = tuple(item)
    stage["adaptation_receipt_bytes"] = tuple(matrix)
    with pytest.raises(StructuredExecutionValidationError, match="reward vectors"):
        validate_structured_stage_execution(**stage)


def test_official_adaptation_rewards_never_enter_updater_or_signal() -> None:
    baseline = validate_structured_stage_execution(**_build_stage(official_reward=0.25))
    changed = validate_structured_stage_execution(**_build_stage(official_reward=1e9))
    assert baseline.adaptation_items == changed.adaptation_items


def test_signal_threshold_is_inclusive_and_nextafter_below_misses() -> None:
    for floor in (
        execution.PAIR_PROBABILITY_MEAN_ABS_FLOOR,
        execution.REWARD_POPULATION_STD_FLOOR,
        execution.REWARD_PAIR_RMS_FLOOR,
    ):
        assert execution._meets_floor(floor, floor) is True
        assert execution._meets_floor(math.nextafter(floor, 0.0), floor) is False


def test_signal_miss_is_valid_no_signal_not_integrity_failure() -> None:
    stage = _build_stage(zero_signal=("closed_loop_active", 5))
    report = validate_structured_stage_execution(**stage)
    assert report.integrity_pass is True
    assert report.signal_miss_item_count == 1
    assert report.all_scientific_signal_gates_pass is False
    branch = report.adaptation_items[4].branch_results[0]
    assert branch.signal_pass is False
    assert set(branch.missed_gates) >= {
        "reward_population_std_floor",
        "reward_pair_rms_floor",
        "non_tied_reward_pair_floor",
        "nonzero_sign_es_direction",
    }


def test_duplicate_and_subfloor_candidate_actions_are_valid_signal_miss() -> None:
    report = validate_structured_stage_execution(**_build_stage(zero_action_item=4))
    assert report.integrity_pass is True
    assert report.adaptation_items[3].signal_pass is False
    assert all(
        "unique_candidate_semantic_actions" in branch.missed_gates
        and "pair_probability_mean_abs_floor" in branch.missed_gates
        for branch in report.adaptation_items[3].branch_results
    )


def test_cross_family_allows_raw_trace_and_action_differences_but_not_join_drift(
    valid_stage: dict[str, object],
) -> None:
    # The fixture intentionally uses 0.5 structured actions, 0.6 canonical
    # actions, and family-specific raw-trace hashes.
    report = validate_structured_stage_execution(**valid_stage)
    assert report.canonical_online_joined is True

    mismatch = _build_stage(canonical_join_mismatch=("held_out", 4))
    with pytest.raises(StructuredExecutionValidationError, match="row/context"):
        validate_structured_stage_execution(**mismatch)


def test_cross_family_canonical_model_inventory_mismatch_is_invalid() -> None:
    mismatch = _build_stage(
        family_inventory_overrides={
            ("canonical_online_icl", "model_sha256"): _sha("canonical-model-drift")
        }
    )
    with pytest.raises(
        StructuredExecutionValidationError,
        match="cross-family public inventory mismatch for model_sha256",
    ):
        validate_structured_stage_execution(**mismatch)


def test_both_family_item3_static_inventory_drift_is_invalid() -> None:
    drift = _sha("shared-item3-model-drift")
    mismatch = _build_stage(
        item_inventory_overrides={
            ("structured", "adaptation", 3, "model_sha256"): drift,
            ("canonical_online_icl", "adaptation", 3, "model_sha256"): drift,
        }
    )
    with pytest.raises(
        StructuredExecutionValidationError,
        match="structured public inventory drift for model_sha256",
    ):
        validate_structured_stage_execution(**mismatch)


def test_phase_inventory_item_drift_is_invalid_even_when_cross_family_matches() -> None:
    drift = _sha("shared-item3-dgp-drift")
    mismatch = _build_stage(
        item_inventory_overrides={
            ("structured", "adaptation", 3, "dgp_sha256"): drift,
            ("canonical_online_icl", "adaptation", 3, "dgp_sha256"): drift,
        }
    )
    with pytest.raises(
        StructuredExecutionValidationError,
        match="structured adaptation public inventory drift for dgp_sha256",
    ):
        validate_structured_stage_execution(**mismatch)


@pytest.mark.parametrize(
    "key", ("dgp_sha256", "schedule_sha256", "condition_order_sha256")
)
def test_adaptation_and_heldout_phase_inventory_digest_must_differ(key: str) -> None:
    mismatch = _build_stage(phase_collision_keys=(key,))
    with pytest.raises(
        StructuredExecutionValidationError,
        match=rf"adaptation/held-out public inventory must differ for {key}",
    ):
        validate_structured_stage_execution(**mismatch)


@pytest.mark.parametrize("key", ("protocol_sha256", "source_sha256"))
def test_protocol_source_may_differ_cross_family_but_not_within_family(
    valid_stage: dict[str, object], key: str
) -> None:
    structured = json.loads(valid_stage["adaptation_precommit_bytes"][0])
    canonical = json.loads(valid_stage["canonical_adaptation_precommit_bytes"][0])
    assert structured["inventory_sha256"][key] != canonical["inventory_sha256"][key]
    assert validate_structured_stage_execution(**valid_stage).integrity_pass is True

    mismatch = _build_stage(
        item_inventory_overrides={
            ("structured", "adaptation", 3, key): _sha(f"item3-{key}-drift")
        }
    )
    with pytest.raises(
        StructuredExecutionValidationError,
        match=rf"structured public inventory drift for {key}",
    ):
        validate_structured_stage_execution(**mismatch)


def test_canonical_is_optional_and_no_efficacy_fields_are_returned(
    valid_stage: dict[str, object],
) -> None:
    structured_only = {
        key: value
        for key, value in valid_stage.items()
        if not key.startswith("canonical_")
    }
    report = validate_structured_stage_execution(**structured_only)
    assert report.canonical_online_joined is False
    assert report.public_inventory_consistent is True
    assert report.dgp_seal_bound is False
    field_names = {field.name for field in fields(report)}
    assert field_names.isdisjoint(
        {"delta", "mean", "confidence_interval", "ci", "efficacy"}
    )
