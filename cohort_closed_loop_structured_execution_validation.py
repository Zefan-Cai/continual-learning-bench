"""Pure state/receipt validation for one structured-state execution block.

This module validates only the public structured-state precommit and scalar
receipt boundary.  It has no artifact/path, network, process, model, task,
DGP resolver, DGP seal, hidden-registry, or scorer interface.  Its public function
accepts immutable byte tuples, calls the commitment validators again, and
returns only integrity/signal booleans and opaque counts.  It never computes or
returns a held-out delta, mean, confidence interval, or efficacy statistic.

This is deliberately *not* formal-execution authorization.  A future sealed
runner must independently bind the loaded source/module identities, protocol
seal, DGP/grid contents and seals, publication ordering, completion, and scorer
replay.  This module checks consistency of the already-public inventory digest
claims only; it does not validate the objects named by those digests.
The existing commitment validator binds its numerical/source identity by
reading its own implementation file; this module performs no direct I/O and
offers no injectable runtime-identity seam.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from cohort_closed_loop_structured_commitments import (
    CANDIDATE_ACTION_IDS,
    InvocationCommitment,
    StructuredCommitmentError,
    ValidatedPrecommit,
    ValidatedReceiptRequest,
    validate_complete_receipt_inventory,
    validate_precommit_bytes,
    validate_precommit_digest_sequence,
)
from cohort_closed_loop_structured_state import (
    ACTION_FIELD_NAMES,
    CANDIDATE_IDS,
    ETA,
    MAX_OFFICIAL_STATE_ABS,
    POSITIVE_ZERO_STATE,
    STATE_DIMENSION,
    StructuredStateProtocolError,
    parse_semantic_action,
    sign_es_update,
    validate_state,
)


class StructuredExecutionValidationError(ValueError):
    """Raised when the public state/receipt execution boundary is invalid."""


VALIDATION_PROTOCOL = "cohort_closed_loop_structured_execution_validation_v1"
STRUCTURED_ADAPTATION_BRANCHES: tuple[str, ...] = (
    "closed_loop_active",
    "closed_loop_lr0",
    "pair_sign_reverse",
)
STRUCTURED_HELDOUT_BRANCHES: tuple[str, ...] = (
    *STRUCTURED_ADAPTATION_BRANCHES,
    "closed_loop_rollback",
)

UNIQUE_CANDIDATE_COUNT = 16
PAIR_COUNT = 8
PAIR_PROBABILITY_MEAN_ABS_FLOOR = 1e-4
REWARD_POPULATION_STD_FLOOR = 1e-5
REWARD_PAIR_RMS_FLOOR = 1e-5
NON_TIED_PAIR_FLOOR = 4

_STATIC_INVENTORY_KEYS: tuple[str, ...] = (
    "model_sha256",
    "tokenizer_sha256",
    "environment_sha256",
    "task_sha256",
    "schema_sha256",
    "cohort_layer_inventory_sha256",
)
_PHASE_INVENTORY_KEYS: tuple[str, ...] = (
    "dgp_sha256",
    "schedule_sha256",
    "condition_order_sha256",
)
_FAMILY_FROZEN_INVENTORY_KEYS: tuple[str, ...] = (
    "protocol_sha256",
    "source_sha256",
)
_CROSS_FAMILY_INVENTORY_KEYS: tuple[str, ...] = (
    *_STATIC_INVENTORY_KEYS,
    *_PHASE_INVENTORY_KEYS,
)

_SIGNAL_GATE_NAMES: tuple[str, ...] = (
    "unique_candidate_semantic_actions",
    "candidate_semantic_action_not_official",
    "pair_probability_mean_abs_floor",
    "reward_population_std_floor",
    "reward_pair_rms_floor",
    "non_tied_reward_pair_floor",
    "nonzero_sign_es_direction",
)


@dataclass(frozen=True, slots=True)
class BranchSignalValidation:
    """Outcome-blind signal result for one candidate-bearing branch/item."""

    branch_id: str
    candidate_count: int
    unique_candidate_semantic_action_count: int
    candidate_semantic_action_equal_to_official_count: int
    probability_pair_floor_pass_count: int
    non_tied_reward_pair_count: int
    signal_pass: bool
    missed_gates: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdaptationItemValidation:
    """Integrity/signal result for one adaptation position."""

    block_id: str
    item_id: int
    integrity_pass: bool
    branch_results: tuple[BranchSignalValidation, ...]
    signal_pass: bool


@dataclass(frozen=True, slots=True)
class StructuredStageExecutionValidation:
    """Pure non-efficacy report for one complete public execution block."""

    validation_protocol: str
    block_id: str
    items_per_phase: int
    canonical_online_joined: bool
    public_inventory_consistent: bool
    dgp_seal_bound: bool
    integrity_pass: bool
    adaptation_items: tuple[AdaptationItemValidation, ...]
    signal_pass_item_count: int
    signal_miss_item_count: int
    all_scientific_signal_gates_pass: bool


@dataclass(frozen=True, slots=True)
class _ValidatedItem:
    precommit: ValidatedPrecommit
    receipts: tuple[ValidatedReceiptRequest, ...]
    attestation_bytes: bytes


def _inventory_map(precommit: ValidatedPrecommit) -> dict[str, str]:
    inventory = dict(precommit.inventory_sha256)
    expected = {
        *_STATIC_INVENTORY_KEYS,
        *_PHASE_INVENTORY_KEYS,
        *_FAMILY_FROZEN_INVENTORY_KEYS,
    }
    if set(inventory) != expected:
        raise StructuredExecutionValidationError("public inventory key set mismatch")
    return inventory


def _validate_family_public_inventory(
    *,
    adaptation: tuple[_ValidatedItem, ...],
    heldout: tuple[_ValidatedItem, ...],
    family: str,
) -> None:
    """Validate digest-claim consistency, never the referenced DGP objects."""

    all_items = (*adaptation, *heldout)
    anchor = _inventory_map(adaptation[0].precommit)
    for item in all_items:
        inventory = _inventory_map(item.precommit)
        for key in (*_STATIC_INVENTORY_KEYS, *_FAMILY_FROZEN_INVENTORY_KEYS):
            if inventory[key] != anchor[key]:
                raise StructuredExecutionValidationError(
                    f"{family} public inventory drift for {key}"
                )

    adaptation_inventory = _inventory_map(adaptation[0].precommit)
    heldout_inventory = _inventory_map(heldout[0].precommit)
    for phase, items, phase_anchor in (
        ("adaptation", adaptation, adaptation_inventory),
        ("held_out", heldout, heldout_inventory),
    ):
        for item in items:
            inventory = _inventory_map(item.precommit)
            for key in _PHASE_INVENTORY_KEYS:
                if inventory[key] != phase_anchor[key]:
                    raise StructuredExecutionValidationError(
                        f"{family} {phase} public inventory drift for {key}"
                    )
    for key in _PHASE_INVENTORY_KEYS:
        if adaptation_inventory[key] == heldout_inventory[key]:
            raise StructuredExecutionValidationError(
                f"{family} adaptation/held-out public inventory must differ for {key}"
            )


def _require_bytes_tuple(value: object, *, label: str, length: int) -> tuple[bytes, ...]:
    if type(value) is not tuple:
        raise StructuredExecutionValidationError(f"{label} must be an immutable tuple")
    if len(value) != length:
        raise StructuredExecutionValidationError(f"{label} length mismatch")
    if any(type(entry) is not bytes for entry in value):
        raise StructuredExecutionValidationError(
            f"{label} entries must be immutable bytes"
        )
    return value


def _require_receipt_matrix(
    value: object, *, label: str, length: int
) -> tuple[tuple[bytes, ...], ...]:
    if type(value) is not tuple:
        raise StructuredExecutionValidationError(f"{label} must be an immutable tuple")
    if len(value) != length:
        raise StructuredExecutionValidationError(f"{label} length mismatch")
    result: list[tuple[bytes, ...]] = []
    for index, entry in enumerate(value):
        if type(entry) is not tuple or any(type(raw) is not bytes for raw in entry):
            raise StructuredExecutionValidationError(
                f"{label}[{index}] must be an immutable bytes tuple"
            )
        result.append(entry)
    return tuple(result)


def _local_u() -> tuple[tuple[int, ...], ...]:
    """Rebuild H8 and select its first six columns without trusting summaries."""

    matrix: tuple[tuple[int, ...], ...] = ((1,),)
    for _ in range(3):
        matrix = tuple(tuple(row) + tuple(row) for row in matrix) + tuple(
            tuple(row) + tuple(-entry for entry in row) for row in matrix
        )
    u = tuple(tuple(row[:STATE_DIMENSION]) for row in matrix)
    expected_gram = tuple(
        tuple(8 if left == right else 0 for right in range(STATE_DIMENSION))
        for left in range(STATE_DIMENSION)
    )
    gram = tuple(
        tuple(
            sum(row[left] * row[right] for row in u)
            for right in range(STATE_DIMENSION)
        )
        for left in range(STATE_DIMENSION)
    )
    if len(u) != PAIR_COUNT or gram != expected_gram:
        raise StructuredExecutionValidationError("independent Hadamard design mismatch")
    signed_balance = tuple(
        sum(sign * row[column] for row in u for sign in (1, -1))
        for column in range(STATE_DIMENSION)
    )
    if signed_balance != (0, 0, 0, 0, 0, 0):
        raise StructuredExecutionValidationError("independent probe balance mismatch")
    return u


def _index_invocations(
    precommit: ValidatedPrecommit,
) -> dict[tuple[str, str, str], InvocationCommitment]:
    indexed: dict[tuple[str, str, str], InvocationCommitment] = {}
    for invocation in precommit.invocations:
        key = (invocation.branch_id, invocation.action_role, invocation.action_id)
        if key in indexed:
            raise StructuredExecutionValidationError("duplicate invocation view")
        indexed[key] = invocation
    return indexed


def _index_receipts(
    receipts: tuple[ValidatedReceiptRequest, ...],
) -> dict[tuple[str, str, str], ValidatedReceiptRequest]:
    indexed: dict[tuple[str, str, str], ValidatedReceiptRequest] = {}
    for receipt in receipts:
        key = (receipt.branch_id, receipt.action_role, receipt.action_id)
        if key in indexed:
            raise StructuredExecutionValidationError("duplicate receipt view")
        indexed[key] = receipt
    return indexed


def _branch_state(precommit: ValidatedPrecommit, branch_id: str) -> tuple[float, ...]:
    matches = [
        branch for branch in precommit.branch_records if branch.branch_id == branch_id
    ]
    if len(matches) != 1 or matches[0].state_before is None:
        raise StructuredExecutionValidationError(
            f"missing structured state for {branch_id}"
        )
    try:
        return validate_state(matches[0].state_before, max_abs=MAX_OFFICIAL_STATE_ABS)
    except StructuredStateProtocolError as exc:
        raise StructuredExecutionValidationError(
            f"invalid structured state for {branch_id}"
        ) from exc


def _candidate_receipts(
    receipts_by_key: dict[tuple[str, str, str], ValidatedReceiptRequest],
    branch_id: str,
) -> tuple[ValidatedReceiptRequest, ...]:
    try:
        return tuple(
            receipts_by_key[(branch_id, "candidate", action_id)]
            for action_id in CANDIDATE_ACTION_IDS
        )
    except KeyError as exc:
        raise StructuredExecutionValidationError(
            f"candidate receipt inventory missing for {branch_id}"
        ) from exc


def _independent_direction(
    candidate_receipts: tuple[ValidatedReceiptRequest, ...], *, reverse_pairs: bool
) -> tuple[float, ...]:
    if len(candidate_receipts) != UNIQUE_CANDIDATE_COUNT:
        raise StructuredExecutionValidationError("candidate reward count mismatch")
    u = _local_u()
    sums = [0] * STATE_DIMENSION
    for pair_index, row in enumerate(u):
        plus = candidate_receipts[2 * pair_index].scalar_reward
        minus = candidate_receipts[2 * pair_index + 1].scalar_reward
        if reverse_pairs:
            plus, minus = minus, plus
        reward_sign = 1 if plus > minus else -1 if plus < minus else 0
        for column, direction in enumerate(row):
            sums[column] += reward_sign * direction
    return validate_state(tuple(float(total) / 8.0 for total in sums))


def _independent_update(
    *,
    precommit: ValidatedPrecommit,
    branch_id: str,
    state_before: tuple[float, ...],
    candidate_receipts: tuple[ValidatedReceiptRequest, ...],
) -> tuple[float, ...]:
    """Recompute candidate-only sign-ES and cross-check the frozen primitive."""

    candidate_rewards = tuple(
        (CANDIDATE_IDS[index], receipt.scalar_reward)
        for index, receipt in enumerate(candidate_receipts)
    )
    payload = {
        "precommit_sha256": precommit.precommit_sha256,
        "branch_id": branch_id,
        "item_id": precommit.item_id,
        "scoring_context_sha256": precommit.scoring_context_sha256,
        "candidate_rewards": candidate_rewards,
    }
    try:
        primitive_update = sign_es_update(state_before, payload)
    except StructuredStateProtocolError as exc:
        raise StructuredExecutionValidationError(
            f"sign-ES primitive rejected {branch_id} item {precommit.item_id}"
        ) from exc

    true_direction = _independent_direction(candidate_receipts, reverse_pairs=False)
    used_direction = _independent_direction(
        candidate_receipts, reverse_pairs=branch_id == "pair_sign_reverse"
    )
    if primitive_update.true_direction != true_direction:
        raise StructuredExecutionValidationError("true sign-ES direction mismatch")
    if primitive_update.used_direction != used_direction:
        raise StructuredExecutionValidationError("used sign-ES direction mismatch")
    if branch_id == "pair_sign_reverse":
        expected_negative = tuple(
            -value if value != 0.0 else 0.0 for value in true_direction
        )
        if used_direction != expected_negative:
            raise StructuredExecutionValidationError("pair-sign reverse is not exact")

    if branch_id == "closed_loop_lr0":
        independent_after = POSITIVE_ZERO_STATE
    else:
        independent_after = validate_state(
            tuple(
                state_before[column] + ETA * used_direction[column]
                for column in range(STATE_DIMENSION)
            ),
            max_abs=MAX_OFFICIAL_STATE_ABS,
        )
    if primitive_update.state_after != independent_after:
        raise StructuredExecutionValidationError("sign-ES state transition mismatch")
    return independent_after


def _meets_floor(metric: float, floor: float) -> bool:
    """Registered inclusive floor comparison, factored for boundary tests."""

    return metric >= floor


def _population_std(values: tuple[float, ...]) -> float:
    # Scaling avoids overflow for finite scorer outputs near binary64 max while
    # preserving the registered population (not sample) denominator.
    scale = max(abs(value) for value in values)
    if scale == 0.0:
        return 0.0
    scaled = tuple(value / scale for value in values)
    mean = math.fsum(scaled) / float(len(scaled))
    return scale * math.sqrt(
        math.fsum((value - mean) ** 2 for value in scaled) / len(scaled)
    )


def _branch_signal_validation(
    *,
    branch_id: str,
    invocation_by_key: dict[tuple[str, str, str], InvocationCommitment],
    candidate_receipts: tuple[ValidatedReceiptRequest, ...],
    true_direction: tuple[float, ...],
) -> BranchSignalValidation:
    try:
        official = invocation_by_key[(branch_id, "official", "official")]
        candidates = tuple(
            invocation_by_key[(branch_id, "candidate", action_id)]
            for action_id in CANDIDATE_ACTION_IDS
        )
    except KeyError as exc:
        raise StructuredExecutionValidationError(
            f"invocation inventory missing for {branch_id}"
        ) from exc

    candidate_hashes = tuple(candidate.semantic_action_sha256 for candidate in candidates)
    unique_count = len(set(candidate_hashes))
    equal_official_count = sum(
        digest == official.semantic_action_sha256 for digest in candidate_hashes
    )

    parsed_candidates: list[dict[str, float]] = []
    for candidate in candidates:
        try:
            parsed_candidates.append(parse_semantic_action(candidate.action_bytes))
        except StructuredStateProtocolError as exc:
            raise StructuredExecutionValidationError(
                f"candidate action parse failed for {branch_id}"
            ) from exc
    probability_pair_floor_pass_count = 0
    for pair_index in range(PAIR_COUNT):
        plus = parsed_candidates[2 * pair_index]
        minus = parsed_candidates[2 * pair_index + 1]
        mean_abs = math.fsum(
            abs(plus[field_name] - minus[field_name])
            for field_name in ACTION_FIELD_NAMES
        ) / len(ACTION_FIELD_NAMES)
        probability_pair_floor_pass_count += _meets_floor(
            mean_abs, PAIR_PROBABILITY_MEAN_ABS_FLOOR
        )

    rewards = tuple(receipt.scalar_reward for receipt in candidate_receipts)
    reward_population_std = _population_std(rewards)
    pair_differences = tuple(
        rewards[2 * index] - rewards[2 * index + 1] for index in range(PAIR_COUNT)
    )
    reward_pair_rms = math.sqrt(
        math.fsum(value * value for value in pair_differences) / PAIR_COUNT
    )
    non_tied_count = sum(value != 0.0 for value in pair_differences)
    direction_nonzero = math.sqrt(math.fsum(value * value for value in true_direction)) > 0.0

    gates = {
        "unique_candidate_semantic_actions": unique_count == UNIQUE_CANDIDATE_COUNT,
        "candidate_semantic_action_not_official": equal_official_count == 0,
        "pair_probability_mean_abs_floor": (
            probability_pair_floor_pass_count == PAIR_COUNT
        ),
        "reward_population_std_floor": _meets_floor(
            reward_population_std, REWARD_POPULATION_STD_FLOOR
        ),
        "reward_pair_rms_floor": _meets_floor(
            reward_pair_rms, REWARD_PAIR_RMS_FLOOR
        ),
        "non_tied_reward_pair_floor": non_tied_count >= NON_TIED_PAIR_FLOOR,
        "nonzero_sign_es_direction": direction_nonzero,
    }
    missed = tuple(name for name in _SIGNAL_GATE_NAMES if not gates[name])
    return BranchSignalValidation(
        branch_id=branch_id,
        candidate_count=len(candidates),
        unique_candidate_semantic_action_count=unique_count,
        candidate_semantic_action_equal_to_official_count=equal_official_count,
        probability_pair_floor_pass_count=probability_pair_floor_pass_count,
        non_tied_reward_pair_count=non_tied_count,
        signal_pass=not missed,
        missed_gates=missed,
    )


def _validate_item_inputs(
    *,
    precommit_bytes: tuple[bytes, ...],
    receipt_bytes: tuple[tuple[bytes, ...], ...],
    attestation_bytes: tuple[bytes, ...],
    expected_family: str,
    expected_phase: str,
) -> tuple[_ValidatedItem, ...]:
    validated: list[_ValidatedItem] = []
    for index, (precommit_raw, receipt_raw, attestation_raw) in enumerate(
        zip(precommit_bytes, receipt_bytes, attestation_bytes), start=1
    ):
        try:
            precommit = validate_precommit_bytes(
                precommit_raw,
                scoring_context_attestation_bytes=attestation_raw,
            )
            receipts = validate_complete_receipt_inventory(
                precommit_bytes=precommit_raw,
                receipt_bytes=list(receipt_raw),
                scoring_context_attestation_bytes=attestation_raw,
            )
        except (StructuredCommitmentError, StructuredStateProtocolError) as exc:
            raise StructuredExecutionValidationError(
                f"{expected_family} {expected_phase} item {index} is invalid"
            ) from exc
        if (
            precommit.commitment_family != expected_family
            or precommit.commitment_phase != expected_phase
            or precommit.item_id != index
            or precommit.instance_index != index - 1
        ):
            raise StructuredExecutionValidationError(
                f"{expected_family} {expected_phase} item identity mismatch"
            )
        validated.append(
            _ValidatedItem(
                precommit=precommit,
                receipts=receipts,
                attestation_bytes=attestation_raw,
            )
        )
    return tuple(validated)


def _assert_item1_vectors_equal(item: _ValidatedItem) -> None:
    invocations = _index_invocations(item.precommit)
    receipts = _index_receipts(item.receipts)
    action_vectors: list[tuple[tuple[str, str, bytes], ...]] = []
    reward_vectors: list[tuple[str, ...]] = []
    for branch_id in STRUCTURED_ADAPTATION_BRANCHES:
        refs = (("official", "official"),) + tuple(
            ("candidate", action_id) for action_id in CANDIDATE_ACTION_IDS
        )
        action_vectors.append(
            tuple(
                (
                    invocations[(branch_id, role, action_id)].semantic_action_sha256,
                    invocations[(branch_id, role, action_id)].action_bytes_sha256,
                    invocations[(branch_id, role, action_id)].action_bytes,
                )
                for role, action_id in refs
            )
        )
        reward_vectors.append(
            tuple(
                receipts[(branch_id, role, action_id)].scalar_reward_float_hex
                for role, action_id in refs
            )
        )
    if any(vector != action_vectors[0] for vector in action_vectors[1:]):
        raise StructuredExecutionValidationError(
            "item-1 action vectors differ across structured branches"
        )
    if any(vector != reward_vectors[0] for vector in reward_vectors[1:]):
        raise StructuredExecutionValidationError(
            "item-1 true reward vectors differ across structured branches"
        )


def _validate_adaptation_transitions(
    items: tuple[_ValidatedItem, ...],
) -> tuple[tuple[AdaptationItemValidation, ...], dict[str, tuple[float, ...]]]:
    _assert_item1_vectors_equal(items[0])
    item_reports: list[AdaptationItemValidation] = []
    terminal_states: dict[str, tuple[float, ...]] = {}
    for index, item in enumerate(items):
        precommit = item.precommit
        invocation_by_key = _index_invocations(precommit)
        receipt_by_key = _index_receipts(item.receipts)
        branch_reports: list[BranchSignalValidation] = []
        for branch_id in STRUCTURED_ADAPTATION_BRANCHES:
            state_before = _branch_state(precommit, branch_id)
            candidate_receipts = _candidate_receipts(receipt_by_key, branch_id)
            state_after = _independent_update(
                precommit=precommit,
                branch_id=branch_id,
                state_before=state_before,
                candidate_receipts=candidate_receipts,
            )
            true_direction = _independent_direction(
                candidate_receipts, reverse_pairs=False
            )
            branch_reports.append(
                _branch_signal_validation(
                    branch_id=branch_id,
                    invocation_by_key=invocation_by_key,
                    candidate_receipts=candidate_receipts,
                    true_direction=true_direction,
                )
            )
            if index + 1 < len(items):
                next_state = _branch_state(items[index + 1].precommit, branch_id)
                if next_state != state_after:
                    raise StructuredExecutionValidationError(
                        f"unreachable state jump for {branch_id} after item {index + 1}"
                    )
            else:
                terminal_states[branch_id] = state_after

        report_tuple = tuple(branch_reports)
        item_reports.append(
            AdaptationItemValidation(
                block_id=precommit.block_id,
                item_id=precommit.item_id,
                integrity_pass=True,
                branch_results=report_tuple,
                signal_pass=all(report.signal_pass for report in report_tuple),
            )
        )
    return tuple(item_reports), terminal_states


def _validate_heldout_freeze(
    *,
    items: tuple[_ValidatedItem, ...],
    terminal_states: dict[str, tuple[float, ...]],
) -> None:
    expected_states = {
        "closed_loop_active": terminal_states["closed_loop_active"],
        "closed_loop_lr0": POSITIVE_ZERO_STATE,
        "pair_sign_reverse": terminal_states["pair_sign_reverse"],
        "closed_loop_rollback": POSITIVE_ZERO_STATE,
    }
    for item in items:
        precommit = item.precommit
        invocations = _index_invocations(precommit)
        receipts = _index_receipts(item.receipts)
        for branch_id in STRUCTURED_HELDOUT_BRANCHES:
            state = _branch_state(precommit, branch_id)
            if state != expected_states[branch_id]:
                raise StructuredExecutionValidationError(
                    f"held-out frozen state drift for {branch_id}"
                )
            branch = next(
                record
                for record in precommit.branch_records
                if record.branch_id == branch_id
            )
            if branch.candidate_invocation_refs or branch.probe_states:
                raise StructuredExecutionValidationError(
                    f"held-out candidate inventory exists for {branch_id}"
                )

        lr0_invocation = invocations[("closed_loop_lr0", "official", "official")]
        rollback_invocation = invocations[
            ("closed_loop_rollback", "official", "official")
        ]
        if (
            lr0_invocation.action_bytes != rollback_invocation.action_bytes
            or lr0_invocation.action_bytes_sha256
            != rollback_invocation.action_bytes_sha256
            or lr0_invocation.semantic_action_sha256
            != rollback_invocation.semantic_action_sha256
        ):
            raise StructuredExecutionValidationError(
                "held-out LR0/rollback action identity mismatch"
            )
        lr0_receipt = receipts[("closed_loop_lr0", "official", "official")]
        rollback_receipt = receipts[
            ("closed_loop_rollback", "official", "official")
        ]
        if (
            lr0_receipt.action_bytes_sha256 != rollback_receipt.action_bytes_sha256
            or lr0_receipt.semantic_action_sha256
            != rollback_receipt.semantic_action_sha256
            or lr0_receipt.scalar_reward_float_hex
            != rollback_receipt.scalar_reward_float_hex
        ):
            raise StructuredExecutionValidationError(
                "held-out LR0/rollback reward identity mismatch"
            )


def _validate_cross_family_join(
    *, structured: tuple[_ValidatedItem, ...], canonical: tuple[_ValidatedItem, ...]
) -> None:
    if len(structured) != len(canonical):
        raise StructuredExecutionValidationError("cross-family item count mismatch")
    for structured_item, canonical_item in zip(structured, canonical):
        left = structured_item.precommit
        right = canonical_item.precommit
        left_inventory = _inventory_map(left)
        right_inventory = _inventory_map(right)
        for key in _CROSS_FAMILY_INVENTORY_KEYS:
            if left_inventory[key] != right_inventory[key]:
                raise StructuredExecutionValidationError(
                    f"cross-family public inventory mismatch for {key}"
                )
        # Raw trace and raw action identities intentionally are not compared:
        # the two preregistered policies may produce different public traces.
        if (
            left.block_id != right.block_id
            or left.commitment_phase != right.commitment_phase
            or left.item_id != right.item_id
            or left.instance_id != right.instance_id
            or left.instance_index != right.instance_index
            or left.query_sha256 != right.query_sha256
            or left.scoring_context_sha256 != right.scoring_context_sha256
            or left.scoring_context_attestation_sha256
            != right.scoring_context_attestation_sha256
            or structured_item.attestation_bytes != canonical_item.attestation_bytes
        ):
            raise StructuredExecutionValidationError("cross-family row/context join mismatch")
        if len(right.branch_records) != 1:
            raise StructuredExecutionValidationError("canonical branch count mismatch")
        branch = right.branch_records[0]
        if (
            branch.branch_id != "canonical_online_icl"
            or branch.state_before is not None
            or branch.candidate_invocation_refs
            or branch.probe_states
        ):
            raise StructuredExecutionValidationError(
                "canonical online ICL state/candidate boundary mismatch"
            )
        if len(right.invocations) != 1 or len(canonical_item.receipts) != 1:
            raise StructuredExecutionValidationError(
                "canonical online ICL must have one official invocation/receipt"
            )
        invocation = right.invocations[0]
        if (
            invocation.action_role != "official"
            or invocation.action_id != "official"
            or invocation.action_bytes != right.shared_raw_action_bytes
        ):
            raise StructuredExecutionValidationError(
                "canonical online ICL official action is not the raw action"
            )


def validate_structured_stage_execution(
    *,
    adaptation_precommit_bytes: object,
    adaptation_receipt_bytes: object,
    adaptation_attestation_bytes: object,
    heldout_precommit_bytes: object,
    heldout_receipt_bytes: object,
    heldout_attestation_bytes: object,
    expected_items_per_phase: object,
    canonical_adaptation_precommit_bytes: object | None = None,
    canonical_adaptation_receipt_bytes: object | None = None,
    canonical_adaptation_attestation_bytes: object | None = None,
    canonical_heldout_precommit_bytes: object | None = None,
    canonical_heldout_receipt_bytes: object | None = None,
    canonical_heldout_attestation_bytes: object | None = None,
) -> StructuredStageExecutionValidation:
    """Validate one block's public state/receipt execution, without efficacy.

    Only immutable canonical bytes are accepted.  Signal misses are returned as
    valid scientific no-signal observations; execution-integrity failures raise
    :class:`StructuredExecutionValidationError`.  A successful report always
    says ``public_inventory_consistent=True`` and ``dgp_seal_bound=False``:
    digest-claim consistency is checked, but DGP content/seal validation is out
    of scope and remains mandatory in the future formal runner.
    """

    if type(expected_items_per_phase) is not int or expected_items_per_phase not in (
        5,
        20,
    ):
        raise StructuredExecutionValidationError(
            "expected_items_per_phase must be exactly 5 or 20"
        )
    count = expected_items_per_phase
    adaptation_precommits = _require_bytes_tuple(
        adaptation_precommit_bytes,
        label="adaptation_precommit_bytes",
        length=count,
    )
    adaptation_receipts = _require_receipt_matrix(
        adaptation_receipt_bytes,
        label="adaptation_receipt_bytes",
        length=count,
    )
    adaptation_attestations = _require_bytes_tuple(
        adaptation_attestation_bytes,
        label="adaptation_attestation_bytes",
        length=count,
    )
    heldout_precommits = _require_bytes_tuple(
        heldout_precommit_bytes,
        label="heldout_precommit_bytes",
        length=count,
    )
    heldout_receipts = _require_receipt_matrix(
        heldout_receipt_bytes,
        label="heldout_receipt_bytes",
        length=count,
    )
    heldout_attestations = _require_bytes_tuple(
        heldout_attestation_bytes,
        label="heldout_attestation_bytes",
        length=count,
    )

    try:
        validate_precommit_digest_sequence(
            adaptation_precommit_bytes=list(adaptation_precommits),
            heldout_precommit_bytes=list(heldout_precommits),
            expected_items_per_phase=count,
        )
    except (StructuredCommitmentError, StructuredStateProtocolError) as exc:
        raise StructuredExecutionValidationError(
            "structured precommit sequence is invalid"
        ) from exc
    adaptation = _validate_item_inputs(
        precommit_bytes=adaptation_precommits,
        receipt_bytes=adaptation_receipts,
        attestation_bytes=adaptation_attestations,
        expected_family="structured",
        expected_phase="adaptation",
    )
    heldout = _validate_item_inputs(
        precommit_bytes=heldout_precommits,
        receipt_bytes=heldout_receipts,
        attestation_bytes=heldout_attestations,
        expected_family="structured",
        expected_phase="held_out",
    )
    block_id = adaptation[0].precommit.block_id
    if any(item.precommit.block_id != block_id for item in (*adaptation, *heldout)):
        raise StructuredExecutionValidationError("structured block identity mismatch")
    _validate_family_public_inventory(
        adaptation=adaptation,
        heldout=heldout,
        family="structured",
    )

    item_reports, terminal_states = _validate_adaptation_transitions(adaptation)
    _validate_heldout_freeze(items=heldout, terminal_states=terminal_states)

    canonical_values = (
        canonical_adaptation_precommit_bytes,
        canonical_adaptation_receipt_bytes,
        canonical_adaptation_attestation_bytes,
        canonical_heldout_precommit_bytes,
        canonical_heldout_receipt_bytes,
        canonical_heldout_attestation_bytes,
    )
    canonical_joined = any(value is not None for value in canonical_values)
    if canonical_joined and any(value is None for value in canonical_values):
        raise StructuredExecutionValidationError(
            "canonical online ICL inputs must be all present or all absent"
        )
    if canonical_joined:
        canonical_adaptation_precommits = _require_bytes_tuple(
            canonical_adaptation_precommit_bytes,
            label="canonical_adaptation_precommit_bytes",
            length=count,
        )
        canonical_adaptation_receipts = _require_receipt_matrix(
            canonical_adaptation_receipt_bytes,
            label="canonical_adaptation_receipt_bytes",
            length=count,
        )
        canonical_adaptation_attestations = _require_bytes_tuple(
            canonical_adaptation_attestation_bytes,
            label="canonical_adaptation_attestation_bytes",
            length=count,
        )
        canonical_heldout_precommits = _require_bytes_tuple(
            canonical_heldout_precommit_bytes,
            label="canonical_heldout_precommit_bytes",
            length=count,
        )
        canonical_heldout_receipts = _require_receipt_matrix(
            canonical_heldout_receipt_bytes,
            label="canonical_heldout_receipt_bytes",
            length=count,
        )
        canonical_heldout_attestations = _require_bytes_tuple(
            canonical_heldout_attestation_bytes,
            label="canonical_heldout_attestation_bytes",
            length=count,
        )
        try:
            validate_precommit_digest_sequence(
                adaptation_precommit_bytes=list(canonical_adaptation_precommits),
                heldout_precommit_bytes=list(canonical_heldout_precommits),
                expected_items_per_phase=count,
            )
        except (StructuredCommitmentError, StructuredStateProtocolError) as exc:
            raise StructuredExecutionValidationError(
                "canonical precommit sequence is invalid"
            ) from exc
        canonical_adaptation = _validate_item_inputs(
            precommit_bytes=canonical_adaptation_precommits,
            receipt_bytes=canonical_adaptation_receipts,
            attestation_bytes=canonical_adaptation_attestations,
            expected_family="canonical_online_icl",
            expected_phase="adaptation",
        )
        canonical_heldout = _validate_item_inputs(
            precommit_bytes=canonical_heldout_precommits,
            receipt_bytes=canonical_heldout_receipts,
            attestation_bytes=canonical_heldout_attestations,
            expected_family="canonical_online_icl",
            expected_phase="held_out",
        )
        _validate_family_public_inventory(
            adaptation=canonical_adaptation,
            heldout=canonical_heldout,
            family="canonical_online_icl",
        )
        _validate_cross_family_join(
            structured=adaptation,
            canonical=canonical_adaptation,
        )
        _validate_cross_family_join(
            structured=heldout,
            canonical=canonical_heldout,
        )

    signal_pass_count = sum(item.signal_pass for item in item_reports)
    return StructuredStageExecutionValidation(
        validation_protocol=VALIDATION_PROTOCOL,
        block_id=block_id,
        items_per_phase=count,
        canonical_online_joined=canonical_joined,
        public_inventory_consistent=True,
        dgp_seal_bound=False,
        integrity_pass=True,
        adaptation_items=item_reports,
        signal_pass_item_count=signal_pass_count,
        signal_miss_item_count=count - signal_pass_count,
        all_scientific_signal_gates_pass=signal_pass_count == count,
    )


__all__ = [
    "AdaptationItemValidation",
    "BranchSignalValidation",
    "NON_TIED_PAIR_FLOOR",
    "PAIR_PROBABILITY_MEAN_ABS_FLOOR",
    "REWARD_PAIR_RMS_FLOOR",
    "REWARD_POPULATION_STD_FLOOR",
    "StructuredExecutionValidationError",
    "StructuredStageExecutionValidation",
    "VALIDATION_PROTOCOL",
    "validate_structured_stage_execution",
]
