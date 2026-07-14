from __future__ import annotations

import pytest

import cohort_closed_loop_structured_dgp_context as dgp
import cohort_closed_loop_structured_stage_authorization as auth


def test_legacy_seal_only_trigger_and_claim_only_protocol_plan_are_disabled() -> None:
    with pytest.raises(
        auth.StructuredStageAuthorizationError,
        match="seal-only trigger receipts are disabled",
    ):
        auth.build_trigger_receipt_bytes(trigger_execution_seal_bytes=b"{}")
    with pytest.raises(
        auth.StructuredStageAuthorizationError,
        match="legacy trigger receipt validation is disabled",
    ):
        auth.validate_trigger_receipt_bytes(b"{}")
    with pytest.raises(
        auth.StructuredStageAuthorizationError,
        match="legacy protocol-plan construction is disabled",
    ):
        auth.build_protocol_plan_seal_bytes(
            trigger_receipt_bytes=b"{}",
            source_binding_inventory_bytes=b"{}",
            asset_binding_inventory_bytes=b"{}",
            durable_root="/durable",
        )
    with pytest.raises(
        auth.StructuredStageAuthorizationError,
        match="legacy protocol-plan validation is disabled",
    ):
        auth.validate_protocol_plan_seal_bytes(b"{}", trigger_receipt_bytes=b"{}")


@pytest.mark.parametrize(
    "stage,expected_cells,expected_receipts,expected_generations",
    (
        (dgp.StageKind.SMOKE, 5, 285, 20),
        (dgp.StageKind.INTERNAL, 15, 3420, 240),
        (dgp.StageKind.CONFIRMATION, 40, 9120, 640),
    ),
)
def test_registered_accounting_remains_descriptive_and_exact(
    stage: dgp.StageKind,
    expected_cells: int,
    expected_receipts: int,
    expected_generations: int,
) -> None:
    accounting = auth.registered_stage_accounting(stage.value)
    assert accounting["logical_arm_cell_count"] == expected_cells
    assert accounting["total_scorer_receipt_count"] == expected_receipts
    assert accounting["initial_model_generation_count"] == expected_generations


@pytest.mark.parametrize(
    "stage,expected_inventory_count,expected_absence_count",
    (
        (dgp.StageKind.SMOKE, 1_317, 1_241),
        (dgp.StageKind.INTERNAL, 14_625, 13_881),
        (dgp.StageKind.CONFIRMATION, 38_895, 36_931),
    ),
)
def test_registered_path_enumeration_remains_closed_and_deterministic(
    stage: dgp.StageKind,
    expected_inventory_count: int,
    expected_absence_count: int,
) -> None:
    paths = auth._concrete_paths(  # noqa: SLF001
        durable_root="/durable",
        stage=stage,
        attempt_id="attempt-001",
    )
    inventory = auth._expected_path_inventory(stage=stage, paths=paths)  # noqa: SLF001
    assert len(inventory) == expected_inventory_count
    assert inventory == sorted(inventory, key=lambda row: row["path"])
    assert len({row["path"] for row in inventory}) == len(inventory)
    pending = auth._expected_pending_production_outputs(  # noqa: SLF001
        {
            "stage_kind": stage.value,
            "paths": paths,
            "expected_path_inventory": inventory,
        }
    )
    assert len(pending) == expected_absence_count
    assert len({row["path"] for row in pending}) == len(pending)


@pytest.mark.parametrize(
    "attempt_id",
    (
        "smoke-attempt-001",
        "attempt-1",
        "attempt-0001",
        "attempt-abc",
        "latest",
        "attempt-001/child",
    ),
)
def test_attempt_id_is_exact_attempt_nnn(attempt_id: str) -> None:
    with pytest.raises(
        auth.StructuredStageAuthorizationError,
        match=r"attempt-\[0-9\]\{3\}",
    ):
        auth._concrete_paths(  # noqa: SLF001
            durable_root="/durable",
            stage=dgp.StageKind.SMOKE,
            attempt_id=attempt_id,
        )


def test_stage_transitions_remain_fail_closed_until_phase_later_validators_exist() -> (
    None
):
    with pytest.raises(
        auth.StructuredStageAuthorizationError,
        match="stage transitions are unavailable",
    ):
        auth.build_stage_transition_receipt_bytes(
            stage_kind="smoke",
            attempt_id="attempt-001",
            structured_stage_protocol_seal_bytes=b"",
            prelaunch_gate_bytes=b"",
            stage_report_bytes=b"",
            stage_report_revalidated_bytes=b"",
            private_validation_bytes=b"",
            completion_marker_bytes=b"",
            sealed_inventory_bytes=b"",
            prior_transition_receipt_bytes=(),
        )
