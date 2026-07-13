"""Adversarial identity and finite-value tests for group-PG publication gates."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from validate_group_pg_manifest import validate as validate_manifest
from validate_group_pg_pairing import validate_pairing


def make_config(
    cfg_id: str,
    *,
    grpo_seed: int,
    context: str = "full",
    frozen: bool = False,
    release_stage: int = 1,
) -> dict:
    arm = "frozen" if frozen else "active"
    return {
        "cfg_id": cfg_id,
        "task": "cohort_studies",
        "group": f"test_{context}_{arm}",
        "pair_id": f"cohort_seed{grpo_seed}",
        "arm": arm,
        "task_order_seed": 42,
        "sampling_seed": grpo_seed,
        "release_stage": release_stage,
        "task_params": {
            "schedule": "default",
            "num_instances": 2,
            "seed": 42,
        },
        "run_mode": "replicate",
        "needs": "",
        "system_params": {
            "reward_update_rule": "group_pg_instance",
            "context_policy": context,
            "grpo_run_seed": grpo_seed,
            "freeze_parameter_updates": frozen,
            "best_of_n": 3,
        },
        "runs": 1,
    }


def make_manifest(config: dict) -> dict:
    frozen = config["arm"] == "frozen"
    num_instances = config["task_params"]["num_instances"]
    updates = 0 if frozen else num_instances
    log = []
    if not frozen:
        log = [
            {
                "group_size": 2,
                "sampling_seed": config["sampling_seed"] + index,
                "sampling_prompt_sha256": f"{index + 1:064x}",
                "prompt_tokens_retained_min": 1,
                "optimizer_steps": 1,
                "loss": 0.25 + index,
                "candidate_sampling": {
                    "requested_group_size": config["system_params"]["best_of_n"],
                    "initial_sample_attempts": (
                        config["system_params"]["best_of_n"] - 1
                    ),
                    "rescue_sample_attempts": 0,
                    "sample_attempts": config["system_params"]["best_of_n"] - 1,
                    "generation_failures": 0,
                    "parse_failures": 0,
                    "duplicates": 0,
                    "valid_unique": config["system_params"]["best_of_n"],
                },
            }
            for index in range(num_instances)
        ]
    outcomes = [
        {
            "instance_id": f"study-{index}",
            "instance_index": index,
            "reward": 0.1 + index,
        }
        for index in range(num_instances)
    ]
    return {
        "status": "completed",
        "phase": "run",
        "system": {
            "name": "qwen_local",
            "params": deepcopy(config["system_params"]),
        },
        "task": {
            "name": config["task"],
            "params": {
                **deepcopy(config["task_params"]),
                "expected_num_instances": num_instances,
            },
        },
        "execution": {
            "run_group_id": config["cfg_id"],
            "run_index": 0,
        },
        "result": {
            "score": 0.6,
            "instance_outcomes": outcomes,
        },
        "system_update_metrics": {
            "reward_update_rule": "group_pg_instance",
            "parameter_updates_enabled": not frozen,
            "freeze_parameter_updates": frozen,
            "grpo_objective": "group_normalized_policy_gradient",
            "grpo_run_seed": config["sampling_seed"],
            "grpo_updates": updates,
            "grpo_optimizer_steps": updates,
            "grpo_skipped_low_std": 0,
            "grpo_skipped_no_group": 0,
            "reward_pg_updates": 0,
            "bon_updates": 0,
            "distill_updates": 0,
            "adaptation_count": 0,
            "grpo_instance_log": log,
        },
    }


def assert_has_error(errors: list[str], fragment: str) -> None:
    assert any(fragment in error for error in errors), errors


def make_candidate_distill_case() -> tuple[dict, dict]:
    config = make_config("cfg-candidate-distill", grpo_seed=303)
    config["system_params"].update(
        {
            "reward_update_rule": "candidate_distill_instance",
            "grpo_candidate_proposer": "unit_interval_jitter",
            "grpo_std_floor": 1e-4,
            "best_of_n": 4,
        }
    )
    manifest = make_manifest(config)
    metrics = manifest["system_update_metrics"]
    metrics["reward_update_rule"] = "candidate_distill_instance"
    metrics["grpo_objective"] = "group_normalized_candidate_distillation"
    metrics["grpo_candidate_proposer"] = "unit_interval_jitter"
    for index, row in enumerate(metrics["grpo_instance_log"]):
        row["objective"] = "group_normalized_candidate_distillation"
        row["candidate_proposer"] = "unit_interval_jitter"
        row["group_size"] = 4
        row["reward_std"] = 0.01
        sampling = row["candidate_sampling"]
        sampling.update(
            {
                "candidate_proposer": "unit_interval_jitter",
                "target_valid_unique": 4,
                "max_sample_attempts": 6,
                "model_generation_attempts": 0,
                "structured_proposal_attempts": 3,
                "proposal_seed_digests": [
                    f"{index * 10 + attempt + 1:064x}" for attempt in range(3)
                ],
                "proposal_mode_counts": {
                    "primary_policy": 1,
                    "unit_interval_jitter": 3,
                },
            }
        )
    return config, manifest


def test_manifest_accepts_exact_registered_config() -> None:
    config = make_config("cfg-a", grpo_seed=101)
    assert (
        validate_manifest(
            make_manifest(config),
            strict_smoke=False,
            expected_config=config,
        )
        == []
    )


def test_manifest_accepts_candidate_distillation_with_honest_objective() -> None:
    config, manifest = make_candidate_distill_case()
    assert (
        validate_manifest(
            manifest,
            strict_smoke=True,
            expected_config=config,
        )
        == []
    )


def test_manifest_rejects_candidate_distillation_mislabeled_as_policy_gradient() -> (
    None
):
    config, manifest = make_candidate_distill_case()
    manifest["system_update_metrics"]["grpo_objective"] = (
        "group_normalized_policy_gradient"
    )
    errors = validate_manifest(
        manifest,
        strict_smoke=True,
        expected_config=config,
    )
    assert_has_error(errors, "wrong/missing grpo_objective")


def test_manifest_rejects_tampered_structured_proposal_seed_provenance() -> None:
    config, manifest = make_candidate_distill_case()
    sampling = manifest["system_update_metrics"]["grpo_instance_log"][0][
        "candidate_sampling"
    ]
    sampling["proposal_seed_digests"][1] = sampling["proposal_seed_digests"][0]
    errors = validate_manifest(
        manifest,
        strict_smoke=True,
        expected_config=config,
    )
    assert_has_error(errors, "proposal_seed_digests are invalid")


def test_candidate_distillation_strict_smoke_requires_four_unique_rewards() -> None:
    config, manifest = make_candidate_distill_case()
    row = manifest["system_update_metrics"]["grpo_instance_log"][0]
    row["group_size"] = 3
    row["candidate_sampling"]["valid_unique"] = 3
    row["candidate_sampling"]["proposal_mode_counts"]["unit_interval_jitter"] = 2
    errors = validate_manifest(
        manifest,
        strict_smoke=True,
        expected_config=config,
    )
    assert_has_error(errors, "diversity gate requires valid_unique >= 4")
    assert_has_error(errors, "diversity gate requires group_size >= 4")


def test_manifest_rejects_misplaced_cfg() -> None:
    config = make_config("cfg-a", grpo_seed=101)
    manifest = make_manifest(config)
    manifest["execution"]["run_group_id"] = "cfg-b"
    errors = validate_manifest(
        manifest,
        strict_smoke=False,
        expected_config=config,
    )
    assert_has_error(errors, "run_group_id/cfg_id mismatch")


def test_manifest_rejects_seed999_substitution() -> None:
    config = make_config("cfg-a", grpo_seed=101)
    manifest = make_manifest(config)
    manifest["system"]["params"]["grpo_run_seed"] = 999
    manifest["system_update_metrics"]["grpo_run_seed"] = 999
    errors = validate_manifest(
        manifest,
        strict_smoke=False,
        expected_config=config,
    )
    assert_has_error(errors, "system.params.grpo_run_seed mismatch")
    assert_has_error(errors, "metric grpo_run_seed mismatch")


def test_manifest_rejects_task_param_substitution() -> None:
    config = make_config("cfg-a", grpo_seed=101)
    manifest = make_manifest(config)
    manifest["task"]["params"]["seed"] = 999
    errors = validate_manifest(
        manifest,
        strict_smoke=False,
        expected_config=config,
    )
    assert_has_error(errors, "task.params.seed mismatch")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requested_group_size", 4),
        ("initial_sample_attempts", 3),
        ("rescue_sample_attempts", -1),
        ("sample_attempts", 3),
        ("generation_failures", 1),
        ("parse_failures", 1),
        ("duplicates", 1),
        ("valid_unique", 2),
    ],
)
def test_manifest_rejects_tampered_candidate_sampling_counter(
    field: str, value: int
) -> None:
    config = make_config("cfg-a", grpo_seed=101)
    manifest = make_manifest(config)
    manifest["system_update_metrics"]["grpo_instance_log"][0]["candidate_sampling"][
        field
    ] = value
    errors = validate_manifest(
        manifest,
        strict_smoke=False,
        expected_config=config,
    )
    assert_has_error(errors, "candidate_sampling")


def test_manifest_accepts_accounted_rescue_sampling() -> None:
    config = make_config("cfg-a", grpo_seed=101)
    config["system_params"]["best_of_n"] = 4
    manifest = make_manifest(config)
    manifest["system_update_metrics"]["grpo_instance_log"][0]["candidate_sampling"] = {
        "requested_group_size": 4,
        "initial_sample_attempts": 3,
        "rescue_sample_attempts": 1,
        "sample_attempts": 4,
        "generation_failures": 2,
        "parse_failures": 0,
        "duplicates": 0,
        "valid_unique": 3,
    }
    assert (
        validate_manifest(
            manifest,
            strict_smoke=True,
            expected_config=config,
        )
        == []
    )


def test_manifest_rejects_legacy_skip_without_candidate_sampling() -> None:
    config = make_config("cfg-a", grpo_seed=101)
    manifest = make_manifest(config)
    row = manifest["system_update_metrics"]["grpo_instance_log"][0]
    row["skipped"] = "low_std"
    row.pop("optimizer_steps")
    row.pop("candidate_sampling")
    metrics = manifest["system_update_metrics"]
    metrics["grpo_updates"] = 1
    metrics["grpo_optimizer_steps"] = 1
    metrics["grpo_skipped_low_std"] = 1
    errors = validate_manifest(
        manifest,
        strict_smoke=False,
        expected_config=config,
    )
    assert_has_error(errors, "candidate_sampling is missing")


def test_manifest_rejects_legacy_success_without_candidate_sampling() -> None:
    config = make_config("cfg-a", grpo_seed=101)
    manifest = make_manifest(config)
    manifest["system_update_metrics"]["grpo_instance_log"][0].pop("candidate_sampling")
    errors = validate_manifest(
        manifest,
        strict_smoke=False,
        expected_config=config,
    )
    assert_has_error(errors, "candidate_sampling is missing")


def test_manifest_rejects_success_group_larger_than_valid_unique() -> None:
    config = make_config("cfg-a", grpo_seed=101)
    manifest = make_manifest(config)
    sampling = manifest["system_update_metrics"]["grpo_instance_log"][0][
        "candidate_sampling"
    ]
    sampling["duplicates"] = 2
    sampling["valid_unique"] = 1
    errors = validate_manifest(
        manifest,
        strict_smoke=False,
        expected_config=config,
    )
    assert_has_error(errors, "valid_unique 1 < successful group_size 2")


@pytest.mark.parametrize(
    ("location", "value"),
    [
        ("score", float("nan")),
        ("score", float("inf")),
        ("reward", float("nan")),
        ("reward", float("-inf")),
    ],
)
def test_manifest_rejects_nonfinite_result_tree(location: str, value: float) -> None:
    config = make_config("cfg-a", grpo_seed=101, frozen=True)
    manifest = make_manifest(config)
    if location == "score":
        manifest["result"]["score"] = value
    else:
        manifest["result"]["instance_outcomes"][0]["reward"] = value
    errors = validate_manifest(
        manifest,
        strict_smoke=False,
        expected_config=config,
    )
    assert_has_error(errors, "non-finite result/instance_outcomes")


def make_stage1_grid() -> list[dict]:
    return [
        make_config("full-active", grpo_seed=101),
        make_config("full-frozen", grpo_seed=101, frozen=True),
        make_config("qonly-active", grpo_seed=101, context="question_only"),
    ]


def test_pairing_accepts_exact_stage_set() -> None:
    grid = make_stage1_grid()
    manifests = [(cfg["cfg_id"], make_manifest(cfg)) for cfg in grid]
    assert (
        validate_pairing(
            manifests,
            grid,
            release_stage=1,
            require_formal_counts=False,
        )
        == []
    )


def test_pairing_rejects_missing_cell() -> None:
    grid = make_stage1_grid()
    manifests = [(cfg["cfg_id"], make_manifest(cfg)) for cfg in grid[:-1]]
    errors = validate_pairing(
        manifests,
        grid,
        release_stage=1,
        require_formal_counts=False,
    )
    assert_has_error(errors, "missing expected cfg_id")


def test_pairing_rejects_duplicate_cell() -> None:
    grid = make_stage1_grid()
    manifests = [(cfg["cfg_id"], make_manifest(cfg)) for cfg in grid]
    manifests.append(("duplicate-copy", deepcopy(manifests[0][1])))
    errors = validate_pairing(
        manifests,
        grid,
        release_stage=1,
        require_formal_counts=False,
    )
    assert_has_error(errors, "duplicate manifest cfg_id")


def test_pairing_rejects_wrong_context_and_arm() -> None:
    grid = make_stage1_grid()
    manifests = [(cfg["cfg_id"], make_manifest(cfg)) for cfg in grid]
    manifests[2][1]["system"]["params"]["context_policy"] = "full"
    manifests[1][1]["system"]["params"]["freeze_parameter_updates"] = False
    errors = validate_pairing(
        manifests,
        grid,
        release_stage=1,
        require_formal_counts=False,
    )
    assert_has_error(errors, "system.params.context_policy mismatch")
    assert_has_error(errors, "system.params.freeze_parameter_updates mismatch")


def test_actual_formal_grid_passes_exact_stage2_registration() -> None:
    grid = json.loads(
        (Path(__file__).resolve().parents[1] / "grid_group_pg_formal.json").read_text()
    )
    manifests = [(cfg["cfg_id"], make_manifest(cfg)) for cfg in grid]
    assert (
        validate_pairing(
            manifests,
            grid,
            release_stage=2,
            require_formal_counts=True,
        )
        == []
    )
