#!/usr/bin/env python3
"""Fail-closed validator for active and frozen-stream group-PG manifests."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def finite_tree(value: Any) -> bool:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return True
    if isinstance(value, (int, float)):
        return math.isfinite(float(value))
    if isinstance(value, list):
        return all(finite_tree(item) for item in value)
    if isinstance(value, dict):
        return all(finite_tree(item) for item in value.values())
    return False


def integer(value: Any, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def strict_json_equal(actual: Any, expected: Any) -> bool:
    """JSON equality that does not treat ``True`` as integer ``1``."""
    if isinstance(expected, bool) or isinstance(actual, bool):
        return (
            isinstance(actual, bool)
            and isinstance(expected, bool)
            and actual == expected
        )
    if isinstance(expected, dict):
        return (
            isinstance(actual, dict)
            and actual.keys() == expected.keys()
            and all(
                strict_json_equal(actual[key], value) for key, value in expected.items()
            )
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(strict_json_equal(a, e) for a, e in zip(actual, expected))
        )
    return type(actual) is type(expected) and actual == expected


def validate_expected_subset(
    actual: Any,
    expected: Any,
    *,
    path: str,
) -> list[str]:
    """Require every expected JSON field while allowing runtime-added fields."""
    if not isinstance(expected, dict):
        return [] if strict_json_equal(actual, expected) else [f"{path} mismatch"]
    if not isinstance(actual, dict):
        return [f"{path} is not an object"]
    errors: list[str] = []
    for key, expected_value in expected.items():
        child_path = f"{path}.{key}"
        if key not in actual:
            errors.append(f"missing {child_path}")
            continue
        actual_value = actual[key]
        if isinstance(expected_value, dict):
            errors.extend(
                validate_expected_subset(
                    actual_value,
                    expected_value,
                    path=child_path,
                )
            )
        elif not strict_json_equal(actual_value, expected_value):
            errors.append(
                f"{child_path} mismatch: expected={expected_value!r} "
                f"actual={actual_value!r}"
            )
    return errors


def validate_expected_config_shape(expected: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    cfg_id = expected.get("cfg_id")
    task = expected.get("task")
    task_params = expected.get("task_params")
    system_params = expected.get("system_params")
    arm = expected.get("arm")
    if not isinstance(cfg_id, str) or not cfg_id:
        errors.append("expected config needs non-empty cfg_id")
    if not isinstance(task, str) or not task:
        errors.append("expected config needs non-empty task")
    if not isinstance(task_params, dict):
        errors.append("expected config task_params must be an object")
    if not isinstance(system_params, dict):
        errors.append("expected config system_params must be an object")
        system_params = {}
    if arm not in {"active", "frozen"}:
        errors.append("expected config arm must be active or frozen")
    elif (arm == "frozen") != (system_params.get("freeze_parameter_updates") is True):
        errors.append("expected config arm/freeze_parameter_updates mismatch")
    if isinstance(task_params, dict):
        if expected.get("task_order_seed") != task_params.get("seed"):
            errors.append("expected config task_order_seed/task_params.seed mismatch")
    if isinstance(system_params, dict):
        if expected.get("sampling_seed") != system_params.get("grpo_run_seed"):
            errors.append("expected config sampling_seed/grpo_run_seed mismatch")
    if expected.get("runs") != 1:
        errors.append("expected config runs must be exactly 1")
    if expected.get("run_mode") != "replicate":
        errors.append("expected config run_mode must be replicate")
    return errors


def validate_candidate_sampling(
    row: dict[str, Any],
    *,
    index: int,
    best_of_n: Any,
    candidate_proposer: Any,
    successful: bool,
) -> list[str]:
    path = f"log[{index}].candidate_sampling"
    sampling = row.get("candidate_sampling")
    if not isinstance(sampling, dict):
        return [f"{path} is missing or not an object"]

    fields = (
        "requested_group_size",
        "initial_sample_attempts",
        "rescue_sample_attempts",
        "sample_attempts",
        "generation_failures",
        "parse_failures",
        "duplicates",
        "valid_unique",
    )
    errors = [
        f"{path}.{field} is not a nonnegative integer"
        for field in fields
        if not integer(sampling.get(field))
    ]
    if not integer(best_of_n, minimum=2):
        errors.append("system.params.best_of_n is not an integer >= 2")
        return errors
    if errors:
        return errors

    requested = sampling["requested_group_size"]
    initial = sampling["initial_sample_attempts"]
    rescue = sampling["rescue_sample_attempts"]
    attempts = sampling["sample_attempts"]
    generation_failures = sampling["generation_failures"]
    parse_failures = sampling["parse_failures"]
    duplicates = sampling["duplicates"]
    valid_unique = sampling["valid_unique"]
    if requested != best_of_n:
        errors.append(
            f"{path}.requested_group_size {requested} != best_of_n {best_of_n}"
        )
    if initial != best_of_n - 1:
        errors.append(
            f"{path}.initial_sample_attempts {initial} != best_of_n-1 {best_of_n - 1}"
        )
    if rescue > best_of_n - 1:
        errors.append(
            f"{path}.rescue_sample_attempts {rescue} exceeds best_of_n-1 {best_of_n - 1}"
        )
    if attempts != initial + rescue:
        errors.append(
            f"{path}.sample_attempts {attempts} != initial+rescue {initial + rescue}"
        )
    expected_unique = 1 + attempts - generation_failures - parse_failures - duplicates
    if valid_unique != expected_unique:
        errors.append(
            f"{path}.valid_unique {valid_unique} != accounting value {expected_unique}"
        )
    if not 1 <= valid_unique <= best_of_n:
        errors.append(f"{path}.valid_unique must be in [1, {best_of_n}]")
    group_size = row.get("group_size")
    if successful and integer(group_size, minimum=2) and valid_unique < group_size:
        errors.append(
            f"{path}.valid_unique {valid_unique} < successful group_size {group_size}"
        )
    if candidate_proposer == "unit_interval_jitter":
        if sampling.get("candidate_proposer") != candidate_proposer:
            errors.append(f"{path}.candidate_proposer mismatch")
        if sampling.get("target_valid_unique") != best_of_n:
            errors.append(f"{path}.target_valid_unique must equal best_of_n")
        expected_cap = 2 * (best_of_n - 1)
        if sampling.get("max_sample_attempts") != expected_cap:
            errors.append(f"{path}.max_sample_attempts must equal {expected_cap}")
        if attempts > expected_cap:
            errors.append(f"{path}.sample_attempts exceeds bounded cap")
        if sampling.get("model_generation_attempts") != 0:
            errors.append(f"{path}.model_generation_attempts must be zero")
        if sampling.get("structured_proposal_attempts") != attempts:
            errors.append(
                f"{path}.structured_proposal_attempts must equal sample_attempts"
            )
        digests = sampling.get("proposal_seed_digests")
        if (
            not isinstance(digests, list)
            or len(digests) != attempts
            or len(set(digests)) != len(digests)
            or any(
                not isinstance(digest, str) or len(digest) != 64 for digest in digests
            )
        ):
            errors.append(f"{path}.proposal_seed_digests are invalid")
        counts = sampling.get("proposal_mode_counts")
        if not isinstance(counts, dict) or counts != {
            "primary_policy": 1,
            "unit_interval_jitter": valid_unique - 1,
        }:
            errors.append(f"{path}.proposal_mode_counts mismatch")
    elif candidate_proposer != "policy_sample":
        errors.append(f"unsupported candidate proposer: {candidate_proposer!r}")
    return errors


def validate(
    payload: dict[str, Any],
    *,
    strict_smoke: bool,
    expected_config: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    metrics = payload.get("system_update_metrics")
    system = payload.get("system")
    result = payload.get("result")
    task = payload.get("task")
    execution = payload.get("execution")
    if not isinstance(metrics, dict):
        return ["missing system_update_metrics"]
    if not isinstance(system, dict) or not isinstance(system.get("params"), dict):
        return ["missing system.params"]
    if not isinstance(result, dict) or not isinstance(
        result.get("instance_outcomes"), list
    ):
        return ["missing result.instance_outcomes"]
    if not isinstance(task, dict) or not isinstance(task.get("params"), dict):
        return ["missing task.params"]
    if not isinstance(execution, dict):
        return ["missing execution"]

    sp = system["params"]
    tp = task["params"]
    reward_update_rule = sp.get("reward_update_rule")
    candidate_proposer = sp.get("grpo_candidate_proposer", "policy_sample")
    expected_objective = (
        "group_normalized_candidate_distillation"
        if reward_update_rule == "candidate_distill_instance"
        else "group_normalized_policy_gradient"
    )
    frozen = sp.get("freeze_parameter_updates") is True
    expected = tp.get("expected_num_instances", tp.get("num_instances"))
    outcomes = [
        row
        for row in result["instance_outcomes"]
        if isinstance(row, dict)
        and not str(row.get("instance_id", "")).startswith("__failed")
    ]
    failed = [
        row
        for row in result["instance_outcomes"]
        if isinstance(row, dict)
        and str(row.get("instance_id", "")).startswith("__failed")
    ]
    log = metrics.get("grpo_instance_log")
    updates = metrics.get("grpo_updates")
    optimizer_steps = metrics.get("grpo_optimizer_steps")
    low_std = metrics.get("grpo_skipped_low_std")
    no_group = metrics.get("grpo_skipped_no_group")

    if payload.get("status") != "completed":
        errors.append("status is not completed")
    if system.get("name") != "qwen_local":
        errors.append("wrong system name")
    if reward_update_rule not in {
        "group_pg_instance",
        "candidate_distill_instance",
    }:
        errors.append("wrong reward_update_rule")
    if metrics.get("reward_update_rule") != reward_update_rule:
        errors.append("metric rule mismatch")
    if metrics.get("grpo_objective") != expected_objective:
        errors.append("wrong/missing grpo_objective")
    metric_candidate_proposer = metrics.get(
        "grpo_candidate_proposer",
        "policy_sample" if candidate_proposer == "policy_sample" else None,
    )
    if metric_candidate_proposer != candidate_proposer:
        errors.append("metric candidate proposer mismatch")
    if reward_update_rule == "group_pg_instance" and candidate_proposer != (
        "policy_sample"
    ):
        errors.append("group policy-gradient requires policy_sample proposer")
    if reward_update_rule == "candidate_distill_instance" and candidate_proposer != (
        "unit_interval_jitter"
    ):
        errors.append("candidate distillation requires unit_interval_jitter proposer")
    frozen_weight_probe = (
        reward_update_rule == "candidate_distill_instance"
        and sp.get("ttt_lr") == 0
        and sp.get("reward_pg_lr") == 0
    )
    if frozen_weight_probe:
        initial_hash = metrics.get("grpo_trainable_param_sha256_initial")
        current_hash = metrics.get("grpo_trainable_param_sha256_current")
        if (
            not isinstance(initial_hash, str)
            or len(initial_hash) != 64
            or current_hash != initial_hash
        ):
            errors.append("LR0 trainable parameter hashes are missing or changed")
    if not integer(sp.get("grpo_run_seed")):
        errors.append("missing explicit grpo_run_seed")
    if not integer(expected, minimum=1) or len(outcomes) != expected:
        errors.append(f"real outcome count {len(outcomes)} != expected {expected}")
    if failed:
        errors.append(f"phantom/failed outcomes present: {len(failed)}")
    if not all(
        integer(value) for value in (updates, optimizer_steps, low_std, no_group)
    ):
        errors.append("update/skip counters are not nonnegative integers")
    if not isinstance(log, list):
        errors.append("grpo_instance_log is not a list")
        log = []
    if any(
        metrics.get(name) != 0
        for name in (
            "reward_pg_updates",
            "bon_updates",
            "distill_updates",
            "adaptation_count",
        )
    ):
        errors.append("legacy update path activity detected")
    if not finite_tree(metrics):
        errors.append("non-finite telemetry")
    if not finite_tree(result):
        errors.append("non-finite result/instance_outcomes")

    if expected_config is not None:
        errors.extend(validate_expected_config_shape(expected_config))
        expected_task_params = expected_config.get("task_params")
        if not isinstance(expected_task_params, dict):
            expected_task_params = {}
        expected_system_params = expected_config.get("system_params")
        if not isinstance(expected_system_params, dict):
            expected_system_params = {}
        cfg_id = expected_config.get("cfg_id")
        if execution.get("run_group_id") != cfg_id:
            errors.append(
                "execution.run_group_id/cfg_id mismatch: "
                f"expected={cfg_id!r} actual={execution.get('run_group_id')!r}"
            )
        if task.get("name") != expected_config.get("task"):
            errors.append(
                "task.name mismatch: "
                f"expected={expected_config.get('task')!r} "
                f"actual={task.get('name')!r}"
            )
        errors.extend(
            validate_expected_subset(
                tp,
                expected_task_params,
                path="task.params",
            )
        )
        errors.extend(
            validate_expected_subset(
                sp,
                expected_system_params,
                path="system.params",
            )
        )
        expected_runs = expected_config.get("runs")
        if (
            integer(expected_runs, minimum=1)
            and execution.get("run_index") != expected_runs - 1
        ):
            errors.append(
                "execution.run_index mismatch: "
                f"expected={expected_runs - 1} actual={execution.get('run_index')!r}"
            )
        expected_arm = expected_config.get("arm")
        if expected_arm in {"active", "frozen"}:
            actual_arm = "frozen" if frozen else "active"
            if actual_arm != expected_arm:
                errors.append(
                    f"arm mismatch: expected={expected_arm!r} actual={actual_arm!r}"
                )
        expected_seed = expected_system_params.get("grpo_run_seed")
        if metrics.get("grpo_run_seed") != expected_seed:
            errors.append(
                "metric grpo_run_seed mismatch: "
                f"expected={expected_seed!r} actual={metrics.get('grpo_run_seed')!r}"
            )
        expected_frozen = expected_system_params.get("freeze_parameter_updates")
        if metrics.get("freeze_parameter_updates") is not expected_frozen:
            errors.append(
                "metric freeze_parameter_updates mismatch: "
                f"expected={expected_frozen!r} "
                f"actual={metrics.get('freeze_parameter_updates')!r}"
            )

    if frozen:
        if metrics.get("parameter_updates_enabled") is not False:
            errors.append("frozen arm reports updates enabled")
        if any(value != 0 for value in (updates, optimizer_steps, low_std, no_group)):
            errors.append("frozen arm has nonzero update/skip counters")
        if log:
            errors.append("frozen arm generated/trained a candidate group")
    else:
        if metrics.get("parameter_updates_enabled") is not True:
            errors.append("active arm reports updates disabled")
        if integer(expected, minimum=1) and len(log) != expected:
            errors.append(f"active log count {len(log)} != expected {expected}")
        if integer(updates) and integer(low_std) and integer(no_group):
            if updates + low_std + no_group != len(log):
                errors.append("active update/skip accounting mismatch")
            if optimizer_steps != updates:
                errors.append("optimizer_steps must equal successful group updates")
        for index, row in enumerate(log):
            if not isinstance(row, dict):
                errors.append(f"log[{index}] is not an object")
                continue
            row_objective = row.get("objective")
            if (
                row_objective is not None or candidate_proposer != "policy_sample"
            ) and row_objective != expected_objective:
                errors.append(f"log[{index}] objective mismatch")
            row_proposer = row.get("candidate_proposer")
            if (
                row_proposer is not None or candidate_proposer != "policy_sample"
            ) and row_proposer != candidate_proposer:
                errors.append(f"log[{index}] candidate proposer mismatch")
            successful = row.get("skipped") is None
            errors.extend(
                validate_candidate_sampling(
                    row,
                    index=index,
                    best_of_n=sp.get("best_of_n"),
                    candidate_proposer=candidate_proposer,
                    successful=successful,
                )
            )
            if successful:
                if row.get("optimizer_steps") != 1:
                    errors.append(f"log[{index}] did not use one group optimizer step")
                if not integer(row.get("group_size"), minimum=2):
                    errors.append(f"log[{index}] has invalid group_size")
                if not integer(row.get("sampling_seed")):
                    errors.append(f"log[{index}] missing sampling_seed")
                digest = row.get("sampling_prompt_sha256")
                if not isinstance(digest, str) or len(digest) != 64:
                    errors.append(f"log[{index}] missing prompt digest")
                retained = row.get(
                    "prompt_tokens_retained_min",
                    row.get("retained_prompt_tokens_min"),
                )
                if not integer(retained, minimum=1):
                    errors.append(f"log[{index}] retained no prompt tokens")
                if frozen_weight_probe:
                    before_hash = row.get("trainable_param_sha256_before")
                    after_hash = row.get("trainable_param_sha256_after")
                    if (
                        not isinstance(before_hash, str)
                        or len(before_hash) != 64
                        or after_hash != before_hash
                    ):
                        errors.append(
                            f"log[{index}] LR0 trainable parameter hash changed"
                        )
        if strict_smoke:
            if updates != expected:
                errors.append("smoke requires one successful update per instance")
            if low_std != 0 or no_group != 0:
                errors.append("smoke does not permit skipped groups")
            if reward_update_rule == "candidate_distill_instance":
                required_unique = min(4, int(sp.get("best_of_n") or 0))
                for index, row in enumerate(log):
                    if not isinstance(row, dict):
                        continue
                    sampling = row.get("candidate_sampling")
                    valid_unique = (
                        sampling.get("valid_unique")
                        if isinstance(sampling, dict)
                        else None
                    )
                    if not integer(valid_unique, minimum=required_unique):
                        errors.append(
                            f"log[{index}] diversity gate requires valid_unique "
                            f">= {required_unique}"
                        )
                    if not integer(row.get("group_size"), minimum=required_unique):
                        errors.append(
                            f"log[{index}] diversity gate requires group_size "
                            f">= {required_unique}"
                        )
                    reward_std = row.get("reward_std")
                    if (
                        not isinstance(reward_std, (int, float))
                        or isinstance(reward_std, bool)
                        or float(reward_std) <= float(sp.get("grpo_std_floor", 1e-4))
                    ):
                        errors.append(
                            f"log[{index}] diversity gate requires nonzero reward_std"
                        )

    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--expected-config",
        required=True,
        help="Full registered grid-cell JSON object.",
    )
    parser.add_argument("--strict-smoke", action="store_true")
    args = parser.parse_args()
    try:
        expected_config = json.loads(args.expected_config)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--expected-config is not valid JSON: {exc}") from exc
    if not isinstance(expected_config, dict):
        raise SystemExit("--expected-config must decode to one grid-cell object")
    errors = validate(
        json.loads(args.manifest.read_text()),
        strict_smoke=args.strict_smoke,
        expected_config=expected_config,
    )
    if errors:
        for error in errors:
            print(f"INVALID: {error}")
        raise SystemExit(1)
    print("GROUP_PG_MANIFEST_OK")


if __name__ == "__main__":
    main()
