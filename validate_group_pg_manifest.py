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


def validate(payload: dict[str, Any], *, strict_smoke: bool) -> list[str]:
    errors: list[str] = []
    metrics = payload.get("system_update_metrics")
    system = payload.get("system")
    result = payload.get("result")
    task = payload.get("task")
    if not isinstance(metrics, dict):
        return ["missing system_update_metrics"]
    if not isinstance(system, dict) or not isinstance(system.get("params"), dict):
        return ["missing system.params"]
    if not isinstance(result, dict) or not isinstance(result.get("instance_outcomes"), list):
        return ["missing result.instance_outcomes"]
    if not isinstance(task, dict) or not isinstance(task.get("params"), dict):
        return ["missing task.params"]

    sp = system["params"]
    tp = task["params"]
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
    if sp.get("reward_update_rule") != "group_pg_instance":
        errors.append("wrong reward_update_rule")
    if metrics.get("reward_update_rule") != "group_pg_instance":
        errors.append("metric rule mismatch")
    if metrics.get("grpo_objective") != "group_normalized_policy_gradient":
        errors.append("wrong/missing grpo_objective")
    if tp.get("seed") != 42:
        errors.append("registered task-order seed is not 42")
    if not integer(sp.get("grpo_run_seed")):
        errors.append("missing explicit grpo_run_seed")
    if tp.get("run_index") != 1:
        errors.append("registered task run_index missing")
    if not integer(expected, minimum=1) or len(outcomes) != expected:
        errors.append(f"real outcome count {len(outcomes)} != expected {expected}")
    if failed:
        errors.append(f"phantom/failed outcomes present: {len(failed)}")
    if not all(integer(value) for value in (updates, optimizer_steps, low_std, no_group)):
        errors.append("update/skip counters are not nonnegative integers")
    if not isinstance(log, list):
        errors.append("grpo_instance_log is not a list")
        log = []
    if any(metrics.get(name) != 0 for name in ("reward_pg_updates", "bon_updates", "distill_updates", "adaptation_count")):
        errors.append("legacy update path activity detected")
    if not finite_tree(metrics):
        errors.append("non-finite telemetry")

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
            if row.get("skipped") is None:
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
        if strict_smoke:
            if updates != expected:
                errors.append("smoke requires one successful update per instance")
            if low_std != 0 or no_group != 0:
                errors.append("smoke does not permit skipped groups")

    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--strict-smoke", action="store_true")
    args = parser.parse_args()
    errors = validate(json.loads(args.manifest.read_text()), strict_smoke=args.strict_smoke)
    if errors:
        for error in errors:
            print(f"INVALID: {error}")
        raise SystemExit(1)
    print("GROUP_PG_MANIFEST_OK")


if __name__ == "__main__":
    main()
