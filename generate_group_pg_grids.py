#!/usr/bin/env python3
"""Generate the corrected D2 group-PG smoke and production grids.

This file is intentionally standalone and does not mutate the living TTT-RL
runbook.  It encodes paired task order and model sampling seeds so active,
frozen-stream, and qonly arms can be compared without hidden order drift.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any


FORMAL_SEEDS = (2026071201, 2026071202, 2026071203, 2026071204, 2026071205)
SMOKE_SEED = 2026071299
TASK_ORDER_SEED = 42

COMMON_SYSTEM_PARAMS: dict[str, Any] = {
    "max_context_tokens": 32768,
    "head_tokens": 4096,
    "tail_tokens": 4096,
    "max_new_tokens": 8192,
    "action_max_new_tokens": 4096,
    # Cohort terminal targets are about 2642 tokens.  1024 would truncate the
    # whole prompt and silently train target-only; 4096 retains prompt context.
    "ttt_max_tokens": 4096,
    "ttt_chunk_tokens": 512,
    "ttt_stride_tokens": 256,
    "ttt_max_chunks": 4,
    "reward_positive_weight": 1.0,
    "reward_negative_weight": 0.5,
    "adaptation_context_policy": "head4k_tail4k",
    "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
    "inject_env_reward": False,
    "lora_param_norm_clip": 0.25,
    "method": "ttt_rl",
    "ttt_rl_source": "sft",
    "peft_method": "lora",
    "lora_rank": 64,
    "lora_alpha": 128,
    "lora_target_modules": "q_proj,v_proj,gate_proj,up_proj,down_proj",
    "history_ttt": False,
    "best_of_n": 8,
    "bon_temperature": 0.8,
    "bon_critic": "env",
    "distill_provider": "off",
    "distill_contrastive": True,
    "reward_judge_provider": "env",
    "ttt_lr": 1e-4,
    "reward_pg_lr": 1e-4,
    "ttt_steps": 1,
    "bon_env_reward": "near",
    # Honest method name.  grpo_instance remains a compatibility alias only.
    "reward_update_rule": "group_pg_instance",
}


def task_params(num_instances: int) -> dict[str, Any]:
    # run_index=1 is deliberate: CohortStudiesTask.prepare_run(0) is a no-op.
    # The launcher must pass run_mode=replicate so the benchmark does not
    # overwrite this explicit index with the outer single-run index (zero).
    return {
        "schedule": "default",
        "num_instances": num_instances,
        "seed": TASK_ORDER_SEED,
        "run_index": 1,
        "rollout_index": 1,
    }


def cell(
    *,
    seed: int,
    context: str,
    frozen: bool,
    num_instances: int,
    release_stage: int,
) -> dict[str, Any]:
    context_id = "full" if context == "full" else "qonly"
    arm = "frozen" if frozen else "active"
    cfg_id = f"gpgfix_cohort_{context_id}_{arm}_k8_lr1e-4_seed{seed}"
    system_params = deepcopy(COMMON_SYSTEM_PARAMS)
    system_params.update(
        {
            "context_policy": context,
            "grpo_run_seed": seed,
            "freeze_parameter_updates": frozen,
        }
    )
    return {
        "cfg_id": cfg_id,
        "task": "cohort_studies",
        "group": f"gpgfix_cohort_{context_id}_{arm}",
        "pair_id": f"cohort_seed{seed}",
        "arm": arm,
        "task_order_seed": TASK_ORDER_SEED,
        "sampling_seed": seed,
        "release_stage": release_stage,
        "task_params": task_params(num_instances),
        "run_mode": "replicate",
        "needs": "",
        "system_params": system_params,
        "runs": 1,
    }


def make_smoke() -> list[dict[str, Any]]:
    return [
        cell(
            seed=SMOKE_SEED,
            context="full",
            frozen=False,
            num_instances=5,
            release_stage=1,
        ),
        cell(
            seed=SMOKE_SEED,
            context="full",
            frozen=True,
            num_instances=5,
            release_stage=1,
        ),
    ]


def make_formal() -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    configs.extend(
        cell(
            seed=seed,
            context="full",
            frozen=False,
            num_instances=20,
            release_stage=1 if seed == FORMAL_SEEDS[0] else 2,
        )
        for seed in FORMAL_SEEDS
    )
    configs.extend(
        cell(
            seed=seed,
            context="full",
            frozen=True,
            num_instances=20,
            release_stage=1 if seed == FORMAL_SEEDS[0] else 2,
        )
        for seed in FORMAL_SEEDS[:2]
    )
    configs.extend(
        cell(
            seed=seed,
            context="question_only",
            frozen=False,
            num_instances=20,
            release_stage=1 if seed == FORMAL_SEEDS[0] else 2,
        )
        for seed in FORMAL_SEEDS[:3]
    )
    return configs


def validate(configs: list[dict[str, Any]], *, smoke: bool) -> None:
    ids = [cfg["cfg_id"] for cfg in configs]
    assert len(ids) == len(set(ids)), "cfg_ids must be globally unique"
    assert all(cfg["runs"] == 1 for cfg in configs)
    assert all(cfg["run_mode"] == "replicate" for cfg in configs)
    assert all(cfg["task_params"]["run_index"] == 1 for cfg in configs)
    assert all(cfg["task_params"]["seed"] == TASK_ORDER_SEED for cfg in configs)
    assert all(cfg["task_order_seed"] == TASK_ORDER_SEED for cfg in configs)
    assert all(cfg["system_params"]["reward_update_rule"] == "group_pg_instance" for cfg in configs)
    assert len({json.dumps(cfg["task_params"], sort_keys=True) for cfg in configs}) == 1

    by_pair: dict[str, list[dict[str, Any]]] = {}
    for cfg in configs:
        by_pair.setdefault(cfg["pair_id"], []).append(cfg)
    for members in by_pair.values():
        task_shapes = {json.dumps(cfg["task_params"], sort_keys=True) for cfg in members}
        assert len(task_shapes) == 1, "paired arms must have identical task order"

    if smoke:
        assert len(configs) == 2
        assert all(cfg["task_params"]["num_instances"] == 5 for cfg in configs)
    else:
        counts = Counter(
            (
                cfg["system_params"]["context_policy"],
                cfg["system_params"]["freeze_parameter_updates"],
            )
            for cfg in configs
        )
        assert len(configs) == 10
        assert counts[("full", False)] == 5
        assert counts[("full", True)] == 2
        assert counts[("question_only", False)] == 3
        assert all(cfg["task_params"]["num_instances"] == 20 for cfg in configs)


def write_json(path: Path, payload: list[dict[str, Any]]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    smoke = make_smoke()
    formal = make_formal()
    validate(smoke, smoke=True)
    validate(formal, smoke=False)
    if args.check:
        print("GROUP_PG_GRID_CHECK_OK smoke=2 formal=10")
        return
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "grid_group_pg_smoke.json", smoke)
    write_json(args.output_dir / "grid_group_pg_formal.json", formal)
    print(f"wrote {args.output_dir}/grid_group_pg_smoke.json (2 cells)")
    print(f"wrote {args.output_dir}/grid_group_pg_formal.json (10 cells)")


if __name__ == "__main__":
    main()
