#!/usr/bin/env python3
"""Generate the paired formal candidate-distillation grid.

Candidate distillation is an explicitly off-policy objective.  Each sampling
seed is evaluated with an updating arm and a zero-learning-rate control while
keeping task order, proposer randomness, and every other registered parameter
identical.
"""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


FORMAL_SEEDS = (2026071201, 2026071202, 2026071203)
TASK_ORDER_SEED = 42
NUM_INSTANCES = 20
GRID_NAME = "grid_candidate_distill_formal.json"

COMMON_SYSTEM_PARAMS: dict[str, Any] = {
    "max_context_tokens": 32768,
    "head_tokens": 4096,
    "tail_tokens": 4096,
    "max_new_tokens": 8192,
    "action_max_new_tokens": 4096,
    "ttt_max_tokens": 4096,
    "ttt_chunk_tokens": 512,
    "ttt_stride_tokens": 256,
    "ttt_max_chunks": 4,
    "reward_positive_weight": 1.0,
    "reward_negative_weight": 0.5,
    "adaptation_context_policy": "head4k_tail4k",
    "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
    "inject_env_reward": False,
    "lora_param_norm_clip": 0.0,
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
    "ttt_lr": 0.0,
    "ttt_steps": 1,
    "bon_env_reward": "near",
    "reward_update_rule": "candidate_distill_instance",
    "grpo_candidate_proposer": "unit_interval_jitter",
    "context_policy": "full",
    "freeze_parameter_updates": False,
}


def task_params() -> dict[str, Any]:
    """Return the registered deterministic Cohort task shape."""

    return {
        "schedule": "default",
        "num_instances": NUM_INSTANCES,
        "expected_num_instances": NUM_INSTANCES,
        "seed": TASK_ORDER_SEED,
    }


def cell(*, seed: int, candidate_arm: str) -> dict[str, Any]:
    """Build one member of a seed-matched active/LR0 pair."""

    if candidate_arm not in {"active", "lr0"}:
        raise ValueError(f"unsupported candidate_arm: {candidate_arm!r}")
    reward_pg_lr = 1e-4 if candidate_arm == "active" else 0.0
    cfg_id = (
        "gpgfix_cohort_full_candidate_distill_v2_"
        f"{candidate_arm}_seed{seed}_n{NUM_INSTANCES}"
    )
    system_params = deepcopy(COMMON_SYSTEM_PARAMS)
    system_params.update(
        {
            "reward_pg_lr": reward_pg_lr,
            "grpo_run_seed": seed,
        }
    )
    return {
        "cfg_id": cfg_id,
        "task": "cohort_studies",
        "group": f"gpgfix_cohort_full_candidate_distill_v2_{candidate_arm}",
        "pair_id": f"cohort_candidate_distill_seed{seed}",
        # Candidate distillation uses its own arm label.  Keep the legacy arm
        # active because both cells execute the active path and the current
        # assignment validator binds arm=frozen to freeze_parameter_updates.
        "candidate_arm": candidate_arm,
        "arm": "active",
        "task_order_seed": TASK_ORDER_SEED,
        "sampling_seed": seed,
        "release_stage": 1,
        "task_params": task_params(),
        "run_mode": "replicate",
        "needs": "",
        "system_params": system_params,
        "runs": 1,
    }


def make_formal() -> list[dict[str, Any]]:
    """Return three adjacent active/LR0 pairs in deterministic seed order."""

    return [
        cell(seed=seed, candidate_arm=candidate_arm)
        for seed in FORMAL_SEEDS
        for candidate_arm in ("active", "lr0")
    ]


def validate(configs: list[dict[str, Any]]) -> None:
    """Fail closed if pairing or the formal experiment contract drifts."""

    assert len(configs) == 2 * len(FORMAL_SEEDS)
    cfg_ids = [cfg["cfg_id"] for cfg in configs]
    assert len(cfg_ids) == len(set(cfg_ids)), "cfg_ids must be globally unique"

    for seed in FORMAL_SEEDS:
        pair = [cfg for cfg in configs if cfg["sampling_seed"] == seed]
        assert len(pair) == 2, f"seed {seed} must have exactly two arms"
        assert {cfg["candidate_arm"] for cfg in pair} == {"active", "lr0"}
        assert len({cfg["pair_id"] for cfg in pair}) == 1
        assert (
            len({json.dumps(cfg["task_params"], sort_keys=True) for cfg in pair}) == 1
        )
        assert all(cfg["arm"] == "active" for cfg in pair)
        assert all(
            cfg["system_params"]["freeze_parameter_updates"] is False for cfg in pair
        )
        rates = {
            cfg["candidate_arm"]: cfg["system_params"]["reward_pg_lr"] for cfg in pair
        }
        assert rates == {"active": 1e-4, "lr0": 0.0}

    for cfg in configs:
        sp = cfg["system_params"]
        tp = cfg["task_params"]
        assert cfg["task"] == "cohort_studies"
        assert cfg["sampling_seed"] == sp["grpo_run_seed"]
        assert cfg["task_order_seed"] == TASK_ORDER_SEED
        assert cfg["run_mode"] == "replicate"
        assert cfg["runs"] == 1
        assert tp == task_params()
        assert sp["ttt_lr"] == 0.0
        assert sp["lora_param_norm_clip"] == 0.0
        assert sp["freeze_parameter_updates"] is False
        assert sp["grpo_candidate_proposer"] == "unit_interval_jitter"
        assert sp["reward_update_rule"] == "candidate_distill_instance"
        assert sp["context_policy"] == "full"
        assert sp["best_of_n"] == 8


def json_text(payload: list[dict[str, Any]]) -> str:
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    formal = make_formal()
    validate(formal)
    output = args.output_dir / GRID_NAME
    expected = json_text(formal)
    if args.check:
        if not output.is_file() or output.read_text() != expected:
            raise SystemExit(f"registered grid is stale: {output}")
        print("CANDIDATE_DISTILL_GRID_CHECK_OK formal=6 pairs=3")
        return

    args.output_dir.mkdir(parents=True, exist_ok=True)
    output.write_text(expected)
    print(f"wrote {output} (6 cells, 3 pairs)")


if __name__ == "__main__":
    main()
