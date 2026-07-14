#!/usr/bin/env python3
"""Generate the preregistered Cohort qonly frozen-tape experiment grids."""

from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
PROTOCOL = "cohort_qonly_frozen_tape_weight_update_ablation_v1"
MECHANISM_LABEL = (
    "frozen-tape weight-update ablation; not exact historical replication"
)
PREREG_COMMIT = "493c43c7ac19e470d5bcda933294dab41c125c5b"
ADAPTER_INIT_SEED = 2026071400
FORMAL_SEEDS = (2026071401, 2026071402, 2026071403)
SMOKE_SEED = 2026071498
NUM_INSTANCES = 20
SMOKE_INSTANCES = 2

DATASETS = {
    "adaptation": {
        "path": "data/cohort_studies/causal_adapt_2026071411",
        "schedule": "causal_adapt_2026071411",
        "seed": 2026071411,
        "corpus_sha256": (
            "31f94d0130573e347ef8276a44c8d71c7b2159b881334798a7b73cd084ae9d9a"
        ),
        "schedule_sha256": (
            "a471a2e1dca55317dda9d6858b2103f3cd51539d9cfa081836a338058eed44f5"
        ),
    },
    "heldout": {
        "path": "data/cohort_studies/causal_eval_2026071412",
        "schedule": "causal_eval_2026071412",
        "seed": 2026071412,
        "corpus_sha256": (
            "a5c56f2c408b0d909a31cbfad490a95d5facd583eb8d3cbb3190aea4c39e0b80"
        ),
        "schedule_sha256": (
            "81dde8ec92fe18af6410fbf38ff9cebd52fc298d534d9fb5107df3da5afe09ea"
        ),
    },
}

COMMON_SYSTEM_PARAMS: dict[str, Any] = {
    "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
    "method": "ttt_rl",
    "ttt_rl_source": "sft",
    "peft_method": "prefix",
    "num_virtual_tokens": 512,
    "context_policy": "question_only",
    "adaptation_context_policy": "head4k_tail4k",
    "max_context_tokens": 32768,
    "head_tokens": 4096,
    "tail_tokens": 4096,
    "max_new_tokens": 8192,
    "action_max_new_tokens": 4096,
    "temperature": 0.0,
    "top_p": 1.0,
    "parse_retries": 2,
    "system_prompt": "",
    "name": "qwen_local",
    "trust_remote_code": True,
    "ttt_steps": 1,
    "ttt_max_tokens": 1024,
    "ttt_chunk_tokens": 512,
    "ttt_stride_tokens": 256,
    "ttt_max_chunks": 4,
    "ttt_train_every": 1,
    "lora_rank": 8,
    "lora_alpha": 16,
    "lora_dropout": 0.0,
    "lora_target_modules": "q_proj,v_proj",
    "lora_param_norm_clip": 0.25,
    "reward_pg_steps": 1,
    "reward_positive_weight": 1.0,
    "reward_negative_weight": 0.5,
    "reward_update_rule": "reward_pg",
    "reward_advantage_window": 8,
    "reward_ppo_clip": 0.2,
    "reward_update_terminal": True,
    "reward_judge_provider": "env",
    "reward_judge_model": "gpt-5.4-nano",
    "reward_judge_api_key_env": "OPENAI_API_KEY",
    "reward_judge_base_url": "https://api.openai.com/v1",
    "reward_judge_timeout_seconds": 30.0,
    "inject_env_reward": False,
    "distill_provider": "off",
    "distill_contrastive": True,
    "best_of_n": 8,
    "bon_temperature": 0.8,
    "bon_critic": "env",
    "bon_env_reward": "report",
    "history_ttt": False,
    "adapter_init_seed": ADAPTER_INIT_SEED,
}


def _canonical_sha(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _system_params(arm: str, *, run_seed: int) -> dict[str, Any]:
    if arm not in {"active", "lr0"}:
        raise ValueError(f"unknown arm: {arm}")
    params = deepcopy(COMMON_SYSTEM_PARAMS)
    lr = 5e-4 if arm == "active" else 0.0
    params.update(
        {
            "grpo_run_seed": run_seed,
            "ttt_lr": lr,
            "reward_pg_lr": lr,
        }
    )
    return params


def _masked_pair_sha(params: dict[str, Any]) -> str:
    masked = deepcopy(params)
    masked["ttt_lr"] = "<ARM_LR>"
    masked["reward_pg_lr"] = "<ARM_LR>"
    return _canonical_sha(masked)


def _task_params(dataset_key: str, num_instances: int) -> dict[str, Any]:
    dataset = DATASETS[dataset_key]
    return {
        "schedule": dataset["schedule"],
        "dataset_path": dataset["path"],
        "num_instances": num_instances,
        "action_budget": 20,
        "seed": dataset["seed"],
        "repeat_instructions": True,
    }


def _collector(seed: int, num_instances: int, label: str) -> dict[str, Any]:
    cfg_id = f"causal_cohort_qonly_tape_{label}_seed{seed}_n{num_instances}"
    params = _system_params("lr0", run_seed=seed)
    task_params = _task_params("adaptation", num_instances)
    return {
        "cfg_id": cfg_id,
        "mode": "collect_tape",
        "run_seed": seed,
        "arm": "collector_lr0",
        "expected_num_instances": num_instances,
        "tape_path": f"artifacts/cohort_causal/tapes/{cfg_id}.json",
        "task_params": task_params,
        "task_params_sha256": _canonical_sha(task_params),
        "system_params": params,
        "system_params_sha256": _canonical_sha(params),
    }


def _replay_cell(
    *, seed: int, arm: str, num_instances: int, label: str, collector: dict[str, Any]
) -> dict[str, Any]:
    pair_id = f"cohort_qonly_frozen_tape_{label}_seed{seed}"
    cfg_id = f"causal_cohort_qonly_{label}_{arm}_seed{seed}_n{num_instances}"
    params = _system_params(arm, run_seed=seed)
    task_params = _task_params("heldout", num_instances)
    return {
        "cfg_id": cfg_id,
        "mode": "replay_eval",
        "pair_id": pair_id,
        "run_seed": seed,
        "arm": arm,
        "expected_num_instances": num_instances,
        "collector_cfg_id": collector["cfg_id"],
        "tape_path": collector["tape_path"],
        "task_params": task_params,
        "task_params_sha256": _canonical_sha(task_params),
        "system_params": params,
        "system_params_sha256": _canonical_sha(params),
        "masked_pair_config_sha256": _masked_pair_sha(params),
        "cell_manifest_path": (
            f"artifacts/cohort_causal/cells/{cfg_id}.manifest.json"
        ),
    }


def make_grid(*, smoke: bool) -> dict[str, Any]:
    seeds = (SMOKE_SEED,) if smoke else FORMAL_SEEDS
    count = SMOKE_INSTANCES if smoke else NUM_INSTANCES
    label = "smoke" if smoke else "formal"
    collectors = [_collector(seed, count, label) for seed in seeds]
    cells = [
        _replay_cell(
            seed=seed,
            arm=arm,
            num_instances=count,
            label=label,
            collector=collectors[index],
        )
        for index, seed in enumerate(seeds)
        for arm in ("active", "lr0")
    ]
    grid = {
        "schema_version": SCHEMA_VERSION,
        "protocol": PROTOCOL,
        "mechanism_label": MECHANISM_LABEL,
        "prereg_commit": PREREG_COMMIT,
        "adapter_init_seed": ADAPTER_INIT_SEED,
        "kind": label,
        "datasets": deepcopy(DATASETS),
        "collectors": collectors,
        "evaluation_cells": cells,
    }
    validate(grid, smoke=smoke)
    return grid


def _validate_dataset(dataset: dict[str, Any]) -> None:
    path = ROOT / dataset["path"]
    manifest = json.loads((path / "manifest.json").read_text())
    if manifest["corpus_sha256"] != dataset["corpus_sha256"]:
        raise ValueError(f"corpus hash drift: {path}")
    if manifest["schedule_sha256"] != dataset["schedule_sha256"]:
        raise ValueError(f"schedule hash drift: {path}")
    if manifest["schedule_id"] != dataset["schedule"]:
        raise ValueError(f"schedule id drift: {path}")
    if manifest["seed"] != dataset["seed"]:
        raise ValueError(f"dataset seed drift: {path}")


def validate(grid: dict[str, Any], *, smoke: bool) -> None:
    if grid["schema_version"] != SCHEMA_VERSION:
        raise ValueError("schema version drift")
    if grid["protocol"] != PROTOCOL or grid["mechanism_label"] != MECHANISM_LABEL:
        raise ValueError("protocol label drift")
    if grid["prereg_commit"] != PREREG_COMMIT:
        raise ValueError("prereg commit drift")
    for dataset in grid["datasets"].values():
        _validate_dataset(dataset)
    if DATASETS["adaptation"]["corpus_sha256"] == DATASETS["heldout"]["corpus_sha256"]:
        raise ValueError("adaptation and held-out corpora must differ")

    seeds = (SMOKE_SEED,) if smoke else FORMAL_SEEDS
    expected_count = SMOKE_INSTANCES if smoke else NUM_INSTANCES
    collectors = grid["collectors"]
    cells = grid["evaluation_cells"]
    if len(collectors) != len(seeds) or len(cells) != 2 * len(seeds):
        raise ValueError("grid cardinality drift")

    for seed, collector in zip(seeds, collectors, strict=True):
        if collector["run_seed"] != seed or collector["arm"] != "collector_lr0":
            raise ValueError("collector seed/arm mismatch")
        if collector["expected_num_instances"] != expected_count:
            raise ValueError("collector instance count mismatch")
        if collector["system_params"]["ttt_lr"] != 0.0:
            raise ValueError("collector must be LR0")
        if collector["system_params"]["reward_pg_lr"] != 0.0:
            raise ValueError("collector must be LR0")
        if collector["system_params_sha256"] != _canonical_sha(
            collector["system_params"]
        ):
            raise ValueError("collector system config hash drift")
        if collector["task_params_sha256"] != _canonical_sha(
            collector["task_params"]
        ):
            raise ValueError("collector task config hash drift")

        pair = [cell for cell in cells if cell["run_seed"] == seed]
        if len(pair) != 2 or {cell["arm"] for cell in pair} != {"active", "lr0"}:
            raise ValueError(f"seed {seed} must have one active/LR0 pair")
        if len({cell["pair_id"] for cell in pair}) != 1:
            raise ValueError("pair id drift")
        if len({cell["tape_path"] for cell in pair}) != 1:
            raise ValueError("pair tape mismatch")
        if pair[0]["tape_path"] != collector["tape_path"]:
            raise ValueError("pair does not consume its collector tape")
        if len({cell["task_params_sha256"] for cell in pair}) != 1:
            raise ValueError("paired held-out task drift")
        if len({cell["masked_pair_config_sha256"] for cell in pair}) != 1:
            raise ValueError("paired system config differs beyond learning rates")
        for cell in pair:
            if cell["system_params_sha256"] != _canonical_sha(
                cell["system_params"]
            ):
                raise ValueError("cell system config hash drift")
            if cell["task_params_sha256"] != _canonical_sha(cell["task_params"]):
                raise ValueError("cell task config hash drift")
            if cell["masked_pair_config_sha256"] != _masked_pair_sha(
                cell["system_params"]
            ):
                raise ValueError(
                    "paired system config differs beyond learning rates"
                )
        by_arm = {cell["arm"]: cell for cell in pair}
        for key in ("ttt_lr", "reward_pg_lr"):
            if by_arm["active"]["system_params"][key] != 5e-4:
                raise ValueError(f"active {key} drift")
            if by_arm["lr0"]["system_params"][key] != 0.0:
                raise ValueError(f"LR0 {key} drift")


def _json_text(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = {
        ROOT / "grid_cohort_causal_smoke.json": make_grid(smoke=True),
        ROOT / "grid_cohort_causal_formal.json": make_grid(smoke=False),
    }
    for path, payload in outputs.items():
        expected = _json_text(payload)
        if args.check:
            if not path.is_file() or path.read_text() != expected:
                raise SystemExit(f"registered grid is stale: {path}")
        else:
            path.write_text(expected)
            print(f"wrote {path}")
    if args.check:
        print("COHORT_CAUSAL_GRID_CHECK_OK smoke=3 formal=9")


if __name__ == "__main__":
    main()
