from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import generate_candidate_distill_grids as grids


ROOT = Path(__file__).resolve().parents[1]
REGISTERED_GRID = ROOT / grids.GRID_NAME


def test_formal_grid_has_three_seed_matched_active_lr0_pairs() -> None:
    configs = grids.make_formal()

    grids.validate(configs)
    assert len(configs) == 6
    assert [cfg["sampling_seed"] for cfg in configs] == [
        seed for seed in grids.FORMAL_SEEDS for _ in range(2)
    ]
    for seed in grids.FORMAL_SEEDS:
        pair = [cfg for cfg in configs if cfg["sampling_seed"] == seed]
        assert [cfg["candidate_arm"] for cfg in pair] == ["active", "lr0"]
        assert len({cfg["pair_id"] for cfg in pair}) == 1
        assert {cfg["arm"] for cfg in pair} == {"active"}
        assert {cfg["system_params"]["reward_pg_lr"] for cfg in pair} == {
            0.0,
            1e-4,
        }
    assert {cfg["system_params"]["grpo_adapter_init_seed"] for cfg in configs} == {
        grids.ADAPTER_INIT_SEED
    }
    assert all(grids.EXPERIMENT_REVISION in cfg["cfg_id"] for cfg in configs)
    old_ids = {
        "gpgfix_cohort_full_candidate_distill_v2_"
        f"{arm}_seed{seed}_n{grids.NUM_INSTANCES}"
        for seed in grids.FORMAL_SEEDS
        for arm in ("active", "lr0")
    }
    assert old_ids.isdisjoint({cfg["cfg_id"] for cfg in configs})


def test_formal_grid_preserves_gate_shape_except_learning_rate_and_size() -> None:
    configs = grids.make_formal()

    for cfg in configs:
        params = cfg["system_params"]
        assert cfg["task_params"] == {
            "schedule": "default",
            "num_instances": 20,
            "expected_num_instances": 20,
            "seed": 42,
        }
        assert params["ttt_lr"] == 0.0
        assert params["lora_param_norm_clip"] == 0.0
        assert params["grpo_adapter_init_seed"] == grids.ADAPTER_INIT_SEED
        assert not isinstance(params["grpo_adapter_init_seed"], bool)
        assert params["freeze_parameter_updates"] is False
        assert params["grpo_candidate_proposer"] == "unit_interval_jitter"
        assert params["reward_update_rule"] == "candidate_distill_instance"
        assert params["context_policy"] == "full"
        assert params["best_of_n"] == 8
        assert cfg["sampling_seed"] == params["grpo_run_seed"]


def test_registered_formal_grid_is_generator_exact() -> None:
    assert json.loads(REGISTERED_GRID.read_text()) == grids.make_formal()
    completed = subprocess.run(
        [sys.executable, str(ROOT / "generate_candidate_distill_grids.py"), "--check"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == (
        "CANDIDATE_DISTILL_GRID_CHECK_OK formal=6 pairs=3"
    )


def test_check_rejects_a_stale_registered_grid(tmp_path: Path) -> None:
    (tmp_path / grids.GRID_NAME).write_text("[]\n")
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "generate_candidate_distill_grids.py"),
            "--output-dir",
            str(tmp_path),
            "--check",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "registered grid is stale" in completed.stderr
