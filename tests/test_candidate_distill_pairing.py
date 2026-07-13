from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import generate_candidate_distill_grids as grids
from validate_candidate_distill_pairing import evaluate, load_manifests


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "validate_candidate_distill_pairing.py"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _make_outcomes(delta: float) -> list[dict]:
    baseline_reward = 0.2
    later_reward = baseline_reward + (delta * 20 / 19)
    rewards = [baseline_reward, *([later_reward] * 19)]
    return [
        {
            "instance_id": f"cohort_studies:variant-{index:02d}",
            "instance_index": index,
            "reward": reward,
            "success": reward > 0,
            "raw_metric_name": "kl_information_gain_bits",
            "raw_metric_value": reward,
            "raw_metric_higher_is_better": True,
            "metadata": {
                "mean_kl_divergence": 0.4,
                "mean_reference_kl": 0.6,
                "steps": 1,
                "study_name": f"study-{index:02d}",
                "timed_out": False,
            },
        }
        for index, reward in enumerate(rewards)
    ]


def _make_manifest(config: dict, *, delta: float) -> dict:
    seed = config["sampling_seed"]
    candidate_arm = config["candidate_arm"]
    outcomes = _make_outcomes(delta if candidate_arm == "active" else 0.0)
    initial_hash = _digest(f"initial-{seed}")
    if candidate_arm == "active":
        hashes = [initial_hash] + [
            _digest(f"active-{seed}-{index}") for index in range(1, 21)
        ]
    else:
        hashes = [initial_hash] * 21
    log = []
    for index in range(20):
        proposal_digests = [
            _digest(f"proposal-{seed}-{index}-{attempt}") for attempt in range(7)
        ]
        log.append(
            {
                "candidate_proposer": "unit_interval_jitter",
                "candidate_sampling": {
                    "candidate_proposer": "unit_interval_jitter",
                    "duplicates": 0,
                    "generation_failures": 0,
                    "initial_sample_attempts": 7,
                    "max_sample_attempts": 14,
                    "model_generation_attempts": 0,
                    "parse_failures": 0,
                    "proposal_mode_counts": {
                        "primary_policy": 1,
                        "unit_interval_jitter": 7,
                    },
                    "proposal_seed_digests": proposal_digests,
                    "proposal_seed_scheme": (
                        "blake2b(base_sampling_seed,attempt_index)"
                    ),
                    "requested_group_size": 8,
                    "rescue_sample_attempts": 0,
                    "sample_attempts": 7,
                    "structured_proposal_attempts": 7,
                    "target_valid_unique": 8,
                    "valid_unique": 8,
                },
                "committed_reward": 0.2,
                "group_size": 8,
                "loss": 0.1,
                "n_batches": 8,
                "objective": "group_normalized_candidate_distillation",
                "optimizer_steps": 1,
                "prompt_tokens_retained_min": 16,
                "reward_mean": 0.25,
                "reward_std": 0.05,
                "sampling_prompt_sha256": _digest(f"prompt-{seed}-{index}"),
                "sampling_seed": seed + index,
                "trainable_param_sha256_after": hashes[index + 1],
                "trainable_param_sha256_before": hashes[index],
            }
        )
    first_id = outcomes[0]["instance_id"]
    return {
        "execution": {"run_group_id": config["cfg_id"], "run_index": 0},
        "interactions": [
            {
                "done": False,
                "observation": {
                    "content": "first observation",
                    "instance_complete": True,
                    "metadata": {"env_feedback_reward": 0.2},
                },
                "query": {
                    "feedback": None,
                    "instance_id": first_id,
                    "instance_index": 0,
                    "metadata": {},
                    "prompt": "first prompt",
                    "response_schema": "CohortReport",
                },
                "response": {
                    "action": {"report": [0.8, 0.7, 0.6]},
                    "action_type": "structured",
                    "metadata": {},
                },
                "step_number": 0,
                "timestamp": "ignored-by-pairing-validator",
                "timing": {"response_latency_seconds": 1.0},
                "usage": {"interaction": {"input_tokens": 10}},
            }
        ],
        "phase": "run",
        "result": {
            "instance_outcomes": outcomes,
            "score": statistics.mean(row["reward"] for row in outcomes),
        },
        "status": "completed",
        "system": {
            "name": "qwen_local",
            "params": deepcopy(config["system_params"]),
        },
        "system_update_metrics": {
            "adaptation_count": 0,
            "bon_updates": 0,
            "distill_updates": 0,
            "freeze_parameter_updates": False,
            "grpo_candidate_proposer": "unit_interval_jitter",
            "grpo_instance_log": log,
            "grpo_objective": "group_normalized_candidate_distillation",
            "grpo_optimizer_steps": 20,
            "grpo_run_seed": seed,
            "grpo_skipped_low_std": 0,
            "grpo_skipped_no_group": 0,
            "grpo_trainable_param_sha256_current": hashes[-1],
            "grpo_trainable_param_sha256_initial": hashes[0],
            "grpo_updates": 20,
            "parameter_updates_enabled": True,
            "reward_pg_updates": 0,
            "reward_update_rule": "candidate_distill_instance",
        },
        "task": {
            "name": config["task"],
            "params": deepcopy(config["task_params"]),
        },
    }


def _write_case(tmp_path: Path, deltas: list[float]) -> tuple[Path, Path]:
    configs = grids.make_formal()
    grid_path = tmp_path / "grid.json"
    results_root = tmp_path / "results"
    results_root.mkdir()
    grid_path.write_text(json.dumps(configs))
    delta_by_seed = dict(zip(grids.FORMAL_SEEDS, deltas, strict=True))
    for config in configs:
        manifest = _make_manifest(config, delta=delta_by_seed[config["sampling_seed"]])
        run_dir = results_root / config["cfg_id"]
        run_dir.mkdir()
        (run_dir / "run_1.json").write_text(json.dumps(manifest))
    return grid_path, results_root


def _result_path(results_root: Path, config: dict) -> Path:
    return results_root / config["cfg_id"] / "run_1.json"


def test_go_report_accepts_three_valid_pairs(tmp_path: Path) -> None:
    grid_path, results_root = _write_case(tmp_path, [0.04, 0.05, 0.03])
    grid = json.loads(grid_path.read_text())
    manifests, load_errors = load_manifests(grid, results_root)

    report = evaluate(grid, manifests, load_errors=load_errors)

    assert report["errors"] == []
    assert report["status"] == "valid"
    assert report["decision"] == "go"
    assert report["aggregate"] == {
        "mean_delta": 0.04,
        "median_delta": 0.04,
        "min_delta": 0.03,
        "positive_seeds": 3,
    }
    assert report["checks"]["trajectory_pairs_checked"] == 3


def test_no_go_is_a_valid_zero_exit_scientific_result(tmp_path: Path) -> None:
    grid_path, results_root = _write_case(tmp_path, [0.02, 0.01, -0.01])
    output_path = tmp_path / "formal_decision.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--grid",
            str(grid_path),
            "--results-root",
            str(results_root),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    report = json.loads(completed.stdout)
    assert json.loads(output_path.read_text()) == report
    assert report["status"] == "valid"
    assert report["decision"] == "no_go"
    assert report["errors"] == []
    assert report["threshold_checks"]["mean_delta_gte_0_03"] is False


def test_tampered_first_proposer_seed_is_invalid(tmp_path: Path) -> None:
    grid_path, results_root = _write_case(tmp_path, [0.04, 0.05, 0.03])
    grid = json.loads(grid_path.read_text())
    active = next(cfg for cfg in grid if cfg["candidate_arm"] == "active")
    path = _result_path(results_root, active)
    manifest = json.loads(path.read_text())
    manifest["system_update_metrics"]["grpo_instance_log"][0]["candidate_sampling"][
        "proposal_seed_digests"
    ][0] = _digest("tampered-but-well-shaped")
    path.write_text(json.dumps(manifest))

    completed = subprocess.run(
        [sys.executable, str(VALIDATOR), str(grid_path), str(results_root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report["decision"] == "invalid"
    assert any(
        "first proposal_seed_digests mismatch" in error for error in report["errors"]
    )


def test_missing_manifest_and_non_bit_exact_lr0_are_invalid(tmp_path: Path) -> None:
    grid_path, results_root = _write_case(tmp_path, [0.04, 0.05, 0.03])
    grid = json.loads(grid_path.read_text())
    lr0_cells = [cfg for cfg in grid if cfg["candidate_arm"] == "lr0"]
    missing = lr0_cells[-1]
    _result_path(results_root, missing).unlink()
    tampered = lr0_cells[1]
    path = _result_path(results_root, tampered)
    manifest = json.loads(path.read_text())
    manifest["result"]["instance_outcomes"][5]["metadata"]["steps"] = 2
    path.write_text(json.dumps(manifest))

    manifests, load_errors = load_manifests(grid, results_root)
    report = evaluate(grid, manifests, load_errors=load_errors)

    assert report["decision"] == "invalid"
    assert any("missing result manifest" in error for error in report["errors"])
    assert any(
        "LR0 score-relevant outcomes are not bit-exact" in error
        for error in report["errors"]
    )
