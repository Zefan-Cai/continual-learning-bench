"""CPU checks that terminal GRPO evidence survives compact live manifests."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, ".")

from src.interface import EvalMetrics, TaskResult
from src.trace_storage import TraceRecorder


with tempfile.TemporaryDirectory() as tmp:
    live = Path(tmp) / "run_1.json"
    recorder = TraceRecorder(
        system_name="qwen_local",
        task_name="dummy",
        system_params={"reward_update_rule": "group_pg_instance"},
        task_params={},
        live_trace_path=live,
    )
    artifacts = {
        "artifact_type": "qwen_local",
        "reward_update_rule": "group_pg_instance",
        "parameter_updates_enabled": True,
        "freeze_parameter_updates": False,
        "grpo_frozen_stream": False,
        "grpo_objective": "group_normalized_policy_gradient",
        "grpo_run_seed": 20260712,
        "grpo_adapter_init_seed": 2026071200,
        "grpo_updates": 3,
        "grpo_optimizer_steps": 3,
        "grpo_skipped_low_std": 0,
        "grpo_skipped_no_group": 0,
        "last_grpo_loss": 0.125,
        "last_grpo_group_size": 7,
        "last_grpo_reward_mean": 0.2,
        "last_grpo_reward_std": 0.1,
        "last_grpo_committed_reward": 0.3,
        "reward_pg_updates": 0,
        "bon_updates": 0,
        "distill_updates": 0,
        "adaptation_count": 0,
        "grpo_instance_log": [{"group_size": 7, "loss": 0.125}],
    }
    recorder.record_system_artifacts(artifacts)
    result = TaskResult(
        metrics={},
        summary="done",
        eval_metrics=EvalMetrics([], 0.0, 0.0),
    )
    payload = recorder.finalize(result)
    compact = json.load(open(live))
    assert payload["system_update_metrics"] == compact["system_update_metrics"]
    assert compact["system_update_metrics"]["grpo_updates"] == 3
    assert compact["system_update_metrics"]["grpo_optimizer_steps"] == 3
    assert compact["system_update_metrics"]["grpo_run_seed"] == 20260712
    assert compact["system_update_metrics"]["grpo_adapter_init_seed"] == 2026071200
    assert (
        compact["system_update_metrics"]["grpo_objective"]
        == "group_normalized_policy_gradient"
    )
    assert compact["system_update_metrics"]["grpo_instance_log"][0]["loss"] == 0.125

    candidate_live = Path(tmp) / "candidate_run.json"
    candidate = TraceRecorder(
        system_name="qwen_local",
        task_name="dummy",
        system_params={
            "reward_update_rule": "candidate_distill_instance",
            "grpo_candidate_proposer": "unit_interval_jitter",
        },
        task_params={},
        live_trace_path=candidate_live,
    )
    candidate.record_system_artifacts(
        {
            **artifacts,
            "reward_update_rule": "candidate_distill_instance",
            "grpo_objective": "group_normalized_candidate_distillation",
            "grpo_candidate_proposer": "unit_interval_jitter",
            "grpo_instance_log": [
                {
                    "group_size": 4,
                    "objective": "group_normalized_candidate_distillation",
                    "candidate_proposer": "unit_interval_jitter",
                }
            ],
        }
    )
    candidate.finalize(result)
    candidate_compact = json.load(open(candidate_live))
    assert candidate_compact["system_update_metrics"]["grpo_objective"] == (
        "group_normalized_candidate_distillation"
    )
    assert candidate_compact["system_update_metrics"]["grpo_candidate_proposer"] == (
        "unit_interval_jitter"
    )

    legacy_group_live = Path(tmp) / "legacy_group_run.json"
    legacy_group = TraceRecorder(
        system_name="qwen_local",
        task_name="dummy",
        system_params={"reward_update_rule": "group_pg_instance"},
        task_params={},
        live_trace_path=legacy_group_live,
    )
    legacy_group_artifacts = dict(artifacts)
    legacy_group_artifacts.pop("grpo_adapter_init_seed")
    legacy_group.record_system_artifacts(legacy_group_artifacts)
    legacy_group.finalize(result)
    assert (
        "grpo_adapter_init_seed"
        not in json.load(open(legacy_group_live))["system_update_metrics"]
    )

    old_live = Path(tmp) / "old_run.json"
    old = TraceRecorder(
        system_name="qwen_local",
        task_name="dummy",
        system_params={},
        task_params={},
        live_trace_path=old_live,
    )
    old.record_system_artifacts(
        {"artifact_type": "qwen_local", "reward_update_rule": "reward_pg"}
    )
    old.finalize(result)
    assert "system_update_metrics" not in json.load(open(old_live))

print("GRPO_TRACE_SUMMARY_ALL_PASS")
