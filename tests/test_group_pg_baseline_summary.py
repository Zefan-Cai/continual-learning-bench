"""Merged baseline keeps per-instance frozen-update evidence after compaction."""

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, ".")

from src.cli import _persist_full_trace_outputs
from src.interface import EvalMetrics, InstanceOutcome, TaskResult
from src.runs.baseline import _merge_baseline_instance_results
from src.trace_storage import TraceRecorder


def make_instance(index: int):
    outcome = InstanceOutcome(
        instance_id=f"real-{index}", instance_index=index, reward=0.1 + index
    )
    result = TaskResult(
        metrics={},
        summary="done",
        eval_metrics=EvalMetrics([], 1.0, outcome.reward),
        instance_outcomes=[outcome],
    )
    recorder = TraceRecorder(
        system_name="qwen_local",
        task_name="dummy",
        system_params={"reward_update_rule": "grpo_instance"},
        task_params={"expected_num_instances": 2},
        run_group_id="baseline-summary-test",
        run_index=index,
        phase="baseline",
    )
    recorder.record_system_artifacts(
        {
            "artifact_type": "qwen_local",
            "reward_update_rule": "grpo_instance",
            "parameter_updates_enabled": False,
            "grpo_updates": 0,
            "grpo_skipped_low_std": 0,
            "grpo_skipped_no_group": 0,
            "last_grpo_loss": None,
            "last_grpo_group_size": None,
            "last_grpo_reward_mean": None,
            "last_grpo_reward_std": None,
            "last_grpo_committed_reward": None,
            "reward_pg_updates": 0,
            "bon_updates": 0,
            "distill_updates": 0,
            "adaptation_count": 0,
            "grpo_instance_log": [],
        }
    )
    return index, result, recorder.finalize(result)


start = datetime.now()
_, merged, _ = _merge_baseline_instance_results(
    [make_instance(0), make_instance(1)],
    run_group_id="baseline-summary-test",
    system_name="qwen_local",
    task_name="dummy",
    task_params={"expected_num_instances": 2},
    start_time=start.isoformat(),
    end_time=(start + timedelta(seconds=1)).isoformat(),
    system_params={"reward_update_rule": "grpo_instance"},
    expected_num_instances=2,
)

with tempfile.TemporaryDirectory() as tmp:
    old_cwd = os.getcwd()
    os.chdir(tmp)
    try:
        path, _ = _persist_full_trace_outputs(
            task_name="dummy",
            run_group_id="baseline-summary-test",
            baseline_trace_data=merged,
            run_trace_data_list=[],
            root_dir=Path(tmp),
        )
        assert path is not None
        compact = json.load(open(Path(tmp) / path))
    finally:
        os.chdir(old_cwd)

summaries = [trace.get("system_update_metrics") for trace in compact["instance_traces"]]
assert len(summaries) == 2
assert all(summary["parameter_updates_enabled"] is False for summary in summaries)
assert all(summary["grpo_updates"] == 0 for summary in summaries)
assert all(trace.get("system_artifacts") is None for trace in compact["instance_traces"])

print("GRPO_BASELINE_SUMMARY_ALL_PASS")
