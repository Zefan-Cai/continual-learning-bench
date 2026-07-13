from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_cell_runner_is_fail_closed_and_strict() -> None:
    text = (ROOT / "run_candidate_distill_formal.sh").read_text()
    assert "refusing to overwrite existing result dir" in text
    assert '"reward_update_rule": "candidate_distill_instance"' in text
    assert '"grpo_candidate_proposer": "unit_interval_jitter"' in text
    assert '"ttt_lr": 0.0' in text
    assert '"lora_param_norm_clip": 0.0' in text
    assert "--strict-smoke" in text
    assert "CUDA_VISIBLE_DEVICES" in text


def test_launcher_requires_six_unique_gpus_and_runs_pairing_gate() -> None:
    text = (ROOT / "launch_candidate_distill_formal.sh").read_text()
    assert "exactly six comma-separated GPU indices" in text
    assert "GPU_LIST entries must be unique" in text
    assert "validate_candidate_distill_pairing.py" in text
    assert "formal_decision.json" in text
