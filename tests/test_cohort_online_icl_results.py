"""Statistical decision tests for the three-arm internal Cohort screen."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import statistics
import sys

import pytest

import run_cohort_online_icl as runner
import validate_cohort_online_icl_results as results_module
import validate_cohort_online_icl_smoke as smoke_module
from validate_cohort_online_icl_results import (
    PROTOCOL,
    assemble_internal_screen,
    revalidate_registered_formal_smoke_gate,
    validate_formal_smoke_gate_binding,
)


SHARED_PROVENANCE = {
    "environment_lock_sha256": "e" * 64,
    "model_path": "/model",
    "model_sha256": "m" * 64,
    "source_commit": "c" * 40,
    "tokenizer_sha256": "t" * 64,
}


def causal_manifest(active: list[float], lr0: list[float]) -> dict:
    seeds = [2026071401, 2026071402, 2026071403]
    return {
        "provenance": SHARED_PROVENANCE,
        "pairs": [
            {
                "run_seed": seed,
                "active": {
                    "score": active[index],
                    "integrity_counters": integrity(),
                },
                "lr0": {
                    "score": lr0[index],
                    "integrity_counters": integrity(),
                },
            }
            for index, seed in enumerate(seeds)
        ],
    }


def online_cells(scores: list[float]) -> list[dict]:
    return [
        {
            "run_seed": seed,
            "score": scores[index],
            "provenance": {
                **SHARED_PROVENANCE,
                "base_causal_commit": SHARED_PROVENANCE["source_commit"],
            },
            "heldout": {"integrity_counters": integrity()},
        }
        for index, seed in enumerate([2026071401, 2026071402, 2026071403])
    ]


def integrity(*, retries: int = 0, repairs: int = 0) -> dict:
    return {
        "fallbacks": 0,
        "hard_schema_failures": 0,
        "missing_outcomes": 0,
        "parse_retries": retries,
        "repairs": repairs,
        "synthetic_outcomes": 0,
        "timed_out_outcomes": 0,
    }


def smoke_cell_integrity() -> dict:
    return {
        "adaptation_trace_file_sha256": "c" * 64,
        "adaptation_trace_sha256": "5" * 64,
        "cell_manifest_file_sha256": "d" * 64,
        "cell_manifest_sha256": "6" * 64,
        "cfg_id": "cohort_online_icl_smoke_seed2026071498_n2",
        "context_inventory_file_sha256": "e" * 64,
        "context_inventory_sha256": "7" * 64,
        "heldout_trace_file_sha256": "f" * 64,
        "heldout_trace_sha256": "8" * 64,
        "restoration_audit_file_sha256": "0" * 64,
        "restoration_audit_sha256": "9" * 64,
        "run_seed": 2026071498,
        "snapshot_file_sha256": "1" * 64,
        "snapshot_artifact_sha256": "a" * 64,
        "snapshot_sha256": "b" * 64,
        "valid": True,
    }


def adaptation_reward_trace() -> tuple[dict, dict, list[str]]:
    instance_id = "cohort_studies:adaptation-0"
    system_params = {
        "context_policy": "full",
        "inject_env_reward": True,
        "max_context_tokens": 32768,
        "system_prompt": "",
    }
    task_params = {"dataset_path": "adaptation"}

    def interaction(
        *, action: dict, complete: bool, metadata: dict, prompt: str
    ) -> dict:
        return {
            "observation": {
                "content": "report accepted" if complete else "tool result",
                "instance_complete": complete,
                "metadata": metadata,
            },
            "query": {
                "feedback": None,
                "instance_id": instance_id,
                "instance_index": 0,
                "prompt": prompt,
            },
            "response": {
                "action": action,
                "metadata": {"icl_context_sealed_eval": False},
            },
        }

    outcome = {"instance_id": instance_id, "instance_index": 0, "reward": 0.25}
    trace = {
        "instance_outcomes": [outcome],
        "interactions": [
            interaction(
                action={"tool": "query"},
                complete=False,
                metadata={},
                prompt="inspect study",
            ),
            interaction(
                action={"estimate": 0.5},
                complete=True,
                metadata={
                    "env_feedback_instance_id": instance_id,
                    "env_feedback_instance_index": 0,
                    "env_feedback_reward": 0.25,
                },
                prompt="submit report",
            ),
        ],
        "phase": "rollout",
        "result": {"instance_outcomes": [outcome]},
        "status": "completed",
        "system": {"name": "qwen_local", "params": system_params},
        "task": {"name": "cohort_studies", "params": task_params},
    }
    cfg = {
        "adaptation_task_params": task_params,
        "system_params": system_params,
    }
    return trace, cfg, [instance_id]


def causal_decision(active: list[float], lr0: list[float]) -> dict:
    seeds = [2026071401, 2026071402, 2026071403]
    passed = all(
        active_score > lr0_score for active_score, lr0_score in zip(active, lr0)
    )
    return {
        "decision": "pass" if passed else "valid_no_go",
        "decision_scope": "internal_gate_pass" if passed else "internal_gate_no_go",
        "errors": [],
        "pairs": [
            {
                "active_score": active[index],
                "delta_seed": active[index] - lr0[index],
                "lr0_score": lr0[index],
                "run_seed": seed,
            }
            for index, seed in enumerate(seeds)
        ],
        "status": "valid",
    }


@pytest.fixture(autouse=True)
def stub_causal_manifest_revalidation(monkeypatch: pytest.MonkeyPatch) -> None:
    def evaluate(manifest: dict) -> dict:
        pairs = manifest["pairs"]
        return causal_decision(
            [pair["active"]["score"] for pair in pairs],
            [pair["lr0"]["score"] for pair in pairs],
        )

    monkeypatch.setattr(results_module, "evaluate_causal_manifest", evaluate)


def test_adaptation_reward_requires_terminal_post_score_report_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace, cfg, expected_ids = adaptation_reward_trace()
    monkeypatch.setattr(
        results_module,
        "_independent_reward",
        lambda _action, **_kwargs: 0.25,
    )

    rows, _counters, _actions = results_module._reconstruct_trace_phase(
        trace=trace,
        cfg=cfg,
        role="adaptation",
        expected=1,
        expected_ids=expected_ids,
        scoring_contract={},
    )
    assert rows[0]["reward"] == pytest.approx(0.25)

    wrong_reward = deepcopy(trace)
    wrong_reward["interactions"][1]["observation"]["metadata"][
        "env_feedback_reward"
    ] = 0.5
    with pytest.raises(ValueError, match="independently rescored submitted report"):
        results_module._reconstruct_trace_phase(
            trace=wrong_reward,
            cfg=cfg,
            role="adaptation",
            expected=1,
            expected_ids=expected_ids,
            scoring_contract={},
        )

    wrong_identity = deepcopy(trace)
    wrong_identity["interactions"][1]["observation"]["metadata"][
        "env_feedback_instance_index"
    ] = 1
    with pytest.raises(ValueError, match="reward identity differs"):
        results_module._reconstruct_trace_phase(
            trace=wrong_identity,
            cfg=cfg,
            role="adaptation",
            expected=1,
            expected_ids=expected_ids,
            scoring_contract={},
        )

    missing_identity = deepcopy(trace)
    missing_identity["interactions"][1]["observation"]["metadata"].pop(
        "env_feedback_instance_id"
    )
    with pytest.raises(ValueError, match="reward identity differs"):
        results_module._reconstruct_trace_phase(
            trace=missing_identity,
            cfg=cfg,
            role="adaptation",
            expected=1,
            expected_ids=expected_ids,
            scoring_contract={},
        )

    missing_terminal_reward = deepcopy(trace)
    missing_terminal_reward["interactions"][1]["observation"]["metadata"].pop(
        "env_feedback_reward"
    )
    with pytest.raises(ValueError, match="lacks a finite post-score reward"):
        results_module._reconstruct_trace_phase(
            trace=missing_terminal_reward,
            cfg=cfg,
            role="adaptation",
            expected=1,
            expected_ids=expected_ids,
            scoring_contract={},
        )


@pytest.mark.parametrize("mutation", ["duplicate_terminal", "missing_terminal"])
def test_adaptation_reward_rejects_duplicate_or_missing_terminal_interaction(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    trace, cfg, expected_ids = adaptation_reward_trace()
    monkeypatch.setattr(
        results_module,
        "_independent_reward",
        lambda _action, **_kwargs: 0.25,
    )
    if mutation == "duplicate_terminal":
        trace["interactions"].append(deepcopy(trace["interactions"][-1]))
        expected_error = "identity/order differs|duplicate terminal"
    else:
        trace["interactions"].pop()
        expected_error = "terminal interaction IDs/order differ"

    with pytest.raises(ValueError, match=expected_error):
        results_module._reconstruct_trace_phase(
            trace=trace,
            cfg=cfg,
            role="adaptation",
            expected=1,
            expected_ids=expected_ids,
            scoring_contract={},
        )


def test_consistently_resigned_early_adaptation_reward_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace, cfg, expected_ids = adaptation_reward_trace()
    early_reward_trace = deepcopy(trace)
    terminal_metadata = early_reward_trace["interactions"][1]["observation"]["metadata"]
    early_metadata = early_reward_trace["interactions"][0]["observation"]["metadata"]
    for field in (
        "env_feedback_instance_id",
        "env_feedback_instance_index",
        "env_feedback_reward",
    ):
        early_metadata[field] = terminal_metadata.pop(field)

    class TraceTokenizer:
        @staticmethod
        def apply_chat_template(messages, **_kwargs) -> str:
            return json.dumps(messages, sort_keys=True, separators=(",", ":"))

        @staticmethod
        def encode(rendered: str, **_kwargs) -> list[int]:
            return list(rendered.encode())

    # Model an adversary who rewrites every downstream digest consistently.
    trace_sha256 = results_module.canonical_sha256(early_reward_trace)
    snapshot_state = results_module._reconstruct_adaptation_snapshot_state(
        trace=early_reward_trace,
        system_params=cfg["system_params"],
        tokenizer=TraceTokenizer(),
    )
    unsigned_snapshot = {
        "protocol": "qwen_local_icl_context_snapshot_v1",
        "schema_version": 1,
        "state": snapshot_state,
        "system_contract": {"registered": True},
    }
    snapshot_sha256 = results_module.canonical_sha256(unsigned_snapshot)
    snapshot_artifact = {
        "snapshot": {
            **unsigned_snapshot,
            "snapshot_sha256": snapshot_sha256,
        }
    }
    snapshot_artifact["artifact_sha256"] = results_module.canonical_sha256(
        snapshot_artifact
    )
    manifest = {
        "adaptation": {"trace_sha256": trace_sha256},
        "snapshot_artifact_sha256": snapshot_artifact["artifact_sha256"],
        "snapshot_sha256": snapshot_sha256,
    }
    manifest_sha256 = results_module.canonical_sha256(manifest)
    assert trace_sha256 == results_module.canonical_sha256(early_reward_trace)
    assert snapshot_sha256 == results_module.canonical_sha256(unsigned_snapshot)
    assert manifest_sha256 == results_module.canonical_sha256(manifest)

    monkeypatch.setattr(
        results_module,
        "_independent_reward",
        lambda _action, **_kwargs: 0.25,
    )
    with pytest.raises(ValueError, match="nonterminal observation exposes"):
        results_module._reconstruct_trace_phase(
            trace=early_reward_trace,
            cfg=cfg,
            role="adaptation",
            expected=1,
            expected_ids=expected_ids,
            scoring_contract={},
        )


def test_results_cli_rejects_smoke_grid_before_loading_or_printing_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "must-not-exist.json"
    monkeypatch.setattr(runner, "load_grid", lambda _path: {"kind": "smoke"})
    monkeypatch.setattr(
        runner,
        "load_provenance",
        lambda _path: pytest.fail("smoke rejection must precede provenance loading"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_cohort_online_icl_results.py",
            "--grid",
            str(tmp_path / "smoke-grid.json"),
            "--provenance",
            str(tmp_path / "provenance.json"),
            "--protocol-seal",
            str(tmp_path / "seal.json"),
            "--cell-manifest",
            str(tmp_path / "score-bearing-cell.json"),
            "--output",
            str(output),
            "--root",
            str(tmp_path),
        ],
    )

    with pytest.raises(SystemExit, match="accepts only the formal grid"):
        results_module.main()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "score" not in captured.err.lower()
    assert not output.exists()


def _occupy_final_output(path: Path, *, occupancy: str) -> tuple[bytes, Path | None]:
    marker = b"preexisting-output-must-survive\n"
    if occupancy == "existing":
        path.write_bytes(marker)
        return marker, None
    target = path.parent / f"{path.stem}.dangling-target.json"
    path.symlink_to(target)
    return marker, target


def _assert_final_output_untouched(
    path: Path,
    *,
    occupancy: str,
    marker: bytes,
    target: Path | None,
) -> None:
    if occupancy == "existing":
        assert path.read_bytes() == marker
        assert target is None
    else:
        assert path.is_symlink()
        assert target is not None
        assert not target.exists()


@pytest.mark.parametrize("occupancy", ["existing", "dangling_symlink"])
def test_smoke_cli_final_output_is_no_overwrite_for_files_and_dangling_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    occupancy: str,
) -> None:
    cell_path = tmp_path / "smoke-cell.json"
    causal_gate_path = tmp_path / "causal-gate.json"
    for path in (cell_path, causal_gate_path):
        path.write_text("{}\n")
    output = tmp_path / "smoke-gate.json"
    marker, target = _occupy_final_output(output, occupancy=occupancy)
    grid = {
        "kind": "smoke",
        "cells": [
            {
                "cell_manifest_path": str(cell_path),
                "system_params": {"model_path": "/model"},
            }
        ],
    }
    monkeypatch.setattr(smoke_module, "load_grid", lambda _path: grid)
    monkeypatch.setattr(smoke_module, "load_provenance", lambda _path: {})
    monkeypatch.setattr(
        smoke_module, "verify_runtime_provenance", lambda *_a, **_k: None
    )
    monkeypatch.setattr(smoke_module, "load_causal_provenance", lambda _path: {})
    monkeypatch.setattr(
        smoke_module,
        "validate_causal_smoke_prerequisite",
        lambda **_kwargs: {},
    )
    monkeypatch.setattr(smoke_module, "load_protocol_seal", lambda _path: {})
    monkeypatch.setattr(
        smoke_module,
        "validate_smoke",
        lambda **_kwargs: {"status": "pass", "cell": {"valid": True}},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_cohort_online_icl_smoke.py",
            "--grid",
            str(tmp_path / "smoke-grid.json"),
            "--provenance",
            str(tmp_path / "provenance.json"),
            "--protocol-seal",
            str(tmp_path / "seal.json"),
            "--cell-manifest",
            str(cell_path),
            "--causal-root",
            str(tmp_path),
            "--causal-smoke-gate",
            str(causal_gate_path),
            "--causal-provenance",
            str(tmp_path / "causal-provenance.json"),
            "--output",
            str(output),
            "--root",
            str(tmp_path),
        ],
    )

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        smoke_module.main()

    _assert_final_output_untouched(
        output,
        occupancy=occupancy,
        marker=marker,
        target=target,
    )


@pytest.mark.parametrize("occupancy", ["existing", "dangling_symlink"])
def test_results_cli_final_output_is_no_overwrite_for_files_and_dangling_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    occupancy: str,
) -> None:
    cfg_id = "formal-cell"
    run_seed = 2026071401
    cell_path = tmp_path / "formal-cell.json"
    cell_path.write_text(json.dumps({"run_seed": run_seed}) + "\n")
    input_paths = {
        name: tmp_path / f"{name}.json"
        for name in (
            "provenance",
            "seal",
            "icl-smoke-gate",
            "causal-smoke-gate",
            "causal-provenance",
            "causal-manifest",
            "causal-decision",
        )
    }
    for path in input_paths.values():
        path.write_text("{}\n")
    output = tmp_path / "formal-results.json"
    marker, target = _occupy_final_output(output, occupancy=occupancy)
    grid = {
        "cells": [
            {
                "cell_manifest_path": str(cell_path),
                "cfg_id": cfg_id,
                "run_seed": run_seed,
                "system_params": {"model_path": "/model"},
            }
        ],
        "decision_scope": "internal_screen",
        "grid_sha256": "1" * 64,
        "kind": "formal",
    }
    monkeypatch.setattr(runner, "load_grid", lambda _path: grid)
    monkeypatch.setattr(runner, "load_provenance", lambda _path: {})
    monkeypatch.setattr(runner, "verify_runtime_provenance", lambda *_a, **_k: None)
    monkeypatch.setattr(runner, "load_protocol_seal", lambda _path: {})
    monkeypatch.setattr(
        runner,
        "verify_runtime_protocol_seal",
        lambda *_a, **_k: "2" * 64,
    )
    monkeypatch.setattr(
        "run_cohort_causal.load_provenance",
        lambda _path: {},
    )
    monkeypatch.setattr(
        results_module,
        "revalidate_registered_formal_smoke_gate",
        lambda **_kwargs: "3" * 64,
    )
    monkeypatch.setattr(
        results_module,
        "validate_cell",
        lambda **_kwargs: {"cfg_id": cfg_id, "valid": True},
    )
    monkeypatch.setattr(
        results_module,
        "assemble_internal_screen",
        lambda **_kwargs: {"decision": "pass"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_cohort_online_icl_results.py",
            "--grid",
            str(tmp_path / "formal-grid.json"),
            "--provenance",
            str(input_paths["provenance"]),
            "--protocol-seal",
            str(input_paths["seal"]),
            "--cell-manifest",
            str(cell_path),
            "--causal-manifest",
            str(input_paths["causal-manifest"]),
            "--causal-decision",
            str(input_paths["causal-decision"]),
            "--causal-root",
            str(tmp_path),
            "--causal-smoke-gate",
            str(input_paths["causal-smoke-gate"]),
            "--causal-provenance",
            str(input_paths["causal-provenance"]),
            "--icl-smoke-gate",
            str(input_paths["icl-smoke-gate"]),
            "--output",
            str(output),
            "--root",
            str(tmp_path),
        ],
    )

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        results_module.main()

    _assert_final_output_untouched(
        output,
        occupancy=occupancy,
        marker=marker,
        target=target,
    )


def test_internal_screen_pass_is_descriptive_not_publication_grade() -> None:
    active = [0.15, 0.16, 0.17]
    lr0 = [0.12, 0.13, 0.14]
    report = assemble_internal_screen(
        causal_manifest=causal_manifest(active=active, lr0=lr0),
        causal_decision=causal_decision(active, lr0),
        online_cells=online_cells([0.12, 0.12, 0.13]),
    )
    assert report["decision"] == "pass"
    assert report["decision_scope"] == "internal_screen"
    assert report["publication_grade"] is False
    assert report["effective_n"] == 3
    assert report["competitive_deltas"] == pytest.approx([0.03, 0.04, 0.04])
    assert report["sample_standard_deviation"] == pytest.approx(
        statistics.stdev(report["competitive_deltas"])
    )
    assert report["sign_test_two_sided_p"] == 0.25
    assert all(report["threshold_checks"].values())


def test_competitive_miss_is_valid_no_go_and_cannot_rescue_causal_failure() -> None:
    active = [0.15, 0.16, 0.17]
    lr0 = [0.12, 0.13, 0.14]
    miss = assemble_internal_screen(
        causal_manifest=causal_manifest(active=active, lr0=lr0),
        causal_decision=causal_decision(active, lr0),
        online_cells=online_cells([0.14, 0.17, 0.14]),
    )
    assert miss["decision"] == "valid_no_go"
    assert miss["threshold_checks"]["all_competitive_deltas_positive"] is False

    with pytest.raises(ValueError, match="causal internal gate pass"):
        assemble_internal_screen(
            causal_manifest=causal_manifest(
                active=[0.15, 0.16, 0.17], lr0=[0.16, 0.17, 0.18]
            ),
            causal_decision=causal_decision([0.15, 0.16, 0.17], [0.16, 0.17, 0.18]),
            online_cells=online_cells([0.10, 0.10, 0.10]),
        )


def test_three_arm_seed_inventory_must_match_exactly() -> None:
    active = [0.15, 0.16, 0.17]
    lr0 = [0.12, 0.13, 0.14]
    cells = online_cells([0.1, 0.1, 0.1])
    cells[-1]["run_seed"] = 999
    with pytest.raises(ValueError, match="seed inventory"):
        assemble_internal_screen(
            causal_manifest=causal_manifest(active=active, lr0=lr0),
            causal_decision=causal_decision(active, lr0),
            online_cells=cells,
        )


def test_active_retry_regression_against_icl_is_a_valid_no_go() -> None:
    active = [0.15, 0.16, 0.17]
    lr0 = [0.12, 0.13, 0.14]
    manifest = causal_manifest(active=active, lr0=lr0)
    cells = online_cells([0.12, 0.12, 0.13])
    manifest["pairs"][1]["active"]["integrity_counters"] = integrity(retries=1)

    report = assemble_internal_screen(
        causal_manifest=manifest,
        causal_decision=causal_decision(active, lr0),
        online_cells=cells,
    )

    assert report["decision"] == "valid_no_go"
    assert report["threshold_checks"]["no_schema_format_regression"] is False


def test_causal_decision_must_bind_raw_manifest_scores() -> None:
    active = [0.15, 0.16, 0.17]
    lr0 = [0.12, 0.13, 0.14]
    decision = causal_decision(active, lr0)
    decision["pairs"][0]["active_score"] = 0.99

    with pytest.raises(ValueError, match="not the exact evaluation"):
        assemble_internal_screen(
            causal_manifest=causal_manifest(active=active, lr0=lr0),
            causal_decision=decision,
            online_cells=online_cells([0.12, 0.12, 0.13]),
        )


def test_three_arm_model_tokenizer_environment_provenance_must_match() -> None:
    active = [0.15, 0.16, 0.17]
    lr0 = [0.12, 0.13, 0.14]
    cells = online_cells([0.12, 0.12, 0.13])
    cells[2]["provenance"] = {
        **cells[2]["provenance"],
        "model_sha256": "x" * 64,
    }

    with pytest.raises(ValueError, match="shared provenance mismatch"):
        assemble_internal_screen(
            causal_manifest=causal_manifest(active=active, lr0=lr0),
            causal_decision=causal_decision(active, lr0),
            online_cells=cells,
        )


def test_formal_requires_the_exact_passing_online_icl_smoke_seal() -> None:
    provenance = {
        "base_causal_commit": "d" * 40,
        "environment_lock_sha256": "e" * 64,
        "model_path": "/model",
        "model_sha256": "3" * 64,
        "source_commit": "a" * 40,
        "tokenizer_sha256": "4" * 64,
    }
    seal_sha256 = "b" * 64
    gate = {
        "causal_prerequisite": {
            "causal_provenance_sha256": "1" * 64,
            "causal_smoke_gate_sha256": "2" * 64,
            "causal_source_commit": provenance["base_causal_commit"],
            "environment_lock_sha256": provenance["environment_lock_sha256"],
            "model_path": provenance["model_path"],
            "model_sha256": provenance["model_sha256"],
            "tokenizer_sha256": provenance["tokenizer_sha256"],
        },
        "cell": smoke_cell_integrity(),
        "decision": "pass",
        "decision_scope": "infrastructure_smoke",
        "efficacy_interpretation_allowed": False,
        "protocol": PROTOCOL,
        "protocol_seal_sha256": seal_sha256,
        "provenance_sha256": results_module.canonical_sha256(provenance),
        "publication_grade": False,
        "schema_version": 1,
        "status": "pass",
    }
    assert validate_formal_smoke_gate_binding(
        smoke_gate=gate,
        provenance=provenance,
        protocol_seal_sha256=seal_sha256,
    ) == results_module.canonical_sha256(gate)

    changed = {**gate, "protocol_seal_sha256": "c" * 64}
    with pytest.raises(ValueError, match="exact seal"):
        validate_formal_smoke_gate_binding(
            smoke_gate=changed,
            provenance=provenance,
            protocol_seal_sha256=seal_sha256,
        )

    extra_top_level_field = {**gate, "legacy_unbound_field": True}
    with pytest.raises(ValueError, match="smoke gate schema mismatch"):
        validate_formal_smoke_gate_binding(
            smoke_gate=extra_top_level_field,
            provenance=provenance,
            protocol_seal_sha256=seal_sha256,
        )

    outcome_bearing_smoke_cell = {
        **gate,
        "cell": {**gate["cell"], "heldout_score": 0.99},
    }
    with pytest.raises(ValueError, match="smoke gate cell schema mismatch"):
        validate_formal_smoke_gate_binding(
            smoke_gate=outcome_bearing_smoke_cell,
            provenance=provenance,
            protocol_seal_sha256=seal_sha256,
        )

    missing_causal_binding = {**gate, "causal_prerequisite": {}}
    with pytest.raises(ValueError, match="causal prerequisite schema"):
        validate_formal_smoke_gate_binding(
            smoke_gate=missing_causal_binding,
            provenance=provenance,
            protocol_seal_sha256=seal_sha256,
        )

    changed_causal_binding = {
        **gate,
        "causal_prerequisite": {
            **gate["causal_prerequisite"],
            "model_sha256": "5" * 64,
        },
    }
    with pytest.raises(ValueError, match="causal/online provenance differs"):
        validate_formal_smoke_gate_binding(
            smoke_gate=changed_causal_binding,
            provenance=provenance,
            protocol_seal_sha256=seal_sha256,
        )


def test_formal_revalidates_registered_smoke_raw_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provenance = {
        "base_causal_commit": "d" * 40,
        "environment_lock_sha256": "e" * 64,
        "model_path": "/model",
        "model_sha256": "3" * 64,
        "source_commit": "a" * 40,
        "tokenizer_sha256": "4" * 64,
    }
    seal_sha256 = "b" * 64
    causal_prerequisite = {
        "causal_provenance_sha256": "1" * 64,
        "causal_smoke_gate_sha256": "2" * 64,
        "causal_source_commit": provenance["base_causal_commit"],
        "environment_lock_sha256": provenance["environment_lock_sha256"],
        "model_path": provenance["model_path"],
        "model_sha256": provenance["model_sha256"],
        "tokenizer_sha256": provenance["tokenizer_sha256"],
    }
    gate = {
        "causal_prerequisite": causal_prerequisite,
        "cell": smoke_cell_integrity(),
        "decision": "pass",
        "decision_scope": "infrastructure_smoke",
        "efficacy_interpretation_allowed": False,
        "protocol": PROTOCOL,
        "protocol_seal_sha256": seal_sha256,
        "provenance_sha256": results_module.canonical_sha256(provenance),
        "publication_grade": False,
        "schema_version": 1,
        "status": "pass",
    }

    grid_path = tmp_path / "registered-smoke-grid.json"
    grid_path.write_text("{}\n")
    cell_path = tmp_path / "artifacts" / "smoke.manifest.json"
    raw_path = tmp_path / "artifacts" / "smoke.raw.trace.json"
    cell_path.parent.mkdir(parents=True)
    cell_path.write_text(
        json.dumps({"raw_trace_path": str(raw_path.relative_to(tmp_path))}) + "\n"
    )
    raw_path.write_text(json.dumps({"state": "expected"}) + "\n")
    smoke_grid = {
        "cells": [{"cell_manifest_path": str(cell_path.relative_to(tmp_path))}],
        "grid_sha256": "6" * 64,
        "kind": "smoke",
    }
    protocol_seal = {
        "grids": {
            "smoke": {
                "file_sha256": hashlib.sha256(grid_path.read_bytes()).hexdigest(),
                "grid_sha256": smoke_grid["grid_sha256"],
                "path": grid_path.name,
            }
        }
    }
    monkeypatch.setattr(runner, "load_grid", lambda path: smoke_grid)

    def exact_smoke_revalidation(**kwargs) -> dict:
        raw = json.loads(
            (kwargs["root"] / kwargs["cell"]["raw_trace_path"]).read_text()
        )
        if raw != {"state": "expected"}:
            raise ValueError("registered raw smoke artifact was tampered")
        assert kwargs["causal_prerequisite"] == causal_prerequisite
        return gate

    monkeypatch.setattr(smoke_module, "validate_smoke", exact_smoke_revalidation)
    monkeypatch.setattr(
        smoke_module,
        "validate_causal_smoke_prerequisite",
        lambda **_kwargs: causal_prerequisite,
    )
    causal_revalidation_args = {
        "causal_root": tmp_path / "causal-root",
        "causal_smoke_gate": {"decision": "pass"},
        "causal_provenance": {"source_commit": provenance["base_causal_commit"]},
    }
    assert revalidate_registered_formal_smoke_gate(
        root=tmp_path,
        smoke_gate=gate,
        provenance=provenance,
        protocol_seal=protocol_seal,
        protocol_seal_sha256=seal_sha256,
        **causal_revalidation_args,
    ) == results_module.canonical_sha256(gate)

    monkeypatch.setattr(
        smoke_module,
        "validate_causal_smoke_prerequisite",
        lambda **_kwargs: {
            **causal_prerequisite,
            "causal_smoke_gate_sha256": "f" * 64,
        },
    )
    with pytest.raises(ValueError, match="causal prerequisite differs"):
        revalidate_registered_formal_smoke_gate(
            root=tmp_path,
            smoke_gate=gate,
            provenance=provenance,
            protocol_seal=protocol_seal,
            protocol_seal_sha256=seal_sha256,
            **causal_revalidation_args,
        )
    monkeypatch.setattr(
        smoke_module,
        "validate_causal_smoke_prerequisite",
        lambda **_kwargs: causal_prerequisite,
    )

    raw_path.unlink()
    with pytest.raises(ValueError, match="raw artifact is missing"):
        revalidate_registered_formal_smoke_gate(
            root=tmp_path,
            smoke_gate=gate,
            provenance=provenance,
            protocol_seal=protocol_seal,
            protocol_seal_sha256=seal_sha256,
            **causal_revalidation_args,
        )

    raw_path.write_text(json.dumps({"state": "tampered"}) + "\n")
    with pytest.raises(ValueError, match="raw smoke artifact was tampered"):
        revalidate_registered_formal_smoke_gate(
            root=tmp_path,
            smoke_gate=gate,
            provenance=provenance,
            protocol_seal=protocol_seal,
            protocol_seal_sha256=seal_sha256,
            **causal_revalidation_args,
        )
