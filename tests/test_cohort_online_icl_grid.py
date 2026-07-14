from __future__ import annotations

import ast
import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import generate_cohort_online_icl_grid as grid


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_OUTCOME_KEYS = {
    "decision",
    "delta",
    "heldout_outcomes",
    "mean_reward",
    "outcomes",
    "p_value",
    "result",
    "results",
    "reward",
    "score",
}


def canonical_sha(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        keys.update(value)
        for item in value.values():
            keys.update(collect_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.update(collect_keys(item))
    return keys


def copy_registered_dataset(
    tmp_path: Path, dataset: dict[str, Any]
) -> tuple[dict[str, Any], Path]:
    copied = copy.deepcopy(dataset)
    source_dataset = ROOT / copied["path"]
    target_dataset = tmp_path / copied["path"]
    target_dataset.parent.mkdir(parents=True)
    shutil.copytree(source_dataset, target_dataset)
    manifest = json.loads((source_dataset / "manifest.json").read_text())
    for relative in manifest["source_sha256"]:
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return copied, target_dataset


def resign_copied_artifact(
    dataset: dict[str, Any], dataset_dir: Path, relative_path: str
) -> None:
    manifest_path = dataset_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    artifact = next(
        row for row in manifest["artifacts"] if row["path"] == relative_path
    )
    raw = (dataset_dir / relative_path).read_bytes()
    artifact["sha256"] = hashlib.sha256(raw).hexdigest()
    artifact["size_bytes"] = len(raw)
    manifest["corpus_sha256"] = canonical_sha(manifest["artifacts"])
    dataset["corpus_sha256"] = manifest["corpus_sha256"]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


@pytest.mark.parametrize(
    "smoke,seeds,count,scope",
    [
        (True, [2026071498], 2, "infrastructure_smoke"),
        (
            False,
            [2026071401, 2026071402, 2026071403],
            20,
            "internal_screen",
        ),
    ],
)
def test_one_online_adapt_seal_eval_cell_per_seed(
    smoke: bool, seeds: list[int], count: int, scope: str
) -> None:
    payload = grid.make_grid(smoke=smoke)

    assert payload["protocol"] == "cohort_reward_aware_online_icl_v1"
    assert payload["decision_scope"] == scope
    assert payload["publication_grade"] is False
    assert [cell["run_seed"] for cell in payload["cells"]] == seeds
    assert len(payload["cells"]) == len(seeds)
    for cell in payload["cells"]:
        assert cell["mode"] == "online_icl_eval"
        assert cell["arm"] == "online_icl"
        assert cell["expected_num_instances"] == count
        assert cell["execution_contract"]["phase_order"] == [
            "verify_protocol_seal",
            "revalidate_paired_causal_gate",
            "online_adaptation",
            "seal_context",
            "heldout_evaluation",
        ]


def test_system_settings_are_exactly_the_preregistered_online_icl_arm() -> None:
    expected = {
        "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
        "method": "icl",
        "context_policy": "full",
        "adaptation_context_policy": "full",
        "max_context_tokens": 32768,
        "head_tokens": 4096,
        "tail_tokens": 4096,
        "max_new_tokens": 8192,
        "action_max_new_tokens": 4096,
        "temperature": 0.0,
        "top_p": 1.0,
        "parse_retries": 2,
        "system_prompt": "",
        "trust_remote_code": True,
        "inject_env_reward": True,
        "ttt_steps": 0,
        "ttt_lr": 0.0,
        "reward_pg_steps": 0,
        "reward_pg_lr": 0.0,
        "history_ttt": False,
        "best_of_n": 1,
        "distill_provider": "off",
    }

    assert grid.SYSTEM_PARAMS == expected
    for smoke in (True, False):
        for cell in grid.make_grid(smoke=smoke)["cells"]:
            assert cell["system_params"] == expected
            assert cell["system_params_sha256"] == canonical_sha(expected)


def test_formal_dataset_and_task_projection_is_exactly_paired_to_causal_grid() -> None:
    payload = grid.make_grid(smoke=False)
    causal_path = ROOT / grid.PAIRED_CAUSAL_GRID_PATHS[False]
    causal = json.loads(causal_path.read_text())

    assert payload["datasets"] == causal["datasets"]
    assert payload["paired_causal_grid"] == {
        "path": grid.PAIRED_CAUSAL_GRID_PATHS[False],
        "sha256": file_sha(causal_path),
    }
    for cell in payload["cells"]:
        seed = cell["run_seed"]
        collector = next(row for row in causal["collectors"] if row["run_seed"] == seed)
        paired = [row for row in causal["evaluation_cells"] if row["run_seed"] == seed]
        assert cell["adaptation_task_params"] == collector["task_params"]
        assert all(cell["heldout_task_params"] == row["task_params"] for row in paired)
        assert cell["adaptation_task_params_sha256"] == canonical_sha(
            collector["task_params"]
        )
        assert cell["heldout_task_params_sha256"] == canonical_sha(
            paired[0]["task_params"]
        )


def test_smoke_uses_independent_outcome_blind_dgps() -> None:
    payload = grid.make_grid(smoke=True)
    causal_path = ROOT / grid.PAIRED_CAUSAL_GRID_PATHS[True]
    causal = json.loads(causal_path.read_text())

    assert payload["datasets"] == grid.SMOKE_DATASETS
    assert payload["datasets"] != causal["datasets"]
    assert causal["datasets"] == grid.FORMAL_DATASETS
    for role in ("adaptation", "heldout"):
        smoke_dataset = payload["datasets"][role]
        formal_dataset = causal["datasets"][role]
        assert smoke_dataset["path"] != formal_dataset["path"]
        assert smoke_dataset["seed"] != formal_dataset["seed"]
        assert smoke_dataset["corpus_sha256"] != formal_dataset["corpus_sha256"]
        manifest = json.loads(
            (ROOT / smoke_dataset["path"] / "manifest.json").read_text()
        )
        assert manifest["seed"] == smoke_dataset["seed"]
        assert manifest["corpus_sha256"] == smoke_dataset["corpus_sha256"]

    cell = payload["cells"][0]
    assert (
        cell["adaptation_task_params"]["dataset_path"]
        == (grid.SMOKE_DATASETS["adaptation"]["path"])
    )
    assert (
        cell["heldout_task_params"]["dataset_path"]
        == (grid.SMOKE_DATASETS["heldout"]["path"])
    )


def test_smoke_validator_rejects_formal_dgp_overlap() -> None:
    payload = grid.make_grid(smoke=True)
    payload["datasets"]["heldout"] = copy.deepcopy(grid.FORMAL_DATASETS["heldout"])
    with pytest.raises(ValueError, match="dataset contract"):
        grid.validate(payload, smoke=True)


@pytest.mark.parametrize("smoke", [True, False])
def test_registered_corpus_bytes_project_and_rescore_without_dgp_constants(
    smoke: bool,
) -> None:
    from run_cohort_online_icl import _dataset_projection
    from validate_cohort_online_icl_results import _scoring_contract

    payload = grid.make_grid(smoke=smoke)
    for role in ("adaptation", "heldout"):
        projection = _dataset_projection(ROOT, payload, role)
        assert (
            projection["aggregate_sha256"] == payload["datasets"][role]["corpus_sha256"]
        )
        assert projection["dgp_seed"] == payload["datasets"][role]["seed"]
        assert len(projection["canonical_instance_ids"]) == 20
        contract = _scoring_contract(
            root=ROOT,
            grid=payload,
            role=role,
            corpus=projection,
        )
        assert len(contract["action_keys"]) == 108
        assert len(contract["references"]) == 20


def test_smoke_projection_matches_the_shared_tasks_legacy_default_ids() -> None:
    from run_cohort_online_icl import _dataset_projection

    task_source = ast.parse(
        (ROOT / "src/tasks/cohort_studies/task.py").read_text(),
        filename="src/tasks/cohort_studies/task.py",
    )
    helper = next(
        node
        for node in task_source.body
        if isinstance(node, ast.FunctionDef) and node.name == "cohort_instance_id"
    )
    namespace: dict[str, Any] = {}
    exec(
        compile(ast.Module(body=[helper], type_ignores=[]), "<task-id>", "exec"),
        namespace,
    )
    task_instance_id = namespace["cohort_instance_id"]

    payload = grid.make_grid(smoke=True)
    projection = _dataset_projection(ROOT, payload, "adaptation")
    manifest = json.loads(
        (ROOT / payload["datasets"]["adaptation"]["path"] / "manifest.json").read_text()
    )
    expected = [
        task_instance_id("default", row["variant_id"]) for row in manifest["instances"]
    ]
    assert projection["canonical_instance_ids"] == expected
    assert expected[0] == "cohort_studies:herald_suburban"


def test_generic_corpus_verifier_rejects_byte_drift_and_unregistered_files(
    tmp_path: Path,
) -> None:
    from run_cohort_online_icl import _dataset_projection

    dataset, target_dataset = copy_registered_dataset(
        tmp_path, grid.SMOKE_DATASETS["adaptation"]
    )
    manifest = json.loads((target_dataset / "manifest.json").read_text())
    payload = {"datasets": {"adaptation": dataset}}
    assert (
        _dataset_projection(tmp_path, payload, "adaptation")["dgp_seed"]
        == (dataset["seed"])
    )

    database = target_dataset / manifest["artifacts"][0]["path"]
    original = database.read_bytes()
    database.write_bytes(original + b"tamper")
    with pytest.raises(ValueError, match="artifact size drift"):
        _dataset_projection(tmp_path, payload, "adaptation")
    database.write_bytes(original)

    unregistered = target_dataset / "unregistered.txt"
    unregistered.write_text("not in manifest\n")
    with pytest.raises(ValueError, match="file inventory differs"):
        _dataset_projection(tmp_path, payload, "adaptation")
    unregistered.unlink()

    dangling = target_dataset / "dangling-artifact"
    dangling.symlink_to(target_dataset / "missing-artifact")
    with pytest.raises(ValueError, match="unregistered symlink"):
        _dataset_projection(tmp_path, payload, "adaptation")


@pytest.mark.parametrize(
    "field,value",
    [
        ("study_name", "ALTERED"),
        ("region_slice", "WrongRegion"),
        ("db_filename", "herald_rural.db"),
        ("n_patients", 999),
    ],
)
def test_generic_corpus_verifier_rejects_resigned_prompt_metadata_drift(
    tmp_path: Path, field: str, value: Any
) -> None:
    from run_cohort_online_icl import _dataset_projection

    dataset, target_dataset = copy_registered_dataset(
        tmp_path, grid.SMOKE_DATASETS["adaptation"]
    )
    metadata_path = target_dataset / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["instances"][0][field] = value
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    resign_copied_artifact(dataset, target_dataset, "metadata.json")

    with pytest.raises(
        ValueError, match="(metadata instance 0 binding|prompt metadata) drift"
    ):
        _dataset_projection(
            tmp_path, {"datasets": {"adaptation": dataset}}, "adaptation"
        )


def test_generic_corpus_verifier_rejects_resigned_manifest_instance_schema(
    tmp_path: Path,
) -> None:
    from run_cohort_online_icl import _dataset_projection

    dataset, target_dataset = copy_registered_dataset(
        tmp_path, grid.SMOKE_DATASETS["adaptation"]
    )
    manifest_path = target_dataset / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["instances"][0]["unregistered"] = True
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    with pytest.raises(ValueError, match="manifest instance 0 schema mismatch"):
        _dataset_projection(
            tmp_path, {"datasets": {"adaptation": dataset}}, "adaptation"
        )


def test_generic_corpus_verifier_rejects_dataset_symlink(
    tmp_path: Path,
) -> None:
    from run_cohort_online_icl import _dataset_projection

    dataset = copy.deepcopy(grid.SMOKE_DATASETS["adaptation"])
    source_dataset = ROOT / dataset["path"]
    target_dataset = tmp_path / dataset["path"]
    target_dataset.parent.mkdir(parents=True)
    target_dataset.symlink_to(source_dataset, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink component"):
        _dataset_projection(
            tmp_path, {"datasets": {"adaptation": dataset}}, "adaptation"
        )


def test_reward_visibility_seal_and_heldout_isolation_are_frozen() -> None:
    contract = grid.make_grid(smoke=False)["cells"][0]["execution_contract"]
    adaptation = contract["online_adaptation"]
    seal = contract["seal_context"]
    heldout = contract["heldout_evaluation"]
    integrity = contract["integrity"]
    protocol_seal = contract["protocol_seal"]

    assert adaptation == {
        "consume_own_trajectory_only": True,
        "candidate_sampler_forbidden": True,
        "extra_model_calls_per_action": 0,
        "terminal_reward_visible_only_after_report_commit_and_score": True,
        "terminal_reward_template": (
            "ENV_REWARD (score of your previous answer, higher is better): {reward:.4f}"
        ),
    }
    assert seal["quiescent_state_required"] is True
    assert seal["one_way_feedback_gate_required"] is True
    assert seal["snapshot_digest_independently_recomputed"] is True
    assert seal["snapshot_state_bound_to_adaptation_trace"] is True
    assert seal["message_and_token_inventory_independently_recomputed"] is True
    assert seal["snapshot_protocol"] == "qwen_local_icl_context_snapshot_v1"
    assert seal["canonical_json"] == {
        "allow_nan": False,
        "encoding": "utf-8",
        "separators": [",", ":"],
        "sort_keys": True,
    }
    assert heldout["restore_snapshot_after_every_completed_condition_including_last"]
    assert heldout["initial_snapshot_digest_identical_for_every_condition"]
    assert heldout["terminal_query_feedback_ingestion_forbidden"]
    assert heldout["terminal_observe_content_ingestion_forbidden"]
    assert heldout["forbidden_sensitive_fields"] == [
        "cohort_gt",
        "env_feedback_reward",
        "ref_survival",
        "terminal_content",
        "terminal_reward",
    ]
    assert integrity["adapter_creation_forbidden"]
    assert integrity["optimizer_creation_forbidden"]
    assert integrity["parameter_update_count_required"] == 0
    assert integrity["candidate_sample_count_required"] == 0
    assert integrity["model_state_hash_unchanged_required"]
    assert integrity["model_state_hash_covers_parameters_and_persistent_buffers"]
    assert integrity["immutable_artifacts_atomic_no_overwrite"]
    assert integrity["smoke_dgp_overlap_with_internal_screen_forbidden"]
    assert integrity["smoke_user_visible_efficacy_fields_forbidden"]
    assert integrity["validated_report_binds_every_raw_artifact_sha256"]
    causal = contract["causal_prerequisite"]
    assert causal == {
        "bind_exact_gate_and_provenance_sha256": True,
        "recompute_gate_from_registered_raw_artifacts": True,
        "require_empty_errors_and_pass": True,
        "shared_environment_model_tokenizer_required": True,
    }
    assert protocol_seal == {
        "atomic_no_overwrite_required": True,
        "binds_both_smoke_and_formal_grid_digests": True,
        "binds_exact_runtime_provenance": True,
        "created_before_first_icl_outcome": True,
        "same_artifact_and_source_commit_for_smoke_and_formal": True,
    }


@pytest.mark.parametrize("smoke", [True, False])
def test_cells_expose_runner_compatible_paths_and_canonical_digests(
    smoke: bool,
) -> None:
    payload = grid.make_grid(smoke=smoke)
    required = {
        "cfg_id",
        "mode",
        "arm",
        "run_seed",
        "expected_num_instances",
        "system_params",
        "system_params_sha256",
        "adaptation_task_params",
        "adaptation_task_params_sha256",
        "heldout_task_params",
        "heldout_task_params_sha256",
        "cell_manifest_path",
        "snapshot_path",
        "adaptation_trace_path",
        "heldout_trace_path",
    }
    for cell in payload["cells"]:
        assert required <= set(cell)
        assert cell["snapshot_path"].endswith(".sealed_snapshot.json")
        assert cell["cell_manifest_path"].endswith(".manifest.json")
        assert cell["adaptation_trace_path"].endswith(".adaptation.trace.json")
        assert cell["heldout_trace_path"].endswith(".heldout.trace.json")
        without_sha = copy.deepcopy(cell)
        embedded = without_sha.pop("cell_config_sha256")
        assert embedded == canonical_sha(without_sha)
    without_sha = copy.deepcopy(payload)
    embedded = without_sha.pop("grid_sha256")
    assert embedded == canonical_sha(without_sha)


@pytest.mark.parametrize("smoke", [True, False])
def test_grid_binds_current_preregistration_and_contains_no_outcomes(
    smoke: bool,
) -> None:
    payload = grid.make_grid(smoke=smoke)
    prereg = ROOT / "COHORT_MATCHED_ICL_PREREG_V1.md"

    assert payload["preregistration"] == {
        "path": prereg.name,
        "sha256": file_sha(prereg),
    }
    assert not (collect_keys(payload) & FORBIDDEN_OUTCOME_KEYS)


def test_validator_fails_closed_on_parameter_update_or_leakage_drift() -> None:
    update_drift = grid.make_grid(smoke=False)
    update_drift["cells"][0]["system_params"]["ttt_steps"] = 1
    with pytest.raises(ValueError, match="system settings"):
        grid.validate(update_drift, smoke=False)

    leakage_drift = grid.make_grid(smoke=False)
    leakage_drift["cells"][0]["execution_contract"]["heldout_evaluation"][
        "terminal_query_feedback_ingestion_forbidden"
    ] = False
    with pytest.raises(ValueError, match="seal/held-out contract"):
        grid.validate(leakage_drift, smoke=False)

    outcome_drift = grid.make_grid(smoke=False)
    outcome_drift["cells"][0]["execution_contract"]["score"] = 1.0
    with pytest.raises(ValueError, match="forbidden outcome keys"):
        grid.validate(outcome_drift, smoke=False)


def test_validator_rejects_seed_dataset_and_digest_drift() -> None:
    seed_drift = grid.make_grid(smoke=False)
    seed_drift["cells"][0]["run_seed"] += 1
    with pytest.raises(ValueError, match="seed/order"):
        grid.validate(seed_drift, smoke=False)

    dataset_drift = grid.make_grid(smoke=False)
    dataset_drift["datasets"]["heldout"]["corpus_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="dataset contract"):
        grid.validate(dataset_drift, smoke=False)

    digest_drift = grid.make_grid(smoke=False)
    digest_drift["grid_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="grid canonical digest"):
        grid.validate(digest_drift, smoke=False)


def test_registered_grids_are_generator_exact() -> None:
    for smoke in (True, False):
        registered = json.loads((ROOT / grid.GRID_PATHS[smoke]).read_text())
        assert registered == grid.make_grid(smoke=smoke)
        grid.validate(registered, smoke=smoke)

    completed = subprocess.run(
        [sys.executable, str(ROOT / "generate_cohort_online_icl_grid.py"), "--check"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == (
        "COHORT_ONLINE_ICL_GRID_CHECK_OK smoke=1 formal=3"
    )


def test_check_rejects_stale_registered_grid(tmp_path: Path) -> None:
    for name in grid.GRID_PATHS.values():
        (tmp_path / name).write_text("{}\n")
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "generate_cohort_online_icl_grid.py"),
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
