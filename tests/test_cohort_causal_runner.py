from __future__ import annotations

import json
import shutil
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

import run_cohort_causal as runner
from validate_cohort_causal_results import EXPECTED_STATISTICAL_ADDENDUM_SHA256


REPO_ROOT = Path(__file__).resolve().parents[1]
HASH_A = "a" * 64
HASH_B = "b" * 64


@dataclass
class FakeOutcome:
    instance_id: str
    instance_index: int
    reward: float


class FakeResult:
    def __init__(self, instance_ids: list[str]) -> None:
        self.instance_outcomes = [
            FakeOutcome(instance_id, index, 0.1234567890123 + index / 10)
            for index, instance_id in enumerate(instance_ids)
        ]

    @property
    def score(self) -> float:
        return round(
            sum(row.reward for row in self.instance_outcomes)
            / len(self.instance_outcomes),
            6,
        )


class FakeTask:
    def __init__(self, **params) -> None:
        self.params = params

    def get_agent_brief(self):
        return None


class FakeRecorder:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.interactions = []

    def finalize(self, result, status="completed"):
        return {
            "status": status,
            "interactions": list(self.interactions),
            "result": {"score": result.score},
        }


class FakeSystem:
    def __init__(self, **params) -> None:
        self.params = params
        self.initial = HASH_A
        self.final = HASH_A

    def initialize_and_snapshot_adapter_state(self):
        return self.initial

    def restore_initial_adapter_state(self):
        self.final = self.initial
        return self.initial

    def current_trainable_param_sha256(self):
        return self.final

    def capture_frozen_tape_item(
        self,
        _observation,
        *,
        sequence_index,
        instance_id,
        instance_index,
        integrity,
    ):
        if integrity["schema_valid"] is not True or integrity["fallback"] is not False:
            raise ValueError("frozen tape item failed integrity gate")
        item = {
            "sequence_index": sequence_index,
            "instance_id": instance_id,
            "instance_index": instance_index,
            "integrity": integrity,
        }
        item["item_sha256"] = runner.canonical_sha256(item)
        return item

    def assemble_frozen_update_tape(self, items):
        tape = {"items": items}
        tape["tape_sha256"] = runner.canonical_sha256(tape)
        return tape

    def serialize_frozen_update_tape(self, tape):
        return json.dumps(tape, sort_keys=True, separators=(",", ":")).encode()

    def replay_frozen_update_tape(self, tape_bytes, *, expected_tape_sha256):
        assert json.loads(tape_bytes)["tape_sha256"] == expected_tape_sha256
        if self.params["ttt_lr"]:
            self.final = HASH_B
        return {
            "tape_sha256": expected_tape_sha256,
            "trainable_param_sha256_initial": self.initial,
            "trainable_param_sha256_final": self.final,
            "items": [],
        }

    def freeze_updates_for_heldout_eval(self):
        return self.final


def fake_run_task(task, system, *, trace_recorder, before_observe=None, **kwargs):
    count = int(task.params["num_instances"])
    manifest = json.loads(
        (Path(task.params["dataset_path"]) / "manifest.json").read_text()
    )
    instance_ids = [
        f"cohort_studies:{manifest['schedule_id']}:{row['variant_id']}"
        for row in manifest["instances"][:count]
    ]
    result = FakeResult(instance_ids)
    for outcome in result.instance_outcomes:
        query = SimpleNamespace(
            instance_id=outcome.instance_id,
            instance_index=outcome.instance_index,
        )
        # A nonterminal action must never enter the frozen update tape.
        if before_observe is not None:
            before_observe(
                1,
                query,
                SimpleNamespace(metadata={}),
                SimpleNamespace(
                    observation=SimpleNamespace(instance_complete=False)
                ),
            )
            before_observe(
                2,
                query,
                SimpleNamespace(metadata={}),
                SimpleNamespace(
                    observation=SimpleNamespace(instance_complete=True)
                ),
            )
        trace_recorder.interactions.append(
            {
                "query": {
                    "instance_id": outcome.instance_id,
                    "instance_index": outcome.instance_index,
                },
                "response": {
                    "metadata": {
                        "parse_retries_used": 0,
                        "parse_repair_used": False,
                    }
                },
                "observation": {"instance_complete": True},
            }
        )
    return result


def fallback_run_task(task, system, *, trace_recorder, before_observe=None, **kwargs):
    manifest = json.loads(
        (Path(task.params["dataset_path"]) / "manifest.json").read_text()
    )
    query = SimpleNamespace(
        instance_id=(
            f"cohort_studies:{manifest['schedule_id']}:"
            f"{manifest['instances'][0]['variant_id']}"
        ),
        instance_index=0,
    )
    before_observe(
        1,
        query,
        SimpleNamespace(
            metadata={
                "llm_error": {
                    "error_type": "RuntimeError",
                    "error_message": "did not parse as the required JSON",
                }
            }
        ),
        SimpleNamespace(observation=SimpleNamespace(instance_complete=True)),
    )
    raise AssertionError("fallback terminal capture should have failed closed")


@pytest.fixture
def bindings():
    return runner.RuntimeBindings(
        system_cls=FakeSystem,
        task_cls=FakeTask,
        run_task=fake_run_task,
        trace_recorder_cls=FakeRecorder,
    )


@pytest.fixture
def smoke_grid(tmp_path):
    grid = json.loads((REPO_ROOT / "grid_cohort_causal_smoke.json").read_text())
    for role in ("adaptation", "heldout"):
        grid["datasets"][role]["path"] = str(
            REPO_ROOT / grid["datasets"][role]["path"]
        )
    for row in [*grid["collectors"], *grid["evaluation_cells"]]:
        row["task_params"]["dataset_path"] = str(
            REPO_ROOT / row["task_params"]["dataset_path"]
        )
    schedule_dir = tmp_path / "src/tasks/cohort_studies/schedules"
    schedule_dir.mkdir(parents=True)
    for role in ("adaptation", "heldout"):
        schedule = grid["datasets"][role]["schedule"]
        shutil.copyfile(
            REPO_ROOT / f"src/tasks/cohort_studies/schedules/{schedule}.json",
            schedule_dir / f"{schedule}.json",
        )
    return grid


@pytest.fixture
def provenance(smoke_grid):
    return {
        "source_commit": "1" * 40,
        "preregistered_parent_commit": runner.PREREGISTERED_PARENT_COMMIT,
        "environment_lock_sha256": "3" * 64,
        "model_sha256": "4" * 64,
        "tokenizer_sha256": "5" * 64,
        "evaluation_code_sha256": "6" * 64,
        "statistical_addendum_sha256": EXPECTED_STATISTICAL_ADDENDUM_SHA256,
        "model_path": smoke_grid["collectors"][0]["system_params"]["model_path"],
        "adapter_init_seed": smoke_grid["adapter_init_seed"],
    }


def test_dataset_projection_uses_checked_in_builder_manifest():
    grid = json.loads((REPO_ROOT / "grid_cohort_causal_formal.json").read_text())
    adaptation = runner._dataset_projection(REPO_ROOT, grid, "adaptation")
    heldout = runner._dataset_projection(REPO_ROOT, grid, "heldout")

    assert adaptation["aggregate_sha256"] == grid["datasets"]["adaptation"][
        "corpus_sha256"
    ]
    assert heldout["aggregate_sha256"] == grid["datasets"]["heldout"][
        "corpus_sha256"
    ]
    assert len(adaptation["canonical_instance_ids"]) == 20
    assert len(heldout["canonical_instance_ids"]) == 20
    assert adaptation["canonical_instance_ids"] != heldout[
        "canonical_instance_ids"
    ]
    assert adaptation["database_sha256"] != heldout["database_sha256"]
    assert adaptation["used_for_updates"] is True
    assert heldout["never_updated"] is True


def test_dataset_projection_rejects_tampered_artifact(tmp_path):
    source = REPO_ROOT / "data/cohort_studies/causal_adapt_2026071411"
    copied = tmp_path / "tampered"
    shutil.copytree(source, copied)
    ground_truth = copied / "ground_truth.json"
    ground_truth.write_bytes(ground_truth.read_bytes() + b"\n")
    grid = json.loads((REPO_ROOT / "grid_cohort_causal_formal.json").read_text())
    grid["datasets"]["adaptation"]["path"] = str(copied)
    with pytest.raises(ValueError, match="artifact size drift"):
        runner._dataset_projection(REPO_ROOT, grid, "adaptation")


def test_collection_is_terminal_only_lr0_and_no_overwrite(
    tmp_path, smoke_grid, bindings, provenance, monkeypatch
):
    monkeypatch.setattr(runner, "seed_everything", lambda _seed: None)
    cfg = smoke_grid["collectors"][0]
    manifest = runner.run_collection(
        root=tmp_path,
        grid=smoke_grid,
        cfg=cfg,
        bindings=bindings,
        provenance=provenance,
    )

    tape_path = tmp_path / cfg["tape_path"]
    tape = json.loads(tape_path.read_text())
    assert len(tape["items"]) == cfg["expected_num_instances"] == 2
    assert manifest["trainable_param_sha256_initial"] == HASH_A
    assert manifest["trainable_param_sha256_final"] == HASH_A
    assert manifest["tape_sha256"] == tape["tape_sha256"]
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        runner.run_collection(
            root=tmp_path,
            grid=smoke_grid,
            cfg=cfg,
            bindings=bindings,
            provenance=provenance,
        )


def test_replay_restores_freezes_and_writes_validator_cell(
    tmp_path, smoke_grid, bindings, provenance, monkeypatch
):
    monkeypatch.setattr(runner, "seed_everything", lambda _seed: None)
    collector = smoke_grid["collectors"][0]
    runner.run_collection(
        root=tmp_path,
        grid=smoke_grid,
        cfg=collector,
        bindings=bindings,
        provenance=provenance,
    )
    cfg = next(
        row for row in smoke_grid["evaluation_cells"] if row["arm"] == "active"
    )
    cell = runner.run_replay_eval(
        root=tmp_path,
        grid=smoke_grid,
        cfg=cfg,
        bindings=bindings,
        provenance=provenance,
    )

    assert cell["heldout_updates_frozen"] is True
    assert cell["replay"]["trainable_param_sha256_initial"] == HASH_A
    assert cell["replay"]["trainable_param_sha256_final"] == HASH_B
    assert cell["system_config"] == cfg["system_params"]
    assert cell["task_config"] == {
        **cfg["task_params"],
        "runs": 1,
        "max_workers": 1,
        "run_mode": "replicate",
    }
    assert cell["integrity_counters"]["fallbacks"] == 0
    assert len(cell["heldout_outcomes"]) == 2
    expected_score = statistics.mean(
        row["reward"] for row in cell["heldout_outcomes"]
    )
    assert cell["score"] == expected_score
    assert cell["score"] != round(cell["score"], 6)
    assert (tmp_path / cfg["cell_manifest_path"]).is_file()


def test_collector_rejects_terminal_fallback_even_if_system_state_is_stale(
    tmp_path, smoke_grid, provenance, monkeypatch
):
    monkeypatch.setattr(runner, "seed_everything", lambda _seed: None)
    bindings = runner.RuntimeBindings(
        system_cls=FakeSystem,
        task_cls=FakeTask,
        run_task=fallback_run_task,
        trace_recorder_cls=FakeRecorder,
    )
    cfg = {**smoke_grid["collectors"][0], "expected_num_instances": 1}
    with pytest.raises(ValueError, match="integrity gate"):
        runner.run_collection(
            root=tmp_path,
            grid=smoke_grid,
            cfg=cfg,
            bindings=bindings,
            provenance=provenance,
        )
    assert not (tmp_path / cfg["tape_path"]).exists()
    assert not runner._collector_manifest_path(tmp_path, cfg).exists()


def test_launcher_defaults_avoid_known_occupied_gpu_one():
    text = (REPO_ROOT / "launch_cohort_causal.sh").read_text()
    assert 'COLLECTOR_GPUS="0"' in text
    assert 'EVAL_GPUS="2,3"' in text
    assert 'COLLECTOR_GPUS="0,2,3"' in text
    assert 'EVAL_GPUS="0,2,3,4,5,6"' in text
    assert 'EVAL_GPUS="0,1' not in text
    assert 'PYTHONHASHSEED="$run_seed"' in text
    assert 'print(matches[0]["run_seed"])' in text


def test_main_reverifies_provenance_before_loading_runtime(
    tmp_path, smoke_grid, provenance, monkeypatch
):
    registered_grid = json.loads(
        (REPO_ROOT / "grid_cohort_causal_smoke.json").read_text()
    )
    grid_path = tmp_path / "grid.json"
    provenance_path = tmp_path / "provenance.json"
    grid_path.write_text(json.dumps(registered_grid))
    provenance_path.write_text(json.dumps(provenance))
    cfg = registered_grid["collectors"][0]
    events: list[tuple[str, object]] = []

    def verify(root, payload, *, expected_model_path=None):
        events.append(
            (
                "verify",
                (root, payload, expected_model_path),
            )
        )

    class RuntimeLoaded(Exception):
        pass

    def load_runtime():
        events.append(("load_runtime", None))
        raise RuntimeLoaded

    monkeypatch.setattr(runner, "verify_runtime_provenance", verify)
    monkeypatch.setattr(runner, "load_runtime_bindings", load_runtime)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_cohort_causal.py",
            "--grid",
            str(grid_path),
            "--cfg-id",
            cfg["cfg_id"],
            "--provenance",
            str(provenance_path),
            "--root",
            str(tmp_path),
        ],
    )

    with pytest.raises(RuntimeLoaded):
        runner.main()

    assert [event[0] for event in events] == ["verify", "load_runtime"]
    verified_root, verified_payload, verified_model_path = events[0][1]
    assert verified_root == tmp_path.resolve()
    assert verified_payload == provenance
    assert verified_model_path == Path(cfg["system_params"]["model_path"])


def test_load_grid_rejects_untracked_self_consistent_config_drift(tmp_path):
    grid = json.loads((REPO_ROOT / "grid_cohort_causal_smoke.json").read_text())
    grid["collectors"][0]["system_params"]["max_new_tokens"] = 1
    path = tmp_path / "unregistered-grid.json"
    path.write_text(json.dumps(grid))

    with pytest.raises(ValueError, match="differs from the preregistered grid"):
        runner.load_grid(path)


def test_seed_everything_requires_prestarted_matching_python_hash_seed(monkeypatch):
    monkeypatch.delenv("PYTHONHASHSEED", raising=False)
    with pytest.raises(RuntimeError, match="must be set before process start"):
        runner.seed_everything(2026071498)
    monkeypatch.setenv("PYTHONHASHSEED", "123")
    with pytest.raises(RuntimeError, match="expected 2026071498"):
        runner.seed_everything(2026071498)
