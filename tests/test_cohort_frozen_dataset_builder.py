from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from experiments.cohort_studies.build_frozen_dataset import build_frozen_dataset
from src.tasks.cohort_studies.frozen_db import load_metadata, sha256_file


@pytest.fixture(scope="module")
def frozen_corpora(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    root = tmp_path_factory.mktemp("cohort-frozen-corpora")
    first = root / "seed-42-a"
    repeat = root / "seed-42-b"
    held_out = root / "seed-20260713"
    build_frozen_dataset(first, seed=42, schedule_id="default")
    build_frozen_dataset(repeat, seed=42, schedule_id="default")
    build_frozen_dataset(held_out, seed=20260713, schedule_id="default")
    return first, repeat, held_out


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _manifest(root: Path) -> dict[str, object]:
    return json.loads((root / "manifest.json").read_text())


def _patient_ids(db_path: Path) -> list[int]:
    with sqlite3.connect(db_path) as conn:
        return [int(row[0]) for row in conn.execute("SELECT patient_id FROM patients")]


def _assert_task_loads(dataset: Path, schedule_id: str) -> None:
    # Keep dependency shims isolated from the pytest process. They are needed
    # only in minimal developer environments that omit the task/runtime extras;
    # CohortStudiesTask construction does not execute either shimmed API.
    script = r"""
import importlib.util
import sys
import types

if importlib.util.find_spec("litellm") is None:
    litellm = types.ModuleType("litellm")
    litellm.model_cost = {}
    sys.modules["litellm"] = litellm
if importlib.util.find_spec("lifelines") is None:
    lifelines = types.ModuleType("lifelines")
    lifelines.KaplanMeierFitter = type("KaplanMeierFitter", (), {})
    sys.modules["lifelines"] = lifelines

from src.tasks.cohort_studies.task import CohortStudiesTask

task = CohortStudiesTask(
    dataset_path=sys.argv[1], schedule=sys.argv[2], num_instances=20
)
print(task.schedule_id, len(task.instances), task.instances[0].variant_id)
"""
    proc = subprocess.run(
        [sys.executable, "-c", script, str(dataset), schedule_id],
        check=True,
        text=True,
        capture_output=True,
    )
    assert proc.stdout.strip() == f"{schedule_id} 20 herald_suburban"


def test_same_seed_is_byte_identical(
    frozen_corpora: tuple[Path, Path, Path],
) -> None:
    first, repeat, _ = frozen_corpora
    assert _files(first) == _files(repeat)
    assert _manifest(first)["corpus_sha256"] == _manifest(repeat)["corpus_sha256"]


def test_seed_42_reproduces_default_patient_splits(
    frozen_corpora: tuple[Path, Path, Path],
) -> None:
    generated, _, _ = frozen_corpora
    checked_in = Path("data/cohort_studies/default")
    metadata = load_metadata(generated)

    assert metadata.n_instances == 20
    for instance in metadata.instances:
        generated_ids = _patient_ids(generated / "dbs" / instance.db_filename)
        checked_in_ids = _patient_ids(checked_in / "dbs" / instance.db_filename)
        assert generated_ids == checked_in_ids, instance.variant_id

    for filename in (
        "ground_truth.json",
        "instance_references.json",
        "cohort_definitions.json",
    ):
        assert json.loads((generated / filename).read_text()) == json.loads(
            (checked_in / filename).read_text()
        )


def test_different_seeds_define_distinct_corpus_namespaces(
    frozen_corpora: tuple[Path, Path, Path],
) -> None:
    train, _, held_out = frozen_corpora
    train_manifest = _manifest(train)
    held_out_manifest = _manifest(held_out)

    assert train_manifest["corpus_sha256"] != held_out_manifest["corpus_sha256"]

    train_instances = {item["variant_id"]: item for item in train_manifest["instances"]}
    held_out_instances = {
        item["variant_id"]: item for item in held_out_manifest["instances"]
    }
    assert train_instances.keys() == held_out_instances.keys()
    assert all(
        train_instances[key]["patient_ids_sha256"]
        != held_out_instances[key]["patient_ids_sha256"]
        for key in train_instances
    )
    assert all(
        train_instances[key]["db_sha256"] != held_out_instances[key]["db_sha256"]
        for key in train_instances
    )


def test_s1_s2_patient_draws_are_disjoint(
    frozen_corpora: tuple[Path, Path, Path],
) -> None:
    dataset, _, _ = frozen_corpora
    metadata = load_metadata(dataset)
    by_variant = {instance.variant_id: instance for instance in metadata.instances}

    for variant_id, second in by_variant.items():
        if not variant_id.endswith("_s2"):
            continue
        first = by_variant[variant_id.removesuffix("_s2")]
        first_ids = set(_patient_ids(dataset / "dbs" / first.db_filename))
        second_ids = set(_patient_ids(dataset / "dbs" / second.db_filename))
        assert first_ids.isdisjoint(second_ids), variant_id


def test_metadata_manifest_and_databases_are_loadable(
    frozen_corpora: tuple[Path, Path, Path],
) -> None:
    dataset, _, _ = frozen_corpora
    metadata = load_metadata(dataset)
    manifest = _manifest(dataset)

    assert metadata.schedule_id == "default"
    assert metadata.seed == 42
    assert metadata.n_instances == len(metadata.instances) == 20
    assert manifest["n_instances"] == 20

    artifact_hashes = {item["path"]: item["sha256"] for item in manifest["artifacts"]}
    for instance in metadata.instances:
        db_path = dataset / "dbs" / instance.db_filename
        assert sha256_file(db_path) == instance.db_sha256
        assert artifact_hashes[f"dbs/{instance.db_filename}"] == instance.db_sha256
        with sqlite3.connect(db_path) as conn:
            assert conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == (
                instance.n_patients
            )

    # Recompute the documented corpus digest from the artifact table.
    canonical_artifacts = json.dumps(
        manifest["artifacts"], sort_keys=True, separators=(",", ":")
    ).encode()
    assert hashlib.sha256(canonical_artifacts).hexdigest() == manifest["corpus_sha256"]


def test_task_loads_generated_dataset(
    frozen_corpora: tuple[Path, Path, Path],
) -> None:
    dataset, _, _ = frozen_corpora
    _assert_task_loads(dataset, "default")


@pytest.mark.parametrize(
    ("schedule_id", "seed"),
    [
        ("causal_adapt_2026071411", 2026071411),
        ("causal_eval_2026071412", 2026071412),
    ],
)
def test_preregistered_schedule_ids_build_matching_metadata(
    tmp_path: Path, schedule_id: str, seed: int
) -> None:
    output = tmp_path / schedule_id
    manifest = build_frozen_dataset(output, seed=seed, schedule_id=schedule_id)
    metadata = load_metadata(output)
    schedule_path = Path("src/tasks/cohort_studies/schedules") / f"{schedule_id}.json"

    assert metadata.schedule_id == schedule_id
    assert metadata.seed == seed
    assert metadata.n_instances == 20
    assert manifest["schedule_sha256"] == sha256_file(schedule_path)
    assert manifest["corpus_sha256"]
    _assert_task_loads(output, schedule_id)


def test_preregistered_schedule_rejects_wrong_seed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="declares DGP seed"):
        build_frozen_dataset(
            tmp_path / "wrong-seed",
            seed=2026071412,
            schedule_id="causal_adapt_2026071411",
        )
