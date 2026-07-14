from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from assemble_cohort_causal_manifest import _verify_tape, assemble_manifest
from run_cohort_causal import _collector_manifest_path, _trace_paths
from validate_cohort_causal_results import (
    EXPECTED_STATISTICAL_ADDENDUM_SHA256,
    STATISTICAL_ADDENDUM_FILENAME,
    canonical_sha256,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def _tape(seed: int) -> dict:
    item = {
        "sequence_index": 0,
        "instance_id": f"cohort_studies:adapt:{seed}",
        "instance_index": 0,
    }
    item["item_sha256"] = canonical_sha256(item)
    tape = {"items": [item]}
    tape["tape_sha256"] = canonical_sha256(tape)
    return tape


def test_verify_tape_rejects_item_mutation():
    tape = _tape(1)
    assert _verify_tape(tape)["digest_verified"] is True
    tape["items"][0]["instance_index"] = 9
    try:
        _verify_tape(tape)
    except ValueError as exc:
        assert "root digest" in str(exc) or "item digest" in str(exc)
    else:
        raise AssertionError("mutated tape unexpectedly verified")


def test_assemble_formal_manifest_splits_label_and_binds_all_cells(tmp_path):
    grid = json.loads((REPO_ROOT / "grid_cohort_causal_formal.json").read_text())
    for role in ("adaptation", "heldout"):
        grid["datasets"][role]["path"] = str(
            REPO_ROOT / grid["datasets"][role]["path"]
        )
    schedule_dir = tmp_path / "src/tasks/cohort_studies/schedules"
    schedule_dir.mkdir(parents=True)
    for role in ("adaptation", "heldout"):
        schedule = grid["datasets"][role]["schedule"]
        shutil.copyfile(
            REPO_ROOT / f"src/tasks/cohort_studies/schedules/{schedule}.json",
            schedule_dir / f"{schedule}.json",
        )
    provenance = {
        "source_commit": "1" * 40,
        "preregistered_parent_commit": "2" * 40,
        "environment_lock_sha256": "3" * 64,
        "model_sha256": "4" * 64,
        "tokenizer_sha256": "5" * 64,
        "evaluation_code_sha256": "6" * 64,
        "statistical_addendum_sha256": EXPECTED_STATISTICAL_ADDENDUM_SHA256,
        "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
        "adapter_init_seed": grid["adapter_init_seed"],
    }
    cells = {
        (row["run_seed"], row["arm"]): row for row in grid["evaluation_cells"]
    }
    for collector in grid["collectors"]:
        seed = collector["run_seed"]
        tape = _tape(seed)
        verification = _verify_tape(tape)
        _write_json(tmp_path / collector["tape_path"], tape)
        _write_json(
            _collector_manifest_path(tmp_path, collector),
            {
                "status": "completed",
                "run_seed": seed,
                "trainable_param_sha256_initial": "a" * 64,
                "trainable_param_sha256_final": "a" * 64,
                "tape_sha256": tape["tape_sha256"],
                "tape_verification": verification,
                "provenance": provenance,
            },
        )
        for arm in ("active", "lr0"):
            cfg = cells[(seed, arm)]
            trace_path, _ = _trace_paths(tmp_path, cfg)
            trace = {
                "phase": "baseline",
                "status": "completed",
                "instance_outcomes": [],
                "interactions": [],
                "result": {"instance_outcomes": [], "score": 0.0},
            }
            _write_json(trace_path, trace)
            _write_json(
                tmp_path / cfg["cell_manifest_path"],
                {
                    "status": "completed",
                    "arm": arm,
                    "tape_sha256": tape["tape_sha256"],
                    "provenance": provenance,
                    "trace_path": str(trace_path),
                    "trace_sha256": canonical_sha256(trace),
                },
            )
    preregistration = tmp_path / "COHORT_QONLY_CAUSAL_PREREG.md"
    shutil.copyfile(REPO_ROOT / preregistration.name, preregistration)
    statistical_addendum = tmp_path / STATISTICAL_ADDENDUM_FILENAME
    shutil.copyfile(REPO_ROOT / statistical_addendum.name, statistical_addendum)

    manifest = assemble_manifest(
        root=tmp_path,
        grid=grid,
        provenance=provenance,
        preregistration_path=preregistration,
    )

    assert manifest["mechanism_label"] == "frozen-tape weight-update ablation"
    assert manifest["limitation"] == "not exact historical replication"
    assert (
        manifest["statistical_addendum_sha256"]
        == EXPECTED_STATISTICAL_ADDENDUM_SHA256
    )
    assert len(manifest["pairs"]) == 3
    assert manifest["corpora"]["adaptation"]["canonical_instance_ids"] != manifest[
        "corpora"
    ]["heldout"]["canonical_instance_ids"]
    assert all(set(pair) >= {"tape", "active", "lr0"} for pair in manifest["pairs"])
    assert all(
        "heldout_trace" in pair[arm]
        for pair in manifest["pairs"]
        for arm in ("active", "lr0")
    )

    first_collector = grid["collectors"][0]
    collector_path = _collector_manifest_path(tmp_path, first_collector)
    bad_collector = json.loads(collector_path.read_text())
    bad_collector["provenance"] = {**provenance, "model_sha256": "9" * 64}
    _write_json(collector_path, bad_collector)
    with pytest.raises(ValueError, match="collector provenance mismatch"):
        assemble_manifest(
            root=tmp_path,
            grid=grid,
            provenance=provenance,
            preregistration_path=preregistration,
        )

    bad_collector["provenance"] = provenance
    _write_json(collector_path, bad_collector)
    first_active = cells[(first_collector["run_seed"], "active")]
    trace_path, _ = _trace_paths(tmp_path, first_active)
    trace = json.loads(trace_path.read_text())
    trace["status"] = "tampered-after-cell-publication"
    _write_json(trace_path, trace)
    with pytest.raises(ValueError, match="trace SHA-256 mismatch during assembly"):
        assemble_manifest(
            root=tmp_path,
            grid=grid,
            provenance=provenance,
            preregistration_path=preregistration,
        )

    trace["status"] = "completed"
    _write_json(trace_path, trace)
    alternate_preregistration = tmp_path / "alternate-prereg.md"
    alternate_preregistration.write_bytes(preregistration.read_bytes())
    with pytest.raises(ValueError, match="path is not the checked-in"):
        assemble_manifest(
            root=tmp_path,
            grid=grid,
            provenance=provenance,
            preregistration_path=alternate_preregistration,
        )

    alternate_addendum = tmp_path / "alternate-addendum.md"
    alternate_addendum.write_bytes(statistical_addendum.read_bytes())
    with pytest.raises(ValueError, match="addendum path is not the checked-in"):
        assemble_manifest(
            root=tmp_path,
            grid=grid,
            provenance=provenance,
            preregistration_path=preregistration,
            statistical_addendum_path=alternate_addendum,
        )
