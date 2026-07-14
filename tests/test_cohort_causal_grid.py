from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

import generate_cohort_causal_grid as grid


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("smoke,collectors,cells", [(True, 1, 2), (False, 3, 6)])
def test_grid_contract(smoke: bool, collectors: int, cells: int) -> None:
    payload = grid.make_grid(smoke=smoke)
    assert payload["mechanism_label"] == (
        "frozen-tape weight-update ablation; not exact historical replication"
    )
    assert len(payload["collectors"]) == collectors
    assert len(payload["evaluation_cells"]) == cells
    assert payload["datasets"]["adaptation"]["corpus_sha256"] != (
        payload["datasets"]["heldout"]["corpus_sha256"]
    )


def test_formal_pairs_differ_only_in_learning_rates() -> None:
    payload = grid.make_grid(smoke=False)
    for seed in grid.FORMAL_SEEDS:
        pair = [
            cell for cell in payload["evaluation_cells"] if cell["run_seed"] == seed
        ]
        active = next(cell for cell in pair if cell["arm"] == "active")
        lr0 = next(cell for cell in pair if cell["arm"] == "lr0")
        active_params = copy.deepcopy(active["system_params"])
        lr0_params = copy.deepcopy(lr0["system_params"])
        assert active_params.pop("ttt_lr") == active_params.pop("reward_pg_lr") == 5e-4
        assert lr0_params.pop("ttt_lr") == lr0_params.pop("reward_pg_lr") == 0.0
        assert active_params == lr0_params
        assert active["tape_path"] == lr0["tape_path"]
        assert active["task_params"] == lr0["task_params"]


def test_validator_rejects_non_lr_drift() -> None:
    payload = grid.make_grid(smoke=False)
    payload["evaluation_cells"][0]["system_params"]["best_of_n"] = 7
    with pytest.raises(ValueError, match="config"):
        grid.validate(payload, smoke=False)


def test_registered_grids_are_current() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "generate_cohort_causal_grid.py"), "--check"],
        cwd=ROOT,
        check=True,
    )


def test_registered_formal_json_has_three_pairs() -> None:
    payload = json.loads((ROOT / "grid_cohort_causal_formal.json").read_text())
    assert {cell["run_seed"] for cell in payload["evaluation_cells"]} == set(
        grid.FORMAL_SEEDS
    )
    assert {cell["arm"] for cell in payload["evaluation_cells"]} == {
        "active",
        "lr0",
    }
