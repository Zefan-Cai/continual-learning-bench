from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_frozen_corpus_identity_is_qualified_without_changing_db_loading() -> None:
    """Exercise the real task in an isolated optional-dependency shim process."""

    script = r'''
import importlib.util
import json
import sys
import types
from pathlib import Path

if importlib.util.find_spec("litellm") is None:
    litellm = types.ModuleType("litellm")
    litellm.model_cost = {}
    sys.modules["litellm"] = litellm
if importlib.util.find_spec("lifelines") is None:
    lifelines = types.ModuleType("lifelines")
    lifelines.KaplanMeierFitter = type("KaplanMeierFitter", (), {})
    sys.modules["lifelines"] = lifelines

from src.tasks.cohort_studies.frozen_db import load_instance_db
from src.tasks.cohort_studies.scorer import CohortScoreResult
from src.tasks.cohort_studies.task import CohortStudiesTask, cohort_instance_id

root = Path(sys.argv[1])
schedules = (
    "default",
    "causal_adapt_2026071411",
    "causal_eval_2026071412",
)
ids_by_schedule = {}

for schedule_id in schedules:
    dataset_dir = root / "data" / "cohort_studies" / schedule_id
    task = CohortStudiesTask(
        dataset_path=str(dataset_dir),
        schedule=schedule_id,
        num_instances=20,
    )
    metadata = json.loads((dataset_dir / "metadata.json").read_text())
    variants = [item["variant_id"] for item in metadata["instances"]]
    ids = [task._instance_id(instance) for instance in task.instances]
    expected = [cohort_instance_id(schedule_id, variant) for variant in variants]

    assert len(task.instances) == len(ids) == len(set(ids)) == 20
    assert ids == expected
    assert [instance.variant_id for instance in task.instances] == variants

    # Opening every frozen DB verifies identity qualification has no bearing on
    # dataset resolution or canonical database ordering.
    loaded_studies = []
    for instance in task.instances:
        connection = load_instance_db(instance.db_path)
        loaded_studies.append(
            connection.execute(
                "SELECT value FROM _study_info WHERE key = 'study_label'"
            ).fetchone()[0]
        )
        connection.close()
    assert len(loaded_studies) == 20

    # Every task-produced identity path uses the same helper, including the
    # terminal extraction query used after budget/error recovery.
    first_query = task.build_current_query()
    assert first_query.instance_id == ids[0]
    assert first_query.metadata["schedule_id"] == schedule_id
    assert task._step_query().instance_id == ids[0]
    extraction = task._transition_to_submission_extraction("recover")
    assert extraction.next_query is not None
    assert extraction.next_query.instance_id == ids[0]
    assert extraction.next_query.metadata["schedule_id"] == schedule_id
    outcome = task._record_outcome(
        task.instances[0],
        CohortScoreResult(
            score=0.0,
            mean_kl_divergence=0.0,
            mean_reference_kl=0.0,
            n_cohorts_total=36,
            n_cohorts_estimated=0,
            n_cohorts_missing=36,
        ),
    )
    assert outcome.instance_id == ids[0]
    assert outcome.metadata["schedule_id"] == schedule_id
    if task._executor is not None:
        task._executor.conn.close()

    ids_by_schedule[schedule_id] = ids

default_ids = ids_by_schedule["default"]
adapt_ids = ids_by_schedule["causal_adapt_2026071411"]
eval_ids = ids_by_schedule["causal_eval_2026071412"]
assert default_ids[0] == "cohort_studies:herald_suburban"
assert all(identifier.count(":") == 1 for identifier in default_ids)
assert all(
    identifier.startswith("cohort_studies:causal_adapt_2026071411:")
    for identifier in adapt_ids
)
assert all(
    identifier.startswith("cohort_studies:causal_eval_2026071412:")
    for identifier in eval_ids
)
assert all(adapt != heldout for adapt, heldout in zip(adapt_ids, eval_ids))
print("cohort corpus identity contract: 3 schedules x 20 DBs passed")
'''

    completed = subprocess.run(
        [sys.executable, "-c", script, str(REPO_ROOT)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == (
        "cohort corpus identity contract: 3 schedules x 20 DBs passed"
    )
