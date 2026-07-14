# Frozen held-out Cohort Studies corpora

`build_frozen_dataset.py` turns an explicit DGP seed and Cohort Studies
schedule into a deterministic 20-instance frozen corpus. It exists for
confirmatory experiments that must evaluate on patient draws not used during
method selection.

```bash
python experiments/cohort_studies/build_frozen_dataset.py \
  --seed 20260713 \
  --schedule-id default \
  --output /path/to/cohort-heldout-seed20260713
```

The builder doubles each study's configured target sample size, performs the
existing order-independent biased study sampling, sorts selected patient IDs
within each scheduled region, and divides them into first (`s1`) and second
(`s2`) halves. For seed 42 this reproduces the patient membership, population
ground truth, per-instance Kaplan-Meier references, and cohort definitions of
the checked-in `data/cohort_studies/default` corpus. Stochastic coding
transforms and distractors receive a separate order-independent database seed
derived from `(seed, schedule_id, variant_id)`.

Every output includes:

- `dbs/*.db`: 20 frozen SQLite instances;
- `metadata.json`, `ground_truth.json`, `instance_references.json`, and
  `cohort_definitions.json`, in the format consumed by `CohortStudiesTask`;
- `manifest.json`: source hashes, per-instance DB and patient-membership
  hashes, derived DB seeds, an artifact table, and a corpus SHA-256.

The build contains no timestamps or output-path fields, so two builds from the
same source revision and software stack are byte-identical. SQLite file bytes
can depend on the SQLite implementation; archive the manifest and runtime
lockfile with publication artifacts.

## Confirmatory-use contract

Choose and record the held-out seed before building or inspecting its scores.
Do not tune on the held-out corpus. Numeric `patient_id` values are local to a
generated population and can coincide across seeds; the corpus SHA-256 is the
identity namespace. Train and held-out datasets count as distinct only when
their manifest `corpus_sha256` values differ. Archive both manifests alongside
the preregistration, config grid, run outputs, and paired statistical report.

The causal-gate preregistration has dedicated task schedule IDs. Build them
with their frozen seeds so `metadata.schedule_id` and the task's requested
schedule agree:

```bash
python experiments/cohort_studies/build_frozen_dataset.py \
  --seed 2026071411 --schedule-id causal_adapt_2026071411 \
  --output /path/to/cohort-causal-adapt-2026071411
python experiments/cohort_studies/build_frozen_dataset.py \
  --seed 2026071412 --schedule-id causal_eval_2026071412 \
  --output /path/to/cohort-causal-eval-2026071412
```

Use an explicit task dataset path while keeping the schedule fixed:

```json
{
  "task": {
    "name": "cohort_studies",
    "params": {
      "schedule": "default",
      "dataset_path": "/path/to/cohort-heldout-seed20260713"
    }
  }
}
```

Pass `--force` only when intentionally replacing an existing output. The new
corpus is fully built before the old directory is swapped out.
