# Corrected D2 group-PG wave (draft only)

This document describes a non-deployed draft for the corrected TTT-RL D2
experiment. It does not modify `system.py`, the living runbook, S3, or Pluto
jobs.

## Registered experiment

The formal grid contains exactly 10 independent cfg IDs:

- `cohort/full/K8 active` x 5 seeds
- matched `cohort/full frozen_stream` x 2 seeds
- `cohort/qonly/K8 active` x 3 seeds

All arms use the same task order: `task_params.seed=42` and
`task_params.run_index=1`. Only the algorithm sampling trajectory changes via
`grpo_run_seed=2026071201..2026071205`; the first two sampling seeds also have
matched frozen controls. This separation is necessary because two frozen
controls can cover five active sampling trajectories only when the environment
stream itself is fixed. `task_params.run_index=1` and
`run_mode=replicate` are both required: CLBench's normal single-cell
`--run-mode permute` rewrites the task run index to zero, and CohortStudiesTask
treats `prepare_run(0)` as a no-op. The corrected combination gives one stable
within-stage permutation for every arm.

Canonical new system inputs expected from the method patch:

- `reward_update_rule="group_pg_instance"`
- `grpo_run_seed=<int>`
- `freeze_parameter_updates=<bool>`

`grpo_objective="group_normalized_policy_gradient"` is output telemetry, not a
system input. The legacy `grpo_instance` spelling and `grpo_frozen_stream`
field are compatibility aliases only and are deliberately absent from the new
grid.

## Draft files

- `generate_group_pg_grids.py`: deterministic grid source and invariants.
- `grid_group_pg_smoke.json`: 2 matched five-instance smoke cells.
- `grid_group_pg_formal.json`: the registered 10-cell wave.
- `prepare_group_pg_assignments.py`: emits separate system/task JSON files and
  carries `run_mode` into each worker assignment.
- `validate_group_pg_manifest.py`: fail-closed active/frozen manifest gate.
- `validate_group_pg_pairing.py`: cross-arm order check and bit-exact frozen
  control check.
- `main_group_pg_worker_draft.sh`: worker integration draft. It intentionally
  contains no Pluto create/start/deploy operation.

Generate/check:

```bash
python3 generate_group_pg_grids.py --check
python3 generate_group_pg_grids.py
python3 prepare_group_pg_assignments.py \
  grid_group_pg_formal.json /tmp/gpg-assign --release-stage 1
```

## Release and stop gates

1. **Code gate:** default-off/legacy regression tests, exact sampled-prompt
   digest, one group-mean optimizer step, deterministic seed derivation, and
   frozen-stream tests must pass before GPU work. Deployment checksum/marker
   must replace the stale GRPO-v4 hashes in the old mains; this draft does not
   guess those hashes.
2. **Five-instance smoke gate:** run the two matched smoke cells with
   `TTT_RL_STRICT_SMOKE=1`. The active cell must complete 5 real outcomes,
   perform 5 group updates and 5 optimizer steps, have no low-std/no-group
   skips, record finite loss, group size >=2, sampling seed, prompt digest, and
   nonzero retained prompt tokens, and show zero legacy-path updates. The
   frozen cell must complete the same ordered five outcomes with
   `parameter_updates_enabled=false`, zero candidate groups, zero
   optimizer/update/skip counts, and zero legacy activity.
3. **Formal stage 1:** release only seed `2026071201` across full-active,
   full-frozen and qonly-active (`TTT_RL_RELEASE_STAGE=1`). This is an
   operational validity gate, not an optional performance peek. Do not release
   stage 2 if instance IDs/order differ across paired arms, any failed/phantom
   outcome appears, active update accounting is incomplete, frozen performs an
   update, a non-finite value appears, or terminal candidate generation exceeds
   the bounded timeout.
4. **Formal stage 2:** after stage 1 passes, release the remaining seven cfgs
   (`TTT_RL_RELEASE_STAGE=2`). Preserve the pre-registered 5/2/3 arm counts
   regardless of the seed-1 reward direction to avoid optional stopping.
5. **Canonical artifact gate:** upload partial evidence only under
   `${PREFIX}_partial`; upload the canonical manifest last and only after the
   strict validator passes. S3 paths remain
   `results_probe/cohort_studies/live/<unique_cfg_id>/...` unless the parent
   launcher intentionally chooses a narrower prefix.
6. **Cross-arm gate:** after all 10 cells land, run
   `validate_group_pg_pairing.py --require-formal-counts` on the manifests.
   Every arm must have the same instance-id order and the two frozen controls
   must have bit-exact scores and `instance_outcomes`.

## Launcher compatibility findings

- Existing `main_grpo_{a,b}.sh` ignores every grid `task_params` object and
  hardcodes `{"schedule":"default"}`. It therefore cannot run the registered
  smoke/order design unchanged.
- Existing separate `_r1/_r2/_r3` cells all use `runs=1`; the benchmark injects
  outer run index zero, so their task order is identical. Candidate seeds are
  not reproducible because deployed D2 currently commits `os.urandom(8)`.
- Existing manifest validation rejects frozen controls because it always
  requires `parameter_updates_enabled=true` and a non-empty GRPO log. The new
  validator branches on the manifest's own `freeze_parameter_updates` value.
- `CohortStudiesTask` accepts `schedule`, `num_instances`, `seed`, and a derived
  `run_index`; a five-instance smoke needs no new schedule file.
- The formal grid uses unique `gpgfix_*` cfg IDs, so it cannot be skipped by or
  overwrite the completed `grpoinst_*` D2 artifacts.
- The two full frozen controls differ only in the unused `grpo_run_seed`; their
  `result.instance_outcomes` must be bit-exact. A mismatch invalidates the
  frozen control or exposes nondeterminism and blocks the claim.
- Cohort terminal outputs are roughly 2642 tokens; the new grids set
  `ttt_max_tokens=4096`, not the old 1024, and the gate requires telemetry that
  proves some prompt tokens survived truncation.

## Intended Pluto shape after validation

Use one-pod A100-40G jobs (`--xpus-per-pod 8 --num-pods 1`). Check live
capacity immediately before submission; prefer P1
`--quota-charged-reclaimable --enable-autorecovery` without `--auto-requeue`,
then fall back to P2 `--quota-free --auto-requeue --enable-autorecovery`.
No job has been submitted from this draft.
