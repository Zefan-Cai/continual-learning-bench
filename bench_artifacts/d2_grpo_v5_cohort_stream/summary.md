# D2 v5 cohort stream probe

Hypothesis: an exact-prompt, group-normalized policy-gradient update can produce a reproducible cohort improvement over a matched full-history frozen stream.

Naive baseline: the same model, task order, task seed, run seed, context policy, and primary generations with parameter updates fail-closed for the entire rollout.

Promotion gates:

- Sampling and training prompt hashes match for every updated group.
- Candidate advantages are aggregated into one optimizer step per group.
- Frozen-stream runs execute zero optimizer steps and zero norm clipping.
- Run and candidate seeds are deterministic from configuration and instance identity.
- Five-instance smoke completes with full denominator accounting, finite telemetry, no legacy update path, and effective group size at least two.
- Formal promotion requires at least five active trajectories and matched frozen controls; the primary paired mean reward delta must exceed 0.03 without a seed-level sign reversal pattern.

Kill conditions: prompt mismatch, non-deterministic seeds, frozen parameter drift, invalid outcomes, repeated effective group size one, non-finite loss, OOM, or timeout.

CPU gate (2026-07-12): passed. Changed files are ruff-clean; 80 targeted runtime tests, 109 changed-task tests, and 577 broader tests passed. Twelve optional tests skipped. One unrelated test module was excluded because the upstream checkout does not contain its `experiments/` package. The gate also exposed and fixed the baseline sliced-worker phantom-backfill bug.
