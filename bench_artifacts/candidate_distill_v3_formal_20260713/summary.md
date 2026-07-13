# Candidate-distillation v3 formal

Status: running after all launch gates passed.

This is the preregistered three-seed active-versus-LR0 Cohort efficacy test for
the explicitly off-policy `candidate_distill_instance` objective. It is not
reported as GRPO or policy gradient.

## Reproducibility contract

- Source commit: `b74bc81f0c4d326f149d5b4d5409b1aa5f9521c0`
- Adapter initialization seed shared by all six cells: `2026071200`
- Proposer seeds: `2026071201`, `2026071202`, `2026071203`
- Task order seed: `42`
- Instances per cell: `20`
- Active learning rate: `1e-4`; paired control learning rate: `0`
- GPUs: A100-40G indices `0,2,3,4,5,6` on `ttt-rl-nescc1`
- GPU1 retained its unrelated legacy process; GPU7 remained spare.

Two independent GPU processes loaded the exact deployed code and model,
installed the adapter, and both produced this initial trainable-parameter hash:

`4e904ce3813b2c0ec0bbd13fcd838b1d6704ef801b1db20d1d4259a84e7e1d7f`

The formal validator additionally requires all six manifests to share one
initial hash, each LR0 hash chain to remain bit-identical, each active final
hash to change, exact paired first trajectories/proposals, and bit-exact LR0
score-relevant outcomes across proposer seeds.

## Validation performed before launch

- Local runnable suite: 653 passed, 12 skipped, 5 subtests passed. The skipped
  collection target imports an upstream `experiments` module absent from this
  checkout; warnings are the existing missing-Docker destructors and LiteLLM
  deprecations.
- Remote registered-grid, CLI typing, trace projection, import, validator, and
  source-checksum contracts passed. The runtime venv has no `pytest`, so the
  full suite was run locally against the exact pushed commit.
- Immutable stage contains 443 Git-tracked files and passed SHA256 plus
  executable-bit verification.

## Remote evidence

- Stage: `/mnt/localssd/ttt-rl-candidate-distill-formal/b74bc81f0c4d326f149d5b4d5409b1aa5f9521c0`
- Stage manifest SHA256: `7d989115b8c6a94072514e14d4d00b5c2dc7f0717f04f0d69e4f96cd24404dd3`
- Delta SHA256: `5cbc8731bc135e799f283147721b11b9df9dd54ccab0aff3d09303d95b6b3bb5`
- Adapter preflight: `/mnt/localssd/ttt-rl-candidate-distill-formal/preflight/b74bc81f0c4d326f149d5b4d5409b1aa5f9521c0/adapter_hash/result.json`
- Formal logs: `/mnt/localssd/ttt-rl-candidate-distill-formal/logs/v3_adapterseed2026071200_b74bc81`
- Launcher PID: `1112998`

## Invalidated launch

The earlier v2 launch did not explicitly control adapter initialization. It was
stopped while all six cells were still in baseline, before treatment and before
any `run_*.json` existed. Its logs and partial baseline directories are retained
only as invalid provenance at:

`/mnt/localssd/ttt-rl-candidate-distill-formal/aborted/unseeded_adapter_init_20260713T001451-0700`

No result from that launch may be used for efficacy analysis.
