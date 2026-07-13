# Candidate-distillation v2 LR0 gate

- Probe: `gpgfix_cohort_full_candidate_distill_v2_lr0_seed2026071299_n5`
- Source commit: `bcce5d4ae0fefa5492155bab7e17aca0bae4bbd6`
- Runtime: existing `ttt-rl-nescc1`, GPU0, A100-40G
- Decision: **pass**
- Validator: `GROUP_PG_MANIFEST_OK`
- Outcomes: 5/5 real instances, status `completed`
- Candidate groups: 5/5 with `valid_unique=8`, `group_size=8`
- Reward standard deviations: `0.013294`, `0.012761`, `0.015576`, `0.012547`, `0.011299`
- Updates: `5`; optimizer steps: `5`; `no_group=0`; `low_std=0`
- Proposal accounting per instance: 7 structured attempts, 0 model generations, 0 duplicates, 0 generation failures, 0 parse failures
- Objective label: `group_normalized_candidate_distillation`
- LR0 weight integrity: initial/current and every before/after SHA256 are identical (`0900b411...effe9ff`)
- Result score: `-0.0288508` (not an efficacy result; this gate only establishes diversity, execution, and frozen-weight integrity)
- `run_1.json` SHA256: `eb770eabdc866e427236bba91da00da61d35d1f5edf3e9d302670d164ef26d48`
- `summary.json` SHA256: `729f6711a13d9840fe028478b4b00d9578b8d75db2a6663391123e41f10d55ab`

The gate justifies the preregistered six-cell formal mini-grid: three proposal seeds, each paired between active candidate distillation (`reward_pg_lr=1e-4`) and the same execution path at LR0. It does not justify calling the method GRPO or policy gradient.
