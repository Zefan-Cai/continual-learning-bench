# Cohort qonly causal schema-retry amendment V5

Status: **prospectively frozen before any `causal-retry-005` setup or model call**

Date: 2026-07-15 America/Los_Angeles

This amendment authorizes one fresh schema retry,
`causal-retry-005/attempt-002`, after `causal-retry-004/attempt-002` completed
execution but failed its preregistered exact-schema validator. It changes only
the terminal response-metadata key allowlist and the fresh retry identity. It
changes no corpus, model, seed, prompt, candidate policy, update rule, arm,
estimand, threshold, grid, branch rule, or reveal rule.

## Retry-004 closure and outcome boundary

The spent formal run used source commit
`fd9ab294a939350ee5f174acbab0ad279e33ee1e`, retry ID
`causal-retry-004`, and compatibility leaf `attempt-002`. Its outcome-safe
diagnostic, produced under source commit
`a3e887fc73860b1ce4a71476d7e2c6618ad20074`, reported exactly 366 validation
errors: 183 classified as `update_parameter_transition` and 183 classified as
`tape_integrity`. The diagnostic exposed no response, reward, score, paired
delta, aggregate, confidence interval, gate decision, or branch-bearing value.

Source inspection reconstructs the count without reading efficacy-bearing
artifacts. Each of the six cells has 20 terminal response-metadata schema
mismatches. The validator then skips terminal reconstruction, which produces
one missing 20-action-hash error, 20 missing independently scored terminal
errors, and 20 bound-trace mismatch errors: 61 errors per cell and 366 total.
The active/LR0 183/183 category split is a diagnostic label-classification
artifact: every pair ID contains `frozen_tape`, while the LR0 label additionally
contains `lr0`. It is not evidence that active replay failed to update weights.

Retry-004 is invalid, nonpromotable, and nonreusable. All of its files remain
append-only audit evidence and may not be copied, linked, referenced as an input,
or otherwise consumed by the new retry.

## Root cause and sole code correction

Production commit `bd9bb0a2030b5b29699320f12d98517b790ab27c` added eight
unconditional Qwen response-metadata fields:

```text
prompt_tokens_before_hard_cap
prompt_token_budget
prompt_hard_truncated
generation_calls
generation_input_tokens_total
generation_output_tokens_total
generation_prompt_hard_truncations
icl_context_sealed_eval
```

The Qwen response therefore contains 40 unconditional literal metadata keys,
and the runtime runner adds `usage`, for an exact production total of 41. The
formal validator retained the preceding 33-key contract and rejected all 20
terminal records in every cell before independent reconstruction.

The sole scientific-pipeline correction authorized by this amendment is to add
exactly those eight keys to `_TERMINAL_RESPONSE_METADATA_KEYS` in
`validate_cohort_causal_results.py`. No existing key is removed, renamed, or
made optional. A source-level regression test independently extracts the 40
literal production keys, adds the runner-owned `usage` key, and requires exact
equality with a literal 41-key fixture and the validator set, with no missing or
extra keys. The producer, runner, collector, replay implementation, scoring,
statistics, and all scientific parameters remain unchanged.

## Sole authorized retry

The only authorized new run is `causal-retry-005/attempt-002` at one new pushed
source commit containing this amendment, the eight-key validator correction,
the fresh wrapper identity, the provenance binding, and the regression tests.
That commit must have
`a3e887fc73860b1ce4a71476d7e2c6618ad20074` as its sole direct parent, and
the parent-to-source diff must contain exactly these seven paths:

```text
COHORT_QONLY_CAUSAL_SCHEMA_RETRY_AMENDMENT_V5.md
build_cohort_causal_provenance.py
run_cohort_causal_formal_registered.py
tests/test_cohort_causal_provenance.py
tests/test_cohort_causal_registered_formal_wrapper.py
tests/test_cohort_causal_results.py
validate_cohort_causal_results.py
```

Any merge commit, intermediate commit, missing path, renamed path, or additional
path is outside this authorization. The authorized commit's four roots are:

```text
/mnt/localssd/ttt-rl-cohort-causal/<new-source-commit>/causal-retry-005/attempt-002
/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/<new-source-commit>/retries/causal-retry-005/attempts/attempt-002
/tmp/cohort-causal-formal-retry/<new-source-commit>
/tmp/cohort-causal-terminal-verifier-v2/<new-source-commit>
```

All four exact roots must be absent before setup. The model, corpora, grids,
provenance, tapes, encrypted logs, receipts, controls, and terminal evidence are
generated afresh. There is no relaunch within this tuple. Any later retry
requires another prospective, outcome-blind amendment.

## Unchanged scientific and reveal contract

The smoke gate and three-seed formal grid remain byte-for-byte unchanged. The
active versus LR0 comparison, true-update requirement, `3/3` positive rule,
mean `+0.02` threshold, positive clustered lower 95% bound, schema gates, and
structured-state branch rule are unchanged. Formal efficacy remains hidden
until completion attestation, independent semantic revalidation, and the
conditional execution seal reach the registered V2 reveal boundary.
