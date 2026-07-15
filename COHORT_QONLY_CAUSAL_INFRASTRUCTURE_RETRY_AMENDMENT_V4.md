# Cohort qonly causal infrastructure-retry amendment V4

Status: **prospectively frozen before any `causal-retry-004` setup or model call**

Date: 2026-07-15 America/Los_Angeles

This amendment authorizes one fresh infrastructure retry,
`causal-retry-004/attempt-002`, after `causal-retry-003` failed before a
scientific result existed. It changes only the publication fence for encrypted
logs and the fresh retry identity. It changes no corpus, model, seed, prompt,
candidate policy, update rule, arm, estimand, threshold, grid, or branch rule.

## Retry-003 closure and outcome boundary

The spent retry is source commit
`dd834d040e94cb0da4cf53486954935754787b84`, retry ID
`causal-retry-003`, and compatibility leaf `attempt-002`.

Its smoke collector supervisor exited with infrastructure code `70` before a
collector completion receipt or final ciphertext was published. The smoke gate
does not exist, the formal wrapper was never launched, both formal transport
roots remain absent, and all eight GPUs returned to zero MiB. No response,
reward, score, paired delta, aggregate, confidence interval, gate decision, or
branch-bearing value was opened or observed. The no-overwrite incident record
is:

```text
/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/dd834d040e94cb0da4cf53486954935754787b84/retries/causal-retry-003/attempts/attempt-002/control/CAUSAL_RETRY_003_INFRASTRUCTURE_INVALID.json
sha256:bfbdcc49df74e2fbe24c9999bb7e991ac37913c8c86d341c254180760c9a0f74
```

Retry-003 is infrastructure-invalid, nonpromotable, and nonreusable. Its files
remain append-only evidence and may not be consumed by the new retry.

## Root cause and sole code correction

The encrypted-log publisher uses a same-directory hard link followed by unlink
to obtain no-overwrite publication. On `/sensei-fs`, the published pathname can
temporarily report the pre-unlink link count before converging to one. The V3
publisher sampled immediately and treated that delayed metadata as an identity
attack. A non-scientific transport probe reproduced
`sealed_artifact_identity_invalid` on `/sensei-fs`; the identical probe passed
on `/tmp`, and later `stat` on the published SenseiFS pathname reported a normal
regular file with `nlink=1`.

The only implementation correction is to wait, within the already registered
visibility timeout, for the published pathname to expose a stable regular-file
snapshot. Every accepted snapshot must retain the source temporary file's
device, inode, mode, size, and mtime; known fixed payloads must also retain their
SHA-256. Symlinks, replacement inodes, content changes, timeout, or a final
link count other than one still fail closed. Encryption, private-key absence,
no-overwrite publication, ciphertext hashing, receipt schemas, and terminal
verification remain unchanged.

## Sole authorized retry

The only authorized new run is `causal-retry-004/attempt-002` at a new pushed
source commit containing this amendment, the visibility correction, and its
regression test. Its four roots are:

```text
/mnt/localssd/ttt-rl-cohort-causal/<new-source-commit>/causal-retry-004/attempt-002
/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/<new-source-commit>/retries/causal-retry-004/attempts/attempt-002
/tmp/cohort-causal-formal-retry/<new-source-commit>
/tmp/cohort-causal-terminal-verifier-v2/<new-source-commit>
```

All four exact roots must be absent before setup. The model, corpora, grids,
provenance, tapes, encrypted logs, receipts, controls, and terminal evidence are
generated afresh. There is no relaunch within this tuple. Any later
infrastructure retry would require another prospective, outcome-blind
amendment.

## Unchanged scientific and reveal contract

The smoke gate and three-seed formal grid remain byte-for-byte unchanged. The
active versus LR0 comparison, true-update requirement, `3/3` positive rule,
mean `+0.02` threshold, positive clustered lower 95% bound, schema gates, and
structured-state branch rule are unchanged. Formal efficacy remains hidden
until completion attestation, independent semantic revalidation, and the
conditional execution seal reach the registered V2 reveal boundary.
