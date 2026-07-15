# Cohort qonly causal infrastructure-retry amendment V2

Status: **prospectively frozen before any `causal-retry-002` command or
outcome reveal**

Date: 2026-07-14 America/Los_Angeles

This amendment authorizes one final, wholly fresh infrastructure retry of the
preregistered Cohort qonly frozen-tape causal gate. It changes no corpus, seed,
model, prompt, candidate policy, update rule, estimand, threshold, or branch
rule. Its only implementation changes are a bounded, outcome-blind
filesystem-visibility fence around newly published attempt artifacts and
mechanical suppression of formal decision content from the wrapper log.

## `causal-retry-001` incident and knowledge boundary

The spent retry is identified by the complete tuple

```text
source commit:
  059b26b45180b5a295c4c1b36a180cb2a91d5405
scientific run name:
  causal-retry-001
absolute checkout root:
  /mnt/localssd/ttt-rl-cohort-causal/059b26b45180b5a295c4c1b36a180cb2a91d5405/causal-retry-001/attempt-002
absolute durable root:
  /sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/059b26b45180b5a295c4c1b36a180cb2a91d5405/retries/causal-retry-001/attempts/attempt-002
verifier-compatible leaf:
  attempt-002
```

Its fresh smoke collector and paired active/LR0 replay completed, and the blind
smoke validator published a passing smoke gate. The registered formal wrapper
then published its PID file and launch expectation. Before it could publish
`CAUSAL_FORMAL_REGISTERED_READY_V1.json`, its immediate stable read of the
newly linked SenseiFS launch expectation observed the file as not yet being a
nonempty single-link regular file and failed closed. The same file subsequently
became visible as a nonempty single-link regular file without any operator
rewrite. This is the fixed incident class
`retry_001_pre_ready_senseifs_visibility_failure`.

The wrapper process exited. No READY document, formal-start authorization,
formal launcher, formal collector, formal replay cell, formal manifest, formal
decision, or formal exit marker was created. No formal model output, reward,
score, paired delta, confidence interval, or branch decision existed or was
interpreted. The retry decision uses only the outcome-independent wrapper log,
PID/expectation metadata, file metadata, and the absence of READY,
authorization, and formal targets.

## Permanent closure of `causal-retry-001`

The fully qualified `causal-retry-001` tuple above is infrastructure-invalid
and non-promotable. Its checkout, provenance, smoke grid, smoke tapes, smoke
outputs, smoke gate, PID, expectation, wrapper log, and every other byte remain
append-only audit evidence. They may not be deleted, overwritten, resumed,
copied into the next retry, used as a smoke prerequisite, or relabelled as a
scientific no-go or pass. The partial wrapper registration may not be completed
and the wrapper may not be relaunched in that namespace.

This closure does not revive the original legacy run covered by V1. There is no
V3 recovery launch, no V4 recovery overlay, and no semantic opening of any
legacy efficacy artifact.

## Sole authorized fresh retry

The sole authorized retry after this amendment is named `causal-retry-002`.
Its verifier leaf remains exactly `attempt-002` because the registered V1/V2
validators and seal builders bind that compatibility leaf. The leaf is not a
globally unique run identifier.

The fully qualified retry identity is

```text
(new pushed source commit containing this amendment and the visibility fix,
 scientific run name = causal-retry-002,
 absolute new clean checkout root,
 absolute new durable root,
 verifier-compatible leaf = attempt-002)
```

The intended roots are

```text
/mnt/localssd/ttt-rl-cohort-causal/<new-source-commit>/causal-retry-002/attempt-002
/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/<new-source-commit>/retries/causal-retry-002/attempts/attempt-002
```

The literal pushed commit and absolute roots must be frozen in fresh provenance
and controls before the new smoke starts. No file, process state, transport
file, smoke artifact, control, or result from either the original legacy tuple
or `causal-retry-001` may be reused.

## Frozen visibility-fence contract

No-overwrite publication remains mandatory. A producer may never repair a
published pathname by truncating, touching, renaming over, or rewriting it.
Before a newly published SenseiFS file is consumed, the relevant producer or
consumer must wait for two matching snapshots separated by at least one second,
within a maximum of 60 seconds.

For non-opaque control and pipeline files, each successful snapshot must prove
all of the following through an `O_NOFOLLOW` file descriptor and a matching
pathname `lstat`:

- the pathname is a nonempty regular file with `st_nlink == 1`;
- device, inode, size, nanosecond mtime, link count, and bytes remain unchanged
  during the read;
- the two snapshots have the same identity and SHA-256;
- when the producer knows the payload, the bytes equal the exact payload that
  was published.

Temporary `ENOENT`, an empty stale view, a publication-time link count of two,
or an in-read identity drift may be polled only until the fixed deadline. A
symlink, non-regular file, link count greater than two, unexpected bytes,
unexpected pathname, or a condition that persists through the deadline fails
closed immediately or at the deadline. A failed namespace is never cleaned and
retried.

The same fence applies at these outcome-blind boundaries:

1. fresh provenance and its detailed sidecar before smoke consumption;
2. wrapper PID and launch expectation before READY publication;
3. V1/V2 terminal-control plans, procfs inventory, and detached transport
   bindings before authorization preflight, then formal-start authorization
   before wrapper consumption;
4. collector tape/manifest/final trace before replay starts;
5. replay cell manifest/final trace before smoke validation or formal assembly;
6. formal manifest before the independent decision validator starts;
7. formal decision before the wrapper creates its exit marker.

Formal manifest and decision contents remain opaque to the wrapper. At that
boundary the wrapper may compare only descriptor/path identity, nonzero size,
single-link regular-file status, and stable metadata; it may not read, hash,
parse, print, or interpret their bytes. The formal decision validator writes
its registered output file with stdout suppressed so decision content is not
copied into the wrapper log. Per-cell execution logs remain embargoed,
uninspected efficacy artifacts outside the terminal inventory and may not be
inspected before the terminal reveal boundary. The terminal verifier retains
sole authority for semantic opening after completion attestation.

## Unchanged scientific and terminal contracts

All scientific choices in `COHORT_QONLY_CAUSAL_PREREG.md`,
`COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md`, and V1 remain unchanged.
`causal-retry-002` uses the same committed smoke/formal grids, Qwen3-4B bytes,
adaptation and held-out corpora, adapter seed, three formal run seeds, prompts,
candidate budget, reward timing, frozen-tape order, active/LR0 definitions,
action budget, decoding settings, estimands, bootstrap, `3/3` rule, `+0.02`
mean threshold, positive clustered lower bound, integrity/schema gates, and
branch rules. `generate_cohort_causal_grid.py --check` must produce no grid
diff.

The new retry uses the registered V2 terminal-verifier path directly. V3 is not
generated or authorized, and no V4 exists. The legal sequence remains:

```text
completion attestation -> semantic revalidation -> conditional seal -> reveal
```

A valid no-go is sealed before reveal. A causal internal-gate pass is revealed
without a no-go seal and may then authorize the separately preregistered online
ICL comparison. An infrastructure-invalid run makes no scientific claim.
