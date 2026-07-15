# Cohort causal formal invalid-only diagnostic amendment V1

Status: **prospectively frozen before any semantic opening of retry-004 formal artifacts**
Date: 2026-07-15 America/Los_Angeles

This amendment authorizes exactly one outcome-blind, invalid-only diagnostic
pass over the completed `causal-retry-004/attempt-002` namespace.  It does not
authorize a scientific reveal, a V2 or V3 terminal launch, a relaunch inside the
retry, a structured-state execution seal, or a fresh scientific retry.  It
changes no corpus, model, seed, prompt, candidate policy, update rule, arm,
estimand, threshold, grid, or branch rule.

## Frozen incident and operator knowledge boundary

The immutable attempt identity is:

```text
source commit:
  fd9ab294a939350ee5f174acbab0ad279e33ee1e
scientific run name:
  causal-retry-004
compatibility leaf:
  attempt-002
checkout root:
  /mnt/localssd/ttt-rl-cohort-causal/fd9ab294a939350ee5f174acbab0ad279e33ee1e/causal-retry-004/attempt-002
durable root:
  /sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/fd9ab294a939350ee5f174acbab0ad279e33ee1e/retries/causal-retry-004/attempts/attempt-002
```

Before this amendment was frozen, the operator observed only the registered
liveness surface: the Pluto job remained running, all eight A100-40G GPUs were
idle, the registered wrapper PID was dead, the formal manifest and formal
decision pathnames existed, and the wrapper exit marker was canonical `1\n`.
The marker has size two and SHA-256
`4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865`.
The pinned validator maps a semantic `decision=invalid` to exit 1, an
infrastructure visibility failure to exit 2, and valid `pass` or
`valid_no_go` decisions to exit 0.

No formal manifest, formal decision, pair record, model response, candidate,
reward, score, seed delta, aggregate, bootstrap, confidence interval, threshold
check, raw error, tape, trace, plaintext log, or ciphertext was semantically
opened, printed, copied, or interpreted by an operator.  Existing per-cell logs
remain encrypted and the private `age` identity remains absent from the host.

## Why the registered terminal chain is closed

The V1 completion attester requires the wrapper exit marker to be zero.  V2
executes that exact V1 gate, and V3 also requires exact `0\n` while addressing
only the previously registered equal-second timestamp incident.  The V1/V2
revalidator again requires exit zero and accepts only `pass` or `valid_no_go`.
Therefore no V2/V3 detached launcher, completion attestation, semantic
revalidation, or execution-seal builder may be invoked for retry-004.  Creating
a detached receipt merely to observe the expected attester failure is forbidden.

The retry-004 manifest and decision remain efficacy-bearing sealed artifacts.
Their existence plus exit 1 proves only that the attempt is invalid; it does not
identify the failed integrity predicate and makes no scientific claim about
TTT-RL efficacy.

## Sole authorized diagnostic

The only authorized semantic consumer is the checked-in
`diagnose_cohort_causal_invalid.py` tool, used in two distinct stages from a new
pushed diagnostic-tooling commit.

### Stage 1: opaque freeze

The `freeze` stage must run before the diagnostic stage.  It may inspect only
path identity, regular-file mode, device, inode, link count, size, mtime, and
opaque SHA-256 bytes.  It must not JSON-decode the formal manifest or decision.
The diagnostic-tooling commit must be a commit object in the same repository,
must descend from the formal source commit, and must be contained by the exact
already-fetched authority ref
`refs/remotes/origin/codex/cohort-closed-loop-state-prereg`.  That checkout's
registered fetchspec is exactly
`+refs/heads/codex/cohort-closed-loop-state-prereg:refs/remotes/origin/codex/cohort-closed-loop-state-prereg`.
The deployed diagnostic script and this amendment must be byte-identical to
their blobs at the diagnostic-tooling commit.  These commit, ref-containment,
fetchspec, and blob checks are frozen into the plan and revalidated before and
after diagnosis.
It must require:

1. the exact attempt identity above and a clean, commit-qualified checkout;
2. the exact canonical exit bytes `1\n` and the registered wrapper PID/start
   identity no longer live;
3. the formal manifest and decision both present as stable, single-link regular
   files, with the exit marker strictly later than both;
4. all bound inputs stable across two snapshots separated by at least one
   second, with no symlink, inode substitution, temporary file, or live process
   referencing either attempt root;
5. the exact amendment, tool source, historical validator, launch expectation,
   formal manifest, formal decision, wrapper PID file, and wrapper exit file
   bound by normalized absolute pathname, SHA-256, size, device, inode, mode,
   link count, and mtime;
6. one canonical no-overwrite plan at
   `$DU/control/CAUSAL_FORMAL_INVALID_DIAGNOSTIC_PLAN_V1.json`, binding the exact
   diagnostic argv, Python path/version, output path, and diagnostic-tooling
   source commit.

Every plan or receipt publication must remain inside a bounded visibility
wait until the target exposes the expected device/inode/mode/size/mtime and
payload, link count one, and two consecutive identical stable observations.
Timeout, replacement identity, changed bytes, or a final non-one link count
fails closed.  Dynamic loading of the pinned V1/V2 verifier sources must reject
any `__pycache__`, `.pyc`, `.pyo`, or symlink in the deployed verifier tooling
tree before and after import.

The freeze must also prove that the scientific checkout is at clean HEAD
`fd9ab294a939350ee5f174acbab0ad279e33ee1e`, that no live/partial/temporary
artifact exists under the artifact or prep roots, and that no component of any
bound pathname is a symlink.  It binds and validates the already prospective
V2 procfs exception inventory, including its exact static records and dynamic
`monitor-connect`/`sleep` policy, rather than weakening unreadable-cwd handling.

The opaque stage must publish no efficacy-bearing value.  Failure leaves no
authority to run the diagnostic stage.

The freeze uses the same `/tmp` cwd, exact `env -i` environment, Python path,
and Python version registered below.  Its only additional authority argument is
`--tooling-commit <new pushed diagnostic-tooling commit>`; that value determines
the fixed tooling directory and is sealed into the plan.

### Stage 2: invalid-only semantic diagnosis

The `diagnose` stage must be invoked from a fresh non-multiplexed SSH session,
with cwd `/tmp` and this exact environment after `env -i`:

```text
HOME=/tmp
LANG=C.UTF-8
LC_ALL=C.UTF-8
PATH=/usr/bin:/bin
PYTHONDONTWRITEBYTECODE=1
PYTHONHASHSEED=0
```

Its exact Python argv is:

```text
/usr/bin/python3.10 -I <bound diagnostic tool> diagnose --plan <frozen canonical plan>
```

The plan is the only diagnostic-stage authority argument; the tooling commit
and every attempt path are derived from and checked against it.  The stage must
require cwd `/tmp`, Python `3.10.12`, the environment and argv above, the same
hostname and boot ID registered by the formal wrapper, and the exact V2 procfs
exception policy.  It must revalidate every plan and input binding before and
after semantic work and prove that no experiment process remains live.

It may decode only the already-bound formal decision.  The formal manifest
remains opaque.  The decision must have the exact registered top-level schema
and must state `decision=invalid`, `decision_scope=invalid`, `status=invalid`,
`publication_grade=false`, null aggregate/bootstrap/threshold fields, and a
nonempty string error list.  A `pass`, `valid_no_go`, malformed decision,
changed byte, changed inode, process reference, or unknown output field fails
closed without publishing a diagnosis.

Raw error strings are never written or printed.  Every error is mapped by the
prospectively checked-in rule table to an enum reason ID and one of these broad
classes:

```text
schema_contract
provenance_binding
tape_integrity
update_contract
evaluation_integrity
format_stability
endpoint_completeness
other_integrity
```

An unmatched error may produce only `UNKNOWN_INTEGRITY_FAILURE`.  It may not
surface the string itself, a digest of that string, or any reversible or
dictionary-testable surrogate.

The sole output is the no-overwrite canonical receipt
`$DU/control/CAUSAL_FORMAL_INVALID_DIAGNOSTIC_RECEIPT_V1.json`.  Its public
schema is limited to protocol/version/status, attempt and plan bindings, input
hashes, reason IDs/classes/counts, timestamps, and the
literal sentinel:

```json
{
  "efficacy_fields_emitted": false,
  "formal_manifest_parsed": false,
  "raw_errors_emitted": false
}
```

It must never contain or derive a pair, arm score, reward, seed delta,
aggregate, bootstrap sample, confidence interval, threshold result, model text,
candidate text, tape item, trace item, raw error, or branch-bearing scientific
value.  CLI stdout is limited to a fixed completion token; stderr is limited to
a fixed failure token.

## Closure and subsequent branch

A valid diagnostic receipt closes retry-004 as invalid and nonpromotable.  It
does not turn the attempt into a valid no-go or pass, and it does not reveal its
efficacy.  All retry-004 files remain append-only audit evidence and may not be
overwritten, repaired in place, resumed, or reused as scientific inputs.

After the safe reason IDs are known, a separate prospective amendment is
required for any next action.  If they identify a generator, schema, or
transport defect, that amendment may authorize one wholly fresh
`causal-retry-005` with only the exact outcome-independent defect corrected.  If
they instead prove that the active arm failed the registered true-update or
update-stability contract without an implementation defect, the frozen-tape
parameter-adaptation family closes and the only permitted mechanism pivot is
the preregistered structured latent-state TTT-RL route.  Neither branch may be
chosen from hidden efficacy values.
