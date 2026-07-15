# Cohort qonly causal infrastructure-retry amendment V3

Status: **prospectively frozen before any `causal-retry-003` setup command,
attempt-root creation, smoke command, or efficacy reveal**

Date: 2026-07-14 America/Los_Angeles

This amendment authorizes exactly one wholly fresh infrastructure retry,
`causal-retry-003/attempt-002`. It changes only run identity, per-cell log
opacity, outcome-blind liveness reporting, provenance bindings, and terminal
inventory accounting for encrypted logs. It changes no corpus, seed, model,
prompt, candidate policy, update rule, estimand, threshold, grid, or branch
rule.

The `V3` in this filename denotes the third infrastructure-retry amendment. It
does not authorize the repository's terminal-verifier V3 recovery path.

## `causal-retry-002` incident and operator knowledge boundary

The spent retry is the complete tuple:

```text
source commit:
  6e0a638a7d0700d6df0b75f4c99ced9fae0f1324
scientific run name:
  causal-retry-002
checkout root:
  /mnt/localssd/ttt-rl-cohort-causal/6e0a638a7d0700d6df0b75f4c99ced9fae0f1324/causal-retry-002/attempt-002
durable root:
  /sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/6e0a638a7d0700d6df0b75f4c99ced9fae0f1324/retries/causal-retry-002/attempts/attempt-002
formal transport root:
  /tmp/cohort-causal-formal-retry/6e0a638a7d0700d6df0b75f4c99ced9fae0f1324
V2 verifier transport root:
  /tmp/cohort-causal-terminal-verifier-v2/6e0a638a7d0700d6df0b75f4c99ced9fae0f1324
verifier-compatible leaf:
  attempt-002
```

During smoke liveness monitoring, an operator caused exactly one per-cell
execution log to be opened with `tail -n 80`. The opened pathname was:

```text
/mnt/localssd/ttt-rl-cohort-causal/6e0a638a7d0700d6df0b75f4c99ced9fae0f1324/causal-retry-002/attempt-002/artifacts/cohort_causal/logs/causal_cohort_qonly_tape_smoke_seed2026071498_n2.log
```

The access occurred after that file's recorded mtime
`2026-07-15T06:34:29Z` and before the next outcome-blind monitor sample at
`2026-07-15T06:35:07Z`. The command was a remote read-only status probe that
ran `stat` followed by `tail`; it was not issued by the registered experiment
process.

Opening the log itself breached the V2 artifact-level embargo. This remains a
protocol breach even though the operator contemporaneously attests that the
visible bytes were limited to a deprecation warning, checkpoint-loading
progress, `Starting`, an instance identifier, interaction progress, and a
generation-configuration warning. No model response, candidate, reward,
score, paired delta, aggregate, confidence interval, gate, decision, or
branch-bearing value was observed, copied, or interpreted. This is an operator
knowledge attestation; it is not a claim that the file remained semantically
unopened.

The smoke runner was then terminated. The registered formal wrapper was never
launched, both formal transport roots remained absent, and no formal
collector, replay cell, manifest, decision, exit marker, V2 attestation,
semantic revalidation, conditional seal, or formal efficacy result existed.
The no-overwrite incident record is:

```text
/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/6e0a638a7d0700d6df0b75f4c99ced9fae0f1324/retries/causal-retry-002/attempts/attempt-002/control/CAUSAL_RETRY_002_INFRASTRUCTURE_INVALID.json
sha256:e3ff293e25dcadf5bc47a0b85a7d40d30e18958a4ee8bbeaba64bdf271d327c6
```

The incident class is
`retry_002_smoke_log_opacity_breach_before_formal_launch`. The stop decision
uses only the access incident, outcome-blind process/GPU metadata, and the
absence of formal-launch controls.

## Permanent closure

`causal-retry-002` is infrastructure-invalid and nonpromotable. Its checkout,
durable artifacts, smoke outputs, opened log, gates, controls, and metadata
remain append-only audit evidence. They may not be reopened, overwritten,
deleted, renamed, resumed, repaired, copied into another attempt, used as a
smoke prerequisite, or used to choose code, parameters, or analysis.

The following exact source-commit attempt families are closed:

- `1caf142f6ce611da8da8691d4c336388a4c3c4b3`
- `059b26b45180b5a295c4c1b36a180cb2a91d5405`
- `6e0a638a7d0700d6df0b75f4c99ced9fae0f1324`

Closed attempt code may remain as audited ancestry. No artifact or process
state from a closed tuple may be consumed by the new retry.

## Sole authorized fresh retry

The only authorized retry after this amendment is `causal-retry-003`, with
compatibility leaf `attempt-002`, at a new pushed source commit containing this
amendment, the encrypted-log implementation, its provenance and terminal
inventory bindings, and its regression tests.

Its four fresh roots are:

```text
/mnt/localssd/ttt-rl-cohort-causal/<new-source-commit>/causal-retry-003/attempt-002
/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/<new-source-commit>/retries/causal-retry-003/attempts/attempt-002
/tmp/cohort-causal-formal-retry/<new-source-commit>
/tmp/cohort-causal-terminal-verifier-v2/<new-source-commit>
```

Before provisioning, `lexists` must be false for all four roots. They must not
be symlinks, bind-mount aliases, hard-link sources, or otherwise share inode or
process state with a closed attempt. Provenance, grids, tapes, outputs,
encrypted logs, receipts, controls, plans, handoffs, inventories, and seals
are generated afresh with no-overwrite publication. No retry-002 smoke gate or
artifact may be reused.

This amendment authorizes no relaunch inside `causal-retry-003`, no
`causal-retry-004`, and no terminal-verifier V3 recovery.

## Cryptographic per-cell log opacity

Every smoke and formal cell's merged stdout/stderr stream must pass directly
from an anonymous pipe into the pinned `age` public-key encryptor. Plaintext
may never be written to a filesystem pathname, terminal, launcher log, wrapper
log, `tee`, or readable `nohup` output.

The committed public recipient and runtime contract are:

```text
COHORT_CAUSAL_LOG_RECIPIENT_V1.txt
COHORT_CAUSAL_SEALED_LOG_RUNTIME_V1.json
recipient sha256:ce9e4b378ecf219147a9a7b9949adc58a319c08a0dee3f6b9d197f7c8f9c75b2
age version:v1.3.1
Linux amd64 archive sha256:bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377
Linux amd64 binary sha256:2e305637f2a0555305e21c17fb74446acbb39b53135d43d4b744e50c287133a5
```

The matching private identity must never be uploaded to the experiment host,
stored in an environment variable, placed in any checkout/durable/transport
root, passed in argv, or included in provenance. It remains in local private
custody outside tracked repository state. The experiment host therefore has
no decryption capability. The private identity may be used only after the
registered terminal chain reaches its legal reveal boundary and only against
the ciphertext hashes bound by the completion attestation.

Each cell publishes exactly these final audit artifacts:

```text
artifacts/cohort_causal/sealed_logs/<kind>/<cfg_id>.stdout_stderr.age
artifacts/cohort_causal/sealed_logs/<kind>/<cfg_id>.receipt.json
```

It also publishes one fixed-schema, outcome-blind liveness control before the
cell can be monitored:

```text
artifacts/cohort_causal/sealed_logs/<kind>/<cfg_id>.start.json
```

The start control contains only registered identity, process identity, public
recipient digest, and timestamps. It contains no runner output or scientific
value. Its canonical SHA-256 is bound by the final receipt and it is validated
by the phase fence, sealed-log verifier, and liveness command. Although it is
an operational liveness control rather than a scientific result, it remains
part of the exact formal completion inventory so the terminal verifier can
independently bind the complete start-to-finish chain.

The fixed-schema receipt binds the public recipient, runner/sealer process
identities and exit codes, start-receipt hash, ciphertext size, and ciphertext
SHA-256. It contains no stdout, stderr, traceback, response, reward, score, or
result excerpt. Formal completion inventory adds exactly nine encrypted logs,
nine start receipts, and nine finish receipts, changing the registered formal
count from 23 to 50 without changing the scientific manifest or decision
schema.

No operator, monitor, IDE, debugger, or diagnostic process may decrypt a cell
log or read plaintext through `/proc`, a pipe, a process attachment, or any
other bypass before reveal. A missing/changed ciphertext, receipt mismatch,
nonzero runner or sealer exit, private-identity presence on the host, plaintext
leak, or decryption attempt fails closed and invalidates the namespace.

## Outcome-blind liveness surface

Human-visible launcher/wrapper stdout and operational monitoring are limited
to fixed-schema liveness tokens and receipts: Pluto job/pod state, GPU
occupancy, registered PID identity/aliveness, phase name, cfg ID, READY and
authorization markers, exit codes, and stable metadata for explicitly
allowlisted control or ciphertext paths. They may not contain or derive
dynamic runner stdout/stderr, exception text, result fields, scores, or
artifact excerpts.

The liveness status command may read only `.start.json` and `.receipt.json`
files in the registered sealed-log directory. It may not glob, open, decrypt,
or print ciphertext, tapes, traces, raw manifests, decisions, or results.

Only the blind smoke validator may consume smoke result artifacts, and it may
surface only the registered integrity gate. Only the registered V2 terminal
chain may semantically consume formal efficacy artifacts.

## Unchanged scientific contract

`COHORT_QONLY_CAUSAL_PREREG.md`,
`COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md`, V1, and V2 remain unchanged
scientifically. `causal-retry-003` uses the same committed smoke/formal grids,
Qwen3-4B bytes, corpora, adapter seed, three formal seeds, prompts, candidate
budget, reward timing, frozen-tape order, active/LR0 definitions, update
operations, estimands, bootstrap, integrity/schema gates, `3/3` rule, `+0.02`
threshold, positive clustered lower bound, and branch rules.

`generate_cohort_causal_grid.py --check` must produce no diff. V3 source
changes are restricted to retry identity, public-key log transport,
outcome-blind liveness, provenance and terminal inventory bindings, and tests;
they may not alter runner scientific arguments or behavior.

## V2 terminal chain only

`causal-retry-003` uses the normal registered V2 terminal-verifier chain
directly, including only the V1 compatibility controls already bound by V2.
No `CAUSAL_TERMINAL_VERIFIER_V3*` artifact may be generated or used.

The legal sequence remains:

```text
completion attestation -> semantic revalidation -> conditional seal -> reveal
```

A valid no-go is sealed before reveal. An internal-gate pass is revealed
without a no-go seal. Infrastructure-invalid execution makes no scientific
claim.
