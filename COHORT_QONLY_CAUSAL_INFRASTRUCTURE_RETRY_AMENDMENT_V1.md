# Cohort qonly causal infrastructure-retry amendment V1

Status: **prospectively frozen before any retry command or outcome reveal**
Date: 2026-07-14 America/Los_Angeles

This amendment authorizes one wholly fresh infrastructure retry of the
preregistered Cohort qonly frozen-tape causal gate. It changes no corpus,
seed, model, prompt, candidate policy, update rule, estimand, threshold, or
branch rule.

## Legacy run incident and knowledge boundary

The legacy run is identified by the complete tuple

```text
source commit:
  1caf142f6ce611da8da8691d4c336388a4c3c4b3
absolute checkout root:
  /mnt/localssd/ttt-rl-cohort-causal/1caf142f6ce611da8da8691d4c336388a4c3c4b3/attempt-002
absolute durable root:
  /sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/1caf142f6ce611da8da8691d4c336388a4c3c4b3/attempts/attempt-002
verifier-compatible leaf:
  attempt-002
```

That fully qualified legacy run reached a completed but semantically unopened
formal artifact set. Its V2 terminal verifier then encountered the already
documented equal-second filesystem timestamp false negative. The sole V3
recovery overlay was prepared outcome-blind, including its immutable failure
closure, completion fence, execution plan, and detached handoff.

Before the V3 detached launcher was invoked, a real static stage preflight
failed. `load_and_validate_execution_plan_stage` reused its requested `stage`
argument as the loop variable while validating all registered invocations.
After that loop, it selected the last iterated stage rather than the requested
stage and therefore compared a caller with the wrong registered topology. This
is the fixed incident class `v3_prelaunch_stage_shadow_validation_failure`.

No V3 launch claim, detached receipt, completion attestation, revalidated
decision, revalidation receipt, or execution seal was created. No formal
manifest, formal decision, model output, reward, score, seed delta, aggregate,
confidence interval, or branch decision was semantically opened, surfaced, or
interpreted by an operator. The failure was discovered from outcome-blind
control metadata and code inspection only.

## Permanent closure of the legacy run identity

The fully qualified legacy run above is infrastructure-invalid and
non-promotable. Its checkout, provenance, grids, tapes, snapshots, raw model
outputs, manifests, decisions, inventories, receipts, closure, fence, V1/V2/V3
plans, handoff, logs, and every other artifact remain append-only audit
evidence. They may not be overwritten, copied into the retry, resumed,
replayed, revalidated into a pass, or used as a formal prerequisite. Their
efficacy-bearing bytes remain unopened.

There is no V4 recovery overlay and no second V3 launch. The outcome-independent
stage-shadow correction closes the software defect but does not revive the
spent recovery namespace. Any future interpretation of the fully qualified
legacy run is forbidden by this amendment.

## Sole authorized fresh retry

The sole authorized scientific retry is named `causal-retry-001`. Its verifier
leaf remains exactly `attempt-002` solely because the registered V1/V2
validators and seal builders bind that leaf at multiple fail-closed sites. The
leaf is a protocol-compatibility component, not a globally unique attempt
number, and must never identify a run by itself.

The fully qualified retry identity is the tuple

```text
(new pushed source commit,
 absolute new clean checkout root,
 absolute new durable root,
 verifier-compatible leaf = attempt-002)
```

Both absolute roots must contain the new source commit and the scientific run
name `causal-retry-001`. The intended layouts are

```text
/mnt/localssd/ttt-rl-cohort-causal/<new-source-commit>/causal-retry-001/attempt-002
/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal/<new-source-commit>/retries/causal-retry-001/attempts/attempt-002
```

The literal source commit and absolute roots must be frozen in the new
provenance and controls before smoke execution. This identity cannot equal or
alias the legacy tuple. The retry must begin from a new clean checkout of a
pushed commit that contains this amendment, the stage-shadow correction, its
regression tests, and the prospective terminal-marker correction. No file or
process state from the legacy checkout, durable root, or transport root may be
reused.

`causal-retry-001` must generate all of the following afresh with no-overwrite
publication:

1. source and environment provenance, evaluation-code inventory, protocol
   controls, and deployment hashes;
2. smoke grids, smoke tapes, smoke outputs, validation receipts, and the smoke
   gate;
3. formal grids, all three adaptation tapes, all active and LR0 raw outputs,
   snapshots, restoration audits, manifests, and terminal controls;
4. the formal V2 attestation, revalidated decision, revalidation receipt, and
   conditional execution seal.

Formal execution remains forbidden until the freshly generated
`causal-retry-001` smoke artifacts pass the unchanged blind smoke validator. A
smoke gate or raw artifact from the legacy tuple cannot satisfy this condition.

## Frozen scientific contract

All scientific choices from `COHORT_QONLY_CAUSAL_PREREG.md` and
`COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md` remain unchanged. In
particular, `causal-retry-001` uses:

- the exact adaptation corpus `causal_adapt_2026071411` and held-out corpus
  `causal_eval_2026071412`, with their already registered bytes and hashes;
- adapter initialization seed `2026071400`, run seeds `2026071401`,
  `2026071402`, and `2026071403`, and bootstrap seed `2026071499`;
- the same Qwen3-4B model and tokenizer bytes, active/LR0 arm definitions,
  frozen-tape collection and replay order, prompts, candidate budget, reward
  timing, environment scorer, action budget, decoding settings, and failure
  policy;
- the same three seed-level paired estimands, hierarchical paired bootstrap,
  integrity gate, schema gate, `3/3` strictly positive rule, mean delta
  threshold `+0.02`, and strictly positive clustered 95% lower bound;
- the same no-go, pass, and downstream branch rules.

The registered corpora and seeds are reused as scientific inputs; their
attempt-local copies, tapes, executions, and outputs are newly generated. No
hyperparameter or analysis rule may be selected using bytes from the legacy
tuple.

## Prospective V2 terminal path

`causal-retry-001` uses the registered V2 terminal-verifier path directly. V3
recovery is neither generated nor authorized. The formal wrapper must publish
and fsync the formal manifest and formal decision before creating the canonical
`0\n` exit marker. Before that one-shot creation, it must wait for a later
filesystem timestamp tick; after creation and fsync it must verify

```text
formal_manifest.mtime_ns < causal_formal.exit.mtime_ns
formal_decision.mtime_ns < causal_formal.exit.mtime_ns
```

The exit marker must also retain the registered zero-exit bytes and all other
V2 wrapper bindings. Equality, an earlier marker, a noncanonical marker, or an
unverifiable timestamp is an infrastructure failure, not a scientific no-go.
The marker may not be touched or rewritten after publication.

After the immutable V2 plan and detached handoff are published, but before any
launch claim or detached launcher invocation, an outcome-blind preflight must
execute the real commit-qualified `load_and_validate_execution_plan_stage`
path separately for `attester`, `revalidator`, and
`execution_seal_builder`. Each call must use that stage's exact registered
inputs, outputs, parameters, argv, Python path, and Python version from the
published plan. Comparing dictionaries without executing the validator, using
a mock or alternate checkout, or checking only one stage does not satisfy the
gate. All three calls must pass in the clean deployed runtime; any failure
invalidates `causal-retry-001` before claim creation.

Only after the fresh smoke gate, strict later exit-marker check, complete
three-stage real preflight, deployment byte audit, and all existing V2
outcome-blind prerequisites pass may the one-shot V2 detached launcher run.
Efficacy remains sealed until the normal attestation, semantic revalidation,
and conditional-seal sequence reaches its preregistered reveal boundary.
