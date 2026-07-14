# Preregistration: Cohort causal TTT-RL versus reward-aware ICL v1

Status: **preregistered before any competitive-ICL outcome is observed**
Date: 2026-07-13 America/Los_Angeles
Base causal implementation: `1caf142f6ce611da8da8691d4c336388a4c3c4b3`
Related immutable protocols: `COHORT_QONLY_CAUSAL_PREREG.md` and
`COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md`

## Scope and correction made before outcomes

This document adds a mandatory competitive ICL control to the frozen Cohort
weight-update ablation. It does not alter the original active-versus-LR0 tapes,
corpora, prompts, update operations, seeds, thresholds, or interpretation.

An earlier uncommitted draft proposed an `update-input-matched` ICL prompt made
from the frozen optimizer tape. Audit before any ICL outcome showed that this
label was not defensible: all optimizer inputs cannot in general fit in the
registered context, while a readable tape rendering can reveal information that
the optimizer did not consume as text. That proposed arm is removed from the
primary claim. No result was observed under it.

The mandatory competitor is instead a canonical reward-aware online ICL
algorithm. It uses the same base model, adaptation population, held-out
population, task order, action budget, decoder, parser, and scorer, but consumes
its own online adaptation trajectory as context and makes no parameter update.
This is a total-algorithm comparison, not an information-matched intervention.

No ICL prompt policy, model setting, seed, endpoint, margin, or analysis rule may
change after the first competitive-ICL outcome is observed. The implementation,
tests, grids, validator, and provenance allowlist must be committed and pushed
before the first ICL GPU cell is launched.

## Immutable pre-outcome protocol seal

Before the first competitive-ICL outcome, one canonical protocol-seal artifact
must be built from the clean pushed source commit and exact runtime provenance.
The seal binds the canonical provenance SHA-256; its explicit source-commit,
evaluation-code, preregistration, environment, model, tokenizer, and shared
three-arm parity fields; and both the smoke and formal online-ICL grid digests.
It is published atomically with no-overwrite semantics.

The shared-parity field is not a label: before sealing, every Git-tracked byte
of both registered Cohort corpora, schedules, task, scorer, schemas, templates,
structured-output parser, causal grid/provenance builder, manifest assembler,
and causal smoke/formal validator is compared with commit `1caf142`. Any
missing, extra, dirty, or byte-different shared file invalidates provenance.
Only the prospectively registered online-ICL isolation/runtime surface may
differ.

The byte-identical seal, provenance, and source commit must be used for both
smoke and formal. The smoke gate records their canonical digests. Formal is
forbidden unless its current provenance and seal exactly match those recorded
by the passing smoke gate. A code, preregistration, model, tokenizer,
environment, or grid change requires a new prospective protocol and smoke; it
may not be introduced between this protocol's smoke and formal cells. This seal
addition was made before any online-ICL GPU outcome was launched.

Before the online-ICL smoke allocates a model, it must also reload the exact
causal smoke provenance and recompute the registered causal smoke decision from
its collector tape, replay cells, traces, and grid in the immutable causal
checkout. A JSON carrying only favorable labels is not a prerequisite. The
online-ICL smoke report binds the canonical causal gate and provenance digests,
causal source commit, and shared environment/model/tokenizer fields. Formal
first recomputes that same causal prerequisite from its registered raw causal
artifacts and requires an exact binding match, then recomputes the online-ICL
smoke gate from its raw cell artifacts rather than trusting either report's
labels alone.

## Ordered estimands

Let `Y[a,b,i]` be official Cohort reward for arm `a`, independent block or
screen seed `b`, and held-out scoring condition `i`. The block score is the
unweighted mean over the 20 registered held-out conditions:

```text
score[a,b] = mean_i Y[a,b,i]
```

The two primary estimands are distinct and tested in this order:

1. **Causal frozen-tape parameter-update effect**

   ```text
   delta_causal[b] = score[active,b] - score[LR0,b]
   ```

   Active and LR0 consume the byte-identical update tape and differ only in
   `ttt_lr` and `reward_pg_lr`. This is the only primary contrast that isolates
   the effect of nonzero parameters under the frozen-tape intervention.

2. **Competitive advantage over canonical reward-aware online ICL**

   ```text
   delta_icl[b] = score[active,b] - score[onlineICL,b]
   ```

   The algorithms can take different adaptation actions and therefore see
   different public tool results. This is part of the total-algorithm contrast.
   It cannot by itself identify a parameter-update effect.

A positive claim requires both estimands to pass. If the causal contrast fails,
an active-minus-ICL difference cannot rescue the parameter mechanism. If the
causal contrast passes but the ICL contrast fails, a real update effect exists
without demonstrated competitive advantage.

The 20 held-out rows within a block are fixed scoring conditions, not 20
independent replicates. The inferential unit is the seed/DGP block.

## Frozen active and LR0 arms

Active and LR0 remain exactly the arms registered at commit `1caf142`:

- local `/sensei-fs/users/zcai/models/Qwen3-4B`;
- prefix tuning with 512 virtual tokens and adapter seed `2026071400`;
- `context_policy=question_only`, `history_ttt=false`, and no reward injection;
- one reward-PG update and one environment-BoN best/worst update per valid tape
  item, with `best_of_n=8` and `bon_temperature=0.8`;
- active `ttt_lr=reward_pg_lr=5e-4`, versus LR0 rates of zero while still
  executing the same ordered optimizer calls; and
- frozen held-out evaluation with identical corpus, order, task, schema,
  decoding, parser, failure policy, action budget, and scorer.

This document adds no parameter-adaptation mechanism or hyperparameter sweep.

## Mandatory canonical online-ICL arm

The arm is named `cohort_reward_aware_online_icl_v1` and uses
`QwenLocalSystem`. Its frozen settings are:

```json
{
  "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
  "method": "icl",
  "context_policy": "full",
  "adaptation_context_policy": "full",
  "max_context_tokens": 32768,
  "head_tokens": 4096,
  "tail_tokens": 4096,
  "max_new_tokens": 8192,
  "action_max_new_tokens": 4096,
  "temperature": 0.0,
  "top_p": 1.0,
  "parse_retries": 2,
  "system_prompt": "",
  "trust_remote_code": true,
  "inject_env_reward": true,
  "ttt_steps": 0,
  "ttt_lr": 0.0,
  "reward_pg_steps": 0,
  "reward_pg_lr": 0.0,
  "history_ttt": false,
  "best_of_n": 1,
  "distill_provider": "off"
}
```

No adapter, optimizer, distiller, candidate sampler, or update may be created.
The model and tokenizer asset hashes must equal the paired active/LR0 block.
The runtime model-state hash covers the complete model `state_dict`, including
parameters and persistent buffers, and must be unchanged from before adaptation
through the end of held-out evaluation. Greedy decoding, schema, retry policy,
held-out task code, condition order, scorer, and action budget are identical to
active.

### Online adaptation and reward visibility

For each block, ICL runs all 20 registered adaptation conditions in canonical
order. It receives public task observations and the official terminal
environment reward only after the corresponding report has been committed and
scored. The fixed wrapper is the existing `QwenLocalSystem` text:

```text
ENV_REWARD (score of your previous answer, higher is better): {reward:.4f}
```

ICL receives no frozen active candidates, no counterfactual candidate scores,
no held-out evidence, and no extra model call. Its own actions determine its
own public tool trajectory. `best_of_n=1` is intentional and is reported as a
compute difference, not hidden as a matched budget.

The validator independently requires every adaptation reward to appear only on
the terminal observation of its own instance, after the committed report; all
nonterminal observations must omit it. The terminal action is independently
re-scored from the frozen corpus, and its instance ID, trace order, and exact
reward must match the injected value. A trace that moves a correctly signed
reward earlier, moves it to another instance, or consistently re-signs the
derived snapshot is invalid. This fail-closed evidence-chain requirement was
added before the first online-ICL outcome.

The normal `context_policy=full` FIFO message policy is used during adaptation.
Any message truncation, prompt hard truncation, input/output token count, retry,
or repair is recorded. No alternative summary, retrieval policy, enlarged
context, frozen-tape prompt, or post-outcome context variant is tried.

### Sealing and held-out isolation

After the twentieth valid adaptation outcome:

1. the ICL state must be quiescent with no pending response or observation;
2. a one-way sealed-evaluation gate disables terminal reward and sensitive
   feedback ingestion through both `observe()` and `Query.feedback`;
3. the full prompt-bearing state is serialized as canonical UTF-8 JSON with
   sorted keys, compact separators, finite numbers only, and a SHA-256 digest;
4. the snapshot, message inventory, tokenized rendered context, and digests are
   written before held-out evaluation; and
5. the same sealed snapshot is restored after every completed held-out
   condition, including the last one.

The validator independently recomputes the inner snapshot digest, exact schema,
message inventory, rendered prompt/token inventory with the registered
tokenizer, and the prompt-bearing state implied by the bound adaptation trace.
Changing the snapshot and consistently re-signing its surrounding artifacts is
therefore invalid. Every final trace, snapshot, inventory, restoration audit,
cell manifest, smoke gate, and screen report uses atomic no-overwrite
publication. Each validated cell retains both its semantic canonical digest and
the SHA-256 of the exact on-disk bytes for both traces, the snapshot, message
and token inventory, restoration audit, and cell manifest. Formal smoke
revalidation therefore rejects even semantically equivalent byte drift. Raw
artifacts with duplicate JSON keys, a final-component symlink, or bytes other
than the canonical JSON encoding followed by one newline are invalid.

Before either task object is constructed, every registered corpus artifact is
hash-verified and materialized byte-for-byte into a private per-cell runtime
snapshot. The adaptation and held-out task objects read only those private
snapshots; the registered corpus and source bindings are reverified after both
constructors consume the shared schedule. This closes mutation windows between
corpus verification, model initialization, and later SQLite tool access.

Thus every held-out condition starts from the byte-identical adaptation state.
Within-condition public tool results may enter context. After a terminal report,
the scorer may see ground truth, reference survival, and reward, but the system
may not ingest terminal content, `cohort_gt`, `ref_survival`, or
`env_feedback_reward`. The clone is restored before any later response.

The cell is invalid if the initial snapshot digest differs across held-out
conditions, any previous held-out state reaches a later prompt, a sensitive
field appears in a prompt, or model/update state changes.

## Information and compute accounting

This protocol does not claim compute or information equality between active and
online ICL. It requires transparent accounting:

- the three arms share adaptation and held-out DGPs, condition order, task
  interface, action budget, model assets, maximum input/output limits, and
  evaluation code;
- active/LR0 share the exact tape and candidate sampling budget; online ICL has
  its own online trajectory with no best-of-N candidates;
- report collection, adaptation/replay, snapshot/seal, and held-out evaluation
  separately;
- for each phase report generation calls, input/output tokens, candidate
  samples, optimizer forward/backward calls, optimizer steps, wall seconds,
  GPU-seconds, peak allocated GPU memory, retries, repairs, and failures; and
- charge collector cost to standalone active/LR0 pipelines and online ICL's own
  adaptation cost to the ICL pipeline. No compute-adjusted reward is primary.

A favorable score may not be described as cheaper or more efficient unless the
end-to-end accounting supports that separate claim.

## Independent, outcome-blind infrastructure smoke

Before any competitive-ICL outcome was generated, an independent audit found
that taking the first two rows of the internal-screen DGPs would expose a small
but avoidable efficacy preview. The smoke is therefore restricted to
infrastructure integrity and uses two separately generated frozen corpora that
do not overlap either internal-screen corpus:

- smoke adaptation corpus
  `data/cohort_studies/online_icl_smoke_adapt_2026071496`, DGP seed
  `2026071496`, corpus SHA-256
  `43aaf213a341b96514a3f22926fb7ff976d6a6af9888b6f295a059775d000e6b`;
- smoke held-out corpus
  `data/cohort_studies/online_icl_smoke_eval_2026071497`, DGP seed
  `2026071497`, corpus SHA-256
  `f5adba01d7ef5d124fb46a77f3b5da8adecec12548e3ee850947f594141243cf`;
  and
- both use the byte-identical `default` 20-condition schedule, SHA-256
  `9afb2b7c569b8fea700073fb8484b57b2ce86d1b94c401e0ee8e7db3e45996f7`,
  with the smoke executing only its first two conditions.

The smoke still requires the exact passing active/LR0 causal smoke gate as an
implementation prerequisite, but it is deliberately not a DGP-matched efficacy
comparison. Its user-visible completion line and smoke gate contain no reward,
arm score, terminal action, or other efficacy-bearing field. Raw traces and the
cell manifest remain sealed inputs for exact validator recomputation; operators
must not inspect them for efficacy. Passing smoke commits the protocol to the
already registered three-seed screen and cannot be used for optional stopping.

This correction changes no internal-screen DGP, seed, model setting, threshold,
or analysis rule. It was made before the first online-ICL GPU outcome.

## Internal three-seed screen

The internal screen uses run/tape seeds `2026071401`, `2026071402`, and
`2026071403`, adaptation corpus `causal_adapt_2026071411`, and held-out corpus
`causal_eval_2026071412`. ICL is greedy, so repeated ICL runs on the same DGP may
be identical; it is still paired to each active block, and effective `n=3`
comes from the active adaptation/tape seeds. No within-condition pooling is
used as independent evidence.

The parameter route advances only if:

1. the immutable active-versus-LR0 internal causal gate passes, including its
   legacy clustered-bootstrap field, with `publication_grade=false`;
2. all three `delta_icl` values are strictly positive;
3. mean `delta_icl >= +0.02` official score units;
4. all three-arm provenance and integrity checks pass; and
5. active has no hard schema failure and no greater total retry/repair count
   than either paired control.

Report the three raw deltas, sample standard deviation, descriptive two-sided
Student-t interval with `df=2`, and exact two-sided sign-test p-value. With three
positive seeds the sign-test p-value is `0.25`; the screen is not publication
confirmation. A failed competitive gate triggers no ICL prompt or context sweep.

## Publication confirmation: eight wholly new blocks

A positive screen triggers one fixed confirmation with eight new independent
blocks. Screen and smoke seeds are excluded:

| Block | run/tape seed | adaptation DGP seed | held-out DGP seed |
|---:|---:|---:|---:|
| 1 | 2026072001 | 2026072101 | 2026072201 |
| 2 | 2026072002 | 2026072102 | 2026072202 |
| 3 | 2026072003 | 2026072103 | 2026072203 |
| 4 | 2026072004 | 2026072104 | 2026072204 |
| 5 | 2026072005 | 2026072105 | 2026072205 |
| 6 | 2026072006 | 2026072106 | 2026072206 |
| 7 | 2026072007 | 2026072107 | 2026072207 |
| 8 | 2026072008 | 2026072108 | 2026072208 |

Each block has an independently generated adaptation population/study draw and
independently generated held-out population/study draw. Before any confirmation
model run, freeze the DGP generator source commit, complete generator arguments,
seed, schedule, regeneration/failure rule, database/ground-truth hashes,
canonical order, and aggregate corpus hashes. A generation failure is repaired
with the same code/seed; a block may not be replaced.

All 24 primary arm-block cells must finish. An integrity-invalid cell is rerun
only with the same block, code, configuration, and reconstructed inputs. A valid
negative score remains a result, never an infrastructure failure.

### Confirmatory inference

For each primary estimand use the eight block-level paired deltas. Report raw
deltas, mean, median, sample standard deviation, and the two-sided 95% Student-t
interval with `df=7`:

```text
mean(delta) +/- t_0.975,7 * sd(delta) / sqrt(8)
```

Also enumerate all `2^8=256` sign vectors and compute the two-sided conditional
sign-flip p-value of the mean, including equality in the tail and retaining zero
deltas. This is not design-based randomization inference; exactness is
conditional on the model assumption that the eight independent null deltas are
jointly sign-exchangeable about zero.

The endpoints are tested in fixed sequence at `alpha=0.05`: causal first, then
online-ICL competitive only if causal passes. Each must have:

1. sign-flip `p <= 0.05`;
2. mean paired delta at least `+0.02`;
3. 95% t-interval lower endpoint strictly above zero;
4. all eight blocks valid; and
5. no active schema/format regression against either control.

No per-condition pooling, favorable DGP selection, Monte Carlo p-value, or
unregistered alternative interval is permitted.

### Blinding and no optional stopping

Per-cell rewards may be generated only into append-only sealed artifacts needed
for execution. Before all 24 primary cells and their inventory hash are sealed,
no operator or analysis process may read arm comparisons or compute a partial
aggregate. Operational logs may expose only liveness, resource use, integrity,
and completion. The run never stops at a favorable threshold and never adds a
block after a miss.

## Preregistered causal follow-ups after a positive primary confirmation

The full mechanism claim additionally requires the same eight blocks to run
these derived frozen-tape arms, defined and implemented before primary
confirmation unblinding:

- `reward_pg_only`: execute committed reward-PG updates and skip BoN SFT;
- `bon_only`: execute BoN best/worst SFT and skip reward-PG;
- `reward_shuffle`: rotate committed rewards and each candidate-reward vector by
  one item within the 20-item tape, preserve text/candidate order, recompute
  best/worst selection, and bind the derived tape hash; and
- `rollback`: run the full active replay, then restore the exact initial adapter
  before held-out evaluation.

The fixed confirmatory sequence continues with `active - reward_shuffle` only
after both primary endpoints pass; it uses the same `+0.02`, sign-flip, and
positive-lower-interval requirements. `rollback` must be bitwise identical to
LR0 in final adapter hash and deterministic held-out terminal actions. The two
single-component arms estimate each component's incremental contribution and
are reported with intervals, but are not additional significance claims.

No component result is required for the initial three-seed screen. Component
implementation and final derived-tape rules must be committed before the first
eight-block primary outcome is unblinded.

After all Cohort gates pass, the only allowed second-task test is a separately
preregistered Sales transfer; it is not launched earlier. No broad six-task
positive sweep is allowed.

## Negative-result interpretation

Missing a positive gate means only “no demonstrated positive effect.” It does
not establish zero effect or harm. For either estimand, excluding a practically
useful effect of `+0.02` requires a publication-grade one-sided 95% upper bound
below `+0.02`; claiming harm requires that upper bound below zero.

If the parameter route is a valid no-go, it ends without a prompt, context, LR,
or seed sweep. The sole permitted mechanism pivot is the already declared
structured latent-state learner. A final negative goal result must retain raw
artifacts and provide the planned six-task audit report.

## Required artifacts and integrity

Each screen or confirmation manifest must bind and independently verify:

- source commit, all three preregistration documents, environment lock, model,
  tokenizer, DGP generator, task/scorer, runner, snapshot/seal code, grids,
  validators, and analysis code;
- active/LR0 tape, replay log, update counts, initial/final parameter hashes,
  corpus/order hashes, per-condition outcomes, and original causal decision;
- online-ICL adaptation trace, sealed snapshot, message/token inventory,
  snapshot digest before every held-out condition, and restoration audit;
- zero ICL adapter/optimizer/update/candidate counts and unchanged model-state
  hash;
- absence of held-out ground truth, references, terminal rewards, terminal
  content, and prior held-out state from later prompts;
- exactly 20 unique, real, non-synthetic, non-timeout outcomes per arm;
- per-condition reward, terminal-action hash, exact-zero field count,
  retry/repair count, usage, calls, and phase-separated compute; and
- block deltas, frozen analysis-code hash, all threshold checks, and an explicit
  `internal_screen` or `publication_confirmation` decision scope.

Tampering, missing provenance, fallback output, hidden hard truncation,
cross-instance state, unreported cost, or a post-outcome protocol change makes
the affected block invalid. A valid unfavorable result remains valid.

## Prospective infrastructure amendment A1 after invalid smoke attempt-001

Date: 2026-07-14 America/Los_Angeles

This amendment was frozen before any retry or formal online-ICL cell.

Attempt-001, executed from source commit
`bd9bb0a2030b5b29699320f12d98517b790ab27c`, completed GPU execution but
produced no valid smoke gate. The fail-closed validator rejected exact
adaptation-trace-to-snapshot reconstruction before any formal run. As required
by validation, the automated process had already parsed and independently
re-scored bound rewards and terminal actions, but it emitted no smoke gate,
report, score, reward, action, or arm comparison. No operator viewed or
interpreted any efficacy-bearing value from attempt-001.

The failure was an outcome-independent verifier serialization mismatch. The
runtime stored assistant messages with the trace-bound Pydantic response
class's `model_dump_json()` serialization. The validator reconstructed the
parsed action mapping with generic compact `json.dumps()`, which cannot recover
Pydantic declaration order after the trace's sorted-key canonical JSON round
trip.

The sole authorized correction is to select the exact registered response
class from `query.response_schema`, require the trace action to validate and
round-trip without semantic normalization, and reconstruct the assistant
message with `model_dump_json()`. Missing, unknown, invalid, extra, normalized,
or type-coerced response records fail closed. The runner, runtime snapshot
bytes, online-ICL algorithm, prompts, model and tokenizer, corpora, schedules,
seeds, condition order, action budget, reward timing, scorer, estimands,
thresholds, and analysis rules remain unchanged.

Attempt-001 and its original provenance, seal, traces, snapshot, inventory,
restoration audit, and manifest remain append-only invalid audit evidence. They
may not be overwritten, reused, revalidated into a pass, or used as a formal
prerequisite.

Because no efficacy-bearing value was surfaced to or interpreted by an
operator, and the correction is wholly outcome-independent, attempt-002 may
reuse the already registered independent smoke corpora and smoke seed. It must
run in a new immutable attempt directory from a new clean pushed source commit,
freshly regenerated online-ICL grids, fresh no-overwrite provenance and
protocol seal, and newly generated raw artifacts. Formal execution remains
forbidden until attempt-002 passes exact blind smoke revalidation.

The algorithm identifier remains `cohort_reward_aware_online_icl_v1` because
this amendment changes only independent verification, not the algorithm or
estimand. All statements that a seal predates an outcome are revision-scoped:
the new execution contract says
`created_before_first_outcome_under_current_protocol_seal`, and the old global
`created_before_first_icl_outcome` field is retired. Revision identity is the
new preregistration SHA-256, source commit, provenance SHA-256, grid digests,
and protocol-seal SHA-256.
