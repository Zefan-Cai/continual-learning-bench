# Conditional Preregistration: Closed-Loop Structured-State TTT-RL for Cohort

## Status and scope

This document prospectively registers
`cohort_closed_loop_structured_state_ttt_rl_v1`. It is conditional: the
document and its implementation may be prepared in advance, but no smoke DGP,
formal DGP, model call, candidate action, or candidate reward may be generated
until one of the two exact execution triggers below has been independently
revalidated and sealed.

The mechanism is named **closed-loop structured latent-state TTT-RL**. It is
not offline calibration, frozen-base replay, parameter adaptation, prompt
optimization, or an online-ICL variant. The learned state changes the official
action and the center of the candidate group on the next adaptation item.

This protocol is the only registered mechanism pivot after a valid failure of
the current parameter route. It adds no state dimension, perturbation-radius,
learning-rate, reward-scaling, context, prompt, decoding, or seed sweep.

## Exact conditional execution trigger

Let `C_original` be the decision written by the current causal formal wrapper.
The causal implementation has no protocol-seal artifact. This protocol must
not create a new file and retroactively call it the causal protocol seal. The
causal trigger inventory is exactly:

- the registered causal formal grid, compact provenance, and detailed
  provenance sidecar;
- `COHORT_QONLY_CAUSAL_PREREG.md` and its registered statistical addendum;
- the exact adaptation and held-out corpus bundles: both dataset manifests,
  every artifact registered by those manifests, both registered schedule files,
  and their aggregate corpus/order hashes;
- the registered causal smoke gate;
- exactly three collector tapes, three collector manifests, and three
  collector traces;
- exactly six replay-cell manifests and six replay-cell traces;
- the assembled causal formal manifest;
- every file/path/digest in the causal provenance sidecar's exact
  evaluation-code allowlist, including the causal grid generator, provenance
  builder, runner, assembler, smoke validator, formal validator, and
  `launch_cohort_causal.sh`; and
- `C_original`, the existing causal outer-wrapper PID/exit files under
  `attempt-002/prep/`, and the independently published trigger-completion
  attestation defined below.

The trigger inventory and execution seal must encode:

```text
causal_protocol_seal_sha256 = null
causal_protocol_seal_status = "not_applicable_existing_implementation_has_none"
```

No causal artifact may be omitted, substituted, or accepted from an
unregistered path. Define `causal_pre_attestation_inventory` as every causal
input/output plus the existing PID/exit files enumerated above, but explicitly
excluding the later completion attestation, `C_revalidated`, and the structured
execution seal. This nonrecursive inventory is the object snapshotted below.

The already running causal wrapper predates this document:
its PID and exit files are ordinary files, it has no registered lock, and its
exit file is not an atomic no-overwrite completion certificate. This protocol
must not retroactively claim otherwise.

The original decision may first be semantically parsed, interpreted, or exposed
to an operator only after the existing exit
file exists and its UTF-8 text, after trimming ASCII whitespace, equals exactly
`0`, its mtime is later than both formal output mtimes, and the PID-file bytes
match exactly `^[1-9][0-9]*\n?$` in ASCII. Parsing those bytes as canonical
base-10 yields the recorded launcher PID; that PID is no longer live, no process command line
or working directory references the exact attempt checkout or artifact root,
no registered `.live.json` or `.*.tmp.*` remains, and two metadata/hash
snapshots of the exact final
inventory taken at least one second apart are identical. The inventory must
contain exactly the registered three tapes, three collector manifests, three
collector final traces, six replay manifests, six replay final traces,
`formal_manifest.json`, and `formal_decision.json`, in addition to the frozen
provenance/smoke/corpus/code inputs enumerated above.

The verifier may stream raw files, including `formal_decision.json`, solely to
compute length and cryptographic digests for these snapshots. It may not parse,
decode, print, classify, or otherwise reveal their semantic content before the
completion attestation is published.

Before opening `C_original`, a separate verifier publishes a canonical
`causal_trigger_completion_attestation` with atomic no-overwrite semantics. It
binds the literal PID-file and exit-file bytes/digests, expected launcher
command/source digest, process-absence audit, both stable inventory snapshots,
the exact `causal_pre_attestation_inventory_sha256`, no-live/no-temporary audit,
and completion time. The attestation itself is excluded from that inventory
digest, eliminating self-reference.
The attestation is evidence about the terminal snapshot; it is not relabelled
as an original causal protocol seal or wrapper marker. Operator observation is
not completion evidence.

Immediately before semantic opening, before independent revalidation, and
again before publishing the structured execution seal, the verifier must
recompute every current file length/digest in
`causal_pre_attestation_inventory` plus the literal PID/exit file digests. Each
recomputation must match the attested stable snapshot byte-for-byte. Any drift
after attestation invalidates the trigger; matching a newly recomputed decision
cannot rescue changed source or output bytes.

Let `C_revalidated` be a separate no-overwrite revalidation artifact. It must
be reconstructed from the complete causal inventory using a duplicate-key-
rejecting loader and an exact-key schema, without trusting any aggregate or
decision field in `C_original`. The revalidator must independently rebuild the
formal manifest and decision. Both conditions are mandatory:

```text
canonical_bytes(C_revalidated) == canonical_bytes(C_original)
file_bytes(C_revalidated) == file_bytes(C_original)
```

The prescribed report serializer is therefore part of the causal inventory.
Define `C := C_revalidated`. Its object must satisfy:

```text
C.protocol          == "cohort_qonly_frozen_tape_weight_update_ablation_v1"
C.schema_version    == 1
C.experiment        == "cohort_qonly_frozen_tape_causal_formal"
C.status            == "valid"
C.errors            == []
C.publication_grade == false
```

Execution is permitted if and only if exactly one of these branches holds.

### Trigger A: causal parameter effect is a valid no-go

```text
C.decision       == "valid_no_go"
C.decision_scope == "internal_gate_no_go"
```

The execution seal records:

```text
trigger_branch = "causal_valid_no_go"
causal_decision_sha256 = SHA256(canonical_bytes(C))
causal_original_file_sha256 = SHA256(file_bytes(C_original))
causal_revalidation_file_sha256 = SHA256(file_bytes(C_revalidated))
causal_inventory_sha256 = SHA256(canonical_bytes(causal_inventory))
causal_pre_attestation_inventory_sha256 =
    causal_trigger_completion_attestation.pre_attestation_inventory_sha256
causal_inventory_recheck_matches_attestation = true
causal_protocol_seal_sha256 = null
causal_pid_file_sha256 = SHA256(file_bytes(causal_wrapper_pid_file))
causal_exit_file_sha256 = SHA256(file_bytes(causal_wrapper_exit_file))
causal_completion_attestation_sha256 =
    SHA256(file_bytes(causal_trigger_completion_attestation))
online_icl_decision_sha256 = null
```

### Trigger B: causal effect passes, but the matched online-ICL internal screen is a valid no-go

For this branch, `C` must instead satisfy:

```text
C.decision       == "pass"
C.decision_scope == "internal_gate_pass"
```

Let `I_original` be the matched online-ICL formal output. Its exact registered
inventory is:

- `COHORT_MATCHED_ICL_PREREG_V1.md`, the online-ICL formal grid, compact
  provenance, and detailed provenance sidecar;
- the existing online-ICL protocol seal and
  `build_cohort_online_icl_protocol_seal.py`;
- the online-ICL smoke gate plus its exact registered raw smoke inventory: one
  smoke cell manifest, one adaptation trace, one held-out trace, one sealed
  snapshot, one context inventory, and one restoration audit;
- the exact paired causal-smoke prerequisite consumed by the real online
  launcher: `grid_cohort_causal_smoke.json`, its compact and detailed causal
  provenance, the causal smoke gate, the registered smoke adaptation and
  held-out corpus/schedule bundles, exactly one collector tape, one collector
  manifest, one collector trace, two replay-cell manifests, and two replay-cell
  traces;
- the exact online-ICL formal inventory: three cell manifests, three adaptation
  traces, three held-out traces, three sealed snapshots, three context
  inventories, and three restoration audits;
- the paired causal formal manifest, `C_original`, and every causal digest
  that the online formal grid registers;
- every file/path/digest in the online provenance sidecar's exact
  evaluation-code allowlist, including the online grid generator, runner,
  provenance builder, causal-parity checker, smoke validator, formal validator,
  protocol-seal builder, and `launch_cohort_online_icl.sh`; and
- `I_original`, the prospectively registered online wrapper contract/source,
  and the online completion marker described below.

The online formal has not launched. Before its first model call, its wrapper
contract and source must be published no-overwrite and bound into the online
launch inventory. The wrapper must create its PID file with `O_EXCL`, acquire
and hold the registered `flock` for its entire lifetime, launch the exact sealed
command, wait for every child, and then stream-hash (without semantically
opening `I_original`) an exact `online_pre_marker_inventory` that excludes the
completion marker itself. Only after exit code `0`, no live child, no
`.live.json`/temporary artifact, and a closed expected inventory may it publish
a canonical completion marker atomically with no-overwrite semantics. That
marker binds the wrapper source/command digest, PID, exit code, start/end time,
process-absence audit, and `online_pre_marker_inventory_sha256`; only then does
the wrapper release its lock.

`I_original` may first be parsed, interpreted, or exposed after the marker
validates, the PID is dead, the lock can be acquired nonblocking by the verifier,
and a current recomputation of the complete pre-marker inventory exactly equals
the marker-bound digest. The verifier repeats that equality check before
revalidation and before publishing the structured execution seal. This is a
prospective online-only contract; it does not claim the already running causal
wrapper had a lock or an atomic marker.

Let `I_revalidated` be independently reconstructed from this complete
inventory with the same duplicate-rejecting, exact-key, no-overwrite contract
used for `C_revalidated`. It may not trust the original `cells` projection,
`internal_screen`, or decision fields. Both conditions are mandatory:

```text
canonical_bytes(I_revalidated) == canonical_bytes(I_original)
file_bytes(I_revalidated) == file_bytes(I_original)
```

Define `I := I_revalidated`. It must satisfy:

```text
I.protocol                         == "cohort_reward_aware_online_icl_v1"
I.schema_version                   == 1
I.status                           == "valid"
I.decision_scope                   == "internal_screen"
I.internal_screen.decision         == "valid_no_go"
I.internal_screen.decision_scope   == "internal_screen"
I.internal_screen.effective_n      == 3
I.internal_screen.publication_grade == false
I.internal_screen.protocol         == "cohort_reward_aware_online_icl_v1"
I.internal_screen.schema_version   == 1
I.internal_screen.causal_decision_sha256 == SHA256(canonical_bytes(C))
```

The execution seal records:

```text
trigger_branch = "causal_pass_online_internal_screen_valid_no_go"
causal_decision_sha256 = SHA256(canonical_bytes(C))
causal_original_file_sha256 = SHA256(file_bytes(C_original))
causal_revalidation_file_sha256 = SHA256(file_bytes(C_revalidated))
causal_inventory_sha256 = SHA256(canonical_bytes(causal_inventory))
causal_pre_attestation_inventory_sha256 =
    causal_trigger_completion_attestation.pre_attestation_inventory_sha256
causal_inventory_recheck_matches_attestation = true
causal_protocol_seal_sha256 = null
causal_pid_file_sha256 = SHA256(file_bytes(causal_wrapper_pid_file))
causal_exit_file_sha256 = SHA256(file_bytes(causal_wrapper_exit_file))
causal_completion_attestation_sha256 =
    SHA256(file_bytes(causal_trigger_completion_attestation))
online_icl_decision_sha256 = SHA256(canonical_bytes(I))
online_icl_original_file_sha256 = SHA256(file_bytes(I_original))
online_icl_revalidation_file_sha256 = SHA256(file_bytes(I_revalidated))
online_icl_inventory_sha256 = SHA256(canonical_bytes(online_icl_inventory))
online_icl_protocol_seal_sha256 = I.protocol_seal_sha256
online_icl_wrapper_contract_sha256 =
    SHA256(file_bytes(online_wrapper_contract))
online_icl_wrapper_exit_marker_sha256 = SHA256(file_bytes(online_wrapper_exit_marker))
online_icl_inventory_recheck_matches_marker = true
```

For either trigger, the execution seal binds the original file digest,
revalidation file digest, canonical-object digest, complete inventory digest,
revalidation code, source commit, preregistration files, grids, provenance,
smoke gates, and the explicit causal protocol-seal `not_applicable` marker. For
Trigger B it additionally binds the real online-ICL protocol seal and both
original/revalidation digests for `I`. Revalidation of `C` and `I` is symmetric;
neither receives a weaker trust path.

An invalid, partial, smoke-only, missing-cell, resource-failed, cancelled, or
operator-interpreted result never triggers this protocol. A stale decision that
has not been independently revalidated never triggers it. If the causal and
matched online-ICL internal gates both pass, the pivot is forbidden at that
point and the parameter route proceeds to its already registered confirmation.
Before any confirmation DGP is generated or any confirmation model call is
made, a separate prospective addendum may bind the still-to-be-implemented
confirmation inventory/validator and add an exact Trigger C for an
integrity-valid parameter-route confirmation no-go. Without that pre-outcome
addendum, a later confirmation result cannot trigger this pivot. The two
branches above are the only currently executable branches; no confirmation
outcome may itself motivate or shape an added trigger. Such an addendum may
only map the already registered parameter-route confirmation classifier's
complete, integrity-valid `valid_no_go` to Trigger C. It may not change or add
arms, seeds, DGPs, estimands, thresholds, endpoint order, statistical analysis,
claim boundaries, or any structured-state mechanism constant, and it must be
committed before any confirmation DGP/corpus, model call, run/output artifact,
or outcome exists. Confirmation implementation/configuration files may exist
first only so the addendum can bind their exact digests; they are not
run/output artifacts and may not change after the addendum is committed.

## Registered question and estimands

The registered question is:

> Given scalar rewards from precommitted, structured counterfactual actions,
> does a six-dimensional state that changes the next adaptation policy improve
> independently generated Cohort held-out performance over zero state, an
> incorrect reward-credit intervention, and canonical reward-aware online ICL?

The three ordered estimands are:

```text
H1_state[b] = score[closed_loop_active,b] - score[closed_loop_lr0,b]

H2_oracle_rich_total_algorithm[b]
            = score[closed_loop_active,b] - score[canonical_online_icl,b]

H3_reward_shuffle_credit[b]
            = score[closed_loop_active,b] - score[pair_sign_reverse,b]
```

`H1` is the primary state-policy contrast. `H3` is the registered
within-item reward-shuffle causality contrast and tests whether the direction
of reward credit matters. `H2` is explicitly an **oracle-rich total-algorithm
contrast**: the structured learner receives sixteen counterfactual scalar
rewards per adaptation item, whereas canonical online ICL receives only its
official scalar terminal reward. `H2` is not information matched, compute
matched, or by itself causal evidence for the state update.

## Frozen task and raw-policy configuration

All structured arms use the same Cohort task, schema, 36 registered cohort IDs,
three survival horizons, official scorer, action budget, condition order, and
dataset projection. The cohort-to-layer inventory is the sorted mapping from
each registered `CohortSpec.id` to its frozen `CohortSpec.layer`; its canonical
bytes and SHA256 are part of every new structured-state protocol seal.

The raw policy is frozen as:

```json
{
  "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
  "method": "icl",
  "context_policy": "question_only",
  "adaptation_context_policy": "question_only",
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
  "inject_env_reward": false,
  "ttt_steps": 0,
  "ttt_lr": 0.0,
  "reward_pg_steps": 0,
  "reward_pg_lr": 0.0,
  "history_ttt": false,
  "best_of_n": 1,
  "distill_provider": "off",
  "reset_between_instances": true
}
```

No adapter, optimizer, distiller, parameter update, model-generated candidate,
or cross-instance model context may exist. The complete model `state_dict`
hash, including persistent buffers, must remain unchanged throughout each
block. A single raw terminal report is shared by all structured branches for a
given condition; branch differences are produced only by the registered state
transform.

## Six-dimensional state

The dimensionless state has fixed order:

```text
x = [
  layer1_level, layer1_slope,
  layer2_level, layer2_slope,
  layer3_level, layer3_slope
]
```

All state arithmetic uses CPU IEEE-754 float64. The initial state is six
bitwise positive zeros. Negative zero, NaN, infinity, or a reordered state is
invalid. For every official or probe state, construct exactly this six-element
array in the field order printed above:

```text
[[field_name_0, float(value_0).hex()],
 ...,
 [field_name_5, float(value_5).hex()]]
```

`state_sha256` is SHA256 of that array's UTF-8 canonical JSON with compact
separators, `allow_nan=false`, and no trailing newline. The field names,
serializer, and Python binary64/`float.hex()` runtime identity are sealed
protocol inputs; no object-key sorting or decimal reserialization substitutes
for this ordered payload.

The actual logit-offset state is:

```text
d = [7/20, 7/60, 7/20, 7/60, 7/20, 7/60]
z = d elementwise-multiplied by x
```

Thus `x` is the learned, dimensionless state. The transform API accepts `x`
and computes `z=d elementwise-multiplied by x` internally. Callers may not
pre-scale the state or pass `z` directly. No other learned or hidden state is
allowed.

## Semantic action identity

Every schema-valid action has two different hashes with disjoint purposes.

`semantic_action_sha256` uses this exact construction:

1. parse with duplicate-key rejection and require exactly the 108 terminal
   fields `{cohort_id}__s{horizon}`, with `cohort_id` from the sealed sorted list
   of 36 registered IDs and `horizon` in the fixed order `(12,24,36)`;
2. convert every JSON numeric token with the registered correctly rounded
   IEEE-754 binary64 parser, require a finite value in `[0,1]`, and preserve the
   lexical sign when a token converts to zero; integer, decimal, and exponent
   spellings that convert to the same nonzero binary64 value are equivalent;
3. construct the 108-element array, ordered first by the sealed lexicographic
   cohort-ID list and then by `(12,24,36)`, whose entries are exactly
   `[field_name, float(value).hex()]`; and
4. hash the UTF-8 bytes of that array serialized as canonical JSON with compact
   separators, no trailing newline, and `allow_nan=false`.

The sealed cohort-ID list, field-order array, binary64 parser/runtime identity,
and semantic-payload serializer digest are protocol inputs. Missing, extra, or
duplicate fields are invalid. This construction includes signed-zero identity
and is independent of JSON whitespace, input object-key order, or equivalent
nonzero numeric spellings. All candidate uniqueness gates, cross-branch action
equality, official/candidate equality, and scoring joins use this semantic hash.

`action_bytes_sha256` hashes the literal emitted bytes. It is retained only for
artifact provenance and the byte-exact whole-action zero sentinel. It must not
be used to claim that two non-sentinel actions are semantically distinct or
equal.

## Unified terminal-action transform and exact-zero sentinel

The only transform API is:

```text
T_x(raw_action_bytes, x)
```

It validates the dimensionless six-vector `x`, computes
`z=d elementwise-multiplied by x` internally, and has no other state argument.

For a nonzero state, let a cohort in layer `l` have raw survival fields
`(p12, p24, p36)`. For horizon `h`, define the field offset:

```text
delta_12 = z_layer_l_level + z_layer_l_slope
delta_24 = z_layer_l_level
delta_36 = z_layer_l_level - z_layer_l_slope
```

Each field uses the following exact decision order:

```text
if p_h == 0.0:
    q_h := p_h                 # preserve its signed zero exactly
else if delta_h == 0.0:
    q_h := p_h                 # semantic per-field identity
else:
    q_h := sigmoid(logit(clamp(p_h, 1e-6, 1-1e-6)) + delta_h)
```

Equivalently, the non-identity branch is:

```text
q12 = sigmoid(logit(clamp(p12, 1e-6, 1-1e-6))
              + z_layer_l_level + z_layer_l_slope)

q24 = sigmoid(logit(clamp(p24, 1e-6, 1-1e-6))
              + z_layer_l_level)

q36 = sigmoid(logit(clamp(p36, 1e-6, 1-1e-6))
              + z_layer_l_level - z_layer_l_slope)
```

The nonzero transform must not sort the three horizons, perform an isotonic or
monotonic repair, or round to six decimal places. It validates the full
float64 values with the registered schema and serializes the validated object
as canonical JSON using UTF-8, sorted keys, no insignificant whitespace,
`allow_nan=false`, and the runtime's shortest round-trip representation of
each float. No task truth, reference survival, reward, or prior outcome may
enter this transform.

Exact numeric zero is also a field-level missing-value sentinel in the frozen
Cohort scorer. Therefore, for every individual survival field and for every
state, a parsed `+0.0` or `-0.0` must bypass clamp, logit, sigmoid, and offset
application and remain the same signed zero in the transformed object. A
nonzero state may change only a nonzero submitted estimate; it may not turn a
scorer fallback sentinel into an estimate. This field-level rule is separate
from the whole-action zero-state sentinel below. Independently, any field whose
computed `delta_h` is exactly zero must retain the original parsed float value;
it must not take a clamp/logit/sigmoid round trip.

Zero state is a mandatory byte-exact sentinel:

```text
T_x(raw_action_bytes, positive_zero_float64^6) := raw_action_bytes
```

The zero path bypasses parse, clamp, transform, schema reserialization,
canonicalization, field reordering, and rounding. It must satisfy:

```text
T_x(raw, 0) is raw byte-for-byte
SHA256(T_x(raw, 0)) == SHA256(raw)
```

This rule applies to every zero-state official action, including all LR0 and
post-rollback held-out actions.

## Closed-loop adaptation order

Each formal block contains 20 adaptation items. At item `t`, numbered from 1:

1. Reset the raw policy. It may execute the task's registered public
   nonterminal tool calls and observe their public results. Those calls/results
   are part of one branch-shared raw trajectory and are fully traced. They may
   not contain ground truth, reference survival, terminal reward, scorer
   details, or a task/scorer object. A nonterminal `task.step` is allowed only
   for such a registered public tool action/result.
2. Intercept the schema-valid raw terminal report before terminal submission.
   No terminal `task.step`, terminal `system.observe`, scorer call, hidden-state
   lookup, or reward reveal has occurred at this point.
3. For active, LR0, and pair-sign-reverse, use the branch's `x_(t-1)` to
   construct `T_x(raw_t,x_(t-1))` as its official terminal action and construct
   the registered candidate group centered at the same state. Rollback aliases
   the complete active adaptation branch.
4. Atomically commit the one shared raw trajectory/action, every branch state,
   every official action, and every candidate action before any terminal
   submission, scorer call, hidden-state resolution, or reward reveal.
5. After the commitment is durably published and reread, an isolated pure
   scorer resolves the registered opaque scoring-context handle. It scores all
   three official actions and every precommitted candidate. No branch official
   action is submitted through the standard runner and no terminal Observation
   is passed to the raw policy or updater.
6. The pure scorer returns only one finite float64 scalar per synchronous
   invocation. A separate exact-key receipt builder joins that scalar to the
   already committed invocation ID and publishes the scalar-only no-overwrite
   receipt. Official scalar rewards are retained for adaptation accounting but
   are not updater inputs. The updater receives only candidate IDs, the common
   scoring-context digest, and sixteen scalar candidate rewards.
7. The updater changes `x_(t-1)` to `x_t`. The exact `x_t` state hash must
   appear as `state_before` for that branch's official action and candidate
   center at item `t+1`.

The per-item pre-reveal barrier starts only after the isolated pre-launch
registrar phase has finished and its registries/attestations are sealed. Within
an item, after the public raw trajectory, it starts immediately before the
earliest attempted terminal submission, pure-scorer invocation, opaque
scoring-handle resolution, or per-item hidden-state/reward access; it does not
start at the beginning of the item. The registrar is explicitly outside this
per-item barrier and cannot run or mutate state after any raw-policy lifecycle
begins. The direct structured path has no terminal submission, so its barrier
begins before the pure scorer or handle resolution. Registered public
nonterminal tool interaction, including its nonterminal `task.step`, is allowed
before the barrier. Hidden terminal state is never allowed across the raw-policy,
transform, or updater boundaries. The generic runner path that calls
`system.observe` with the Cohort terminal Observation is explicitly forbidden
for structured adaptation because that Observation contains hidden scoring
metadata.

Item 1 uses `x_0=0`; therefore every structured branch's item-1 official action
must have the same semantic action hash as the shared raw action and, by the
whole-action zero sentinel, must also be byte-identical to it. An update from
item `t` never changes item `t`; it first affects item `t+1`.

## Balanced signed-Hadamard candidate design

The perturbation radius and group size are fixed:

```text
rho = 1/4
number_of_direction_rows = 8
number_of_candidates = 16
```

Let `H8` be the unnormalised Sylvester Hadamard matrix:

```text
H1 = [1]
H_(2n) = [[H_n,  H_n],
          [H_n, -H_n]]
```

Let `U` be the first six columns of `H8`. It is fixed for every item and every
branch:

```text
U is in {-1,+1}^{8 by 6}
U^T U == 8 I_6
rank(U) == 6
```

Every item uses every row `u_j`, `j=0,...,7`, and both signs:

```text
x_(t,j,+) = x_(t-1) + rho*u_j
x_(t,j,-) = x_(t-1) - rho*u_j

candidate_(t,j,+) = T_x(raw_t, x_(t,j,+))
candidate_(t,j,-) = T_x(raw_t, x_(t,j,-))
```

Candidate IDs are exactly `(h0,+), (h0,-), ..., (h7,+), (h7,-)`.
Rewards are joined by candidate ID, never by array position. The complete row
set is identical for every item, so it is independent of item order, seed,
reward, state history, or a salted runtime hash. Across the sixteen signed
probes, every state coordinate has exact zero sum.

Candidates use no model call and may not be resampled, repaired, or selected
after observing reward. The probe state is centered on the branch's current
state, not on zero and not on a frozen earlier state.

## Scalar-only sign-ES update

After precommit, the isolated scorer returns exactly one finite scalar score
per precommitted candidate, and the receipt builder binds it to that candidate's
committed ID. The updater input schema is restricted to:

```text
precommit_sha256
branch_id
item_id
scoring_context_sha256
[(candidate_id, scalar_reward)] of exact length 16
```

Each `scalar_reward` is decoded exactly once from the receipt's canonical
`scalar_reward_float_hex` with `float.fromhex`; decimal reserialization or
rounding before the sign comparison is forbidden.

The updater rejects every additional field. In particular it cannot receive
`cohort_gt`, `ref_survival`, a per-cohort score vector, official-action reward,
task metadata, scorer state, or a task object.

Before smoke can pass, boundary poison tests must inject each forbidden field,
both at top level and nested inside an otherwise valid payload, into the raw
policy, `T_x`, and updater boundaries. The forbidden inventory includes at
least `cohort_gt`, `ref_survival`, `env_feedback_reward`, per-cohort score
details, terminal Observation, task object, scorer object, and a callable that
can resolve the opaque scoring handle. Each injection must fail closed before
state or context changes. Complementary scorer-output poison tests replace the
required scalar primitive with an object carrying one forbidden detail field;
the caller and receipt builder must reject it. A receipt-builder request or
published receipt with a swapped branch, item, candidate ID, action hash,
precommit hash, scoring-context digest, or context-attestation digest must also
be rejected.

For a scalar difference, define exactly:

```text
sign(v) = +1 if v > 0
          0 if v == 0
         -1 if v < 0
```

Equality is equality of the two committed float64 scalar rewards; there is no
tolerance, random tie break, jitter, reward centering, reward standardization,
reward clipping, or reward-magnitude weighting.

The registered sign-ES direction is:

```text
g_t = (1/8) * sum over j=0,...,7 of
      sign(r_(t,j,+) - r_(t,j,-)) * u_j
```

The learning-rate schedule is the constant:

```text
eta_t = 1/16 for every t=1,...,20
```

The active update is:

```text
x_t = x_(t-1) + eta_t*g_t
```

There is no optimizer, gradient clipping, state clipping, momentum, decay, or
adaptive schedule. Because every coordinate of `g_t` lies in `[-1,1]`, the
registered update has the prospective bounds:

```text
max_abs(x_t) <= t/16 <= 5/4
max_abs(candidate_probe_x) <= 5/4 + 1/4 == 3/2
```

The corresponding maximum absolute level and slope offsets after 20 updates
are `7/16` and `7/48`; the maximum candidate-probe offsets are `21/40` and
`7/40`. Any observed violation or any nonzero clip counter is an integrity
failure, not permission to add clipping.

## Structured branches and controls

### `closed_loop_active`

Use the true committed plus/minus scalar-reward association and the registered
sign-ES update. Its updated state changes the next adaptation official action
and candidate center.

### `closed_loop_lr0`

Generate, precommit, score, and audit the same number of current-state
candidates and compute the registered `g_t`, but suppress the state assignment:

```text
x_t := positive_zero_float64^6
```

Every official action therefore uses the byte-exact zero sentinel. LR0 is not
allowed to skip candidate scoring, because H1 must match the active arm's
oracle-call count and candidate budget.

### `pair_sign_reverse`

This branch has its own genuine closed-loop state and candidates centered on
that state. After receiving its true scalar-reward receipt, and only at the
updater boundary, it uses:

```text
r_used(j,+) = r_true(j,-)
r_used(j,-) = r_true(j,+)
```

It then applies the same sign function, Hadamard rows, and `eta=1/16` update.
For a fixed candidate receipt its update direction is exactly the negative of
the true-credit direction. At item 1 its candidate actions and true rewards are
identical to active; later policy differences are downstream consequences of
the reward-credit intervention. This exact within-pair permutation is the
registered reward-shuffle ablation; it preserves the sixteen-reward multiset,
candidate budget, reveal time, and scorer calls while assigning every plus
reward to the paired minus ID and vice versa. Future-item reward shuffle,
across-item reward rotation, and candidate-text reassignment are forbidden.

### `closed_loop_rollback`

Rollback uses the complete active adaptation action, candidate, reward, and
state-hash chain. After the twentieth active update and before any held-out raw
action is generated, it restores the exact initial six positive-zero bytes.
Rollback and LR0 must have identical semantic action hashes and official
rewards on every deterministic held-out condition. Their action bytes must also
match, but that byte comparison is recorded only as the required zero-sentinel
audit. Rollback is an integrity/mechanism control, not an additional efficacy
endpoint.

## Atomic terminal pre-submission, no-overwrite commitment

During pre-launch DGP sealing, an isolated context registrar creates each
opaque scoring handle and its hidden registry entry. It computes the context
digest by the formula below and publishes, before any model call, a no-overwrite
public attestation with the exact schema:

```text
scoring_context_protocol
opaque_handle_sha256
scoring_context_sha256
hidden_registry_entry_sha256
```

The protocol seal binds the complete attestation inventory and the hidden
registry inventory digest. The attestation reveals no ground truth, reference,
or scorer detail. Its own file digest is
`scoring_context_attestation_sha256`. The registrar, pure scorer, and
independent validator can resolve the hidden registry; the raw policy,
transform, updater, receipt builder, and operator-visible report cannot.
Registrar access occurs before any raw-policy lifecycle and exposes only these
sealed digests to the later commitment path; it is not a per-item reward reveal.

After the public nonterminal raw trajectory but before terminal submission,
adaptation scoring, or per-item hidden-registry resolution, one canonical
commitment bundle must bind at least:

- protocol, source, model, tokenizer, environment, task, schema, DGP, schedule,
  condition-order, and cohort-layer inventory hashes;
- `block_id`, `item_id`, `instance_id`, `instance_index`, query hash, and public
  raw-trajectory hash, excluding ground truth and reference;
- the single shared raw terminal-action bytes, semantic hash, and byte hash;
- each branch's state-before hex values and hash;
- each branch's official terminal-action bytes, semantic hash, and byte hash;
- `d`, `rho`, the complete integer `U`, all sixteen probe-state hex values,
  candidate IDs, candidate bytes, semantic hashes, and byte hashes;
- the registered opaque scoring-context handle, its public
  `scoring_context_sha256`, and `scoring_context_attestation_sha256`, without
  its hidden contents;
- the previous item commitment digest; and
- the exact serializer and numerical-runtime identity.

The raw trajectory/action is stored once as a shared object. Branch records may
reference it but may not carry independently mutable copies.

Publishing is fixed:

1. create a unique temporary file on the destination filesystem with
   `O_CREAT|O_EXCL`;
2. write the canonical bytes and `fsync` the file;
3. atomically publish the complete inode to the final path with a hard link;
   an existing final path must fail with `EEXIST`;
4. `fsync` the parent directory, unlink the temporary name, reread the final
   bytes, and verify length and SHA256; and
5. only then permit the isolated scorer to resolve the opaque scoring-context
   handle and access hidden task state.

Overwrite, truncate-in-place, rename-over-existing, mutable `latest` pointers,
or deleting a prior commitment to reuse its path are forbidden. A filesystem
that cannot satisfy this publish contract cannot run a formal cell.

The pure scorer API is exactly:

```text
pure_score(exact_precommitted_schema_valid_action_bytes,
           sealed_opaque_scoring_context_handle)
    -> finite_float64_scalar
```

This permits the mandatory raw-byte zero sentinel; it does not permit an
uncommitted canonicalized copy. The synchronous caller retains the committed
invocation ID outside the scorer. Candidate actions may be semantically
duplicate without becoming ambiguous because the scalar return is joined to
that caller-held ID, never inferred from action bytes. Internally the scorer
resolves the sealed hidden registry entry, recomputes the following digest, and
fails closed unless it equals the precommitted public attestation:

```text
scoring_context_sha256 = SHA256(canonical_bytes({
  scoring_context_protocol: "cohort_closed_loop_scoring_context_v1",
  scorer_source_sha256,
  dataset_ground_truth_sha256,
  instance_id,
  instance_index,
  reference_survival_sha256
}))
```

`scoring_context_protocol` is a fixed scorer-context constant, not an arm's
experiment protocol; therefore structured and canonical online-ICL actions for
the same held-out instance can and must share this digest. Every official and
candidate receipt for an adaptation item must bind the same
`scoring_context_sha256`.

The separate receipt builder has no scorer or hidden-task access. Its exact
request schema is:

```text
precommit_sha256
shared_join_key
branch_id
item_id
action_role                 # "official" or "candidate"
action_id
semantic_action_sha256
action_bytes_sha256
scoring_context_sha256
scoring_context_attestation_sha256
scalar_reward_float_hex
```

It rereads the immutable precommit, requires every metadata field and both
action hashes to identify exactly one committed invocation, hashes the literal
opaque handle, and verifies the sealed public attestation and both context
digests without resolving hidden content. Immediately after `pure_score`
returns a finite binary64 primitive, the synchronous caller converts it once
with the registered Python `float.hex()` implementation. The builder accepts
`scalar_reward_float_hex` only as a string `s` for which `float.fromhex(s)` is
finite and `float.hex(float.fromhex(s)) == s`; no decimal or object alternative
is accepted. It then publishes an
exact-key scalar-only receipt with those same fields using the post-reveal
no-overwrite rule. Missing, extra, duplicate, or inconsistent fields fail
closed. Ground truth, reference survival, per-cohort details, task state, and
scorer objects may exist only inside the isolated scorer; they are never
serialized into a receipt-builder request, policy, transform, updater input, or
published receipt. This receipt-builder contract applies to adaptation and
held-out scoring for every structured arm and canonical online ICL.

The exact shared join key is:

```text
{
  block_id,
  item_id,
  instance_id,
  instance_index,
  query_sha256,
  raw_trace_sha256,
  raw_semantic_action_sha256,
  raw_action_bytes_sha256,
  scoring_context_sha256,
  scoring_context_attestation_sha256
}
```

All branch official receipts and all candidate receipts must join to this one
key. Missing, duplicate, cross-branch, cross-item, or cross-instance joins are
invalid.

## Per-item integrity and scientific-signal gates

Every adaptation item in every formal candidate-bearing branch (active, LR0,
and pair-sign-reverse) records two disjoint gate classes. Rollback reuses the
complete active adaptation chain rather than creating a fourth candidate tape.

### Execution-integrity gates

These must hold for an interpretable cell:

```text
candidate_id_count == 16
unique_probe_state_count == 16
rank(U) == 6
U^T U == 8 I_6 exactly
sum_of_all_16_signed_probe_offsets == positive_zero^6 exactly
all official and candidate actions schema-valid
all 16 scalar rewards finite
max_abs(state_before) <= 5/4
max_abs(state_after) <= 5/4
max_abs(probe_state) <= 3/2
probe_state_clip_count == 0
state_update_clip_count == 0
gradient_clip_count == 0
reward_clip_count == 0
precommit_published_before_hidden_state_access == true
state_before_hash == prior_item_state_after_hash
all branch receipts share the exact registered join key
all item-1 active/LR0/reverse official semantic hashes are equal
all item-1 active/LR0/reverse candidate semantic-hash vectors are equal
all item-1 active/LR0/reverse true scalar-reward vectors are equal
```

The fixed `1e-6` probability clamp used only inside a nonzero logit transform
is recorded separately as `input_probability_boundary_clamp_count`; it is not
a state, gradient, or reward clip. The zero sentinel must report zero transform
and boundary-clamp calls.

A broken precommit, malformed receipt, schema failure, nonfinite reward,
Hadamard drift, state-chain break, shared-join mismatch, bound violation, or
nonzero forbidden clip counter is an execution-integrity failure. It is not a
negative scientific result. Rerun semantics are defined by the whole-stage
classification section below; isolated valid cells may never be spliced across
attempts.

### Registered scientific-signal gates

For the sixteen canonical candidate actions and eight pairs, compute:

```text
unique_candidate_semantic_action_hashes == 16
candidate_semantic_hash_equal_to_official_count == 0

for every j:
  mean over the 108 submitted probabilities of
  abs(p_(j,+) - p_(j,-)) >= 1e-4

population_std(the 16 scalar rewards) >= 1e-5 bits/cohort

sqrt(mean over j of (r_(j,+)-r_(j,-))^2)
  >= 1e-5 bits/cohort

number of non-tied reward pairs >= 4
norm_2(g_t) > 0
```

These are mechanism-signal gates, not infrastructure gates. A duplicate action,
sub-floor action diversity, zero/tied candidate rewards, or `g_t=0` is retained
as an observed scientific no-signal item. The update uses the registered
`sign(0)=0`, the run continues, and no candidate is replaced or resampled.

For either the three-block screen or eight-block confirmation, every registered
formal item must pass every scientific-signal gate for a positive decision. A
miss makes the completed experiment a valid mechanism `valid_no_go`; it does
not make the cell invalid and does not authorize a rerun.

## Independent integrity recomputation

Runner summaries, stored gate booleans, stored action hashes, scalar receipts,
and state-transition summaries are claims, not evidence. A separate validator
with an independently hashed source file must reconstruct every check from the
lowest-level sealed artifacts.

For every item and branch, the validator must independently:

1. rebuild the Sylvester `H8`, select its first six columns, and recompute the
   exact integer `U`, signed balance, `U^T U`, and rank;
2. rebuild all sixteen probe states from raw float-hex `state_before`, `rho`,
   and `U`, without reading stored probe-state summaries;
3. rerun `T_x` from the one shared raw action for every official and candidate
   action, including whole-action zero sentinel, per-field `p==0`, and
   per-field `delta==0` identity paths;
4. reparse all recorded actions and recompute semantic action hashes; literal
   byte hashes are checked only for provenance and zero-sentinel identity;
5. independently invoke the frozen pure Cohort scorer on each reconstructed
   exact action byte string after semantic validation and with the sealed
   scoring-context handle; independently recompute the hidden registry entry,
   public context attestation, and scoring-context digest, then require the
   returned scalar's float-hex value and serialized receipt bytes to equal the
   independently reconstructed scalar-only receipt exactly;
6. recompute every reward sign, `g_t`, constant-`eta` state transition, state
   bound, state hash, and next-item state join;
7. reconstruct pair-sign-reverse by swapping only the two scalar rewards inside
   each registered pair and verify its used sign vector and state chain;
8. verify LR0 computed the registered `g_t` but retained six positive zeros,
   and verify rollback exactly reused the active adaptation chain before
   restoring zero;
9. recompute all shared joins across block, item, instance, query, raw trace,
   raw action, scoring context, and context attestation; and
10. rerun the boundary poison tests and receipt-mismatch tests registered above.

The validator must explicitly test swapped branch receipts, wrong item or
instance IDs, duplicate or missing branches, a changed shared raw action,
changed scoring context, reordered candidates, and an LR0 item-1 mismatch. Each
must make a mutation copy invalid. Acceptance based only on self-reported hashes
or booleans is forbidden.

## Five-instance infrastructure smoke

The smoke uses only independently generated, outcome-blind infrastructure DGPs:

```text
run seed        = 2026071598
adaptation seed = 2026071596
held-out seed   = 2026071597
adaptation N    = 5
held-out N      = 5
```

It runs active, LR0, pair-sign-reverse, rollback, and canonical online ICL. It
checks:

- exact precommit-before-reveal ordering and no-overwrite behavior;
- all execution-integrity gates;
- `T_x(raw,0)==raw` byte-for-byte;
- item `t+1` official action and candidate center bind item `t` state-after;
- active, LR0, and sign-reverse have identical item-1 official semantic hashes,
  candidate semantic-hash vectors, scoring contexts, and true reward vectors;
- active and sign-reverse item-1 used update directions are exact negatives;
- rollback restores the exact positive-zero state and has held-out semantic
  action/reward equality with LR0, plus sentinel byte equality;
- no held-out state update or hidden-state ingestion occurs;
- model-state hashes are unchanged; and
- canonical online ICL satisfies its registered no-parameter-update and
  held-out context-seal checks.

The smoke also applies every registered scientific-signal gate to every one of
its five adaptation items in every candidate-bearing branch. Its decision is a
closed, mutually exclusive three-state machine with this priority:

1. If any execution, inventory, provenance, poison-test, shared-join, or
   independent-recomputation check fails:

   ```text
   status = "invalid"
   decision = "infrastructure_fail"
   decision_scope = "infrastructure_smoke"
   errors = nonempty list of redacted error codes
   publication_grade = false
   efficacy_interpretation_allowed = false
   validator_exit_code = 1
   ```

   Scientific-signal checks are not interpreted.

2. Otherwise, if any registered scientific-signal gate misses:

   ```text
   status = "valid"
   decision = "mechanism_smoke_no_go"
   decision_scope = "mechanism_smoke_no_go"
   errors = []
   publication_grade = false
   efficacy_interpretation_allowed = false
   validator_exit_code = 0
   ```

3. Otherwise:

   ```text
   status = "pass"
   decision = "pass"
   decision_scope = "mechanism_smoke_pass"
   errors = []
   publication_grade = false
   efficacy_interpretation_allowed = false
   validator_exit_code = 0
   ```

The smoke report exact-key schema contains only:

```text
protocol
schema_version
status
decision
decision_scope
errors
publication_grade
efficacy_interpretation_allowed
validator_exit_code
grid_sha256
provenance_sha256
protocol_seal_sha256
trigger_inventory_sha256
integrity_gate_counts
scientific_signal_gate_counts
artifact_digests
```

The three count/digest maps also use registered duplicate-rejecting exact-key
schemas. Recursive forbidden-key validation rejects
candidate or official rewards, scores, deltas, per-item signs, `g`, state
values/directions, ground truth, references, and raw error text. User-visible
output contains only redacted gate labels, counts, decisions, and digests.
Here `protocol_seal_sha256` is the new structured-state protocol seal; it is not
and may not be represented as a causal-route protocol seal.

The formal launcher predicate is exact and has no truthy/falsy shorthand:

```text
validator_exit_code == 0
AND status == "pass"
AND decision == "pass"
AND decision_scope == "mechanism_smoke_pass"
AND errors == []
AND publication_grade == false
AND efficacy_interpretation_allowed == false
AND protocol == formal_launcher.registered_protocol
AND schema_version == formal_launcher.registered_schema_version
AND grid_sha256 == formal_launcher.registered_grid_sha256
AND provenance_sha256 == formal_launcher.registered_provenance_sha256
AND protocol_seal_sha256 == formal_launcher.registered_protocol_seal_sha256
AND trigger_inventory_sha256
    == formal_launcher.registered_trigger_inventory_sha256
AND SHA256(file_bytes(smoke_report))
    == formal_launcher.registered_smoke_report_file_sha256
```

Every other state forbids formal launch. An infrastructure failure permits only
a whole-smoke-stage rerun with the same seeds and DGP after a bounded
infrastructure repair. A `mechanism_smoke_no_go` stops this mechanism family
before formal and cannot be repaired by changing a DGP, radius, scale,
direction set, threshold, or seed.

## Held-out freeze and pre-reveal commitment

After adaptation, freeze:

```text
closed_loop_active:   x_20_active
closed_loop_lr0:      positive_zero_float64^6
pair_sign_reverse:    x_20_reverse
closed_loop_rollback: positive_zero_float64^6
```

Each held-out condition proceeds as follows:

1. reset the raw policy, allow only registered public nonterminal tool
   interactions, and generate one structured-arms-shared raw terminal report;
2. apply `T_x` with each branch's frozen state;
3. before terminal submission, ground-truth, reference-survival, scorer, or
   reward access, atomically commit the raw action, every frozen state hash, and
   every official structured action with both semantic and provenance byte
   hashes using the same no-overwrite protocol;
4. only after rereading and validating the commitment may the pure scorer
   compute official scalar rewards and the separate receipt builder publish
   their exact-key scalar-only receipts; and
5. never generate held-out candidates, update state, expose hidden task fields
   to the system/updater, or let a previous held-out condition affect a later
   one.

The frozen state hash must be identical before every held-out condition in a
branch. LR0 and rollback must take the byte-exact sentinel and therefore have
identical semantic action hashes and rewards condition by condition; their byte
hashes must additionally be identical as a zero-sentinel audit. All structured
official receipts for a held-out item bind the same independently recomputed
scoring-context digest.

## Canonical online-ICL comparator

The comparator remains `cohort_reward_aware_online_icl_v1` with its complete
frozen configuration:

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

Within a block, online ICL and the structured arms share model/tokenizer assets,
adaptation and held-out DGPs, canonical condition order, task, schema, official
scorer, greedy decoding, parser/retry policy, action budget, and maximum token
limits. Online ICL retains its own full-context online trajectory and scalar
official rewards. It creates no adapter, optimizer, distiller, or candidate
sampler and must preserve its registered adaptation snapshot and held-out reset
audits.

Every canonical online-ICL held-out official action must also be atomically
committed with the registered no-overwrite protocol before any scorer,
ground-truth, reference-survival, or reward access. The online-ICL system may
not ingest those hidden fields, and its sealed adaptation snapshot must be
restored before every later held-out condition. For the same block and held-out
instance, its official scalar receipt must bind the same independently
recomputed `scoring_context_sha256` as all structured arms.

The protocols do not claim equal information or compute. Per phase and arm,
report model generation calls, input/output tokens, candidate scorer calls,
official scorer calls, retries, repairs, failures, wall time, GPU-seconds, and
peak allocated memory. Structured active is charged for all sixteen candidate
scores per adaptation item. No score may be described as more sample efficient,
compute efficient, or fairly reward-budget matched on the basis of H2.

## DGP disjointness gate

Smoke, three-block screen, and eight-block confirmation DGPs must be generated
only after the applicable execution trigger and must be pairwise disjoint. The
generator and each stage validator independently compare, for every adaptation
and held-out corpus:

- run and DGP seeds;
- the set of registered instance IDs;
- per-instance database hashes;
- per-instance ground-truth hashes;
- per-instance reference-survival hashes;
- the set of composite row identities
  `(instance_id, database_sha256, ground_truth_sha256,
  reference_survival_sha256)`; and
- aggregate database, ground-truth, schedule, order, and corpus hashes.

The exact pass predicate for every pair of corpora, including adaptation versus
held-out within a block and different blocks within the same stage, is:

```text
dgp_seed_A != dgp_seed_B
intersection(instance_id_set_A, instance_id_set_B) == empty
intersection(per_instance_database_sha256_set_A,
             per_instance_database_sha256_set_B) == empty
intersection(per_instance_ground_truth_sha256_set_A,
             per_instance_ground_truth_sha256_set_B) == empty
intersection(per_instance_reference_survival_sha256_set_A,
             per_instance_reference_survival_sha256_set_B) == empty
intersection(composite_row_identity_set_A,
             composite_row_identity_set_B) == empty
aggregate_database_sha256_A != aggregate_database_sha256_B
aggregate_ground_truth_sha256_A != aggregate_ground_truth_sha256_B
aggregate_schedule_sha256_A != aggregate_schedule_sha256_B
aggregate_order_sha256_A != aggregate_order_sha256_B
aggregate_corpus_sha256_A != aggregate_corpus_sha256_B
```

Run seeds label execution blocks rather than individual corpora: the adaptation
and held-out corpora within one block intentionally share that block's run seed.
Run seeds must be distinct across blocks and stages, but run-seed equality
within a block neither fails nor establishes corpus disjointness. DGP seeds are
corpus-specific and must be pairwise distinct as required above.

Smoke must be disjoint from both formal stages, and the three-block screen must
be disjoint from the eight-block confirmation under every component predicate,
not only instance or aggregate-corpus identity. A collision is an
inventory/provenance failure, not permission to replace only the colliding row
after model execution.
The complete disjointness audit is a pre-launch gate. A collision found before
any model call permits a prospective generator repair with the same registered
seeds followed by regeneration and resealing of the entire affected stage. A
collision first discovered after a model call invalidates the stage and has no
automatic rerun under this preregistration; it requires a prospective amendment
rather than outcome-dependent row replacement.

## Exact schema/retry non-regression gate

For each block and separately for the 20 adaptation positions and 20 held-out
positions, count parser retries and schema-repair invocations from the sealed
raw traces. A retry is one additional model generation after the initial parse
fails. A repair is one registered parser/schema repair invocation; the same
event may increment both registered counters if and only if the trace records
both operations. The endpoint controls are fixed:

```text
control(H1) = closed_loop_lr0
control(H2) = canonical_online_icl
control(H3) = pair_sign_reverse
```

For each `H in {H1,H2,H3}`, block `b`, and
`phase in {adaptation,heldout}`, the exact endpoint predicate is:

```text
hard_schema_failure_count[closed_loop_active,b,phase] == 0
hard_schema_failure_count[control(H),b,phase] == 0
parse_retry_count[closed_loop_active,b,phase]
    <= parse_retry_count[control(H),b,phase]
schema_repair_count[closed_loop_active,b,phase]
    <= schema_repair_count[control(H),b,phase]
```

The structured active/LR0/reverse arms use one shared raw trajectory, so their
raw retry/repair counts must additionally be exactly equal; duplicated branch
accounting is forbidden. Rollback is excluded from this endpoint comparison
because it aliases active adaptation and is an integrity control, not an
independent raw-policy arm. An exhausted hard schema failure is an execution-
integrity failure and takes classification priority. A count inequality with
otherwise valid actions is an endpoint scientific non-regression miss.

## Three-block internal screen

The internal screen uses three independently generated blocks:

| Block | Run seed | Adaptation DGP seed | Held-out DGP seed |
|---:|---:|---:|---:|
| 1 | 2026071501 | 2026071511 | 2026071512 |
| 2 | 2026071502 | 2026071521 | 2026071522 |
| 3 | 2026071503 | 2026071531 | 2026071532 |

Each block contains exactly 20 adaptation and 20 held-out conditions. Before
the first model call, freeze the DGP-generator source, complete arguments,
seeds, schedule, regeneration/failure rule, database and ground-truth hashes,
canonical order, and aggregate corpus hashes. A generation failure is repaired
with the same code and seed; a block may not be replaced.

For endpoint `H` and block `b`, compute only the block-level paired delta:

```text
delta_H[b] = mean over the 20 registered held-out positions of
             (reward_arm_A[b,i] - reward_arm_B[b,i])
```

At `n=3`, report only the three raw block deltas, unweighted mean, median,
sample standard deviation, descriptive two-sided Student-t 95% interval, and
the exact two-sided sign-test p-value. With all three deltas, including zeros,
the descriptive interval is:

```text
mean_delta = (delta_1 + delta_2 + delta_3) / 3
s_delta = sqrt(sum_b (delta_b - mean_delta)^2 / 2)
t_interval = mean_delta +/- 4.302652729911275 * s_delta / sqrt(3)
```

If `s_delta==0`, the interval is the degenerate `[mean_delta,mean_delta]`.
Zeros remain in the mean, median, SD, and t interval. For the descriptive sign
test, let `n_nonzero` exclude exact-zero block deltas, let `n_pos` and `n_neg`
count the remaining signs, and let `k=min(n_pos,n_neg)`:

```text
if n_nonzero == 0:
    p_sign = 1
else:
    p_sign = min(1,
                 2 * sum_(j=0)^k choose(n_nonzero,j) / 2^n_nonzero)
```

The zero count and `n_nonzero` are always reported. With three positive and no
zero blocks, `p_sign=0.25`. Any zero block delta fails the registered
strictly-positive screen gate, but does not stop execution or disappear from
the descriptive statistics.

The inferential unit is the independently generated block. Do not pool 60 rows
as independent evidence, run a hierarchical bootstrap, or treat the t interval
or sign test as confirmation.

All fifteen registered logical cells must finish: for each of three blocks,
`closed_loop_active`, `closed_loop_lr0`, `pair_sign_reverse`,
`closed_loop_rollback`, and `canonical_online_icl`. Endpoints are interpreted
in fixed gatekeeping sequence `H1`, then `H2`, then `H3`. All endpoint
statistics are retained, but H2 can advance the decision only if H1 passes and
H3 can advance it only if both H1 and H2 pass. The internal screen advances
only if, for every endpoint:

1. all three block deltas are strictly positive;
2. the unweighted mean block delta is at least `+0.02` official score units;
3. every cell passes execution integrity;
4. every formal adaptation item passes every registered scientific-signal gate;
5. rollback and LR0 have identical held-out semantic actions/rewards and pass
   the separate sentinel byte-equality audit; and
6. the exact per-endpoint schema/retry non-regression predicate above passes.

The descriptive t-interval lower endpoint and sign-test p-value are not `n=3`
gates. Any gate miss is a valid internal-screen no-go and forbids confirmation,
additional seeds, hyperparameter changes, or another mechanism family.

## Eight-block confirmation

Only a passing three-block internal screen permits the one registered
confirmation. Its wholly new independent blocks are:

| Block | Run seed | Adaptation DGP seed | Held-out DGP seed |
|---:|---:|---:|---:|
| 1 | 2026081001 | 2026081101 | 2026081201 |
| 2 | 2026081002 | 2026081102 | 2026081202 |
| 3 | 2026081003 | 2026081103 | 2026081203 |
| 4 | 2026081004 | 2026081104 | 2026081204 |
| 5 | 2026081005 | 2026081105 | 2026081205 |
| 6 | 2026081006 | 2026081106 | 2026081206 |
| 7 | 2026081007 | 2026081107 | 2026081207 |
| 8 | 2026081008 | 2026081108 | 2026081208 |

Each block again contains exactly 20 adaptation and 20 held-out conditions and
uses exactly five registered logical arms:

```text
closed_loop_active
closed_loop_lr0
pair_sign_reverse
closed_loop_rollback
canonical_online_icl
```

The registered confirmation inventory is therefore exactly `8*5=40` logical
arm-block cells. All 40 cells and their artifact inventory must be complete and
sealed before unblinding, even if an early endpoint or block could no longer
pass.

For each endpoint, retain all eight block deltas, including exact zeros, and
report their mean, median, sample standard deviation, and two-sided 95%
Student-t interval with `df=7`:

```text
mean_delta = (1/8) * sum_(b=1)^8 delta_b
s_delta = sqrt(sum_(b=1)^8 (delta_b-mean_delta)^2 / 7)
t_lower = mean_delta - 2.3646242515927844 * s_delta / sqrt(8)
t_upper = mean_delta + 2.3646242515927844 * s_delta / sqrt(8)
```

For the exact two-sided conditional sign-flip test, define:

```text
T_observed = abs((1/8) * sum_b delta_b)

p_flip = (1/256) * sum over every s in {-1,+1}^8 of
         1[abs((1/8) * sum_b s_b*delta_b) >= T_observed]
```

There is no Monte Carlo approximation and no plus-one correction. Equality is
included in the tail; exact-zero deltas remain zero under both signs and are
retained. This test is conditional on block-level sign exchangeability; it is
not described as design-based randomization inference.

The endpoints are tested in fixed gatekeeping order `H1`, `H2`, `H3`, each at
`alpha=0.05`. H2 is confirmatory only if H1 passes; H3 is confirmatory only if
both H1 and H2 pass. A downstream endpoint is still computed and reported when
an earlier endpoint fails, but it is descriptive and cannot rescue the fixed
sequence. Alpha is not recycled and no endpoint may be reordered. An endpoint
passes only if:

1. sign-flip `p <= 0.05`;
2. mean paired block delta is at least `+0.02`;
3. the 95% t-interval lower endpoint is strictly above zero;
4. all eight blocks and all registered cells are integrity-valid;
5. every formal adaptation item passes every scientific-signal gate;
6. rollback and LR0 have identical held-out semantic actions/rewards and pass
   the separate sentinel byte-equality audit; and
7. the exact per-endpoint schema/retry non-regression predicate above passes.

Only all three passed confirmation endpoints support a demonstrated positive
closed-loop structured-state result. H2 must still be named the **oracle-rich
total-algorithm contrast** in every table, plot, abstract, and conclusion.

## Formal stage classification and whole-stage reruns

Each formal stage has one mutually exclusive stage decision. Classification
uses this fixed priority, regardless of apparent efficacy:

1. If any registered cell is missing or any execution, inventory, provenance,
   DGP-disjointness, poison-test, shared-join, or independent-recomputation
   check fails:

   ```text
   status = "invalid"
   decision = "infrastructure_fail"
   decision_scope = "internal_screen"
                    or "publication_confirmation"
   errors = nonempty redacted error-code list
   publication_grade = false
   efficacy_interpretation_allowed = false
   validator_exit_code = 1
   ```

   The first `decision_scope` value applies to the 15-cell stage and the second
   to the 40-cell stage. Scientific-signal and endpoint gates are not
   interpreted.

2. Otherwise, if any item-level scientific-signal gate or any applicable
   endpoint gate misses:

   ```text
   status = "valid"
   decision = "valid_no_go"
   decision_scope = "internal_screen_no_go"
                    or "publication_confirmation_no_go"
   errors = []
   publication_grade = false for the 15-cell stage;
                       true for the complete integrity-valid 40-cell stage
   efficacy_interpretation_allowed = true
   validator_exit_code = 0
   ```

3. Otherwise:

   ```text
   status = "pass"
   decision = "pass"
   decision_scope = "internal_screen_pass"
                    or "publication_confirmation_pass"
   errors = []
   publication_grade = false for the 15-cell stage;
                       true for the complete integrity-valid 40-cell stage
   efficacy_interpretation_allowed = true
   validator_exit_code = 0
   ```

The three-block report always has `publication_grade=false`. The confirmation
report may set `publication_grade=true` only when all 40 registered cells are
complete and integrity-valid; this does not weaken the separate claim-boundary
rules for zero, harm, or H2.

An invalid smoke, screen, or confirmation attempt can never be repaired by
rerunning or replacing only a cell and combining it with cells from the failed
attempt. The entire registered stage must run again under a new no-overwrite
`attempt_id`, with all prior artifacts retained and bound. Seeds, DGP bytes,
condition order, mechanism constants, arms, endpoints, and analysis remain
identical. A bounded infrastructure-only source repair is permitted only if it
does not change the registered mechanism or statistical plan; its diff and new
source hash are sealed before the whole-stage rerun. No artifact or decision
field may be spliced across attempt IDs. The only exception is the late-
discovered DGP collision case above, which has no automatic rerun and instead
requires a prospective amendment.

A complete, integrity-valid `valid_no_go` is a scientific result and is never
rerun. This priority is absolute: `infrastructure_fail` dominates a simultaneous
signal miss, a signal/endpoint miss dominates pass, and apparent positive
efficacy never overrides either class.

## Blinding, completion, and no favorable stopping

During either formal stage, operational visibility is restricted to liveness,
resource use, integrity hashes, completion counts, and no-overwrite status. No
operator or analysis process may inspect arm rewards, state directions,
scientific-signal summaries, block deltas, or a partial endpoint aggregate
until every registered arm and block in that stage is complete and the artifact
inventory is sealed.

Every formal item and every registered cell must run to completion even when a
candidate pair ties, `g_t=0`, an item misses a scientific-signal gate, an early
block delta is unfavorable, or an endpoint could no longer pass. The registered
`sign(0)=0` transition is applied and execution continues. There is no favorable
stopping, futility stopping, item replacement, candidate resampling, block
replacement, or seed addition.

A scientific-signal gate miss or unfavorable efficacy threshold in a complete,
integrity-valid formal stage is a valid scientific `valid_no_go`. It is never
relabelled as infrastructure failure. Conversely, an execution-integrity
failure is invalid evidence and is never counted as a scientific no-go; its
only permitted retry is the whole-stage attempt defined above.

## Negative-result and claim boundaries

A valid no-go means only that this registered structured-state mechanism did
not demonstrate a positive effect under the frozen protocol. It does not prove
zero effect or harm. Excluding a practically useful effect of `+0.02` requires
a publication-grade one-sided 95% upper bound below `+0.02`; claiming harm
requires that bound below zero.

If the three-block screen or eight-block confirmation is a valid no-go, this
mechanism family terminates. No state-size, `d`, `rho`, candidate-count,
Hadamard, `eta`, sign rule, transform, prompt, context, LR, reward, DGP, or seed
sweep follows. Raw artifacts, failed scientific-signal gates, exact-zero audits,
and all negative block deltas remain part of the final report.

## Required sealed artifacts

Every smoke, screen, or confirmation seal must bind at least:

- the applicable Trigger A or Trigger B original and revalidation decision
  bytes/hashes, exact inventories, revalidation code, causal protocol-seal
  `not_applicable` marker, the causal PID/exit files and independent
  no-overwrite completion attestation, and the prospective machine-verifiable
  online wrapper completion evidence plus real online protocol seal when
  applicable;
- source commit, this preregistration, environment lock, model/tokenizer assets,
  task/schema/scorer files, and cohort-layer inventory;
- grids, DGP generator arguments, seeds, databases, ground truth, schedules,
  orders, corpus hashes, and all pairwise DGP-disjointness checks;
- raw-policy configuration and complete model-state hashes;
- every pre-reveal action/candidate commitment and reward receipt;
- raw, official, and candidate action bytes, semantic-action hashes, and
  provenance byte hashes;
- shared raw trajectory and exact cross-branch join records, opaque scoring
  handles, public scoring-context attestations, hidden-registry inventory
  digests, scoring-context digests, scalar-only receipts, and poison-test logs;
- all state-before/state-after float hex values and hash chains;
- Hadamard, probe-balance, candidate-uniqueness, diversity, rank, bound, and clip
  audits per item;
- independent recomputation output and every required mutation-test result;
- exact-zero sentinel tests and rollback/LR0 held-out equality;
- held-out pre-reveal commitments and frozen-state audits;
- canonical online-ICL context, snapshot, no-update, and reset audits;
- phase-separated information and compute accounting;
- every per-condition outcome, block delta, descriptive statistic, threshold
  check, and fixed-sequence decision; and
- stage attempt IDs, the three-level classification audit, and a no-overwrite
  artifact inventory whose digest is sealed before unblinding.

Tampering, hidden overwrite, missing provenance, unregistered fallback output,
post-outcome protocol change, hidden ground-truth access, partial unblinding,
or failure to preserve a valid negative result invalidates the affected claim.
