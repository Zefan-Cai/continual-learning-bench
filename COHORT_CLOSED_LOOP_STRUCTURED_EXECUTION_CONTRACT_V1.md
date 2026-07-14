# Prospective Execution Contract: Closed-Loop Structured-State TTT-RL

## Status

This document freezes the production execution topology for
`cohort_closed_loop_structured_state_ttt_rl_v1`. It supplements, and does not
replace, `COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md`.

This document, source code, tests, and non-outcome configuration may be prepared
before an execution trigger. They do not authorize a production DGP, model
call, scorer call, or output. A production DGP is permitted only after the
trigger, protocol-plan seal, stage plan, and DGP generation claim have been
published and revalidated. A model or scorer import/call remains forbidden
until the later launch chain is complete.

The existing
`cohort_closed_loop_structured_state_trigger_execution_seal_v1` is trigger
evidence only. It is not a structured protocol seal, a stage plan, or a model-
call capability.

## One-way authorization state machine

The primary production transition is:

```text
prospective code and preregistration
  -> valid trigger receipt
  -> structured protocol-plan seal
  -> per-stage plan
  -> DGP generation claim
  -> sealed DGP/context manifest and completion receipt
  -> per-stage structured protocol seal
  -> launch expectation
  -> prelaunch gate
  -> single-use launch claim
  -> first model or scorer import/call
```

The authorization scopes are exact:

| Artifact | Authorization scope | Model/scorer calls |
|---|---|---:|
| trigger receipt | publish one structured protocol-plan seal | forbidden |
| structured protocol-plan seal | publish the registered next stage plan | forbidden |
| stage plan | generate only the declared DGP/context outputs | forbidden |
| DGP generation claim | write only the plan-declared DGP/context outputs | forbidden |
| per-stage structured protocol seal | publish one launch expectation | forbidden |
| launch expectation | build one prelaunch gate | forbidden |
| prelaunch gate | create one exact registered launch claim | not yet permitted |
| single-use launch claim | exact bound launcher invocation | permitted |

The only retry subgraph is:

```text
closed infrastructure-failed stage attempt
  -> failed-attempt closure receipt
  -> retry authorization receipt
     -> same-source new stage-attempt plan
     or
     -> bounded-repair new source commit and experiment attempt
        -> replacement protocol-plan seal
        -> new whole-stage plan
```

The failed-attempt closure receipt authorizes only construction of one retry
receipt. A `same_source_whole_stage_retry` receipt authorizes exactly one new
stage plan under the existing protocol-plan seal. A
`bounded_source_repair_whole_stage_retry` receipt authorizes exactly one
replacement protocol-plan seal under the new source commit, and that seal
authorizes exactly one new whole-stage plan. Both transitions bind every prior
attempt. No other failure edge exists; valid no-go/pass and a post-model DGP
collision are terminal under this contract.

The launcher must create the single-use launch claim with `O_CREAT|O_EXCL`
before importing a model runtime, task, scorer, context resolver, or runner
module. Existing claim bytes, any upstream byte drift, or any command, cwd,
environment, boot, node, or process mismatch causes exit before the first
import or call.

There is no direct transition, optional bypass, truthy shortcut, operator
override, `latest` path, or digest-only substitute. A downstream artifact binds
`SHA256(file_bytes(upstream))`, not only an embedded self-digest or a parsed
object. A failed builder produces no usable downstream authorization chain and
may leave only reserved or poison paths that permanently fail that attempt.

## Canonical bytes and publication

All authorization objects use one JSON encoding:

```text
UTF-8
sorted object keys
compact separators ',' and ':'
ensure_ascii = true
allow_nan = false
no trailing newline
```

Loaders reject duplicate object keys, nonfinite numbers, extra or missing keys,
and type substitution, including `bool` for an integer. SHA-256 values are
exactly 64 lowercase hexadecimal characters. Git commit IDs are exactly 40
lowercase hexadecimal characters. Absolute paths must be normalized and must
remain beneath their registered real-directory root.

Every authorization artifact has a self-digest computed over its canonical
object with only that self-digest field omitted. Downstream artifacts also bind
the full file SHA-256 and size of every upstream artifact.

Every authorization-artifact publication begins with a deterministic
`O_CREAT|O_EXCL` intent sidecar and a unique `O_CREAT|O_EXCL` pending file,
using `O_NOFOLLOW` and directory file descriptors anchored beneath the
registered root. The publisher writes, fsyncs, changes the pending file to
exactly `0444`, and fsyncs again before atomically hard-linking it to the final
no-replace pathname. It fsyncs the parent and freshly retraverses every ancestor
to verify directory identities, intent bytes, pending/final inode equality, and
complete bytes while the final link count is two. Removing the pending link is
the commit point. A valid committed artifact therefore requires the exact
intent, an absent registered pending name, a final link count of one, and two
matching fresh full-path observations.

For a registered root-relative final path `P`, let `H = SHA256(ASCII(P))`.
The two sidecar basenames are exactly:

```text
publish-intent-<H>.json
publish-pending-<H>.bin
```

They are stored in the final artifact's registered parent directory. Here
"unique" means unique to the registered final path: neither name contains
runtime randomness. This makes both paths prospectively enumerable while the
intent's `O_EXCL` creation remains the concurrency serialization point.

Intent and pending paths are part of the closed inventory. A pre-commit failure
never removes them; an existing intent forbids reuse even when the final path is
absent. A failure after final linking but before pending-link removal leaves
link-count-two poison. Pending-link removal is the commit point; a later
durability or fresh-observation failure leaves the single-link final and intent
reserved, closes the attempt as a post-commit infrastructure failure, and may
not authorize automatic retry or path reuse. The publisher runs under the
registered dedicated service identity in a root it
owns that is not group/other writable; the protocol-plan seal binds that
ownership/access-policy and mount-identity attestation. The portable publisher
itself rejects symlink traversal and cross-device descent. A separate platform
attestation rejects a same-device alternate/bind mount before any artifact is
trusted. Non-regular files, overwrite, rename-over-final, unlink-and-retry, and
partially written replacement are forbidden. Mere valid-looking file bytes are
never authority without the successful enclosing builder/wrapper chain.

## Trigger branches

Only the two trigger branches in the parent preregistration exist:

```text
causal_valid_no_go
causal_pass_online_internal_screen_valid_no_go
```

Trigger A requires the exact revalidated causal decision class and scope:

```text
valid_no_go
internal_gate_no_go
```

Its online-ICL trigger record is exactly null.

Trigger B requires the exact revalidated causal decision class and scope:

```text
pass
internal_gate_pass
```

and a non-null, independently revalidated online-ICL record with:

```text
valid_no_go
internal_screen
effective_n = 3
publication_grade = false
```

The online record binds its original and revalidated decision file bytes, real
online protocol seal, wrapper contract, held-lifetime lock contract, atomic
completion marker, complete inventory, and causal-decision digest join. The
current trigger builder is Trigger-A-only. Trigger B remains unavailable until
its separate prospective online plan extension is published before the first
online formal model call.

Trigger C does not exist. If both upstream internal screens pass, this
structured pivot is forbidden unless the parent preregistration's separate
prospective parameter-route confirmation addendum is completed before any
parameter-route confirmation DGP or model call.

The normalized trigger receipt has the exact top-level schema:

```text
protocol
schema_version
status
attempt_id
trigger_branch
tooling_source_commit
structured_preregistration
trigger_execution_seal
trigger_validator_inventory
causal
online_icl
pretrigger_absence_evidence
created_at_utc
trigger_receipt_sha256
```

The receipt builder consumes and binds the full bytes of the existing trigger
execution seal; it does not reinterpret that file as a structured protocol
seal. Its independently hashed revalidator repeats every parent-preregistered
top-level causal predicate, validates the original/revalidated decision byte
equality, and binds the complete causal inventory, completion attestation,
revalidation receipt, PID/exit digests, original and revalidated decisions,
causal decision canonical digest, and explicit causal-protocol-seal null/N/A
status. Trigger A requires `online_icl=null`.

For Trigger B, the non-null `online_icl` record additionally repeats every
parent-preregistered top-level and nested protocol/schema/status predicate and
binds the original/revalidated decision bytes, real online protocol seal,
wrapper contract, held-lifetime lock contract, atomic completion marker,
revalidation receipt, complete inventory, and causal-decision digest join.
Unknown branches, missing evidence, a pass-shaped object not reconstructed from
the registered raw bytes, or any weaker Trigger-B predicate are rejected.

The trigger receipt and protocol-plan-seal builder each require a fresh absence
attestation proving that no production structured DGP, context registry,
precommit, receipt, raw trace, model output, report, or decision exists beneath
the registered structured durable root.

## Fixed roots and identifiers

Let:

```text
SOURCE_COMMIT = exact 40-hex implementation commit
EXPERIMENT_ATTEMPT_ID = attempt-[0-9]{3}
STAGE_ATTEMPT_ID = attempt-[0-9]{3}
```

The exact production roots are:

```text
checkout_root =
  /mnt/localssd/ttt-rl-cohort-structured-state/
  <SOURCE_COMMIT>/<EXPERIMENT_ATTEMPT_ID>

durable_root =
  /sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/
  <SOURCE_COMMIT>/attempts/<EXPERIMENT_ATTEMPT_ID>
```

Both roots are real directories. The checkout is clean at `SOURCE_COMMIT`.
Production artifacts are written directly beneath `durable_root`; no artifact
root is a symlink into or out of it.

The common control layout is:

```text
<durable_root>/control/source_inventory.json
<durable_root>/control/asset_inventory.json
<durable_root>/control/trigger_receipt.json
<durable_root>/control/structured_protocol_plan_seal.json
```

The exact stage roots are:

```text
<durable_root>/stages/smoke/<STAGE_ATTEMPT_ID>
<durable_root>/stages/internal/<STAGE_ATTEMPT_ID>
<durable_root>/stages/confirmation/<STAGE_ATTEMPT_ID>
```

Within a stage root, the fixed control files are:

```text
control/stage_plan.json
control/dgp_generation.claim.json
control/dgp_completion_receipt.json
control/structured_stage_protocol_seal.json
control/launch_expectation.json
control/prelaunch_gate.json
control/launch.claim.json
control/wrapper.pid
control/wrapper.lock
control/wrapper.exit.json
control/completion_marker.json
control/private_validation_receipt.json
control/private_validation_revalidation_receipt.json
control/poison_test_receipt.json
control/stage_report.revalidated.json
control/failed_attempt_closure_receipt.json
control/retry_authorization_receipt.json
control/stage_transition_receipt.json
control/sealed_artifact_inventory.json
dgp/stage_manifest.json
reports/stage_report.json
```

No `latest`, implicit attempt, glob-selected input, or fallback output is valid.
A whole-stage retry is forbidden unless one of the exact retry transitions
below exists. A valid scientific no-go or pass is never retried.

## Protocol-plan seal source and asset inventory

The structured protocol-plan seal cannot be published until exact source records
exist for all of these roles:

```text
structured_state
structured_commitments
structured_execution_validation
structured_dgp_context_validation
structured_stage_authorization
structured_atomic_publisher
trigger_receipt_builder
trigger_receipt_revalidator
dgp_generator
context_registrar
pure_scorer
stage_grid_builder
runner
launcher
wrapper
provenance_builder
protocol_seal_builder
stage_plan_builder
dgp_completion_validator
stage_protocol_seal_builder
launch_expectation_builder
prelaunch_gate_builder
stage_assembler
smoke_validator
formal_validator
independent_private_validator
report_serializer
environment_lock
private_context_access_boundary
```

Each source record has exact role, path, size, and SHA-256. No role may share a
mutable pathname or be satisfied by an untracked or dirty file. The protocol-
plan seal binds the clean source commit and the complete sorted inventory.

The exact asset roles are:

```text
model_config
model_state_dict
tokenizer
environment
task
schema
official_scorer
cohort_layer_inventory
structured_raw_policy_config
canonical_online_icl_config
```

The raw-policy and canonical comparator configurations are the exact canonical
objects in the parent preregistration. The complete model state, including
persistent buffers, is hashed before and after each block. The protocol-plan
seal and per-stage protocol seal bind the model/tokenizer roots and their closed
file inventories; a directory name alone is not an asset digest.

The protocol-plan seal also freezes the DGP generator source, runtime, full
argument schema, fixed seed tables, regeneration/failure rule, output schema,
and canonical ordering. It does not contain or predict generated DGP output
hashes. Those hashes first appear after plan-authorized generation and are bound
by the DGP completion receipt.

After DGP/context generation and independent public-integrity validation, each
stage publishes a distinct `structured_stage_protocol_seal`. This is the
"structured-state protocol seal" required by the parent preregistration. It
binds the trigger receipt, protocol-plan seal, stage plan, DGP claim, DGP
completion receipt, exact current and prior DGP manifest file bytes, complete
public context-attestation inventory, hidden-registry inventory digest,
source/assets/configuration, and the complete declared scientific input
inventory. The stage report's `protocol_seal_sha256` is exactly the full file
SHA-256 of this per-stage seal. The launch expectation and every runner output
bind the same full file bytes. A protocol-plan seal is never accepted in that
field.

## Registered stages and accounting

The arm order is exact:

```text
closed_loop_active
closed_loop_lr0
pair_sign_reverse
closed_loop_rollback
canonical_online_icl
```

For a stage with `B` blocks and `N` adaptation plus `N` held-out conditions per
block, the exact logical accounting is:

```text
logical_arm_cells            = 5 * B
corpora                      = 2 * B
DGP rows                     = 2 * B * N
public context identities    = 2 * B * N
precommit bundles            = 4 * B * N
candidate scorer receipts    = 48 * B * N
official scorer receipts     = 9 * B * N
all scalar scorer receipts   = 57 * B * N
initial model generations    = 4 * B * N
maximum generation attempts  = 12 * B * N
```

The concrete stage registry is:

| Stage | B | N | Cells | Corpora | Rows/contexts | Precommits | Candidate receipts | Official receipts | All receipts | Initial generations | Max attempts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| smoke | 1 | 5 | 5 | 2 | 10 | 20 | 240 | 45 | 285 | 20 | 60 |
| internal | 3 | 20 | 15 | 6 | 120 | 240 | 2880 | 540 | 3420 | 240 | 720 |
| confirmation | 8 | 20 | 40 | 16 | 320 | 640 | 7680 | 1440 | 9120 | 640 | 1920 |

Across all three stages the registered maxima are 60 cells, 24 corpora, 450
rows/contexts, 900 precommit bundles, 12,825 scalar receipts, 900 initial model
generations, and 2,700 maximum attempts.

Per block, active, LR0, and pair-sign-reverse each receive `18*N` physical
scorer calls: `16*N` candidates, `N` adaptation official actions, and `N`
held-out official actions. Rollback has only `N` held-out official calls; its
adaptation chain aliases active and it has no candidate calls. Canonical online
ICL has `2*N` official calls. Identical item-1 candidate action bytes across
structured branches do not permit scorer-call deduplication: all registered
`48*N` branch/candidate invocations and receipts must exist in deterministic
branch/candidate order.

There are exactly two initial model generations per condition: one shared raw
structured trajectory and one canonical online-ICL trajectory. Across both
phases this is `4*N` per block. With `parse_retries=2`, each initial generation
has at most two additional attempts. Four separate structured raw-policy
generations, model-generated candidates, rollback adaptation generations, and
held-out candidates are forbidden.

There are exactly two precommit bundles per DGP row:

```text
structured
canonical_online_icl
```

The adaptation structured bundle contains active, LR0, and pair-sign-reverse
official actions plus all 48 candidate actions. The held-out structured bundle
contains the four structured official actions and no candidate. The canonical
bundle contains one official action and no candidate in either phase.

## Exact block and item layout

Blocks and corpus order are the exact identifiers defined by
`cohort_closed_loop_structured_dgp_context.py`. Under a stage root:

```text
dgp/corpora/<block_id>/<phase>/corpus_inventory.json
dgp/corpora/<block_id>/<phase>/rows/<item_id>.json
contexts/<block_id>/<phase>/<item_id>/public_attestation.json
contexts/<block_id>/<phase>/<item_id>/registry_digest_record.json
raw_traces/<block_id>/<phase>/<item_id>/structured_shared.json
raw_traces/<block_id>/<phase>/<item_id>/canonical_online_icl.json
precommits/<block_id>/<phase>/<item_id>/structured.json
precommits/<block_id>/<phase>/<item_id>/canonical_online_icl.json
```

Adaptation scalar receipts are:

```text
receipts/<block_id>/adaptation/<item_id>/structured/
  closed_loop_active/official.json
  closed_loop_active/candidates/<candidate_id>.json
  closed_loop_lr0/official.json
  closed_loop_lr0/candidates/<candidate_id>.json
  pair_sign_reverse/official.json
  pair_sign_reverse/candidates/<candidate_id>.json
receipts/<block_id>/adaptation/<item_id>/canonical_online_icl/official.json
```

Held-out scalar receipts are:

```text
receipts/<block_id>/held_out/<item_id>/structured/
  closed_loop_active/official.json
  closed_loop_lr0/official.json
  pair_sign_reverse/official.json
  closed_loop_rollback/official.json
receipts/<block_id>/held_out/<item_id>/canonical_online_icl/official.json
```

The fixed candidate order is Hadamard row `0..7`, with `plus` then `minus` for
each row. The candidate ID grammar and exact mapping are frozen by the stage
grid; no receipt may be reused for another branch, candidate, item, or context.

State and lifecycle artifacts are:

```text
states/<block_id>/adaptation/<item_id>/<branch>.json
states/<block_id>/held_out/<item_id>/<branch>.json
snapshots/<block_id>/canonical_online_icl/adaptation_complete.json
restorations/<block_id>/held_out/<item_id>/canonical_online_icl.json
cell_manifests/<block_id>/<arm>.json
compute/<block_id>/<arm>/<phase>.json
```

The `<branch>` expansion is exactly, in this order:

```text
closed_loop_active
closed_loop_lr0
pair_sign_reverse
closed_loop_rollback
```

During adaptation, rollback's state artifact is an immutable alias receipt that
binds the active chain; it is not a second update or scorer invocation. During
held-out, every state artifact binds the frozen state and records no update.

Independent validation evidence is stored only at the fixed control paths
`private_validation_receipt.json`,
`private_validation_revalidation_receipt.json`, `poison_test_receipt.json`, and
`stage_report.revalidated.json`. These paths are part of the complete static
inventory and cannot be supplied as optional extras.

One static enumerator, itself source-bound by the protocol-plan seal, expands these
templates into the complete sorted expected path inventory before the stage
plan is published. The plan stores every relative path and expected artifact
role; wildcards and count-only closure are insufficient. For every base final
artifact path it also adds exactly one deterministic
`atomic_publication_intent` record and one deterministic
`atomic_publication_pending_absent` record using the naming rule above. Publication
sidecars are not recursively expanded into sidecars of their own. A successful
sealed inventory requires every registered intent to exist with exact bytes and
every registered pending path to be absent; a poison closure instead preserves
and reports the applicable pending path.

Hidden registry contents are never stored beneath the operator-readable
`durable_root`. Before a protocol-plan seal can exist, deployment must register
a separate `private_context_root` protected by a distinct service identity and
an access-control boundary that denies the experiment operator and launcher
direct read access while allowing only the registrar, pure-scorer service, and
independent private-validator service. The public durable tree stores only the
registered digest record and public attestation shown above.

The protocol-plan seal binds the private service identity, private-root
attestation, access-policy digest, and positive/negative access-test receipt.
The prelaunch gate is invalid unless a fresh test proves the permitted services
can resolve a registered test handle and the operator/launcher identities
cannot read or enumerate the private registry. Same-UID file permissions, an
ordinary `0700` subdirectory, an environment variable, or an operator-held
encryption key does not satisfy this boundary. If the platform cannot provide
the boundary, production execution remains blocked.

## Stage plan and DGP generation

Every completed stage publishes a no-overwrite transition receipt with the
exact top-level schema:

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
experiment_attempt_id
stage_attempt_id
stage_kind
trigger_receipt
protocol_plan_seal
stage_plan
dgp_completion_receipt
stage_protocol_seal
completion_marker
sealed_artifact_inventory
stage_report
stage_report_revalidated
private_validation_receipt
private_validation_revalidation_receipt
poison_test_receipt
validator_source_inventory
prior_transition_receipts
created_at_utc
stage_transition_receipt_sha256
```

Every named evidence field is a full path/size/file-SHA binding. The independent
private validator reconstructs scorer receipts from hidden context and sealed
actions; the report revalidator reconstructs the complete report from raw
artifacts without trusting its decision or aggregate fields. Original and
revalidated report bytes must be identical. The transition receipt binds the
complete attempt, not a pass-shaped projection, timestamp, or standalone
classifier.

The smoke stage has no parent transition. The internal stage plan requires an
exact smoke transition receipt whose validated fields are:

```text
protocol = cohort_closed_loop_structured_smoke_v1
schema_version = 1
status = pass
decision = pass
decision_scope = mechanism_smoke_pass
errors = []
publication_grade = false
efficacy_interpretation_allowed = false
validator_exit_code = 0
grid_sha256 = registered grid SHA256
provenance_sha256 = registered provenance SHA256
protocol_seal_sha256 = full structured_stage_protocol_seal file SHA256
trigger_inventory_sha256 = registered trigger inventory SHA256
report_file_sha256 = bound stage_report full file SHA256
```

The internal-plan builder reruns this full predicate from the bound smoke report
and revalidated report bytes, then validates the transition receipt, completion
marker, sealed smoke inventory, private-validation pair, poison receipt,
validator sources, exact smoke DGP/context stage-manifest bytes, and all common
attempt joins.

The confirmation plan requires an exact internal transition receipt with:

```text
protocol = cohort_closed_loop_structured_internal_screen_v1
schema_version = 1
status = pass
decision = pass
decision_scope = internal_screen_pass
errors = []
publication_grade = false
efficacy_interpretation_allowed = true
validator_exit_code = 0
grid_sha256 = registered grid SHA256
provenance_sha256 = registered provenance SHA256
protocol_seal_sha256 = full structured_stage_protocol_seal file SHA256
trigger_inventory_sha256 = registered trigger inventory SHA256
report_file_sha256 = bound stage_report full file SHA256
```

It binds the exact smoke and internal manifest file bytes, the exact smoke and
internal transition receipts, full internal report/revalidation/private-
validation/completion evidence, and verifies that the internal manifest itself
binds that same smoke manifest. A no-go, invalid, partial, substituted, or
different-attempt transition cannot create a later plan.

The confirmation-plan builder independently reconstructs the internal report,
requires original and revalidated report bytes to match, reruns every field of
the predicate above, and revalidates the transition receipt, completion marker,
sealed inventory, private-validation pair, poison receipt, validator sources,
protocol-seal/trigger/grid/provenance joins, and exact parent-attempt chain. It
does not authorize from bound report bytes without semantic reconstruction.

Before writing any DGP output, the generator creates
`control/dgp_generation.claim.json` with `O_CREAT|O_EXCL`. It binds the trigger
receipt, protocol-plan seal, stage plan full file hashes, generator source and
runtime, exact argv/cwd/nonsecret-environment digest, process ID/start ticks,
boot ID, node identity, and the complete output path inventory. It may then
write only declared DGP/context paths.

After DGP/context publication, an independent validator uses raw canonical
current/prior manifest bytes to run the complete stage-integrity validation.
It publishes `control/dgp_completion_receipt.json`, binding:

- the stage plan and DGP claim full file hashes;
- the complete DGP/context file inventory;
- the current stage manifest full file hash;
- exact prior stage manifest full file hashes in registered order;
- the frozen DGP generator digest across current and prior stages;
- seed, shape, row, context-coverage, aggregate, and pairwise-disjointness
  recomputation; and
- hidden-registry inventory digest metadata, while explicitly setting hidden-
  registry-content validation and scorer reexecution to false.

The completion receipt closes the plan-to-DGP edge. The DGP manifest alone is
not launch authority.

## Whole-stage retry transitions

A second plan for the same stage requires a separately published
`failed_attempt_closure_receipt` and `retry_authorization_receipt`. The closure
receipt is created only after the prior wrapper and every child are absent, its
lock is acquirable by the verifier, no live/temporary artifact remains, and two
stable full-inventory snapshots match. It binds the complete prior attempt,
wrapper/claim/PID/exit/completion evidence, sealed partial-or-complete inventory,
validator sources, and one exact three-level classification.

Retry is eligible only when independent validation reconstructs:

```text
status = invalid
decision = infrastructure_fail
errors = nonempty redacted registered codes
```

and the failure is not a valid scientific no-go or pass. The retry receipt has
an exact discriminated `retry_kind`:

```text
same_source_whole_stage_retry
bounded_source_repair_whole_stage_retry
```

`same_source_whole_stage_retry` keeps the source commit, protocol-plan seal,
mechanism constants, seeds, DGP bytes when already validly generated, condition
order, arms, endpoints, thresholds, and analysis identical. It uses a new stage
attempt ID, binds the closed failed attempt and every earlier attempt, and may
not splice any prior cell or output.

`bounded_source_repair_whole_stage_retry` binds a registered infrastructure-only
failure code, the exact old and new source commits, a complete patch/diff file,
independent review receipt, invariant comparison, and the closed failed attempt.
It creates a new experiment attempt under the new source commit, a new source
inventory, and a new protocol-plan seal that in turn binds the old trigger and
failed attempt. The repair may not change mechanism constants, arms, seeds,
DGPs except for the specific pre-model collision repair below, estimands,
thresholds, endpoint order, statistical analysis, or claim boundary.

The retry receipt records whether any model/scorer claim was created and whether
a DGP collision was detected. A DGP collision found before any model/scorer
claim permits only the parent-preregistered generator repair with the same
seeds, full affected-stage regeneration, a bounded-source-repair transition,
and a newly sealed complete stage. A DGP collision first discovered after a
model/scorer claim or call has no automatic retry under this contract. Its
retry classifier is exactly `prospective_amendment_required`, which is not an
authorizing transition. Missing retry evidence, an unknown failure, changed
science bytes, a reused attempt ID, or an earlier `valid_no_go`/`pass` forbids a
new stage plan.

## Launch expectation and prelaunch gate

The launch expectation binds full bytes for the trigger receipt, protocol-plan
seal, per-stage structured protocol seal, stage plan, DGP claim, DGP completion
receipt, current/prior DGP manifests,
source inventory, asset inventory, preregistrations, grids, environment, model,
tokenizer, task, schema, scorer, cohort layers, raw-policy configuration,
canonical online-ICL configuration, launcher, wrapper, runner, validators, and
report serializer.

It freezes exact executable path and version, argv, cwd, nonsecret environment
digest, GPU/resource shape, boot ID, node/job identity, artifact root,
claim/PID/lock/exit/completion paths, and the complete expected output path
inventory. A prelaunch absence snapshot proves every production output is
absent and no process references the stage checkout or artifact root.

The prelaunch gate is the sole artifact that may lead to a model/scorer call.
It is published only after fresh revalidation of every upstream full byte and
all of these exact checks:

```text
upstream_full_bytes_match = true
trigger_branch_and_attempt_join = true
source_prereg_and_assets_match = true
parent_transition_valid = true
dgp_plan_and_claim_join = true
dgp_seed_shape_and_disjointness_valid = true
public_context_coverage_valid = true
prior_stage_chain_valid = true
canonical_comparator_bound = true
expected_output_inventory_closed = true
prelaunch_outputs_absent = true
prelaunch_process_absent = true
launcher_contract_matches = true
forbidden_efficacy_fields_absent = true
```

The gate is single-use and binds the exact expected launch-claim path and
launcher argv digest. It cannot authorize DGP mutation, a different stage, a
different attempt, or a second launch. The launcher repeats all checks and
creates the claim before any scientific import/call.

## Outcome blindness and unblinding

Trigger receipts, protocol seals, stage plans, DGP claims/completion receipts,
launch expectations, and prelaunch gates contain no score, reward, delta,
efficacy summary, state value/direction, per-item sign, `g`, ground truth,
reference, or raw error text. Necessary trigger and parent-transition decision
enums are the only scientific classifiers permitted in authorization objects.
Ground-truth and reference digests are allowed only inside the sealed DGP/
context inventory required for integrity and disjointness; their contents are
not operator-visible.

During a formal stage, only liveness, resource use, artifact counts, hashes,
and no-overwrite status may be observed. Every registered cell and item must
complete before the sealed artifact inventory, completion marker, stage report,
and transition receipt are published. Formal efficacy bytes remain unopened
until the complete stage inventory is sealed and independently validated.

## Remaining production blockers

This document does not claim the production runtime already exists. Before the
first trigger-authorized DGP generation, all source roles above must exist,
their exact bytes must be clean and committed, and independent tests must show:

1. the filesystem publisher enforces anchored no-symlink, single-link,
   no-overwrite `0444` publication and poison-file semantics;
2. the stage enumerator produces the complete exact path inventory and counts;
3. the DGP generator and completion validator bind the stage plan and claim;
4. canonical comparator inputs are mandatory, not optional;
5. runner/scorer ordering and the no-dedup accounting above are exact;
6. the distinct private service identity enforces the negative operator/
   launcher access test, while the private validator resolves hidden context,
   reruns the pure scorer, and compares exact scalar receipt bytes;
7. the wrapper holds its lock, waits for all children, publishes an atomic
   completion marker, and releases the lock only after closure;
8. the smoke/formal report schemas and serializers are exact and independently
   reconstructed; and
9. AST and runtime call-counter tests prove zero model/scorer import or call
   before the single-use launch claim.

Until every blocker is closed and bound into both the protocol-plan seal and
the applicable per-stage protocol seal, no prelaunch gate is valid and no model
call or scorer call is authorized. A production DGP remains separately gated by
the trigger, protocol-plan seal, stage plan, and DGP generation claim.
