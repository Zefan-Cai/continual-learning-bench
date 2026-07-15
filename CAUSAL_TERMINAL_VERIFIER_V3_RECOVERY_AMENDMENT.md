# Causal terminal verifier V3 recovery amendment

Status: outcome-blind recovery foundation for one already observed filesystem
timestamp incident. This amendment changes no causal input, grid, estimator,
threshold, branch rule, or efficacy-bearing byte.

## Exact incident and claim boundary

V2 required the wrapper exit-file mtime to be strictly later than both formal
outputs. The registered attempt instead has the one allowed relation

`formal_manifest.mtime_ns < formal_decision.mtime_ns == causal_formal.exit.mtime_ns`

with decision and exit mtimes exactly on an integer-second boundary and exit
bytes exactly `0\n`. V3 classifies this as
`v2_equal_second_strict_mtime_false_negative`. It does **not** reinterpret a
different ordering, a merely equal floor-second, a subsecond tie, a nonzero or
noncanonical exit, or any live process. The public truth literals are:

- `completion_method = "post-wrapper-death two-snapshot fence"`
- `mtime_relation = "formal_manifest_before_formal_decision_equal_wrapper_exit"`
- `legacy_strict_mtime_proof = false`
- `historical_exit_order_claimed = false`

The formal manifest and decision are opened only as opaque regular files for
path, stat metadata, size, and SHA-256. They are never JSON-decoded or
semantically interpreted by the recovery freezer. Therefore neither recovery
document reveals or predicts the causal result.

## Two no-overwrite phases

The first phase publishes
`control/CAUSAL_TERMINAL_VERIFIER_V2_FAILURE_CLOSURE_V1.json` with protocol
`cohort_causal_terminal_verifier_v2_failure_closure_v1`, schema 1, and status
`closed_equal_second_false_negative`. It binds the exact incident, launch
expectation, canonical V2 plan, canonical procfs inventory, canonical detached
receipt, recovery source, and exact wrapper PID/start identity. It records only
that the receipt process is gone, the wrapper process is gone, the exact
equal-second predicate is incompatible with V2's legacy strict-mtime gate, and
no V1, V2, or V3 downstream attestation/revalidation/seal output exists. It
does not claim a known attester exit code or a successful V2 attestation.

The closure authorizes one successful link-based no-overwrite publication at
the exact path
`control/CAUSAL_TERMINAL_VERIFIER_COMPLETION_FENCE_V3.json`. The second phase
consumes that immutable closure and publishes the fence with protocol
`cohort_causal_terminal_verifier_completion_fence_v3`, schema 3, and status
`frozen_terminal_quiescence`. The authorization is path-specific and the
destination is no-overwrite, so it cannot authorize two successful fence
documents.

## Completion fence

Before snapshot one, after snapshot two, and immediately before publication,
the freezer requires both the wrapper PID/start identity and the V2 detached
receipt PID/start identity to be gone. PID reuse with a different start tick is
not treated as the old process; resurrection of either exact identity is
fatal. The V2 receipt must remain canonical and statically bound to the exact
V2 plan, inventory, runtime namespace, argv, environment, and transport
receipt path.

The fence contains two complete opaque inventories separated by at least one
second in both monotonic elapsed time and `CLOCK_BOOTTIME`. Every registered
path, inode, size, mtime, role, and SHA-256 must be identical. The inventory
includes the original V1 causal completion inventory plus the V2 plan, procfs
inventory, detached receipt, V2 failure closure, and V3 recovery source.
Symlink components, aliased inodes, empty files, temporary/live/partial names,
and any drift are fatal.

At both samples the process audit reuses the V2 exact static cwd-exception set
and its one-child dynamic `monitor-connect` policy. It binds the static count
and digest, dynamic-policy digest, full V2 inventory digest, durable and
artifact roots, and the V2 runtime namespace. The live namespace must equal
the V2 baseline at both samples. All V1, V2, and prospective V3 downstream
attestation, revalidation, receipt, and execution-seal paths must remain absent
through publication.

Both documents set `outcome_blind=true` and
`semantic_artifacts_opened=false`. The fence is completion evidence for a
future V3 attester; it is not itself a causal attestation, semantic
revalidation, branch decision, or authorization to reveal efficacy.

## Operational boundary

The freezer source is hash-bound in both outputs and re-read before each
publication. It excludes only its own process from the V2 full-procfs audit;
every other process whose readable command line or cwd references the causal
roots is fatal. The source makes no claim that a client-side SSH configuration
or persistent Pluto service ancestry is mechanically attested. Operators must
use a transport that leaves no other target-referencing process alive when the
registered samples are taken.
