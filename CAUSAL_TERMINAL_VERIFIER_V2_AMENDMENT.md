# Causal terminal verifier V2 amendment

Status: prospectively frozen, outcome-blind infrastructure amendment.

This amendment changes only the terminal liveness proof.  It does not change
the causal grid, registered inputs, statistical estimator, thresholds, branch
logic, or any efficacy-bearing bytes.

V1 required both `/proc/<pid>/cmdline` and `/proc/<pid>/cwd` to be readable for
every process.  The Pluto container can deny `readlink(/proc/<pid>/cwd)` for a
small set of long-lived processes even when their command lines remain
readable.  Inventory protocol/schema V2 retains an exact static exception set
that predates the wrapper and adds one narrowly registered dynamic policy: one
direct child of the exact static `monitor-connect` anchor may rotate PID only
while matching either the frozen `sleep` profile or the bounded pre-`exec`
anchor-clone transition profile.  Both profiles bind exact command-line hash
and size; the transition profile is derived from the exact anchor record.  The
child must have proc-directory uid/gid zero, all four `Uid:` and `Gid:` status
columns zero, exact `EACCES`, and the same cgroup bytes as frozen `/proc/1`.
Maximum and required concurrency are both one.  Each record additionally binds
`cwd_errno`, `status_uids`, and `status_gids`; raw command lines, raw cgroups,
and credentials are never persisted.  Every non-verifier command line is still
read and scanned literally before any cwd handling at each
attestation sample, and any reference to the causal checkout, the complete
durable attempt root, or the artifact root is fatal.  The verifier's own exact
NUL-separated command line is separately bound by the detached receipt.  An
unregistered unreadable cwd, an unreadable command line, a missing or extra
static exception, static PID reuse/restart, anchor drift, dynamic parent,
profile, identity, cgroup, or count drift, and evidence drift are fatal.  Only
the dynamic leaf PID/start identity may rotate.

Policy discovery is bounded to 100 attempts at 50 milliseconds.  Only the
single exact anchor-clone transition described above is retryable; zero child,
multiple children, a wrong parent/profile/identity/cgroup, any extra
post-wrapper cwd exception, or any other scan error is immediately fatal.
Static records and the exact anchor must remain identical across discovery.
Discovery observations are not registered snapshots.  Snapshot one begins
only after an exact `sleep` child has been observed and freezes that sleep
profile; snapshot two follows at least one second later and may contain either
registered profile.  The logical inventory digest commits both the exact
static set and the dynamic policy, while a separate static digest supports the
stable process-audit payload.

The exception set is generated only by the source-hash-bound standalone freezer
copy under the source-commit-qualified `/tmp` transport directory.  The freezer
uses isolated Python (`-I`), a fixed environment, `/dev/null` stdio, no PTY,
`setsid`, `ppid=1`, and an exact command line; it waits 30 seconds and requires
the fork-launching parent PID/start identity to have disappeared.  Pluto keeps
an `sshd`/shell/s6 service hierarchy alive independently of any one command, so
V2 does not claim that this complete persistent service ancestry terminates.
Instead, `ppid=1`, a new session/process group, sanitized descriptors, no
controlling terminal or `/dev/pts` descriptor, and the exact exec boundary prove
that the freezer itself is detached from the interactive terminal.  It records
two full-procfs snapshots whose `CLOCK_BOOTTIME` timestamps are at least one
second apart.  Static records must be identical; each snapshot separately
records and validates its dynamic observation, whose PID may differ.  Its
source hash must equal the freezer source
dependency bound by the V2 plan, and the freezer PID/start identity itself must
be gone before the plan can be accepted.

For compatibility, the inventory and receipt wire key remains
`startup_ancestors`, but V2 contract revision 4 requires it to contain exactly
one record: the pre-fork Python launcher parent.  It is not an ancestry walk.

Each exception is classified only as a
`stable_pre_wrapper_cwd_permission_denied_process`: its cwd returned exactly
`EACCES` or `EPERM`, its identity and non-semantic metadata were stable across
two snapshots, and it predates the causal wrapper.  This is an evidence label,
not a claim of platform ownership.  The detached transport mechanically proves
that its fork-launching parent has exited, but it does not classify or claim
termination of the persistent Pluto `sshd`/shell/s6 service ancestry.  Procfs
permission evidence alone cannot distinguish a fixed platform daemon from a
different, already-running long-lived operator process.  Deployment therefore
trusts the platform/orchestrator not to supply such an unrelated process unless
a separately registered platform allowlist or trusted cgroup/ancestry attestation
is added.  No operator may manually add an exception.  Contract revision 4
adds the dynamic anchor policy above.  Root identity and equality with
`/proc/1` cgroup do not mechanically prove platform origin.  Because the
dynamic cwd is unreadable, absence of a target path in that cwd is also not
mechanically proved; only its readable command line is mechanically scanned.
These two limits are registered trust assumptions, not scientific claims.

The freezer records boot, PID/mount namespace, procfs mount, `/proc/1` identity
and cgroup hash, and
`/proc/self` identity, and the detached launcher plus same-PID attester require
exact live continuity from that inventory baseline through attestation
completion.  The downstream revalidator and seal validate the frozen namespace
bindings; they do not compare their own live namespaces.  This detects namespace
or procfs drift between the freezer and attestation completion; it does not
mechanically prove that the inventory baseline originated in the causal
wrapper's earlier namespace or that a pre-existing/mount-only filtered procfs
view was absent.  The unfiltered origin of that baseline is an explicit
trusted-platform assumption: the operator launches the registered freezer in
the original Pluto default container namespace.  A pre-wrapper platform
attestation would be required to replace that assumption mechanically.

All V2 control and output names are versioned and use no-overwrite publication.
The V2 plan binds the immutable V1 execution plan, this amendment, the exception
inventory, all three V2 tools, their source commit, the V1 implementation
sources reused by V2, and durable source copies for both the `/tmp` freezer and
launcher; each transport copy must be byte-identical to its bound durable
source.  The launcher itself uses isolated Python (`-I`), always
forks before `setsid`, closes inherited descriptors, redirects stdio to
`/dev/null`, proves no `/dev/pts` descriptor or controlling TTY remains, waits
30 seconds, requires the frozen fork-launching parent to have gone, and
publishes a no-overwrite receipt before same-PID `execve` into the exact attester
argv with an allowlisted environment.  The inventory, launcher, receipt, and
attester bind the same inventory-baseline boot ID, PID/mount namespace
identities, procfs mount, `PROC_SUPER_MAGIC`, `/proc/1`, and `/proc/self`
consistency.  That binding is a continuity proof from freezer onward, not an
origin attestation for the earlier causal wrapper.

Operationally, the freezer and launcher must each be invoked from a fresh SSH
connection with client multiplexing disabled (`-S none`, `ControlMaster=no`,
`ControlPath=none`, and `ControlPersist=no`).  The remote evidence cannot
mechanically attest those client-side flags, and V2 therefore does not claim
that the complete SSH service ancestry has exited.  This is an explicit
deployment trust condition.  A schema-bound persistent-service lineage suffix
would be required to make that stronger claim.  Any still-running process whose
command line or cwd references the causal checkout, complete durable attempt
root, or artifact root remains fatal in the freezer and attester full-procfs
scans regardless of this service-ancestry boundary.

The process audit is explicitly a point-in-time readable-`cmdline` scan plus
exact-static-cwd and registered-dynamic-policy proof at the registered samples.
Its stable audit payload commits only the exact static digest and dynamic policy
digest, never a rotating PID.  It does not claim continuous absence between samples
and does not expand V2 to inspect `fd`, `maps`, or `map_files` target references;
the only descriptor inspection is the transport proof that no PTY remains.

Revalidation delegates the semantic reconstruction to
the exact V1 revalidation function after V2-only control validation, preserving
the decision bytes and statistical logic.  The structured-state trigger branch
remains identical to V1.
The internal object passed to the unchanged V1 validator contains a synthetic
legacy `linux_procfs_cmdline_and_cwd` method solely as an unpublished
compatibility adapter.  It is not written to the V2 attestation, receipt,
revalidation result, seal, or any external scientific evidence; the published
V2 process-audit method and its narrower claims remain authoritative.
