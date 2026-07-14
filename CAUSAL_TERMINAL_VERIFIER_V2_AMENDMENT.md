# Causal terminal verifier V2 amendment

Status: prospectively frozen, outcome-blind infrastructure amendment.

This amendment changes only the terminal liveness proof.  It does not change
the causal grid, registered inputs, statistical estimator, thresholds, branch
logic, or any efficacy-bearing bytes.

V1 required both `/proc/<pid>/cmdline` and `/proc/<pid>/cwd` to be readable for
every process.  The Pluto container can deny `readlink(/proc/<pid>/cwd)` for a
small, stable set of long-lived processes even when their command lines remain
readable.  V2 permits that one case only when all such processes were frozen
before semantic opening in a canonical, exact-set evidence inventory containing
two identical snapshots.  Each record binds only `uid`, `gid`, `pid`, `ppid`,
`comm`, process `start_ticks`, `cmdline_sha256`, `cmdline_size_bytes`, and
`cgroup_sha256`; raw command lines, raw cgroups, and credentials are never
persisted.  Every non-verifier command line is still read and scanned at each
attestation sample, and any reference to the causal checkout, the complete
durable attempt root, or the artifact root is fatal.  The verifier's own exact
NUL-separated command line is separately bound by the detached receipt.  An
unregistered unreadable cwd, an unreadable command line, a missing or extra
exception, PID reuse, process restart, evidence drift, or a process that began
after the registered wrapper is fatal.

The exception set is generated only by the source-hash-bound standalone freezer
copy under the source-commit-qualified `/tmp` transport directory.  The freezer
uses isolated Python (`-I`), a fixed environment, `/dev/null` stdio, no PTY,
`setsid`, `ppid=1`, and an exact command line; it waits 30 seconds and requires
the frozen per-session startup ancestor identities to have disappeared.  It
records two identical full-procfs snapshots whose `CLOCK_BOOTTIME` timestamps
are at least one second apart.  Its source hash must equal the freezer source
dependency bound by the V2 plan, and the freezer PID/start identity itself must
be gone before the plan can be accepted.

Each exception is classified only as a
`stable_pre_wrapper_cwd_permission_denied_process`: its cwd returned exactly
`EACCES` or `EPERM`, its identity and non-semantic metadata were stable across
two snapshots, and it predates the causal wrapper.  This is an evidence label,
not a claim of platform ownership.  The detached transport mechanically excludes
its own per-session `ssh`/`sshd`, `sudo`, shell, and launcher ancestry, but procfs
permission evidence alone cannot distinguish a fixed platform daemon from a
different, already-running long-lived operator process.  Deployment therefore
trusts the platform/orchestrator not to supply such an unrelated process unless
a separately registered platform allowlist or trusted cgroup/ancestry attestation
is added.  No operator may manually add an exception.

The freezer records boot, PID/mount namespace, procfs mount, `/proc/1`, and
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
30 seconds, requires every frozen ephemeral startup ancestor to have gone, and
publishes a no-overwrite receipt before same-PID `execve` into the exact attester
argv with an allowlisted environment.  The inventory, launcher, receipt, and
attester bind the same inventory-baseline boot ID, PID/mount namespace
identities, procfs mount, `PROC_SUPER_MAGIC`, `/proc/1`, and `/proc/self`
consistency.  That binding is a continuity proof from freezer onward, not an
origin attestation for the earlier causal wrapper.

The process audit is explicitly a point-in-time `cmdline`/`cwd` absence proof at
the registered samples.  It does not claim continuous absence between samples
and does not expand V2 to inspect `fd`, `maps`, or `map_files` target references;
the only descriptor inspection is the transport proof that no PTY remains.

Revalidation delegates the semantic reconstruction to
the exact V1 revalidation function after V2-only control validation, preserving
the decision bytes and statistical logic.  The structured-state trigger branch
remains identical to V1.
