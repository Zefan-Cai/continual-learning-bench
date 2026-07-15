#!/usr/bin/env python3
"""Prospective, outcome-blind formal wrapper for causal-retry-004.

The wrapper registers its process identity and launch expectation before any
model call, then waits for a no-overwrite authorization binding the complete
V1/V2 terminal control chain.  After the unchanged formal launcher returns it
treats the manifest and decision as opaque files and publishes the wrapper exit
marker exactly once on a strictly later filesystem timestamp tick.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import resource
import socket
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping, Sequence


RETRY_ID = "causal-retry-004"
ATTEMPT_ID = "attempt-002"
CLOSED_SOURCE_COMMITS = frozenset(
    {
        "1caf142f6ce611da8da8691d4c336388a4c3c4b3",
        "059b26b45180b5a295c4c1b36a180cb2a91d5405",
        "6e0a638a7d0700d6df0b75f4c99ced9fae0f1324",
        "dd834d040e94cb0da4cf53486954935754787b84",
    }
)
RETRY_AMENDMENT_FILENAME = "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V4.md"
CHECKOUT_BASE = Path("/mnt/localssd/ttt-rl-cohort-causal")
DURABLE_BASE = Path("/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal")
REQUIRE_PUSHED_REMOTE_REF = True
EXPECTED_PYTHON_PATH = "/usr/bin/python3.10"
EXPECTED_PYTHON_VERSION = "3.10.12"
HANDOFF_FILENAME = "CAUSAL_FORMAL_REGISTERED_HANDOFF_V1.json"
READY_FILENAME = "CAUSAL_FORMAL_REGISTERED_READY_V1.json"
AUTHORIZATION_FILENAME = "CAUSAL_FORMAL_START_AUTHORIZATION_V1.json"
EXPECTATION_FILENAME = "CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json"
V1_PLAN_FILENAME = "CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN.json"
V2_PLAN_FILENAME = "CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V2.json"
V2_INVENTORY_FILENAME = "CAUSAL_TERMINAL_VERIFIER_PROCFS_EXCEPTION_INVENTORY_V2.json"
V2_HANDOFF_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V2_DETACHED_HANDOFF.json"
V2_RECEIPT_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V2_DETACHED_RECEIPT.json"
V2_LAUNCHER_FILENAME = "launch_cohort_causal_terminal_verifier_v2_detached.py"
WRAPPER_LOG_FILENAME = "causal-formal-registered-wrapper.log"
HANDOFF_PROTOCOL = "cohort_causal_formal_registered_handoff_v1"
READY_PROTOCOL = "cohort_causal_formal_registered_ready_v1"
AUTHORIZATION_PROTOCOL = "cohort_causal_formal_start_authorization_v1"
HANDOFF_STATUS = "registered_outcome_blind"
READY_STATUS = "waiting_for_terminal_control_authorization"
AUTHORIZATION_STATUS = "authorized_before_formal_outcomes"
STAGES = ("attester", "revalidator", "execution_seal_builder")
COLLECTOR_GPUS = (0, 2, 3)
EVAL_GPUS = (0, 2, 3, 4, 5, 6)
PUBLISHED_VISIBILITY_TIMEOUT_SECONDS = 60.0
PUBLISHED_STABILITY_SECONDS = 1.0
PUBLISHED_POLL_SECONDS = 0.25
EXPECTED_FINAL_INVENTORY = {
    "cell_final_traces": 6,
    "cell_manifests": 6,
    "collector_final_traces": 3,
    "collector_manifests": 3,
    "formal_decisions": 1,
    "formal_manifests": 1,
    "sealed_cell_log_receipts": 9,
    "sealed_cell_log_start_receipts": 9,
    "sealed_cell_logs": 9,
    "tapes": 3,
    "total": 50,
}
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

CRITICAL_TRACKED_FILES = (
    "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V1.md",
    "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V2.md",
    "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V3.md",
    RETRY_AMENDMENT_FILENAME,
    "COHORT_CAUSAL_LOG_RECIPIENT_V1.txt",
    "COHORT_CAUSAL_SEALED_LOG_RUNTIME_V1.json",
    "assemble_cohort_causal_manifest.py",
    "build_cohort_causal_provenance.py",
    "build_cohort_structured_state_execution_seal.py",
    "build_cohort_structured_state_execution_seal_v2.py",
    "grid_cohort_causal_formal.json",
    "launch_cohort_causal.sh",
    "run_cohort_causal_formal_registered.py",
    "run_cohort_causal_cell_sealed.py",
    "validate_cohort_causal_results.py",
    "validate_cohort_causal_smoke.py",
    "wait_cohort_causal_phase_outputs.py",
)

SMOKE_GATE_KEYS = frozenset(
    {
        "decision",
        "errors",
        "limitation",
        "mechanism_label",
        "provenance_sha256",
        "schema_version",
        "statistical_addendum_sha256",
        "status",
        "tape_sha256",
        "terminal_actions",
        "trainable_param_sha256_initial",
    }
)
SMOKE_REVALIDATION_PROGRAM = r"""
import json
import sys
from pathlib import Path

if (
    Path(sys.executable).resolve().as_posix() != "/usr/bin/python3.10"
    or f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    != "3.10.12"
    or sys.flags.isolated != 1
    or sys.flags.no_site != 1
    or sys.flags.dont_write_bytecode != 1
):
    raise SystemExit(91)
root = Path(sys.argv[1])
grid_path = Path(sys.argv[2])
provenance_path = Path(sys.argv[3])
gate_path = Path(sys.argv[4])
sys.path.insert(0, root.as_posix())
from run_cohort_causal import load_grid, load_provenance
from validate_cohort_causal_smoke import validate_smoke

report = validate_smoke(
    root=root,
    grid=load_grid(grid_path),
    provenance=load_provenance(provenance_path),
)
rendered = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
raise SystemExit(0 if rendered == gate_path.read_bytes() else 92)
""".strip()

HANDOFF_KEYS = frozenset(
    {
        "artifact_root",
        "attempt_id",
        "authorization_path",
        "authorization_timeout_seconds",
        "checkout_root",
        "collector_gpus",
        "durable_attempt_root",
        "eval_gpus",
        "exit_path",
        "formal_decision_path",
        "formal_grid",
        "formal_manifest_path",
        "handoff_path",
        "launch_expectation_path",
        "launcher",
        "max_used_memory_mib",
        "outcome_blind",
        "pid_path",
        "poll_interval_seconds",
        "protocol",
        "provenance",
        "pushed_remote_refs",
        "ready_path",
        "retry_amendment",
        "retry_id",
        "schema_version",
        "semantic_artifacts_opened",
        "smoke_gate",
        "smoke_validator",
        "source_commit",
        "source_tree_sha256",
        "status",
        "v1_execution_plan_path",
        "v1_plan_loader",
        "v2_detached_handoff_path",
        "v2_execution_plan_path",
        "v2_plan_loader",
        "v2_procfs_inventory_path",
        "wrapper_source",
        "wrapper_transport",
    }
)


class RegisteredFormalError(RuntimeError):
    """Fail-closed registered-wrapper error."""


class _VisibilityPending(RuntimeError):
    """A bounded publication transition has not reached a stable view yet."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _canonical_object_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        dict(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(payload)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _absolute(value: str | Path, label: str) -> Path:
    text = os.fspath(value)
    path = Path(text)
    if not path.is_absolute() or os.path.normpath(text) != text:
        raise RegisteredFormalError(f"{label} must be a normalized absolute path")
    return path


def _path_prefixes(path: Path) -> list[Path]:
    target = _absolute(path, "path ancestry")
    prefixes: list[Path] = []
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current /= part
        prefixes.append(current)
    return prefixes


def _allow_darwin_tmp_alias(path: Path, info: os.stat_result) -> bool:
    return (
        sys.platform == "darwin"
        and path == Path("/tmp")
        and stat.S_ISLNK(info.st_mode)
        and path.resolve() == Path("/private/tmp")
    )


def _assert_real_ancestry(path: Path, *, label: str, include_leaf: bool) -> None:
    prefixes = _path_prefixes(path)
    if not include_leaf:
        prefixes = prefixes[:-1]
    for prefix in prefixes:
        info = prefix.lstat()
        if _allow_darwin_tmp_alias(prefix, info):
            continue
        if stat.S_ISLNK(info.st_mode):
            raise RegisteredFormalError(f"{label} has a symlink path component")
        if prefix != path and not stat.S_ISDIR(info.st_mode):
            raise RegisteredFormalError(f"{label} has a nondirectory ancestor")


def _assert_real_directory(path: Path, label: str) -> None:
    target = _absolute(path, label)
    _assert_real_ancestry(target, label=label, include_leaf=True)
    info = target.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RegisteredFormalError(f"{label} must be a real directory")


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not value:
        raise RegisteredFormalError("Linux boot ID is unavailable")
    return value


def _fsync_directory(path: Path) -> None:
    target = _absolute(path, "directory fsync path")
    _assert_real_ancestry(target, label="directory fsync path", include_leaf=True)
    descriptor = os.open(
        target,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise RegisteredFormalError("directory fsync target is not a directory")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_no_overwrite(path: Path, payload: bytes) -> None:
    target = _absolute(path, "publication path")
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_real_ancestry(target.parent, label="publication parent", include_leaf=True)
    parent_info = target.parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or target.parent.is_symlink():
        raise RegisteredFormalError("publication parent must be a real directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.tmp.publish.", dir=target.parent
    )
    temporary = Path(temporary_name)
    linked = False
    expected_inode: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        expected_inode = (written.st_dev, written.st_ino)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, target)
        linked = True
        _fsync_directory(target.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        if linked:
            _fsync_directory(target.parent)
    if expected_inode is None:
        raise AssertionError("publication inode was not captured")
    _wait_for_stable_regular(
        target,
        "published file",
        expected_payload=payload,
        expected_inode=expected_inode,
        maximum_wait_seconds=PUBLISHED_VISIBILITY_TIMEOUT_SECONDS,
        stability_seconds=PUBLISHED_STABILITY_SECONDS,
        poll_seconds=PUBLISHED_POLL_SECONDS,
    )


def _read_regular_snapshot(
    path: Path, label: str, *, allow_visibility_transient: bool = False
) -> tuple[bytes, os.stat_result]:
    target = _absolute(path, label)
    _assert_real_ancestry(target, label=label, include_leaf=False)
    descriptor = os.open(
        target,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink not in {1, 2}:
            raise RegisteredFormalError(
                f"{label} must be a nonempty single-link regular file"
            )
        if before.st_size <= 0 or before.st_nlink == 2:
            error = f"{label} must be a nonempty single-link regular file"
            if allow_visibility_transient:
                raise _VisibilityPending(error)
            raise RegisteredFormalError(error)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    pathname = target.lstat()
    if (
        _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(pathname)
        or stat.S_ISLNK(pathname.st_mode)
    ):
        if allow_visibility_transient:
            raise _VisibilityPending(f"{label} changed during stable read")
        raise RegisteredFormalError(f"{label} changed during stable read")
    payload = b"".join(chunks)
    if len(payload) != after.st_size:
        if allow_visibility_transient:
            raise _VisibilityPending(f"{label} size changed during stable read")
        raise RegisteredFormalError(f"{label} size changed during stable read")
    return payload, after


def _read_regular(path: Path, label: str) -> bytes:
    payload, _ = _read_regular_snapshot(path, label)
    return payload


def _assert_retryable_visibility_leaf(
    path: Path, label: str, *, expected_inode: tuple[int, int] | None = None
) -> None:
    """Reject unsafe leaves while allowing bounded publication-cache lag."""

    target = _absolute(path, label)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ESTALE}:
            return
        raise
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink not in {1, 2}
        or (expected_inode is not None and (info.st_dev, info.st_ino) != expected_inode)
    ):
        raise RegisteredFormalError(
            f"{label} visibility failure is not a publication transient"
        )


def _wait_for_stable_regular(
    path: Path,
    label: str,
    *,
    expected_payload: bytes | None = None,
    expected_inode: tuple[int, int] | None = None,
    maximum_wait_seconds: float | None = None,
    stability_seconds: float | None = None,
    poll_seconds: float | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> bytes:
    """Wait for two identical safe reads of a no-overwrite publication.

    SenseiFS can briefly expose stale size/link metadata after the publisher
    unlinks its temporary hardlink.  This barrier never weakens the stable
    reader: it retries only a missing or regular one/two-link leaf, requires two
    matching fd/path snapshots, and immediately rejects unexpected bytes or an
    unsafe filesystem object.
    """

    maximum_wait_seconds = (
        PUBLISHED_VISIBILITY_TIMEOUT_SECONDS
        if maximum_wait_seconds is None
        else maximum_wait_seconds
    )
    stability_seconds = (
        PUBLISHED_STABILITY_SECONDS if stability_seconds is None else stability_seconds
    )
    poll_seconds = PUBLISHED_POLL_SECONDS if poll_seconds is None else poll_seconds
    if maximum_wait_seconds <= 0 or stability_seconds < 0 or poll_seconds <= 0:
        raise RegisteredFormalError("publication visibility timing is invalid")
    target = _absolute(path, label)
    deadline = monotonic_fn() + maximum_wait_seconds
    previous: tuple[tuple[int, ...], str] | None = None
    previous_at: float | None = None
    observed_inode: tuple[int, int] | None = expected_inode
    observed_sample: tuple[tuple[int, ...], str] | None = None
    last_error: BaseException | None = None
    while True:
        try:
            raw, info = _read_regular_snapshot(
                target, label, allow_visibility_transient=True
            )
        except FileNotFoundError as exc:
            last_error = exc
            previous = None
            previous_at = None
            _assert_retryable_visibility_leaf(
                target, label, expected_inode=observed_inode
            )
        except OSError as exc:
            if exc.errno not in {errno.ENOENT, errno.ESTALE}:
                raise
            last_error = exc
            previous = None
            previous_at = None
            _assert_retryable_visibility_leaf(
                target, label, expected_inode=observed_inode
            )
        except _VisibilityPending as exc:
            last_error = exc
            previous = None
            previous_at = None
            _assert_retryable_visibility_leaf(
                target, label, expected_inode=observed_inode
            )
        else:
            inode = (info.st_dev, info.st_ino)
            if observed_inode is not None and inode != observed_inode:
                raise RegisteredFormalError(f"{label} published inode differs")
            if expected_payload is not None and raw != expected_payload:
                raise RegisteredFormalError(f"{label} published bytes differ")
            sample = (_stat_identity(info), _sha256(raw))
            now = monotonic_fn()
            if now > deadline:
                break
            if observed_inode is None:
                observed_inode = inode
            if observed_sample is None:
                observed_sample = sample
            elif sample != observed_sample:
                raise RegisteredFormalError(
                    f"{label} changed between visibility snapshots"
                )
            if previous == sample and previous_at is not None:
                elapsed = now - previous_at
                if elapsed >= stability_seconds:
                    return raw
                delay = stability_seconds - elapsed
            else:
                previous = sample
                previous_at = now
                delay = stability_seconds
            last_error = None
            if delay > max(0.0, deadline - now):
                break
            sleep_fn(delay)
            continue
        now = monotonic_fn()
        if now >= deadline:
            break
        sleep_fn(min(poll_seconds, max(0.0, deadline - now)))
    raise RegisteredFormalError(
        f"{label} did not become stably visible"
    ) from last_error


def _binding(path: Path, label: str) -> dict[str, str]:
    target = _absolute(path, label)
    raw = _read_regular(target, label)
    return {"path": target.as_posix(), "sha256": _sha256(raw)}


def _stable_binding(path: Path, label: str) -> dict[str, str]:
    target = _absolute(path, label)
    raw = _wait_for_stable_regular(target, label)
    return {"path": target.as_posix(), "sha256": _sha256(raw)}


def _validate_binding(value: Any, expected_path: Path, label: str) -> bytes:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise RegisteredFormalError(f"{label} binding schema differs")
    target = _absolute(value["path"], f"{label} binding path")
    if target != expected_path or _SHA256_RE.fullmatch(value["sha256"] or "") is None:
        raise RegisteredFormalError(f"{label} binding differs")
    raw = _read_regular(target, label)
    if _sha256(raw) != value["sha256"]:
        raise RegisteredFormalError(f"{label} bytes drifted")
    return raw


def _strict_document(
    path: Path, *, keys: frozenset[str], label: str
) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegisteredFormalError(f"{label} is not JSON") from exc
    if not isinstance(value, dict) or set(value) != keys:
        raise RegisteredFormalError(f"{label} schema differs")
    if raw != _canonical_bytes(value):
        raise RegisteredFormalError(f"{label} is not canonical")
    return value, raw


def _validate_smoke_gate(
    path: Path,
    *,
    provenance: Mapping[str, Any],
    provenance_path: Path,
    checkout: Path,
) -> dict[str, str]:
    target = _absolute(path, "smoke gate")
    raw = _read_regular(target, "smoke gate")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegisteredFormalError("smoke gate is not JSON") from exc
    expected_raw = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if (
        not isinstance(value, dict)
        or set(value) != SMOKE_GATE_KEYS
        or raw != expected_raw
        or value["schema_version"] != 1
        or value["status"] != "pass"
        or value["decision"] != "pass"
        or value["errors"] != []
        or value["mechanism_label"] != "frozen-tape weight-update ablation"
        or value["limitation"] != "not exact historical replication"
        or value["provenance_sha256"] != _canonical_object_sha256(provenance)
        or value["statistical_addendum_sha256"]
        != provenance.get("statistical_addendum_sha256")
        or _SHA256_RE.fullmatch(value["tape_sha256"] or "") is None
        or _SHA256_RE.fullmatch(value["trainable_param_sha256_initial"] or "") is None
        or not isinstance(value["terminal_actions"], dict)
        or set(value["terminal_actions"]) != {"active", "lr0"}
    ):
        raise RegisteredFormalError("smoke gate contract differs")
    _revalidate_smoke_gate(
        checkout=checkout, provenance_path=provenance_path, gate_path=target
    )
    return {"path": target.as_posix(), "sha256": _sha256(raw)}


def _revalidate_smoke_gate(
    *, checkout: Path, provenance_path: Path, gate_path: Path
) -> None:
    command = [
        EXPECTED_PYTHON_PATH,
        "-I",
        "-S",
        "-B",
        "-c",
        SMOKE_REVALIDATION_PROGRAM,
        checkout.as_posix(),
        (checkout / "grid_cohort_causal_smoke.json").as_posix(),
        provenance_path.as_posix(),
        gate_path.as_posix(),
    ]
    completed = subprocess.run(
        command,
        cwd="/tmp",
        env={"LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        check=False,
        capture_output=True,
        timeout=300,
    )
    if completed.returncode != 0:
        raise RegisteredFormalError("real isolated smoke revalidation failed")


def _git_output(checkout: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", checkout.as_posix(), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _git_bytes(checkout: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", checkout.as_posix(), *args],
        check=True,
        capture_output=True,
    ).stdout


def _expected_checkout(commit: str) -> Path:
    return CHECKOUT_BASE / commit / RETRY_ID / ATTEMPT_ID


def _expected_durable(commit: str) -> Path:
    return DURABLE_BASE / commit / "retries" / RETRY_ID / "attempts" / ATTEMPT_ID


def _remote_refs_containing(checkout: Path, commit: str) -> list[str]:
    raw = _git_output(
        checkout,
        "for-each-ref",
        "--format=%(refname)",
        f"--contains={commit}",
        "refs/remotes/",
    )
    refs = sorted(line for line in raw.splitlines() if line)
    if any(not value.startswith("refs/remotes/") for value in refs):
        raise RegisteredFormalError("source remote-ref inventory differs")
    return refs


def _validate_clean_tracked_checkout(
    checkout: Path, commit: str, *, expected_remote_refs: Sequence[str] | None = None
) -> tuple[str, list[str]]:
    if _git_output(checkout, "rev-parse", "--show-toplevel") != checkout.as_posix():
        raise RegisteredFormalError("checkout is not the git toplevel")
    if _git_output(checkout, "rev-parse", "HEAD") != commit:
        raise RegisteredFormalError("checkout HEAD differs from source commit")
    status = _git_bytes(
        checkout,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
    )
    records = [record for record in status.split(b"\0") if record]
    allowed = {b"?? artifacts", b"?? artifacts/", b"!! artifacts", b"!! artifacts/"}
    if any(record not in allowed for record in records) or len(records) != 1:
        raise RegisteredFormalError(
            "fresh checkout may contain only the exact artifacts symlink"
        )
    for relative in CRITICAL_TRACKED_FILES:
        tracked = _git_output(checkout, "ls-files", "--error-unmatch", "--", relative)
        if tracked != relative:
            raise RegisteredFormalError(f"critical source is not tracked: {relative}")
        committed = _git_bytes(checkout, "cat-file", "blob", f"{commit}:{relative}")
        current = _read_regular(checkout / relative, f"critical source {relative}")
        if committed != current:
            raise RegisteredFormalError(
                f"critical source differs from HEAD: {relative}"
            )
    source_tree_sha256 = _sha256(
        _git_bytes(checkout, "ls-tree", "-r", "--full-tree", commit)
    )
    remote_refs = _remote_refs_containing(checkout, commit)
    if REQUIRE_PUSHED_REMOTE_REF and not remote_refs:
        raise RegisteredFormalError("source commit has no fetched pushed remote ref")
    if expected_remote_refs is not None and remote_refs != list(expected_remote_refs):
        raise RegisteredFormalError("source pushed remote-ref inventory drifted")
    return source_tree_sha256, remote_refs


def make_handoff(
    *,
    checkout_root: Path,
    durable_attempt_root: Path,
    provenance_path: Path,
    handoff_path: Path,
    authorization_timeout_seconds: int = 3600,
    poll_interval_seconds: float = 0.25,
    max_used_memory_mib: int = 1024,
) -> dict[str, Any]:
    """Build the retry handoff without publishing it."""

    checkout = _absolute(checkout_root, "checkout root")
    durable = _absolute(durable_attempt_root, "durable attempt root")
    provenance = _absolute(provenance_path, "provenance path")
    handoff = _absolute(handoff_path, "handoff path")
    if authorization_timeout_seconds <= 0 or poll_interval_seconds <= 0:
        raise RegisteredFormalError("authorization timing must be positive")
    if max_used_memory_mib < 0:
        raise RegisteredFormalError("GPU memory threshold must be nonnegative")
    commit = _git_output(checkout, "rev-parse", "HEAD")
    if _COMMIT_RE.fullmatch(commit) is None or commit in CLOSED_SOURCE_COMMITS:
        raise RegisteredFormalError("source commit is invalid")
    if checkout != _expected_checkout(commit) or durable != _expected_durable(commit):
        raise RegisteredFormalError("fresh roots do not match the registered layouts")
    for root, label in ((checkout, "checkout root"), (durable, "durable root")):
        _assert_real_ancestry(root, label=label, include_leaf=True)
    expected_handoff = (
        Path("/tmp/cohort-causal-formal-retry") / commit / HANDOFF_FILENAME
    )
    if handoff != expected_handoff:
        raise RegisteredFormalError("handoff path is not commit-qualified")

    durable_artifacts = durable / "artifacts"
    checkout_artifacts = checkout / "artifacts"
    if (
        not checkout_artifacts.is_symlink()
        or os.readlink(checkout_artifacts) != durable_artifacts.as_posix()
    ):
        raise RegisteredFormalError(
            "checkout artifacts must target the fresh durable root"
        )
    source_tree_sha256, pushed_remote_refs = _validate_clean_tracked_checkout(
        checkout, commit
    )
    artifact_root = durable_artifacts / "cohort_causal"
    control = durable / "control"
    prep = durable / "prep"
    for directory in (
        checkout,
        durable,
        durable_artifacts,
        artifact_root,
        control,
        prep,
    ):
        if directory == checkout_artifacts:
            continue
        _assert_real_directory(directory, f"required directory {directory}")

    wrapper_source = checkout / Path(__file__).name
    retry_amendment = checkout / RETRY_AMENDMENT_FILENAME
    launcher = checkout / "launch_cohort_causal.sh"
    formal_grid = checkout / "grid_cohort_causal_formal.json"
    smoke_validator = checkout / "validate_cohort_causal_smoke.py"
    if provenance.parent != artifact_root:
        raise RegisteredFormalError("provenance must live in the fresh artifact root")
    try:
        provenance_value = json.loads(_read_regular(provenance, "causal provenance"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegisteredFormalError("causal provenance is not JSON") from exc
    if (
        not isinstance(provenance_value, dict)
        or provenance_value.get("source_commit") != commit
    ):
        raise RegisteredFormalError("causal provenance source commit differs")
    smoke_gate = _validate_smoke_gate(
        artifact_root / "smoke_gate.json",
        provenance=provenance_value,
        provenance_path=provenance,
        checkout=checkout,
    )
    transport_root = Path("/tmp/cohort-causal-terminal-verifier-v2") / commit
    tooling_root = control / "verifier" / commit
    v1_plan_loader = tooling_root / "build_cohort_structured_state_execution_seal.py"
    v2_plan_loader = tooling_root / "build_cohort_structured_state_execution_seal_v2.py"
    for deployed, source, label in (
        (
            v1_plan_loader,
            checkout / v1_plan_loader.name,
            "V1 plan loader",
        ),
        (
            v2_plan_loader,
            checkout / v2_plan_loader.name,
            "V2 plan loader",
        ),
    ):
        deployed_binding = _binding(deployed, f"deployed {label}")
        source_binding = _binding(source, f"tracked {label}")
        if deployed_binding["sha256"] != source_binding["sha256"]:
            raise RegisteredFormalError(
                f"deployed {label} differs from the clean commit"
            )
    wrapper_transport_path = handoff.parent / wrapper_source.name
    wrapper_source_raw = _read_regular(wrapper_source, "registered wrapper source")
    if os.path.lexists(wrapper_transport_path):
        raise RegisteredFormalError("wrapper transport namespace is not fresh")
    _publish_no_overwrite(wrapper_transport_path, wrapper_source_raw)
    document: dict[str, Any] = {
        "artifact_root": artifact_root.as_posix(),
        "attempt_id": ATTEMPT_ID,
        "authorization_path": (control / AUTHORIZATION_FILENAME).as_posix(),
        "authorization_timeout_seconds": authorization_timeout_seconds,
        "checkout_root": checkout.as_posix(),
        "collector_gpus": list(COLLECTOR_GPUS),
        "durable_attempt_root": durable.as_posix(),
        "eval_gpus": list(EVAL_GPUS),
        "exit_path": (prep / "causal_formal.exit").as_posix(),
        "formal_decision_path": (artifact_root / "formal_decision.json").as_posix(),
        "formal_grid": _binding(formal_grid, "formal grid"),
        "formal_manifest_path": (artifact_root / "formal_manifest.json").as_posix(),
        "handoff_path": handoff.as_posix(),
        "launch_expectation_path": (control / EXPECTATION_FILENAME).as_posix(),
        "launcher": _binding(launcher, "causal launcher"),
        "max_used_memory_mib": max_used_memory_mib,
        "outcome_blind": True,
        "pid_path": (prep / "causal_formal.pid").as_posix(),
        "poll_interval_seconds": poll_interval_seconds,
        "protocol": HANDOFF_PROTOCOL,
        "provenance": _binding(provenance, "causal provenance"),
        "pushed_remote_refs": pushed_remote_refs,
        "ready_path": (handoff.parent / READY_FILENAME).as_posix(),
        "retry_amendment": _binding(retry_amendment, "retry amendment"),
        "retry_id": RETRY_ID,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "smoke_gate": smoke_gate,
        "smoke_validator": _binding(smoke_validator, "smoke validator"),
        "source_commit": commit,
        "source_tree_sha256": source_tree_sha256,
        "status": HANDOFF_STATUS,
        "v1_execution_plan_path": (control / V1_PLAN_FILENAME).as_posix(),
        "v1_plan_loader": _binding(v1_plan_loader, "V1 plan loader"),
        "v2_detached_handoff_path": (transport_root / V2_HANDOFF_FILENAME).as_posix(),
        "v2_execution_plan_path": (control / V2_PLAN_FILENAME).as_posix(),
        "v2_plan_loader": _binding(v2_plan_loader, "V2 plan loader"),
        "v2_procfs_inventory_path": (control / V2_INVENTORY_FILENAME).as_posix(),
        "wrapper_source": _binding(wrapper_source, "registered wrapper source"),
        "wrapper_transport": _binding(wrapper_transport_path, "wrapper transport"),
    }
    if set(document) != HANDOFF_KEYS:
        raise AssertionError("handoff schema drift")
    return document


def publish_handoff(path: Path, handoff: Mapping[str, Any]) -> None:
    target = _absolute(path, "handoff output")
    if target != Path(handoff["handoff_path"]):
        raise RegisteredFormalError("handoff output path differs")
    _publish_no_overwrite(target, _canonical_bytes(handoff))


def load_handoff(path: Path) -> tuple[dict[str, Any], bytes]:
    target = _absolute(path, "handoff")
    value, raw = _strict_document(target, keys=HANDOFF_KEYS, label="formal handoff")
    if (
        value["protocol"] != HANDOFF_PROTOCOL
        or value["schema_version"] != 1
        or value["status"] != HANDOFF_STATUS
        or value["retry_id"] != RETRY_ID
        or value["attempt_id"] != ATTEMPT_ID
        or value["outcome_blind"] is not True
        or value["semantic_artifacts_opened"] is not False
        or value["handoff_path"] != target.as_posix()
        or _COMMIT_RE.fullmatch(value["source_commit"] or "") is None
    ):
        raise RegisteredFormalError("formal handoff contract differs")
    checkout = _absolute(value["checkout_root"], "handoff checkout root")
    durable = _absolute(value["durable_attempt_root"], "handoff durable root")
    commit = value["source_commit"]
    if (
        commit in CLOSED_SOURCE_COMMITS
        or checkout != _expected_checkout(commit)
        or durable != _expected_durable(commit)
    ):
        raise RegisteredFormalError("handoff fresh-run identity differs")
    for root, label in ((checkout, "checkout root"), (durable, "durable root")):
        _assert_real_ancestry(root, label=label, include_leaf=True)
    if (
        not isinstance(value["pushed_remote_refs"], list)
        or any(not isinstance(item, str) for item in value["pushed_remote_refs"])
        or not isinstance(value["source_tree_sha256"], str)
        or _SHA256_RE.fullmatch(value["source_tree_sha256"]) is None
    ):
        raise RegisteredFormalError("handoff source-tree proof differs")
    source_tree_sha256, _ = _validate_clean_tracked_checkout(
        checkout, commit, expected_remote_refs=value["pushed_remote_refs"]
    )
    if source_tree_sha256 != value["source_tree_sha256"]:
        raise RegisteredFormalError("handoff source tree drifted")
    expected_artifact_root = durable / "artifacts" / "cohort_causal"
    if Path(value["artifact_root"]) != expected_artifact_root:
        raise RegisteredFormalError("handoff artifact root differs")
    checkout_artifacts = checkout / "artifacts"
    if (
        not checkout_artifacts.is_symlink()
        or os.readlink(checkout_artifacts) != (durable / "artifacts").as_posix()
    ):
        raise RegisteredFormalError("handoff artifact link drifted")
    for directory in (
        checkout,
        durable,
        durable / "artifacts",
        expected_artifact_root,
        durable / "control",
        durable / "prep",
    ):
        _assert_real_directory(directory, f"handoff directory {directory}")
    control = durable / "control"
    prep = durable / "prep"
    transport_root = Path("/tmp/cohort-causal-terminal-verifier-v2") / commit
    fixed_paths = {
        "authorization_path": control / AUTHORIZATION_FILENAME,
        "exit_path": prep / "causal_formal.exit",
        "formal_decision_path": expected_artifact_root / "formal_decision.json",
        "formal_manifest_path": expected_artifact_root / "formal_manifest.json",
        "handoff_path": Path("/tmp/cohort-causal-formal-retry")
        / commit
        / HANDOFF_FILENAME,
        "launch_expectation_path": control / EXPECTATION_FILENAME,
        "pid_path": prep / "causal_formal.pid",
        "ready_path": target.parent / READY_FILENAME,
        "v1_execution_plan_path": control / V1_PLAN_FILENAME,
        "v2_detached_handoff_path": transport_root / V2_HANDOFF_FILENAME,
        "v2_execution_plan_path": control / V2_PLAN_FILENAME,
        "v2_procfs_inventory_path": control / V2_INVENTORY_FILENAME,
    }
    for key, fixed in fixed_paths.items():
        if _absolute(value[key], f"handoff {key}") != fixed:
            raise RegisteredFormalError(f"handoff fixed path differs: {key}")
    _validate_binding(
        value["formal_grid"], checkout / "grid_cohort_causal_formal.json", "formal grid"
    )
    _validate_binding(
        value["launcher"], checkout / "launch_cohort_causal.sh", "causal launcher"
    )
    _validate_binding(
        value["retry_amendment"],
        checkout / RETRY_AMENDMENT_FILENAME,
        "retry amendment",
    )
    provenance_raw = _validate_binding(
        value["provenance"],
        expected_artifact_root / "provenance.json",
        "causal provenance",
    )
    try:
        provenance_value = json.loads(provenance_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegisteredFormalError("causal provenance is not JSON") from exc
    if (
        not isinstance(provenance_value, dict)
        or provenance_value.get("source_commit") != commit
    ):
        raise RegisteredFormalError("causal provenance source commit differs")
    _validate_binding(
        value["smoke_validator"],
        checkout / "validate_cohort_causal_smoke.py",
        "smoke validator",
    )
    smoke_binding = _validate_smoke_gate(
        expected_artifact_root / "smoke_gate.json",
        provenance=provenance_value,
        provenance_path=expected_artifact_root / "provenance.json",
        checkout=checkout,
    )
    if value["smoke_gate"] != smoke_binding:
        raise RegisteredFormalError("smoke gate binding drifted")
    _validate_binding(
        value["wrapper_source"],
        checkout / Path(__file__).name,
        "registered wrapper source",
    )
    wrapper_transport = target.parent / Path(__file__).name
    _validate_binding(
        value["wrapper_transport"], wrapper_transport, "wrapper transport"
    )
    if value["wrapper_source"]["sha256"] != value["wrapper_transport"]["sha256"]:
        raise RegisteredFormalError("wrapper transport differs from tracked source")
    tooling_root = control / "verifier" / commit
    for key, filename, label in (
        (
            "v1_plan_loader",
            "build_cohort_structured_state_execution_seal.py",
            "V1 plan loader",
        ),
        (
            "v2_plan_loader",
            "build_cohort_structured_state_execution_seal_v2.py",
            "V2 plan loader",
        ),
    ):
        deployed = tooling_root / filename
        _validate_binding(value[key], deployed, label)
        source = checkout / filename
        if _binding(source, f"tracked {label}")["sha256"] != value[key]["sha256"]:
            raise RegisteredFormalError(f"deployed {label} differs from clean commit")
    if value["collector_gpus"] != list(COLLECTOR_GPUS) or value["eval_gpus"] != list(
        EVAL_GPUS
    ):
        raise RegisteredFormalError("handoff GPU assignment differs")
    return value, raw


def _pid_start_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text()
    close = raw.rfind(")")
    if close < 0:
        raise RegisteredFormalError("cannot parse procfs stat")
    fields = raw[close + 2 :].split()
    if len(fields) <= 19:
        raise RegisteredFormalError("procfs stat is truncated")
    return int(fields[19], 10)


def _process_identity(pid: int) -> tuple[int, bytes]:
    return _pid_start_ticks(pid), Path(f"/proc/{pid}/cmdline").read_bytes()


def _make_expectation(handoff: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    pid = os.getpid()
    start_ticks, cmdline = _process_identity(pid)
    pid_raw = f"{pid}\n".encode("ascii")
    expectation = {
        "artifact_root": handoff["artifact_root"],
        "attempt_id": ATTEMPT_ID,
        "boot_id": _boot_id(),
        "collector_gpus": list(COLLECTOR_GPUS),
        "created_at_utc": _utc_now(),
        "durable_attempt_root": handoff["durable_attempt_root"],
        "eval_gpus": list(EVAL_GPUS),
        "expected_final_inventory": dict(EXPECTED_FINAL_INVENTORY),
        "exit_file": handoff["exit_path"],
        "formal_grid_file_sha256": handoff["formal_grid"]["sha256"],
        "launch_mode": "formal",
        "launcher_file_sha256": handoff["launcher"]["sha256"],
        "max_used_memory_mib": handoff["max_used_memory_mib"],
        "node_hostname": socket.gethostname(),
        "pid_file": handoff["pid_path"],
        "pid_file_sha256_at_registration": _sha256(pid_raw),
        "protocol": "cohort_causal_formal_launch_expectation_v1",
        "provenance_file_sha256": handoff["provenance"]["sha256"],
        "schema_version": 1,
        "source_commit": handoff["source_commit"],
        "wrapper_cmdline_sha256_at_registration": _sha256(cmdline),
        "wrapper_pid": pid,
        "wrapper_start_ticks": start_ticks,
        "checkout_root": handoff["checkout_root"],
    }
    return expectation, pid_raw


def _validate_registered_runtime(handoff: Mapping[str, Any]) -> None:
    executable = Path(sys.executable).resolve().as_posix()
    version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    expected_argv = [
        handoff["wrapper_transport"]["path"],
        "run",
        "--handoff",
        handoff["handoff_path"],
    ]
    expected_cmdline = (
        b"\0".join(
            item.encode("utf-8")
            for item in [
                EXPECTED_PYTHON_PATH,
                "-I",
                "-S",
                "-B",
                "-u",
                *expected_argv,
            ]
        )
        + b"\0"
    )
    stat_raw = Path("/proc/self/stat").read_bytes()
    close = stat_raw.rfind(b") ")
    fields = stat_raw[close + 2 :].split() if close >= 2 else []
    pid = os.getpid()
    if len(fields) < 20:
        raise RegisteredFormalError("registered wrapper procfs stat is invalid")
    log_path = Path(handoff["handoff_path"]).parent / WRAPPER_LOG_FILENAME
    log_info = log_path.lstat()
    stdin_target = Path("/proc/self/fd/0").resolve()
    stdout_info = os.fstat(1)
    stderr_info = os.fstat(2)
    extra_fds: list[int] = []
    for entry_name in os.listdir("/proc/self/fd"):
        if not entry_name.isdigit() or int(entry_name) <= 2:
            continue
        descriptor = int(entry_name)
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        extra_fds.append(descriptor)
    if (
        executable != EXPECTED_PYTHON_PATH
        or version != EXPECTED_PYTHON_VERSION
        or sys.argv != expected_argv
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.dont_write_bytecode != 1
        or not getattr(sys.stdout, "write_through", False)
        or Path("/proc/self/cmdline").read_bytes() != expected_cmdline
        or os.getppid() != 1
        or int(fields[2]) != pid
        or int(fields[3]) != pid
        or int(fields[4]) != 0
        or os.getsid(0) != pid
        or os.getpgrp() != pid
        or Path.cwd() != Path("/tmp")
        or stdin_target != Path("/dev/null")
        or os.isatty(0)
        or os.isatty(1)
        or os.isatty(2)
        or not stat.S_ISREG(log_info.st_mode)
        or log_info.st_nlink != 1
        or _stat_identity(stdout_info) != _stat_identity(log_info)
        or _stat_identity(stderr_info) != _stat_identity(log_info)
        or extra_fds
    ):
        raise RegisteredFormalError(
            "registered wrapper runtime, detachment, or argv differs"
        )


def register_wrapper(
    handoff_path: Path, *, validate_runtime: bool = True
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Publish PID, launch expectation, and readiness before model calls."""

    handoff, handoff_raw = load_handoff(handoff_path)
    if validate_runtime:
        _validate_registered_runtime(handoff)
    forbidden = [
        Path(handoff[key])
        for key in (
            "pid_path",
            "exit_path",
            "launch_expectation_path",
            "ready_path",
            "authorization_path",
            "formal_manifest_path",
            "formal_decision_path",
            "v1_execution_plan_path",
            "v2_detached_handoff_path",
            "v2_execution_plan_path",
            "v2_procfs_inventory_path",
        )
    ]
    existing = [path.as_posix() for path in forbidden if os.path.lexists(path)]
    if existing:
        raise RegisteredFormalError(f"fresh wrapper paths already exist: {existing}")
    expectation, pid_raw = _make_expectation(handoff)
    pid_path = Path(handoff["pid_path"])
    expectation_path = Path(handoff["launch_expectation_path"])
    ready_path = Path(handoff["ready_path"])
    _publish_no_overwrite(pid_path, pid_raw)
    stable_pid_raw = _wait_for_stable_regular(
        pid_path,
        "wrapper PID file",
        expected_payload=pid_raw,
    )
    expectation_raw = _canonical_bytes(expectation)
    _publish_no_overwrite(expectation_path, expectation_raw)
    stable_expectation_raw = _wait_for_stable_regular(
        expectation_path,
        "launch expectation",
        expected_payload=expectation_raw,
    )
    ready = {
        "handoff": {
            "path": Path(handoff_path).as_posix(),
            "sha256": _sha256(handoff_raw),
        },
        "launch_expectation": {
            "path": expectation_path.as_posix(),
            "sha256": _sha256(stable_expectation_raw),
        },
        "outcome_blind": True,
        "pid_file": {
            "path": pid_path.as_posix(),
            "sha256": _sha256(stable_pid_raw),
        },
        "protocol": READY_PROTOCOL,
        "retry_id": RETRY_ID,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "source_commit": handoff["source_commit"],
        "status": READY_STATUS,
        "wrapper_pid": expectation["wrapper_pid"],
        "wrapper_start_ticks": expectation["wrapper_start_ticks"],
    }
    _publish_no_overwrite(ready_path, _canonical_bytes(ready))
    return handoff, ready


READY_KEYS = frozenset(
    {
        "handoff",
        "launch_expectation",
        "outcome_blind",
        "pid_file",
        "protocol",
        "retry_id",
        "schema_version",
        "semantic_artifacts_opened",
        "source_commit",
        "status",
        "wrapper_pid",
        "wrapper_start_ticks",
    }
)

EXPECTATION_KEYS = frozenset(
    {
        "artifact_root",
        "attempt_id",
        "boot_id",
        "checkout_root",
        "collector_gpus",
        "created_at_utc",
        "durable_attempt_root",
        "eval_gpus",
        "exit_file",
        "expected_final_inventory",
        "formal_grid_file_sha256",
        "launch_mode",
        "launcher_file_sha256",
        "max_used_memory_mib",
        "node_hostname",
        "pid_file",
        "pid_file_sha256_at_registration",
        "protocol",
        "provenance_file_sha256",
        "schema_version",
        "source_commit",
        "wrapper_cmdline_sha256_at_registration",
        "wrapper_pid",
        "wrapper_start_ticks",
    }
)

AUTHORIZATION_KEYS = frozenset(
    {
        "authorized_at_utc",
        "control_bindings",
        "outcome_blind",
        "preflight_stages",
        "protocol",
        "retry_id",
        "schema_version",
        "semantic_artifacts_opened",
        "source_commit",
        "status",
        "wrapper_pid",
        "wrapper_start_ticks",
    }
)


def _control_paths(handoff: Mapping[str, Any]) -> dict[str, Path]:
    return {
        "formal_grid": Path(handoff["formal_grid"]["path"]),
        "handoff": Path(handoff["handoff_path"]),
        "launch_expectation": Path(handoff["launch_expectation_path"]),
        "launcher": Path(handoff["launcher"]["path"]),
        "pid_file": Path(handoff["pid_path"]),
        "provenance": Path(handoff["provenance"]["path"]),
        "ready": Path(handoff["ready_path"]),
        "retry_amendment": Path(handoff["retry_amendment"]["path"]),
        "smoke_gate": Path(handoff["smoke_gate"]["path"]),
        "smoke_validator": Path(handoff["smoke_validator"]["path"]),
        "v1_execution_plan": Path(handoff["v1_execution_plan_path"]),
        "v1_plan_loader": Path(handoff["v1_plan_loader"]["path"]),
        "v2_detached_handoff": Path(handoff["v2_detached_handoff_path"]),
        "v2_execution_plan": Path(handoff["v2_execution_plan_path"]),
        "v2_plan_loader": Path(handoff["v2_plan_loader"]["path"]),
        "v2_procfs_inventory": Path(handoff["v2_procfs_inventory_path"]),
        "wrapper_source": Path(handoff["wrapper_source"]["path"]),
        "wrapper_transport": Path(handoff["wrapper_transport"]["path"]),
    }


def _authorization_paths(handoff: Mapping[str, Any]) -> dict[str, Path]:
    paths = _control_paths(handoff)
    plan_path = Path(handoff["v2_execution_plan_path"])
    try:
        plan = json.loads(_wait_for_stable_regular(plan_path, "V2 execution plan"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegisteredFormalError("V2 execution plan is not JSON") from exc
    if not isinstance(plan, dict):
        raise RegisteredFormalError("V2 execution plan schema differs")
    tooling = (
        Path(handoff["durable_attempt_root"])
        / "control"
        / "verifier"
        / handoff["source_commit"]
    )
    control = Path(handoff["durable_attempt_root"]) / "control"
    v2_transport = (
        Path("/tmp/cohort-causal-terminal-verifier-v2") / handoff["source_commit"]
    )
    allowed_roots = (tooling, control, v2_transport)

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if set(value) == {"path", "sha256"}:
                path = _absolute(value["path"], "V2 plan binding path")
                if not any(
                    path == root or path.is_relative_to(root) for root in allowed_roots
                ):
                    raise RegisteredFormalError("V2 plan binding escapes control roots")
                key = f"v2_plan_binding_{_sha256(path.as_posix().encode())[:20]}"
                if key in paths and paths[key] != path:
                    raise RegisteredFormalError("V2 plan binding key collision")
                paths[key] = path
                return
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(plan)
    return dict(sorted(paths.items()))


def _load_ready(handoff: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    ready, raw = _strict_document(
        Path(handoff["ready_path"]), keys=READY_KEYS, label="wrapper readiness"
    )
    if (
        ready["protocol"] != READY_PROTOCOL
        or ready["schema_version"] != 1
        or ready["status"] != READY_STATUS
        or ready["retry_id"] != RETRY_ID
        or ready["source_commit"] != handoff["source_commit"]
        or ready["outcome_blind"] is not True
        or ready["semantic_artifacts_opened"] is not False
    ):
        raise RegisteredFormalError("wrapper readiness contract differs")
    _validate_binding(ready["handoff"], Path(handoff["handoff_path"]), "ready handoff")
    _validate_binding(
        ready["launch_expectation"],
        Path(handoff["launch_expectation_path"]),
        "ready launch expectation",
    )
    pid_raw = _validate_binding(
        ready["pid_file"], Path(handoff["pid_path"]), "ready PID"
    )
    expectation, _ = _strict_document(
        Path(handoff["launch_expectation_path"]),
        keys=EXPECTATION_KEYS,
        label="launch expectation",
    )
    if (
        expectation["protocol"] != "cohort_causal_formal_launch_expectation_v1"
        or expectation["schema_version"] != 1
        or expectation["artifact_root"] != handoff["artifact_root"]
        or expectation["attempt_id"] != ATTEMPT_ID
        or expectation["checkout_root"] != handoff["checkout_root"]
        or expectation["durable_attempt_root"] != handoff["durable_attempt_root"]
        or expectation["collector_gpus"] != list(COLLECTOR_GPUS)
        or expectation["eval_gpus"] != list(EVAL_GPUS)
        or expectation["exit_file"] != handoff["exit_path"]
        or expectation["expected_final_inventory"] != EXPECTED_FINAL_INVENTORY
        or expectation["formal_grid_file_sha256"] != handoff["formal_grid"]["sha256"]
        or expectation["launch_mode"] != "formal"
        or expectation["launcher_file_sha256"] != handoff["launcher"]["sha256"]
        or expectation["max_used_memory_mib"] != handoff["max_used_memory_mib"]
        or expectation["node_hostname"] != socket.gethostname()
        or expectation["pid_file"] != handoff["pid_path"]
        or expectation["provenance_file_sha256"] != handoff["provenance"]["sha256"]
        or expectation["source_commit"] != handoff["source_commit"]
        or expectation["boot_id"] != _boot_id()
    ):
        raise RegisteredFormalError("launch expectation does not join the handoff")
    if (
        not isinstance(ready["wrapper_pid"], int)
        or isinstance(ready["wrapper_pid"], bool)
        or ready["wrapper_pid"] <= 1
        or not isinstance(ready["wrapper_start_ticks"], int)
        or isinstance(ready["wrapper_start_ticks"], bool)
        or ready["wrapper_start_ticks"] <= 0
        or ready["wrapper_pid"] != expectation["wrapper_pid"]
        or ready["wrapper_start_ticks"] != expectation["wrapper_start_ticks"]
        or pid_raw != f"{ready['wrapper_pid']}\n".encode("ascii")
        or expectation["pid_file_sha256_at_registration"] != _sha256(pid_raw)
        or ready["pid_file"]["sha256"] != _sha256(pid_raw)
        or _SHA256_RE.fullmatch(
            expectation["wrapper_cmdline_sha256_at_registration"] or ""
        )
        is None
    ):
        raise RegisteredFormalError("ready, expectation, and PID identity differ")
    ready["_expectation"] = expectation
    return ready, raw


def _validate_live_ready(
    ready: Mapping[str, Any],
    *,
    identity_fn: Callable[[int], tuple[int, bytes]] | None = None,
) -> None:
    if identity_fn is None:
        identity_fn = _process_identity
    pid = ready["wrapper_pid"]
    try:
        observed_start, observed_cmdline = identity_fn(pid)
    except (FileNotFoundError, ProcessLookupError) as exc:
        raise RegisteredFormalError("registered wrapper is not live") from exc
    expectation = ready.get("_expectation")
    if not isinstance(expectation, dict):
        raise RegisteredFormalError("joined launch expectation is absent")
    if (
        observed_start != ready["wrapper_start_ticks"]
        or _sha256(observed_cmdline)
        != expectation["wrapper_cmdline_sha256_at_registration"]
    ):
        raise RegisteredFormalError("registered wrapper live identity drifted")


def _load_commit_qualified_v2(
    handoff: Mapping[str, Any], plan: Mapping[str, Any]
) -> ModuleType:
    tooling = (
        Path(handoff["durable_attempt_root"])
        / "control"
        / "verifier"
        / handoff["source_commit"]
    )
    if _absolute(plan["tooling_root"], "V2 tooling root") != tooling:
        raise RegisteredFormalError("V2 plan selected a different tooling root")
    module_path = Path(handoff["v2_plan_loader"]["path"])
    v1_path = Path(handoff["v1_plan_loader"]["path"])
    v2_raw = _validate_binding(handoff["v2_plan_loader"], module_path, "V2 plan loader")
    v1_raw = _validate_binding(handoff["v1_plan_loader"], v1_path, "V1 plan loader")
    if module_path != tooling / module_path.name or v1_path != tooling / v1_path.name:
        raise RegisteredFormalError("commit-qualified loader path differs")
    for name in (
        "build_cohort_structured_state_execution_seal",
        "build_cohort_structured_state_execution_seal_v2",
    ):
        sys.modules.pop(name, None)
    v1_module = ModuleType("build_cohort_structured_state_execution_seal")
    v1_module.__file__ = v1_path.as_posix()
    v1_module.__package__ = ""
    sys.modules[v1_module.__name__] = v1_module
    try:
        exec(
            compile(v1_raw, v1_path.as_posix(), "exec", dont_inherit=True),
            v1_module.__dict__,
        )
        module = ModuleType("build_cohort_structured_state_execution_seal_v2")
        module.__file__ = module_path.as_posix()
        module.__package__ = ""
        sys.modules[module.__name__] = module
        exec(
            compile(v2_raw, module_path.as_posix(), "exec", dont_inherit=True),
            module.__dict__,
        )
    except BaseException:
        sys.modules.pop("build_cohort_structured_state_execution_seal_v2", None)
        sys.modules.pop("build_cohort_structured_state_execution_seal", None)
        raise
    if (
        module.v1 is not v1_module
        or module.__file__ != module_path.as_posix()
        or v1_module.__file__ != v1_path.as_posix()
        or _validate_binding(
            handoff["v2_plan_loader"], module_path, "post-import V2 plan loader"
        )
        != v2_raw
        or _validate_binding(
            handoff["v1_plan_loader"], v1_path, "post-import V1 plan loader"
        )
        != v1_raw
    ):
        raise RegisteredFormalError("commit-qualified loader execution drifted")
    return module


def _preflight_v2_stages(
    handoff: Mapping[str, Any],
    *,
    validator: Callable[..., Any] | None = None,
) -> None:
    plan_path = Path(handoff["v2_execution_plan_path"])
    plan_raw = _wait_for_stable_regular(plan_path, "V2 execution plan")
    plan = json.loads(plan_raw)
    if not isinstance(plan, dict) or not isinstance(plan.get("invocations"), dict):
        raise RegisteredFormalError("V2 execution plan schema differs")
    _assert_terminal_launcher_not_started(handoff, plan)
    if validator is None:
        if (
            sys.flags.isolated != 1
            or sys.flags.no_site != 1
            or sys.flags.ignore_environment != 1
            or sys.flags.dont_write_bytecode != 1
        ):
            raise RegisteredFormalError(
                "real V2 preflight requires Python -I -S -B isolation"
            )
        module = _load_commit_qualified_v2(handoff, plan)
        validator = module.load_and_validate_execution_plan_stage
        python_path = Path(sys.executable).resolve().as_posix()
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if (python_path, python_version) != (
            module.EXPECTED_PYTHON_PATH,
            module.EXPECTED_PYTHON_VERSION,
        ):
            raise RegisteredFormalError(
                "real V2 preflight must use the registered Python runtime"
            )
    else:
        python_path = EXPECTED_PYTHON_PATH
        python_version = EXPECTED_PYTHON_VERSION
    for stage_name in STAGES:
        invocation = plan["invocations"].get(stage_name)
        if not isinstance(invocation, dict):
            raise RegisteredFormalError(f"V2 stage is absent: {stage_name}")
        outputs = invocation.get("outputs")
        if not isinstance(outputs, dict):
            raise RegisteredFormalError(f"V2 stage outputs differ: {stage_name}")
        for output_path in outputs.values():
            if os.path.lexists(output_path):
                raise RegisteredFormalError(
                    f"V2 stage output predates formal authorization: {stage_name}"
                )
        validator(
            execution_plan_path=plan_path,
            stage=stage_name,
            expected_inputs=invocation["inputs"],
            expected_outputs=invocation["outputs"],
            expected_parameters=invocation["parameters"],
            actual_argv=invocation["argv"],
            runtime_python_path=python_path,
            runtime_python_version=python_version,
        )
    _assert_terminal_launcher_not_started(handoff, plan)


def _assert_terminal_launcher_not_started(
    handoff: Mapping[str, Any], plan: Mapping[str, Any]
) -> None:
    transport = plan.get("detached_transport")
    if not isinstance(transport, dict) or set(transport) != {
        "handoff",
        "launcher",
        "receipt_path",
    }:
        raise RegisteredFormalError("V2 detached transport schema differs")
    commit = handoff["source_commit"]
    transport_root = Path("/tmp/cohort-causal-terminal-verifier-v2") / commit
    launcher = transport_root / V2_LAUNCHER_FILENAME
    detached_handoff = transport_root / V2_HANDOFF_FILENAME
    receipt = Path(handoff["durable_attempt_root"]) / "control" / V2_RECEIPT_FILENAME
    for value, expected, label in (
        (transport["launcher"], launcher, "V2 detached launcher"),
        (transport["handoff"], detached_handoff, "V2 detached handoff"),
    ):
        _validate_binding(value, expected, label)
    if _absolute(
        transport["receipt_path"], "V2 detached receipt"
    ) != receipt or os.path.lexists(receipt):
        raise RegisteredFormalError("V2 detached receipt predates formal completion")
    expected_argv = [
        EXPECTED_PYTHON_PATH,
        "-I",
        launcher.as_posix(),
        "--handoff",
        detached_handoff.as_posix(),
        "--delay-seconds",
        "30",
    ]
    expected_cmdline = (
        b"\0".join(item.encode("utf-8") for item in expected_argv) + b"\0"
    )
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        raise RegisteredFormalError("Linux procfs is required for terminal ordering")
    for process in proc_root.iterdir():
        if not process.name.isdigit():
            continue
        try:
            current = (process / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            continue
        if current == expected_cmdline:
            raise RegisteredFormalError(
                "V2 detached launcher started before formal completion"
            )


def authorize_formal_start(
    handoff_path: Path,
    *,
    validator: Callable[..., Any] | None = None,
    identity_fn: Callable[[int], tuple[int, bytes]] | None = None,
) -> dict[str, Any]:
    """Publish start authorization only after the complete real V2 preflight."""

    handoff, _ = load_handoff(handoff_path)
    ready, _ = _load_ready(handoff)
    _validate_live_ready(ready, identity_fn=identity_fn)
    pid = ready["wrapper_pid"]
    for key in ("formal_manifest_path", "formal_decision_path", "exit_path"):
        if os.path.lexists(handoff[key]):
            raise RegisteredFormalError("formal outcome exists before authorization")
    before_paths = _authorization_paths(handoff)
    before_bindings = {
        name: _stable_binding(path, f"authorization preflight {name}")
        for name, path in before_paths.items()
    }
    _preflight_v2_stages(handoff, validator=validator)
    after_paths = _authorization_paths(handoff)
    bindings = {
        name: _stable_binding(path, f"authorization postflight {name}")
        for name, path in after_paths.items()
    }
    if after_paths != before_paths or bindings != before_bindings:
        raise RegisteredFormalError("terminal controls drifted during V2 preflight")
    ready_after, _ = _load_ready(handoff)
    _validate_live_ready(ready_after, identity_fn=identity_fn)
    for key in ("formal_manifest_path", "formal_decision_path", "exit_path"):
        if os.path.lexists(handoff[key]):
            raise RegisteredFormalError("formal outcome appeared during authorization")
    authorization = {
        "authorized_at_utc": _utc_now(),
        "control_bindings": bindings,
        "outcome_blind": True,
        "preflight_stages": list(STAGES),
        "protocol": AUTHORIZATION_PROTOCOL,
        "retry_id": RETRY_ID,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "source_commit": handoff["source_commit"],
        "status": AUTHORIZATION_STATUS,
        "wrapper_pid": pid,
        "wrapper_start_ticks": ready["wrapper_start_ticks"],
    }
    authorization_path = Path(handoff["authorization_path"])
    authorization_raw = _canonical_bytes(authorization)
    _publish_no_overwrite(authorization_path, authorization_raw)
    _wait_for_stable_regular(
        authorization_path,
        "formal start authorization",
        expected_payload=authorization_raw,
    )
    return authorization


def _validate_authorization(
    handoff: Mapping[str, Any],
    authorization_path: Path,
    *,
    require_outcomes_absent: bool = True,
) -> dict[str, Any]:
    authorization, authorization_raw = _strict_document(
        authorization_path,
        keys=AUTHORIZATION_KEYS,
        label="formal start authorization",
    )
    if (
        authorization["protocol"] != AUTHORIZATION_PROTOCOL
        or authorization["schema_version"] != 1
        or authorization["status"] != AUTHORIZATION_STATUS
        or authorization["retry_id"] != RETRY_ID
        or authorization["source_commit"] != handoff["source_commit"]
        or authorization["outcome_blind"] is not True
        or authorization["semantic_artifacts_opened"] is not False
        or authorization["preflight_stages"] != list(STAGES)
        or authorization["wrapper_pid"] != os.getpid()
        or authorization["wrapper_start_ticks"] != _pid_start_ticks(os.getpid())
    ):
        raise RegisteredFormalError("formal start authorization contract differs")
    refreshed_handoff, _ = load_handoff(Path(handoff["handoff_path"]))
    if refreshed_handoff != dict(handoff):
        raise RegisteredFormalError("formal handoff drifted before authorization use")
    ready, _ = _load_ready(refreshed_handoff)
    _validate_live_ready(ready)
    bindings = authorization["control_bindings"]
    paths = _authorization_paths(refreshed_handoff)
    if not isinstance(bindings, dict) or set(bindings) != set(paths):
        raise RegisteredFormalError("authorization binding inventory differs")
    for name, path in paths.items():
        _validate_binding(bindings[name], path, f"authorization {name}")
    _preflight_v2_stages(refreshed_handoff)
    after_paths = _authorization_paths(refreshed_handoff)
    if after_paths != paths:
        raise RegisteredFormalError("authorization paths drifted during consumption")
    for name, path in after_paths.items():
        _validate_binding(bindings[name], path, f"authorization postflight {name}")
    if require_outcomes_absent:
        for key in ("formal_manifest_path", "formal_decision_path", "exit_path"):
            if not os.path.lexists(handoff[key]):
                continue
            raise RegisteredFormalError(
                "formal outcome predates authorization consumption"
            )
    if (
        _read_regular(authorization_path, "formal start authorization")
        != authorization_raw
    ):
        raise RegisteredFormalError(
            "formal start authorization drifted during validation"
        )
    return authorization


def _wait_for_authorization(handoff: Mapping[str, Any]) -> dict[str, Any]:
    path = Path(handoff["authorization_path"])
    deadline = time.monotonic() + float(handoff["authorization_timeout_seconds"])
    while time.monotonic() < deadline:
        if os.path.lexists(path):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            _wait_for_stable_regular(
                path,
                "formal start authorization",
                maximum_wait_seconds=remaining,
                poll_seconds=float(handoff["poll_interval_seconds"]),
            )
            return _validate_authorization(handoff, path)
        time.sleep(float(handoff["poll_interval_seconds"]))
    raise RegisteredFormalError("timed out waiting for formal start authorization")


def _mtime_ns(path: Path) -> int:
    return path.stat().st_mtime_ns


def _open_opaque_outcome(path: Path) -> tuple[int, os.stat_result]:
    candidate = _absolute(path, "opaque formal outcome")
    _assert_real_ancestry(candidate, label="opaque formal outcome", include_leaf=False)
    descriptor = os.open(
        candidate,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink not in {1, 2}:
            raise RegisteredFormalError(
                "formal outcome must be a nonempty single-link regular file"
            )
        if info.st_size <= 0 or info.st_nlink == 2:
            raise _VisibilityPending(
                "formal outcome must be a nonempty single-link regular file"
            )
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        pathname = candidate.lstat()
        if stat.S_ISLNK(pathname.st_mode) or not stat.S_ISREG(pathname.st_mode):
            raise RegisteredFormalError("formal outcome pathname is unsafe")
        if _stat_identity(info) != _stat_identity(pathname):
            raise _VisibilityPending("formal outcome pathname identity differs")
        _fsync_directory(candidate.parent)
        return descriptor, info
    except BaseException:
        os.close(descriptor)
        raise


def _verify_open_outcome(
    path: Path, descriptor: int, registered: os.stat_result
) -> None:
    candidate = _absolute(path, "opaque formal outcome")
    _assert_real_ancestry(candidate, label="opaque formal outcome", include_leaf=False)
    current = os.fstat(descriptor)
    pathname = candidate.lstat()
    if (
        _stat_identity(current) != _stat_identity(registered)
        or _stat_identity(pathname) != _stat_identity(registered)
        or stat.S_ISLNK(pathname.st_mode)
    ):
        raise RegisteredFormalError("formal outcome changed before exit publication")


def _wait_for_stable_opaque_outcome(
    path: Path,
    *,
    maximum_wait_seconds: float | None = None,
    stability_seconds: float | None = None,
    poll_seconds: float | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> tuple[int, os.stat_result]:
    """Open an opaque outcome after stable metadata, without reading its bytes."""

    maximum_wait_seconds = (
        PUBLISHED_VISIBILITY_TIMEOUT_SECONDS
        if maximum_wait_seconds is None
        else maximum_wait_seconds
    )
    stability_seconds = (
        PUBLISHED_STABILITY_SECONDS if stability_seconds is None else stability_seconds
    )
    poll_seconds = PUBLISHED_POLL_SECONDS if poll_seconds is None else poll_seconds
    if maximum_wait_seconds <= 0 or stability_seconds < 0 or poll_seconds <= 0:
        raise RegisteredFormalError("opaque outcome visibility timing is invalid")
    candidate = _absolute(path, "opaque formal outcome")
    deadline = monotonic_fn() + maximum_wait_seconds
    observed_inode: tuple[int, int] | None = None
    last_error: BaseException | None = None
    while True:
        try:
            descriptor, info = _open_opaque_outcome(candidate)
        except FileNotFoundError as exc:
            last_error = exc
            _assert_retryable_visibility_leaf(candidate, "opaque formal outcome")
        except OSError as exc:
            if exc.errno not in {errno.ENOENT, errno.ESTALE}:
                raise
            last_error = exc
            _assert_retryable_visibility_leaf(candidate, "opaque formal outcome")
        except _VisibilityPending as exc:
            last_error = exc
            _assert_retryable_visibility_leaf(candidate, "opaque formal outcome")
        else:
            inode = (info.st_dev, info.st_ino)
            if observed_inode is not None and inode != observed_inode:
                os.close(descriptor)
                raise RegisteredFormalError("formal outcome published inode differs")
            if observed_inode is None:
                observed_inode = inode
            opened_at = monotonic_fn()
            if opened_at > deadline:
                os.close(descriptor)
                break
            if stability_seconds > max(0.0, deadline - opened_at):
                os.close(descriptor)
                break
            sleep_fn(stability_seconds)
            verified_at = monotonic_fn()
            if verified_at > deadline or verified_at - opened_at < stability_seconds:
                os.close(descriptor)
                continue
            try:
                _verify_open_outcome(candidate, descriptor, info)
            except FileNotFoundError as exc:
                os.close(descriptor)
                last_error = exc
                _assert_retryable_visibility_leaf(
                    candidate,
                    "opaque formal outcome",
                    expected_inode=observed_inode,
                )
                continue
            except OSError as exc:
                if exc.errno not in {errno.ENOENT, errno.ESTALE}:
                    os.close(descriptor)
                    raise
                os.close(descriptor)
                last_error = exc
                _assert_retryable_visibility_leaf(
                    candidate,
                    "opaque formal outcome",
                    expected_inode=observed_inode,
                )
                continue
            except BaseException:
                os.close(descriptor)
                raise
            return descriptor, info
        now = monotonic_fn()
        if now >= deadline:
            break
        sleep_fn(min(poll_seconds, max(0.0, deadline - now)))
    raise RegisteredFormalError(
        "opaque formal outcome did not become stably visible"
    ) from last_error


def publish_exit_marker(
    *,
    exit_path: Path,
    return_code: int,
    outcome_paths: Sequence[Path],
    sleep_fn: Callable[[float], None] = time.sleep,
    maximum_wait_seconds: float = PUBLISHED_VISIBILITY_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Publish a no-overwrite marker strictly after opaque outcome files."""

    target = _absolute(exit_path, "formal exit path")
    if os.path.lexists(target):
        raise FileExistsError("refusing pre-existing formal exit marker")
    threshold = -1
    exit_inode: tuple[int, int] | None = None
    if len(outcome_paths) != 2:
        raise RegisteredFormalError("formal exit requires two opaque outcome files")
    opened: list[tuple[Path, int, os.stat_result]] = []
    outcome_deadline = time.monotonic() + maximum_wait_seconds
    try:
        for path in outcome_paths:
            candidate = _absolute(path, "opaque formal outcome")
            remaining = outcome_deadline - time.monotonic()
            if remaining <= 0:
                raise RegisteredFormalError(
                    "opaque formal outcomes exceeded their shared visibility deadline"
                )
            descriptor, info = _wait_for_stable_opaque_outcome(
                candidate,
                maximum_wait_seconds=remaining,
                sleep_fn=sleep_fn,
            )
            opened.append((candidate, descriptor, info))
            threshold = max(threshold, info.st_mtime_ns)

        payload = f"{return_code}\n".encode("ascii")
        deadline = time.monotonic() + maximum_wait_seconds
        attempt = 0
        while True:
            attempt += 1
            probe = target.with_name(
                f".{target.name}.tmp.candidate.{os.getpid()}.{attempt}"
            )
            _publish_no_overwrite(probe, payload)
            probe_info = probe.lstat()
            probe_inode = (probe_info.st_dev, probe_info.st_ino)
            probe_mtime = _mtime_ns(probe)
            if probe_mtime > threshold:
                for candidate, descriptor, info in opened:
                    _verify_open_outcome(candidate, descriptor, info)
                try:
                    os.link(probe, target)
                except FileExistsError:
                    probe.unlink(missing_ok=True)
                    raise FileExistsError("formal exit marker appeared concurrently")
                for candidate, descriptor, info in opened:
                    _verify_open_outcome(candidate, descriptor, info)
                _fsync_directory(target.parent)
                probe.unlink()
                _fsync_directory(target.parent)
                exit_inode = probe_inode
                for candidate, descriptor, info in opened:
                    _verify_open_outcome(candidate, descriptor, info)
                break
            probe.unlink()
            _fsync_directory(target.parent)
            if time.monotonic() >= deadline:
                raise RegisteredFormalError("filesystem timestamp did not advance")
            sleep_fn(0.25)

        if exit_inode is None:
            raise AssertionError("formal exit inode was not captured")
        final_raw = _wait_for_stable_regular(
            target,
            "formal exit marker",
            expected_payload=payload,
            expected_inode=exit_inode,
            maximum_wait_seconds=maximum_wait_seconds,
            sleep_fn=sleep_fn,
        )
        final_mtime = _mtime_ns(target)
        if final_raw != payload or final_mtime <= threshold:
            raise RegisteredFormalError("formal exit marker postcondition failed")
        return {
            "exit_mtime_ns": final_mtime,
            "outcome_mtime_upper_bound_ns": threshold,
            "return_code": return_code,
            "strictly_later": True,
        }
    finally:
        for _, descriptor, _ in opened:
            os.close(descriptor)


def run_registered_wrapper(
    handoff_path: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> int:
    """Register, await authorization, run formal, and publish the exit marker."""

    if os.getppid() != 1:
        raise RegisteredFormalError("registered wrapper must be detached with ppid=1")
    handoff, _ = register_wrapper(handoff_path)
    _wait_for_authorization(handoff)
    _validate_authorization(
        handoff, Path(handoff["authorization_path"]), require_outcomes_absent=True
    )
    command = [
        handoff["launcher"]["path"],
        "formal",
        "--provenance",
        handoff["provenance"]["path"],
        "--collector-gpus",
        ",".join(str(value) for value in handoff["collector_gpus"]),
        "--eval-gpus",
        ",".join(str(value) for value in handoff["eval_gpus"]),
        "--max-used-memory-mib",
        str(handoff["max_used_memory_mib"]),
    ]
    completed = runner(command, cwd=handoff["checkout_root"], check=False)
    return_code = int(completed.returncode)
    _validate_authorization(
        handoff, Path(handoff["authorization_path"]), require_outcomes_absent=False
    )
    outcomes = [
        Path(handoff["formal_manifest_path"]),
        Path(handoff["formal_decision_path"]),
    ]
    publish_exit_marker(
        exit_path=Path(handoff["exit_path"]),
        return_code=return_code,
        outcome_paths=outcomes,
    )
    return return_code


def launch_detached(handoff_path: Path) -> int:
    """Fork, detach, and exec the exact registered wrapper source."""

    handoff, _ = load_handoff(handoff_path)
    for key in (
        "pid_path",
        "exit_path",
        "launch_expectation_path",
        "ready_path",
        "authorization_path",
        "formal_manifest_path",
        "formal_decision_path",
    ):
        if os.path.lexists(handoff[key]):
            raise RegisteredFormalError(f"fresh path already exists: {key}")
    child = os.fork()
    if child:
        return child
    os.setsid()
    os.chdir("/tmp")
    log_path = Path(handoff["handoff_path"]).parent / WRAPPER_LOG_FILENAME
    if os.path.lexists(log_path):
        raise FileExistsError("refusing pre-existing registered wrapper log")
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    null_in = os.open("/dev/null", os.O_RDONLY)
    os.dup2(null_in, 0)
    os.dup2(descriptor, 1)
    os.dup2(descriptor, 2)
    if null_in > 2:
        os.close(null_in)
    if descriptor > 2:
        os.close(descriptor)
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    close_limit = 1_048_576 if soft_limit == resource.RLIM_INFINITY else int(soft_limit)
    os.closerange(3, close_limit)
    _wait_until_adopted()
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("PYTHON")
    }
    argv = [
        EXPECTED_PYTHON_PATH,
        "-I",
        "-S",
        "-B",
        "-u",
        handoff["wrapper_transport"]["path"],
        "run",
        "--handoff",
        Path(handoff_path).as_posix(),
    ]
    os.execve(EXPECTED_PYTHON_PATH, argv, environment)
    raise AssertionError("execve returned")


def _wait_until_adopted(timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if os.getppid() == 1:
            return
        time.sleep(0.05)
    raise RegisteredFormalError("detached wrapper was not adopted by pid 1")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-handoff")
    build.add_argument("--checkout-root", type=Path, required=True)
    build.add_argument("--durable-attempt-root", type=Path, required=True)
    build.add_argument("--provenance", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--authorization-timeout-seconds", type=int, default=3600)
    launch = subparsers.add_parser("launch")
    launch.add_argument("--handoff", type=Path, required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--handoff", type=Path, required=True)
    authorize = subparsers.add_parser("authorize")
    authorize.add_argument("--handoff", type=Path, required=True)
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    if args.command == "build-handoff":
        handoff = make_handoff(
            checkout_root=args.checkout_root,
            durable_attempt_root=args.durable_attempt_root,
            provenance_path=args.provenance,
            handoff_path=args.output,
            authorization_timeout_seconds=args.authorization_timeout_seconds,
        )
        publish_handoff(args.output, handoff)
        print("registered formal handoff published")
    elif args.command == "launch":
        child = launch_detached(args.handoff)
        print(f"registered formal wrapper launched pid={child}")
    elif args.command == "run":
        _wait_until_adopted()
        raise SystemExit(run_registered_wrapper(args.handoff))
    elif args.command == "authorize":
        authorize_formal_start(args.handoff)
        print("registered formal start authorization published")
    else:  # pragma: no cover
        raise AssertionError("unreachable command")


if __name__ == "__main__":
    main()
