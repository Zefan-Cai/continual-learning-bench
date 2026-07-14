#!/usr/bin/env python3
"""Publish the outcome-blind causal completion attestation V2.

The only V2 exception is a frozen exact set of stable processes that predate
the wrapper, whose cmdline remains readable, and whose procfs cwd link returns
EACCES/EPERM.  This is not a platform-provenance claim.  Every cmdline is still
scanned for both causal target paths.  No raw command line is ever persisted.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import attest_cohort_causal_completion as v1
import build_cohort_structured_state_execution_seal_v2 as seal_v2


PROTOCOL = seal_v2.ATTESTATION_PROTOCOL
SCHEMA_VERSION = 2
MINIMUM_STABILITY_SECONDS = v1.MINIMUM_STABILITY_SECONDS
PROCESS_AUDIT_KEYS = seal_v2.PROCESS_AUDIT_KEYS
EXEC_ENV = seal_v2.DETACHED_EXEC_ENV
DETACHED_RECEIPT_KEYS = seal_v2.DETACHED_RECEIPT_KEYS


class AttestationV2Error(v1.AttestationError):
    """A fail-closed V2 completion-attestation error."""


def _parse_proc_stat_identity(payload: bytes) -> tuple[int, int, str]:
    """Parse Linux proc stat ppid/starttime without trusting spaces in comm."""

    close = payload.rfind(b") ")
    if close < 2:
        raise AttestationV2Error("proc stat has no canonical comm terminator")
    fields = payload[close + 2 :].split()
    if len(fields) < 20:
        raise AttestationV2Error("proc stat is truncated before starttime")
    ppid_raw = fields[1]
    start_raw = fields[19]
    if not ppid_raw.isdigit() or not start_raw.isdigit() or start_raw.startswith(b"0"):
        raise AttestationV2Error("proc stat starttime is invalid")
    open_paren = payload.find(b"(")
    if open_paren < 1:
        raise AttestationV2Error("proc stat has no comm opener")
    comm_sha256 = hashlib.sha256(payload[open_paren + 1 : close]).hexdigest()
    return int(ppid_raw, 10), int(start_raw, 10), comm_sha256


def _read_stat_identity(entry: Path) -> tuple[int, int, str]:
    return _parse_proc_stat_identity((entry / "stat").read_bytes())


def _read_process_record(entry: Path, cmdline_bytes: bytes) -> dict[str, Any]:
    try:
        metadata = os.stat(entry, follow_symlinks=False)
        comm_raw = (entry / "comm").read_bytes()
        stat_raw = (entry / "stat").read_bytes()
        cgroup_raw = (entry / "cgroup").read_bytes()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise AttestationV2Error(
            "registered cwd exception metadata is unreadable"
        ) from exc
    if not comm_raw.endswith(b"\n") or comm_raw.count(b"\n") != 1:
        raise AttestationV2Error("proc comm is not one newline-terminated record")
    try:
        comm = comm_raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise AttestationV2Error("proc comm is not ASCII") from exc
    ppid, start_ticks, stat_comm_sha256 = _parse_proc_stat_identity(stat_raw)
    if stat_comm_sha256 != hashlib.sha256(comm_raw[:-1]).hexdigest():
        raise AttestationV2Error("proc stat/comm identity differs")
    return {
        "cgroup_sha256": hashlib.sha256(cgroup_raw).hexdigest(),
        "classification": "stable_pre_wrapper_cwd_permission_denied_process",
        "cmdline_sha256": hashlib.sha256(cmdline_bytes).hexdigest(),
        "cmdline_size_bytes": len(cmdline_bytes),
        "comm": comm,
        "gid": metadata.st_gid,
        "pid": int(entry.name),
        "ppid": ppid,
        "start_ticks": start_ticks,
        "uid": metadata.st_uid,
    }


def _current_exec_identity(
    *,
    proc_stat_path: Path = Path("/proc/self/stat"),
    uptime_path: Path = Path("/proc/uptime"),
) -> tuple[int, int, int, int, int, int]:
    raw = proc_stat_path.read_bytes()
    close = raw.rfind(b") ")
    fields = raw[close + 2 :].split() if close >= 2 else []
    if len(fields) < 20 or not fields[1].isdigit() or not fields[19].isdigit():
        raise AttestationV2Error("cannot parse attester /proc/self/stat")
    ppid = int(fields[1], 10)
    start_ticks = int(fields[19], 10)
    clock_ticks = os.sysconf("SC_CLK_TCK")
    uptime_raw = uptime_path.read_text(encoding="ascii").split()[0]
    whole, dot, fraction = uptime_raw.partition(".")
    if not whole.isdigit() or (dot and not fraction.isdigit()):
        raise AttestationV2Error("cannot parse attester /proc/uptime")
    numerator = int(whole) * (10 ** len(fraction)) + int(fraction or "0")
    uptime_ticks = numerator * clock_ticks // (10 ** len(fraction))
    tty_raw = fields[4]
    if not tty_raw.lstrip(b"-").isdigit():
        raise AttestationV2Error("attester tty_nr is invalid")
    return (
        os.getpid(),
        ppid,
        start_ticks,
        int(tty_raw, 10),
        clock_ticks,
        uptime_ticks - start_ticks,
    )


def _stdio_and_pts_state() -> tuple[list[str], bool]:
    targets = [os.readlink(f"/proc/self/fd/{descriptor}") for descriptor in (0, 1, 2)]
    no_pts = True
    for entry in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        if target.startswith("/dev/pts"):
            no_pts = False
    return targets, no_pts


def _assert_ancestors_gone(
    records: list[dict[str, Any]], *, proc_root: Path = Path("/proc")
) -> None:
    if len(records) != 1:
        raise AttestationV2Error("receipt needs exactly one detached launcher parent")
    seen: set[int] = set()
    for record in records:
        if (
            not isinstance(record, dict)
            or set(record) != {"comm_sha256", "pid", "start_ticks"}
            or not seal_v2._is_int(record["pid"])
            or record["pid"] <= 1
            or record["pid"] in seen
            or not seal_v2._is_int(record["start_ticks"])
            or record["start_ticks"] <= 0
        ):
            raise AttestationV2Error("startup ancestor receipt is invalid")
        seal_v2._require_sha256(record["comm_sha256"], "startup ancestor comm")
        seen.add(record["pid"])
        try:
            _, start_ticks, _ = _read_stat_identity(proc_root / str(record["pid"]))
        except FileNotFoundError:
            continue
        # PID plus start_ticks is the stable process identity; comm may change
        # after exec/prctl while the same startup ancestor remains live.
        if start_ticks == record["start_ticks"]:
            raise AttestationV2Error("detached launcher parent remains live")


def _current_runtime_namespace() -> dict[str, Any]:
    lines = Path("/proc/self/mountinfo").read_bytes().splitlines(keepends=True)
    matches = [
        line for line in lines if len(line.split()) >= 5 and line.split()[4] == b"/proc"
    ]
    if len(matches) != 1:
        raise AttestationV2Error("cannot identify exactly one current /proc mount")
    proc_metadata = os.stat("/proc", follow_symlinks=False)
    statfs_buffer = ctypes.create_string_buffer(256)
    statfs = ctypes.CDLL(None, use_errno=True).statfs
    statfs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    statfs.restype = ctypes.c_int
    if statfs(b"/proc", ctypes.byref(statfs_buffer)) != 0:
        raise AttestationV2Error("statfs(/proc) failed")
    proc_super_magic = ctypes.c_long.from_buffer(statfs_buffer).value
    proc1_ppid, proc1_start_ticks, proc1_comm_sha256 = _read_stat_identity(
        Path("/proc/1")
    )
    if proc1_ppid != 0:
        raise AttestationV2Error("/proc/1 does not have PPID zero")
    self_raw = Path("/proc/self/stat").read_bytes()
    self_pid_raw = self_raw.split(b" ", 1)[0]
    if not self_pid_raw.isdigit() or int(self_pid_raw, 10) != os.getpid():
        raise AttestationV2Error("/proc/self is inconsistent with getpid")
    return {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "mount_namespace_inode": os.stat("/proc/self/ns/mnt").st_ino,
        "pid_namespace_inode": os.stat("/proc/self/ns/pid").st_ino,
        "proc1_comm_sha256": proc1_comm_sha256,
        "proc1_start_ticks": proc1_start_ticks,
        "proc_mountinfo_sha256": hashlib.sha256(matches[0]).hexdigest(),
        "proc_root_device": proc_metadata.st_dev,
        "proc_root_inode": proc_metadata.st_ino,
        "proc_self_consistent": True,
        "proc_super_magic": proc_super_magic,
    }


def _validate_detached_receipt(
    *,
    path: Path,
    plan: dict[str, Any],
    plan_raw: bytes,
    expected_runtime_namespace: dict[str, Any],
    proc_identity_fn: Callable[
        [], tuple[int, int, int, int, int, int]
    ] = _current_exec_identity,
    getppid_fn: Callable[[], int] = os.getppid,
    getcwd_fn: Callable[[], str] = os.getcwd,
    getsid_fn: Callable[[int], int] = os.getsid,
    getpgrp_fn: Callable[[], int] = os.getpgrp,
    runtime_namespace_fn: Callable[[], dict[str, Any]] = _current_runtime_namespace,
    environ_fn: Callable[[], dict[str, str]] = lambda: dict(os.environ),
    cmdline_fn: Callable[[], bytes] = lambda: Path("/proc/self/cmdline").read_bytes(),
    stdio_fn: Callable[[], tuple[list[str], bool]] = _stdio_and_pts_state,
    ancestors_gone_fn: Callable[[list[dict[str, Any]]], None] = _assert_ancestors_gone,
) -> dict[str, Any]:
    receipt_raw = v1._read_opaque_bytes(path, permitted_roots=(path.parent,))
    try:
        receipt = seal_v2.validate_detached_receipt_document(
            seal_v2._strict_json_bytes(receipt_raw, "detached launch receipt"),
            plan=plan,
            execution_plan_path=(
                Path(plan["durable_attempt_root"]) / "control" / seal_v2.PLAN_FILENAME
            ),
            execution_plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
            runtime_namespace=expected_runtime_namespace,
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise AttestationV2Error("detached launch receipt is invalid") from exc
    transport = plan["detached_transport"]
    expected_plan = {
        "path": (
            Path(plan["durable_attempt_root"]) / "control" / seal_v2.PLAN_FILENAME
        ).as_posix(),
        "sha256": hashlib.sha256(plan_raw).hexdigest(),
    }
    if (
        path.as_posix() != transport["receipt_path"]
        or receipt["plan"] != expected_plan
        or receipt["handoff"] != transport["handoff"]
        or receipt["launcher"] != transport["launcher"]
        or receipt["detached_launch_contract"] != plan["detached_launch_contract"]
        or receipt["exec_argv_sha256"]
        != seal_v2.canonical_sha256(plan["invocations"]["attester"]["argv"])
        or receipt["exec_env_sha256"] != seal_v2.canonical_sha256(EXEC_ENV)
        or receipt["minimum_delay_seconds"] != 30
    ):
        raise AttestationV2Error("detached launch receipt bindings differ")
    for key in (
        "clock_ticks_per_second",
        "minimum_delay_seconds",
        "observed_age_ticks",
        "pid",
        "process_group_id",
        "ppid",
        "process_start_ticks",
        "session_id",
    ):
        if not seal_v2._is_int(receipt[key]) or receipt[key] < 1:
            raise AttestationV2Error(f"detached receipt {key} is invalid")
    pid, ppid, start_ticks, tty_nr, clock_ticks, current_age_ticks = proc_identity_fn()
    expected_cmdline = (
        b"\0".join(
            item.encode("utf-8") for item in plan["invocations"]["attester"]["argv"]
        )
        + b"\0"
    )
    stdio_targets, no_pts_fds = stdio_fn()
    ancestors = receipt["startup_ancestors"]
    if not isinstance(ancestors, list) or receipt[
        "startup_ancestors_sha256"
    ] != seal_v2.canonical_sha256(ancestors):
        raise AttestationV2Error("startup ancestor digest differs")
    ancestors_gone_fn(ancestors)
    if (
        receipt["pid"] != pid
        or receipt["ppid"] != 1
        or ppid != 1
        or getppid_fn() != 1
        or receipt["process_start_ticks"] != start_ticks
        or receipt["clock_ticks_per_second"] != clock_ticks
        or receipt["session_id"] != pid
        or receipt["process_group_id"] != pid
        or getsid_fn(0) != pid
        or getpgrp_fn() != pid
        or receipt["tty_nr"] != 0
        or tty_nr != 0
        or receipt["cwd"] != "/tmp"
        or getcwd_fn() != "/tmp"
        or receipt["observed_age_ticks"] < 30 * clock_ticks
        or current_age_ticks < 30 * clock_ticks
        or receipt["runtime_namespace"] != expected_runtime_namespace
        or runtime_namespace_fn() != expected_runtime_namespace
        or receipt["no_pts_fds"] is not True
        or no_pts_fds is not True
        or stdio_targets != ["/dev/null", "/dev/null", "/dev/null"]
        or receipt["stdio_targets_sha256"] != seal_v2.canonical_sha256(stdio_targets)
        or environ_fn() != EXEC_ENV
        or cmdline_fn() != expected_cmdline
    ):
        raise AttestationV2Error("detached exec identity/cwd/age proof differs")
    return receipt


def _scan_process_references(
    *,
    attempt_checkout: Path,
    artifact_root: Path,
    exception_records: list[dict[str, Any]],
    exception_file_sha256: str,
    proc_root: Path = Path("/proc"),
    self_pid: int | None = None,
) -> dict[str, Any]:
    """Prove exact process absence with the frozen cwd-only exception set."""

    if not proc_root.is_dir():
        raise AttestationV2Error("Linux procfs is required for V2 process audit")
    targets = (
        v1._absolute_without_following(attempt_checkout),
        v1._absolute_without_following(artifact_root).parents[1],
        v1._absolute_without_following(artifact_root),
    )
    target_bytes = tuple(target.as_posix().encode("utf-8") for target in targets)
    registered = {record["pid"]: record for record in exception_records}
    if len(registered) != len(exception_records):
        raise AttestationV2Error("frozen exception PIDs are not unique")
    observed: list[dict[str, Any]] = []
    current_self = os.getpid() if self_pid is None else self_pid
    try:
        entries = sorted(
            (entry for entry in proc_root.iterdir() if entry.name.isdigit()),
            key=lambda entry: int(entry.name),
        )
    except OSError as exc:
        raise AttestationV2Error("cannot enumerate Linux procfs") from exc
    for entry in entries:
        pid = int(entry.name)
        if pid == current_self:
            continue
        try:
            identity_before = _read_stat_identity(entry)
            cmdline_bytes = (entry / "cmdline").read_bytes()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AttestationV2Error(
                "process cmdline is unreadable; V2 permits cwd-only exceptions"
            ) from exc
        if any(target in cmdline_bytes for target in target_bytes):
            raise AttestationV2Error("a live process cmdline references the attempt")
        try:
            cwd = Path(os.readlink(entry / "cwd"))
        except FileNotFoundError:
            continue
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EPERM}:
                raise AttestationV2Error(
                    "process cwd failed for a reason other than EACCES/EPERM"
                ) from exc
            try:
                record = _read_process_record(entry, cmdline_bytes)
            except FileNotFoundError:
                continue
            expected = registered.get(pid)
            if expected is None:
                raise AttestationV2Error("unregistered process has unreadable cwd")
            if record != expected:
                raise AttestationV2Error(
                    "registered cwd exception drifted or its PID restarted"
                )
            observed.append(record)
            try:
                if _read_stat_identity(entry) != identity_before:
                    raise AttestationV2Error(
                        "process identity changed during procfs audit"
                    )
            except FileNotFoundError as exc:
                raise AttestationV2Error(
                    "registered exception vanished during procfs audit"
                ) from exc
            continue
        for target in targets:
            if v1._path_contains(cwd, target):
                raise AttestationV2Error("a live process cwd references the attempt")
        try:
            if _read_stat_identity(entry) != identity_before:
                raise AttestationV2Error("process identity changed during procfs audit")
        except FileNotFoundError:
            continue
    observed.sort(key=lambda item: (item["pid"], item["start_ticks"]))
    if seal_v2.canonical_bytes(observed) != seal_v2.canonical_bytes(exception_records):
        raise AttestationV2Error(
            "observed cwd exception set has missing or extra records"
        )
    payload = {
        "artifact_root_path": targets[2].as_posix(),
        "attempt_checkout_path": targets[0].as_posix(),
        "durable_attempt_root_path": targets[1].as_posix(),
        "exception_inventory_sha256": seal_v2._require_sha256(
            exception_file_sha256, "exception file SHA-256"
        ),
        "method": seal_v2.PROCESS_AUDIT_METHOD,
        "observed_exception_count": len(observed),
        "observed_exceptions_sha256": seal_v2.canonical_sha256(observed),
        "status": "pass",
    }
    return {**payload, "audit_sha256": seal_v2.canonical_sha256(payload)}


@contextmanager
def _capture_v1_attestation_as_v2(
    *, exception_path: Path, detached_receipt_path: Path
) -> Iterable[dict[str, Any]]:
    captured: dict[str, Any] = {}

    def plan_adapter(**kwargs: Any):
        inputs = dict(kwargs["expected_inputs"])
        inputs["procfs_exception_inventory"] = exception_path
        inputs["detached_launch_receipt"] = detached_receipt_path
        kwargs["expected_inputs"] = inputs
        return seal_v2.load_and_validate_execution_plan_stage(**kwargs)

    def capture_publish(path: Path, payload: bytes) -> None:
        if captured:
            raise AttestationV2Error("V1 engine attempted multiple publications")
        captured["path"] = path
        captured["payload"] = payload

    replacements = {
        "PROTOCOL": PROTOCOL,
        "SCHEMA_VERSION": SCHEMA_VERSION,
        "PROCESS_AUDIT_KEYS": PROCESS_AUDIT_KEYS,
        "load_and_validate_execution_plan_stage": plan_adapter,
        "_atomic_publish_no_overwrite": capture_publish,
    }
    previous = {name: getattr(v1, name) for name in replacements}
    try:
        for name, item in replacements.items():
            setattr(v1, name, item)
        yield captured
    finally:
        for name, item in previous.items():
            setattr(v1, name, item)


def build_and_publish_attestation(
    *,
    root: Path,
    execution_plan_path: Path,
    detached_launch_receipt_path: Path,
    launch_expectation_path: Path,
    procfs_exception_inventory_path: Path,
    provenance_path: Path,
    provenance_details_path: Path,
    output: Path,
    stability_seconds: float = MINIMUM_STABILITY_SECONDS,
    sleep_fn: Callable[[float], None] = __import__("time").sleep,
    monotonic_fn: Callable[[], float] = __import__("time").monotonic,
    now_fn: Callable[[], str] = v1._utc_now,
    pid_is_live_fn: Callable[[int], bool] = v1._pid_is_live,
    temporary_audit_fn: Callable[..., dict[str, Any]] = v1._scan_live_or_temporary,
    boot_id_fn: Callable[[], str] = v1._current_boot_id,
    hostname_fn: Callable[[], str] = __import__("socket").gethostname,
    source_commit_fn: Callable[[Path], str] = v1._current_source_commit,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
    proc_root: Path = Path("/proc"),
    self_pid: int | None = None,
) -> dict[str, Any]:
    """Run the exact V1 terminal gates plus the V2 procfs exception proof."""

    root = v1._absolute_without_following(root)
    execution_plan_path = v1._absolute_without_following(execution_plan_path)
    detached_receipt_path = v1._absolute_without_following(detached_launch_receipt_path)
    launch_expectation_path = v1._absolute_without_following(launch_expectation_path)
    exception_path = v1._absolute_without_following(procfs_exception_inventory_path)
    output = v1._absolute_without_following(output)
    if os.path.lexists(output):
        raise FileExistsError("refusing to overwrite V2 completion attestation")
    stage_inputs = {
        "detached_launch_receipt": detached_receipt_path,
        "execution_plan": execution_plan_path,
        "launch_expectation": launch_expectation_path,
        "procfs_exception_inventory": exception_path,
        "provenance": v1._absolute_without_following(provenance_path),
        "provenance_details": v1._absolute_without_following(provenance_details_path),
        "root": root,
    }
    stage_outputs = {"attestation": output}
    stage_parameters = {"stability_seconds": str(stability_seconds)}
    try:
        plan, plan_raw = seal_v2.load_and_validate_execution_plan_stage(
            execution_plan_path=execution_plan_path,
            stage="attester",
            expected_inputs=stage_inputs,
            expected_outputs=stage_outputs,
            expected_parameters=stage_parameters,
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise AttestationV2Error("V2 execution plan is invalid") from exc
    expectation, expectation_raw = v1._load_launch_expectation(launch_expectation_path)
    exception_raw = v1._read_opaque_bytes(
        exception_path, permitted_roots=(exception_path.parent,)
    )
    exception_object = seal_v2._strict_json_bytes(
        exception_raw, "frozen procfs exception inventory"
    )
    exception, records = seal_v2.validate_exception_inventory(
        exception_object,
        launch_expectation_path=launch_expectation_path,
        launch_expectation_sha256=hashlib.sha256(expectation_raw).hexdigest(),
        wrapper_pid=expectation["wrapper_pid"],
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
    )
    if (
        exception_path
        != Path(expectation["durable_attempt_root"])
        / "control"
        / seal_v2.EXCEPTION_INVENTORY_FILENAME
    ):
        raise AttestationV2Error("procfs exception inventory path is not fixed")
    exception_file_sha256 = hashlib.sha256(exception_raw).hexdigest()
    receipt = _validate_detached_receipt(
        path=detached_receipt_path,
        plan=plan,
        plan_raw=plan_raw,
        expected_runtime_namespace=exception["runtime_namespace"],
    )

    def process_audit_fn(*, attempt_checkout: Path, artifact_root: Path):
        return _scan_process_references(
            attempt_checkout=attempt_checkout,
            artifact_root=artifact_root,
            exception_records=records,
            exception_file_sha256=exception_file_sha256,
            proc_root=proc_root,
            self_pid=self_pid,
        )

    with _capture_v1_attestation_as_v2(
        exception_path=exception_path,
        detached_receipt_path=detached_receipt_path,
    ) as captured:
        v1.build_and_publish_attestation(
            root=root,
            execution_plan_path=execution_plan_path,
            launch_expectation_path=launch_expectation_path,
            provenance_path=provenance_path,
            provenance_details_path=provenance_details_path,
            output=output,
            stability_seconds=stability_seconds,
            sleep_fn=sleep_fn,
            monotonic_fn=monotonic_fn,
            now_fn=now_fn,
            pid_is_live_fn=pid_is_live_fn,
            process_audit_fn=process_audit_fn,
            temporary_audit_fn=temporary_audit_fn,
            boot_id_fn=boot_id_fn,
            hostname_fn=hostname_fn,
            source_commit_fn=source_commit_fn,
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    if captured.get("path") != output or not isinstance(captured.get("payload"), bytes):
        raise AttestationV2Error("V1 terminal engine produced no captured payload")
    attestation = json.loads(captured["payload"])
    detached_receipt_raw = v1._read_opaque_bytes(
        detached_receipt_path, permitted_roots=(detached_receipt_path.parent,)
    )
    attestation["detached_launch_receipt"] = {
        "path": detached_receipt_path.as_posix(),
        "pid": receipt["pid"],
        "process_start_ticks": receipt["process_start_ticks"],
        "sha256": hashlib.sha256(detached_receipt_raw).hexdigest(),
    }
    attestation["procfs_exception_inventory"] = {
        "inventory_sha256": exception["inventory_sha256"],
        "path": exception_path.as_posix(),
        "sha256": exception_file_sha256,
    }
    if set(attestation) != seal_v2.ATTESTATION_KEYS:
        raise AssertionError("V2 attestation exact schema drift")

    # Close the capture/enrichment window without parsing any efficacy artifact.
    try:
        final_plan, final_plan_raw = seal_v2.load_and_validate_execution_plan_stage(
            execution_plan_path=execution_plan_path,
            stage="attester",
            expected_inputs=stage_inputs,
            expected_outputs=stage_outputs,
            expected_parameters=stage_parameters,
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise AttestationV2Error("V2 bindings drifted before publication") from exc
    final_receipt = _validate_detached_receipt(
        path=detached_receipt_path,
        plan=final_plan,
        plan_raw=final_plan_raw,
        expected_runtime_namespace=exception["runtime_namespace"],
    )
    if final_plan_raw != plan_raw or seal_v2.canonical_bytes(
        final_receipt
    ) != seal_v2.canonical_bytes(receipt):
        raise AttestationV2Error("V2 plan or detached receipt drifted before publish")
    current_exception = v1._read_opaque_bytes(
        exception_path, permitted_roots=(exception_path.parent,)
    )
    current_plan = v1._read_opaque_bytes(
        execution_plan_path, permitted_roots=(execution_plan_path.parent,)
    )
    current_receipt = v1._read_opaque_bytes(
        detached_receipt_path, permitted_roots=(detached_receipt_path.parent,)
    )
    if hashlib.sha256(current_exception).hexdigest() != exception_file_sha256:
        raise AttestationV2Error("frozen exception inventory drifted before publish")
    if hashlib.sha256(current_plan).hexdigest() != attestation["execution_plan_sha256"]:
        raise AttestationV2Error("V2 execution plan drifted before publish")
    if (
        hashlib.sha256(current_receipt).hexdigest()
        != attestation["detached_launch_receipt"]["sha256"]
    ):
        raise AttestationV2Error("detached launch receipt drifted before publish")
    payload = seal_v2.canonical_bytes(attestation)
    v1._assert_no_symlink_components(
        output.parent, (Path(expectation["durable_attempt_root"]),)
    )
    # Use the saved V1 primitive after the interception context has restored it.
    v1._atomic_publish_no_overwrite(output, payload)
    return {
        "attestation_sha256": hashlib.sha256(payload).hexdigest(),
        "causal_pre_attestation_inventory_sha256": attestation[
            "causal_pre_attestation_inventory_sha256"
        ],
        "path": output.as_posix(),
        "status": "complete",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--detached-launch-receipt", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--procfs-exception-inventory", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--provenance-details", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stability-seconds", type=float, default=1.0)
    args = parser.parse_args()
    try:
        result = build_and_publish_attestation(
            root=args.root,
            execution_plan_path=args.execution_plan,
            detached_launch_receipt_path=args.detached_launch_receipt,
            launch_expectation_path=args.launch_expectation,
            procfs_exception_inventory_path=args.procfs_exception_inventory,
            provenance_path=args.provenance,
            provenance_details_path=args.provenance_details,
            output=args.output,
            stability_seconds=args.stability_seconds,
        )
    except (
        AttestationV2Error,
        v1.AttestationError,
        seal_v2.ExecutionSealV2Error,
        FileExistsError,
    ) as exc:
        raise SystemExit(f"causal completion attestation V2 failed: {exc}") from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
