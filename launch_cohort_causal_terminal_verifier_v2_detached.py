#!/usr/bin/env python3
"""Transport-only detached launcher for the causal terminal verifier V2.

The launcher is deployed under a source-commit-qualified directory in /tmp.
Its command line contains only /tmp paths and a delay.  It changes cwd to /tmp,
waits for the interactive SSH ancestry to disappear, publishes a canonical
no-overwrite receipt, and execs the exact plan-bound attester argv.  It has no
scientific authority and never opens efficacy-bearing files.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any


PLAN_PROTOCOL = "cohort_causal_terminal_verifier_execution_plan_v2"
HANDOFF_PROTOCOL = "cohort_causal_terminal_verifier_v2_detached_handoff_v1"
RECEIPT_PROTOCOL = "cohort_causal_terminal_verifier_v2_detached_receipt_v1"
EXPECTED_PYTHON_PATH = "/usr/bin/python3.10"
MINIMUM_DELAY_SECONDS = 30
EXEC_ENV = {
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONHASHSEED": "0",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
}

HANDOFF_KEYS = frozenset(
    {
        "attester_argv",
        "detached_launch_contract",
        "launcher",
        "launcher_argv",
        "minimum_delay_seconds",
        "plan_path",
        "protocol",
        "receipt_path",
        "required_cwd",
        "required_parent_pid",
        "schema_version",
        "status",
        "transport_only_no_scientific_authority",
    }
)
BINDING_KEYS = frozenset({"path", "sha256"})
RECEIPT_KEYS = frozenset(
    {
        "clock_ticks_per_second",
        "cwd",
        "detached_launch_contract",
        "exec_argv_sha256",
        "exec_env_sha256",
        "handoff",
        "launcher",
        "minimum_delay_seconds",
        "observed_age_ticks",
        "outcome_blind",
        "no_pts_fds",
        "pid",
        "plan",
        "process_group_id",
        "ppid",
        "process_start_ticks",
        "protocol",
        "schema_version",
        "session_id",
        "status",
        "startup_ancestors",
        "startup_ancestors_sha256",
        "stdio_targets_sha256",
        "tty_nr",
        "runtime_namespace",
    }
)


class DetachedLaunchError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise DetachedLaunchError("duplicate JSON key")
        result[key] = item
    return result


def _reject_constant(value: str) -> None:
    raise DetachedLaunchError(f"non-finite JSON constant {value}")


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DetachedLaunchError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict) or payload != _canonical(value):
        raise DetachedLaunchError(f"{label} is not a canonical JSON object")
    return value


def _read_stable(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise DetachedLaunchError("transport input is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise DetachedLaunchError("transport input changed while reading")
    return b"".join(chunks)


def _binding(value: Any, label: str) -> tuple[Path, str]:
    if not isinstance(value, dict) or set(value) != BINDING_KEYS:
        raise DetachedLaunchError(f"{label} binding schema differs")
    path = Path(value["path"])
    digest = value["sha256"]
    if (
        not path.is_absolute()
        or os.path.normpath(value["path"]) != value["path"]
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise DetachedLaunchError(f"{label} binding is invalid")
    return path, digest


def _parse_stat(raw: bytes) -> tuple[int, int, int, str]:
    close = raw.rfind(b") ")
    opener = raw.find(b"(")
    fields = raw[close + 2 :].split() if close >= 2 else []
    if (
        opener < 1
        or len(fields) < 20
        or not fields[1].isdigit()
        or not fields[4].lstrip(b"-").isdigit()
        or not fields[19].isdigit()
    ):
        raise DetachedLaunchError("cannot parse proc stat identity")
    return (
        int(fields[1], 10),
        int(fields[19], 10),
        int(fields[4], 10),
        _sha(raw[opener + 1 : close]),
    )


def _proc_identity() -> tuple[int, int, int, int, str]:
    ppid, start_ticks, tty_nr, comm_sha = _parse_stat(
        Path("/proc/self/stat").read_bytes()
    )
    return os.getpid(), ppid, start_ticks, tty_nr, comm_sha


def _startup_ancestors(
    *, start_pid: int | None = None, proc_root: Path = Path("/proc")
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[int] = set()
    pid = os.getppid() if start_pid is None else start_pid
    while pid != 1:
        if pid <= 0 or pid in seen:
            raise DetachedLaunchError("startup ancestor chain is invalid")
        seen.add(pid)
        raw = (proc_root / str(pid) / "stat").read_bytes()
        ppid, start_ticks, _, comm_sha = _parse_stat(raw)
        if ppid == 1:
            # The persistent pid-1-owned listener/service is the trust boundary,
            # not part of the per-session SSH/shell/sudo ancestry that must die.
            break
        records.append(
            {"comm_sha256": comm_sha, "pid": pid, "start_ticks": start_ticks}
        )
        pid = ppid
    return records


def _assert_startup_ancestors_gone(
    records: list[dict[str, Any]], *, proc_root: Path = Path("/proc")
) -> None:
    for record in records:
        try:
            _, start_ticks, _, _ = _parse_stat(
                (proc_root / str(record["pid"]) / "stat").read_bytes()
            )
        except FileNotFoundError:
            continue
        # A process can change comm through exec/prctl without changing its
        # identity.  Treat matching PID+start_ticks as still live.
        if start_ticks == record["start_ticks"]:
            raise DetachedLaunchError("interactive startup ancestor is still live")


def _self_ancestor_record() -> dict[str, Any]:
    pid, _, start_ticks, _, comm_sha = _proc_identity()
    return {"comm_sha256": comm_sha, "pid": pid, "start_ticks": start_ticks}


def _sanitize_file_descriptors() -> list[str]:
    for entry in list(Path("/proc/self/fd").iterdir()):
        try:
            descriptor = int(entry.name)
        except ValueError:
            continue
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError:
                pass
    devnull = os.open("/dev/null", os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    try:
        for descriptor in (0, 1, 2):
            os.dup2(devnull, descriptor, inheritable=True)
    finally:
        if devnull > 2:
            os.close(devnull)
    targets = [os.readlink(f"/proc/self/fd/{descriptor}") for descriptor in (0, 1, 2)]
    if targets != ["/dev/null", "/dev/null", "/dev/null"]:
        raise DetachedLaunchError("stdio was not redirected to /dev/null")
    return targets


def _assert_no_pts_fds() -> None:
    for entry in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        if target.startswith("/dev/pts"):
            raise DetachedLaunchError("a pts file descriptor remains inherited")


def _uptime_ticks(clock_ticks: int) -> int:
    raw = Path("/proc/uptime").read_text(encoding="ascii").split()[0]
    whole, dot, fraction = raw.partition(".")
    if not whole.isdigit() or (dot and not fraction.isdigit()):
        raise DetachedLaunchError("cannot parse /proc/uptime")
    numerator = int(whole) * (10 ** len(fraction)) + int(fraction or "0")
    return numerator * clock_ticks // (10 ** len(fraction))


def _runtime_namespace_identity() -> dict[str, Any]:
    mountinfo = Path("/proc/self/mountinfo").read_bytes().splitlines(keepends=True)
    matches = [
        line
        for line in mountinfo
        if len(line.split()) >= 5 and line.split()[4] == b"/proc"
    ]
    if len(matches) != 1:
        raise DetachedLaunchError("cannot identify exactly one /proc mount")
    proc_metadata = os.stat("/proc", follow_symlinks=False)
    statfs_buffer = ctypes.create_string_buffer(256)
    statfs = ctypes.CDLL(None, use_errno=True).statfs
    statfs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    statfs.restype = ctypes.c_int
    if statfs(b"/proc", ctypes.byref(statfs_buffer)) != 0:
        raise DetachedLaunchError("statfs(/proc) failed")
    proc_super_magic = ctypes.c_long.from_buffer(statfs_buffer).value
    proc1_ppid, proc1_start, _, proc1_comm = _parse_stat(
        Path("/proc/1/stat").read_bytes()
    )
    self_pid_raw = Path("/proc/self/stat").read_bytes().split(b" ", 1)[0]
    if (
        proc1_ppid != 0
        or not self_pid_raw.isdigit()
        or int(self_pid_raw) != os.getpid()
    ):
        raise DetachedLaunchError("proc1/proc-self identity is inconsistent")
    return {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "mount_namespace_inode": os.stat("/proc/self/ns/mnt").st_ino,
        "pid_namespace_inode": os.stat("/proc/self/ns/pid").st_ino,
        "proc1_comm_sha256": proc1_comm,
        "proc1_start_ticks": proc1_start,
        "proc_mountinfo_sha256": _sha(matches[0]),
        "proc_root_device": proc_metadata.st_dev,
        "proc_root_inode": proc_metadata.st_ino,
        "proc_self_consistent": True,
        "proc_super_magic": proc_super_magic,
    }


def _publish_no_overwrite(path: Path, payload: bytes) -> None:
    if os.path.lexists(path):
        raise FileExistsError("detached receipt already exists")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.tmp."
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def launch(*, handoff_path: Path, delay_seconds: int) -> None:
    if delay_seconds != MINIMUM_DELAY_SECONDS:
        raise DetachedLaunchError("detached delay must be exact registered minimum")
    if not handoff_path.is_absolute() or not handoff_path.as_posix().startswith(
        "/tmp/"
    ):
        raise DetachedLaunchError("handoff must use a normalized /tmp path")
    startup_ancestors = [_self_ancestor_record(), *_startup_ancestors()]
    child_pid = os.fork()
    if child_pid != 0:
        os._exit(0)
    os.chdir("/tmp")
    try:
        os.setsid()
    except OSError as exc:
        raise DetachedLaunchError(
            "launcher could not create a detached session"
        ) from exc
    stdio_targets = _sanitize_file_descriptors()
    _assert_no_pts_fds()

    handoff_raw = _read_stable(handoff_path)
    handoff = _strict_json(handoff_raw, "detached handoff")
    if set(handoff) != HANDOFF_KEYS or (
        handoff["protocol"] != HANDOFF_PROTOCOL
        or handoff["schema_version"] != 1
        or handoff["status"] != "registered"
        or handoff["transport_only_no_scientific_authority"] is not True
        or handoff["minimum_delay_seconds"] != MINIMUM_DELAY_SECONDS
        or handoff["required_parent_pid"] != 1
        or handoff["required_cwd"] != "/tmp"
    ):
        raise DetachedLaunchError("detached handoff contract differs")

    launcher_path, launcher_sha = _binding(handoff["launcher"], "launcher")
    self_path = Path(__file__).absolute()
    if self_path != launcher_path or _sha(_read_stable(self_path)) != launcher_sha:
        raise DetachedLaunchError("runtime launcher differs from frozen binding")
    plan_path = Path(handoff["plan_path"])
    plan_raw = _read_stable(plan_path)
    plan = _strict_json(plan_raw, "V2 execution plan")
    if plan.get("protocol") != PLAN_PROTOCOL:
        raise DetachedLaunchError("handoff does not reference a V2 plan")
    transport = plan.get("detached_transport")
    if not isinstance(transport, dict):
        raise DetachedLaunchError("V2 plan has no detached transport binding")
    bound_handoff, bound_handoff_sha = _binding(
        transport.get("handoff"), "plan handoff"
    )
    bound_launcher, bound_launcher_sha = _binding(
        transport.get("launcher"), "plan launcher"
    )
    if (
        bound_handoff != handoff_path
        or bound_handoff_sha != _sha(handoff_raw)
        or bound_launcher != self_path
        or bound_launcher_sha != launcher_sha
    ):
        raise DetachedLaunchError("plan transport bindings differ")
    contract_path, contract_sha = _binding(
        handoff["detached_launch_contract"], "detached contract"
    )
    plan_contract_path, plan_contract_sha = _binding(
        plan.get("detached_launch_contract"), "plan detached contract"
    )
    if (contract_path, contract_sha) != (plan_contract_path, plan_contract_sha):
        raise DetachedLaunchError("handoff/plan detached contracts differ")
    if _sha(_read_stable(contract_path)) != contract_sha:
        raise DetachedLaunchError("detached contract bytes drifted")
    inventory_path, inventory_sha = _binding(
        plan.get("procfs_exception_inventory"), "procfs exception inventory"
    )
    inventory_raw = _read_stable(inventory_path)
    inventory = _strict_json(inventory_raw, "procfs exception inventory")
    baseline_namespace = inventory.get("runtime_namespace")
    if (
        _sha(inventory_raw) != inventory_sha
        or not isinstance(baseline_namespace, dict)
        or _runtime_namespace_identity() != baseline_namespace
    ):
        raise DetachedLaunchError(
            "launcher runtime namespace differs from frozen baseline"
        )

    attester_argv = handoff["attester_argv"]
    launcher_argv = handoff["launcher_argv"]
    if (
        attester_argv != plan.get("invocations", {}).get("attester", {}).get("argv")
        or not isinstance(attester_argv, list)
        or not attester_argv
        or any(not isinstance(item, str) or not item for item in attester_argv)
        or launcher_argv
        != [
            EXPECTED_PYTHON_PATH,
            "-I",
            self_path.as_posix(),
            "--handoff",
            handoff_path.as_posix(),
            "--delay-seconds",
            str(MINIMUM_DELAY_SECONDS),
        ]
        or Path("/proc/self/cmdline").read_bytes()
        != b"\0".join(item.encode("utf-8") for item in launcher_argv) + b"\0"
    ):
        raise DetachedLaunchError("detached launcher or attester argv differs")
    for target in (plan.get("causal_checkout_root"), plan.get("durable_attempt_root")):
        if isinstance(target, str) and any(target in item for item in launcher_argv):
            raise DetachedLaunchError("waiting launcher argv contains an attempt path")

    time.sleep(delay_seconds)
    _assert_startup_ancestors_gone(startup_ancestors)
    pid, ppid, start_ticks, tty_nr, _ = _proc_identity()
    clock_ticks = os.sysconf("SC_CLK_TCK")
    observed_age_ticks = _uptime_ticks(clock_ticks) - start_ticks
    if (
        ppid != 1
        or os.getppid() != 1
        or os.getsid(0) != pid
        or os.getpgrp() != pid
        or tty_nr != 0
        or Path.cwd() != Path("/tmp")
        or observed_age_ticks < delay_seconds * clock_ticks
    ):
        raise DetachedLaunchError("SSH disconnect/cwd/age proof did not close")

    # Recheck every transport binding immediately before receipt publication.
    if (
        _sha(_read_stable(handoff_path)) != _sha(handoff_raw)
        or _sha(_read_stable(plan_path)) != _sha(plan_raw)
        or _sha(_read_stable(self_path)) != launcher_sha
    ):
        raise DetachedLaunchError("transport binding drifted during disconnect wait")
    receipt_path = Path(handoff["receipt_path"])
    receipt = {
        "clock_ticks_per_second": clock_ticks,
        "cwd": "/tmp",
        "detached_launch_contract": handoff["detached_launch_contract"],
        "exec_argv_sha256": _sha(_canonical(attester_argv)),
        "exec_env_sha256": _sha(_canonical(EXEC_ENV)),
        "handoff": {"path": handoff_path.as_posix(), "sha256": _sha(handoff_raw)},
        "launcher": handoff["launcher"],
        "minimum_delay_seconds": delay_seconds,
        "no_pts_fds": True,
        "observed_age_ticks": observed_age_ticks,
        "outcome_blind": True,
        "pid": pid,
        "plan": {"path": plan_path.as_posix(), "sha256": _sha(plan_raw)},
        "process_group_id": os.getpgrp(),
        "ppid": ppid,
        "process_start_ticks": start_ticks,
        "protocol": RECEIPT_PROTOCOL,
        "schema_version": 1,
        "session_id": os.getsid(0),
        "status": "ready_to_exec_exact_attester",
        "runtime_namespace": baseline_namespace,
        "startup_ancestors": startup_ancestors,
        "startup_ancestors_sha256": _sha(_canonical(startup_ancestors)),
        "stdio_targets_sha256": _sha(_canonical(stdio_targets)),
        "tty_nr": tty_nr,
    }
    if set(receipt) != RECEIPT_KEYS:
        raise AssertionError("detached receipt schema drift")
    _publish_no_overwrite(receipt_path, _canonical(receipt))
    os.execve(attester_argv[0], attester_argv, EXEC_ENV)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--delay-seconds", type=int, required=True)
    args = parser.parse_args()
    try:
        launch(handoff_path=args.handoff, delay_seconds=args.delay_seconds)
    except (DetachedLaunchError, FileExistsError, OSError) as exc:
        # Error text contains no raw argv, environment, or artifact contents.
        raise SystemExit(f"detached verifier transport failed: {exc}") from exc


if __name__ == "__main__":
    main()
