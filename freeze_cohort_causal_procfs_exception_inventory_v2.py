#!/usr/bin/env python3
"""Freeze the outcome-blind procfs cwd-exception inventory for verifier V2.

This standalone transport utility reads only the launch expectation and Linux
procfs.  It daemonizes from /tmp, waits through a detachment grace period and
requires its fork-launching parent to disappear, takes two snapshots at least
one second apart, and canonically publishes an exact static set plus one bounded
rotating monitor-connect child observation.  It never stores or prints raw argv
or cgroups.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROTOCOL = "cohort_causal_procfs_cwd_exception_inventory_v2"
OUTPUT_FILENAME = "CAUSAL_TERMINAL_VERIFIER_PROCFS_EXCEPTION_INVENTORY_V2.json"
PROC_SUPER_MAGIC = 0x9FA0
DETACHMENT_GRACE_SECONDS = 30
SNAPSHOT_INTERVAL_SECONDS = 1
DYNAMIC_POLICY_DISCOVERY_INTERVAL_SECONDS = 0.05
DYNAMIC_POLICY_DISCOVERY_MAX_ATTEMPTS = 100
EXPECTED_PYTHON_PATH = "/usr/bin/python3.10"
EXPECTED_PYTHON_VERSION = "3.10.12"
EXEC_ENV = {
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONHASHSEED": "0",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
}
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
ANCESTOR_KEYS = frozenset({"comm_sha256", "pid", "start_ticks"})
TRANSPORT_PROOF_KEYS = frozenset(
    {
        "cwd",
        "exec_argv_sha256",
        "exec_env_sha256",
        "no_pts_fds",
        "pid",
        "ppid",
        "process_group_id",
        "process_start_ticks",
        "python_path",
        "python_version",
        "session_id",
        "startup_ancestors",
        "startup_ancestors_sha256",
        "stdio_targets_sha256",
        "tty_nr",
    }
)


class FreezerError(RuntimeError):
    pass


class DynamicPolicyDiscoveryPending(FreezerError):
    """A single exact anchor-clone child was seen before its sleep exec."""

    def __init__(
        self,
        static_records: list[dict[str, Any]],
        anchor_binding: dict[str, Any],
    ) -> None:
        super().__init__("dynamic policy discovery observed the exact anchor clone")
        self.static_records = static_records
        self.anchor_binding = anchor_binding


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


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _read_stable(path: Path) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise FreezerError("freezer input is not a regular file")
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
        raise FreezerError("freezer input changed while reading")
    return b"".join(chunks)


def _strict_json(payload: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise FreezerError("launch expectation has duplicate keys")
            result[key] = item
        return result

    def constant(item: str) -> None:
        raise FreezerError(f"launch expectation has non-finite {item}")

    try:
        value = json.loads(payload, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreezerError("launch expectation is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != EXPECTATION_KEYS:
        raise FreezerError("launch expectation must be an object")
    return value


def _parse_stat(raw: bytes) -> tuple[int, int, str]:
    close = raw.rfind(b") ")
    opener = raw.find(b"(")
    fields = raw[close + 2 :].split() if close >= 2 else []
    if (
        opener < 1
        or len(fields) < 20
        or not fields[1].isdigit()
        or not fields[19].isdigit()
    ):
        raise FreezerError("proc stat identity is invalid")
    return int(fields[1]), int(fields[19]), _sha(raw[opener + 1 : close])


def _path_contains(candidate: Path, root: Path) -> bool:
    candidate = Path(os.path.abspath(candidate))
    root = Path(os.path.abspath(root))
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return candidate == root


def _status_ids(entry: Path) -> tuple[list[int], list[int]]:
    status = (entry / "status").read_bytes().splitlines()
    uid_lines = [line for line in status if line.startswith(b"Uid:")]
    gid_lines = [line for line in status if line.startswith(b"Gid:")]
    if len(uid_lines) != 1 or len(gid_lines) != 1:
        raise FreezerError("proc status has no unique Uid/Gid records")

    def parse(line: bytes, label: str) -> list[int]:
        fields = line.split()[1:]
        if len(fields) != 4 or any(not field.isdigit() for field in fields):
            raise FreezerError(f"proc status {label} is not four canonical IDs")
        return [int(field) for field in fields]

    return parse(uid_lines[0], "Uid"), parse(gid_lines[0], "Gid")


def _process_record(
    entry: Path, cmdline: bytes, *, cwd_errno: int, classification: str
) -> dict[str, Any]:
    metadata = os.stat(entry, follow_symlinks=False)
    comm_raw = (entry / "comm").read_bytes()
    cgroup_raw = (entry / "cgroup").read_bytes()
    stat_raw = (entry / "stat").read_bytes()
    status_uids, status_gids = _status_ids(entry)
    if not comm_raw.endswith(b"\n") or comm_raw.count(b"\n") != 1:
        raise FreezerError("proc comm is not canonical")
    try:
        comm = comm_raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise FreezerError("proc comm is not ASCII") from exc
    ppid, start_ticks, comm_sha = _parse_stat(stat_raw)
    if _sha(comm_raw[:-1]) != comm_sha:
        raise FreezerError("proc stat/comm identity differs")
    return {
        "cgroup_sha256": _sha(cgroup_raw),
        "classification": classification,
        "cmdline_sha256": _sha(cmdline),
        "cmdline_size_bytes": len(cmdline),
        "comm": comm,
        "cwd_errno": cwd_errno,
        "gid": metadata.st_gid,
        "pid": int(entry.name),
        "ppid": ppid,
        "start_ticks": start_ticks,
        "status_gids": status_gids,
        "status_uids": status_uids,
        "uid": metadata.st_uid,
    }


def _dynamic_policy(anchor: dict[str, Any], leaf: dict[str, Any]) -> dict[str, Any]:
    return {
        "anchor_comm": "monitor-connect",
        "anchor_pid": anchor["pid"],
        "anchor_start_ticks": anchor["start_ticks"],
        "anchor_static_record_sha256": _sha(_canonical(anchor)),
        "classification": "dynamic_monitor_connect_sleep_cwd_eacces_direct_child_policy",
        "direct_child_required": True,
        "dynamic_cwd_target_absence_mechanically_proven": False,
        "dynamic_platform_origin_mechanically_proven": False,
        "leaf_cgroup_sha256": leaf["cgroup_sha256"],
        "leaf_cmdline_sha256": leaf["cmdline_sha256"],
        "leaf_cmdline_size_bytes": leaf["cmdline_size_bytes"],
        "leaf_comm": "sleep",
        "leaf_cwd_errno": errno.EACCES,
        "leaf_proc_dir_gid": 0,
        "leaf_proc_dir_uid": 0,
        "leaf_status_gids": [0, 0, 0, 0],
        "leaf_status_uids": [0, 0, 0, 0],
        "literal_cmdline_target_scan_required": True,
        "max_concurrent": 1,
        "required_concurrent": 1,
        "transitional_leaf_cmdline_sha256": anchor["cmdline_sha256"],
        "transitional_leaf_cmdline_size_bytes": anchor["cmdline_size_bytes"],
        "transitional_leaf_comm": "monitor-connect",
    }


def _anchor_binding(anchor: dict[str, Any]) -> dict[str, Any]:
    return {
        "pid": anchor["pid"],
        "start_ticks": anchor["start_ticks"],
        "static_record_sha256": _sha(_canonical(anchor)),
    }


def _matches_dynamic_leaf(
    record: dict[str, Any],
    *,
    policy: dict[str, Any],
    proc1_cgroup_sha256: str,
    wrapper_start_ticks: int,
) -> bool:
    exact_profile = (
        record["comm"] == policy["leaf_comm"] == "sleep"
        and record["cmdline_sha256"] == policy["leaf_cmdline_sha256"]
        and record["cmdline_size_bytes"] == policy["leaf_cmdline_size_bytes"]
    ) or (
        record["comm"] == policy["transitional_leaf_comm"] == "monitor-connect"
        and record["cmdline_sha256"] == policy["transitional_leaf_cmdline_sha256"]
        and record["cmdline_size_bytes"]
        == policy["transitional_leaf_cmdline_size_bytes"]
    )
    return (
        record["classification"] == "dynamic_monitor_connect_sleep_cwd_eacces_process"
        and record["ppid"] == policy["anchor_pid"]
        and exact_profile
        and record["cmdline_size_bytes"] > 0
        and record["start_ticks"] >= wrapper_start_ticks
        and record["uid"] == record["gid"] == 0
        and record["status_uids"] == record["status_gids"] == [0, 0, 0, 0]
        and record["cgroup_sha256"]
        == policy["leaf_cgroup_sha256"]
        == proc1_cgroup_sha256
        and record["cwd_errno"] == policy["leaf_cwd_errno"] == errno.EACCES
    )


def _scan(
    *,
    proc_root: Path,
    targets: tuple[Path, ...],
    self_pid: int,
    wrapper_start_ticks: int,
    proc1_cgroup_sha256: str,
    frozen_dynamic_policy: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    denied: list[dict[str, Any]] = []
    for entry in sorted(
        (item for item in proc_root.iterdir() if item.name.isdigit()),
        key=lambda item: int(item.name),
    ):
        pid = int(entry.name)
        if pid == self_pid:
            continue
        try:
            before = _parse_stat((entry / "stat").read_bytes())
            cmdline = (entry / "cmdline").read_bytes()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FreezerError("a process cmdline/stat is unreadable") from exc
        if any(target.as_posix().encode() in cmdline for target in targets):
            raise FreezerError("a process cmdline references the causal attempt")
        try:
            cwd = Path(os.readlink(entry / "cwd"))
        except FileNotFoundError:
            continue
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EPERM}:
                raise FreezerError(
                    "a process cwd failed outside the allowed errno"
                ) from exc
            try:
                denied.append(
                    _process_record(
                        entry,
                        cmdline,
                        cwd_errno=exc.errno,
                        classification=(
                            "stable_pre_wrapper_cwd_permission_denied_process"
                        ),
                    )
                )
                after = _parse_stat((entry / "stat").read_bytes())
            except FileNotFoundError as vanished:
                raise FreezerError(
                    "cwd exception vanished during snapshot"
                ) from vanished
            if after != before:
                raise FreezerError("cwd exception identity changed during snapshot")
            continue
        if any(_path_contains(cwd, target) for target in targets):
            raise FreezerError("a process cwd references the causal attempt")
        try:
            after = _parse_stat((entry / "stat").read_bytes())
        except FileNotFoundError:
            continue
        if after != before:
            raise FreezerError("process identity changed during snapshot")
    anchors = [
        record
        for record in denied
        if record["comm"] == "monitor-connect"
        and record["start_ticks"] < wrapper_start_ticks
    ]
    if frozen_dynamic_policy is None:
        pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for anchor in anchors:
            for record in denied:
                candidate = {
                    **record,
                    "classification": (
                        "dynamic_monitor_connect_sleep_cwd_eacces_process"
                    ),
                }
                provisional = _dynamic_policy(anchor, candidate)
                if record["comm"] == "sleep" and _matches_dynamic_leaf(
                    candidate,
                    policy=provisional,
                    proc1_cgroup_sha256=proc1_cgroup_sha256,
                    wrapper_start_ticks=wrapper_start_ticks,
                ):
                    pairs.append((anchor, candidate))
        if not pairs:
            transition_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for anchor in anchors:
                for record in denied:
                    candidate = {
                        **record,
                        "classification": (
                            "dynamic_monitor_connect_sleep_cwd_eacces_process"
                        ),
                    }
                    provisional = _dynamic_policy(anchor, candidate)
                    if record["comm"] == "monitor-connect" and _matches_dynamic_leaf(
                        candidate,
                        policy=provisional,
                        proc1_cgroup_sha256=proc1_cgroup_sha256,
                        wrapper_start_ticks=wrapper_start_ticks,
                    ):
                        transition_pairs.append((anchor, candidate))
            if len(transition_pairs) == 1:
                transition_anchor, transition_leaf = transition_pairs[0]
                static_during_discovery = [
                    record
                    for record in denied
                    if record["pid"] != transition_leaf["pid"]
                ]
                if (
                    len(static_during_discovery) + 1 == len(denied)
                    and all(
                        record["start_ticks"] < wrapper_start_ticks
                        for record in static_during_discovery
                    )
                    and any(
                        record["pid"] == transition_anchor["pid"]
                        and record["start_ticks"] == transition_anchor["start_ticks"]
                        and _sha(_canonical(record))
                        == _sha(_canonical(transition_anchor))
                        for record in static_during_discovery
                    )
                ):
                    static_during_discovery.sort(
                        key=lambda record: (record["pid"], record["start_ticks"])
                    )
                    raise DynamicPolicyDiscoveryPending(
                        static_during_discovery,
                        _anchor_binding(transition_anchor),
                    )
        if len(pairs) != 1:
            raise FreezerError("need exactly one monitor-connect/sleep dynamic pair")
        anchor, dynamic_leaf = pairs[0]
        policy = _dynamic_policy(anchor, dynamic_leaf)
    else:
        policy = frozen_dynamic_policy
        matching_anchors = [
            record
            for record in anchors
            if record["pid"] == policy["anchor_pid"]
            and record["start_ticks"] == policy["anchor_start_ticks"]
            and record["comm"] == policy["anchor_comm"] == "monitor-connect"
            and _sha(_canonical(record)) == policy["anchor_static_record_sha256"]
        ]
        if len(matching_anchors) != 1:
            raise FreezerError("dynamic anchor identity or exact static record drifted")
        anchor = matching_anchors[0]
        candidates = [
            {
                **record,
                "classification": "dynamic_monitor_connect_sleep_cwd_eacces_process",
            }
            for record in denied
            if record["pid"] != anchor["pid"]
        ]
        leaves = [
            record
            for record in candidates
            if _matches_dynamic_leaf(
                record,
                policy=policy,
                proc1_cgroup_sha256=proc1_cgroup_sha256,
                wrapper_start_ticks=wrapper_start_ticks,
            )
        ]
        if len(leaves) != 1:
            raise FreezerError("dynamic monitor-connect leaf count or binding differs")
        dynamic_leaf = leaves[0]

    dynamic_pids = {dynamic_leaf["pid"]}
    static_records = [record for record in denied if record["pid"] not in dynamic_pids]
    if any(record["start_ticks"] >= wrapper_start_ticks for record in static_records):
        raise FreezerError("a static cwd exception did not predate the causal wrapper")
    if not any(
        record["pid"] == policy["anchor_pid"]
        and record["start_ticks"] == policy["anchor_start_ticks"]
        and _sha(_canonical(record)) == policy["anchor_static_record_sha256"]
        for record in static_records
    ):
        raise FreezerError("dynamic anchor is not an exact static exception")
    if len(static_records) + 1 != len(denied):
        raise FreezerError("dynamic policy classified more than one process")
    static_records.sort(key=lambda record: (record["pid"], record["start_ticks"]))
    return static_records, [dynamic_leaf], policy


def _runtime_namespace(proc_root: Path) -> dict[str, Any]:
    lines = (proc_root / "self/mountinfo").read_bytes().splitlines(keepends=True)
    matches = [
        line for line in lines if len(line.split()) >= 5 and line.split()[4] == b"/proc"
    ]
    if len(matches) != 1:
        raise FreezerError("cannot identify exactly one /proc mount")
    metadata = os.stat(proc_root, follow_symlinks=False)
    buffer = ctypes.create_string_buffer(256)
    statfs = ctypes.CDLL(None, use_errno=True).statfs
    statfs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    statfs.restype = ctypes.c_int
    if statfs(os.fsencode(proc_root), ctypes.byref(buffer)) != 0:
        raise FreezerError("statfs(procfs) failed")
    super_magic = ctypes.c_long.from_buffer(buffer).value
    proc1_ppid, proc1_start, proc1_comm = _parse_stat(
        (proc_root / "1/stat").read_bytes()
    )
    proc1_cgroup_raw = (proc_root / "1/cgroup").read_bytes()
    self_raw = (proc_root / "self/stat").read_bytes()
    self_pid_raw = self_raw.split(b" ", 1)[0]
    if proc1_ppid != 0 or int(self_pid_raw) != os.getpid():
        raise FreezerError("proc1/proc-self consistency failed")
    return {
        "boot_id": (proc_root / "sys/kernel/random/boot_id").read_text().strip(),
        "mount_namespace_inode": os.stat(proc_root / "self/ns/mnt").st_ino,
        "pid_namespace_inode": os.stat(proc_root / "self/ns/pid").st_ino,
        "proc1_cgroup_sha256": _sha(proc1_cgroup_raw),
        "proc1_comm_sha256": proc1_comm,
        "proc1_start_ticks": proc1_start,
        "proc_mountinfo_sha256": _sha(matches[0]),
        "proc_root_device": metadata.st_dev,
        "proc_root_inode": metadata.st_ino,
        "proc_self_consistent": True,
        "proc_super_magic": super_magic,
    }


def _self_ancestor_record() -> dict[str, Any]:
    pid = os.getpid()
    _, start_ticks, comm_sha = _parse_stat(Path("/proc/self/stat").read_bytes())
    return {"comm_sha256": comm_sha, "pid": pid, "start_ticks": start_ticks}


def _detached_parent_records() -> list[dict[str, Any]]:
    """Bind only the fork-launching parent whose disappearance gives ppid=1.

    Pluto's SSH service is supervised by a persistent sshd/bash/s6 hierarchy.
    That hierarchy is not an interactive descriptor after setsid/fd sanitation,
    and V2 does not claim that the complete service ancestry has terminated.
    """

    return [_self_ancestor_record()]


def _decode_ancestors(payload: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise FreezerError("freezer ancestor payload is not JSON") from exc
    if (
        not isinstance(value, list)
        or len(value) != 1
        or payload.encode() != _canonical(value)
    ):
        raise FreezerError("freezer ancestor payload is not canonical")
    seen: set[int] = set()
    for record in value:
        if (
            not isinstance(record, dict)
            or set(record) != ANCESTOR_KEYS
            or not isinstance(record["pid"], int)
            or isinstance(record["pid"], bool)
            or record["pid"] <= 1
            or record["pid"] in seen
            or not isinstance(record["start_ticks"], int)
            or isinstance(record["start_ticks"], bool)
            or record["start_ticks"] <= 0
            or not isinstance(record["comm_sha256"], str)
            or len(record["comm_sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in record["comm_sha256"])
        ):
            raise FreezerError("freezer ancestor identity is invalid")
        seen.add(record["pid"])
    return value


def _assert_startup_ancestors_gone(
    records: list[dict[str, Any]], *, proc_root: Path = Path("/proc")
) -> None:
    if len(records) != 1:
        raise FreezerError("freezer needs exactly one detached launcher parent")
    for record in records:
        try:
            _, start_ticks, _ = _parse_stat(
                (proc_root / str(record["pid"]) / "stat").read_bytes()
            )
        except FileNotFoundError:
            continue
        # A process can change comm through exec/prctl without changing its
        # identity.  Treat matching PID+start_ticks as still live.
        if start_ticks == record["start_ticks"]:
            raise FreezerError("freezer detached launcher parent remains live")


def _sanitize_file_descriptors() -> list[str]:
    for entry in list(Path("/proc/self/fd").iterdir()):
        if entry.name.isdigit() and int(entry.name) > 2:
            try:
                os.close(int(entry.name))
            except OSError:
                pass
    devnull = os.open("/dev/null", os.O_RDWR)
    for descriptor in (0, 1, 2):
        os.dup2(devnull, descriptor, inheritable=True)
    if devnull > 2:
        os.close(devnull)
    targets = [os.readlink(f"/proc/self/fd/{item}") for item in (0, 1, 2)]
    if targets != ["/dev/null", "/dev/null", "/dev/null"]:
        raise FreezerError("freezer stdio is not /dev/null")
    return targets


def _assert_no_pts_fds() -> None:
    for entry in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        if target.startswith("/dev/pts"):
            raise FreezerError("freezer inherited a pts descriptor")


def _transport_identity() -> tuple[int, int, int, int]:
    raw = Path("/proc/self/stat").read_bytes()
    close = raw.rfind(b") ")
    fields = raw[close + 2 :].split() if close >= 2 else []
    if (
        len(fields) < 20
        or not fields[1].isdigit()
        or not fields[4].lstrip(b"-").isdigit()
        or not fields[19].isdigit()
    ):
        raise FreezerError("freezer transport stat is invalid")
    return os.getpid(), int(fields[1]), int(fields[19]), int(fields[4])


def _uptime_ticks(clock_ticks: int) -> int:
    raw = Path("/proc/uptime").read_text(encoding="ascii").split()[0]
    whole, dot, fraction = raw.partition(".")
    if not whole.isdigit() or (dot and not fraction.isdigit()):
        raise FreezerError("freezer uptime is invalid")
    numerator = int(whole) * (10 ** len(fraction)) + int(fraction or "0")
    return numerator * clock_ticks // (10 ** len(fraction))


def _expected_child_argv(
    *, source: Path, expectation: Path, output: Path, ancestors_json: str
) -> list[str]:
    return [
        EXPECTED_PYTHON_PATH,
        "-I",
        source.as_posix(),
        "--detached-child",
        "--launch-expectation",
        expectation.as_posix(),
        "--output",
        output.as_posix(),
        "--startup-ancestors-json",
        ancestors_json,
    ]


def _spawn_detached_child(*, expectation: Path, output: Path) -> None:
    source = Path(__file__).absolute()
    ancestors = _detached_parent_records()
    ancestors_json = _canonical(ancestors).decode("utf-8")
    child = os.fork()
    if child != 0:
        os._exit(0)
    os.chdir("/tmp")
    os.setsid()
    _sanitize_file_descriptors()
    _assert_no_pts_fds()
    argv = _expected_child_argv(
        source=source,
        expectation=expectation,
        output=output,
        ancestors_json=ancestors_json,
    )
    os.execve(EXPECTED_PYTHON_PATH, argv, EXEC_ENV)


def _verify_detached_child(
    *, expectation: Path, output: Path, ancestors_json: str
) -> dict[str, Any]:
    source = Path(__file__).absolute()
    ancestors = _decode_ancestors(ancestors_json)
    expected_argv = _expected_child_argv(
        source=source,
        expectation=expectation,
        output=output,
        ancestors_json=ancestors_json,
    )
    expected_cmdline = b"\0".join(item.encode() for item in expected_argv) + b"\0"
    if (
        dict(os.environ) != EXEC_ENV
        or Path("/proc/self/cmdline").read_bytes() != expected_cmdline
        or f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        != EXPECTED_PYTHON_VERSION
    ):
        raise FreezerError("freezer exact exec boundary differs")
    time.sleep(DETACHMENT_GRACE_SECONDS)
    _assert_startup_ancestors_gone(ancestors)
    pid, ppid, start_ticks, tty_nr = _transport_identity()
    clock_ticks = os.sysconf("SC_CLK_TCK")
    stdio_targets = [os.readlink(f"/proc/self/fd/{item}") for item in (0, 1, 2)]
    _assert_no_pts_fds()
    if (
        ppid != 1
        or os.getppid() != 1
        or os.getsid(0) != pid
        or os.getpgrp() != pid
        or tty_nr != 0
        or Path.cwd() != Path("/tmp")
        or stdio_targets != ["/dev/null", "/dev/null", "/dev/null"]
        or _uptime_ticks(clock_ticks) - start_ticks
        < DETACHMENT_GRACE_SECONDS * clock_ticks
    ):
        raise FreezerError("freezer detached transport proof did not close")
    return {
        "cwd": "/tmp",
        "exec_argv_sha256": _sha(_canonical(expected_argv)),
        "exec_env_sha256": _sha(_canonical(EXEC_ENV)),
        "no_pts_fds": True,
        "pid": pid,
        "ppid": ppid,
        "process_group_id": os.getpgrp(),
        "process_start_ticks": start_ticks,
        "python_path": EXPECTED_PYTHON_PATH,
        "python_version": EXPECTED_PYTHON_VERSION,
        "session_id": os.getsid(0),
        "startup_ancestors": ancestors,
        "startup_ancestors_sha256": _sha(_canonical(ancestors)),
        "stdio_targets_sha256": _sha(_canonical(stdio_targets)),
        "tty_nr": tty_nr,
    }


def _publish(path: Path, payload: bytes) -> None:
    if os.path.lexists(path):
        raise FileExistsError("refusing to overwrite procfs exception inventory")
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.tmp.")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def freeze(
    *,
    launch_expectation_path: Path,
    output: Path,
    transport_proof: dict[str, Any],
    proc_root: Path = Path("/proc"),
    source_path: Path | None = None,
    source_raw_at_entry: bytes | None = None,
    require_tmp_boundary: bool = True,
    now_fn: Any = _utc_now,
    boottime_ns_fn: Any = lambda: time.clock_gettime_ns(time.CLOCK_BOOTTIME),
    sleep_fn: Any = time.sleep,
    namespace_fn: Any = _runtime_namespace,
    scan_fn: Any = _scan,
    publish_fn: Any = _publish,
) -> None:
    source = Path(__file__).absolute() if source_path is None else source_path
    source_raw = (
        _read_stable(source) if source_raw_at_entry is None else source_raw_at_entry
    )
    if _read_stable(source) != source_raw:
        raise FreezerError("freezer source drifted after child entry")
    expectation_raw = _read_stable(launch_expectation_path)
    expectation = _strict_json(expectation_raw)
    if (
        expectation.get("protocol") != "cohort_causal_formal_launch_expectation_v1"
        or expectation.get("schema_version") != 1
        or expectation.get("attempt_id") != "attempt-002"
    ):
        raise FreezerError("launch expectation protocol differs")
    checkout = Path(expectation["checkout_root"])
    durable = Path(expectation["durable_attempt_root"])
    artifact = Path(expectation["artifact_root"])
    if output != durable / "control" / OUTPUT_FILENAME:
        raise FreezerError("freezer output path is not fixed")
    if require_tmp_boundary and (
        not source.as_posix().startswith("/tmp/") or Path.cwd() != Path("/tmp")
    ):
        raise FreezerError("freezer source and cwd must be under /tmp")
    targets = (checkout, durable, artifact)
    namespace_1 = namespace_fn(proc_root)
    discovery_static_digest: str | None = None
    discovery_anchor_binding: dict[str, Any] | None = None
    for discovery_attempt in range(DYNAMIC_POLICY_DISCOVERY_MAX_ATTEMPTS):
        try:
            records_1, dynamic_1, dynamic_policy = scan_fn(
                proc_root=proc_root,
                targets=targets,
                self_pid=os.getpid(),
                wrapper_start_ticks=expectation["wrapper_start_ticks"],
                proc1_cgroup_sha256=namespace_1["proc1_cgroup_sha256"],
                frozen_dynamic_policy=None,
            )
        except DynamicPolicyDiscoveryPending as exc:
            current_static_digest = _sha(_canonical(exc.static_records))
            if discovery_static_digest is None:
                discovery_static_digest = current_static_digest
            elif current_static_digest != discovery_static_digest:
                raise FreezerError(
                    "static exceptions drifted during dynamic policy discovery"
                ) from exc
            if discovery_anchor_binding is None:
                discovery_anchor_binding = exc.anchor_binding
            elif exc.anchor_binding != discovery_anchor_binding:
                raise FreezerError(
                    "exact anchor drifted during dynamic policy discovery"
                ) from exc
            if discovery_attempt + 1 >= DYNAMIC_POLICY_DISCOVERY_MAX_ATTEMPTS:
                raise FreezerError(
                    "dynamic policy discovery exhausted its bounded retry budget"
                ) from exc
            sleep_fn(DYNAMIC_POLICY_DISCOVERY_INTERVAL_SECONDS)
            continue
        break
    else:  # pragma: no cover - the bounded loop exits or raises above
        raise AssertionError("unreachable dynamic policy discovery state")
    if (
        discovery_static_digest is not None
        and _sha(_canonical(records_1)) != discovery_static_digest
    ):
        raise FreezerError("static exceptions drifted before registered snapshot one")
    if discovery_anchor_binding is not None and discovery_anchor_binding != {
        "pid": dynamic_policy["anchor_pid"],
        "start_ticks": dynamic_policy["anchor_start_ticks"],
        "static_record_sha256": dynamic_policy["anchor_static_record_sha256"],
    }:
        raise FreezerError("exact anchor drifted before registered snapshot one")
    captured_1 = now_fn()
    boottime_1 = boottime_ns_fn()
    sleep_fn(SNAPSHOT_INTERVAL_SECONDS)
    records_2, dynamic_2, observed_policy_2 = scan_fn(
        proc_root=proc_root,
        targets=targets,
        self_pid=os.getpid(),
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
        proc1_cgroup_sha256=namespace_1["proc1_cgroup_sha256"],
        frozen_dynamic_policy=dynamic_policy,
    )
    captured_2 = now_fn()
    boottime_2 = boottime_ns_fn()
    namespace_2 = namespace_fn(proc_root)
    if (
        _canonical(records_1) != _canonical(records_2)
        or observed_policy_2 != dynamic_policy
        or namespace_1 != namespace_2
    ):
        raise FreezerError("static procfs exceptions, policy, or namespace differ")
    if boottime_2 - boottime_1 < 1_000_000_000:
        raise FreezerError("procfs snapshots lack one second of boottime separation")
    wrapper_start = expectation["wrapper_start_ticks"]
    if any(record["start_ticks"] >= wrapper_start for record in records_1):
        raise FreezerError("a static cwd exception did not predate the causal wrapper")
    if (
        not isinstance(transport_proof, dict)
        or set(transport_proof) != TRANSPORT_PROOF_KEYS
        or not isinstance(transport_proof.get("process_start_ticks"), int)
        or isinstance(transport_proof.get("process_start_ticks"), bool)
        or transport_proof["process_start_ticks"] <= wrapper_start
    ):
        raise FreezerError("freezer detached proof does not postdate the wrapper")
    static_digest = _sha(_canonical(records_1))
    dynamic_policy_digest = _sha(_canonical(dynamic_policy))
    inventory_digest = _sha(
        _canonical({"dynamic_policy": dynamic_policy, "static_records": records_1})
    )
    dynamic_digest_1 = _sha(_canonical(dynamic_1))
    dynamic_digest_2 = _sha(_canonical(dynamic_2))
    inventory = {
        "dynamic_policy": dynamic_policy,
        "dynamic_policy_sha256": dynamic_policy_digest,
        "freezer": {
            "path": source.as_posix(),
            "sha256": _sha(source_raw),
            **transport_proof,
        },
        "frozen_at_utc": now_fn(),
        "inventory_sha256": inventory_digest,
        "launch_expectation": {
            "path": launch_expectation_path.as_posix(),
            "sha256": _sha(expectation_raw),
        },
        "outcome_blind": True,
        "protocol": PROTOCOL,
        "runtime_namespace": namespace_1,
        "schema_version": 2,
        "semantic_artifacts_opened": False,
        "static_records_sha256": static_digest,
        "snapshots": [
            {
                "captured_at_utc": captured_1,
                "captured_boottime_ns": boottime_1,
                "dynamic_observation_count": len(dynamic_1),
                "dynamic_observations": dynamic_1,
                "dynamic_observations_sha256": dynamic_digest_1,
                "sequence": 1,
                "static_record_count": len(records_1),
                "static_records": records_1,
                "static_records_sha256": static_digest,
            },
            {
                "captured_at_utc": captured_2,
                "captured_boottime_ns": boottime_2,
                "dynamic_observation_count": len(dynamic_2),
                "dynamic_observations": dynamic_2,
                "dynamic_observations_sha256": dynamic_digest_2,
                "sequence": 2,
                "static_record_count": len(records_2),
                "static_records": records_2,
                "static_records_sha256": static_digest,
            },
        ],
        "status": "frozen_blinded",
        "wrapper": {"pid": expectation["wrapper_pid"], "start_ticks": wrapper_start},
    }
    if (
        _read_stable(source) != source_raw
        or _read_stable(launch_expectation_path) != expectation_raw
    ):
        raise FreezerError(
            "freezer source or launch expectation drifted before publish"
        )
    publish_fn(output, _canonical(inventory))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--detached-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--startup-ancestors-json", help=argparse.SUPPRESS)
    args = parser.parse_args()
    expectation = args.launch_expectation.absolute()
    output = args.output.absolute()
    if not args.detached_child:
        if args.startup_ancestors_json is not None:
            raise SystemExit(2)
        source = Path(__file__).absolute()
        initial_argv = [
            EXPECTED_PYTHON_PATH,
            "-I",
            source.as_posix(),
            "--launch-expectation",
            expectation.as_posix(),
            "--output",
            output.as_posix(),
        ]
        if Path("/proc/self/cmdline").read_bytes() != (
            b"\0".join(item.encode() for item in initial_argv) + b"\0"
        ):
            raise SystemExit(2)
        _spawn_detached_child(expectation=expectation, output=output)
        raise AssertionError("detached freezer exec unexpectedly returned")
    if args.startup_ancestors_json is None:
        raise SystemExit(2)
    try:
        source = Path(__file__).absolute()
        # Freeze the exact transport source at detached-child entry, before
        # the detachment grace or procfs snapshots.  The same bytes are checked
        # again at freeze entry and immediately before publication.
        source_raw_at_entry = _read_stable(source)
        proof = _verify_detached_child(
            expectation=expectation,
            output=output,
            ancestors_json=args.startup_ancestors_json,
        )
        freeze(
            launch_expectation_path=expectation,
            output=output,
            transport_proof=proof,
            source_path=source,
            source_raw_at_entry=source_raw_at_entry,
        )
    except (FreezerError, FileExistsError, OSError):
        # Stdio is /dev/null; no identity, argv, cgroup, or efficacy bytes leak.
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
