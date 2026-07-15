#!/usr/bin/env python3
"""One-shot, outcome-blind detached transport for causal verifier V3.

V3 is a recovery overlay over immutable V2 evidence.  This launcher reads only
control artifacts, permanently consumes the single launch opportunity by
publishing a no-overwrite claim, proves the same detached process properties as
V2, publishes a fresh no-overwrite receipt, and same-PID ``execve`` replaces
itself with the exact plan-bound V3 attester.  It never parses efficacy.
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


PLAN_PROTOCOL = "cohort_causal_terminal_verifier_execution_plan_v3"
PLAN_SCHEMA_VERSION = 3
HANDOFF_PROTOCOL = "cohort_causal_terminal_verifier_v3_detached_handoff_v1"
CLAIM_PROTOCOL = "cohort_causal_terminal_verifier_v3_launch_claim_v1"
RECEIPT_PROTOCOL = "cohort_causal_terminal_verifier_v3_detached_receipt_v1"
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

DETACHED_LAUNCH_CONTRACT = {
    "attester_argv_source": "execution_plan.invocations.attester.argv",
    "attester_environment_exact_allowlist": True,
    "base_v2_detached_receipt_is_static_only": True,
    "claim_is_permanent_no_retry_boundary": True,
    "exact_launcher_cmdline_required": True,
    "launcher_cwd": "/tmp",
    "launcher_python_isolated": True,
    "minimum_detachment_grace_seconds": 30,
    "one_shot_launch_claim_required": True,
    "outcome_blind": True,
    "protocol": "cohort_causal_terminal_verifier_v3_detached_launch_contract_v1",
    "receipt_same_pid_exec": True,
    "require_detached_launcher_parent_gone": True,
    "require_no_controlling_tty": True,
    "require_no_pts_fds": True,
    "require_parent_pid_one": True,
    "require_stdio_devnull": True,
    "schema_version": 1,
    "semantic_artifacts_opened": False,
    "status": "registered_one_shot_recovery_transport",
    "transport_only_no_scientific_authority": True,
}

BINDING_KEYS = frozenset({"path", "sha256"})
BASE_V2_KEYS = frozenset(
    {"execution_plan", "detached_receipt", "procfs_exception_inventory"}
)
RECOVERY_CONTROL_KEYS = frozenset({"v2_failure_closure", "v3_completion_fence"})
DETACHED_TRANSPORT_KEYS = frozenset(
    {"handoff", "launch_claim_path", "launcher", "receipt_path"}
)
HANDOFF_KEYS = frozenset(
    {
        "attester_argv",
        "detached_launch_contract",
        "launch_claim_path",
        "launcher",
        "launcher_argv",
        "minimum_delay_seconds",
        "outcome_blind",
        "plan_path",
        "protocol",
        "receipt_path",
        "required_cwd",
        "required_parent_pid",
        "schema_version",
        "semantic_artifacts_opened",
        "status",
        "transport_only_no_scientific_authority",
    }
)
ANCESTOR_RECORD_KEYS = frozenset({"comm_sha256", "pid", "start_ticks"})
CLAIM_KEYS = frozenset(
    {
        "attester_exec_argv_sha256",
        "attester_exec_env_sha256",
        "claimant",
        "handoff",
        "launcher",
        "launcher_argv_sha256",
        "outcome_blind",
        "plan",
        "protocol",
        "receipt_path",
        "schema_version",
        "semantic_artifacts_opened",
        "status",
    }
)
RECEIPT_KEYS = frozenset(
    {
        "clock_ticks_per_second",
        "cwd",
        "detached_launch_contract",
        "exec_argv_sha256",
        "exec_env_sha256",
        "handoff",
        "launch_claim",
        "launcher",
        "minimum_delay_seconds",
        "no_pts_fds",
        "observed_age_ticks",
        "outcome_blind",
        "pid",
        "plan",
        "ppid",
        "process_group_id",
        "process_start_ticks",
        "protocol",
        "runtime_namespace",
        "schema_version",
        "semantic_artifacts_opened",
        "session_id",
        "startup_ancestors",
        "startup_ancestors_sha256",
        "status",
        "stdio_targets_sha256",
        "tty_nr",
    }
)


class DetachedLaunchV3Error(RuntimeError):
    """A fail-closed V3 transport error."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DetachedLaunchV3Error("value is not finite canonical JSON") from exc


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise DetachedLaunchV3Error("duplicate JSON key")
        result[key] = item
    return result


def _reject_constant(value: str) -> None:
    raise DetachedLaunchV3Error(f"non-finite JSON constant {value}")


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DetachedLaunchV3Error(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict) or payload != _canonical(value):
        raise DetachedLaunchV3Error(f"{label} is not a canonical JSON object")
    return value


def _normalized_absolute(value: Any, label: str) -> Path:
    if not isinstance(value, str):
        raise DetachedLaunchV3Error(f"{label} is not a path string")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise DetachedLaunchV3Error(f"{label} is not a normalized absolute path")
    return path


def _read_stable(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise DetachedLaunchV3Error("transport input is not a regular file")
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
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise DetachedLaunchV3Error("transport input changed while reading")
    return b"".join(chunks)


def _binding(value: Any, label: str) -> tuple[Path, str]:
    if not isinstance(value, dict) or set(value) != BINDING_KEYS:
        raise DetachedLaunchV3Error(f"{label} binding schema differs")
    path = _normalized_absolute(value["path"], f"{label}.path")
    digest = value["sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise DetachedLaunchV3Error(f"{label} digest is invalid")
    return path, digest


def _verify_binding(value: Any, label: str) -> tuple[Path, bytes]:
    path, digest = _binding(value, label)
    payload = _read_stable(path)
    if _sha(payload) != digest:
        raise DetachedLaunchV3Error(f"{label} bytes drifted")
    return path, payload


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
        raise DetachedLaunchV3Error("cannot parse proc stat identity")
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


def _self_record() -> dict[str, Any]:
    pid, _, start_ticks, _, comm_sha = _proc_identity()
    return {"comm_sha256": comm_sha, "pid": pid, "start_ticks": start_ticks}


def _assert_startup_parent_gone(
    record: dict[str, Any], *, proc_root: Path = Path("/proc")
) -> None:
    if not isinstance(record, dict) or set(record) != ANCESTOR_RECORD_KEYS:
        raise DetachedLaunchV3Error("startup parent record schema differs")
    try:
        _, start_ticks, _, _ = _parse_stat(
            (proc_root / str(record["pid"]) / "stat").read_bytes()
        )
    except FileNotFoundError:
        return
    if start_ticks == record["start_ticks"]:
        raise DetachedLaunchV3Error("detached launcher parent is still live")


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
        raise DetachedLaunchV3Error("stdio was not redirected to /dev/null")
    return targets


def _assert_no_pts_fds() -> None:
    for entry in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        if target.startswith("/dev/pts"):
            raise DetachedLaunchV3Error("a pts file descriptor remains inherited")


def _uptime_ticks(clock_ticks: int) -> int:
    raw = Path("/proc/uptime").read_text(encoding="ascii").split()[0]
    whole, dot, fraction = raw.partition(".")
    if not whole.isdigit() or (dot and not fraction.isdigit()):
        raise DetachedLaunchV3Error("cannot parse /proc/uptime")
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
        raise DetachedLaunchV3Error("cannot identify exactly one /proc mount")
    proc_metadata = os.stat("/proc", follow_symlinks=False)
    statfs_buffer = ctypes.create_string_buffer(256)
    statfs = ctypes.CDLL(None, use_errno=True).statfs
    statfs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    statfs.restype = ctypes.c_int
    if statfs(b"/proc", ctypes.byref(statfs_buffer)) != 0:
        raise DetachedLaunchV3Error("statfs(/proc) failed")
    proc_super_magic = ctypes.c_long.from_buffer(statfs_buffer).value
    proc1_ppid, proc1_start, _, proc1_comm = _parse_stat(
        Path("/proc/1/stat").read_bytes()
    )
    proc1_cgroup_raw = Path("/proc/1/cgroup").read_bytes()
    self_pid_raw = Path("/proc/self/stat").read_bytes().split(b" ", 1)[0]
    if (
        proc1_ppid != 0
        or not self_pid_raw.isdigit()
        or int(self_pid_raw) != os.getpid()
    ):
        raise DetachedLaunchV3Error("proc1/proc-self identity is inconsistent")
    return {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "mount_namespace_inode": os.stat("/proc/self/ns/mnt").st_ino,
        "pid_namespace_inode": os.stat("/proc/self/ns/pid").st_ino,
        "proc1_cgroup_sha256": _sha(proc1_cgroup_raw),
        "proc1_comm_sha256": proc1_comm,
        "proc1_start_ticks": proc1_start,
        "proc_mountinfo_sha256": _sha(matches[0]),
        "proc_root_device": proc_metadata.st_dev,
        "proc_root_inode": proc_metadata.st_ino,
        "proc_self_consistent": True,
        "proc_super_magic": proc_super_magic,
    }


def _publish_no_overwrite(path: Path, payload: bytes, label: str) -> None:
    if os.path.lexists(path):
        raise FileExistsError(f"{label} already exists; V3 launch is permanently spent")
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


def _assert_no_symlink_components(path: Path, *, root: Path, label: str) -> None:
    """Require a real fixed root and every descendant component to be non-link."""

    normalized_path = _normalized_absolute(path.as_posix(), label)
    normalized_root = _normalized_absolute(root.as_posix(), f"{label} root")
    try:
        relative = normalized_path.relative_to(normalized_root)
    except ValueError as exc:
        raise DetachedLaunchV3Error(f"{label} escapes its fixed root") from exc
    candidates = [normalized_root]
    current = normalized_root
    for component in relative.parts:
        current /= component
        candidates.append(current)
    for candidate in candidates:
        try:
            metadata = os.lstat(candidate)
        except FileNotFoundError:
            if candidate == normalized_path:
                continue
            raise DetachedLaunchV3Error(f"{label} ancestor is absent") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise DetachedLaunchV3Error(f"{label} has a symlink component")


def _plan_control_payloads(
    plan: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    base = plan.get("base_v2")
    controls = plan.get("recovery_controls")
    if not isinstance(base, dict) or set(base) != BASE_V2_KEYS:
        raise DetachedLaunchV3Error("V3 base-V2 binding schema differs")
    if not isinstance(controls, dict) or set(controls) != RECOVERY_CONTROL_KEYS:
        raise DetachedLaunchV3Error("V3 recovery-control binding schema differs")
    payloads: dict[str, bytes] = {}
    for prefix, values in (("base_v2", base), ("recovery_controls", controls)):
        for name, binding in values.items():
            _, payloads[f"{prefix}.{name}"] = _verify_binding(
                binding, f"{prefix}.{name}"
            )
    inventory = _strict_json(
        payloads["base_v2.procfs_exception_inventory"],
        "base V2 procfs exception inventory",
    )
    namespace = inventory.get("runtime_namespace")
    if not isinstance(namespace, dict) or not namespace:
        raise DetachedLaunchV3Error("base V2 inventory has no runtime namespace")
    return namespace, payloads


def _build_claim(
    *,
    attester_argv: list[str],
    claimant: dict[str, Any],
    handoff_binding: dict[str, str],
    launcher_binding: dict[str, str],
    launcher_argv: list[str],
    plan_binding: dict[str, str],
    receipt_path: Path,
) -> dict[str, Any]:
    claim = {
        "attester_exec_argv_sha256": _sha(_canonical(attester_argv)),
        "attester_exec_env_sha256": _sha(_canonical(EXEC_ENV)),
        "claimant": claimant,
        "handoff": handoff_binding,
        "launcher": launcher_binding,
        "launcher_argv_sha256": _sha(_canonical(launcher_argv)),
        "outcome_blind": True,
        "plan": plan_binding,
        "protocol": CLAIM_PROTOCOL,
        "receipt_path": receipt_path.as_posix(),
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "status": "claimed_once_permanent_no_retry",
    }
    if set(claim) != CLAIM_KEYS:
        raise AssertionError("V3 launch claim schema drift")
    return claim


def launch(*, handoff_path: Path, delay_seconds: int) -> None:
    if delay_seconds != MINIMUM_DELAY_SECONDS:
        raise DetachedLaunchV3Error("detached delay must equal the registered minimum")
    if (
        not handoff_path.is_absolute()
        or os.path.normpath(handoff_path.as_posix()) != handoff_path.as_posix()
        or not handoff_path.as_posix().startswith("/tmp/")
    ):
        raise DetachedLaunchV3Error("handoff must use a normalized /tmp path")

    handoff_raw = _read_stable(handoff_path)
    handoff = _strict_json(handoff_raw, "V3 detached handoff")
    if set(handoff) != HANDOFF_KEYS or (
        handoff["protocol"] != HANDOFF_PROTOCOL
        or handoff["schema_version"] != 1
        or handoff["status"] != "registered_one_shot"
        or handoff["outcome_blind"] is not True
        or handoff["semantic_artifacts_opened"] is not False
        or handoff["transport_only_no_scientific_authority"] is not True
        or handoff["minimum_delay_seconds"] != MINIMUM_DELAY_SECONDS
        or handoff["required_parent_pid"] != 1
        or handoff["required_cwd"] != "/tmp"
        or handoff["detached_launch_contract"] != DETACHED_LAUNCH_CONTRACT
    ):
        raise DetachedLaunchV3Error("V3 detached handoff contract differs")

    launcher_path, launcher_sha = _binding(handoff["launcher"], "launcher")
    self_path = Path(__file__).absolute()
    if self_path != launcher_path or _sha(_read_stable(self_path)) != launcher_sha:
        raise DetachedLaunchV3Error("runtime launcher differs from frozen binding")

    plan_path = _normalized_absolute(handoff["plan_path"], "V3 plan path")
    plan_raw = _read_stable(plan_path)
    plan = _strict_json(plan_raw, "V3 execution plan")
    if (
        plan.get("protocol") != PLAN_PROTOCOL
        or plan.get("schema_version") != PLAN_SCHEMA_VERSION
        or plan.get("status") != "registered_one_shot_recovery"
        or plan.get("outcome_blind") is not True
        or plan.get("semantic_artifacts_opened") is not False
        or plan.get("detached_launch_contract") != DETACHED_LAUNCH_CONTRACT
    ):
        raise DetachedLaunchV3Error("V3 execution plan contract differs")
    durable_root = _normalized_absolute(
        plan.get("durable_attempt_root"), "V3 durable root"
    )
    control_root = durable_root / "control"
    _assert_no_symlink_components(
        durable_root, root=durable_root, label="V3 durable root"
    )
    transport = plan.get("detached_transport")
    if not isinstance(transport, dict) or set(transport) != DETACHED_TRANSPORT_KEYS:
        raise DetachedLaunchV3Error("V3 plan detached transport differs")
    bound_handoff, bound_handoff_raw = _verify_binding(
        transport["handoff"], "plan detached handoff"
    )
    bound_launcher, bound_launcher_raw = _verify_binding(
        transport["launcher"], "plan detached launcher"
    )
    if (
        bound_handoff != handoff_path
        or bound_handoff_raw != handoff_raw
        or bound_launcher != self_path
        or _sha(bound_launcher_raw) != launcher_sha
    ):
        raise DetachedLaunchV3Error("V3 plan transport bindings differ")
    transport_root = handoff_path.parent
    for path, label in (
        (handoff_path, "V3 handoff"),
        (self_path, "V3 transport launcher"),
    ):
        _assert_no_symlink_components(path, root=transport_root, label=label)
    for group_name in (
        "base_v2",
        "recovery_controls",
        "tools",
        "implementation_dependencies",
    ):
        group = plan.get(group_name)
        if not isinstance(group, dict) or not group:
            raise DetachedLaunchV3Error(f"V3 plan {group_name} bindings differ")
        for name, binding in group.items():
            bound_path, _ = _binding(binding, f"{group_name}.{name}")
            _assert_no_symlink_components(
                bound_path,
                root=durable_root,
                label=f"{group_name}.{name}",
            )

    baseline_namespace, _ = _plan_control_payloads(plan)
    if _runtime_namespace_identity() != baseline_namespace:
        raise DetachedLaunchV3Error("runtime namespace differs from base V2 inventory")
    for group_name in ("tools", "implementation_dependencies"):
        group = plan.get(group_name)
        if not isinstance(group, dict) or not group:
            raise DetachedLaunchV3Error(f"V3 plan {group_name} bindings differ")
        for name, binding in group.items():
            _verify_binding(binding, f"{group_name}.{name}")

    attester_argv = handoff["attester_argv"]
    launcher_argv = handoff["launcher_argv"]
    expected_launcher_argv = [
        EXPECTED_PYTHON_PATH,
        "-I",
        self_path.as_posix(),
        "--handoff",
        handoff_path.as_posix(),
        "--delay-seconds",
        str(MINIMUM_DELAY_SECONDS),
    ]
    if (
        attester_argv != plan.get("invocations", {}).get("attester", {}).get("argv")
        or not isinstance(attester_argv, list)
        or not attester_argv
        or any(not isinstance(item, str) or not item for item in attester_argv)
        or launcher_argv != expected_launcher_argv
        or Path("/proc/self/cmdline").read_bytes()
        != b"\0".join(item.encode("utf-8") for item in launcher_argv) + b"\0"
    ):
        raise DetachedLaunchV3Error("detached launcher or V3 attester argv differs")
    for target in (plan.get("causal_checkout_root"), plan.get("durable_attempt_root")):
        if isinstance(target, str) and any(target in item for item in launcher_argv):
            raise DetachedLaunchV3Error(
                "waiting launcher argv contains an attempt path"
            )

    claim_path = _normalized_absolute(handoff["launch_claim_path"], "launch claim")
    receipt_path = _normalized_absolute(handoff["receipt_path"], "detached receipt")
    if (
        claim_path.as_posix() != transport["launch_claim_path"]
        or receipt_path.as_posix() != transport["receipt_path"]
        or claim_path.parent != control_root
        or receipt_path.parent != control_root
        or os.path.lexists(claim_path)
        or os.path.lexists(receipt_path)
    ):
        raise FileExistsError("V3 launch claim or receipt exists; retry is forbidden")
    _assert_no_symlink_components(
        claim_path, root=durable_root, label="V3 launch claim"
    )
    _assert_no_symlink_components(
        receipt_path, root=durable_root, label="V3 detached receipt"
    )

    startup_parent = _self_record()
    handoff_binding = {"path": handoff_path.as_posix(), "sha256": _sha(handoff_raw)}
    launcher_binding = {"path": self_path.as_posix(), "sha256": launcher_sha}
    plan_binding = {"path": plan_path.as_posix(), "sha256": _sha(plan_raw)}
    claim = _build_claim(
        attester_argv=attester_argv,
        claimant=startup_parent,
        handoff_binding=handoff_binding,
        launcher_binding=launcher_binding,
        launcher_argv=launcher_argv,
        plan_binding=plan_binding,
        receipt_path=receipt_path,
    )
    claim_raw = _canonical(claim)
    _assert_no_symlink_components(
        claim_path, root=durable_root, label="V3 launch claim"
    )
    _publish_no_overwrite(claim_path, claim_raw, "V3 launch claim")

    child_pid = os.fork()
    if child_pid != 0:
        os._exit(0)
    os.chdir("/tmp")
    try:
        os.setsid()
    except OSError as exc:
        raise DetachedLaunchV3Error(
            "launcher could not create a detached session"
        ) from exc
    stdio_targets = _sanitize_file_descriptors()
    _assert_no_pts_fds()

    time.sleep(delay_seconds)
    _assert_startup_parent_gone(startup_parent)
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
        raise DetachedLaunchV3Error("detachment/cwd/age proof did not close")
    if (
        Path("/proc/self/cmdline").read_bytes()
        != b"\0".join(item.encode("utf-8") for item in launcher_argv) + b"\0"
        or _read_stable(handoff_path) != handoff_raw
        or _read_stable(plan_path) != plan_raw
        or _read_stable(self_path) != bound_launcher_raw
        or _read_stable(claim_path) != claim_raw
    ):
        raise DetachedLaunchV3Error("transport binding drifted during grace period")
    current_namespace, _ = _plan_control_payloads(plan)
    if (
        current_namespace != baseline_namespace
        or _runtime_namespace_identity() != baseline_namespace
    ):
        raise DetachedLaunchV3Error("control bytes or runtime namespace drifted")

    receipt = {
        "clock_ticks_per_second": clock_ticks,
        "cwd": "/tmp",
        "detached_launch_contract": DETACHED_LAUNCH_CONTRACT,
        "exec_argv_sha256": _sha(_canonical(attester_argv)),
        "exec_env_sha256": _sha(_canonical(EXEC_ENV)),
        "handoff": handoff_binding,
        "launch_claim": {"path": claim_path.as_posix(), "sha256": _sha(claim_raw)},
        "launcher": launcher_binding,
        "minimum_delay_seconds": delay_seconds,
        "no_pts_fds": True,
        "observed_age_ticks": observed_age_ticks,
        "outcome_blind": True,
        "pid": pid,
        "plan": plan_binding,
        "ppid": ppid,
        "process_group_id": os.getpgrp(),
        "process_start_ticks": start_ticks,
        "protocol": RECEIPT_PROTOCOL,
        "runtime_namespace": baseline_namespace,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "session_id": os.getsid(0),
        "startup_ancestors": [startup_parent],
        "startup_ancestors_sha256": _sha(_canonical([startup_parent])),
        "status": "ready_to_same_pid_exec_exact_v3_attester",
        "stdio_targets_sha256": _sha(_canonical(stdio_targets)),
        "tty_nr": tty_nr,
    }
    if set(receipt) != RECEIPT_KEYS:
        raise AssertionError("V3 detached receipt schema drift")
    _assert_no_symlink_components(
        receipt_path, root=durable_root, label="V3 detached receipt"
    )
    _publish_no_overwrite(receipt_path, _canonical(receipt), "V3 detached receipt")
    os.execve(attester_argv[0], attester_argv, EXEC_ENV)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--delay-seconds", type=int, required=True)
    args = parser.parse_args()
    try:
        launch(handoff_path=args.handoff, delay_seconds=args.delay_seconds)
    except (DetachedLaunchV3Error, FileExistsError, OSError) as exc:
        raise SystemExit(f"detached V3 verifier transport failed: {exc}") from exc


if __name__ == "__main__":
    main()
