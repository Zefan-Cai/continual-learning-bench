#!/usr/bin/env python3
"""Versioned, outcome-blind terminal-verifier V2 plan and execution seal.

V2 changes only the Linux procfs completion proof.  The causal reconstruction
and structured-state branch implementation are delegated to the exact V1
functions after strict V2 control validation.  All V2 paths are distinct and
all publishers retain V1's no-overwrite behaviour.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import build_cohort_structured_state_execution_seal as v1


PLAN_PROTOCOL = "cohort_causal_terminal_verifier_execution_plan_v2"
PLAN_SCHEMA_VERSION = 2
PLAN_FILENAME = "CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V2.json"
V1_PLAN_FILENAME = v1.PLAN_FILENAME
AMENDMENT_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V2_AMENDMENT.md"
DETACHED_LAUNCH_CONTRACT_FILENAME = (
    "CAUSAL_TERMINAL_VERIFIER_V2_DETACHED_LAUNCH_CONTRACT.json"
)
EXCEPTION_INVENTORY_FILENAME = (
    "CAUSAL_TERMINAL_VERIFIER_PROCFS_EXCEPTION_INVENTORY_V1.json"
)
DETACHED_HANDOFF_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V2_DETACHED_HANDOFF.json"
DETACHED_RECEIPT_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V2_DETACHED_RECEIPT.json"
TRANSPORT_LAUNCHER_FILENAME = "launch_cohort_causal_terminal_verifier_v2_detached.py"
EXCEPTION_FREEZER_FILENAME = "freeze_cohort_causal_procfs_exception_inventory_v2.py"
ATTESTATION_PROTOCOL = "cohort_causal_terminal_completion_attestation_v2"
ATTESTATION_FILENAME = "causal_trigger_completion_attestation.v2.json"
REVALIDATED_FILENAME = "causal_formal.revalidated.v2.json"
REVALIDATION_RECEIPT_FILENAME = "causal_formal.revalidation_receipt.v2.json"
SEAL_FILENAME = "cohort_closed_loop_structured_state.execution_seal.v2.json"
SEAL_PROTOCOL = "cohort_closed_loop_structured_state_trigger_execution_seal_v2"
SEAL_SCHEMA_VERSION = 2
PLAN_STATUS = "registered"
EXPECTED_PYTHON_PATH = v1.EXPECTED_PYTHON_PATH
EXPECTED_PYTHON_VERSION = v1.EXPECTED_PYTHON_VERSION
LAUNCH_EXPECTATION_FILENAME = v1.LAUNCH_EXPECTATION_FILENAME
STRUCTURED_PREREGISTRATION_FILENAME = v1.STRUCTURED_PREREGISTRATION_FILENAME
CAUSAL_PROTOCOL_SEAL_STATUS = v1.CAUSAL_PROTOCOL_SEAL_STATUS
PLAN_TOOL_NAMES = frozenset({"attester", "revalidator", "execution_seal_builder"})
PLAN_INVOCATION_NAMES = PLAN_TOOL_NAMES

EXCEPTION_INVENTORY_PROTOCOL = "cohort_causal_procfs_cwd_exception_inventory_v1"
EXCEPTION_INVENTORY_SCHEMA_VERSION = 1
PROCESS_AUDIT_METHOD = (
    "linux_procfs_cmdline_cwd_point_in_time_with_frozen_permission_exceptions_v2"
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_COMM_RE = re.compile(r"[ -~]{1,15}\Z")
_BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)

PLAN_BINDING_KEYS = frozenset({"path", "sha256"})
PLAN_RUNTIME_KEYS = frozenset({"python_path", "python_version"})
PLAN_INVOCATION_KEYS = frozenset({"argv", "inputs", "outputs", "parameters"})
PLAN_KEYS = frozenset(
    {
        "amendment",
        "attempt_id",
        "causal_checkout_root",
        "causal_protocol_seal_sha256",
        "causal_protocol_seal_status",
        "created_at_utc",
        "detached_launch_contract",
        "detached_transport",
        "durable_attempt_root",
        "implementation_dependencies",
        "invocations",
        "launch_expectation",
        "online_icl",
        "procfs_exception_inventory",
        "protocol",
        "runtime",
        "schema_version",
        "status",
        "structured_preregistration",
        "tooling_root",
        "tooling_source_commit",
        "tools",
        "v1_execution_plan",
    }
)

_INVOCATION_SCHEMAS = {
    "attester": (
        frozenset(
            {
                "execution_plan",
                "detached_launch_receipt",
                "launch_expectation",
                "procfs_exception_inventory",
                "provenance",
                "provenance_details",
                "root",
            }
        ),
        frozenset({"attestation"}),
        frozenset({"stability_seconds"}),
    ),
    "revalidator": v1._INVOCATION_SCHEMAS["revalidator"],
    "execution_seal_builder": v1._INVOCATION_SCHEMAS["execution_seal_builder"],
}

EXCEPTION_INVENTORY_KEYS = frozenset(
    {
        "frozen_at_utc",
        "freezer",
        "inventory_sha256",
        "launch_expectation",
        "outcome_blind",
        "protocol",
        "runtime_namespace",
        "schema_version",
        "semantic_artifacts_opened",
        "snapshots",
        "status",
        "wrapper",
    }
)
EXCEPTION_SNAPSHOT_KEYS = frozenset(
    {
        "captured_at_utc",
        "captured_boottime_ns",
        "record_count",
        "records",
        "records_sha256",
        "sequence",
    }
)
EXCEPTION_RECORD_KEYS = frozenset(
    {
        "cgroup_sha256",
        "classification",
        "cmdline_sha256",
        "cmdline_size_bytes",
        "comm",
        "gid",
        "pid",
        "ppid",
        "start_ticks",
        "uid",
    }
)
EXCEPTION_WRAPPER_KEYS = frozenset({"pid", "start_ticks"})
EXCEPTION_FREEZER_KEYS = frozenset(
    {
        "cwd",
        "exec_argv_sha256",
        "exec_env_sha256",
        "no_pts_fds",
        "path",
        "pid",
        "ppid",
        "process_group_id",
        "process_start_ticks",
        "python_path",
        "python_version",
        "session_id",
        "sha256",
        "startup_ancestors",
        "startup_ancestors_sha256",
        "stdio_targets_sha256",
        "tty_nr",
    }
)
ANCESTOR_RECORD_KEYS = frozenset({"comm_sha256", "pid", "start_ticks"})
RUNTIME_NAMESPACE_KEYS = frozenset(
    {
        "mount_namespace_inode",
        "boot_id",
        "pid_namespace_inode",
        "proc1_comm_sha256",
        "proc1_start_ticks",
        "proc_mountinfo_sha256",
        "proc_root_device",
        "proc_root_inode",
        "proc_self_consistent",
        "proc_super_magic",
    }
)
DETACHED_TRANSPORT_KEYS = frozenset({"handoff", "launcher", "receipt_path"})

DETACHED_EXEC_ENV = {
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONHASHSEED": "0",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
}
DETACHED_RECEIPT_KEYS = frozenset(
    {
        "clock_ticks_per_second",
        "cwd",
        "detached_launch_contract",
        "exec_argv_sha256",
        "exec_env_sha256",
        "handoff",
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
        "session_id",
        "startup_ancestors",
        "startup_ancestors_sha256",
        "status",
        "stdio_targets_sha256",
        "tty_nr",
    }
)

ATTESTATION_KEYS = frozenset(
    set(v1.ATTESTATION_KEYS) | {"detached_launch_receipt", "procfs_exception_inventory"}
)
ATTESTATION_EXCEPTION_BINDING_KEYS = frozenset({"inventory_sha256", "path", "sha256"})
ATTESTATION_RECEIPT_BINDING_KEYS = frozenset(
    {"path", "pid", "process_start_ticks", "sha256"}
)
PROCESS_AUDIT_KEYS = frozenset(
    set(v1.PROCESS_ABSENCE_KEYS)
    | {
        "exception_inventory_sha256",
        "durable_attempt_root_path",
        "observed_exception_count",
        "observed_exceptions_sha256",
    }
)

DETACHED_LAUNCH_CONTRACT = {
    "attester_environment_exact_allowlist": True,
    "attester_argv_source": "execution_plan.invocations.attester.argv",
    "detached_parent_pid": 1,
    "exception_platform_origin_mechanically_proven": False,
    "exception_scope": "stable_pre_wrapper_cwd_eacces_or_eperm_only",
    "forbid_runtime_namespace_drift_before_attestation_completion": True,
    "launcher_python_isolated": True,
    "launcher_cwd": "/tmp",
    "launcher_wait_cmdline_contains_attempt_path": False,
    "minimum_disconnect_grace_seconds": 30,
    "namespace_continuity_from_inventory_through_attestation_required": True,
    "namespace_origin_trust_assumption": "freezer_launched_by_operator_in_original_pluto_default_container_namespace",
    "outcome_blind": True,
    "protocol": "cohort_causal_terminal_verifier_v2_detached_launch_contract_v2",
    "require_interactive_ssh_disconnected": True,
    "require_no_controlling_tty": True,
    "require_no_pts_fds": True,
    "require_startup_ancestors_gone": True,
    "require_stdio_devnull": True,
    "receipt_same_pid_exec": True,
    "schema_version": 2,
    "status": "registered",
    "transport_only_no_scientific_authority": True,
    "wrapper_namespace_origin_mechanically_proven": False,
}


class ExecutionSealV2Error(v1.ExecutionSealError):
    """A fail-closed V2 control, inventory, or seal error."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExecutionSealV2Error("value is not canonical finite JSON") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_exact(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ExecutionSealV2Error(f"{label} exact-key schema differs")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ExecutionSealV2Error(f"{label} is not a lowercase SHA-256")
    return value


def _require_commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise ExecutionSealV2Error(f"{label} is not a lowercase 40-hex commit")
    return value


def _normalized_absolute(value: str | Path, label: str) -> Path:
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise ExecutionSealV2Error(f"{label} is not a path") from exc
    path = Path(text)
    if not path.is_absolute() or os.path.normpath(text) != text:
        raise ExecutionSealV2Error(f"{label} is not a normalized absolute path")
    return path


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ExecutionSealV2Error(f"{label} is not UTC Z text")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ExecutionSealV2Error(f"{label} is not an ISO timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise ExecutionSealV2Error(f"{label} is not UTC")
    return parsed


def _strict_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ExecutionSealV2Error(f"{label} has a duplicate key")
            result[key] = item
        return result

    def reject_constant(item: str) -> None:
        raise ExecutionSealV2Error(f"{label} has non-finite constant {item}")

    try:
        value = json.loads(
            payload,
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutionSealV2Error(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ExecutionSealV2Error(f"{label} must be a JSON object")
    if payload != canonical_bytes(value):
        raise ExecutionSealV2Error(f"{label} is not canonical JSON bytes")
    return value


def _stable_binding(path: Path, label: str) -> dict[str, str]:
    record = v1._binding_record(path, label=label)
    return {"path": record["path"], "sha256": record["sha256"]}


def _validate_binding(value: Any, label: str) -> dict[str, str]:
    binding = _require_exact(value, PLAN_BINDING_KEYS, label)
    path = _normalized_absolute(binding["path"], f"{label}.path")
    digest = _require_sha256(binding["sha256"], f"{label}.sha256")
    current = _stable_binding(path, label)
    if current != {"path": path.as_posix(), "sha256": digest}:
        raise ExecutionSealV2Error(f"{label} current bytes differ")
    return current


def _validate_detached_launch_contract(path: Path) -> dict[str, str]:
    raw, _ = v1._read_stable_file(path, label="V2 detached launch contract")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutionSealV2Error("detached launch contract is not JSON") from exc
    if value != DETACHED_LAUNCH_CONTRACT:
        raise ExecutionSealV2Error("detached launch contract semantics differ")
    if raw not in {
        canonical_bytes(DETACHED_LAUNCH_CONTRACT),
        canonical_bytes(DETACHED_LAUNCH_CONTRACT) + b"\n",
    }:
        raise ExecutionSealV2Error("detached launch contract bytes are not canonical")
    return {"path": path.as_posix(), "sha256": _sha256(raw)}


def _transport_paths(
    *, tooling_source_commit: str, durable_root: Path
) -> tuple[Path, Path, Path]:
    transport_root = (
        Path("/tmp") / "cohort-causal-terminal-verifier-v2" / tooling_source_commit
    )
    return (
        transport_root / TRANSPORT_LAUNCHER_FILENAME,
        transport_root / DETACHED_HANDOFF_FILENAME,
        durable_root / "control" / DETACHED_RECEIPT_FILENAME,
    )


def _freezer_transport_path(*, tooling_source_commit: str) -> Path:
    return (
        Path("/tmp")
        / "cohort-causal-terminal-verifier-v2"
        / tooling_source_commit
        / EXCEPTION_FREEZER_FILENAME
    )


def _parse_proc_stat_for_ancestor(payload: bytes) -> tuple[int, str]:
    close = payload.rfind(b") ")
    opener = payload.find(b"(")
    fields = payload[close + 2 :].split() if close >= 2 else []
    if opener < 1 or len(fields) < 20 or not fields[19].isdigit():
        raise ExecutionSealV2Error("startup ancestor proc stat is invalid")
    return int(fields[19], 10), _sha256(payload[opener + 1 : close])


def _validate_ancestor_records(value: Any, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ExecutionSealV2Error(f"{label} must be a non-empty list")
    seen: set[int] = set()
    records: list[dict[str, Any]] = []
    for index, raw_record in enumerate(value):
        record = _require_exact(
            raw_record, ANCESTOR_RECORD_KEYS, f"{label} record {index}"
        )
        if (
            not _is_int(record["pid"])
            or record["pid"] <= 1
            or record["pid"] in seen
            or not _is_int(record["start_ticks"])
            or record["start_ticks"] <= 0
        ):
            raise ExecutionSealV2Error(f"{label} identity is invalid")
        _require_sha256(record["comm_sha256"], f"{label} comm")
        seen.add(record["pid"])
        records.append(record)
    return records


def _assert_ancestor_records_gone(
    records: Sequence[dict[str, Any]], *, proc_root: Path = Path("/proc")
) -> None:
    for record in records:
        try:
            current_start, _ = _parse_proc_stat_for_ancestor(
                (proc_root / str(record["pid"]) / "stat").read_bytes()
            )
        except FileNotFoundError:
            continue
        # PID plus kernel start time is the process identity.  ``comm`` is
        # retained in the frozen record for auditability, but a live ancestor
        # may change it via exec/prctl and must not thereby count as gone.
        if current_start == record["start_ticks"]:
            raise ExecutionSealV2Error("startup transport ancestor remains live")


def _assert_process_start_gone(
    *,
    pid: int,
    start_ticks: int,
    label: str,
    proc_root: Path = Path("/proc"),
) -> None:
    try:
        current_start, _ = _parse_proc_stat_for_ancestor(
            (proc_root / str(pid) / "stat").read_bytes()
        )
    except FileNotFoundError:
        return
    if current_start == start_ticks:
        raise ExecutionSealV2Error(f"{label} process remains live")


def _validate_runtime_namespace(value: Any, *, label: str) -> dict[str, Any]:
    namespace = _require_exact(value, RUNTIME_NAMESPACE_KEYS, label)
    for key in (
        "mount_namespace_inode",
        "pid_namespace_inode",
        "proc1_start_ticks",
        "proc_root_device",
        "proc_root_inode",
        "proc_super_magic",
    ):
        if not _is_int(namespace[key]) or namespace[key] <= 0:
            raise ExecutionSealV2Error(f"{label} {key} is invalid")
    _require_sha256(namespace["proc_mountinfo_sha256"], f"{label} mountinfo")
    _require_sha256(namespace["proc1_comm_sha256"], f"{label} proc1 comm")
    if (
        not isinstance(namespace["boot_id"], str)
        or _BOOT_ID_RE.fullmatch(namespace["boot_id"]) is None
        or namespace["proc_self_consistent"] is not True
        or namespace["proc_super_magic"] != 0x9FA0
    ):
        raise ExecutionSealV2Error(f"{label} boot/proc identity differs")
    return namespace


def _expected_handoff(
    *,
    plan: dict[str, Any],
    launcher_binding: dict[str, str],
    handoff_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    return {
        "attester_argv": plan["invocations"]["attester"]["argv"],
        "detached_launch_contract": plan["detached_launch_contract"],
        "launcher": launcher_binding,
        "launcher_argv": [
            EXPECTED_PYTHON_PATH,
            "-I",
            launcher_binding["path"],
            "--handoff",
            handoff_path.as_posix(),
            "--delay-seconds",
            "30",
        ],
        "minimum_delay_seconds": 30,
        "plan_path": (
            Path(plan["durable_attempt_root"]) / "control" / PLAN_FILENAME
        ).as_posix(),
        "protocol": "cohort_causal_terminal_verifier_v2_detached_handoff_v1",
        "receipt_path": receipt_path.as_posix(),
        "required_cwd": "/tmp",
        "required_parent_pid": 1,
        "schema_version": 1,
        "status": "registered",
        "transport_only_no_scientific_authority": True,
    }


def _validate_handoff_bytes(*, payload: bytes, expected: dict[str, Any]) -> None:
    observed = _strict_json_bytes(payload, "detached transport handoff")
    if observed != expected:
        raise ExecutionSealV2Error("detached transport handoff semantics differ")


def validate_exception_inventory(
    value: Any,
    *,
    launch_expectation_path: Path,
    launch_expectation_sha256: str,
    wrapper_pid: int,
    wrapper_start_ticks: int,
    latest_allowed_time: datetime | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate the canonical, two-snapshot, exact procfs exception set."""

    inventory = _require_exact(
        copy.deepcopy(value), EXCEPTION_INVENTORY_KEYS, "procfs exception inventory"
    )
    if (
        inventory["protocol"] != EXCEPTION_INVENTORY_PROTOCOL
        or inventory["schema_version"] != EXCEPTION_INVENTORY_SCHEMA_VERSION
        or inventory["status"] != "frozen_blinded"
        or inventory["outcome_blind"] is not True
        or inventory["semantic_artifacts_opened"] is not False
    ):
        raise ExecutionSealV2Error("procfs exception inventory is not frozen blind V1")
    freezer = _require_exact(
        inventory["freezer"], EXCEPTION_FREEZER_KEYS, "exception inventory freezer"
    )
    freezer_path = _normalized_absolute(freezer["path"], "exception freezer path")
    freezer_sha = _require_sha256(freezer["sha256"], "exception freezer sha256")
    if (
        freezer_path.name != EXCEPTION_FREEZER_FILENAME
        or freezer_path.parent.parent
        != Path("/tmp") / "cohort-causal-terminal-verifier-v2"
        or _COMMIT_RE.fullmatch(freezer_path.parent.name) is None
    ):
        raise ExecutionSealV2Error("exception inventory freezer path is not fixed")
    current_freezer = _stable_binding(freezer_path, "exception inventory freezer")
    if current_freezer != {
        "path": freezer_path.as_posix(),
        "sha256": freezer_sha,
    }:
        raise ExecutionSealV2Error("exception inventory freezer bytes differ")
    launch = _require_exact(
        inventory["launch_expectation"], PLAN_BINDING_KEYS, "inventory launch binding"
    )
    if launch != {
        "path": launch_expectation_path.as_posix(),
        "sha256": _require_sha256(
            launch_expectation_sha256, "launch expectation SHA-256"
        ),
    }:
        raise ExecutionSealV2Error("procfs inventory launch binding differs")
    wrapper = _require_exact(
        inventory["wrapper"], EXCEPTION_WRAPPER_KEYS, "inventory wrapper"
    )
    if wrapper != {"pid": wrapper_pid, "start_ticks": wrapper_start_ticks}:
        raise ExecutionSealV2Error("procfs inventory wrapper binding differs")
    if not _is_int(wrapper_pid) or wrapper_pid <= 0:
        raise ExecutionSealV2Error("wrapper PID is invalid")
    if not _is_int(wrapper_start_ticks) or wrapper_start_ticks <= 0:
        raise ExecutionSealV2Error("wrapper start ticks are invalid")
    namespace = _validate_runtime_namespace(
        inventory["runtime_namespace"], label="inventory runtime namespace"
    )
    if namespace["proc1_start_ticks"] > wrapper_start_ticks:
        raise ExecutionSealV2Error("runtime boot/proc identity baseline differs")

    freezer_ancestors = _validate_ancestor_records(
        freezer["startup_ancestors"], label="freezer startup ancestors"
    )
    for key in (
        "pid",
        "ppid",
        "process_group_id",
        "process_start_ticks",
        "session_id",
        "tty_nr",
    ):
        if not _is_int(freezer[key]):
            raise ExecutionSealV2Error(f"exception freezer {key} is invalid")
    if (
        freezer["pid"] <= 1
        or freezer["ppid"] != 1
        or freezer["process_group_id"] != freezer["pid"]
        or freezer["session_id"] != freezer["pid"]
        or freezer["process_start_ticks"] <= wrapper_start_ticks
        or freezer["tty_nr"] != 0
        or freezer["cwd"] != "/tmp"
        or freezer["no_pts_fds"] is not True
        or freezer["python_path"] != EXPECTED_PYTHON_PATH
        or freezer["python_version"] != EXPECTED_PYTHON_VERSION
        or freezer["exec_env_sha256"] != canonical_sha256(DETACHED_EXEC_ENV)
        or freezer["stdio_targets_sha256"]
        != canonical_sha256(["/dev/null", "/dev/null", "/dev/null"])
        or freezer["startup_ancestors_sha256"] != canonical_sha256(freezer_ancestors)
        or any(
            record["start_ticks"] > freezer["process_start_ticks"]
            for record in freezer_ancestors
        )
    ):
        raise ExecutionSealV2Error("exception freezer detached proof differs")
    expected_freezer_argv = [
        EXPECTED_PYTHON_PATH,
        "-I",
        freezer_path.as_posix(),
        "--detached-child",
        "--launch-expectation",
        launch_expectation_path.as_posix(),
        "--output",
        (launch_expectation_path.parent / EXCEPTION_INVENTORY_FILENAME).as_posix(),
        "--startup-ancestors-json",
        canonical_bytes(freezer_ancestors).decode("utf-8"),
    ]
    if freezer["exec_argv_sha256"] != canonical_sha256(expected_freezer_argv):
        raise ExecutionSealV2Error("exception freezer exact argv binding differs")
    _assert_ancestor_records_gone(freezer_ancestors)
    _assert_process_start_gone(
        pid=freezer["pid"],
        start_ticks=freezer["process_start_ticks"],
        label="exception freezer",
    )

    snapshots = inventory["snapshots"]
    if not isinstance(snapshots, list) or len(snapshots) != 2:
        raise ExecutionSealV2Error("procfs inventory needs exactly two snapshots")
    prior_time: datetime | None = None
    prior_boottime_ns: int | None = None
    validated_snapshots: list[dict[str, Any]] = []
    for position, raw_snapshot in enumerate(snapshots, start=1):
        snapshot = _require_exact(
            raw_snapshot, EXCEPTION_SNAPSHOT_KEYS, f"exception snapshot {position}"
        )
        if snapshot["sequence"] != position:
            raise ExecutionSealV2Error("exception snapshot sequence differs")
        captured = _parse_utc(
            snapshot["captured_at_utc"], f"exception snapshot {position} time"
        )
        captured_boottime_ns = snapshot["captured_boottime_ns"]
        if not _is_int(captured_boottime_ns) or captured_boottime_ns <= 0:
            raise ExecutionSealV2Error("exception snapshot boottime is invalid")
        if prior_time is not None and (captured - prior_time).total_seconds() < 1.0:
            raise ExecutionSealV2Error(
                "exception snapshots must be strictly separated by at least one second"
            )
        if (
            prior_boottime_ns is not None
            and captured_boottime_ns - prior_boottime_ns < 1_000_000_000
        ):
            raise ExecutionSealV2Error(
                "exception snapshot boottime separation is below one second"
            )
        prior_time = captured
        prior_boottime_ns = captured_boottime_ns
        records = snapshot["records"]
        if not isinstance(records, list):
            raise ExecutionSealV2Error("exception snapshot records must be a list")
        validated_records: list[dict[str, Any]] = []
        for index, raw_record in enumerate(records):
            record = _require_exact(
                raw_record,
                EXCEPTION_RECORD_KEYS,
                f"exception snapshot {position} record {index}",
            )
            if (
                record["classification"]
                != "stable_pre_wrapper_cwd_permission_denied_process"
            ):
                raise ExecutionSealV2Error("exception classification differs")
            for key in ("uid", "gid", "ppid", "pid", "start_ticks"):
                minimum = 0 if key in {"uid", "gid", "ppid"} else 1
                if not _is_int(record[key]) or record[key] < minimum:
                    raise ExecutionSealV2Error(f"exception {key} is invalid")
            if (
                not _is_int(record["cmdline_size_bytes"])
                or record["cmdline_size_bytes"] < 0
            ):
                raise ExecutionSealV2Error("exception cmdline_size_bytes is invalid")
            if record["pid"] == wrapper_pid:
                raise ExecutionSealV2Error("wrapper cannot be a procfs exception")
            if record["start_ticks"] >= wrapper_start_ticks:
                raise ExecutionSealV2Error(
                    "every procfs exception must predate the wrapper"
                )
            if (
                not isinstance(record["comm"], str)
                or _COMM_RE.fullmatch(record["comm"]) is None
            ):
                raise ExecutionSealV2Error(
                    "exception comm is not canonical printable text"
                )
            _require_sha256(record["cmdline_sha256"], "exception cmdline_sha256")
            _require_sha256(record["cgroup_sha256"], "exception cgroup_sha256")
            validated_records.append(record)
        sort_keys = [
            (item["pid"], item["start_ticks"], item["uid"], item["comm"])
            for item in validated_records
        ]
        if sort_keys != sorted(sort_keys) or len(
            {item[0] for item in sort_keys}
        ) != len(sort_keys):
            raise ExecutionSealV2Error("exception records are not PID-sorted unique")
        if snapshot["record_count"] != len(validated_records):
            raise ExecutionSealV2Error("exception record_count differs")
        digest = canonical_sha256(validated_records)
        if snapshot["records_sha256"] != digest:
            raise ExecutionSealV2Error("exception records digest differs")
        validated_snapshots.append(snapshot)
    if canonical_bytes(validated_snapshots[0]["records"]) != canonical_bytes(
        validated_snapshots[1]["records"]
    ):
        raise ExecutionSealV2Error("exception snapshots are not identical")
    records = validated_snapshots[0]["records"]
    if inventory["inventory_sha256"] != canonical_sha256(records):
        raise ExecutionSealV2Error("exception inventory digest differs")
    frozen = _parse_utc(inventory["frozen_at_utc"], "exception frozen_at_utc")
    if prior_time is None or frozen < prior_time:
        raise ExecutionSealV2Error("exception inventory froze before its snapshots")
    if latest_allowed_time is not None and frozen > latest_allowed_time:
        raise ExecutionSealV2Error("exception inventory was frozen after the V2 plan")
    return inventory, records


def validate_detached_receipt_document(
    value: Any,
    *,
    plan: dict[str, Any],
    execution_plan_path: Path,
    execution_plan_sha256: str,
    runtime_namespace: dict[str, Any],
) -> dict[str, Any]:
    """Validate the complete immutable receipt without consulting outcomes."""

    receipt = _require_exact(
        copy.deepcopy(value), DETACHED_RECEIPT_KEYS, "detached launch receipt"
    )
    if (
        receipt["protocol"] != "cohort_causal_terminal_verifier_v2_detached_receipt_v1"
        or receipt["schema_version"] != 1
        or receipt["status"] != "ready_to_exec_exact_attester"
        or receipt["outcome_blind"] is not True
        or receipt["plan"]
        != {
            "path": execution_plan_path.as_posix(),
            "sha256": _require_sha256(
                execution_plan_sha256, "detached receipt plan digest"
            ),
        }
        or receipt["handoff"] != plan["detached_transport"]["handoff"]
        or receipt["launcher"] != plan["detached_transport"]["launcher"]
        or receipt["detached_launch_contract"] != plan["detached_launch_contract"]
        or receipt["exec_argv_sha256"]
        != canonical_sha256(plan["invocations"]["attester"]["argv"])
        or receipt["exec_env_sha256"] != canonical_sha256(DETACHED_EXEC_ENV)
        or receipt["minimum_delay_seconds"] != 30
        or receipt["runtime_namespace"] != runtime_namespace
    ):
        raise ExecutionSealV2Error("detached receipt frozen bindings differ")
    _validate_runtime_namespace(
        receipt["runtime_namespace"], label="detached receipt runtime namespace"
    )
    for key in (
        "clock_ticks_per_second",
        "minimum_delay_seconds",
        "observed_age_ticks",
        "pid",
        "ppid",
        "process_group_id",
        "process_start_ticks",
        "session_id",
        "tty_nr",
    ):
        if not _is_int(receipt[key]):
            raise ExecutionSealV2Error(f"detached receipt {key} is invalid")
    ancestors = _validate_ancestor_records(
        receipt["startup_ancestors"], label="detached receipt startup ancestors"
    )
    if (
        receipt["clock_ticks_per_second"] <= 0
        or receipt["pid"] <= 1
        or receipt["ppid"] != 1
        or receipt["process_group_id"] != receipt["pid"]
        or receipt["session_id"] != receipt["pid"]
        or receipt["process_start_ticks"] <= 0
        or receipt["tty_nr"] != 0
        or receipt["cwd"] != "/tmp"
        or receipt["no_pts_fds"] is not True
        or receipt["observed_age_ticks"]
        < receipt["minimum_delay_seconds"] * receipt["clock_ticks_per_second"]
        or receipt["stdio_targets_sha256"]
        != canonical_sha256(["/dev/null", "/dev/null", "/dev/null"])
        or receipt["startup_ancestors_sha256"] != canonical_sha256(ancestors)
        or any(
            record["start_ticks"] > receipt["process_start_ticks"]
            for record in ancestors
        )
    ):
        raise ExecutionSealV2Error("detached receipt daemon proof differs")
    return receipt


def _expected_argv(plan: dict[str, Any], stage: str) -> list[str]:
    invocation = plan["invocations"][stage]
    tool = plan["tools"][stage]["path"]
    inputs = invocation["inputs"]
    outputs = invocation["outputs"]
    if stage == "attester":
        return [
            EXPECTED_PYTHON_PATH,
            tool,
            "--execution-plan",
            inputs["execution_plan"],
            "--root",
            inputs["root"],
            "--detached-launch-receipt",
            inputs["detached_launch_receipt"],
            "--launch-expectation",
            inputs["launch_expectation"],
            "--procfs-exception-inventory",
            inputs["procfs_exception_inventory"],
            "--provenance",
            inputs["provenance"],
            "--provenance-details",
            inputs["provenance_details"],
            "--output",
            outputs["attestation"],
            "--stability-seconds",
            invocation["parameters"]["stability_seconds"],
        ]
    if stage == "revalidator":
        return [
            EXPECTED_PYTHON_PATH,
            tool,
            "--execution-plan",
            inputs["execution_plan"],
            "--root",
            inputs["root"],
            "--attestation",
            inputs["attestation"],
            "--launch-expectation",
            inputs["launch_expectation"],
            "--grid",
            inputs["grid"],
            "--provenance",
            inputs["provenance"],
            "--formal-manifest",
            inputs["formal_manifest"],
            "--formal-decision",
            inputs["formal_decision"],
            "--preregistration",
            inputs["preregistration"],
            "--statistical-addendum",
            inputs["statistical_addendum"],
            "--output",
            outputs["revalidated_decision"],
            "--receipt",
            outputs["revalidation_receipt"],
        ]
    if stage == "execution_seal_builder":
        return [
            EXPECTED_PYTHON_PATH,
            tool,
            "--execution-plan",
            inputs["execution_plan"],
            "--attestation",
            inputs["attestation"],
            "--launch-expectation",
            inputs["launch_expectation"],
            "--causal-original",
            inputs["causal_original"],
            "--causal-revalidated",
            inputs["causal_revalidated"],
            "--revalidation-receipt",
            inputs["revalidation_receipt"],
            "--structured-preregistration",
            inputs["structured_preregistration"],
            "--output",
            outputs["execution_seal"],
        ]
    raise ExecutionSealV2Error(f"unknown V2 stage {stage}")


def _fixed_topology(
    *, causal_root: Path, durable_root: Path, tooling_root: Path
) -> dict[str, Any]:
    control = durable_root / "control"
    prep = durable_root / "prep"
    artifact = durable_root / "artifacts" / "cohort_causal"
    plan = control / PLAN_FILENAME
    expectation = control / LAUNCH_EXPECTATION_FILENAME
    exception_inventory = control / EXCEPTION_INVENTORY_FILENAME
    detached_receipt = control / DETACHED_RECEIPT_FILENAME
    attestation = prep / ATTESTATION_FILENAME
    revalidated = prep / REVALIDATED_FILENAME
    receipt = prep / REVALIDATION_RECEIPT_FILENAME
    seal = prep / SEAL_FILENAME
    structured_prereg = tooling_root / STRUCTURED_PREREGISTRATION_FILENAME
    invocations = {
        "attester": {
            "argv": [],
            "inputs": {
                "execution_plan": plan.as_posix(),
                "detached_launch_receipt": detached_receipt.as_posix(),
                "launch_expectation": expectation.as_posix(),
                "procfs_exception_inventory": exception_inventory.as_posix(),
                "provenance": (artifact / "provenance.json").as_posix(),
                "provenance_details": (artifact / "provenance.details.json").as_posix(),
                "root": causal_root.as_posix(),
            },
            "outputs": {"attestation": attestation.as_posix()},
            "parameters": {"stability_seconds": "1.0"},
        },
        "revalidator": {
            "argv": [],
            "inputs": {
                "attestation": attestation.as_posix(),
                "execution_plan": plan.as_posix(),
                "formal_decision": (artifact / "formal_decision.json").as_posix(),
                "formal_manifest": (artifact / "formal_manifest.json").as_posix(),
                "grid": (causal_root / "grid_cohort_causal_formal.json").as_posix(),
                "launch_expectation": expectation.as_posix(),
                "preregistration": (
                    causal_root / v1.CAUSAL_PREREGISTRATION_FILENAME
                ).as_posix(),
                "provenance": (artifact / "provenance.json").as_posix(),
                "root": causal_root.as_posix(),
                "statistical_addendum": (
                    causal_root / v1.CAUSAL_STATISTICAL_ADDENDUM_FILENAME
                ).as_posix(),
            },
            "outputs": {
                "revalidated_decision": revalidated.as_posix(),
                "revalidation_receipt": receipt.as_posix(),
            },
            "parameters": {},
        },
        "execution_seal_builder": {
            "argv": [],
            "inputs": {
                "attestation": attestation.as_posix(),
                "causal_original": (artifact / "formal_decision.json").as_posix(),
                "causal_revalidated": revalidated.as_posix(),
                "execution_plan": plan.as_posix(),
                "launch_expectation": expectation.as_posix(),
                "revalidation_receipt": receipt.as_posix(),
                "structured_preregistration": structured_prereg.as_posix(),
            },
            "outputs": {"execution_seal": seal.as_posix()},
            "parameters": {},
        },
    }
    return invocations


def make_detached_handoff(
    *,
    tooling_source_commit: str,
    causal_checkout_root: Path,
    durable_attempt_root: Path,
) -> dict[str, Any]:
    """Build the transport-only /tmp handoff before V2 plan publication."""

    commit = _require_commit(tooling_source_commit, "handoff source commit")
    causal_root = _normalized_absolute(causal_checkout_root, "handoff causal root")
    durable_root = _normalized_absolute(durable_attempt_root, "handoff durable root")
    tooling_root = durable_root / "control" / "verifier" / commit
    tool_paths = {
        "attester": tooling_root / "attest_cohort_causal_completion_v2.py",
        "revalidator": tooling_root / "revalidate_cohort_causal_terminal_v2.py",
        "execution_seal_builder": tooling_root
        / "build_cohort_structured_state_execution_seal_v2.py",
    }
    tools = {
        name: _stable_binding(path, f"handoff V2 tool {name}")
        for name, path in sorted(tool_paths.items())
    }
    invocations = _fixed_topology(
        causal_root=causal_root, durable_root=durable_root, tooling_root=tooling_root
    )
    stub = {
        "detached_launch_contract": _validate_detached_launch_contract(
            tooling_root / DETACHED_LAUNCH_CONTRACT_FILENAME
        ),
        "durable_attempt_root": durable_root.as_posix(),
        "invocations": invocations,
        "tools": tools,
    }
    for stage in sorted(PLAN_INVOCATION_NAMES):
        invocations[stage]["argv"] = _expected_argv(stub, stage)
    launcher, handoff, receipt = _transport_paths(
        tooling_source_commit=commit, durable_root=durable_root
    )
    launcher_binding = _stable_binding(launcher, "handoff detached launcher")
    launcher_source = _stable_binding(
        tooling_root / TRANSPORT_LAUNCHER_FILENAME,
        "handoff registered launcher source",
    )
    if launcher_binding["sha256"] != launcher_source["sha256"]:
        raise ExecutionSealV2Error(
            "detached launcher differs from its registered tooling source"
        )
    return _expected_handoff(
        plan=stub,
        launcher_binding=launcher_binding,
        handoff_path=handoff,
        receipt_path=receipt,
    )


def publish_detached_handoff_no_overwrite(path: Path, handoff: dict[str, Any]) -> None:
    path = _normalized_absolute(path, "detached handoff output")
    if (
        not path.as_posix().startswith("/tmp/")
        or path.name != DETACHED_HANDOFF_FILENAME
    ):
        raise ExecutionSealV2Error("detached handoff path is not fixed under /tmp")
    if os.path.lexists(path):
        raise FileExistsError("refusing to overwrite detached handoff")
    v1._publish_no_overwrite(path, canonical_bytes(handoff))


_V1_LOAD_PLAN = v1.load_and_validate_execution_plan_stage
_V1_VALIDATE_ATTESTATION = v1._validate_attestation
_V1_PLAN_VALIDATION_GLOBALS = {
    name: getattr(v1, name)
    for name in (
        "ATTESTATION_FILENAME",
        "PLAN_FILENAME",
        "PLAN_SCHEMA_VERSION",
        "PLAN_TOOL_NAMES",
        "REVALIDATED_FILENAME",
        "REVALIDATION_RECEIPT_FILENAME",
        "SEAL_FILENAME",
    )
}
_V1_PLAN_PROTOCOL = v1.PLAN_PROTOCOL


def _validate_bound_v1_plan(path: Path) -> dict[str, Any]:
    raw, _ = v1._read_stable_file(path, label="bound V1 execution plan")
    try:
        value = v1._load_json_bytes(raw, label="bound V1 execution plan")
    except v1.ExecutionSealError as exc:
        raise ExecutionSealV2Error("bound V1 execution plan is invalid") from exc
    if raw != v1._canonical_bytes(value):
        raise ExecutionSealV2Error("bound V1 execution plan is not canonical")
    if (
        not isinstance(value, dict)
        or value.get("protocol") != _V1_PLAN_PROTOCOL
        or value.get("schema_version")
        != _V1_PLAN_VALIDATION_GLOBALS["PLAN_SCHEMA_VERSION"]
    ):
        raise ExecutionSealV2Error("bound execution plan is not V1")
    invocation = value.get("invocations", {}).get("attester")
    if not isinstance(invocation, dict):
        raise ExecutionSealV2Error("bound V1 plan has no attester invocation")
    active_globals = {name: getattr(v1, name) for name in _V1_PLAN_VALIDATION_GLOBALS}
    try:
        for name, item in _V1_PLAN_VALIDATION_GLOBALS.items():
            setattr(v1, name, item)
        _V1_LOAD_PLAN(
            execution_plan_path=path,
            stage="attester",
            expected_inputs=invocation["inputs"],
            expected_outputs=invocation["outputs"],
            expected_parameters=invocation["parameters"],
            actual_argv=invocation["argv"],
            runtime_python_path=value["runtime"]["python_path"],
            runtime_python_version=value["runtime"]["python_version"],
        )
    except (KeyError, TypeError, v1.ExecutionSealError) as exc:
        raise ExecutionSealV2Error("bound V1 plan fails full validation") from exc
    finally:
        for name, item in active_globals.items():
            setattr(v1, name, item)
    return value


def make_execution_plan(
    *,
    tooling_source_commit: str,
    causal_checkout_root: Path,
    durable_attempt_root: Path,
    created_at_utc: str,
) -> dict[str, Any]:
    """Construct (but do not publish) the exact prospective V2 execution plan."""

    _require_commit(tooling_source_commit, "tooling_source_commit")
    created_at = _parse_utc(created_at_utc, "plan created_at_utc")
    causal_root = _normalized_absolute(causal_checkout_root, "causal checkout root")
    durable_root = _normalized_absolute(durable_attempt_root, "durable attempt root")
    if durable_root.name != "attempt-002":
        raise ExecutionSealV2Error("V2 is fixed to attempt-002")
    control = durable_root / "control"
    tooling_root = control / "verifier" / tooling_source_commit
    for directory, label in (
        (causal_root, "causal checkout root"),
        (durable_root, "durable attempt root"),
        (control, "durable control root"),
        (tooling_root, "V2 tooling root"),
        (durable_root / "prep", "durable prep root"),
        (durable_root / "artifacts" / "cohort_causal", "causal artifact root"),
    ):
        v1._assert_real_directory(directory, label=label)

    expectation_path = control / LAUNCH_EXPECTATION_FILENAME
    expectation_raw, _ = v1._read_stable_file(
        expectation_path, label="V2 plan launch expectation"
    )
    expectation = v1._validate_launch_expectation(
        v1._load_json_bytes(expectation_raw, label="V2 plan launch expectation")
    )
    if (
        expectation["checkout_root"] != causal_root.as_posix()
        or expectation["durable_attempt_root"] != durable_root.as_posix()
        or expectation["attempt_id"] != durable_root.name
    ):
        raise ExecutionSealV2Error("launch expectation roots differ from V2 plan")

    v1_plan_path = control / V1_PLAN_FILENAME
    _validate_bound_v1_plan(v1_plan_path)
    exception_path = control / EXCEPTION_INVENTORY_FILENAME
    exception_raw, _ = v1._read_stable_file(
        exception_path, label="frozen procfs exception inventory"
    )
    exception_object = _strict_json_bytes(
        exception_raw, "frozen procfs exception inventory"
    )
    validate_exception_inventory(
        exception_object,
        launch_expectation_path=expectation_path,
        launch_expectation_sha256=_sha256(expectation_raw),
        wrapper_pid=expectation["wrapper_pid"],
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
        latest_allowed_time=created_at,
    )

    amendment = tooling_root / AMENDMENT_FILENAME
    detached_contract = tooling_root / DETACHED_LAUNCH_CONTRACT_FILENAME
    structured_prereg = tooling_root / STRUCTURED_PREREGISTRATION_FILENAME
    tool_paths = {
        "attester": tooling_root / "attest_cohort_causal_completion_v2.py",
        "revalidator": tooling_root / "revalidate_cohort_causal_terminal_v2.py",
        "execution_seal_builder": tooling_root
        / "build_cohort_structured_state_execution_seal_v2.py",
    }
    dependency_paths = {
        "exception_inventory_freezer_source": tooling_root
        / "freeze_cohort_causal_procfs_exception_inventory_v2.py",
        "transport_launcher_source": tooling_root / TRANSPORT_LAUNCHER_FILENAME,
        "v1_attester_library": tooling_root / "attest_cohort_causal_completion.py",
        "v1_revalidator_engine": tooling_root / "revalidate_cohort_causal_terminal.py",
        "v1_seal_engine": tooling_root
        / "build_cohort_structured_state_execution_seal.py",
    }
    tools = {
        name: _stable_binding(path, f"deployed V2 tool {name}")
        for name, path in sorted(tool_paths.items())
    }
    dependencies = {
        name: _stable_binding(path, f"deployed V1 dependency {name}")
        for name, path in sorted(dependency_paths.items())
    }
    expected_freezer_path = _freezer_transport_path(
        tooling_source_commit=tooling_source_commit
    )
    if (
        exception_object["freezer"]["path"] != expected_freezer_path.as_posix()
        or exception_object["freezer"]["sha256"]
        != dependencies["exception_inventory_freezer_source"]["sha256"]
    ):
        raise ExecutionSealV2Error(
            "procfs inventory freezer is not the exact plan-bound source copy"
        )
    invocations = _fixed_topology(
        causal_root=causal_root, durable_root=durable_root, tooling_root=tooling_root
    )
    transport_launcher, transport_handoff, transport_receipt = _transport_paths(
        tooling_source_commit=tooling_source_commit, durable_root=durable_root
    )
    v1._assert_real_directory(
        transport_launcher.parent, label="detached transport root"
    )
    if os.path.lexists(transport_receipt):
        raise ExecutionSealV2Error(
            "detached transport receipt must be absent at V2 plan creation"
        )
    launcher_binding = _stable_binding(
        transport_launcher, "detached transport launcher"
    )
    if (
        launcher_binding["sha256"]
        != dependencies["transport_launcher_source"]["sha256"]
    ):
        raise ExecutionSealV2Error(
            "detached launcher differs from its plan-bound tooling source"
        )
    plan: dict[str, Any] = {
        "amendment": _stable_binding(amendment, "V2 amendment"),
        "attempt_id": durable_root.name,
        "causal_checkout_root": causal_root.as_posix(),
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": CAUSAL_PROTOCOL_SEAL_STATUS,
        "created_at_utc": created_at_utc,
        "detached_launch_contract": _validate_detached_launch_contract(
            detached_contract
        ),
        "detached_transport": {
            "handoff": {"path": transport_handoff.as_posix(), "sha256": "0" * 64},
            "launcher": launcher_binding,
            "receipt_path": transport_receipt.as_posix(),
        },
        "durable_attempt_root": durable_root.as_posix(),
        "implementation_dependencies": dependencies,
        "invocations": invocations,
        "launch_expectation": {
            "path": expectation_path.as_posix(),
            "sha256": _sha256(expectation_raw),
        },
        "online_icl": None,
        "procfs_exception_inventory": {
            "path": exception_path.as_posix(),
            "sha256": _sha256(exception_raw),
        },
        "protocol": PLAN_PROTOCOL,
        "runtime": {
            "python_path": EXPECTED_PYTHON_PATH,
            "python_version": EXPECTED_PYTHON_VERSION,
        },
        "schema_version": PLAN_SCHEMA_VERSION,
        "status": PLAN_STATUS,
        "structured_preregistration": _stable_binding(
            structured_prereg, "structured preregistration"
        ),
        "tooling_root": tooling_root.as_posix(),
        "tooling_source_commit": tooling_source_commit,
        "tools": tools,
        "v1_execution_plan": _stable_binding(v1_plan_path, "bound V1 plan"),
    }
    for stage in sorted(PLAN_INVOCATION_NAMES):
        plan["invocations"][stage]["argv"] = _expected_argv(plan, stage)
    handoff_raw, _ = v1._read_stable_file(
        transport_handoff, label="detached transport handoff"
    )
    _validate_handoff_bytes(
        payload=handoff_raw,
        expected=_expected_handoff(
            plan=plan,
            launcher_binding=launcher_binding,
            handoff_path=transport_handoff,
            receipt_path=transport_receipt,
        ),
    )
    plan["detached_transport"]["handoff"]["sha256"] = _sha256(handoff_raw)
    if set(plan) != PLAN_KEYS:
        raise AssertionError("generated V2 execution plan schema drift")
    return plan


def publish_execution_plan_no_overwrite(path: Path, plan: dict[str, Any]) -> None:
    path = _normalized_absolute(path, "V2 execution plan output")
    if path.name != PLAN_FILENAME:
        raise ExecutionSealV2Error("V2 execution plan filename differs")
    if os.path.lexists(path):
        raise FileExistsError("refusing to overwrite V2 execution plan")
    v1._publish_no_overwrite(path, canonical_bytes(plan))


def load_and_validate_execution_plan_stage(
    *,
    execution_plan_path: Path,
    stage: str,
    expected_inputs: Mapping[str, str | Path],
    expected_outputs: Mapping[str, str | Path],
    expected_parameters: Mapping[str, str] | None = None,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Strictly bind one V2 invocation and every frozen control dependency."""

    if stage not in PLAN_TOOL_NAMES:
        raise ExecutionSealV2Error("unknown V2 execution-plan stage")
    path = _normalized_absolute(execution_plan_path, "V2 execution plan")
    raw, _ = v1._read_stable_file(path, label="V2 execution plan")
    plan = _require_exact(
        _strict_json_bytes(raw, "V2 execution plan"), PLAN_KEYS, "V2 plan"
    )
    if (
        plan["protocol"] != PLAN_PROTOCOL
        or plan["schema_version"] != PLAN_SCHEMA_VERSION
        or plan["status"] != PLAN_STATUS
        or plan["online_icl"] is not None
        or plan["causal_protocol_seal_sha256"] is not None
        or plan["causal_protocol_seal_status"] != CAUSAL_PROTOCOL_SEAL_STATUS
    ):
        raise ExecutionSealV2Error("V2 plan protocol/status boundary differs")
    created_at = _parse_utc(plan["created_at_utc"], "V2 plan created_at_utc")
    causal_root = _normalized_absolute(plan["causal_checkout_root"], "plan causal root")
    durable_root = _normalized_absolute(
        plan["durable_attempt_root"], "plan durable root"
    )
    tooling_root = _normalized_absolute(plan["tooling_root"], "plan tooling root")
    commit = _require_commit(plan["tooling_source_commit"], "plan source commit")
    if (
        durable_root.name != plan["attempt_id"]
        or plan["attempt_id"] != "attempt-002"
        or tooling_root != durable_root / "control" / "verifier" / commit
        or path != durable_root / "control" / PLAN_FILENAME
    ):
        raise ExecutionSealV2Error("V2 plan fixed roots or path differ")
    for directory, label in (
        (causal_root, "causal checkout root"),
        (durable_root, "durable root"),
        (durable_root / "control", "control root"),
        (tooling_root, "tooling root"),
    ):
        v1._assert_real_directory(directory, label=label)

    runtime = _require_exact(plan["runtime"], PLAN_RUNTIME_KEYS, "V2 runtime")
    if runtime != {
        "python_path": EXPECTED_PYTHON_PATH,
        "python_version": EXPECTED_PYTHON_VERSION,
    }:
        raise ExecutionSealV2Error("V2 runtime differs")

    control = durable_root / "control"
    fixed_bindings = {
        "v1_execution_plan": control / V1_PLAN_FILENAME,
        "launch_expectation": control / LAUNCH_EXPECTATION_FILENAME,
        "procfs_exception_inventory": control / EXCEPTION_INVENTORY_FILENAME,
        "amendment": tooling_root / AMENDMENT_FILENAME,
        "detached_launch_contract": tooling_root / DETACHED_LAUNCH_CONTRACT_FILENAME,
        "structured_preregistration": tooling_root
        / STRUCTURED_PREREGISTRATION_FILENAME,
    }
    validated_bindings: dict[str, dict[str, str]] = {}
    for name, fixed_path in fixed_bindings.items():
        binding = _validate_binding(plan[name], f"plan.{name}")
        if binding["path"] != fixed_path.as_posix():
            raise ExecutionSealV2Error(f"plan.{name} path is not fixed")
        validated_bindings[name] = binding
    _validate_detached_launch_contract(
        Path(validated_bindings["detached_launch_contract"]["path"])
    )
    transport = _require_exact(
        plan["detached_transport"], DETACHED_TRANSPORT_KEYS, "detached transport"
    )
    fixed_launcher, fixed_handoff, fixed_receipt = _transport_paths(
        tooling_source_commit=commit, durable_root=durable_root
    )
    launcher_binding = _validate_binding(
        transport["launcher"], "detached transport launcher"
    )
    handoff_binding = _validate_binding(
        transport["handoff"], "detached transport handoff"
    )
    receipt_path = _normalized_absolute(
        transport["receipt_path"], "detached transport receipt path"
    )
    if (
        launcher_binding["path"] != fixed_launcher.as_posix()
        or handoff_binding["path"] != fixed_handoff.as_posix()
        or receipt_path != fixed_receipt
    ):
        raise ExecutionSealV2Error("detached transport fixed paths differ")

    fixed_tools = {
        "attester": tooling_root / "attest_cohort_causal_completion_v2.py",
        "revalidator": tooling_root / "revalidate_cohort_causal_terminal_v2.py",
        "execution_seal_builder": tooling_root
        / "build_cohort_structured_state_execution_seal_v2.py",
    }
    tools = _require_exact(plan["tools"], PLAN_TOOL_NAMES, "V2 tools")
    for name, fixed_path in fixed_tools.items():
        binding = _validate_binding(tools[name], f"plan.tools.{name}")
        if binding["path"] != fixed_path.as_posix():
            raise ExecutionSealV2Error(f"V2 tool path differs: {name}")

    dependency_names = frozenset(
        {
            "exception_inventory_freezer_source",
            "transport_launcher_source",
            "v1_attester_library",
            "v1_revalidator_engine",
            "v1_seal_engine",
        }
    )
    dependencies = _require_exact(
        plan["implementation_dependencies"],
        dependency_names,
        "V1 implementation dependencies",
    )
    fixed_dependencies = {
        "exception_inventory_freezer_source": tooling_root
        / "freeze_cohort_causal_procfs_exception_inventory_v2.py",
        "transport_launcher_source": tooling_root / TRANSPORT_LAUNCHER_FILENAME,
        "v1_attester_library": tooling_root / "attest_cohort_causal_completion.py",
        "v1_revalidator_engine": tooling_root / "revalidate_cohort_causal_terminal.py",
        "v1_seal_engine": tooling_root
        / "build_cohort_structured_state_execution_seal.py",
    }
    for name, fixed_path in fixed_dependencies.items():
        binding = _validate_binding(
            dependencies[name], f"plan.implementation_dependencies.{name}"
        )
        if binding["path"] != fixed_path.as_posix():
            raise ExecutionSealV2Error(f"V1 dependency path differs: {name}")
    if (
        launcher_binding["sha256"]
        != dependencies["transport_launcher_source"]["sha256"]
    ):
        raise ExecutionSealV2Error(
            "detached launcher differs from bound tooling source"
        )

    _validate_bound_v1_plan(Path(validated_bindings["v1_execution_plan"]["path"]))
    expectation_path = Path(validated_bindings["launch_expectation"]["path"])
    expectation_raw, _ = v1._read_stable_file(
        expectation_path, label="V2-bound launch expectation"
    )
    expectation = v1._validate_launch_expectation(
        v1._load_json_bytes(expectation_raw, label="V2-bound launch expectation")
    )
    if (
        expectation["checkout_root"] != causal_root.as_posix()
        or expectation["durable_attempt_root"] != durable_root.as_posix()
    ):
        raise ExecutionSealV2Error("V2 plan/launch roots differ")
    exception_path = Path(validated_bindings["procfs_exception_inventory"]["path"])
    exception_raw, _ = v1._read_stable_file(
        exception_path, label="V2-bound procfs exception inventory"
    )
    exception_object, _ = validate_exception_inventory(
        _strict_json_bytes(exception_raw, "V2-bound procfs exception inventory"),
        launch_expectation_path=expectation_path,
        launch_expectation_sha256=_sha256(expectation_raw),
        wrapper_pid=expectation["wrapper_pid"],
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
        latest_allowed_time=created_at,
    )
    freezer_dependency = dependencies["exception_inventory_freezer_source"]
    if (
        exception_object["freezer"]["path"]
        != _freezer_transport_path(tooling_source_commit=commit).as_posix()
        or exception_object["freezer"]["sha256"] != freezer_dependency["sha256"]
    ):
        raise ExecutionSealV2Error(
            "bound procfs inventory freezer differs from plan dependency"
        )

    invocations = _require_exact(
        plan["invocations"], PLAN_INVOCATION_NAMES, "V2 invocations"
    )
    expected_topology = _fixed_topology(
        causal_root=causal_root, durable_root=durable_root, tooling_root=tooling_root
    )
    for name in sorted(PLAN_INVOCATION_NAMES):
        invocation = _require_exact(
            invocations[name], PLAN_INVOCATION_KEYS, f"V2 invocation {name}"
        )
        input_keys, output_keys, parameter_keys = _INVOCATION_SCHEMAS[name]
        inputs = _require_exact(invocation["inputs"], input_keys, f"{name} inputs")
        outputs = _require_exact(invocation["outputs"], output_keys, f"{name} outputs")
        parameters = _require_exact(
            invocation["parameters"], parameter_keys, f"{name} parameters"
        )
        for mapping, label in ((inputs, "input"), (outputs, "output")):
            for key, item in mapping.items():
                mapping[key] = _normalized_absolute(
                    item, f"{name} {label} {key}"
                ).as_posix()
        if parameters != expected_topology[name]["parameters"]:
            raise ExecutionSealV2Error(f"V2 invocation parameters differ: {name}")
        if (
            inputs != expected_topology[name]["inputs"]
            or outputs != expected_topology[name]["outputs"]
        ):
            raise ExecutionSealV2Error(f"V2 invocation topology differs: {name}")
        expected_topology[name]["argv"] = _expected_argv(plan, name)
        if invocation["argv"] != expected_topology[name]["argv"]:
            raise ExecutionSealV2Error(f"V2 invocation argv differs: {name}")

    handoff_raw, _ = v1._read_stable_file(
        fixed_handoff, label="plan-bound detached transport handoff"
    )
    if _sha256(handoff_raw) != handoff_binding["sha256"]:
        raise ExecutionSealV2Error("detached handoff digest differs")
    _validate_handoff_bytes(
        payload=handoff_raw,
        expected=_expected_handoff(
            plan=plan,
            launcher_binding=launcher_binding,
            handoff_path=fixed_handoff,
            receipt_path=fixed_receipt,
        ),
    )

    selected = invocations[stage]
    normalized_expected_inputs = {
        key: _normalized_absolute(value, f"expected {stage} input {key}").as_posix()
        for key, value in expected_inputs.items()
    }
    normalized_expected_outputs = {
        key: _normalized_absolute(value, f"expected {stage} output {key}").as_posix()
        for key, value in expected_outputs.items()
    }
    if selected["inputs"] != normalized_expected_inputs:
        raise ExecutionSealV2Error("actual V2 stage inputs differ from plan")
    if selected["outputs"] != normalized_expected_outputs:
        raise ExecutionSealV2Error("actual V2 stage outputs differ from plan")
    if selected["parameters"] != dict(expected_parameters or {}):
        raise ExecutionSealV2Error("actual V2 stage parameters differ from plan")
    argv = (
        list(actual_argv)
        if actual_argv is not None
        else [
            Path(sys.executable).resolve().as_posix(),
            _normalized_absolute(
                Path(sys.argv[0]).absolute(), "invoked V2 tool"
            ).as_posix(),
            *sys.argv[1:],
        ]
    )
    if argv != selected["argv"]:
        raise ExecutionSealV2Error("actual V2 argv differs from plan")
    python_path = runtime_python_path or Path(sys.executable).resolve().as_posix()
    python_version = runtime_python_version or (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    if (
        python_path != runtime["python_path"]
        or python_version != runtime["python_version"]
    ):
        raise ExecutionSealV2Error("actual V2 Python runtime differs from plan")
    return plan, raw


def _load_bound_exception_for_attestation(
    *, expectation: dict[str, Any]
) -> tuple[Path, bytes, dict[str, Any], list[dict[str, Any]]]:
    durable = Path(expectation["durable_attempt_root"])
    expectation_path = durable / "control" / LAUNCH_EXPECTATION_FILENAME
    exception_path = durable / "control" / EXCEPTION_INVENTORY_FILENAME
    expectation_raw, _ = v1._read_stable_file(
        expectation_path, label="attestation-bound launch expectation"
    )
    exception_raw, _ = v1._read_stable_file(
        exception_path, label="attestation-bound procfs exception inventory"
    )
    exception, records = validate_exception_inventory(
        _strict_json_bytes(exception_raw, "attestation-bound procfs inventory"),
        launch_expectation_path=expectation_path,
        launch_expectation_sha256=_sha256(expectation_raw),
        wrapper_pid=expectation["wrapper_pid"],
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
    )
    return exception_path, exception_raw, exception, records


def _project_v2_attestation_for_v1(
    value: Any,
    *,
    execution_plan_path: Path,
    execution_plan_sha256: str,
    expectation: dict[str, Any],
    launch_expectation_path: Path,
    launch_expectation_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Validate V2 additions, then construct the narrow V1 validation view."""

    attestation = _require_exact(
        copy.deepcopy(value), ATTESTATION_KEYS, "V2 completion attestation"
    )
    if (
        attestation["protocol"] != ATTESTATION_PROTOCOL
        or attestation["schema_version"] != 2
        or attestation["status"] != "complete"
    ):
        raise ExecutionSealV2Error("completion attestation is not V2 complete")
    if (
        attestation["execution_plan_path"] != execution_plan_path.as_posix()
        or attestation["execution_plan_sha256"] != execution_plan_sha256
    ):
        raise ExecutionSealV2Error("V2 attestation plan binding differs")

    plan_raw, _ = v1._read_stable_file(
        execution_plan_path, label="attestation-bound V2 execution plan"
    )
    if _sha256(plan_raw) != execution_plan_sha256:
        raise ExecutionSealV2Error("attestation-bound V2 plan digest differs")
    plan = _require_exact(
        _strict_json_bytes(plan_raw, "attestation-bound V2 execution plan"),
        PLAN_KEYS,
        "attestation-bound V2 plan",
    )

    exception_path, exception_raw, exception, records = (
        _load_bound_exception_for_attestation(expectation=expectation)
    )
    freezer_dependency = plan["implementation_dependencies"][
        "exception_inventory_freezer_source"
    ]
    if (
        exception["freezer"]["path"]
        != _freezer_transport_path(
            tooling_source_commit=plan["tooling_source_commit"]
        ).as_posix()
        or exception["freezer"]["sha256"] != freezer_dependency["sha256"]
    ):
        raise ExecutionSealV2Error(
            "attestation freezer differs from V2 plan dependency"
        )
    exception_binding = _require_exact(
        attestation["procfs_exception_inventory"],
        ATTESTATION_EXCEPTION_BINDING_KEYS,
        "V2 attestation exception binding",
    )
    expected_exception_binding = {
        "inventory_sha256": exception["inventory_sha256"],
        "path": exception_path.as_posix(),
        "sha256": _sha256(exception_raw),
    }
    if exception_binding != expected_exception_binding:
        raise ExecutionSealV2Error("V2 attestation exception binding differs")

    receipt_path = Path(plan["detached_transport"]["receipt_path"])
    receipt_raw, _ = v1._read_stable_file(
        receipt_path, label="attestation-bound detached receipt"
    )
    receipt = validate_detached_receipt_document(
        _strict_json_bytes(receipt_raw, "attestation-bound detached receipt"),
        plan=plan,
        execution_plan_path=execution_plan_path,
        execution_plan_sha256=execution_plan_sha256,
        runtime_namespace=exception["runtime_namespace"],
    )
    receipt_binding = _require_exact(
        attestation["detached_launch_receipt"],
        ATTESTATION_RECEIPT_BINDING_KEYS,
        "V2 attestation detached receipt binding",
    )
    if receipt_binding != {
        "path": receipt_path.as_posix(),
        "pid": receipt.get("pid"),
        "process_start_ticks": receipt.get("process_start_ticks"),
        "sha256": _sha256(receipt_raw),
    }:
        raise ExecutionSealV2Error("detached receipt is not bound to V2 attestation")

    process = _require_exact(
        attestation["process_absence"], PROCESS_AUDIT_KEYS, "V2 process audit"
    )
    process_payload = {key: process[key] for key in process if key != "audit_sha256"}
    if (
        process["status"] != "pass"
        or process["method"] != PROCESS_AUDIT_METHOD
        or process["attempt_checkout_path"] != expectation["checkout_root"]
        or process["artifact_root_path"] != expectation["artifact_root"]
        or process["durable_attempt_root_path"] != expectation["durable_attempt_root"]
        or process["exception_inventory_sha256"] != _sha256(exception_raw)
        or process["observed_exception_count"] != len(records)
        or process["observed_exceptions_sha256"] != exception["inventory_sha256"]
        or process["audit_sha256"] != canonical_sha256(process_payload)
    ):
        raise ExecutionSealV2Error("V2 process audit differs from frozen exact set")

    legacy = copy.deepcopy(attestation)
    del legacy["detached_launch_receipt"]
    del legacy["procfs_exception_inventory"]
    legacy["protocol"] = v1.ATTESTATION_PROTOCOL
    legacy["schema_version"] = 1
    legacy_process_payload = {
        "artifact_root_path": process["artifact_root_path"],
        "attempt_checkout_path": process["attempt_checkout_path"],
        "method": "linux_procfs_cmdline_and_cwd",
        "status": "pass",
    }
    legacy["process_absence"] = {
        **legacy_process_payload,
        "audit_sha256": v1._sha256(v1._canonical_bytes(legacy_process_payload)),
    }
    legacy_validated, files = _V1_VALIDATE_ATTESTATION(
        legacy,
        execution_plan_path=execution_plan_path,
        execution_plan_sha256=execution_plan_sha256,
        expectation=copy.deepcopy(expectation),
        launch_expectation_path=launch_expectation_path,
        launch_expectation_sha256=launch_expectation_sha256,
    )
    return attestation, legacy_validated, files


def _validate_attestation_for_v1_builder(
    value: Any,
    *,
    execution_plan_path: Path,
    execution_plan_sha256: str,
    expectation: dict[str, Any],
    launch_expectation_path: Path,
    launch_expectation_sha256: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    attestation, _, files = _project_v2_attestation_for_v1(
        value,
        execution_plan_path=execution_plan_path,
        execution_plan_sha256=execution_plan_sha256,
        expectation=expectation,
        launch_expectation_path=launch_expectation_path,
        launch_expectation_sha256=launch_expectation_sha256,
    )
    return attestation, files


@contextmanager
def _v1_seal_engine_as_v2() -> Iterable[None]:
    """Temporarily route V1's exact branch engine through V2 validators."""

    replacements = {
        "PLAN_FILENAME": PLAN_FILENAME,
        "PLAN_SCHEMA_VERSION": PLAN_SCHEMA_VERSION,
        "ATTESTATION_FILENAME": ATTESTATION_FILENAME,
        "REVALIDATED_FILENAME": REVALIDATED_FILENAME,
        "REVALIDATION_RECEIPT_FILENAME": REVALIDATION_RECEIPT_FILENAME,
        "SEAL_FILENAME": SEAL_FILENAME,
        "SEAL_PROTOCOL": SEAL_PROTOCOL,
        "SEAL_SCHEMA_VERSION": SEAL_SCHEMA_VERSION,
        "PLAN_TOOL_NAMES": PLAN_TOOL_NAMES,
        "load_and_validate_execution_plan_stage": load_and_validate_execution_plan_stage,
        "_validate_attestation": _validate_attestation_for_v1_builder,
    }
    previous = {name: getattr(v1, name) for name in replacements}
    try:
        for name, item in replacements.items():
            setattr(v1, name, item)
        yield
    finally:
        for name, item in previous.items():
            setattr(v1, name, item)


def build_and_publish_execution_seal(
    *,
    execution_plan_path: Path,
    attestation_path: Path,
    launch_expectation_path: Path,
    causal_original_path: Path,
    causal_revalidated_path: Path,
    revalidation_receipt_path: Path,
    structured_preregistration_path: Path,
    output: Path,
    online_inputs: Mapping[str, Path] | None = None,
    now_fn: Any = None,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
) -> dict[str, Any]:
    """Publish the V2 seal using the exact V1 trigger-branch implementation."""

    with _v1_seal_engine_as_v2():
        return v1.build_and_publish_execution_seal(
            execution_plan_path=execution_plan_path,
            attestation_path=attestation_path,
            launch_expectation_path=launch_expectation_path,
            causal_original_path=causal_original_path,
            causal_revalidated_path=causal_revalidated_path,
            revalidation_receipt_path=revalidation_receipt_path,
            structured_preregistration_path=structured_preregistration_path,
            output=output,
            online_inputs=online_inputs,
            now_fn=now_fn,
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--causal-original", type=Path, required=True)
    parser.add_argument("--causal-revalidated", type=Path, required=True)
    parser.add_argument("--revalidation-receipt", type=Path, required=True)
    parser.add_argument("--structured-preregistration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build_and_publish_execution_seal(
            execution_plan_path=args.execution_plan,
            attestation_path=args.attestation,
            launch_expectation_path=args.launch_expectation,
            causal_original_path=args.causal_original,
            causal_revalidated_path=args.causal_revalidated,
            revalidation_receipt_path=args.revalidation_receipt,
            structured_preregistration_path=args.structured_preregistration,
            output=args.output,
        )
    except (ExecutionSealV2Error, v1.ExecutionSealError, FileExistsError):
        # Do not expose branch-bearing V1 seal errors on stderr.
        raise SystemExit(1) from None
    print(json.dumps({"status": "complete"}, sort_keys=True))


if __name__ == "__main__":
    main()
