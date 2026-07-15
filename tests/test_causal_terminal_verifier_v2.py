from __future__ import annotations

import copy
import errno
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import attest_cohort_causal_completion_v2 as att
import build_cohort_structured_state_execution_seal_v2 as seal
import freeze_cohort_causal_procfs_exception_inventory_v2 as freezer
import launch_cohort_causal_terminal_verifier_v2_detached as launcher
import revalidate_cohort_causal_terminal_v2 as revalidator


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _record(
    *,
    pid: int,
    cmdline: bytes,
    start_ticks: int = 100,
    ppid: int = 1,
    comm: str = "platformd",
    uid: int | None = None,
    gid: int | None = None,
    cgroup: bytes = b"0::/platform\n",
    cwd_errno: int = errno.EACCES,
    classification: str = "stable_pre_wrapper_cwd_permission_denied_process",
) -> dict[str, Any]:
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    return {
        "cgroup_sha256": _sha(cgroup),
        "classification": classification,
        "cmdline_sha256": _sha(cmdline),
        "cmdline_size_bytes": len(cmdline),
        "comm": comm,
        "cwd_errno": cwd_errno,
        "gid": gid,
        "pid": pid,
        "ppid": ppid,
        "start_ticks": start_ticks,
        "status_gids": [gid] * 4,
        "status_uids": [uid] * 4,
        "uid": uid,
    }


def _attested_file_record(path: Path, roles: list[str]) -> dict[str, Any]:
    metadata = path.stat()
    payload = path.read_bytes()
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mtime_ns": metadata.st_mtime_ns,
        "path": path.as_posix(),
        "roles": sorted(roles),
        "sha256": _sha(payload),
        "size_bytes": metadata.st_size,
    }


def _namespace() -> dict[str, Any]:
    return {
        "boot_id": "11111111-1111-1111-1111-111111111111",
        "mount_namespace_inode": 11,
        "pid_namespace_inode": 12,
        "proc1_cgroup_sha256": _sha(b"0::/platform\n"),
        "proc1_comm_sha256": "b" * 64,
        "proc1_start_ticks": 1,
        "proc_mountinfo_sha256": "a" * 64,
        "proc_root_device": 13,
        "proc_root_inode": 14,
        "proc_self_consistent": True,
        "proc_super_magic": 0x9FA0,
    }


def _policy(anchor: dict[str, Any], leaf_cmdline: bytes) -> dict[str, Any]:
    policy = {
        "anchor_comm": "monitor-connect",
        "anchor_pid": anchor["pid"],
        "anchor_start_ticks": anchor["start_ticks"],
        "anchor_static_record_sha256": seal.canonical_sha256(anchor),
        "classification": "dynamic_monitor_connect_sleep_cwd_eacces_direct_child_policy",
        "direct_child_required": True,
        "dynamic_cwd_target_absence_mechanically_proven": False,
        "dynamic_platform_origin_mechanically_proven": False,
        "leaf_cgroup_sha256": _namespace()["proc1_cgroup_sha256"],
        "leaf_cmdline_sha256": _sha(leaf_cmdline),
        "leaf_cmdline_size_bytes": len(leaf_cmdline),
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
    return policy


def _dynamic_record(
    *, pid: int, anchor: dict[str, Any], leaf_cmdline: bytes, start_ticks: int
) -> dict[str, Any]:
    return _record(
        pid=pid,
        ppid=anchor["pid"],
        cmdline=leaf_cmdline,
        start_ticks=start_ticks,
        comm="sleep",
        uid=0,
        gid=0,
        classification="dynamic_monitor_connect_sleep_cwd_eacces_process",
    )


def _freezer_copy(seed: Path, *, payload: bytes | None = None) -> Path:
    commit = hashlib.sha256(seed.as_posix().encode()).hexdigest()[:40]
    path = (
        Path("/tmp")
        / "cohort-causal-terminal-verifier-v2"
        / commit
        / seal.EXCEPTION_FREEZER_FILENAME
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    source = Path(freezer.__file__).read_bytes() if payload is None else payload
    if path.exists() and path.read_bytes() != source:
        path.unlink()
    if not path.exists():
        path.write_bytes(source)
    return path


def _freezer_proof(
    *,
    source: Path,
    expectation_path: Path,
    wrapper_start_ticks: int,
    ancestors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    process_start = wrapper_start_ticks + 1000
    ancestor_records = (
        [
            {
                "comm_sha256": "d" * 64,
                "pid": 987654321,
                "start_ticks": process_start - 1,
            }
        ]
        if ancestors is None
        else ancestors
    )
    output = expectation_path.parent / seal.EXCEPTION_INVENTORY_FILENAME
    argv = [
        seal.EXPECTED_PYTHON_PATH,
        "-I",
        source.as_posix(),
        "--detached-child",
        "--launch-expectation",
        expectation_path.as_posix(),
        "--output",
        output.as_posix(),
        "--startup-ancestors-json",
        seal.canonical_bytes(ancestor_records).decode(),
    ]
    return {
        "cwd": "/tmp",
        "exec_argv_sha256": seal.canonical_sha256(argv),
        "exec_env_sha256": seal.canonical_sha256(seal.DETACHED_EXEC_ENV),
        "no_pts_fds": True,
        "pid": 900001,
        "ppid": 1,
        "process_group_id": 900001,
        "process_start_ticks": process_start,
        "python_path": seal.EXPECTED_PYTHON_PATH,
        "python_version": seal.EXPECTED_PYTHON_VERSION,
        "session_id": 900001,
        "startup_ancestors": ancestor_records,
        "startup_ancestors_sha256": seal.canonical_sha256(ancestor_records),
        "stdio_targets_sha256": seal.canonical_sha256(
            ["/dev/null", "/dev/null", "/dev/null"]
        ),
        "tty_nr": 0,
    }


def _exception_inventory(
    records: list[dict[str, Any]],
    *,
    expectation_path: Path,
    expectation_sha: str,
    wrapper_pid: int = 9999,
    wrapper_start_ticks: int = 1000,
    freezer_path: Path | None = None,
) -> dict[str, Any]:
    anchor = _record(
        pid=380,
        ppid=313,
        cmdline=b"/usr/bin/monitor-connect\0--serve\0",
        start_ticks=max(0, wrapper_start_ticks - 10),
        comm="monitor-connect",
        uid=0,
        gid=0,
    )
    records = sorted([*records, anchor], key=lambda item: item["pid"])
    digest = seal.canonical_sha256(records)
    leaf_cmdline = b"sleep\00.5\0"
    policy = _policy(anchor, leaf_cmdline)
    dynamic = [
        _dynamic_record(
            pid=500 + index,
            anchor=anchor,
            leaf_cmdline=leaf_cmdline,
            start_ticks=wrapper_start_ticks + 10 + index,
        )
        for index in range(2)
    ]
    source = _freezer_copy(expectation_path) if freezer_path is None else freezer_path
    return {
        "dynamic_policy": policy,
        "dynamic_policy_sha256": seal.canonical_sha256(policy),
        "freezer": {
            "path": source.as_posix(),
            "sha256": _sha(source.read_bytes()),
            **_freezer_proof(
                source=source,
                expectation_path=expectation_path,
                wrapper_start_ticks=wrapper_start_ticks,
            ),
        },
        "frozen_at_utc": "2026-07-14T12:00:03Z",
        "inventory_sha256": seal.canonical_sha256(
            {"dynamic_policy": policy, "static_records": records}
        ),
        "launch_expectation": {
            "path": expectation_path.as_posix(),
            "sha256": expectation_sha,
        },
        "outcome_blind": True,
        "protocol": seal.EXCEPTION_INVENTORY_PROTOCOL,
        "runtime_namespace": _namespace(),
        "schema_version": 2,
        "semantic_artifacts_opened": False,
        "static_records_sha256": digest,
        "snapshots": [
            {
                "captured_at_utc": "2026-07-14T12:00:01Z",
                "captured_boottime_ns": 1_000_000_000,
                "dynamic_observation_count": 1,
                "dynamic_observations": [copy.deepcopy(dynamic[0])],
                "dynamic_observations_sha256": seal.canonical_sha256([dynamic[0]]),
                "sequence": 1,
                "static_record_count": len(records),
                "static_records": copy.deepcopy(records),
                "static_records_sha256": digest,
            },
            {
                "captured_at_utc": "2026-07-14T12:00:02Z",
                "captured_boottime_ns": 2_000_000_000,
                "dynamic_observation_count": 1,
                "dynamic_observations": [copy.deepcopy(dynamic[1])],
                "dynamic_observations_sha256": seal.canonical_sha256([dynamic[1]]),
                "sequence": 2,
                "static_record_count": len(records),
                "static_records": copy.deepcopy(records),
                "static_records_sha256": digest,
            },
        ],
        "status": "frozen_blinded",
        "wrapper": {"pid": wrapper_pid, "start_ticks": wrapper_start_ticks},
    }


def _write_proc_entry(
    root: Path,
    *,
    pid: int,
    cmdline: bytes,
    start_ticks: int = 100,
    ppid: int = 1,
    comm: str = "platformd",
    status_uids: list[int] | None = None,
    status_gids: list[int] | None = None,
    cgroup: bytes = b"0::/platform\n",
) -> Path:
    entry = root / str(pid)
    entry.mkdir(parents=True)
    (entry / "cmdline").write_bytes(cmdline)
    (entry / "comm").write_bytes(comm.encode() + b"\n")
    tail = [b"S", str(ppid).encode(), *([b"0"] * 17), str(start_ticks).encode()]
    (entry / "stat").write_bytes(
        str(pid).encode() + b" (" + comm.encode() + b") " + b" ".join(tail) + b"\n"
    )
    (entry / "cgroup").write_bytes(cgroup)
    uids = [os.getuid()] * 4 if status_uids is None else status_uids
    gids = [os.getgid()] * 4 if status_gids is None else status_gids
    (entry / "status").write_bytes(
        b"Name:\t"
        + comm.encode()
        + b"\nUid:\t"
        + b"\t".join(str(item).encode() for item in uids)
        + b"\nGid:\t"
        + b"\t".join(str(item).encode() for item in gids)
        + b"\n"
    )
    (entry / "cwd").symlink_to("/tmp")
    return entry


def _deny_cwd(monkeypatch: pytest.MonkeyPatch, denied_pids: set[int]) -> None:
    real_readlink = os.readlink

    def readlink(path: os.PathLike[str] | str):
        candidate = Path(path)
        if candidate.name == "cwd" and int(candidate.parent.name) in denied_pids:
            raise PermissionError(errno.EACCES, "denied", os.fspath(path))
        return real_readlink(path)

    monkeypatch.setattr(att.os, "readlink", readlink)


def _install_dynamic_scan_fixture(
    proc: Path,
    monkeypatch: pytest.MonkeyPatch,
    denied_pids: set[int],
    *,
    wrapper_start_ticks: int = 1000,
) -> tuple[dict[str, Any], dict[str, Any]]:
    proc1 = proc / "1"
    proc1.mkdir(exist_ok=True)
    (proc1 / "cgroup").write_bytes(b"0::/platform\n")
    anchor_cmdline = b"/usr/bin/monitor-connect\0--serve\0"
    leaf_cmdline = b"sleep\00.5\0"
    anchor = _record(
        pid=380,
        ppid=313,
        cmdline=anchor_cmdline,
        start_ticks=wrapper_start_ticks - 10,
        comm="monitor-connect",
        uid=0,
        gid=0,
    )
    _write_proc_entry(
        proc,
        pid=380,
        ppid=313,
        cmdline=anchor_cmdline,
        start_ticks=wrapper_start_ticks - 10,
        comm="monitor-connect",
        status_uids=[0, 0, 0, 0],
        status_gids=[0, 0, 0, 0],
    )
    _write_proc_entry(
        proc,
        pid=500,
        ppid=380,
        cmdline=leaf_cmdline,
        start_ticks=wrapper_start_ticks + 10,
        comm="sleep",
        status_uids=[0, 0, 0, 0],
        status_gids=[0, 0, 0, 0],
    )
    denied_pids.update({380, 500})
    original = att._read_process_record

    def root_metadata(entry: Path, cmdline: bytes, **kwargs: Any) -> dict[str, Any]:
        record = original(entry, cmdline, **kwargs)
        if int(entry.name) in {380, 500, 501}:
            record["uid"] = record["gid"] = 0
        return record

    monkeypatch.setattr(att, "_read_process_record", root_metadata)
    return anchor, _policy(anchor, leaf_cmdline)


def test_registered_cwd_exception_is_exact_and_target_blind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    command = b"/usr/bin/platformd\0--fixed\0"
    _write_proc_entry(proc, pid=101, cmdline=command)
    denied = {101}
    anchor, policy = _install_dynamic_scan_fixture(proc, monkeypatch, denied)
    _deny_cwd(monkeypatch, denied)
    record = _record(pid=101, cmdline=command)
    static_records = sorted([record, anchor], key=lambda item: item["pid"])

    audit = att._scan_process_references(
        attempt_checkout=tmp_path / "checkout",
        artifact_root=tmp_path / "artifacts",
        exception_records=static_records,
        dynamic_policy=policy,
        dynamic_policy_sha256=seal.canonical_sha256(policy),
        wrapper_start_ticks=1000,
        exception_file_sha256="b" * 64,
        proc_root=proc,
        self_pid=999,
    )

    assert audit["status"] == "pass"
    assert audit["observed_exception_count"] == 2
    assert audit["observed_exceptions_sha256"] == seal.canonical_sha256(static_records)
    assert set(audit) == seal.PROCESS_AUDIT_KEYS
    assert all("pid" not in key and "dynamic_observation" not in key for key in audit)
    serialized = json.dumps(audit)
    assert command.decode("utf-8", errors="ignore") not in serialized
    assert "cmdline_bytes" not in serialized and "raw_cmdline" not in serialized


@pytest.mark.parametrize("mode", ["unregistered", "missing", "restart", "target"])
def test_procfs_exception_mutations_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    target = tmp_path / "checkout"
    command = b"/usr/bin/platformd\0--fixed\0"
    if mode == "target":
        command = target.as_posix().encode() + b"\0"
    _write_proc_entry(
        proc, pid=101, cmdline=command, start_ticks=101 if mode == "restart" else 100
    )
    denied = {101}
    anchor, policy = _install_dynamic_scan_fixture(proc, monkeypatch, denied)
    _deny_cwd(monkeypatch, denied)
    records = [] if mode == "unregistered" else [_record(pid=101, cmdline=command)]
    if mode == "missing":
        records.append(_record(pid=102, cmdline=b"/usr/bin/other\0"))
    records.append(anchor)
    records.sort(key=lambda item: item["pid"])

    with pytest.raises(att.AttestationV2Error):
        att._scan_process_references(
            attempt_checkout=target,
            artifact_root=tmp_path / "artifacts",
            exception_records=records,
            dynamic_policy=policy,
            dynamic_policy_sha256=seal.canonical_sha256(policy),
            wrapper_start_ticks=1000,
            exception_file_sha256="b" * 64,
            proc_root=proc,
            self_pid=999,
        )


def test_process_scan_covers_complete_durable_root_and_pid_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    durable = tmp_path / "attempt-002"
    artifact = durable / "artifacts" / "cohort_causal"
    _write_proc_entry(
        proc,
        pid=101,
        cmdline=(durable / "control" / "receipt.json").as_posix().encode() + b"\0",
    )
    denied: set[int] = set()
    anchor, policy = _install_dynamic_scan_fixture(proc, monkeypatch, denied)
    _deny_cwd(monkeypatch, denied)
    with pytest.raises(att.AttestationV2Error):
        att._scan_process_references(
            attempt_checkout=tmp_path / "checkout",
            artifact_root=artifact,
            exception_records=[anchor],
            dynamic_policy=policy,
            dynamic_policy_sha256=seal.canonical_sha256(policy),
            wrapper_start_ticks=1000,
            exception_file_sha256="b" * 64,
            proc_root=proc,
            self_pid=999,
        )

    (proc / "101/cmdline").write_bytes(b"/usr/bin/fixed\0")
    real_identity = att._read_stat_identity
    calls: dict[int, int] = {}

    def reused(entry: Path) -> tuple[int, int, str]:
        pid = int(entry.name)
        calls[pid] = calls.get(pid, 0) + 1
        identity = real_identity(entry)
        return (
            identity
            if pid != 101 or calls[pid] == 1
            else (identity[0], identity[1] + 1, identity[2])
        )

    monkeypatch.setattr(att, "_read_stat_identity", reused)
    with pytest.raises(att.AttestationV2Error):
        att._scan_process_references(
            attempt_checkout=tmp_path / "checkout",
            artifact_root=artifact,
            exception_records=[anchor],
            dynamic_policy=policy,
            dynamic_policy_sha256=seal.canonical_sha256(policy),
            wrapper_start_ticks=1000,
            exception_file_sha256="b" * 64,
            proc_root=proc,
            self_pid=999,
        )


def test_cmdline_target_is_rejected_before_any_cwd_readlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "1").mkdir()
    (proc / "1/cgroup").write_bytes(b"0::/platform\n")
    checkout = tmp_path / "checkout"
    _write_proc_entry(
        proc,
        pid=101,
        cmdline=checkout.as_posix().encode() + b"\0",
    )
    real_readlink = os.readlink

    def reject_cwd_access(path: os.PathLike[str] | str):
        candidate = Path(path)
        if candidate.name == "cwd" and candidate.parent.name == "101":
            raise AssertionError("cwd was read before target-bearing cmdline rejection")
        return real_readlink(path)

    monkeypatch.setattr(os, "readlink", reject_cwd_access)
    with pytest.raises(freezer.FreezerError, match="cmdline references"):
        freezer._scan(
            proc_root=proc,
            targets=(checkout, tmp_path / "durable", tmp_path / "artifact"),
            self_pid=999,
            wrapper_start_ticks=1000,
            proc1_cgroup_sha256=_sha(b"0::/platform\n"),
            frozen_dynamic_policy=None,
        )

    anchor = _record(
        pid=380,
        ppid=313,
        cmdline=b"monitor-connect\0",
        start_ticks=990,
        comm="monitor-connect",
        uid=0,
        gid=0,
    )
    policy = _policy(anchor, b"sleep\00.5\0")
    with pytest.raises(att.AttestationV2Error, match="cmdline references"):
        att._scan_process_references(
            attempt_checkout=checkout,
            artifact_root=tmp_path / "durable/artifacts/cohort_causal",
            exception_records=[anchor],
            dynamic_policy=policy,
            dynamic_policy_sha256=seal.canonical_sha256(policy),
            wrapper_start_ticks=1000,
            exception_file_sha256="b" * 64,
            proc_root=proc,
            self_pid=999,
        )


def test_exception_inventory_rejects_time_duplicate_nan_and_noncanonical(
    tmp_path: Path,
) -> None:
    expectation = tmp_path / "expectation.json"
    inventory = _exception_inventory(
        [_record(pid=101, cmdline=b"fixed\0")],
        expectation_path=expectation,
        expectation_sha="c" * 64,
    )
    seal.validate_exception_inventory(
        inventory,
        launch_expectation_path=expectation,
        launch_expectation_sha256="c" * 64,
        wrapper_pid=9999,
        wrapper_start_ticks=1000,
    )

    same_time = copy.deepcopy(inventory)
    same_time["snapshots"][1]["captured_at_utc"] = same_time["snapshots"][0][
        "captured_at_utc"
    ]
    with pytest.raises(seal.ExecutionSealV2Error):
        seal.validate_exception_inventory(
            same_time,
            launch_expectation_path=expectation,
            launch_expectation_sha256="c" * 64,
            wrapper_pid=9999,
            wrapper_start_ticks=1000,
        )

    short_boottime = copy.deepcopy(inventory)
    short_boottime["snapshots"][1]["captured_boottime_ns"] = 1_999_999_999
    with pytest.raises(seal.ExecutionSealV2Error):
        seal.validate_exception_inventory(
            short_boottime,
            launch_expectation_path=expectation,
            launch_expectation_sha256="c" * 64,
            wrapper_pid=9999,
            wrapper_start_ticks=1000,
        )

    duplicate = copy.deepcopy(inventory)
    for snapshot in duplicate["snapshots"]:
        snapshot["static_records"].append(copy.deepcopy(snapshot["static_records"][0]))
        snapshot["static_record_count"] = len(snapshot["static_records"])
        snapshot["static_records_sha256"] = seal.canonical_sha256(
            snapshot["static_records"]
        )
    duplicate["static_records_sha256"] = seal.canonical_sha256(
        duplicate["snapshots"][0]["static_records"]
    )
    duplicate["inventory_sha256"] = seal.canonical_sha256(
        {
            "dynamic_policy": duplicate["dynamic_policy"],
            "static_records": duplicate["snapshots"][0]["static_records"],
        }
    )
    with pytest.raises(seal.ExecutionSealV2Error):
        seal.validate_exception_inventory(
            duplicate,
            launch_expectation_path=expectation,
            launch_expectation_sha256="c" * 64,
            wrapper_pid=9999,
            wrapper_start_ticks=1000,
        )

    with pytest.raises(seal.ExecutionSealV2Error):
        seal._strict_json_bytes(b'{"a":1,"a":2}', "duplicate")
    with pytest.raises(seal.ExecutionSealV2Error):
        seal._strict_json_bytes(b'{"a":NaN}', "nan")
    with pytest.raises(seal.ExecutionSealV2Error):
        seal._strict_json_bytes(b'{ "a": 1 }', "noncanonical")


def _validate_inventory_fixture(inventory: dict[str, Any], expectation: Path) -> None:
    seal.validate_exception_inventory(
        inventory,
        launch_expectation_path=expectation,
        launch_expectation_sha256="c" * 64,
        wrapper_pid=9999,
        wrapper_start_ticks=1000,
    )


def _refresh_dynamic_snapshot(snapshot: dict[str, Any]) -> None:
    snapshot["dynamic_observation_count"] = len(snapshot["dynamic_observations"])
    snapshot["dynamic_observations_sha256"] = seal.canonical_sha256(
        snapshot["dynamic_observations"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "parent_not_anchor",
        "status_uid_four_columns",
        "status_gid_four_columns",
        "proc_dir_uid",
        "proc_dir_gid",
        "cgroup",
        "cmdline",
        "cwd_errno",
        "count",
        "anchor_drift",
        "zero_cmdline_size",
    ],
)
def test_dynamic_policy_mutations_fail_closed(tmp_path: Path, mutation: str) -> None:
    expectation = tmp_path / "expectation.json"
    inventory = _exception_inventory(
        [], expectation_path=expectation, expectation_sha="c" * 64
    )
    policy = inventory["dynamic_policy"]
    observations = [
        snapshot["dynamic_observations"][0] for snapshot in inventory["snapshots"]
    ]
    if mutation == "parent_not_anchor":
        for record in observations:
            record["ppid"] += 1
    elif mutation == "status_uid_four_columns":
        for record in observations:
            record["status_uids"] = [0, 0, 0, 1]
    elif mutation == "status_gid_four_columns":
        for record in observations:
            record["status_gids"] = [0, 0, 0]
    elif mutation == "proc_dir_uid":
        for record in observations:
            record["uid"] = 1
    elif mutation == "proc_dir_gid":
        for record in observations:
            record["gid"] = 1
    elif mutation == "cgroup":
        for record in observations:
            record["cgroup_sha256"] = "d" * 64
    elif mutation == "cmdline":
        for record in observations:
            record["cmdline_sha256"] = "e" * 64
    elif mutation == "cwd_errno":
        for record in observations:
            record["cwd_errno"] = errno.EPERM
    elif mutation == "count":
        duplicate = copy.deepcopy(observations[0])
        duplicate["pid"] = 777
        duplicate["start_ticks"] += 1
        inventory["snapshots"][0]["dynamic_observations"].append(duplicate)
    elif mutation == "anchor_drift":
        policy["anchor_pid"] += 1
        for record in observations:
            record["ppid"] = policy["anchor_pid"]
    elif mutation == "zero_cmdline_size":
        policy["leaf_cmdline_size_bytes"] = 0
        for record in observations:
            record["cmdline_size_bytes"] = 0
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(mutation)
    inventory["dynamic_policy_sha256"] = seal.canonical_sha256(policy)
    for snapshot in inventory["snapshots"]:
        _refresh_dynamic_snapshot(snapshot)
    with pytest.raises(seal.ExecutionSealV2Error):
        _validate_inventory_fixture(inventory, expectation)


def test_dynamic_pid_rotation_and_anchor_clone_transition_are_registered(
    tmp_path: Path,
) -> None:
    expectation = tmp_path / "expectation.json"
    inventory = _exception_inventory(
        [], expectation_path=expectation, expectation_sha="c" * 64
    )
    first, second = inventory["snapshots"]
    assert (
        first["dynamic_observations"][0]["pid"]
        != second["dynamic_observations"][0]["pid"]
    )
    anchor = next(
        record
        for record in first["static_records"]
        if record["pid"] == inventory["dynamic_policy"]["anchor_pid"]
    )
    transition = second["dynamic_observations"][0]
    transition["comm"] = "monitor-connect"
    transition["cmdline_sha256"] = anchor["cmdline_sha256"]
    transition["cmdline_size_bytes"] = anchor["cmdline_size_bytes"]
    _refresh_dynamic_snapshot(second)
    _validate_inventory_fixture(inventory, expectation)


def test_snapshot_one_must_freeze_the_observed_sleep_profile(tmp_path: Path) -> None:
    expectation = tmp_path / "expectation.json"
    inventory = _exception_inventory(
        [], expectation_path=expectation, expectation_sha="c" * 64
    )
    policy = inventory["dynamic_policy"]
    anchor = next(
        record
        for record in inventory["snapshots"][0]["static_records"]
        if record["pid"] == policy["anchor_pid"]
    )
    for snapshot in inventory["snapshots"]:
        observation = snapshot["dynamic_observations"][0]
        observation["comm"] = "monitor-connect"
        observation["cmdline_sha256"] = anchor["cmdline_sha256"]
        observation["cmdline_size_bytes"] = anchor["cmdline_size_bytes"]
        _refresh_dynamic_snapshot(snapshot)
    arbitrary_sleep = b"sleep\0999\0"
    policy["leaf_cmdline_sha256"] = _sha(arbitrary_sleep)
    policy["leaf_cmdline_size_bytes"] = len(arbitrary_sleep)
    inventory["dynamic_policy_sha256"] = seal.canonical_sha256(policy)
    inventory["inventory_sha256"] = seal.canonical_sha256(
        {
            "dynamic_policy": policy,
            "static_records": inventory["snapshots"][0]["static_records"],
        }
    )
    with pytest.raises(seal.ExecutionSealV2Error, match="snapshot one did not freeze"):
        _validate_inventory_fixture(inventory, expectation)


def test_static_snapshot_and_proc1_namespace_drift_fail_closed(
    tmp_path: Path,
) -> None:
    expectation = tmp_path / "expectation.json"
    inventory = _exception_inventory(
        [], expectation_path=expectation, expectation_sha="c" * 64
    )
    static_drift = copy.deepcopy(inventory)
    static_drift["snapshots"][1]["static_records"][0]["start_ticks"] += 1
    static_drift["snapshots"][1]["static_records_sha256"] = seal.canonical_sha256(
        static_drift["snapshots"][1]["static_records"]
    )
    with pytest.raises(seal.ExecutionSealV2Error, match="static exception snapshots"):
        _validate_inventory_fixture(static_drift, expectation)

    namespace_drift = copy.deepcopy(inventory)
    namespace_drift["runtime_namespace"]["proc1_cgroup_sha256"] = "f" * 64
    with pytest.raises(seal.ExecutionSealV2Error):
        _validate_inventory_fixture(namespace_drift, expectation)


def test_real_freezer_scan_discovers_sleep_after_exact_anchor_clone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "1").mkdir()
    (proc / "1/cgroup").write_bytes(b"0::/platform\n")
    wrapper_start = 1000
    anchor_cmdline = b"/usr/bin/monitor-connect\0--serve\0"
    sleep_cmdline = b"sleep\00.5\0"
    _write_proc_entry(
        proc,
        pid=380,
        ppid=313,
        cmdline=anchor_cmdline,
        start_ticks=wrapper_start - 10,
        comm="monitor-connect",
        status_uids=[0, 0, 0, 0],
        status_gids=[0, 0, 0, 0],
    )
    _write_proc_entry(
        proc,
        pid=500,
        ppid=380,
        cmdline=anchor_cmdline,
        start_ticks=wrapper_start + 10,
        comm="monitor-connect",
        status_uids=[0, 0, 0, 0],
        status_gids=[0, 0, 0, 0],
    )
    denied = {380, 500, 501}
    real_readlink = freezer.os.readlink

    def denied_readlink(path: os.PathLike[str] | str):
        candidate = Path(path)
        if candidate.name == "cwd" and int(candidate.parent.name) in denied:
            raise PermissionError(errno.EACCES, "denied", os.fspath(path))
        return real_readlink(path)

    monkeypatch.setattr(freezer.os, "readlink", denied_readlink)
    real_record = freezer._process_record

    def root_record(entry: Path, cmdline: bytes, **kwargs: Any) -> dict[str, Any]:
        record = real_record(entry, cmdline, **kwargs)
        if int(entry.name) in denied:
            record["uid"] = record["gid"] = 0
            record["status_uids"] = record["status_gids"] = [0, 0, 0, 0]
        return record

    monkeypatch.setattr(freezer, "_process_record", root_record)
    scan_kwargs = {
        "proc_root": proc,
        "targets": (tmp_path / "checkout", tmp_path / "durable", tmp_path / "artifact"),
        "self_pid": 999,
        "wrapper_start_ticks": wrapper_start,
        "proc1_cgroup_sha256": _sha(b"0::/platform\n"),
    }
    with pytest.raises(freezer.DynamicPolicyDiscoveryPending) as pending:
        freezer._scan(**scan_kwargs, frozen_dynamic_policy=None)
    assert [record["pid"] for record in pending.value.static_records] == [380]

    for item in list((proc / "500").iterdir()):
        item.unlink()
    (proc / "500").rmdir()
    _write_proc_entry(
        proc,
        pid=500,
        ppid=380,
        cmdline=sleep_cmdline,
        start_ticks=wrapper_start + 20,
        comm="sleep",
        status_uids=[0, 0, 0, 0],
        status_gids=[0, 0, 0, 0],
    )
    static, first_dynamic, policy = freezer._scan(
        **scan_kwargs, frozen_dynamic_policy=None
    )
    assert [record["pid"] for record in static] == [380]
    assert first_dynamic[0]["comm"] == "sleep"

    for item in list((proc / "500").iterdir()):
        item.unlink()
    (proc / "500").rmdir()
    _write_proc_entry(
        proc,
        pid=501,
        ppid=380,
        cmdline=anchor_cmdline,
        start_ticks=wrapper_start + 30,
        comm="monitor-connect",
        status_uids=[0, 0, 0, 0],
        status_gids=[0, 0, 0, 0],
    )
    _, second_dynamic, observed_policy = freezer._scan(
        **scan_kwargs, frozen_dynamic_policy=policy
    )
    assert observed_policy == policy
    assert second_dynamic[0]["pid"] == 501
    assert second_dynamic[0]["comm"] == "monitor-connect"


@pytest.mark.parametrize("mode", ["zero", "multiple", "wrong_parent", "extra"])
def test_real_freezer_scan_rejects_nonexact_discovery_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "1").mkdir()
    (proc / "1/cgroup").write_bytes(b"0::/platform\n")
    wrapper_start = 1000
    anchor_cmdline = b"/usr/bin/monitor-connect\0--serve\0"
    _write_proc_entry(
        proc,
        pid=380,
        ppid=313,
        cmdline=anchor_cmdline,
        start_ticks=wrapper_start - 10,
        comm="monitor-connect",
        status_uids=[0, 0, 0, 0],
        status_gids=[0, 0, 0, 0],
    )
    specs: list[tuple[int, int, str, bytes]] = []
    if mode != "zero":
        specs.append(
            (
                500,
                381 if mode == "wrong_parent" else 380,
                "monitor-connect",
                anchor_cmdline,
            )
        )
    if mode == "multiple":
        specs.append((501, 380, "monitor-connect", anchor_cmdline))
    if mode == "extra":
        specs.append((501, 1, "unrelated", b"unrelated\0"))
    for offset, (pid, ppid, comm, cmdline) in enumerate(specs, start=1):
        _write_proc_entry(
            proc,
            pid=pid,
            ppid=ppid,
            cmdline=cmdline,
            start_ticks=wrapper_start + offset,
            comm=comm,
            status_uids=[0, 0, 0, 0],
            status_gids=[0, 0, 0, 0],
        )
    denied = {380, *(pid for pid, *_ in specs)}
    real_readlink = freezer.os.readlink

    def denied_readlink(path: os.PathLike[str] | str):
        candidate = Path(path)
        if candidate.name == "cwd" and int(candidate.parent.name) in denied:
            raise PermissionError(errno.EACCES, "denied", os.fspath(path))
        return real_readlink(path)

    monkeypatch.setattr(freezer.os, "readlink", denied_readlink)
    real_record = freezer._process_record

    def root_record(entry: Path, cmdline: bytes, **kwargs: Any) -> dict[str, Any]:
        record = real_record(entry, cmdline, **kwargs)
        if int(entry.name) in denied:
            record["uid"] = record["gid"] = 0
            record["status_uids"] = record["status_gids"] = [0, 0, 0, 0]
        return record

    monkeypatch.setattr(freezer, "_process_record", root_record)
    with pytest.raises(
        freezer.FreezerError, match="need exactly one monitor-connect/sleep"
    ):
        freezer._scan(
            proc_root=proc,
            targets=(
                tmp_path / "checkout",
                tmp_path / "durable",
                tmp_path / "artifact",
            ),
            self_pid=999,
            wrapper_start_ticks=wrapper_start,
            proc1_cgroup_sha256=_sha(b"0::/platform\n"),
            frozen_dynamic_policy=None,
        )


def test_attester_dynamic_rotation_transition_and_target_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    denied: set[int] = set()
    anchor, policy = _install_dynamic_scan_fixture(proc, monkeypatch, denied)
    _deny_cwd(monkeypatch, denied)
    kwargs = {
        "attempt_checkout": tmp_path / "checkout",
        "artifact_root": tmp_path / "durable/artifacts/cohort_causal",
        "exception_records": [anchor],
        "dynamic_policy": policy,
        "dynamic_policy_sha256": seal.canonical_sha256(policy),
        "wrapper_start_ticks": 1000,
        "exception_file_sha256": "b" * 64,
        "proc_root": proc,
        "self_pid": 999,
    }
    first = att._scan_process_references(**kwargs)
    for item in list((proc / "500").iterdir()):
        item.unlink()
    (proc / "500").rmdir()
    denied.remove(500)
    anchor_cmdline = b"/usr/bin/monitor-connect\0--serve\0"
    _write_proc_entry(
        proc,
        pid=501,
        ppid=380,
        cmdline=anchor_cmdline,
        start_ticks=1020,
        comm="monitor-connect",
        status_uids=[0, 0, 0, 0],
        status_gids=[0, 0, 0, 0],
    )
    denied.add(501)
    second = att._scan_process_references(**kwargs)
    assert first == second
    assert set(second) == seal.PROCESS_AUDIT_KEYS
    assert all("pid" not in key and "dynamic_observation" not in key for key in second)
    assert second["dynamic_policy_enforced"] is True

    target = (tmp_path / "checkout").as_posix().encode() + b"\0"
    (proc / "501/cmdline").write_bytes(target)
    with pytest.raises(att.AttestationV2Error, match="cmdline references"):
        att._scan_process_references(**kwargs)


def test_attester_rejects_parent_not_exact_anchor_and_proc1_cgroup_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    denied: set[int] = set()
    anchor, policy = _install_dynamic_scan_fixture(proc, monkeypatch, denied)
    _deny_cwd(monkeypatch, denied)
    kwargs = {
        "attempt_checkout": tmp_path / "checkout",
        "artifact_root": tmp_path / "durable/artifacts/cohort_causal",
        "exception_records": [anchor],
        "dynamic_policy": policy,
        "dynamic_policy_sha256": seal.canonical_sha256(policy),
        "wrapper_start_ticks": 1000,
        "exception_file_sha256": "b" * 64,
        "proc_root": proc,
        "self_pid": 999,
    }
    stat_raw = (
        (proc / "500/stat").read_bytes().replace(b"(sleep) S 380 ", b"(sleep) S 381 ")
    )
    (proc / "500/stat").write_bytes(stat_raw)
    with pytest.raises(att.AttestationV2Error, match="outside the dynamic cwd policy"):
        att._scan_process_references(**kwargs)

    (proc / "1/cgroup").write_bytes(b"0::/drifted\n")
    with pytest.raises(att.AttestationV2Error, match="cgroup drifted"):
        att._scan_process_references(**kwargs)


def test_revalidator_argv_has_one_tool_and_versioned_outputs() -> None:
    plan = {
        "tools": {"revalidator": {"path": "/tool/revalidator_v2.py"}},
        "invocations": {
            "revalidator": {
                "inputs": {
                    "attestation": "/a",
                    "execution_plan": "/p",
                    "formal_decision": "/d",
                    "formal_manifest": "/m",
                    "grid": "/g",
                    "launch_expectation": "/e",
                    "preregistration": "/r",
                    "provenance": "/v",
                    "root": "/x",
                    "statistical_addendum": "/s",
                },
                "outputs": {
                    "revalidated_decision": "/out.v2.json",
                    "revalidation_receipt": "/receipt.v2.json",
                },
            }
        },
    }
    argv = seal._expected_argv(plan, "revalidator")
    assert argv[:3] == [
        seal.EXPECTED_PYTHON_PATH,
        "/tool/revalidator_v2.py",
        "--execution-plan",
    ]
    assert argv.count("/tool/revalidator_v2.py") == 1
    assert seal.PLAN_FILENAME.endswith("_V2.json")
    assert seal.ATTESTATION_FILENAME.endswith(".v2.json")
    assert seal.REVALIDATED_FILENAME.endswith(".v2.json")
    assert seal.SEAL_FILENAME.endswith(".v2.json")
    contract = json.loads(
        Path(seal.__file__)
        .with_name(seal.DETACHED_LAUNCH_CONTRACT_FILENAME)
        .read_text()
    )
    assert contract == seal.DETACHED_LAUNCH_CONTRACT
    assert contract["dynamic_policy_discovery_max_attempts"] == (
        freezer.DYNAMIC_POLICY_DISCOVERY_MAX_ATTEMPTS
    )
    assert contract["dynamic_policy_discovery_interval_milliseconds"] == int(
        freezer.DYNAMIC_POLICY_DISCOVERY_INTERVAL_SECONDS * 1000
    )


def test_attester_capture_routes_receipt_inventory_and_restores_v1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exception = tmp_path / "exception.json"
    receipt = tmp_path / "receipt.json"
    output = tmp_path / "attestation.json"
    prior_loader = att.v1.load_and_validate_execution_plan_stage
    prior_publisher = att.v1._atomic_publish_no_overwrite
    observed: dict[str, Any] = {}

    def fake_loader(**kwargs: Any) -> tuple[dict[str, Any], bytes]:
        observed.update(kwargs)
        return {}, b"plan"

    monkeypatch.setattr(seal, "load_and_validate_execution_plan_stage", fake_loader)
    with att._capture_v1_attestation_as_v2(
        exception_path=exception, detached_receipt_path=receipt
    ) as captured:
        att.v1.load_and_validate_execution_plan_stage(expected_inputs={})
        att.v1._atomic_publish_no_overwrite(output, b"opaque-attestation")
    assert observed["expected_inputs"]["procfs_exception_inventory"] == exception
    assert observed["expected_inputs"]["detached_launch_receipt"] == receipt
    assert captured == {"path": output, "payload": b"opaque-attestation"}
    assert att.v1.load_and_validate_execution_plan_stage is prior_loader
    assert att.v1._atomic_publish_no_overwrite is prior_publisher


def test_v1_sources_remain_git_clean() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            "git",
            "diff",
            "--exit-code",
            "--",
            "attest_cohort_causal_completion.py",
            "revalidate_cohort_causal_terminal.py",
            "build_cohort_structured_state_execution_seal.py",
        ],
        cwd=root,
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()


def test_all_v2_control_publishers_refuse_overwrite(tmp_path: Path) -> None:
    plan_path = tmp_path / seal.PLAN_FILENAME
    plan_path.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        seal.publish_execution_plan_no_overwrite(plan_path, {})

    transport_root = _freezer_copy(tmp_path / "no-overwrite").parent
    handoff_path = transport_root / seal.DETACHED_HANDOFF_FILENAME
    handoff_path.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        seal.publish_detached_handoff_no_overwrite(handoff_path, {})

    receipt_path = tmp_path / seal.DETACHED_RECEIPT_FILENAME
    receipt_path.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        launcher._publish_no_overwrite(receipt_path, b"new")


def _load_v1_fixture_module() -> Any:
    path = Path(__file__).with_name("test_revalidate_cohort_causal_terminal.py")
    spec = importlib.util.spec_from_file_location("_v1_revalidation_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_v1_seal_fixture_module() -> Any:
    path = Path(__file__).with_name("test_cohort_structured_state_execution_seal.py")
    spec = importlib.util.spec_from_file_location("_v1_seal_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("decision", ["pass", "valid_no_go"])
def test_v2_revalidation_delegates_and_preserves_decision_bytes_and_branch_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, decision: str
) -> None:
    v1_tests = _load_v1_fixture_module()
    fixture = v1_tests._terminal_fixture(tmp_path / "v1", decision=decision)
    full_report = _load_v1_seal_fixture_module()._causal_report(decision)
    fixture["decision"].write_bytes(
        (json.dumps(full_report, indent=2, sort_keys=True) + "\n").encode()
    )
    manifest_mtime = fixture["manifest"].stat().st_mtime_ns
    os.utime(fixture["decision"], ns=(manifest_mtime, manifest_mtime))
    fixture["evaluate"] = lambda _: full_report
    durable = fixture["plan_path"].parents[1]
    control = durable / "control"
    expectation = json.loads(fixture["expectation"].read_text())
    commit = "b" * 40
    tooling = control / "verifier" / commit
    tooling.mkdir(parents=True)
    root = Path(__file__).resolve().parents[1]
    copies = [
        "attest_cohort_causal_completion_v2.py",
        "revalidate_cohort_causal_terminal_v2.py",
        "build_cohort_structured_state_execution_seal_v2.py",
        seal.EXCEPTION_FREEZER_FILENAME,
        seal.TRANSPORT_LAUNCHER_FILENAME,
        "attest_cohort_causal_completion.py",
        "revalidate_cohort_causal_terminal.py",
        "build_cohort_structured_state_execution_seal.py",
        seal.AMENDMENT_FILENAME,
        seal.DETACHED_LAUNCH_CONTRACT_FILENAME,
    ]
    for name in copies:
        (tooling / name).write_bytes((root / name).read_bytes())
    (tooling / seal.STRUCTURED_PREREGISTRATION_FILENAME).write_bytes(
        (Path(fixture["plan"]["structured_preregistration"]["path"])).read_bytes()
    )

    transport = tmp_path / "transport"
    transport.mkdir()
    launcher_path = transport / seal.TRANSPORT_LAUNCHER_FILENAME
    launcher_path.write_bytes(
        (root / "launch_cohort_causal_terminal_verifier_v2_detached.py").read_bytes()
    )
    handoff_path = transport / seal.DETACHED_HANDOFF_FILENAME
    receipt_path = control / seal.DETACHED_RECEIPT_FILENAME
    monkeypatch.setattr(
        seal,
        "_transport_paths",
        lambda **_: (launcher_path, handoff_path, receipt_path),
    )

    freezer_path = seal._freezer_transport_path(tooling_source_commit=commit)
    freezer_path.parent.mkdir(parents=True, exist_ok=True)
    freezer_path.write_bytes((root / seal.EXCEPTION_FREEZER_FILENAME).read_bytes())
    inventory = _exception_inventory(
        [],
        expectation_path=fixture["expectation"],
        expectation_sha=_sha(fixture["expectation"].read_bytes()),
        wrapper_pid=expectation["wrapper_pid"],
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
        freezer_path=freezer_path,
    )
    inventory_path = control / seal.EXCEPTION_INVENTORY_FILENAME
    inventory_path.write_bytes(seal.canonical_bytes(inventory))

    original_launcher_raw = launcher_path.read_bytes()
    launcher_path.write_bytes(original_launcher_raw + b"\n# mutation")
    with pytest.raises(seal.ExecutionSealV2Error):
        seal.make_detached_handoff(
            tooling_source_commit=commit,
            causal_checkout_root=fixture["root"],
            durable_attempt_root=durable,
        )
    launcher_path.write_bytes(original_launcher_raw)
    handoff = seal.make_detached_handoff(
        tooling_source_commit=commit,
        causal_checkout_root=fixture["root"],
        durable_attempt_root=durable,
    )
    assert handoff["launcher_argv"][1] == "-I"
    handoff_path.write_bytes(seal.canonical_bytes(handoff))
    plan = seal.make_execution_plan(
        tooling_source_commit=commit,
        causal_checkout_root=fixture["root"],
        durable_attempt_root=durable,
        created_at_utc="2026-07-14T12:00:04Z",
    )
    assert (
        plan["implementation_dependencies"]["exception_inventory_freezer_source"][
            "sha256"
        ]
        == inventory["freezer"]["sha256"]
    )
    assert (
        plan["implementation_dependencies"]["transport_launcher_source"]["sha256"]
        == plan["detached_transport"]["launcher"]["sha256"]
    )
    original_freezer_raw = freezer_path.read_bytes()
    original_inventory_raw = inventory_path.read_bytes()
    try:
        freezer_path.write_bytes(original_freezer_raw + b"\n# mutation")
        mismatched_inventory = copy.deepcopy(inventory)
        mismatched_inventory["freezer"]["sha256"] = _sha(freezer_path.read_bytes())
        inventory_path.write_bytes(seal.canonical_bytes(mismatched_inventory))
        with pytest.raises(seal.ExecutionSealV2Error):
            seal.make_execution_plan(
                tooling_source_commit=commit,
                causal_checkout_root=fixture["root"],
                durable_attempt_root=durable,
                created_at_utc="2026-07-14T12:00:04Z",
            )
    finally:
        freezer_path.write_bytes(original_freezer_raw)
        inventory_path.write_bytes(original_inventory_raw)
    plan_path = control / seal.PLAN_FILENAME
    plan_path.write_bytes(seal.canonical_bytes(plan))
    receipt = {
        "clock_ticks_per_second": 100,
        "cwd": "/tmp",
        "detached_launch_contract": plan["detached_launch_contract"],
        "exec_argv_sha256": seal.canonical_sha256(
            plan["invocations"]["attester"]["argv"]
        ),
        "exec_env_sha256": seal.canonical_sha256(seal.DETACHED_EXEC_ENV),
        "handoff": plan["detached_transport"]["handoff"],
        "launcher": plan["detached_transport"]["launcher"],
        "minimum_delay_seconds": 30,
        "no_pts_fds": True,
        "observed_age_ticks": 3000,
        "outcome_blind": True,
        "pid": 777,
        "plan": {"path": plan_path.as_posix(), "sha256": _sha(plan_path.read_bytes())},
        "process_group_id": 777,
        "ppid": 1,
        "process_start_ticks": 100,
        "protocol": "cohort_causal_terminal_verifier_v2_detached_receipt_v1",
        "runtime_namespace": inventory["runtime_namespace"],
        "schema_version": 1,
        "session_id": 777,
        "status": "ready_to_exec_exact_attester",
        "startup_ancestors": [
            {"comm_sha256": "c" * 64, "pid": 987654320, "start_ticks": 99}
        ],
        "startup_ancestors_sha256": seal.canonical_sha256(
            [{"comm_sha256": "c" * 64, "pid": 987654320, "start_ticks": 99}]
        ),
        "stdio_targets_sha256": seal.canonical_sha256(
            ["/dev/null", "/dev/null", "/dev/null"]
        ),
        "tty_nr": 0,
    }
    receipt_path.write_bytes(seal.canonical_bytes(receipt))

    old_attestation = json.loads(fixture["attestation"].read_text())
    smoke_gate = fixture["artifact"] / "smoke_gate.json"
    smoke_gate.write_bytes(b'{"status":"pass"}\n')
    smoke_record = _attested_file_record(smoke_gate, ["causal_smoke_gate"])
    decision_record = _attested_file_record(fixture["decision"], ["formal_decision"])
    for snapshot in old_attestation["snapshots"]:
        snapshot["files"] = [
            decision_record if "formal_decision" in record["roles"] else record
            for record in snapshot["files"]
        ]
        snapshot["files"].append(copy.deepcopy(smoke_record))
        snapshot["files"].sort(key=lambda item: item["path"])
        snapshot["file_count"] = len(snapshot["files"])
        snapshot["inventory_sha256"] = seal.canonical_sha256(snapshot["files"])
    old_attestation["causal_pre_attestation_inventory_sha256"] = old_attestation[
        "snapshots"
    ][0]["inventory_sha256"]
    process_payload = {
        "artifact_root_path": fixture["artifact"].as_posix(),
        "attempt_checkout_path": fixture["root"].as_posix(),
        "durable_attempt_root_path": durable.as_posix(),
        "dynamic_policy_enforced": True,
        "dynamic_policy_sha256": inventory["dynamic_policy_sha256"],
        "exception_inventory_sha256": _sha(inventory_path.read_bytes()),
        "method": seal.PROCESS_AUDIT_METHOD,
        "observed_exception_count": len(inventory["snapshots"][0]["static_records"]),
        "observed_exceptions_sha256": inventory["static_records_sha256"],
        "status": "pass",
    }
    old_attestation.update(
        {
            "detached_launch_receipt": {
                "path": receipt_path.as_posix(),
                "pid": 777,
                "process_start_ticks": 100,
                "sha256": _sha(receipt_path.read_bytes()),
            },
            "execution_plan_path": plan_path.as_posix(),
            "execution_plan_sha256": _sha(plan_path.read_bytes()),
            "process_absence": {
                **process_payload,
                "audit_sha256": seal.canonical_sha256(process_payload),
            },
            "procfs_exception_inventory": {
                "inventory_sha256": inventory["inventory_sha256"],
                "path": inventory_path.as_posix(),
                "sha256": _sha(inventory_path.read_bytes()),
            },
            "protocol": seal.ATTESTATION_PROTOCOL,
            "schema_version": 2,
        }
    )
    attestation_path = durable / "prep" / seal.ATTESTATION_FILENAME
    attestation_path.write_bytes(seal.canonical_bytes(old_attestation))

    output = durable / "prep" / seal.REVALIDATED_FILENAME
    output_receipt = durable / "prep" / seal.REVALIDATION_RECEIPT_FILENAME
    revalidator.revalidate_terminal(
        root=fixture["root"],
        execution_plan_path=plan_path,
        attestation_path=attestation_path,
        launch_expectation_path=fixture["expectation"],
        grid_path=fixture["grid_path"],
        provenance_path=fixture["provenance"],
        formal_manifest_path=fixture["manifest"],
        formal_decision_path=fixture["decision"],
        revalidated_output=output,
        receipt_output=output_receipt,
        assemble_fn=fixture["assemble"],
        evaluate_fn=fixture["evaluate"],
        make_grid_fn=lambda *, smoke: fixture["grid"],
        actual_argv=plan["invocations"]["revalidator"]["argv"],
        runtime_python_path=seal.EXPECTED_PYTHON_PATH,
        runtime_python_version=seal.EXPECTED_PYTHON_VERSION,
    )
    assert output.read_bytes() == fixture["decision"].read_bytes()
    assert revalidator.v1.revalidate_terminal is not revalidator.revalidate_terminal

    seal_output = durable / "prep" / seal.SEAL_FILENAME
    seal_kwargs = {
        "execution_plan_path": plan_path,
        "attestation_path": attestation_path,
        "launch_expectation_path": fixture["expectation"],
        "causal_original_path": fixture["decision"],
        "causal_revalidated_path": output,
        "revalidation_receipt_path": output_receipt,
        "structured_preregistration_path": Path(
            plan["structured_preregistration"]["path"]
        ),
        "output": seal_output,
        "now_fn": lambda: "2026-07-14T12:00:05Z",
        "actual_argv": plan["invocations"]["execution_seal_builder"]["argv"],
        "runtime_python_path": seal.EXPECTED_PYTHON_PATH,
        "runtime_python_version": seal.EXPECTED_PYTHON_VERSION,
    }
    if decision == "pass":
        with pytest.raises(seal.v1.ExecutionSealError, match="Trigger A is forbidden"):
            seal.build_and_publish_execution_seal(**seal_kwargs)
        assert not seal_output.exists()
    else:
        result = seal.build_and_publish_execution_seal(**seal_kwargs)
        sealed = json.loads(seal_output.read_bytes())
        assert result["trigger_branch"] == "causal_valid_no_go"
        assert sealed["protocol"] == seal.SEAL_PROTOCOL
        assert sealed["schema_version"] == seal.SEAL_SCHEMA_VERSION


def _write_stat_only(
    root: Path, *, pid: int, ppid: int, start_ticks: int, comm: str
) -> None:
    entry = root / str(pid)
    entry.mkdir(parents=True, exist_ok=True)
    fields = [b"S", str(ppid).encode(), *([b"0"] * 17), str(start_ticks).encode()]
    (entry / "stat").write_bytes(
        str(pid).encode() + b" (" + comm.encode() + b") " + b" ".join(fields)
    )


def test_transport_constants_and_detached_parent_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (
        launcher.RECEIPT_KEYS == seal.DETACHED_RECEIPT_KEYS == att.DETACHED_RECEIPT_KEYS
    )
    assert launcher.EXEC_ENV == freezer.EXEC_ENV == seal.DETACHED_EXEC_ENV
    assert seal.DETACHED_EXEC_ENV["PYTHONNOUSERSITE"] == "1"
    child_argv = freezer._expected_child_argv(
        source=Path("/tmp/freezer.py"),
        expectation=Path("/tmp/expectation.json"),
        output=Path("/tmp/inventory.json"),
        ancestors_json="[]",
    )
    assert child_argv[:3] == [seal.EXPECTED_PYTHON_PATH, "-I", "/tmp/freezer.py"]

    proc = tmp_path / "proc"
    proc.mkdir()
    _write_stat_only(proc, pid=300, ppid=100, start_ticks=30, comm="python3.10")
    _write_stat_only(proc, pid=100, ppid=1, start_ticks=10, comm="sshd-service")
    parent = {
        "comm_sha256": _sha(b"python3.10"),
        "pid": 300,
        "start_ticks": 30,
    }
    expected = [parent]
    monkeypatch.setattr(launcher, "_self_ancestor_record", lambda: parent)
    monkeypatch.setattr(freezer, "_self_ancestor_record", lambda: parent)
    assert launcher._detached_parent_records() == expected
    assert freezer._detached_parent_records() == expected

    extra = {"comm_sha256": _sha(b"sshd"), "pid": 200, "start_ticks": 20}
    with pytest.raises(launcher.DetachedLaunchError, match="exactly one"):
        launcher._assert_startup_ancestors_gone([parent, extra], proc_root=proc)
    with pytest.raises(freezer.FreezerError, match="exactly one"):
        freezer._assert_startup_ancestors_gone([parent, extra], proc_root=proc)
    with pytest.raises(freezer.FreezerError, match="ancestor payload"):
        freezer._decode_ancestors(seal.canonical_bytes([parent, extra]).decode())
    with pytest.raises(seal.ExecutionSealV2Error, match="exactly one"):
        seal._validate_ancestor_records([parent, extra], label="test parent")
    with pytest.raises(att.AttestationV2Error, match="exactly one"):
        att._assert_ancestors_gone([parent, extra], proc_root=proc)

    # comm is audit metadata, not process identity.  The same PID/start may
    # rename itself through exec/prctl and must still fail every gone check.
    _write_stat_only(proc, pid=300, ppid=200, start_ticks=30, comm="renamed")
    with pytest.raises(launcher.DetachedLaunchError, match="still live"):
        launcher._assert_startup_ancestors_gone(expected, proc_root=proc)
    with pytest.raises(freezer.FreezerError, match="remains live"):
        freezer._assert_startup_ancestors_gone(expected, proc_root=proc)
    with pytest.raises(seal.ExecutionSealV2Error, match="remains live"):
        seal._assert_ancestor_records_gone(expected, proc_root=proc)
    with pytest.raises(att.AttestationV2Error, match="remains live"):
        att._assert_ancestors_gone(expected, proc_root=proc)

    (proc / "300/stat").unlink()
    (proc / "300").rmdir()
    launcher._assert_startup_ancestors_gone(expected, proc_root=proc)
    freezer._assert_startup_ancestors_gone(expected, proc_root=proc)
    assert (proc / "100/stat").exists(), "persistent service ancestry stays excluded"


def test_freezer_pid_start_identity_must_be_gone_before_plan(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    _write_stat_only(proc, pid=900001, ppid=1, start_ticks=2000, comm="python3.10")
    with pytest.raises(seal.ExecutionSealV2Error, match="freezer process remains live"):
        seal._assert_process_start_gone(
            pid=900001,
            start_ticks=2000,
            label="exception freezer",
            proc_root=proc,
        )
    seal._assert_process_start_gone(
        pid=900001,
        start_ticks=2001,
        label="exception freezer",
        proc_root=proc,
    )


def test_inventory_validation_invokes_freezer_process_gone_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expectation = tmp_path / "expectation.json"
    inventory = _exception_inventory(
        [], expectation_path=expectation, expectation_sha="c" * 64
    )

    def live(**_: Any) -> None:
        raise seal.ExecutionSealV2Error("exception freezer process remains live")

    monkeypatch.setattr(seal, "_assert_process_start_gone", live)
    with pytest.raises(seal.ExecutionSealV2Error, match="freezer process remains live"):
        seal.validate_exception_inventory(
            inventory,
            launch_expectation_path=expectation,
            launch_expectation_sha256="c" * 64,
            wrapper_pid=9999,
            wrapper_start_ticks=1000,
        )


def _detached_receipt_fixture(
    tmp_path: Path,
) -> tuple[dict[str, Any], bytes, Path, dict[str, Any]]:
    durable = tmp_path / "attempt-002"
    control = durable / "control"
    control.mkdir(parents=True)
    plan_path = control / seal.PLAN_FILENAME
    receipt_path = control / seal.DETACHED_RECEIPT_FILENAME
    argv = [seal.EXPECTED_PYTHON_PATH, "/tmp/attester.py", "--fixed"]
    binding = {"path": "/tmp/bound", "sha256": "a" * 64}
    plan = {
        "detached_launch_contract": copy.deepcopy(binding),
        "detached_transport": {
            "handoff": copy.deepcopy(binding),
            "launcher": copy.deepcopy(binding),
            "receipt_path": receipt_path.as_posix(),
        },
        "durable_attempt_root": durable.as_posix(),
        "invocations": {"attester": {"argv": argv}},
    }
    plan_raw = seal.canonical_bytes(plan)
    ancestor = {"comm_sha256": "c" * 64, "pid": 800001, "start_ticks": 100}
    receipt = {
        "clock_ticks_per_second": 100,
        "cwd": "/tmp",
        "detached_launch_contract": copy.deepcopy(binding),
        "exec_argv_sha256": seal.canonical_sha256(argv),
        "exec_env_sha256": seal.canonical_sha256(seal.DETACHED_EXEC_ENV),
        "handoff": copy.deepcopy(binding),
        "launcher": copy.deepcopy(binding),
        "minimum_delay_seconds": 30,
        "no_pts_fds": True,
        "observed_age_ticks": 3000,
        "outcome_blind": True,
        "pid": 777,
        "plan": {"path": plan_path.as_posix(), "sha256": _sha(plan_raw)},
        "ppid": 1,
        "process_group_id": 777,
        "process_start_ticks": 200,
        "protocol": "cohort_causal_terminal_verifier_v2_detached_receipt_v1",
        "runtime_namespace": _namespace(),
        "schema_version": 1,
        "session_id": 777,
        "startup_ancestors": [ancestor],
        "startup_ancestors_sha256": seal.canonical_sha256([ancestor]),
        "status": "ready_to_exec_exact_attester",
        "stdio_targets_sha256": seal.canonical_sha256(
            ["/dev/null", "/dev/null", "/dev/null"]
        ),
        "tty_nr": 0,
    }
    receipt_path.write_bytes(seal.canonical_bytes(receipt))
    return plan, plan_raw, receipt_path, receipt


def _validate_receipt_fixture(
    *, plan: dict[str, Any], plan_raw: bytes, receipt_path: Path, **overrides: Any
) -> dict[str, Any]:
    argv = plan["invocations"]["attester"]["argv"]
    kwargs: dict[str, Any] = {
        "path": receipt_path,
        "plan": plan,
        "plan_raw": plan_raw,
        "expected_runtime_namespace": _namespace(),
        "proc_identity_fn": lambda: (777, 1, 200, 0, 100, 3000),
        "getppid_fn": lambda: 1,
        "getcwd_fn": lambda: "/tmp",
        "getsid_fn": lambda _: 777,
        "getpgrp_fn": lambda: 777,
        "runtime_namespace_fn": _namespace,
        "environ_fn": lambda: dict(seal.DETACHED_EXEC_ENV),
        "cmdline_fn": lambda: b"\0".join(item.encode() for item in argv) + b"\0",
        "stdio_fn": lambda: (["/dev/null", "/dev/null", "/dev/null"], True),
        "ancestors_gone_fn": lambda _: None,
    }
    kwargs.update(overrides)
    return att._validate_detached_receipt(**kwargs)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("ppid", 2),
        ("cwd", "/"),
        ("tty_nr", 1),
        ("no_pts_fds", False),
        ("exec_env_sha256", "0" * 64),
        ("startup_ancestors_sha256", "0" * 64),
        ("unexpected", "field"),
    ],
)
def test_detached_receipt_mutations_fail_closed(
    tmp_path: Path, field: str, replacement: Any
) -> None:
    plan, plan_raw, receipt_path, receipt = _detached_receipt_fixture(tmp_path)
    _validate_receipt_fixture(plan=plan, plan_raw=plan_raw, receipt_path=receipt_path)
    mutated = copy.deepcopy(receipt)
    mutated[field] = replacement
    receipt_path.write_bytes(seal.canonical_bytes(mutated))
    with pytest.raises(att.AttestationV2Error):
        _validate_receipt_fixture(
            plan=plan, plan_raw=plan_raw, receipt_path=receipt_path
        )


@pytest.mark.parametrize(
    "identity",
    [
        (778, 1, 200, 0, 100, 3000),
        (777, 1, 201, 0, 100, 3000),
        (777, 2, 200, 0, 100, 3000),
        (777, 1, 200, 1, 100, 3000),
        (777, 1, 200, 0, 100, 2999),
    ],
)
def test_detached_exec_live_identity_mutations_fail_closed(
    tmp_path: Path, identity: tuple[int, int, int, int, int, int]
) -> None:
    plan, plan_raw, receipt_path, _ = _detached_receipt_fixture(tmp_path)
    with pytest.raises(att.AttestationV2Error):
        _validate_receipt_fixture(
            plan=plan,
            plan_raw=plan_raw,
            receipt_path=receipt_path,
            proc_identity_fn=lambda: identity,
        )


def test_detached_receipt_namespace_and_live_ancestor_fail_closed(
    tmp_path: Path,
) -> None:
    plan, plan_raw, receipt_path, receipt = _detached_receipt_fixture(tmp_path)
    mutated = copy.deepcopy(receipt)
    mutated["runtime_namespace"]["pid_namespace_inode"] += 1
    receipt_path.write_bytes(seal.canonical_bytes(mutated))
    with pytest.raises(att.AttestationV2Error):
        _validate_receipt_fixture(
            plan=plan, plan_raw=plan_raw, receipt_path=receipt_path
        )

    mutated = copy.deepcopy(receipt)
    mutated["runtime_namespace"]["proc1_cgroup_sha256"] = "0" * 64
    receipt_path.write_bytes(seal.canonical_bytes(mutated))
    with pytest.raises(att.AttestationV2Error):
        _validate_receipt_fixture(
            plan=plan, plan_raw=plan_raw, receipt_path=receipt_path
        )

    receipt_path.write_bytes(seal.canonical_bytes(receipt))

    def still_live(_: list[dict[str, Any]]) -> None:
        raise att.AttestationV2Error("startup ancestor remains live")

    with pytest.raises(att.AttestationV2Error):
        _validate_receipt_fixture(
            plan=plan,
            plan_raw=plan_raw,
            receipt_path=receipt_path,
            ancestors_gone_fn=still_live,
        )


def test_freezer_generates_boottime_bound_canonical_inventory(tmp_path: Path) -> None:
    fixture = _load_v1_fixture_module()._terminal_fixture(tmp_path / "fixture")
    expectation_path = fixture["expectation"]
    expectation = json.loads(expectation_path.read_text())
    source = _freezer_copy(tmp_path / "source")
    output = expectation_path.parent / seal.EXCEPTION_INVENTORY_FILENAME
    proof = _freezer_proof(
        source=source,
        expectation_path=expectation_path,
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
    )
    source_raw_at_entry = source.read_bytes()
    source.write_bytes(source_raw_at_entry + b"\n# post-entry mutation")
    with pytest.raises(freezer.FreezerError, match="drifted after child entry"):
        freezer.freeze(
            launch_expectation_path=expectation_path,
            output=output,
            transport_proof=proof,
            source_path=source,
            source_raw_at_entry=source_raw_at_entry,
            require_tmp_boundary=False,
        )
    source.write_bytes(source_raw_at_entry)
    times = iter(
        [
            "2026-07-14T12:00:01Z",
            "2026-07-14T12:00:02Z",
            "2026-07-14T12:00:03Z",
        ]
    )
    boottimes = iter([1_000_000_000, 2_000_000_000])
    anchor = _record(
        pid=380,
        ppid=313,
        cmdline=b"monitor-connect\0",
        start_ticks=expectation["wrapper_start_ticks"] - 1,
        comm="monitor-connect",
        uid=0,
        gid=0,
    )
    leaf_cmdline = b"sleep\00.5\0"
    policy = _policy(anchor, leaf_cmdline)
    dynamic_pids = iter([500, 501])

    def scan(**kwargs: Any):
        observed_policy = (
            policy
            if kwargs["frozen_dynamic_policy"] is None
            else kwargs["frozen_dynamic_policy"]
        )
        return (
            [anchor],
            [
                _dynamic_record(
                    pid=next(dynamic_pids),
                    anchor=anchor,
                    leaf_cmdline=leaf_cmdline,
                    start_ticks=expectation["wrapper_start_ticks"] + 1,
                )
            ],
            observed_policy,
        )

    freezer.freeze(
        launch_expectation_path=expectation_path,
        output=output,
        transport_proof=proof,
        source_path=source,
        source_raw_at_entry=source_raw_at_entry,
        require_tmp_boundary=False,
        now_fn=lambda: next(times),
        boottime_ns_fn=lambda: next(boottimes),
        sleep_fn=lambda _: None,
        namespace_fn=lambda _: _namespace(),
        scan_fn=scan,
    )
    raw = output.read_bytes()
    value = json.loads(raw)
    assert raw == seal.canonical_bytes(value)
    assert (
        value["snapshots"][1]["captured_boottime_ns"]
        - value["snapshots"][0]["captured_boottime_ns"]
        == 1_000_000_000
    )
    seal.validate_exception_inventory(
        value,
        launch_expectation_path=expectation_path,
        launch_expectation_sha256=_sha(expectation_path.read_bytes()),
        wrapper_pid=expectation["wrapper_pid"],
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
    )
    with pytest.raises(FileExistsError):
        freezer._publish(output, b"{}")


def test_freezer_bounded_discovery_is_not_a_registered_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _load_v1_fixture_module()._terminal_fixture(tmp_path / "fixture")
    expectation_path = fixture["expectation"]
    expectation = json.loads(expectation_path.read_text())
    source = _freezer_copy(tmp_path / "source")
    output = expectation_path.parent / seal.EXCEPTION_INVENTORY_FILENAME
    proof = _freezer_proof(
        source=source,
        expectation_path=expectation_path,
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
    )
    anchor = _record(
        pid=380,
        ppid=313,
        cmdline=b"monitor-connect\0",
        start_ticks=expectation["wrapper_start_ticks"] - 1,
        comm="monitor-connect",
        uid=0,
        gid=0,
    )
    leaf_cmdline = b"sleep\00.5\0"
    policy = _policy(anchor, leaf_cmdline)
    sleep_observation = _dynamic_record(
        pid=500,
        anchor=anchor,
        leaf_cmdline=leaf_cmdline,
        start_ticks=expectation["wrapper_start_ticks"] + 1,
    )
    clone_observation = {
        **_dynamic_record(
            pid=501,
            anchor=anchor,
            leaf_cmdline=leaf_cmdline,
            start_ticks=expectation["wrapper_start_ticks"] + 2,
        ),
        "cmdline_sha256": anchor["cmdline_sha256"],
        "cmdline_size_bytes": anchor["cmdline_size_bytes"],
        "comm": "monitor-connect",
    }
    states = iter(["transition", "sleep", "clone"])

    def scan(**kwargs: Any):
        state = next(states)
        if state == "transition":
            raise freezer.DynamicPolicyDiscoveryPending(
                [anchor], freezer._anchor_binding(anchor)
            )
        if state == "sleep":
            assert kwargs["frozen_dynamic_policy"] is None
            return [anchor], [sleep_observation], policy
        assert kwargs["frozen_dynamic_policy"] == policy
        return [anchor], [clone_observation], policy

    sleeps: list[float] = []
    freezer.freeze(
        launch_expectation_path=expectation_path,
        output=output,
        transport_proof=proof,
        source_path=source,
        source_raw_at_entry=source.read_bytes(),
        require_tmp_boundary=False,
        now_fn=iter(
            [
                "2026-07-14T12:00:01Z",
                "2026-07-14T12:00:02Z",
                "2026-07-14T12:00:03Z",
            ]
        ).__next__,
        boottime_ns_fn=iter([1_000_000_000, 2_000_000_000]).__next__,
        sleep_fn=sleeps.append,
        namespace_fn=lambda _: _namespace(),
        scan_fn=scan,
    )
    inventory = json.loads(output.read_text())
    assert sleeps == [
        freezer.DYNAMIC_POLICY_DISCOVERY_INTERVAL_SECONDS,
        freezer.SNAPSHOT_INTERVAL_SECONDS,
    ]
    assert len(inventory["snapshots"]) == 2
    assert inventory["snapshots"][0]["dynamic_observations"][0]["comm"] == "sleep"
    assert (
        inventory["snapshots"][1]["dynamic_observations"][0]["comm"]
        == "monitor-connect"
    )
    seal.validate_exception_inventory(
        inventory,
        launch_expectation_path=expectation_path,
        launch_expectation_sha256=_sha(expectation_path.read_bytes()),
        wrapper_pid=expectation["wrapper_pid"],
        wrapper_start_ticks=expectation["wrapper_start_ticks"],
    )

    exhausted_fixture = _load_v1_fixture_module()._terminal_fixture(
        tmp_path / "exhausted"
    )
    exhausted_expectation = exhausted_fixture["expectation"]
    exhausted_value = json.loads(exhausted_expectation.read_text())
    exhausted_source = _freezer_copy(tmp_path / "exhausted-source")
    exhausted_output = exhausted_expectation.parent / seal.EXCEPTION_INVENTORY_FILENAME
    monkeypatch.setattr(freezer, "DYNAMIC_POLICY_DISCOVERY_MAX_ATTEMPTS", 2)
    with pytest.raises(freezer.FreezerError, match="exhausted"):
        freezer.freeze(
            launch_expectation_path=exhausted_expectation,
            output=exhausted_output,
            transport_proof=_freezer_proof(
                source=exhausted_source,
                expectation_path=exhausted_expectation,
                wrapper_start_ticks=exhausted_value["wrapper_start_ticks"],
            ),
            source_path=exhausted_source,
            source_raw_at_entry=exhausted_source.read_bytes(),
            require_tmp_boundary=False,
            sleep_fn=lambda _: None,
            namespace_fn=lambda _: _namespace(),
            scan_fn=lambda **_: (_ for _ in ()).throw(
                freezer.DynamicPolicyDiscoveryPending(
                    [anchor], freezer._anchor_binding(anchor)
                )
            ),
        )
    assert not exhausted_output.exists()

    switch_fixture = _load_v1_fixture_module()._terminal_fixture(
        tmp_path / "anchor-switch"
    )
    switch_expectation = switch_fixture["expectation"]
    switch_value = json.loads(switch_expectation.read_text())
    switch_source = _freezer_copy(tmp_path / "anchor-switch-source")
    switch_output = switch_expectation.parent / seal.EXCEPTION_INVENTORY_FILENAME
    anchor_b = _record(
        pid=381,
        ppid=313,
        cmdline=b"other-monitor-connect\0",
        start_ticks=switch_value["wrapper_start_ticks"] - 2,
        comm="monitor-connect",
        uid=0,
        gid=0,
    )
    switch_static = sorted([anchor, anchor_b], key=lambda record: record["pid"])
    policy_b = _policy(anchor_b, leaf_cmdline)
    sleep_b = _dynamic_record(
        pid=600,
        anchor=anchor_b,
        leaf_cmdline=leaf_cmdline,
        start_ticks=switch_value["wrapper_start_ticks"] + 1,
    )
    switch_states = iter(["transition-a", "sleep-b"])

    def switched_scan(**_: Any):
        if next(switch_states) == "transition-a":
            raise freezer.DynamicPolicyDiscoveryPending(
                switch_static, freezer._anchor_binding(anchor)
            )
        return switch_static, [sleep_b], policy_b

    with pytest.raises(freezer.FreezerError, match="exact anchor drifted"):
        freezer.freeze(
            launch_expectation_path=switch_expectation,
            output=switch_output,
            transport_proof=_freezer_proof(
                source=switch_source,
                expectation_path=switch_expectation,
                wrapper_start_ticks=switch_value["wrapper_start_ticks"],
            ),
            source_path=switch_source,
            source_raw_at_entry=switch_source.read_bytes(),
            require_tmp_boundary=False,
            sleep_fn=lambda _: None,
            namespace_fn=lambda _: _namespace(),
            scan_fn=switched_scan,
        )
    assert not switch_output.exists()


def _revalidator_cli_args() -> list[str]:
    return [
        "revalidator-v2",
        "--execution-plan",
        "/p",
        "--root",
        "/r",
        "--attestation",
        "/a",
        "--launch-expectation",
        "/e",
        "--grid",
        "/g",
        "--provenance",
        "/v",
        "--formal-manifest",
        "/m",
        "--formal-decision",
        "/d",
        "--preregistration",
        "/pr",
        "--statistical-addendum",
        "/sa",
        "--output",
        "/o",
        "--receipt",
        "/rr",
    ]


def _seal_cli_args() -> list[str]:
    return [
        "seal-v2",
        "--execution-plan",
        "/p",
        "--attestation",
        "/a",
        "--launch-expectation",
        "/e",
        "--causal-original",
        "/co",
        "--causal-revalidated",
        "/cr",
        "--revalidation-receipt",
        "/rr",
        "--structured-preregistration",
        "/sp",
        "--output",
        "/o",
    ]


def test_revalidator_and_seal_cli_are_branch_nonleaking(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    branch_tokens = ("decision", "decision_scope", "trigger a", "pass")

    monkeypatch.setattr(sys, "argv", _revalidator_cli_args())
    monkeypatch.setattr(
        revalidator,
        "revalidate_terminal",
        lambda **_: {"decision": "pass", "decision_scope": "Trigger A"},
    )
    revalidator.main()
    captured = capsys.readouterr()
    assert captured.out == '{"status": "complete"}\n' and captured.err == ""
    assert all(
        token not in (captured.out + captured.err).lower() for token in branch_tokens
    )

    monkeypatch.setattr(
        revalidator,
        "revalidate_terminal",
        lambda **_: (_ for _ in ()).throw(
            revalidator.v1.RevalidationError("decision_scope Trigger A pass")
        ),
    )
    with pytest.raises(SystemExit) as revalidation_exit:
        revalidator.main()
    assert revalidation_exit.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""

    monkeypatch.setattr(sys, "argv", _seal_cli_args())
    monkeypatch.setattr(
        seal,
        "build_and_publish_execution_seal",
        lambda **_: {"decision": "no-go", "decision_scope": "Trigger A"},
    )
    seal.main()
    captured = capsys.readouterr()
    assert captured.out == '{"status": "complete"}\n' and captured.err == ""
    assert all(
        token not in (captured.out + captured.err).lower() for token in branch_tokens
    )

    monkeypatch.setattr(
        seal,
        "build_and_publish_execution_seal",
        lambda **_: (_ for _ in ()).throw(
            seal.v1.ExecutionSealError("Trigger A requires pass decision_scope")
        ),
    )
    with pytest.raises(SystemExit) as seal_exit:
        seal.main()
    assert seal_exit.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
