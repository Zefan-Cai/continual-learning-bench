from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path

import pytest

import attest_cohort_causal_completion as v1
import build_cohort_structured_state_execution_seal_v2 as seal_v2
import freeze_cohort_causal_terminal_recovery_v3 as recovery


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _runtime_namespace() -> dict:
    return {
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "mount_namespace_inode": 10,
        "pid_namespace_inode": 11,
        "proc1_cgroup_sha256": SHA_A,
        "proc1_comm_sha256": SHA_B,
        "proc1_start_ticks": 1,
        "proc_mountinfo_sha256": SHA_C,
        "proc_root_device": 12,
        "proc_root_inode": 13,
        "proc_self_consistent": True,
        "proc_super_magic": 0x9FA0,
    }


def _file(path: Path, *, mtime_ns: int, digest: str = SHA_A) -> dict:
    return {
        "mtime_ns": mtime_ns,
        "path": path.as_posix(),
        "sha256": digest,
        "size_bytes": 2,
    }


def _bindings(durable: Path) -> dict:
    return {
        "launch_expectation": {
            "path": (
                durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME
            ).as_posix(),
            "sha256": SHA_A,
        },
        "v2_execution_plan": {
            "path": (durable / "control" / seal_v2.PLAN_FILENAME).as_posix(),
            "sha256": SHA_B,
        },
        "v2_procfs_exception_inventory": {
            "dynamic_policy_sha256": SHA_D,
            "inventory_sha256": SHA_A,
            "path": (
                durable / "control" / seal_v2.EXCEPTION_INVENTORY_FILENAME
            ).as_posix(),
            "sha256": SHA_C,
            "static_record_count": 1,
            "static_records_sha256": SHA_B,
        },
        "v2_detached_launch_receipt": {
            "path": (
                durable / "control" / seal_v2.DETACHED_RECEIPT_FILENAME
            ).as_posix(),
            "pid": 303,
            "process_identity_status": "gone",
            "process_start_ticks": 300,
            "sha256": SHA_D,
        },
    }


def _incident(durable: Path) -> dict:
    return {
        "classification": recovery.INCIDENT_CLASSIFICATION,
        "completion_method": recovery.COMPLETION_METHOD,
        "decision_exit_exact_mtime_tie": True,
        "decision_exit_integer_second_boundary": True,
        "decision_manifest_semantics_opened": False,
        "decision_mtime_ns": 2_000_000_000,
        "exit_canonical_zero": True,
        "exit_mtime_ns": 2_000_000_000,
        "formal_decision": _file(
            durable / "artifacts" / "cohort_causal" / "formal_decision.json",
            mtime_ns=2_000_000_000,
            digest=SHA_B,
        ),
        "formal_manifest": _file(
            durable / "artifacts" / "cohort_causal" / "formal_manifest.json",
            mtime_ns=1_000_000_000,
            digest=SHA_A,
        ),
        "historical_exit_order_claimed": False,
        "legacy_strict_mtime_proof": False,
        "manifest_before_decision": True,
        "manifest_mtime_ns": 1_000_000_000,
        "mtime_relation": recovery.MTIME_RELATION,
    }


def _wrapper(durable: Path) -> dict:
    return {
        "exit_file": _file(
            durable / "prep" / "causal_formal.exit", mtime_ns=2_000_000_000
        ),
        "pid": 202,
        "pid_file": _file(durable / "prep" / "causal_formal.pid", mtime_ns=500_000_000),
        "process_identity_status": "gone",
        "start_ticks": 200,
    }


def _closure(durable: Path, source: Path) -> dict:
    bindings = _bindings(durable)
    return {
        "authorized_completion_fence": {
            "maximum_successful_publications": 1,
            "path": (
                durable / "control" / recovery.COMPLETION_FENCE_FILENAME
            ).as_posix(),
            "protocol": recovery.COMPLETION_FENCE_PROTOCOL,
            "publication_mode": recovery.PUBLICATION_MODE,
            "schema_version": recovery.COMPLETION_FENCE_SCHEMA_VERSION,
        },
        "closed_at_utc": "2026-07-14T18:00:00.000000Z",
        "incident": _incident(durable),
        "launch_expectation": bindings["launch_expectation"],
        "outcome_blind": True,
        "protocol": recovery.FAILURE_CLOSURE_PROTOCOL,
        "recovery_freezer": {"path": source.as_posix(), "sha256": SHA_A},
        "schema_version": recovery.FAILURE_CLOSURE_SCHEMA_VERSION,
        "semantic_artifacts_opened": False,
        "status": recovery.FAILURE_CLOSURE_STATUS,
        "v2_detached_launch_receipt": bindings["v2_detached_launch_receipt"],
        "v2_downstream_absence": {
            "paths": recovery._expected_downstream_paths(durable),
            "status": "all_absent",
        },
        "v2_execution_plan": bindings["v2_execution_plan"],
        "v2_procfs_exception_inventory": bindings["v2_procfs_exception_inventory"],
        "wrapper": _wrapper(durable),
    }


def _file_record(
    path: Path,
    *,
    role: str,
    digest: str,
    inode: int,
    mtime_ns: int = 3,
    size_bytes: int = 4,
) -> dict:
    return {
        "device": 1,
        "inode": inode,
        "mtime_ns": mtime_ns,
        "path": path.as_posix(),
        "roles": [role],
        "sha256": digest,
        "size_bytes": size_bytes,
    }


def _process_audit(durable: Path) -> dict:
    payload = {
        "artifact_root_path": (durable / "artifacts" / "cohort_causal").as_posix(),
        "attempt_checkout_path": "/mnt/localssd/causal/attempt-002",
        "durable_attempt_root_path": durable.as_posix(),
        "dynamic_policy_enforced": True,
        "dynamic_policy_sha256": SHA_D,
        "exception_inventory_sha256": SHA_C,
        "method": seal_v2.PROCESS_AUDIT_METHOD,
        "observed_exception_count": 1,
        "observed_exceptions_sha256": SHA_B,
        "status": "pass",
    }
    return {**payload, "audit_sha256": recovery.canonical_sha256(payload)}


def _temporary_audit(durable: Path) -> dict:
    payload = {
        "forbidden_match_count": 0,
        "roots": sorted(
            [
                (durable / "artifacts" / "cohort_causal").as_posix(),
                (durable / "prep").as_posix(),
            ]
        ),
        "status": "pass",
    }
    return {**payload, "audit_sha256": recovery.canonical_sha256(payload)}


def _fence(durable: Path, source: Path, closure_raw: bytes) -> dict:
    bindings = _bindings(durable)
    incident = _incident(durable)
    wrapper = _wrapper(durable)
    closure_path = durable / "control" / recovery.FAILURE_CLOSURE_FILENAME
    specs = [
        (
            Path(bindings["launch_expectation"]["path"]),
            "launch_expectation",
            bindings["launch_expectation"]["sha256"],
            3,
            4,
        ),
        (
            Path(bindings["v2_execution_plan"]["path"]),
            "v2_execution_plan",
            bindings["v2_execution_plan"]["sha256"],
            3,
            4,
        ),
        (
            Path(bindings["v2_procfs_exception_inventory"]["path"]),
            "v2_procfs_exception_inventory",
            bindings["v2_procfs_exception_inventory"]["sha256"],
            3,
            4,
        ),
        (
            Path(bindings["v2_detached_launch_receipt"]["path"]),
            "v2_detached_launch_receipt",
            bindings["v2_detached_launch_receipt"]["sha256"],
            3,
            4,
        ),
        (source, "v3_recovery_freezer_source", SHA_A, 3, 4),
        (
            closure_path,
            "v2_failure_closure",
            hashlib.sha256(closure_raw).hexdigest(),
            3,
            4,
        ),
        (
            Path(wrapper["pid_file"]["path"]),
            "wrapper_pid_file",
            wrapper["pid_file"]["sha256"],
            wrapper["pid_file"]["mtime_ns"],
            wrapper["pid_file"]["size_bytes"],
        ),
        (
            Path(wrapper["exit_file"]["path"]),
            "wrapper_exit_file",
            wrapper["exit_file"]["sha256"],
            wrapper["exit_file"]["mtime_ns"],
            wrapper["exit_file"]["size_bytes"],
        ),
        (
            Path(incident["formal_manifest"]["path"]),
            "formal_manifest",
            incident["formal_manifest"]["sha256"],
            incident["formal_manifest"]["mtime_ns"],
            incident["formal_manifest"]["size_bytes"],
        ),
        (
            Path(incident["formal_decision"]["path"]),
            "formal_decision",
            incident["formal_decision"]["sha256"],
            incident["formal_decision"]["mtime_ns"],
            incident["formal_decision"]["size_bytes"],
        ),
    ]
    files = [
        _file_record(
            path,
            role=role,
            digest=digest,
            inode=index,
            mtime_ns=mtime_ns,
            size_bytes=size_bytes,
        )
        for index, (path, role, digest, mtime_ns, size_bytes) in enumerate(
            sorted(specs, key=lambda item: item[0].as_posix()), start=1
        )
    ]
    snapshots = [
        {
            "captured_at_utc": f"2026-07-14T18:00:0{index}.000000Z",
            "file_count": len(files),
            "files": copy.deepcopy(files),
            "inventory_sha256": recovery.canonical_sha256(files),
            "sequence": index,
        }
        for index in (1, 2)
    ]
    return {
        "causal_pre_attestation_inventory_sha256": recovery.canonical_sha256(files),
        "failure_closure": {
            "path": (
                durable / "control" / recovery.FAILURE_CLOSURE_FILENAME
            ).as_posix(),
            "sha256": hashlib.sha256(closure_raw).hexdigest(),
        },
        "frozen_at_utc": "2026-07-14T18:00:03.000000Z",
        "incident": incident,
        "incident_sha256": recovery.canonical_sha256(incident),
        "launch_expectation": bindings["launch_expectation"],
        "no_live_or_temporary": _temporary_audit(durable),
        "outcome_blind": True,
        "process_absence": _process_audit(durable),
        "protocol": recovery.COMPLETION_FENCE_PROTOCOL,
        "recovery_freezer": {"path": source.as_posix(), "sha256": SHA_A},
        "runtime_namespace": _runtime_namespace(),
        "schema_version": recovery.COMPLETION_FENCE_SCHEMA_VERSION,
        "semantic_artifacts_opened": False,
        "snapshots": snapshots,
        "stability": {
            "boottime_interval_ns": 1_000_000_000,
            "minimum_interval_seconds": 1.0,
            "observed_interval_seconds": 1.0,
            "process_audits_identical": True,
            "runtime_namespace_identical": True,
            "snapshots_identical": True,
            "temporary_audits_identical": True,
        },
        "status": recovery.COMPLETION_FENCE_STATUS,
        "v2_detached_launch_receipt": bindings["v2_detached_launch_receipt"],
        "v2_downstream_absence": {
            "paths": recovery._expected_downstream_paths(durable),
            "status": "all_absent",
        },
        "v2_execution_plan": bindings["v2_execution_plan"],
        "v2_procfs_exception_inventory": bindings["v2_procfs_exception_inventory"],
        "wrapper": wrapper,
    }


@pytest.fixture
def recovery_documents(tmp_path: Path):
    durable = tmp_path / "durable" / "attempt-002"
    (durable / "control").mkdir(parents=True)
    (durable / "prep").mkdir()
    (durable / "artifacts" / "cohort_causal").mkdir(parents=True)
    source = tmp_path / "freeze.py"
    source.write_text("source")
    closure_path = durable / "control" / recovery.FAILURE_CLOSURE_FILENAME
    fence_path = durable / "control" / recovery.COMPLETION_FENCE_FILENAME
    closure = _closure(durable, source)
    closure_raw = recovery.canonical_bytes(closure)
    fence = _fence(durable, source, closure_raw)
    return durable, source, closure_path, fence_path, closure, closure_raw, fence


def test_valid_failure_closure_is_exact_and_outcome_blind(recovery_documents):
    durable, _, closure_path, _, closure, _, _ = recovery_documents
    assert (
        recovery.validate_failure_closure_document(
            closure, durable_attempt_root=durable, expected_path=closure_path
        )
        == closure
    )
    assert closure["outcome_blind"] is True
    assert closure["semantic_artifacts_opened"] is False
    assert closure["incident"]["legacy_strict_mtime_proof"] is False
    assert closure["incident"]["historical_exit_order_claimed"] is False


@pytest.mark.parametrize(
    ("decision", "exit_mtime"),
    [
        (2_000_000_000, 2_000_000_001),
        (2_000_000_001, 2_000_000_001),
        (2_000_000_001, 2_000_000_000),
        (2_000_000_000, 3_000_000_000),
    ],
)
def test_closure_rejects_every_nonexact_tie(
    recovery_documents, decision: int, exit_mtime: int
):
    durable, _, closure_path, _, closure, _, _ = recovery_documents
    closure["incident"]["decision_mtime_ns"] = decision
    closure["incident"]["exit_mtime_ns"] = exit_mtime
    closure["wrapper"]["exit_file"]["mtime_ns"] = exit_mtime
    with pytest.raises(recovery.RecoveryV3Error, match="equal-second"):
        recovery.validate_failure_closure_document(
            closure, durable_attempt_root=durable, expected_path=closure_path
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("legacy_strict_mtime_proof", True),
        ("historical_exit_order_claimed", True),
        ("decision_manifest_semantics_opened", True),
        ("completion_method", "mtime heuristic"),
        ("mtime_relation", "exit_after_decision"),
        ("exit_canonical_zero", False),
    ],
)
def test_closure_rejects_untruthful_incident_semantics(
    recovery_documents, field: str, value
):
    durable, _, closure_path, _, closure, _, _ = recovery_documents
    closure["incident"][field] = value
    with pytest.raises(recovery.RecoveryV3Error, match="equal-second"):
        recovery.validate_failure_closure_document(
            closure, durable_attempt_root=durable, expected_path=closure_path
        )


def test_closure_requires_receipt_and_wrapper_processes_gone(recovery_documents):
    durable, _, closure_path, _, closure, _, _ = recovery_documents
    closure["v2_detached_launch_receipt"]["process_identity_status"] = "unknown"
    with pytest.raises(recovery.RecoveryV3Error, match="receipt process"):
        recovery.validate_failure_closure_document(
            closure, durable_attempt_root=durable, expected_path=closure_path
        )
    closure = _closure(durable, Path(closure["recovery_freezer"]["path"]))
    closure["wrapper"]["process_identity_status"] = "live"
    with pytest.raises(recovery.RecoveryV3Error, match="wrapper process"):
        recovery.validate_failure_closure_document(
            closure, durable_attempt_root=durable, expected_path=closure_path
        )


def test_closure_authorizes_only_one_fixed_no_overwrite_fence(recovery_documents):
    durable, _, closure_path, _, closure, _, _ = recovery_documents
    closure["authorized_completion_fence"]["maximum_successful_publications"] = 2
    with pytest.raises(recovery.RecoveryV3Error, match="authorization"):
        recovery.validate_failure_closure_document(
            closure, durable_attempt_root=durable, expected_path=closure_path
        )


def test_valid_fence_returns_normalized_document_and_inventory(recovery_documents):
    durable, _, closure_path, fence_path, _, closure_raw, fence = recovery_documents
    validated, records = recovery.validate_completion_fence_document(
        fence,
        durable_attempt_root=durable,
        expected_path=fence_path,
        failure_closure_path=closure_path,
        failure_closure_sha256=hashlib.sha256(closure_raw).hexdigest(),
    )
    assert validated == fence
    assert records == fence["snapshots"][0]["files"]
    assert records is not fence["snapshots"][0]["files"]
    assert recovery.extract_completion_fence_inventory(fence) == records


def test_fence_rejects_opaque_inventory_drift(recovery_documents):
    durable, _, closure_path, fence_path, _, closure_raw, fence = recovery_documents
    fence["snapshots"][1]["files"][0]["sha256"] = "f" * 64
    fence["snapshots"][1]["inventory_sha256"] = recovery.canonical_sha256(
        fence["snapshots"][1]["files"]
    )
    with pytest.raises(recovery.RecoveryV3Error, match="snapshots differ"):
        recovery.validate_completion_fence_document(
            fence,
            durable_attempt_root=durable,
            expected_path=fence_path,
            failure_closure_path=closure_path,
            failure_closure_sha256=hashlib.sha256(closure_raw).hexdigest(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("boottime_interval_ns", 999_999_999),
        ("observed_interval_seconds", 0.999),
        ("snapshots_identical", False),
        ("process_audits_identical", False),
        ("temporary_audits_identical", False),
        ("runtime_namespace_identical", False),
    ],
)
def test_fence_rejects_incomplete_stability_proof(
    recovery_documents, field: str, value
):
    durable, _, closure_path, fence_path, _, closure_raw, fence = recovery_documents
    fence["stability"][field] = value
    with pytest.raises(recovery.RecoveryV3Error, match="stability"):
        recovery.validate_completion_fence_document(
            fence,
            durable_attempt_root=durable,
            expected_path=fence_path,
            failure_closure_path=closure_path,
            failure_closure_sha256=hashlib.sha256(closure_raw).hexdigest(),
        )


def test_fence_rejects_process_audit_not_bound_to_dynamic_policy(
    recovery_documents,
):
    durable, _, closure_path, fence_path, _, closure_raw, fence = recovery_documents
    fence["process_absence"]["dynamic_policy_sha256"] = SHA_A
    payload = {
        key: fence["process_absence"][key]
        for key in fence["process_absence"]
        if key != "audit_sha256"
    }
    fence["process_absence"]["audit_sha256"] = recovery.canonical_sha256(payload)
    with pytest.raises(recovery.RecoveryV3Error, match="process audit"):
        recovery.validate_completion_fence_document(
            fence,
            durable_attempt_root=durable,
            expected_path=fence_path,
            failure_closure_path=closure_path,
            failure_closure_sha256=hashlib.sha256(closure_raw).hexdigest(),
        )


def test_fence_rejects_wrong_failure_closure_digest(recovery_documents):
    durable, _, closure_path, fence_path, _, _, fence = recovery_documents
    with pytest.raises(recovery.RecoveryV3Error, match="closure binding"):
        recovery.validate_completion_fence_document(
            fence,
            durable_attempt_root=durable,
            expected_path=fence_path,
            failure_closure_path=closure_path,
            failure_closure_sha256=SHA_A,
        )


def test_publish_is_link_based_no_overwrite(tmp_path: Path):
    output = tmp_path / "output.json"
    recovery._publish_no_overwrite(output, b"first")
    assert output.read_bytes() == b"first"
    with pytest.raises(FileExistsError, match="overwrite"):
        recovery._publish_no_overwrite(output, b"second")
    assert output.read_bytes() == b"first"


def _fake_context(tmp_path: Path) -> tuple[dict, Path, Path]:
    root = tmp_path / "checkout"
    durable = tmp_path / "durable" / "attempt-002"
    artifact = durable / "artifacts" / "cohort_causal"
    for directory in (root, durable / "control", durable / "prep", artifact):
        directory.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "freeze_v3.py"
    source.write_text("outcome-blind recovery source")
    expectation_raw = b"opaque expectation bytes"
    plan_raw = b"opaque V2 plan bytes"
    inventory_raw = b"opaque V2 inventory bytes"
    receipt_raw = b"opaque V2 receipt bytes"
    expectation_path = durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME
    plan_path = durable / "control" / seal_v2.PLAN_FILENAME
    inventory_path = durable / "control" / seal_v2.EXCEPTION_INVENTORY_FILENAME
    receipt_path = durable / "control" / seal_v2.DETACHED_RECEIPT_FILENAME
    pid_path = durable / "prep" / "causal_formal.pid"
    exit_path = durable / "prep" / "causal_formal.exit"
    manifest_path = artifact / "formal_manifest.json"
    decision_path = artifact / "formal_decision.json"
    for path, payload in (
        (expectation_path, expectation_raw),
        (plan_path, plan_raw),
        (inventory_path, inventory_raw),
        (receipt_path, receipt_raw),
        (pid_path, b"202\n"),
        (exit_path, b"0\n"),
        (manifest_path, b"opaque manifest"),
        (decision_path, b"opaque decision"),
    ):
        path.write_bytes(payload)
    os.utime(manifest_path, ns=(1_000_000_000, 1_000_000_000))
    os.utime(decision_path, ns=(2_000_000_000, 2_000_000_000))
    os.utime(exit_path, ns=(2_000_000_000, 2_000_000_000))

    def actual_file(path: Path) -> dict:
        metadata = path.stat()
        return {
            "mtime_ns": metadata.st_mtime_ns,
            "path": path.as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": metadata.st_size,
        }

    incident = _incident(durable)
    incident["formal_manifest"] = actual_file(manifest_path)
    incident["formal_decision"] = actual_file(decision_path)
    wrapper = _wrapper(durable)
    wrapper["pid_file"] = actual_file(pid_path)
    wrapper["exit_file"] = actual_file(exit_path)
    context = {
        "artifact": artifact,
        "durable": durable,
        "expectation": {
            "wrapper_pid": 202,
            "wrapper_start_ticks": 200,
        },
        "expectation_raw": expectation_raw,
        "incident": incident,
        "inventory": {
            "dynamic_policy": {"opaque": "policy"},
            "dynamic_policy_sha256": SHA_D,
            "inventory_sha256": SHA_A,
            "runtime_namespace": _runtime_namespace(),
            "static_records_sha256": SHA_B,
        },
        "inventory_path": inventory_path,
        "inventory_raw": inventory_raw,
        "plan": {},
        "plan_path": plan_path,
        "plan_raw": plan_raw,
        "receipt": {"pid": 303, "process_start_ticks": 300},
        "receipt_path": receipt_path,
        "receipt_raw": receipt_raw,
        "root": root,
        "static_records": [{"opaque": "static record"}],
        "wrapper": wrapper,
    }
    return context, source, durable


def _fake_inventory_builder(
    *, context: dict, closure_path: Path, source_path: Path, **_kwargs
):
    payload = Path(context["durable"]) / "opaque-payload.bin"
    payload.write_bytes(b"immutable")
    builder = v1._InventoryBuilder(
        permitted_roots=(Path(context["durable"]), source_path.parent)
    )
    builder.add(payload, role="opaque_payload")
    expectation_path = (
        Path(context["durable"]) / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME
    )
    for path, role in (
        (expectation_path, "launch_expectation"),
        (Path(context["plan_path"]), "v2_execution_plan"),
        (Path(context["inventory_path"]), "v2_procfs_exception_inventory"),
        (Path(context["receipt_path"]), "v2_detached_launch_receipt"),
        (Path(context["wrapper"]["pid_file"]["path"]), "wrapper_pid_file"),
        (Path(context["wrapper"]["exit_file"]["path"]), "wrapper_exit_file"),
        (
            Path(context["incident"]["formal_manifest"]["path"]),
            "formal_manifest",
        ),
        (
            Path(context["incident"]["formal_decision"]["path"]),
            "formal_decision",
        ),
    ):
        builder.add(path, role=role)
    builder.add(closure_path, role="v2_failure_closure")
    builder.add(source_path, role="v3_recovery_freezer_source")
    return builder


def test_fence_rechecks_pid_start_identities_and_rejects_resurrection(
    tmp_path: Path,
):
    context, source, durable = _fake_context(tmp_path)
    closure_path = durable / "control" / recovery.FAILURE_CLOSURE_FILENAME
    fence_path = durable / "control" / recovery.COMPLETION_FENCE_FILENAME
    recovery.build_and_publish_failure_closure(
        root=Path(context["root"]),
        launch_expectation_path=durable
        / "control"
        / seal_v2.LAUNCH_EXPECTATION_FILENAME,
        v2_execution_plan_path=Path(context["plan_path"]),
        v2_procfs_exception_inventory_path=Path(context["inventory_path"]),
        v2_detached_launch_receipt_path=Path(context["receipt_path"]),
        output=closure_path,
        completion_fence_path=fence_path,
        source_path=source,
        context_loader_fn=lambda **_kwargs: context,
        now_fn=lambda: "2026-07-14T18:00:00.000000Z",
    )
    process = _process_audit(durable)
    process["attempt_checkout_path"] = Path(context["root"]).as_posix()
    process["exception_inventory_sha256"] = hashlib.sha256(
        context["inventory_raw"]
    ).hexdigest()
    payload = {key: process[key] for key in process if key != "audit_sha256"}
    process["audit_sha256"] = recovery.canonical_sha256(payload)
    calls: list[tuple[int, int]] = []

    def resurrect_after_first_snapshot(pid: int, start_ticks: int) -> None:
        calls.append((pid, start_ticks))
        if len(calls) == 3:
            raise recovery.RecoveryV3Error("injected PID/start resurrection")

    monotonic = iter((0.0, 1.1))
    boottime = iter((1_000_000_000, 2_100_000_000))
    now_values = iter(
        (
            "2026-07-14T18:00:01.000000Z",
            "2026-07-14T18:00:02.000000Z",
            "2026-07-14T18:00:03.000000Z",
        )
    )
    with pytest.raises(recovery.RecoveryV3Error, match="resurrection"):
        recovery.build_and_publish_completion_fence(
            root=Path(context["root"]),
            launch_expectation_path=durable
            / "control"
            / seal_v2.LAUNCH_EXPECTATION_FILENAME,
            v2_execution_plan_path=Path(context["plan_path"]),
            v2_procfs_exception_inventory_path=Path(context["inventory_path"]),
            v2_detached_launch_receipt_path=Path(context["receipt_path"]),
            provenance_path=durable / "opaque-provenance.json",
            provenance_details_path=durable / "opaque-provenance.details.json",
            failure_closure_path=closure_path,
            output=fence_path,
            source_path=source,
            stability_seconds=1.0,
            sleep_fn=lambda _seconds: None,
            monotonic_fn=lambda: next(monotonic),
            boottime_ns_fn=lambda: next(boottime),
            now_fn=lambda: "2026-07-14T18:00:01.000000Z",
            context_loader_fn=lambda **_kwargs: context,
            inventory_builder_fn=_fake_inventory_builder,
            process_audit_fn=lambda **_kwargs: copy.deepcopy(process),
            temporary_audit_fn=lambda **_kwargs: _temporary_audit(durable),
            runtime_namespace_fn=_runtime_namespace,
            process_identity_gone_fn=resurrect_after_first_snapshot,
        )
    assert calls == [(202, 200), (303, 300), (202, 200)]
    assert not fence_path.exists()

    monotonic = iter((0.0, 1.1))
    boottime = iter((1_000_000_000, 2_100_000_000))
    result = recovery.build_and_publish_completion_fence(
        root=Path(context["root"]),
        launch_expectation_path=durable
        / "control"
        / seal_v2.LAUNCH_EXPECTATION_FILENAME,
        v2_execution_plan_path=Path(context["plan_path"]),
        v2_procfs_exception_inventory_path=Path(context["inventory_path"]),
        v2_detached_launch_receipt_path=Path(context["receipt_path"]),
        provenance_path=durable / "opaque-provenance.json",
        provenance_details_path=durable / "opaque-provenance.details.json",
        failure_closure_path=closure_path,
        output=fence_path,
        source_path=source,
        stability_seconds=1.0,
        sleep_fn=lambda _seconds: None,
        monotonic_fn=lambda: next(monotonic),
        boottime_ns_fn=lambda: next(boottime),
        now_fn=lambda: next(now_values),
        context_loader_fn=lambda **_kwargs: context,
        inventory_builder_fn=_fake_inventory_builder,
        process_audit_fn=lambda **_kwargs: copy.deepcopy(process),
        temporary_audit_fn=lambda **_kwargs: _temporary_audit(durable),
        runtime_namespace_fn=_runtime_namespace,
        process_identity_gone_fn=lambda _pid, _start_ticks: None,
    )
    assert result["status"] == recovery.COMPLETION_FENCE_STATUS
    assert fence_path.exists()
    fence = seal_v2._strict_json_bytes(fence_path.read_bytes(), "test fence")
    closure_sha = hashlib.sha256(closure_path.read_bytes()).hexdigest()
    validated, records = recovery.validate_completion_fence_document(
        fence,
        durable_attempt_root=durable,
        expected_path=fence_path,
        failure_closure_path=closure_path,
        failure_closure_sha256=closure_sha,
    )
    assert validated == fence
    assert len(records) == 11


def test_absence_check_rejects_symlinked_prep(tmp_path: Path):
    durable = tmp_path / "attempt-002"
    durable.mkdir()
    target = tmp_path / "real-prep"
    target.mkdir()
    (durable / "prep").symlink_to(target, target_is_directory=True)
    paths = [durable / "prep" / name for name in recovery.DOWNSTREAM_FILENAMES]
    with pytest.raises(v1.AttestationError, match="symlink"):
        recovery._assert_absent_outputs(paths, durable=durable)


def test_manifest_and_decision_are_only_named_as_opaque_records():
    source = Path(recovery.__file__).read_text()
    context_body = source.split("def _load_recovery_context", 1)[1].split(
        "def _source_binding", 1
    )[0]
    assert "manifest_record = _opaque_record" in context_body
    assert "decision_record = _opaque_record" in context_body
    assert "json.loads" not in context_body
    assert "formal_manifest.json" in context_body
    assert "formal_decision.json" in context_body


def test_context_rejects_noncanonical_exit_before_any_semantic_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Lock the exact two-byte exit requirement independently of V2 validators."""

    assert recovery.CANONICAL_ZERO_EXIT == b"0\n"
    assert (
        hashlib.sha256(recovery.CANONICAL_ZERO_EXIT).hexdigest()
        != hashlib.sha256(b"0").hexdigest()
    )
    assert recovery.MTIME_RELATION == (
        "formal_manifest_before_formal_decision_equal_wrapper_exit"
    )
    assert recovery.COMPLETION_METHOD == "post-wrapper-death two-snapshot fence"


def test_fixed_public_contract_literals():
    assert recovery.FAILURE_CLOSURE_FILENAME == (
        "CAUSAL_TERMINAL_VERIFIER_V2_FAILURE_CLOSURE_V1.json"
    )
    assert recovery.COMPLETION_FENCE_FILENAME == (
        "CAUSAL_TERMINAL_VERIFIER_COMPLETION_FENCE_V3.json"
    )
    assert recovery.FAILURE_CLOSURE_STATUS == ("closed_equal_second_false_negative")
    assert recovery.COMPLETION_FENCE_STATUS == "frozen_terminal_quiescence"
    assert recovery.FAILURE_CLOSURE_SCHEMA_VERSION == 1
    assert recovery.COMPLETION_FENCE_SCHEMA_VERSION == 3
