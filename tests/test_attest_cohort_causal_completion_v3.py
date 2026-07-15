from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path

import pytest

import attest_cohort_causal_completion as v1
import attest_cohort_causal_completion_v3 as att
import build_cohort_causal_terminal_execution_v3 as execution
import build_cohort_structured_state_execution_seal_v2 as seal_v2
import freeze_cohort_causal_terminal_recovery_v3 as recovery


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
COMMIT = "1" * 40


def _file_record(path: Path, role: str, payload: bytes, inode: int) -> dict:
    metadata = path.stat()
    return {
        "device": 1,
        "inode": inode,
        "mtime_ns": metadata.st_mtime_ns,
        "path": path.as_posix(),
        "roles": [role],
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


def _audit(payload: dict) -> dict:
    return {**payload, "audit_sha256": seal_v2.canonical_sha256(payload)}


@pytest.fixture
def v3_document(tmp_path: Path):
    root = tmp_path / "checkout"
    durable = tmp_path / "durable" / "attempt-002"
    artifact = durable / "artifacts" / "cohort_causal"
    control = durable / "control"
    prep = durable / "prep"
    for directory in (root, artifact, control, prep):
        directory.mkdir(parents=True, exist_ok=True)

    payloads = {
        "formal_manifest": b"opaque manifest bytes",
        "formal_decision": b"opaque decision bytes",
        "wrapper_pid_file": b"202\n",
        "wrapper_exit_file": att.CANONICAL_ZERO_EXIT,
    }
    paths = {
        "formal_manifest": artifact / "formal_manifest.json",
        "formal_decision": artifact / "formal_decision.json",
        "wrapper_pid_file": prep / "causal_formal.pid",
        "wrapper_exit_file": prep / "causal_formal.exit",
    }
    for role, path in paths.items():
        path.write_bytes(payloads[role])
    os.utime(paths["formal_manifest"], ns=(1_000_000_000, 1_000_000_000))
    os.utime(paths["formal_decision"], ns=(2_000_000_000, 2_000_000_000))
    os.utime(paths["wrapper_exit_file"], ns=(2_000_000_000, 2_000_000_000))

    records = [
        _file_record(paths[role], role, payloads[role], inode=index)
        for index, role in enumerate(sorted(paths), start=1)
    ]
    records.sort(key=lambda record: record["path"])
    snapshots = [
        {
            "captured_at_utc": f"2026-07-14T18:00:0{sequence}.000000Z",
            "file_count": len(records),
            "files": copy.deepcopy(records),
            "inventory_sha256": seal_v2.canonical_sha256(records),
            "sequence": sequence,
        }
        for sequence in (1, 2)
    ]
    role_records = {role: att._role_record(snapshots[0], role) for role in paths}

    plan_path = control / execution.PLAN_FILENAME
    closure_path = control / recovery.FAILURE_CLOSURE_FILENAME
    fence_path = control / recovery.COMPLETION_FENCE_FILENAME
    receipt_path = control / execution.DETACHED_RECEIPT_FILENAME
    inventory_path = control / seal_v2.EXCEPTION_INVENTORY_FILENAME
    completion_path = prep / att.ATTESTATION_FILENAME
    launch_path = control / seal_v2.LAUNCH_EXPECTATION_FILENAME
    fence_only_paths = {
        "v2_detached_launch_receipt": control / seal_v2.DETACHED_RECEIPT_FILENAME,
        "v2_execution_plan": control / seal_v2.PLAN_FILENAME,
        "v2_failure_closure": closure_path,
        "v2_procfs_exception_inventory": inventory_path,
        "v3_recovery_freezer_source": (
            control
            / "verifier"
            / COMMIT
            / "freeze_cohort_causal_terminal_recovery_v3.py"
        ),
    }
    fence_only_records = []
    for index, (role, path) in enumerate(sorted(fence_only_paths.items()), start=100):
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = f"opaque {role}".encode("ascii")
        path.write_bytes(payload)
        fence_only_records.append(_file_record(path, role, payload, inode=index))
    fence_inventory_files = sorted(
        [*copy.deepcopy(records), *fence_only_records],
        key=lambda record: record["path"],
    )
    plan_sha = SHA_A
    closure_sha = SHA_B
    fence_sha = SHA_C
    receipt_sha = SHA_D
    inventory_sha = "e" * 64

    process_payload = {
        "artifact_root_path": artifact.as_posix(),
        "attempt_checkout_path": root.as_posix(),
        "durable_attempt_root_path": durable.as_posix(),
        "dynamic_policy_enforced": True,
        "dynamic_policy_sha256": SHA_A,
        "exception_inventory_sha256": inventory_sha,
        "method": seal_v2.PROCESS_AUDIT_METHOD,
        "observed_exception_count": 1,
        "observed_exceptions_sha256": SHA_B,
        "status": "pass",
    }
    temporary_payload = {
        "forbidden_match_count": 0,
        "roots": sorted([artifact.as_posix(), prep.as_posix()]),
        "status": "pass",
    }
    pid_exit = {
        "exit_after_outputs_status": att.PID_EXIT_TIE_STATUS,
        "exit_file_mtime_ns": role_records["wrapper_exit_file"]["mtime_ns"],
        "exit_file_path": role_records["wrapper_exit_file"]["path"],
        "exit_file_sha256": role_records["wrapper_exit_file"]["sha256"],
        "exit_file_size_bytes": role_records["wrapper_exit_file"]["size_bytes"],
        "exit_zero_status": "pass",
        "pid_ascii_status": "pass",
        "pid_file_mtime_ns": role_records["wrapper_pid_file"]["mtime_ns"],
        "pid_file_path": role_records["wrapper_pid_file"]["path"],
        "pid_file_sha256": role_records["wrapper_pid_file"]["sha256"],
        "pid_file_size_bytes": role_records["wrapper_pid_file"]["size_bytes"],
        "pid_liveness_status": "dead",
    }
    proof = {
        "completion_fence_sha256": fence_sha,
        "completion_method": att.COMPLETION_METHOD,
        "formal_decision_mtime_ns": 2_000_000_000,
        "formal_manifest_mtime_ns": 1_000_000_000,
        "historical_exit_order_claimed": False,
        "legacy_strict_mtime_proof": False,
        "mtime_relation": att.MTIME_RELATION,
        "wrapper_exit_exact_zero_newline": True,
        "wrapper_exit_mtime_ns": 2_000_000_000,
        "wrapper_pid_dead": True,
    }
    document = {
        "causal_pre_attestation_inventory_sha256": snapshots[0]["inventory_sha256"],
        "completed_at_utc": "2026-07-14T18:00:03.000000Z",
        "completion_fence": {"path": fence_path.as_posix(), "sha256": fence_sha},
        "completion_proof": proof,
        "detached_launch_receipt": {
            "path": receipt_path.as_posix(),
            "pid": 303,
            "process_start_ticks": 300,
            "sha256": receipt_sha,
        },
        "execution_plan_path": plan_path.as_posix(),
        "execution_plan_sha256": plan_sha,
        "expected_launcher": {
            "formal_grid_file_sha256": SHA_A,
            "launch_expectation_path": launch_path.as_posix(),
            "launch_expectation_sha256": SHA_B,
            "launcher_file_sha256": SHA_C,
            "provenance_file_sha256": SHA_D,
            "source_commit": COMMIT,
            "wrapper_cmdline_sha256_at_registration": inventory_sha,
        },
        "no_live_or_temporary": _audit(temporary_payload),
        "outcome_blind": True,
        "pid_exit": pid_exit,
        "process_absence": _audit(process_payload),
        "procfs_exception_inventory": {
            "inventory_sha256": SHA_A,
            "path": inventory_path.as_posix(),
            "sha256": inventory_sha,
        },
        "protocol": att.PROTOCOL,
        "registered_counts": copy.deepcopy(v1._EXPECTED_INVENTORY),
        "schema_version": att.SCHEMA_VERSION,
        "semantic_open_sentinel": copy.deepcopy(att.SEMANTIC_OPEN_SENTINEL),
        "snapshots": snapshots,
        "stability": {
            "minimum_interval_seconds": 1.0,
            "observed_interval_seconds": 1.0,
            "snapshots_identical": True,
        },
        "status": "complete",
        "v2_failure_closure": {
            "path": closure_path.as_posix(),
            "sha256": closure_sha,
        },
    }
    incident = {
        "completion_method": att.COMPLETION_METHOD,
        "decision_mtime_ns": 2_000_000_000,
        "exit_mtime_ns": 2_000_000_000,
        "historical_exit_order_claimed": False,
        "legacy_strict_mtime_proof": False,
        "manifest_mtime_ns": 1_000_000_000,
        "mtime_relation": att.MTIME_RELATION,
    }
    fence = {
        "incident": incident,
        "outcome_blind": True,
        "protocol": recovery.COMPLETION_FENCE_PROTOCOL,
        "semantic_artifacts_opened": False,
        "status": recovery.COMPLETION_FENCE_STATUS,
        "wrapper": {
            "exit_file": {
                "mtime_ns": 2_000_000_000,
                "path": role_records["wrapper_exit_file"]["path"],
                "sha256": att.CANONICAL_ZERO_EXIT_SHA256,
                "size_bytes": 2,
            }
        },
    }
    closure = {
        "incident": copy.deepcopy(incident),
        "outcome_blind": True,
        "protocol": recovery.FAILURE_CLOSURE_PROTOCOL,
        "semantic_artifacts_opened": False,
        "status": recovery.FAILURE_CLOSURE_STATUS,
    }
    validation = {
        "completion_attestation_path": completion_path,
        "execution_plan_path": plan_path,
        "execution_plan_sha256": plan_sha,
        "failure_closure_path": closure_path,
        "failure_closure_sha256": closure_sha,
        "completion_fence_path": fence_path,
        "completion_fence_sha256": fence_sha,
        "detached_receipt_path": receipt_path,
        "detached_receipt_sha256": receipt_sha,
        "procfs_exception_inventory_path": inventory_path,
        "procfs_exception_inventory_sha256": inventory_sha,
        "durable_attempt_root": durable,
        "failure_closure": closure,
        "completion_fence": (fence, copy.deepcopy(fence_inventory_files)),
    }
    return {
        "artifact": artifact,
        "closure": closure,
        "completion_path": completion_path,
        "document": document,
        "durable": durable,
        "fence": fence,
        "fence_inventory_files": fence_inventory_files,
        "paths": paths,
        "payloads": payloads,
        "root": root,
        "validation": validation,
    }


def _validate(item: dict) -> dict:
    return att.validate_attestation_document(item["document"], **item["validation"])


def test_public_document_validates_without_legacy_pass(v3_document):
    validated = _validate(v3_document)
    assert validated == v3_document["document"]
    assert validated["outcome_blind"] is True
    assert validated["semantic_open_sentinel"] == att.SEMANTIC_OPEN_SENTINEL
    assert validated["pid_exit"]["exit_after_outputs_status"] != "pass"
    assert b'"exit_after_outputs_status":"pass"' not in seal_v2.canonical_bytes(
        validated
    )


@pytest.mark.parametrize(
    ("manifest_ns", "decision_ns", "exit_ns"),
    [
        (2_000_000_000, 2_000_000_000, 2_000_000_000),
        (1_000_000_000, 2_000_000_000, 2_000_000_001),
        (1_000_000_000, 2_000_000_001, 2_000_000_001),
        (1_000_000_000, 2_000_000_000, 3_000_000_000),
    ],
)
def test_rejects_every_nonexact_incident_relation(
    v3_document, manifest_ns: int, decision_ns: int, exit_ns: int
):
    document = v3_document["document"]
    document["completion_proof"]["formal_manifest_mtime_ns"] = manifest_ns
    document["completion_proof"]["formal_decision_mtime_ns"] = decision_ns
    document["completion_proof"]["wrapper_exit_mtime_ns"] = exit_ns
    with pytest.raises(att.AttestationV3Error, match="truth claims|snapshots"):
        _validate(v3_document)


def test_rejects_semantic_open_or_outcome_blind_drift(v3_document):
    v3_document["document"]["semantic_open_sentinel"][
        "formal_decision_json_decoded"
    ] = True
    with pytest.raises(att.AttestationV3Error, match="status"):
        _validate(v3_document)
    v3_document["document"]["semantic_open_sentinel"] = copy.deepcopy(
        att.SEMANTIC_OPEN_SENTINEL
    )
    v3_document["document"]["outcome_blind"] = False
    with pytest.raises(att.AttestationV3Error, match="status"):
        _validate(v3_document)


def test_rejects_exit_binding_other_than_exact_zero_newline(v3_document):
    v3_document["document"]["pid_exit"]["exit_file_sha256"] = hashlib.sha256(
        b"0"
    ).hexdigest()
    for snapshot in v3_document["document"]["snapshots"]:
        record = att._role_record(snapshot, "wrapper_exit_file")
        record["sha256"] = hashlib.sha256(b"0").hexdigest()
        record["size_bytes"] = 1
        snapshot["inventory_sha256"] = seal_v2.canonical_sha256(snapshot["files"])
    v3_document["document"]["pid_exit"]["exit_file_size_bytes"] = 1
    v3_document["document"]["causal_pre_attestation_inventory_sha256"] = v3_document[
        "document"
    ]["snapshots"][0]["inventory_sha256"]
    with pytest.raises(att.AttestationV3Error, match="zero-newline"):
        _validate(v3_document)


def test_rejects_snapshot_or_completion_proof_drift(v3_document):
    second = v3_document["document"]["snapshots"][1]
    att._role_record(second, "formal_manifest")["sha256"] = SHA_D
    second["inventory_sha256"] = seal_v2.canonical_sha256(second["files"])
    with pytest.raises(att.AttestationV3Error, match="stably identical"):
        _validate(v3_document)
    v3_document["document"]["snapshots"][1] = copy.deepcopy(
        v3_document["document"]["snapshots"][0]
    )
    v3_document["document"]["snapshots"][1]["sequence"] = 2
    v3_document["document"]["snapshots"][1]["captured_at_utc"] = (
        "2026-07-14T18:00:02.000000Z"
    )
    v3_document["document"]["completion_proof"]["completion_fence_sha256"] = SHA_D
    with pytest.raises(att.AttestationV3Error, match="bind the fence"):
        _validate(v3_document)


def test_rejects_decision_byte_mutation_after_fence_with_preserved_mtime(
    v3_document,
):
    decision_path = v3_document["paths"]["formal_decision"]
    original = decision_path.read_bytes()
    mutated = bytes([original[0] ^ 1]) + original[1:]
    assert len(mutated) == len(original) and mutated != original
    decision_path.write_bytes(mutated)
    os.utime(decision_path, ns=(2_000_000_000, 2_000_000_000))

    document = v3_document["document"]
    for snapshot in document["snapshots"]:
        record = att._role_record(snapshot, "formal_decision")
        assert record["mtime_ns"] == 2_000_000_000
        record["sha256"] = hashlib.sha256(mutated).hexdigest()
        record["size_bytes"] = len(mutated)
        snapshot["inventory_sha256"] = seal_v2.canonical_sha256(snapshot["files"])
    document["causal_pre_attestation_inventory_sha256"] = document["snapshots"][0][
        "inventory_sha256"
    ]

    with pytest.raises(
        att.AttestationV3Error, match="inventory differs from completion fence"
    ):
        _validate(v3_document)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing_attested", "inventory differs from completion fence"),
        ("substituted_attested", "inventory differs from completion fence"),
        ("unauthorized_extra", "unauthorized extra"),
        ("missing_fence_control", "control inventory is incomplete"),
    ],
)
def test_rejects_missing_substituted_or_extra_fence_records(
    v3_document, mutation: str, message: str
):
    fence_files = v3_document["validation"]["completion_fence"][1]
    decision_path = v3_document["paths"]["formal_decision"].as_posix()
    if mutation == "missing_attested":
        fence_files[:] = [
            record for record in fence_files if record["path"] != decision_path
        ]
    elif mutation == "substituted_attested":
        next(record for record in fence_files if record["path"] == decision_path)[
            "sha256"
        ] = SHA_D
    elif mutation == "unauthorized_extra":
        extra = copy.deepcopy(fence_files[-1])
        extra["path"] = (v3_document["durable"] / "control" / "unexpected").as_posix()
        extra["roles"] = ["unexpected_fence_extra"]
        extra["inode"] += 10_000
        fence_files.append(extra)
    else:
        fence_files[:] = [
            record
            for record in fence_files
            if record["roles"] != ["v2_failure_closure"]
        ]

    with pytest.raises(att.AttestationV3Error, match=message):
        _validate(v3_document)


def test_rejects_self_rehashed_forged_process_or_temporary_audit(v3_document):
    process = v3_document["document"]["process_absence"]
    process["exception_inventory_sha256"] = SHA_A
    process["audit_sha256"] = seal_v2.canonical_sha256(
        {key: process[key] for key in process if key != "audit_sha256"}
    )
    with pytest.raises(att.AttestationV3Error, match="process audit"):
        _validate(v3_document)
    process["exception_inventory_sha256"] = v3_document["document"][
        "procfs_exception_inventory"
    ]["sha256"]
    process["audit_sha256"] = seal_v2.canonical_sha256(
        {key: process[key] for key in process if key != "audit_sha256"}
    )
    temporary = v3_document["document"]["no_live_or_temporary"]
    temporary["forbidden_match_count"] = 1
    temporary["audit_sha256"] = seal_v2.canonical_sha256(
        {key: temporary[key] for key in temporary if key != "audit_sha256"}
    )
    with pytest.raises(att.AttestationV3Error, match="temporary audit"):
        _validate(v3_document)


def test_rejects_fence_or_closure_truth_drift(v3_document):
    v3_document["fence"]["incident"]["historical_exit_order_claimed"] = True
    with pytest.raises(att.AttestationV3Error, match="completion fence"):
        _validate(v3_document)
    v3_document["fence"]["incident"]["historical_exit_order_claimed"] = False
    v3_document["closure"]["incident"]["manifest_mtime_ns"] = 0
    with pytest.raises(att.AttestationV3Error, match="failure closure"):
        _validate(v3_document)


def test_equal_second_pid_exit_reads_exact_bytes_and_rejects_symlink(v3_document):
    snapshot = v3_document["document"]["snapshots"][0]
    expectation = {
        "durable_attempt_root": v3_document["durable"].as_posix(),
        "pid_file_sha256_at_registration": att._role_record(
            snapshot, "wrapper_pid_file"
        )["sha256"],
        "wrapper_pid": 202,
    }
    pid, record = att._validate_equal_second_pid_exit(
        expectation=expectation,
        snapshot=snapshot,
        pid_is_live_fn=lambda _pid: False,
    )
    assert pid == 202
    assert record["exit_after_outputs_status"] == att.PID_EXIT_TIE_STATUS
    exit_path = v3_document["paths"]["wrapper_exit_file"]
    exit_path.unlink()
    exit_path.symlink_to(v3_document["paths"]["formal_manifest"])
    with pytest.raises(v1.AttestationError, match="symlink"):
        att._validate_equal_second_pid_exit(
            expectation=expectation,
            snapshot=snapshot,
            pid_is_live_fn=lambda _pid: False,
        )


def _chain_fixture(v3_document) -> dict:
    plan = {
        "causal_checkout_root": v3_document["root"].as_posix(),
        "durable_attempt_root": v3_document["durable"].as_posix(),
        "outcome_blind": True,
        "semantic_artifacts_opened": False,
    }
    return {
        "base_v2_detached_receipt": {},
        "base_v2_detached_receipt_raw": b"base receipt",
        "base_v2_execution_plan": {},
        "base_v2_execution_plan_raw": b"base plan",
        "base_v2_procfs_exception_inventory": {},
        "base_v2_procfs_exception_inventory_raw": b"base inventory",
        "closure": {
            **copy.deepcopy(v3_document["closure"]),
            "semantic_artifacts_opened": False,
        },
        "closure_raw": b"closure",
        "fence": {
            **copy.deepcopy(v3_document["fence"]),
            "semantic_artifacts_opened": False,
        },
        "fence_inventory_files": [],
        "fence_raw": b"fence",
        "plan": plan,
        "plan_raw": b"plan",
        "receipt": {"outcome_blind": True, "semantic_artifacts_opened": False},
        "receipt_raw": b"fresh receipt",
        "semantic_open_sentinel": copy.deepcopy(att.CONTROL_CHAIN_SENTINEL),
    }


def test_control_chain_requires_exact_semantic_sentinel(
    v3_document, monkeypatch: pytest.MonkeyPatch
):
    chain = _chain_fixture(v3_document)
    monkeypatch.setattr(
        execution,
        "validate_authoritative_v3_control_chain",
        lambda **_kwargs: copy.deepcopy(chain),
    )
    validated = att._validate_control_chain(
        execution_plan_path=Path("/tmp/plan"),
        base_v2_execution_plan_path=Path("/tmp/base-plan"),
        base_v2_detached_receipt_path=Path("/tmp/base-receipt"),
        base_v2_procfs_exception_inventory_path=Path("/tmp/base-inventory"),
        v2_failure_closure_path=Path("/tmp/closure"),
        completion_fence_path=Path("/tmp/fence"),
        detached_launch_receipt_path=Path("/tmp/receipt"),
    )
    assert validated["semantic_open_sentinel"] == att.CONTROL_CHAIN_SENTINEL
    chain["semantic_open_sentinel"]["efficacy_artifacts_parsed"] = True
    with pytest.raises(att.AttestationV3Error, match="semantic-open"):
        att._validate_control_chain(
            execution_plan_path=Path("/tmp/plan"),
            base_v2_execution_plan_path=Path("/tmp/base-plan"),
            base_v2_detached_receipt_path=Path("/tmp/base-receipt"),
            base_v2_procfs_exception_inventory_path=Path("/tmp/base-inventory"),
            v2_failure_closure_path=Path("/tmp/closure"),
            completion_fence_path=Path("/tmp/fence"),
            detached_launch_receipt_path=Path("/tmp/receipt"),
        )


def test_private_projection_is_private_named_and_never_public(
    v3_document, monkeypatch: pytest.MonkeyPatch
):
    assert not hasattr(att, "project_attestation_for_v1")
    assert hasattr(att, "_project_attestation_for_v1")
    source = Path(att.__file__).read_text()
    public_body = source.split("def validate_attestation_document", 1)[1].split(
        "def _project_attestation_for_v1", 1
    )[0]
    assert 'exit_after_outputs_status"] = "pass"' not in public_body
    assert 'legacy["pid_exit"]["exit_after_outputs_status"] = "pass"' in source

    public = copy.deepcopy(v3_document["document"])
    seen = {}
    monkeypatch.setattr(
        att,
        "validate_attestation_document",
        lambda value, **_kwargs: copy.deepcopy(value),
    )

    def validate_legacy(value, **_kwargs):
        seen.update(copy.deepcopy(value))
        return copy.deepcopy(value), []

    monkeypatch.setattr(att.seal_v1, "_validate_attestation", validate_legacy)
    projected, _ = att._project_attestation_for_v1(
        public,
        execution_plan_path=Path(public["execution_plan_path"]),
        execution_plan_sha256=public["execution_plan_sha256"],
        expectation={},
        launch_expectation_path=Path(
            public["expected_launcher"]["launch_expectation_path"]
        ),
        launch_expectation_sha256=public["expected_launcher"][
            "launch_expectation_sha256"
        ],
    )
    assert projected["pid_exit"]["exit_after_outputs_status"] == "pass"
    assert "outcome_blind" not in projected
    assert "semantic_open_sentinel" not in projected
    assert "completion_proof" not in projected
    assert seen == projected
    assert public["pid_exit"]["exit_after_outputs_status"] == att.PID_EXIT_TIE_STATUS
    assert public["semantic_open_sentinel"] == att.SEMANTIC_OPEN_SENTINEL


def test_no_overwrite_rejects_existing_file_before_control_open(v3_document):
    output = v3_document["completion_path"]
    output.write_bytes(b"keep")
    with pytest.raises(FileExistsError, match="overwrite"):
        att.build_and_publish_attestation(
            root=v3_document["root"],
            execution_plan_path=Path("/missing/plan"),
            base_v2_execution_plan_path=Path("/missing/base-plan"),
            base_v2_detached_receipt_path=Path("/missing/base-receipt"),
            base_v2_procfs_exception_inventory_path=Path("/missing/inventory"),
            v2_failure_closure_path=Path("/missing/closure"),
            completion_fence_path=Path("/missing/fence"),
            detached_launch_receipt_path=Path("/missing/receipt"),
            launch_expectation_path=Path("/missing/expectation"),
            provenance_path=Path("/missing/provenance"),
            provenance_details_path=Path("/missing/details"),
            output=output,
        )
    assert output.read_bytes() == b"keep"


def test_capture_plan_adapter_adds_exact_v3_inputs_and_restores_global(
    monkeypatch: pytest.MonkeyPatch,
):
    calls = []
    original = v1.load_and_validate_execution_plan_stage

    def validate(**kwargs):
        calls.append(kwargs)
        return {}, b"plan"

    monkeypatch.setattr(execution, "load_and_validate_execution_plan_stage", validate)
    extras = {
        "base_v2_execution_plan": Path("/tmp/base-plan"),
        "base_v2_detached_receipt": Path("/tmp/base-receipt"),
    }
    with att._capture_v1_attestation_as_v3(stage_extra_inputs=extras):
        v1.load_and_validate_execution_plan_stage(
            execution_plan_path=Path("/tmp/plan"),
            stage="attester",
            expected_inputs={"root": Path("/tmp/root")},
            expected_outputs={"attestation": Path("/tmp/output")},
        )
    assert v1.load_and_validate_execution_plan_stage is original
    assert calls[0]["expected_inputs"] == {
        "root": Path("/tmp/root"),
        **extras,
    }


def test_fixed_build_paths_rejects_launch_expectation_drift(tmp_path: Path):
    durable = tmp_path / "durable" / "attempt-002"
    root = tmp_path / "checkout"
    paths = {
        "root": root,
        "execution_plan": durable / "control" / execution.PLAN_FILENAME,
        "launch_expectation": durable / "control" / "wrong-launch.json",
        "output": durable / "prep" / att.ATTESTATION_FILENAME,
    }
    plan = {
        "causal_checkout_root": root.as_posix(),
        "durable_attempt_root": durable.as_posix(),
    }
    with pytest.raises(att.AttestationV3Error, match="attempt roots"):
        att._validate_fixed_build_paths(paths=paths, plan=plan)

    paths["launch_expectation"] = (
        durable / "control" / seal_v2.LAUNCH_EXPECTATION_FILENAME
    )
    assert att._validate_fixed_build_paths(paths=paths, plan=plan) == durable


def test_static_fresh_receipt_must_bind_exact_plan_and_attestation(
    v3_document, monkeypatch: pytest.MonkeyPatch
):
    document = v3_document["document"]
    plan_path = Path(document["execution_plan_path"])
    receipt_path = Path(document["detached_launch_receipt"]["path"])
    completion_path = v3_document["completion_path"]
    plan = {key: None for key in execution.PLAN_KEYS}
    plan.update(
        {
            "invocations": {
                "attester": {
                    "argv": ["/usr/bin/python3.10", "/tool/attester.py"],
                    "inputs": {},
                    "outputs": {"attestation": completion_path.as_posix()},
                    "parameters": {},
                }
            },
            "outcome_blind": True,
            "protocol": execution.PLAN_PROTOCOL,
            "schema_version": execution.PLAN_SCHEMA_VERSION,
            "semantic_artifacts_opened": False,
            "status": execution.PLAN_STATUS,
        }
    )
    receipt = {key: None for key in execution.launcher_v3.RECEIPT_KEYS}
    receipt.update(
        {
            "exec_argv_sha256": execution.canonical_sha256(
                plan["invocations"]["attester"]["argv"]
            ),
            "outcome_blind": True,
            "pid": document["detached_launch_receipt"]["pid"],
            "plan": {
                "path": plan_path.as_posix(),
                "sha256": document["execution_plan_sha256"],
            },
            "process_start_ticks": document["detached_launch_receipt"][
                "process_start_ticks"
            ],
            "protocol": execution.DETACHED_RECEIPT_PROTOCOL,
            "schema_version": 1,
            "semantic_artifacts_opened": False,
            "status": "ready_to_same_pid_exec_exact_v3_attester",
        }
    )
    plan_raw = b"canonical-plan"
    receipt_raw = b"canonical-receipt"
    parsed = {plan_raw: plan, receipt_raw: receipt}
    original_canonical_bytes = execution.canonical_bytes
    monkeypatch.setattr(
        execution, "_strict_json", lambda raw, _label: copy.deepcopy(parsed[raw])
    )
    monkeypatch.setattr(
        execution,
        "canonical_bytes",
        lambda value: (
            plan_raw
            if isinstance(value, dict)
            and value.get("protocol") == execution.PLAN_PROTOCOL
            else (
                receipt_raw
                if isinstance(value, dict)
                and value.get("protocol") == execution.DETACHED_RECEIPT_PROTOCOL
                else original_canonical_bytes(value)
            )
        ),
    )
    artifact_paths = {
        "completion_attestation": completion_path.as_posix(),
        "execution_plan": plan_path.as_posix(),
        "detached_receipt": receipt_path.as_posix(),
    }
    artifact_bytes = {
        "execution_plan": plan_raw,
        "detached_receipt": receipt_raw,
    }
    document["execution_plan_sha256"] = hashlib.sha256(plan_raw).hexdigest()
    document["detached_launch_receipt"]["sha256"] = hashlib.sha256(
        receipt_raw
    ).hexdigest()
    receipt["plan"]["sha256"] = document["execution_plan_sha256"]
    att._validate_static_plan_and_fresh_receipt_context(
        artifact_paths=artifact_paths,
        artifact_bytes=artifact_bytes,
        attestation=document,
    )
    receipt["pid"] += 1
    with pytest.raises(att.AttestationV3Error, match="not bound"):
        att._validate_static_plan_and_fresh_receipt_context(
            artifact_paths=artifact_paths,
            artifact_bytes=artifact_bytes,
            attestation=document,
        )
