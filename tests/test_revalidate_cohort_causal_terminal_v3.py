from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import revalidate_cohort_causal_terminal as v1
import revalidate_cohort_causal_terminal_v3 as v3


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _binding(path: Path, payload: bytes) -> dict[str, str]:
    return {"path": path.as_posix(), "sha256": _sha(payload)}


def _receipt_fixture(durable: Path) -> dict[str, Any]:
    plan = durable / "control/CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V3.json"
    closure = durable / "control" / v3.FAILURE_CLOSURE_FILENAME
    fence = durable / "control" / v3.COMPLETION_FENCE_FILENAME
    attestation = durable / "prep" / v3.ATTESTATION_FILENAME
    manifest = durable / "artifacts/cohort_causal/formal_manifest.json"
    decision = durable / "artifacts/cohort_causal/formal_decision.json"
    revalidated = durable / "prep" / v3.REVALIDATED_FILENAME
    decision_raw = b'{"decision":"pass"}\n'
    return {
        "completion_attestation": _binding(attestation, b"attestation"),
        "completion_fence": _binding(fence, b"fence"),
        "completion_method": v3.COMPLETION_METHOD,
        "decision": "pass",
        "decision_scope": "internal_gate_pass",
        "execution_plan": _binding(plan, b"plan"),
        "formal_decision": _binding(decision, decision_raw),
        "formal_manifest": _binding(manifest, b"manifest"),
        "historical_exit_order_claimed": False,
        "legacy_publication": False,
        "legacy_strict_mtime_proof": False,
        "mtime_relation": v3.MTIME_RELATION,
        "private_legacy_receipt_sha256": _sha(b"private legacy receipt"),
        "protocol": v3.PROTOCOL,
        "revalidated_decision": _binding(revalidated, decision_raw),
        "revalidated_decision_byte_identical": True,
        "schema_version": v3.SCHEMA_VERSION,
        "status": "valid",
        "v2_failure_closure": _binding(closure, b"closure"),
    }


def test_public_receipt_validator_accepts_only_truthful_v3_schema(
    tmp_path: Path,
) -> None:
    durable = tmp_path / "attempt"
    receipt = _receipt_fixture(durable)
    assert (
        v3.validate_revalidation_receipt_document(receipt, durable_attempt_root=durable)
        == receipt
    )

    poisoned = json.loads(json.dumps(receipt))
    poisoned["legacy_publication"] = True
    with pytest.raises(v3.RevalidationV3Error, match="truth fields"):
        v3.validate_revalidation_receipt_document(
            poisoned, durable_attempt_root=durable
        )

    poisoned = json.loads(json.dumps(receipt))
    poisoned["revalidated_decision"]["sha256"] = "f" * 64
    with pytest.raises(v3.RevalidationV3Error, match="truth fields"):
        v3.validate_revalidation_receipt_document(
            poisoned, durable_attempt_root=durable
        )

    poisoned = json.loads(json.dumps(receipt))
    poisoned["legacy_receipt"] = {"status": "valid"}
    with pytest.raises(v3.RevalidationV3Error, match="schema"):
        v3.validate_revalidation_receipt_document(poisoned)


def test_public_receipt_validator_rehashes_available_authoritative_bytes(
    tmp_path: Path,
) -> None:
    durable = tmp_path / "attempt"
    receipt = _receipt_fixture(durable)
    raws = {
        "execution_plan": b"plan",
        "failure_closure": b"closure",
        "completion_fence": b"fence",
        "completion_attestation": b"attestation",
        "revalidated_decision": b'{"decision":"pass"}\n',
    }
    paths = {
        "execution_plan": receipt["execution_plan"]["path"],
        "failure_closure": receipt["v2_failure_closure"]["path"],
        "completion_fence": receipt["completion_fence"]["path"],
        "completion_attestation": receipt["completion_attestation"]["path"],
        "revalidated_decision": receipt["revalidated_decision"]["path"],
    }
    assert v3.validate_revalidation_receipt_document(
        receipt,
        durable_attempt_root=durable,
        artifact_bytes=raws,
        artifact_paths=paths,
    )
    raws["completion_fence"] = b"drifted fence"
    with pytest.raises(v3.RevalidationV3Error, match="digest differs"):
        v3.validate_revalidation_receipt_document(
            receipt,
            durable_attempt_root=durable,
            artifact_bytes=raws,
            artifact_paths=paths,
        )

    with pytest.raises(v3.RevalidationV3Error, match="completion_fence digest"):
        v3.validate_revalidation_receipt_document(
            receipt,
            completion_fence_path=Path(receipt["completion_fence"]["path"]),
            completion_fence_sha256="0" * 64,
        )


def _file_record(path: Path, role: str) -> dict[str, Any]:
    raw = path.read_bytes()
    metadata = path.stat()
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mtime_ns": metadata.st_mtime_ns,
        "path": path.as_posix(),
        "roles": [role],
        "sha256": _sha(raw),
        "size_bytes": len(raw),
    }


def _equal_second_fixture(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    pid_path = tmp_path / "causal_formal.pid"
    exit_path = tmp_path / "causal_formal.exit"
    manifest_path = tmp_path / "formal_manifest.json"
    decision_path = tmp_path / "formal_decision.json"
    pid_path.write_bytes(b"999999999\n")
    exit_path.write_bytes(b"0\n")
    manifest_path.write_bytes(b"opaque manifest")
    decision_path.write_bytes(b"opaque decision")
    boundary = 1_800_000_000_000_000_000
    os.utime(manifest_path, ns=(boundary - 1_000_000_000, boundary - 1_000_000_000))
    os.utime(decision_path, ns=(boundary, boundary))
    os.utime(exit_path, ns=(boundary, boundary))
    records = [
        _file_record(decision_path, "formal_decision"),
        _file_record(manifest_path, "formal_manifest"),
        _file_record(exit_path, "wrapper_exit_file"),
        _file_record(pid_path, "wrapper_pid_file"),
    ]
    records.sort(key=lambda record: record["path"])
    pid_record = next(
        record for record in records if "wrapper_pid_file" in record["roles"]
    )
    exit_record = next(
        record for record in records if "wrapper_exit_file" in record["roles"]
    )
    attestation = {
        "completion_proof": {
            "completion_method": v3.COMPLETION_METHOD,
            "formal_decision_mtime_ns": boundary,
            "formal_manifest_mtime_ns": boundary - 1_000_000_000,
            "historical_exit_order_claimed": False,
            "legacy_strict_mtime_proof": False,
            "mtime_relation": v3.MTIME_RELATION,
            "wrapper_exit_exact_zero_newline": True,
            "wrapper_exit_mtime_ns": boundary,
            "wrapper_pid_dead": True,
        },
        "pid_exit": {
            "exit_after_outputs_status": "not_proven_equal_second",
            "exit_file_mtime_ns": exit_record["mtime_ns"],
            "exit_file_path": exit_record["path"],
            "exit_file_sha256": exit_record["sha256"],
            "exit_file_size_bytes": exit_record["size_bytes"],
            "exit_zero_status": "pass",
            "pid_ascii_status": "pass",
            "pid_file_mtime_ns": pid_record["mtime_ns"],
            "pid_file_path": pid_record["path"],
            "pid_file_sha256": pid_record["sha256"],
            "pid_file_size_bytes": pid_record["size_bytes"],
            "pid_liveness_status": "dead",
        },
        "snapshots": [{"files": records}],
    }
    inventory = {record["path"]: record for record in records}
    return attestation, inventory


def test_exact_equal_second_gate_accepts_only_current_canonical_incident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attestation, inventory = _equal_second_fixture(tmp_path)
    monkeypatch.setattr(v3, "_pid_is_dead", lambda _pid: True)
    v3._validate_equal_second_current_gate(
        attestation=attestation,
        inventory=inventory,
        formal_manifest=tmp_path / "formal_manifest.json",
        formal_decision=tmp_path / "formal_decision.json",
    )

    (tmp_path / "causal_formal.exit").write_bytes(b"0")
    with pytest.raises(v3.RevalidationV3Error):
        v3._validate_equal_second_current_gate(
            attestation=attestation,
            inventory=inventory,
            formal_manifest=tmp_path / "formal_manifest.json",
            formal_decision=tmp_path / "formal_decision.json",
        )


def test_control_chain_uses_static_gone_receipt_gate_before_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _full_paths(tmp_path)
    events: list[str] = []
    base_plan_path = paths["durable"] / "control/base-plan.json"
    base_receipt_path = paths["durable"] / "control/base-receipt.json"
    base_inventory_path = paths["durable"] / "control/base-inventory.json"
    fresh_receipt_path = paths["durable"] / "control/fresh-receipt.json"
    plan = {
        "base_v2": {
            "execution_plan": {"path": base_plan_path.as_posix()},
            "detached_receipt": {"path": base_receipt_path.as_posix()},
            "procfs_exception_inventory": {"path": base_inventory_path.as_posix()},
        }
    }
    plan_raw = b'{"plan":"raw"}'
    closure = {"control": "closure"}
    fence_record = {
        "device": 1,
        "inode": 2,
        "mtime_ns": 3,
        "path": (tmp_path / "opaque").as_posix(),
        "roles": ["opaque"],
        "sha256": "a" * 64,
        "size_bytes": 4,
    }
    fence = {"control": "fence"}
    attestation = {
        "detached_launch_receipt": {
            "path": fresh_receipt_path.as_posix(),
            "pid": 404,
            "process_start_ticks": 505,
            "sha256": _sha(b'{"receipt":"raw"}'),
        },
        "procfs_exception_inventory": {
            "inventory_sha256": "b" * 64,
            "path": base_inventory_path.as_posix(),
            "sha256": _sha(b'{"base":"inventory"}'),
        },
    }

    def plan_loader(**kwargs: Any):
        events.append("stage-plan")
        assert kwargs["stage"] == "revalidator"
        return plan, plan_raw

    def load_base(**_kwargs: Any) -> dict[str, Any]:
        events.append("base-controls")
        return {
            "base_v2_procfs_exception_inventory": {
                "runtime_namespace": {"boot_id": "frozen"}
            },
            "base_v2_procfs_exception_inventory_raw": b'{"base":"inventory"}',
        }

    def static_receipt(**kwargs: Any):
        events.append("static-receipt-pid-gone")
        assert kwargs["path"] == fresh_receipt_path
        assert kwargs["expected_runtime_namespace"] == {"boot_id": "frozen"}
        return {"pid": 404, "process_start_ticks": 505}, b'{"receipt":"raw"}'

    execution = SimpleNamespace(
        load_and_validate_execution_plan_stage=plan_loader,
        _load_base_v2_controls=load_base,
        validate_detached_receipt_static_document=static_receipt,
    )

    def validate_closure(value: Any, **_kwargs: Any):
        events.append("closure")
        return value

    def validate_fence(value: Any, **_kwargs: Any):
        events.append("fence")
        return value, [fence_record]

    recovery = SimpleNamespace(
        validate_failure_closure_document=validate_closure,
        validate_completion_fence_document=validate_fence,
    )
    validation_count = 0

    def validate_attestation(value: Any, **kwargs: Any):
        nonlocal validation_count
        validation_count += 1
        events.append(
            "attestation-static" if validation_count == 1 else "attestation-bound"
        )
        if validation_count == 2:
            assert kwargs["artifact_bytes"]["detached_receipt"] == b'{"receipt":"raw"}'
            assert kwargs["procfs_exception_inventory_path"] == base_inventory_path
        return value

    def project(value: Any, **_kwargs: Any):
        events.append("private-projection")
        return {"private": "v1"}, [fence_record]

    attester = SimpleNamespace(
        validate_attestation_document=validate_attestation,
        _project_attestation_for_v1=project,
    )
    controls = {
        "V2 failure closure": (closure, b'{"closure":"raw"}'),
        "V3 completion fence": (fence, b'{"fence":"raw"}'),
        "V3 completion attestation": (
            attestation,
            v1._canonical_bytes(attestation),
        ),
    }
    monkeypatch.setattr(
        v3,
        "_strict_control",
        lambda _path, *, label: controls[label],
    )
    monkeypatch.setattr(
        v3.completion_v1,
        "_load_launch_expectation",
        lambda _path: (
            {
                "durable_attempt_root": paths["durable"].as_posix(),
                "wrapper_pid": 999,
            },
            b'{"expectation":"raw"}',
        ),
    )

    def inventory(_files: Any) -> dict[str, Any]:
        events.append("current-inventory")
        registered = {
            paths[name].as_posix(): {"path": paths[name].as_posix()}
            for name in (
                "expectation",
                "grid",
                "provenance",
                "manifest",
                "decision",
                "prereg",
                "addendum",
            )
        }
        return registered

    monkeypatch.setattr(v1, "_verify_current_inventory", inventory)
    monkeypatch.setattr(v1, "_require_inventory_paths", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        v3,
        "_validate_equal_second_current_gate",
        lambda **_kwargs: events.append("equal-second-current"),
    )
    result = v3._validate_revalidator_control_chain(
        execution=execution,
        recovery=recovery,
        attester=attester,
        root=paths["root"],
        execution_plan_path=paths["plan"],
        failure_closure_path=paths["closure"],
        completion_fence_path=paths["fence"],
        attestation_path=paths["attestation"],
        launch_expectation_path=paths["expectation"],
        grid_path=paths["grid"],
        provenance_path=paths["provenance"],
        formal_manifest_path=paths["manifest"],
        formal_decision_path=paths["decision"],
        preregistration_path=paths["prereg"],
        statistical_addendum_path=paths["addendum"],
        revalidated_output=paths["output"],
        receipt_output=paths["receipt"],
        actual_argv=None,
        runtime_python_path=None,
        runtime_python_version=None,
    )
    assert result.plan_raw == plan_raw
    assert events == [
        "stage-plan",
        "closure",
        "fence",
        "attestation-static",
        "base-controls",
        "static-receipt-pid-gone",
        "attestation-bound",
        "private-projection",
        "current-inventory",
        "equal-second-current",
    ]


def _full_paths(tmp_path: Path) -> dict[str, Path]:
    durable = tmp_path / "attempt"
    root = tmp_path / "checkout"
    (durable / "control").mkdir(parents=True)
    (durable / "prep").mkdir()
    (durable / "artifacts/cohort_causal").mkdir(parents=True)
    root.mkdir()
    paths = {
        "durable": durable,
        "root": root,
        "plan": durable / "control/CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V3.json",
        "closure": durable / "control" / v3.FAILURE_CLOSURE_FILENAME,
        "fence": durable / "control" / v3.COMPLETION_FENCE_FILENAME,
        "attestation": durable / "prep" / v3.ATTESTATION_FILENAME,
        "expectation": durable / "control/launch_expectation.json",
        "grid": root / "grid_cohort_causal_formal.json",
        "provenance": durable / "control/provenance.json",
        "manifest": durable / "artifacts/cohort_causal/formal_manifest.json",
        "decision": durable / "artifacts/cohort_causal/formal_decision.json",
        "prereg": root / v1.PREREGISTRATION_FILENAME,
        "addendum": root / v1.STATISTICAL_ADDENDUM_FILENAME,
        "output": durable / "prep" / v3.REVALIDATED_FILENAME,
        "receipt": durable / "prep" / v3.RECEIPT_FILENAME,
    }
    paths["manifest"].write_bytes(b"opaque manifest bytes")
    paths["decision"].write_bytes(b'{"decision":"pass"}\n')
    return paths


def test_v1_pair_is_private_and_only_truthful_v3_pair_is_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _full_paths(tmp_path)
    plan_raw = b'{"v3":"plan"}'
    closure_raw = b'{"v3":"closure"}'
    fence_raw = b'{"v3":"fence"}'
    attestation_raw = b'{"v3":"attestation"}'
    context = v3._ControlContext(
        plan={"v3": "plan"},
        plan_raw=plan_raw,
        closure={"v3": "closure"},
        closure_raw=closure_raw,
        fence={"v3": "fence"},
        fence_raw=fence_raw,
        attestation={"v3": "attestation"},
        attestation_raw=attestation_raw,
        projected_v1_attestation={"v1": "private"},
        attested_files=[],
        expectation={
            "durable_attempt_root": paths["durable"].as_posix(),
            "wrapper_pid": 999,
        },
        expectation_raw=b'{"expectation":"raw"}',
    )
    events: list[str] = []

    def plan_loader(**kwargs: Any):
        events.append("plan-gate")
        assert kwargs["stage"] == "revalidator"
        assert set(kwargs["expected_inputs"]) >= {
            "v2_failure_closure",
            "completion_fence",
        }
        return context.plan, context.plan_raw

    execution = SimpleNamespace(load_and_validate_execution_plan_stage=plan_loader)
    monkeypatch.setattr(v3, "_load_v3_modules", lambda: (execution, object(), object()))

    def prepare(**_kwargs: Any) -> v3._ControlContext:
        events.append("all-v3-control-gates")
        return context

    monkeypatch.setattr(v3, "_validate_revalidator_control_chain", prepare)

    def equal_gate(**_kwargs: Any) -> None:
        events.append("equal-second-current-gate")

    monkeypatch.setattr(v3, "_validate_equal_second_current_gate", equal_gate)
    decision_raw = paths["decision"].read_bytes()
    manifest_raw = paths["manifest"].read_bytes()
    legacy_receipt = {
        "decision": "pass",
        "decision_scope": "internal_gate_pass",
        "execution_plan_path": paths["plan"].as_posix(),
        "execution_plan_sha256": _sha(plan_raw),
        "formal_decision_file_sha256": _sha(decision_raw),
        "formal_manifest_file_sha256": _sha(manifest_raw),
        "status": "valid",
    }
    legacy_raw = v1._pretty_report_bytes(legacy_receipt)

    def private_v1_engine(**kwargs: Any) -> dict[str, Any]:
        v1.load_and_validate_execution_plan_stage(
            execution_plan_path=kwargs["execution_plan_path"],
            stage="revalidator",
            expected_inputs={
                "execution_plan": kwargs["execution_plan_path"],
                "root": kwargs["root"],
            },
            expected_outputs={
                "revalidated_decision": kwargs["revalidated_output"],
                "revalidation_receipt": kwargs["receipt_output"],
            },
            expected_parameters={},
        )
        projected, _ = v1._validate_attestation(context.attestation)
        v1._validate_pid_exit_gate(
            attestation=projected,
            inventory={},
            formal_manifest=kwargs["formal_manifest_path"],
            formal_decision=kwargs["formal_decision_path"],
        )
        events.append("semantic-open-and-recompute")
        v1._publish_pair_no_overwrite(
            [
                (kwargs["revalidated_output"], decision_raw),
                (kwargs["receipt_output"], legacy_raw),
            ]
        )
        return legacy_receipt

    monkeypatch.setattr(v1, "revalidate_terminal", private_v1_engine)
    published: list[list[tuple[Path, bytes]]] = []

    def final_publish(outputs: list[tuple[Path, bytes]]) -> None:
        events.append("public-v3-pair")
        published.append(outputs)

    monkeypatch.setattr(v1, "_publish_pair_no_overwrite", final_publish)
    receipt = v3.revalidate_terminal(
        root=paths["root"],
        execution_plan_path=paths["plan"],
        v2_failure_closure_path=paths["closure"],
        completion_fence_path=paths["fence"],
        attestation_path=paths["attestation"],
        launch_expectation_path=paths["expectation"],
        grid_path=paths["grid"],
        provenance_path=paths["provenance"],
        formal_manifest_path=paths["manifest"],
        formal_decision_path=paths["decision"],
        revalidated_output=paths["output"],
        receipt_output=paths["receipt"],
        preregistration_path=paths["prereg"],
        statistical_addendum_path=paths["addendum"],
    )

    assert events == [
        "all-v3-control-gates",
        "plan-gate",
        "equal-second-current-gate",
        "semantic-open-and-recompute",
        "all-v3-control-gates",
        "public-v3-pair",
    ]
    assert len(published) == 1
    assert published[0][0] == (paths["output"], decision_raw)
    assert published[0][1][0] == paths["receipt"]
    public_raw = published[0][1][1]
    assert legacy_raw not in [payload for _, payload in published[0]]
    assert b"execution_plan_path" not in public_raw
    assert receipt["private_legacy_receipt_sha256"] == _sha(legacy_raw)
    assert receipt["legacy_publication"] is False
    assert receipt["formal_decision"]["sha256"] == _sha(decision_raw)
    assert public_raw == v1._canonical_bytes(receipt)


def test_control_failure_prevents_v1_engine_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _full_paths(tmp_path)
    monkeypatch.setattr(v3, "_load_v3_modules", lambda: (object(), object(), object()))
    monkeypatch.setattr(
        v3,
        "_validate_revalidator_control_chain",
        lambda **_kwargs: (_ for _ in ()).throw(
            v3.RevalidationV3Error("opaque control failure")
        ),
    )
    opened = False

    def semantic_sentinel(**_kwargs: Any) -> dict[str, Any]:
        nonlocal opened
        opened = True
        raise AssertionError("semantic engine opened")

    monkeypatch.setattr(v1, "revalidate_terminal", semantic_sentinel)
    with pytest.raises(v3.RevalidationV3Error, match="opaque control failure"):
        v3.revalidate_terminal(
            root=paths["root"],
            execution_plan_path=paths["plan"],
            v2_failure_closure_path=paths["closure"],
            completion_fence_path=paths["fence"],
            attestation_path=paths["attestation"],
            launch_expectation_path=paths["expectation"],
            grid_path=paths["grid"],
            provenance_path=paths["provenance"],
            formal_manifest_path=paths["manifest"],
            formal_decision_path=paths["decision"],
            revalidated_output=paths["output"],
            receipt_output=paths["receipt"],
            preregistration_path=paths["prereg"],
            statistical_addendum_path=paths["addendum"],
        )
    assert opened is False


def test_cli_suppresses_branch_and_error_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _full_paths(tmp_path)
    monkeypatch.setattr(
        v3,
        "revalidate_terminal",
        lambda **_kwargs: (_ for _ in ()).throw(
            v3.RevalidationV3Error("secret internal_gate_pass detail")
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "revalidate-v3",
            "--execution-plan",
            str(paths["plan"]),
            "--v2-failure-closure",
            str(paths["closure"]),
            "--completion-fence",
            str(paths["fence"]),
            "--root",
            str(paths["root"]),
            "--attestation",
            str(paths["attestation"]),
            "--launch-expectation",
            str(paths["expectation"]),
            "--grid",
            str(paths["grid"]),
            "--provenance",
            str(paths["provenance"]),
            "--formal-manifest",
            str(paths["manifest"]),
            "--formal-decision",
            str(paths["decision"]),
            "--preregistration",
            str(paths["prereg"]),
            "--statistical-addendum",
            str(paths["addendum"]),
            "--output",
            str(paths["output"]),
            "--receipt",
            str(paths["receipt"]),
        ],
    )
    with pytest.raises(SystemExit) as failure:
        v3.main()
    assert failure.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
