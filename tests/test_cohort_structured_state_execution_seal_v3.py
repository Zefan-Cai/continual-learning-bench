from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import build_cohort_structured_state_execution_seal_v3 as seal


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _write(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _binding(path: str, raw: bytes) -> dict[str, Any]:
    return {"path": path, "sha256": _sha(raw), "size_bytes": len(raw)}


def _record(path: str, roles: list[str], raw: bytes, *, inode: int) -> dict[str, Any]:
    return {
        "device": 1,
        "inode": inode,
        "mtime_ns": 1_000_000_000 + inode,
        "path": path,
        "roles": sorted(roles),
        "sha256": _sha(raw),
        "size_bytes": len(raw),
    }


def _fixture(
    tmp_path: Path,
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, str], Path]:
    durable = (tmp_path / "durable" / "attempt-002").resolve()
    paths = {
        name: (durable / relative).as_posix()
        for name, relative in seal.AUTHORITATIVE_RELATIVE_PATHS.items()
    }
    branch_contracts = {"structured": {"publication": False}}
    invocations = {"attester": {"argv": ["python"]}}
    runtime = {"python_path": "/usr/bin/python3.10", "python_version": "3.10.12"}
    tools = {"attester": {"path": "/tmp/attester", "sha256": "a" * 64}}
    plan = {
        "branch_adapter_contracts": branch_contracts,
        "durable_attempt_root": durable.as_posix(),
        "invocations": invocations,
        "protocol": seal.execution_v3.PLAN_PROTOCOL,
        "runtime": runtime,
        "schema_version": seal.execution_v3.PLAN_SCHEMA_VERSION,
        "tooling_source_commit": "a" * 40,
        "tools": tools,
    }
    closure_raw = _canonical({"kind": "closure"})
    fence_raw = _canonical({"kind": "fence"})
    completion_proof = {
        "completion_fence_sha256": _sha(fence_raw),
        "completion_method": seal.COMPLETION_METHOD,
        "formal_decision_mtime_ns": 2_000_000_000,
        "formal_manifest_mtime_ns": 1_000_000_000,
        "historical_exit_order_claimed": False,
        "legacy_strict_mtime_proof": False,
        "mtime_relation": seal.MTIME_RELATION,
        "wrapper_exit_exact_zero_newline": True,
        "wrapper_exit_mtime_ns": 2_000_000_000,
        "wrapper_pid_dead": True,
    }
    attestation = {"completion_proof": completion_proof}
    revalidated_raw = _canonical({"private": "opaque result bytes"})
    receipt = {
        "decision": "valid_no_go",
        "decision_scope": "internal_gate_no_go",
        "revalidated_decision": {
            "path": paths["revalidated_decision"],
            "sha256": _sha(revalidated_raw),
        },
        "status": "valid",
    }
    artifacts = {
        "failure_closure": closure_raw,
        "completion_fence": fence_raw,
        "execution_plan": _canonical(plan),
        "launch_claim": _canonical({"kind": "claim"}),
        "detached_receipt": _canonical({"kind": "transport receipt"}),
        "completion_attestation": _canonical(attestation),
        "revalidated_decision": revalidated_raw,
        "revalidation_receipt": _canonical(receipt),
    }
    base_bindings = {
        name: _binding(f"/opaque/{name}", name.encode())
        for name in seal.BASE_BINDING_NAMES
    }
    for binding_name, artifact_name in {
        "causal_trigger_completion_attestation": "completion_attestation",
        "causal_revalidated": "revalidated_decision",
        "causal_revalidation_receipt": "revalidation_receipt",
        "execution_plan": "execution_plan",
    }.items():
        base_bindings[binding_name] = _binding(
            paths[artifact_name], artifacts[artifact_name]
        )
    pre_attestation_inventory = sorted(
        [
            _record(
                base_bindings["causal_original"]["path"],
                ["formal_decision"],
                b"causal_original",
                inode=1,
            ),
            _record(
                "/opaque/wrapper.exit",
                ["wrapper_exit_file"],
                b"0\n",
                inode=2,
            ),
            _record(
                "/opaque/wrapper.pid",
                ["wrapper_pid_file"],
                b"999\n",
                inode=3,
            ),
        ],
        key=lambda row: row["path"],
    )
    attestation_record = _record(
        paths["completion_attestation"],
        ["causal_trigger_completion_attestation"],
        artifacts["completion_attestation"],
        inode=4,
    )
    inventory = sorted(
        [*pre_attestation_inventory, attestation_record],
        key=lambda row: row["path"],
    )
    value = {
        "bindings": base_bindings,
        "branch_adapter_contracts": branch_contracts,
        "causal_classification": {
            "decision": "valid_no_go",
            "decision_scope": "internal_gate_no_go",
            "status": "valid",
        },
        "causal_completion_attestation_sha256": _sha(
            artifacts["completion_attestation"]
        ),
        "causal_decision_sha256": "c" * 64,
        "causal_exit_file_sha256": _sha(b"0\n"),
        "causal_inventory": inventory,
        "causal_inventory_recheck_matches_attestation": True,
        "causal_inventory_sha256": _sha(_canonical(inventory)),
        "causal_original_file_sha256": _sha(b"causal_original"),
        "causal_pid_file_sha256": _sha(b"999\n"),
        "causal_pre_attestation_inventory_sha256": _sha(
            _canonical(pre_attestation_inventory)
        ),
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": seal.v1.CAUSAL_PROTOCOL_SEAL_STATUS,
        "causal_revalidation_file_sha256": _sha(revalidated_raw),
        "causal_source_commit": "b" * 40,
        "completion_attestation_v3": {
            "path": paths["completion_attestation"],
            "sha256": _sha(artifacts["completion_attestation"]),
        },
        "completion_fence": {
            "path": paths["completion_fence"],
            "sha256": _sha(artifacts["completion_fence"]),
        },
        "completion_method": seal.COMPLETION_METHOD,
        "completion_proof": completion_proof,
        "created_at_utc": "2026-07-14T12:00:00Z",
        "historical_exit_order_claimed": False,
        "legacy_publication": False,
        "legacy_strict_mtime_proof": False,
        "mtime_relation": seal.MTIME_RELATION,
        "online_icl_decision_sha256": None,
        "online_icl_inventory_recheck_matches_marker": None,
        "online_icl_inventory_sha256": None,
        "online_icl_original_file_sha256": None,
        "online_icl_protocol_seal_sha256": None,
        "online_icl_revalidation_file_sha256": None,
        "online_icl_wrapper_contract_sha256": None,
        "online_icl_wrapper_exit_marker_sha256": None,
        "protocol": seal.SEAL_PROTOCOL,
        "revalidation_receipt_v3": {
            "path": paths["revalidation_receipt"],
            "sha256": _sha(artifacts["revalidation_receipt"]),
        },
        "schema_version": seal.SEAL_SCHEMA_VERSION,
        "semantic_revalidation_completed": True,
        "status": "sealed",
        "terminal_verifier_execution_plan_path": paths["execution_plan"],
        "terminal_verifier_execution_plan_sha256": _sha(artifacts["execution_plan"]),
        "tooling_source_commit": "a" * 40,
        "trigger_branch": "causal_valid_no_go",
        "v2_failure_closure": {
            "path": paths["failure_closure"],
            "sha256": _sha(artifacts["failure_closure"]),
        },
        "verifier_execution": {
            "invocations": invocations,
            "invocations_sha256": _sha(_canonical(invocations)),
            "runtime": runtime,
            "tools": tools,
        },
    }
    assert set(value) == seal.SEAL_KEYS
    artifacts["execution_seal"] = _canonical(value)
    return value, artifacts, paths, durable


def _validate(
    value: dict[str, Any],
    artifacts: dict[str, bytes],
    paths: dict[str, str],
    durable: Path,
) -> dict[str, Any]:
    return seal.validate_execution_seal_document(
        value,
        durable_attempt_root=durable,
        artifact_bytes=artifacts,
        artifact_paths=paths,
    )


def test_authoritative_v3_seal_projection_is_exact(tmp_path: Path) -> None:
    value, artifacts, paths, durable = _fixture(tmp_path)
    assert _validate(value, artifacts, paths, durable) == value


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"extra": True}), "schema differs"),
        (
            lambda value: value.update({"legacy_strict_mtime_proof": True}),
            "truth claims differ",
        ),
        (
            lambda value: value.update({"online_icl_decision_sha256": "0" * 64}),
            "base seal truth fields differ",
        ),
        (
            lambda value: value["bindings"]["execution_plan"].update(
                {"sha256": "0" * 64}
            ),
            "base seal digest projection differs",
        ),
    ],
)
def test_public_seal_mutations_fail_closed(
    tmp_path: Path, mutation: Any, message: str
) -> None:
    value, artifacts, paths, durable = _fixture(tmp_path)
    mutation(value)
    artifacts["execution_seal"] = _canonical(value)
    with pytest.raises(seal.ExecutionSealV3Error, match=message):
        _validate(value, artifacts, paths, durable)


def test_plan_projection_drift_fails_closed(tmp_path: Path) -> None:
    value, artifacts, paths, durable = _fixture(tmp_path)
    plan = json.loads(artifacts["execution_plan"])
    plan["tooling_source_commit"] = "9" * 40
    artifacts["execution_plan"] = _canonical(plan)
    value["terminal_verifier_execution_plan_sha256"] = _sha(artifacts["execution_plan"])
    value["bindings"]["execution_plan"] = _binding(
        paths["execution_plan"], artifacts["execution_plan"]
    )
    artifacts["execution_seal"] = _canonical(value)
    with pytest.raises(seal.ExecutionSealV3Error, match="plan projection differs"):
        _validate(value, artifacts, paths, durable)


def test_noncanonical_receipt_and_missing_artifact_fail_closed(tmp_path: Path) -> None:
    value, artifacts, paths, durable = _fixture(tmp_path)
    artifacts["revalidation_receipt"] += b"\n"
    value["revalidation_receipt_v3"]["sha256"] = _sha(artifacts["revalidation_receipt"])
    value["bindings"]["causal_revalidation_receipt"] = _binding(
        paths["revalidation_receipt"], artifacts["revalidation_receipt"]
    )
    artifacts["execution_seal"] = _canonical(value)
    with pytest.raises(seal.ExecutionSealV3Error, match="not canonical object bytes"):
        _validate(value, artifacts, paths, durable)

    value, artifacts, paths, durable = _fixture(tmp_path / "missing")
    del artifacts["launch_claim"]
    with pytest.raises(seal.ExecutionSealV3Error, match="artifact names differ"):
        _validate(value, artifacts, paths, durable)


def test_completion_and_receipt_branch_drift_fail_closed(tmp_path: Path) -> None:
    value, artifacts, paths, durable = _fixture(tmp_path)
    bad = copy.deepcopy(value["completion_proof"])
    bad["historical_exit_order_claimed"] = True
    value["completion_proof"] = bad
    artifacts["execution_seal"] = _canonical(value)
    with pytest.raises(seal.ExecutionSealV3Error, match="completion proof differs"):
        _validate(value, artifacts, paths, durable)

    value, artifacts, paths, durable = _fixture(tmp_path / "branch")
    receipt = json.loads(artifacts["revalidation_receipt"])
    receipt.update({"decision": "pass", "decision_scope": "internal_gate_pass"})
    artifacts["revalidation_receipt"] = _canonical(receipt)
    value["revalidation_receipt_v3"]["sha256"] = _sha(artifacts["revalidation_receipt"])
    value["bindings"]["causal_revalidation_receipt"] = _binding(
        paths["revalidation_receipt"], artifacts["revalidation_receipt"]
    )
    artifacts["execution_seal"] = _canonical(value)
    with pytest.raises(seal.ExecutionSealV3Error, match="projection differs"):
        _validate(value, artifacts, paths, durable)


def test_control_binding_and_completion_proof_schema_fail_closed(
    tmp_path: Path,
) -> None:
    value, artifacts, paths, durable = _fixture(tmp_path)
    value["completion_fence"]["path"] = "relative/control.json"
    artifacts["execution_seal"] = _canonical(value)
    with pytest.raises(seal.ExecutionSealV3Error, match="binding path differs"):
        _validate(value, artifacts, paths, durable)


def test_public_v3_receipt_projection_is_private_and_exact(tmp_path: Path) -> None:
    _, artifacts, _, _ = _fixture(tmp_path)
    receipt = json.loads(artifacts["revalidation_receipt"])
    receipt.update(
        {
            "execution_plan": {"path": "/opaque/plan", "sha256": "1" * 64},
            "formal_decision": {
                "path": "/opaque/decision",
                "sha256": "2" * 64,
            },
            "formal_manifest": {
                "path": "/opaque/manifest",
                "sha256": "3" * 64,
            },
            "legacy_publication": False,
            "private_legacy_receipt_sha256": "4" * 64,
            "protocol": "public-v3-only",
        }
    )
    projected = seal._project_receipt_for_v1(receipt)
    assert set(projected) == seal.v1.REVALIDATION_RECEIPT_KEYS
    assert projected["execution_plan_path"] == "/opaque/plan"
    assert "protocol" not in projected
    assert "private_legacy_receipt_sha256" not in projected
    assert "legacy_publication" not in projected

    value, artifacts, paths, durable = _fixture(tmp_path / "proof")
    value["completion_proof"]["semantic_open_sentinel"] = {"opened": True}
    artifacts["execution_seal"] = _canonical(value)
    with pytest.raises(seal.ExecutionSealV3Error, match="completion proof differs"):
        _validate(value, artifacts, paths, durable)


def test_downstream_default_is_branch_truthful_and_rejects_injected_projection(
    tmp_path: Path,
) -> None:
    value, artifacts, paths, durable = _fixture(tmp_path)
    documents = {name: json.loads(raw) for name, raw in artifacts.items()}
    context = {
        "artifact_bytes": artifacts,
        "artifact_paths": paths,
        "durable_attempt_root": durable,
        "execution_seal": value,
        "revalidation_receipt": documents["revalidation_receipt"],
    }
    with pytest.raises(
        seal.ExecutionSealV3Error,
        match="structured future absence-evidence projection is not preregistered",
    ):
        seal.build_downstream_private_projection(
            adapter_kind="structured_trigger_no_go",
            artifacts=documents,
            **context,
        )
    with pytest.raises(
        seal.ExecutionSealV3Error,
        match="unregistered downstream private projection input is forbidden",
    ):
        seal.build_downstream_private_projection(
            adapter_kind="structured_trigger_no_go",
            artifacts=documents,
            plan_bound_private_projection={"builder_kwargs": {"unsafe": True}},
            **context,
        )

    pass_documents = copy.deepcopy(documents)
    pass_artifacts = dict(artifacts)
    pass_paths = dict(paths)
    del pass_documents["execution_seal"]
    del pass_artifacts["execution_seal"]
    del pass_paths["execution_seal"]
    pass_receipt = copy.deepcopy(pass_documents["revalidation_receipt"])
    pass_receipt.update({"decision": "pass", "decision_scope": "internal_gate_pass"})
    pass_documents["revalidation_receipt"] = pass_receipt
    pass_artifacts["revalidation_receipt"] = _canonical(pass_receipt)
    with pytest.raises(
        seal.ExecutionSealV3Error,
        match="online-ICL future child plan is not preregistered",
    ):
        seal.build_downstream_private_projection(
            adapter_kind="online_icl_future_pass",
            artifacts=pass_documents,
            artifact_bytes=pass_artifacts,
            artifact_paths=pass_paths,
            durable_attempt_root=durable,
            execution_seal=None,
            revalidation_receipt=pass_receipt,
        )


def test_output_no_overwrite_and_dangling_symlink_fail_before_plan_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"preserve")
    monkeypatch.setattr(
        seal.execution_v3,
        "load_and_validate_execution_plan_stage",
        lambda **_: pytest.fail("plan must not be opened after no-overwrite gate"),
    )
    kwargs = {
        "execution_plan_path": tmp_path / "plan.json",
        "v2_failure_closure_path": tmp_path / "closure.json",
        "completion_fence_path": tmp_path / "fence.json",
        "attestation_path": tmp_path / "attestation.json",
        "launch_expectation_path": tmp_path / "expectation.json",
        "causal_original_path": tmp_path / "original.json",
        "causal_revalidated_path": tmp_path / "revalidated.json",
        "revalidation_receipt_path": tmp_path / "receipt.json",
        "structured_preregistration_path": tmp_path / "structured.md",
    }
    with pytest.raises(FileExistsError, match="pre-existing"):
        seal.build_and_publish_execution_seal(output=existing, **kwargs)
    assert existing.read_bytes() == b"preserve"

    dangling = tmp_path / "dangling.json"
    dangling.symlink_to(tmp_path / "absent-target.json")
    with pytest.raises(FileExistsError, match="pre-existing"):
        seal.build_and_publish_execution_seal(output=dangling, **kwargs)
    assert dangling.is_symlink()


def _load_legacy_seal_test_module() -> ModuleType:
    path = Path(__file__).with_name("test_cohort_structured_state_execution_seal.py")
    spec = importlib.util.spec_from_file_location("_v3_legacy_seal_fixture", path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load legacy seal fixture")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _full_builder_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    receipt_decision: str = "valid_no_go",
    drift_recovery_on_final_check: bool = False,
) -> tuple[dict[str, Any], dict[str, Path]]:
    """Use V1's realistic inventory engine behind the private V3 adapters."""

    legacy_module = _load_legacy_seal_test_module()
    legacy = legacy_module.sealed_trigger_fixture.__wrapped__(tmp_path)
    private_attestation = json.loads(legacy["attestation"].read_bytes())
    attested_files = copy.deepcopy(private_attestation["snapshots"][0]["files"])
    durable = Path(legacy["plan"]["durable_attempt_root"])
    prep = durable / "prep"
    control = durable / "control"
    plan_path = control / seal.PLAN_FILENAME
    attestation_path = prep / seal.ATTESTATION_FILENAME
    revalidated_path = prep / seal.REVALIDATED_FILENAME
    receipt_path = prep / seal.REVALIDATION_RECEIPT_FILENAME
    output = prep / seal.SEAL_FILENAME

    closure = {"protocol": "test-v3-closure", "status": "closed"}
    closure_raw = _canonical(closure)
    fence = {"protocol": "test-v3-fence", "status": "frozen"}
    fence_raw = _canonical(fence)
    proof = {
        "completion_fence_sha256": _sha(fence_raw),
        "completion_method": seal.COMPLETION_METHOD,
        "formal_decision_mtime_ns": 2_000_000_000,
        "formal_manifest_mtime_ns": 1_000_000_000,
        "historical_exit_order_claimed": False,
        "legacy_strict_mtime_proof": False,
        "mtime_relation": seal.MTIME_RELATION,
        "wrapper_exit_exact_zero_newline": True,
        "wrapper_exit_mtime_ns": 2_000_000_000,
        "wrapper_pid_dead": True,
    }
    public_attestation = {"completion_proof": proof, "public": "V3-only"}
    public_attestation_raw = _canonical(public_attestation)
    _write(attestation_path, public_attestation_raw)
    _write(revalidated_path, legacy["decision"].read_bytes())

    plan = copy.deepcopy(legacy["plan"])
    plan.update(
        {
            "base_v2": {
                "detached_receipt": {"path": "/opaque/v2-receipt"},
                "execution_plan": {"path": "/opaque/v2-plan"},
                "procfs_exception_inventory": {"path": "/opaque/v2-procfs"},
            },
            "branch_adapter_contracts": {
                "structured_trigger_receipt_adapter": {
                    "publication": False,
                    "protocol": "test-registered-adapter",
                }
            },
            "detached_transport": {
                "receipt_path": (control / "fresh-v3-receipt.json").as_posix()
            },
            "outcome_blind": True,
            "protocol": seal.execution_v3.PLAN_PROTOCOL,
            "public_truth": dict(seal.TRUTH_FIELDS),
            "schema_version": seal.execution_v3.PLAN_SCHEMA_VERSION,
        }
    )
    plan_raw = _canonical(plan)
    _write(plan_path, plan_raw)

    manifest_path = Path(legacy["artifact"]) / "formal_manifest.json"
    decision_scope = (
        "internal_gate_no_go"
        if receipt_decision == "valid_no_go"
        else "internal_gate_pass"
    )
    receipt = {
        "completion_attestation": {
            "path": attestation_path.as_posix(),
            "sha256": _sha(public_attestation_raw),
        },
        "completion_fence": {
            "path": (control / seal.recovery_v3.COMPLETION_FENCE_FILENAME).as_posix(),
            "sha256": _sha(fence_raw),
        },
        "completion_method": seal.COMPLETION_METHOD,
        "decision": receipt_decision,
        "decision_scope": decision_scope,
        "execution_plan": {
            "path": plan_path.as_posix(),
            "sha256": _sha(plan_raw),
        },
        "formal_decision": {
            "path": legacy["decision"].as_posix(),
            "sha256": _sha(legacy["decision"].read_bytes()),
        },
        "formal_manifest": {
            "path": manifest_path.as_posix(),
            "sha256": _sha(manifest_path.read_bytes()),
        },
        "historical_exit_order_claimed": False,
        "legacy_publication": False,
        "legacy_strict_mtime_proof": False,
        "mtime_relation": seal.MTIME_RELATION,
        "private_legacy_receipt_sha256": "9" * 64,
        "protocol": "cohort_causal_terminal_revalidation_receipt_v3",
        "revalidated_decision": {
            "path": revalidated_path.as_posix(),
            "sha256": _sha(revalidated_path.read_bytes()),
        },
        "revalidated_decision_byte_identical": True,
        "schema_version": 3,
        "status": "valid",
        "v2_failure_closure": {
            "path": (control / seal.recovery_v3.FAILURE_CLOSURE_FILENAME).as_posix(),
            "sha256": _sha(closure_raw),
        },
    }
    receipt_raw = _canonical(receipt)
    _write(receipt_path, receipt_raw)

    monkeypatch.setattr(
        seal.execution_v3,
        "load_and_validate_execution_plan_stage",
        lambda **_: (copy.deepcopy(plan), plan_raw),
    )
    recovery_calls = 0

    def load_recovery(**_: Any):
        nonlocal recovery_calls
        recovery_calls += 1
        if drift_recovery_on_final_check and recovery_calls == 2:
            drifted = {**fence, "drift": True}
            return (
                copy.deepcopy(closure),
                closure_raw,
                drifted,
                _canonical(drifted),
                copy.deepcopy(attested_files),
            )
        return (
            copy.deepcopy(closure),
            closure_raw,
            copy.deepcopy(fence),
            fence_raw,
            copy.deepcopy(attested_files),
        )

    monkeypatch.setattr(seal, "_load_recovery_controls", load_recovery)
    detached_receipt_raw = _canonical({"private": "static transport"})

    def load_attestation(**_: Any):
        return (
            copy.deepcopy(public_attestation),
            public_attestation_raw,
            copy.deepcopy(private_attestation),
            copy.deepcopy(attested_files),
            detached_receipt_raw,
        )

    monkeypatch.setattr(seal, "_load_attestation_chain", load_attestation)
    monkeypatch.setattr(
        seal,
        "_load_revalidation_module",
        lambda: SimpleNamespace(
            validate_revalidation_receipt_document=lambda value, **_: copy.deepcopy(
                value
            )
        ),
    )
    kwargs = {
        "execution_plan_path": plan_path,
        "v2_failure_closure_path": control / seal.recovery_v3.FAILURE_CLOSURE_FILENAME,
        "completion_fence_path": control / seal.recovery_v3.COMPLETION_FENCE_FILENAME,
        "attestation_path": attestation_path,
        "launch_expectation_path": legacy["expectation"],
        "causal_original_path": legacy["decision"],
        "causal_revalidated_path": revalidated_path,
        "revalidation_receipt_path": receipt_path,
        "structured_preregistration_path": legacy["structured_preregistration"],
        "output": output,
        "now_fn": lambda: "2026-07-14T12:00:03Z",
    }
    return kwargs, {
        "output": output,
        "receipt": receipt_path,
        "revalidated": revalidated_path,
    }


def test_full_no_go_runs_real_v1_engine_but_publishes_only_truthful_v3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, paths = _full_builder_fixture(tmp_path, monkeypatch)
    result = seal.build_and_publish_execution_seal(**kwargs)
    payload = paths["output"].read_bytes()
    value = json.loads(payload)
    assert payload == _canonical(value)
    assert result["seal_sha256"] == _sha(payload)
    assert value["protocol"] == seal.SEAL_PROTOCOL
    assert value["causal_classification"] == seal.EXPECTED_NO_GO
    assert value["legacy_strict_mtime_proof"] is False
    assert value["historical_exit_order_claimed"] is False
    assert value["legacy_publication"] is False
    assert "semantic_open_sentinel" not in value
    assert "outcome_blind" not in value
    assert "private_legacy_receipt_sha256" not in value


def test_pass_branch_never_enters_v1_seal_engine_or_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, paths = _full_builder_fixture(
        tmp_path, monkeypatch, receipt_decision="pass"
    )
    monkeypatch.setattr(
        seal.v1,
        "build_and_publish_execution_seal",
        lambda **_: pytest.fail("pass branch must not enter the V1 seal engine"),
    )
    with pytest.raises(seal.ExecutionSealV3Error, match="not authorized"):
        seal.build_and_publish_execution_seal(**kwargs)
    assert not paths["output"].exists()


def test_final_recovery_control_drift_aborts_after_private_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, paths = _full_builder_fixture(
        tmp_path, monkeypatch, drift_recovery_on_final_check=True
    )
    with pytest.raises(seal.ExecutionSealV3Error, match="recovery controls drifted"):
        seal.build_and_publish_execution_seal(**kwargs)
    assert not paths["output"].exists()
