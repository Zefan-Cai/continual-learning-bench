from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

import build_cohort_causal_terminal_execution_v3 as execution
import launch_cohort_causal_terminal_verifier_v3_detached as launcher


def _binding(path: Path) -> dict[str, str]:
    return {"path": path.as_posix(), "sha256": execution._sha(path.read_bytes())}


def test_v3_contract_and_fixed_schema_are_canonical() -> None:
    assert (
        execution.PLAN_PROTOCOL == "cohort_causal_terminal_verifier_execution_plan_v3"
    )
    assert execution.PLAN_SCHEMA_VERSION == 3
    assert execution.HANDOFF_PROTOCOL == launcher.HANDOFF_PROTOCOL
    assert execution.CLAIM_PROTOCOL == launcher.CLAIM_PROTOCOL
    assert execution.DETACHED_RECEIPT_PROTOCOL == launcher.RECEIPT_PROTOCOL
    assert execution.EXPECTED_PYTHON_PATH == launcher.EXPECTED_PYTHON_PATH
    assert launcher.MINIMUM_DELAY_SECONDS == 30
    assert launcher.DETACHED_LAUNCH_CONTRACT["receipt_same_pid_exec"] is True
    assert (
        launcher.DETACHED_LAUNCH_CONTRACT["claim_is_permanent_no_retry_boundary"]
        is True
    )
    assert launcher.DETACHED_LAUNCH_CONTRACT["semantic_artifacts_opened"] is False
    assert json.loads(execution.canonical_bytes(launcher.DETACHED_LAUNCH_CONTRACT)) == (
        launcher.DETACHED_LAUNCH_CONTRACT
    )
    assert set(launcher.HANDOFF_KEYS) == {
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
    assert execution.FAILURE_CLOSURE_FILENAME.endswith("_V1.json")
    assert execution.COMPLETION_FENCE_FILENAME.endswith("_V3.json")
    assert execution.PLAN_FILENAME.endswith("_V3.json")
    assert execution.LAUNCH_CLAIM_FILENAME.endswith("_V3_LAUNCH_CLAIM.json")
    assert execution.DETACHED_RECEIPT_FILENAME.endswith("_V3_DETACHED_RECEIPT.json")


def _mock_stage_validation_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict]:
    causal = tmp_path / "causal"
    durable = tmp_path / "attempt-002"
    control = durable / "control"
    tooling = control / "verifier" / ("1" * 40)
    plan_path = control / execution.PLAN_FILENAME
    base_plan_path = control / execution.v2.PLAN_FILENAME
    base_receipt_path = control / execution.v2.DETACHED_RECEIPT_FILENAME
    base_inventory_path = control / execution.v2.EXCEPTION_INVENTORY_FILENAME
    closure_path = control / execution.FAILURE_CLOSURE_FILENAME
    fence_path = control / execution.COMPLETION_FENCE_FILENAME
    launcher_path = tmp_path / "transport" / "launcher.py"
    handoff_path = tmp_path / "transport" / execution.DETACHED_HANDOFF_FILENAME
    claim_path = control / execution.LAUNCH_CLAIM_FILENAME
    receipt_path = control / execution.DETACHED_RECEIPT_FILENAME

    invocations = {
        stage: {
            "argv": [
                execution.EXPECTED_PYTHON_PATH,
                (tooling / execution.TOOL_FILENAMES[stage]).as_posix(),
                f"--{stage}",
            ],
            "inputs": {
                "registered_input": (
                    durable / "registered" / stage / "input.json"
                ).as_posix()
            },
            "outputs": {
                "registered_output": (
                    durable / "registered" / stage / "output.json"
                ).as_posix()
            },
            "parameters": {"registered_stage": stage},
        }
        for stage in ("attester", "execution_seal_builder", "revalidator")
    }
    base_plan = {
        "causal_checkout_root": causal.as_posix(),
        "durable_attempt_root": durable.as_posix(),
        "invocations": {
            "revalidator": {
                "inputs": {
                    "grid": (causal / "grid.json").as_posix(),
                    "preregistration": (causal / "preregistration.md").as_posix(),
                    "statistical_addendum": (causal / "addendum.md").as_posix(),
                }
            }
        },
    }

    def fake_binding(path: Path, _label: str) -> dict[str, str]:
        return {"path": path.as_posix(), "sha256": "a" * 64}

    science_inputs = base_plan["invocations"]["revalidator"]["inputs"]
    plan = {
        "attempt_id": "attempt-002",
        "base_v2": {
            "execution_plan": fake_binding(base_plan_path, "base plan"),
            "detached_receipt": fake_binding(base_receipt_path, "base receipt"),
            "procfs_exception_inventory": fake_binding(
                base_inventory_path, "base inventory"
            ),
        },
        "branch_adapter_contracts": {},
        "causal_checkout_root": causal.as_posix(),
        "created_at_utc": "2026-07-15T00:00:00Z",
        "detached_transport": {
            "handoff": fake_binding(handoff_path, "handoff"),
            "launch_claim_path": claim_path.as_posix(),
            "launcher": fake_binding(launcher_path, "launcher"),
            "receipt_path": receipt_path.as_posix(),
        },
        "durable_attempt_root": durable.as_posix(),
        "implementation_dependencies": {
            name: fake_binding(tooling / filename, name)
            for name, filename in execution.DEPENDENCY_FILENAMES.items()
        },
        "invocations": invocations,
        "public_truth": {
            "completion_method": "post-wrapper-death two-snapshot fence",
            "historical_exit_order_claimed": False,
            "legacy_strict_mtime_proof": False,
            "mtime_relation": (
                "formal_manifest_before_formal_decision_equal_wrapper_exit"
            ),
        },
        "recovery_controls": {
            "v2_failure_closure": fake_binding(closure_path, "closure"),
            "v3_completion_fence": fake_binding(fence_path, "fence"),
        },
        "runtime": {
            "python_path": execution.EXPECTED_PYTHON_PATH,
            "python_version": execution.EXPECTED_PYTHON_VERSION,
        },
        "science_invariants": {
            "base_v2_invocations_sha256": execution.canonical_sha256(
                base_plan["invocations"]
            ),
            "changed": False,
            "estimator_and_thresholds_changed": False,
            **{
                name: fake_binding(Path(science_inputs[name]), name)
                for name in ("grid", "preregistration", "statistical_addendum")
            },
        },
        "structured_preregistration": fake_binding(
            tooling / execution.STRUCTURED_PREREGISTRATION_FILENAME,
            "structured preregistration",
        ),
        "tooling_root": tooling.as_posix(),
        "tooling_source_commit": "1" * 40,
        "tools": {
            name: fake_binding(tooling / filename, name)
            for name, filename in execution.TOOL_FILENAMES.items()
        },
        "amendment": fake_binding(tooling / execution.AMENDMENT_FILENAME, "amendment"),
    }
    base_raw = {
        base_plan_path: b"base-plan",
        base_receipt_path: b"base-receipt",
        base_inventory_path: b"base-inventory",
        closure_path: b"closure",
        fence_path: b"fence",
        handoff_path: b"handoff",
    }
    base_controls = {
        "base_v2_execution_plan": base_plan,
        "base_v2_execution_plan_raw": base_raw[base_plan_path],
        "base_v2_detached_receipt_raw": base_raw[base_receipt_path],
        "base_v2_procfs_exception_inventory_raw": base_raw[base_inventory_path],
    }
    recovery_controls = {
        "closure": {},
        "closure_raw": base_raw[closure_path],
        "fence": {},
        "fence_raw": base_raw[fence_path],
    }
    handoff = {"registered": True}

    monkeypatch.setattr(execution, "_load_plan_document", lambda _path: (plan, b"plan"))
    monkeypatch.setattr(
        execution, "_load_base_v2_controls", lambda **_kwargs: base_controls
    )
    monkeypatch.setattr(
        execution, "_load_recovery_controls", lambda **_kwargs: recovery_controls
    )
    monkeypatch.setattr(execution, "_binding", fake_binding)
    monkeypatch.setattr(
        execution,
        "_validate_binding",
        lambda _value, *, expected_path, label: (
            expected_path,
            base_raw.get(expected_path, b"binding"),
        ),
    )
    monkeypatch.setattr(
        execution, "_validate_recovery_authority_bindings", lambda **_: None
    )
    monkeypatch.setattr(execution, "_branch_adapter_contracts", lambda **_: {})
    monkeypatch.setattr(
        execution, "_fixed_topology", lambda **_: copy.deepcopy(invocations)
    )
    monkeypatch.setattr(
        execution,
        "_transport_paths",
        lambda _commit, _durable: (
            launcher_path,
            handoff_path,
            claim_path,
            receipt_path,
        ),
    )
    monkeypatch.setattr(execution, "_strict_json", lambda _raw, _label: handoff)
    monkeypatch.setattr(execution, "make_detached_handoff", lambda **_: handoff)
    monkeypatch.setattr(
        execution, "_assert_no_symlink_descendant", lambda *_, **__: None
    )
    monkeypatch.setattr(execution, "_assert_durable_plan_bound_paths", lambda **_: None)
    return plan_path, plan


@pytest.mark.parametrize(
    ("stage", "mismatched_stage"),
    [
        ("attester", "revalidator"),
        ("revalidator", "execution_seal_builder"),
        ("execution_seal_builder", "attester"),
    ],
)
def test_requested_v3_stage_validates_only_its_registered_topology(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    mismatched_stage: str,
) -> None:
    plan_path, plan = _mock_stage_validation_plan(tmp_path, monkeypatch)
    registered = plan["invocations"][stage]
    loaded, raw = execution.load_and_validate_execution_plan_stage(
        execution_plan_path=plan_path,
        stage=stage,
        expected_inputs=registered["inputs"],
        expected_outputs=registered["outputs"],
        expected_parameters=registered["parameters"],
        actual_argv=registered["argv"],
        runtime_python_path=execution.EXPECTED_PYTHON_PATH,
        runtime_python_version=execution.EXPECTED_PYTHON_VERSION,
    )
    assert loaded is plan
    assert raw == b"plan"

    mismatch = plan["invocations"][mismatched_stage]
    with pytest.raises(
        execution.CausalExecutionV3Error, match="actual V3 stage topology differs"
    ):
        execution.load_and_validate_execution_plan_stage(
            execution_plan_path=plan_path,
            stage=stage,
            expected_inputs=mismatch["inputs"],
            expected_outputs=mismatch["outputs"],
            expected_parameters=mismatch["parameters"],
            actual_argv=registered["argv"],
            runtime_python_path=execution.EXPECTED_PYTHON_PATH,
            runtime_python_version=execution.EXPECTED_PYTHON_VERSION,
        )


def test_binding_rejects_byte_drift_and_symlink(tmp_path: Path) -> None:
    fixed = tmp_path / "fixed.json"
    fixed.write_bytes(b"{}")
    binding = _binding(fixed)
    path, raw = execution._validate_binding(
        binding, expected_path=fixed, label="fixed control"
    )
    assert path == fixed
    assert raw == b"{}"

    fixed.write_bytes(b'{"drift":true}')
    with pytest.raises(execution.CausalExecutionV3Error, match="bytes differ"):
        execution._validate_binding(binding, expected_path=fixed, label="fixed control")

    real = tmp_path / "real"
    real.mkdir()
    child = real / "child"
    child.write_text("control")
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(execution.CausalExecutionV3Error, match="symlink"):
        execution._assert_no_symlink_descendant(
            linked / "child", root=tmp_path, label="linked control"
        )


def test_transitive_dependency_byte_drift_fails_closed(tmp_path: Path) -> None:
    required = {
        "v1_completion_attester",
        "v2_completion_attester",
        "v1_execution_seal_engine",
        "v2_execution_seal_engine",
        "v1_revalidator_engine",
        "v2_transport_launcher",
        "legacy_online_icl_contract_engine",
        "legacy_structured_trigger_receipt_engine",
        "legacy_structured_trigger_receipt_revalidator_engine",
    }
    assert required < set(execution.DEPENDENCY_FILENAMES)
    dependency = tmp_path / "attest_cohort_causal_completion.py"
    dependency.write_text("frozen source")
    frozen = _binding(dependency)
    dependency.write_text("mutated source")
    with pytest.raises(execution.CausalExecutionV3Error, match="bytes differ"):
        execution._validate_binding(
            frozen,
            expected_path=dependency,
            label="transitive V1 dependency",
        )


def _recovery_authority_fixture(tmp_path: Path) -> tuple[dict, dict]:
    freezer = tmp_path / "freeze_cohort_causal_terminal_recovery_v3.py"
    freezer.write_text("registered recovery freezer")
    registered = _binding(freezer)
    closure_path = tmp_path / execution.FAILURE_CLOSURE_FILENAME
    closure_path.write_text("closure")
    closure_binding = _binding(closure_path)
    wrapper = {"pid": 101, "start_ticks": 202}
    incident = {
        "completion_method": "post-wrapper-death two-snapshot fence",
        "legacy_strict_mtime_proof": False,
    }
    plan = {
        "implementation_dependencies": {"recovery_freezer": registered},
        "recovery_controls": {"v2_failure_closure": closure_binding},
    }
    controls = {
        "closure": {
            "incident": copy.deepcopy(incident),
            "recovery_freezer": copy.deepcopy(registered),
            "wrapper": copy.deepcopy(wrapper),
        },
        "fence": {
            "failure_closure": copy.deepcopy(closure_binding),
            "incident": copy.deepcopy(incident),
            "recovery_freezer": copy.deepcopy(registered),
            "wrapper": copy.deepcopy(wrapper),
        },
    }
    return plan, controls


def test_recovery_source_substitution_with_rehashed_forgery_fails(
    tmp_path: Path,
) -> None:
    plan, controls = _recovery_authority_fixture(tmp_path)
    execution._validate_recovery_authority_bindings(plan=plan, controls=controls)
    forged = tmp_path / "forged_recovery_freezer.py"
    forged.write_text("different but self-consistently rehashed source")
    forged_binding = _binding(forged)
    controls["closure"]["recovery_freezer"] = copy.deepcopy(forged_binding)
    controls["fence"]["recovery_freezer"] = copy.deepcopy(forged_binding)
    with pytest.raises(execution.CausalExecutionV3Error, match="recovery freezer"):
        execution._validate_recovery_authority_bindings(plan=plan, controls=controls)


@pytest.mark.parametrize("field", ["wrapper", "incident"])
def test_closure_fence_authority_mismatch_fails(tmp_path: Path, field: str) -> None:
    plan, controls = _recovery_authority_fixture(tmp_path)
    controls["fence"][field]["unexpected_drift"] = True
    with pytest.raises(execution.CausalExecutionV3Error, match=field):
        execution._validate_recovery_authority_bindings(plan=plan, controls=controls)


def test_fence_must_bind_exact_plan_failure_closure(tmp_path: Path) -> None:
    plan, controls = _recovery_authority_fixture(tmp_path)
    controls["fence"]["failure_closure"] = {
        "path": (tmp_path / "substitute.json").as_posix(),
        "sha256": "f" * 64,
    }
    with pytest.raises(execution.CausalExecutionV3Error, match="failure-closure"):
        execution._validate_recovery_authority_bindings(plan=plan, controls=controls)


def test_stable_read_rejects_post_fd_pathname_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "bound-control.json"
    target.write_bytes(b"{}")
    real_lstat = execution.os.lstat

    def swapped_lstat(path: os.PathLike[str] | str) -> os.stat_result:
        metadata = real_lstat(path)
        if Path(path) != target:
            return metadata
        fields = list(metadata)
        fields[1] += 1
        return os.stat_result(fields)

    monkeypatch.setattr(execution.os, "lstat", swapped_lstat)
    with pytest.raises(execution.CausalExecutionV3Error, match="pathname changed"):
        execution._read_stable(target, "swapped control")


def test_publishers_are_no_overwrite_even_for_identical_bytes(tmp_path: Path) -> None:
    target = tmp_path / "one-shot.json"
    execution._publish_no_overwrite(target, b"{}", "one-shot test")
    assert target.read_bytes() == b"{}"
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        execution._publish_no_overwrite(target, b"{}", "one-shot test")

    launcher_target = tmp_path / "launcher-one-shot.json"
    launcher._publish_no_overwrite(launcher_target, b"{}", "launch claim")
    with pytest.raises(FileExistsError, match="permanently spent"):
        launcher._publish_no_overwrite(launcher_target, b"{}", "launch claim")


def test_launch_claim_binds_exact_future_exec_and_cannot_be_repurposed(
    tmp_path: Path,
) -> None:
    handoff = tmp_path / "handoff.json"
    plan = tmp_path / "plan.json"
    launcher_path = tmp_path / "launcher.py"
    for path in (handoff, plan, launcher_path):
        path.write_text(path.name)
    attester_argv = ["/usr/bin/python3.10", "/tmp/attester.py", "--fixed"]
    launcher_argv = ["/usr/bin/python3.10", "-I", "/tmp/launcher.py"]
    claimant = {"comm_sha256": "a" * 64, "pid": 101, "start_ticks": 202}
    claim = launcher._build_claim(
        attester_argv=attester_argv,
        claimant=claimant,
        handoff_binding=_binding(handoff),
        launcher_binding=_binding(launcher_path),
        launcher_argv=launcher_argv,
        plan_binding=_binding(plan),
        receipt_path=tmp_path / execution.DETACHED_RECEIPT_FILENAME,
    )
    assert set(claim) == launcher.CLAIM_KEYS
    assert claim["status"] == "claimed_once_permanent_no_retry"
    assert claim["attester_exec_argv_sha256"] == execution.canonical_sha256(
        attester_argv
    )
    mutated = copy.deepcopy(claim)
    mutated["receipt_path"] = (tmp_path / "different.json").as_posix()
    assert execution.canonical_sha256(mutated) != execution.canonical_sha256(claim)


def test_launcher_rejects_live_parent_on_pid_start_identity(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    entry = proc / "321"
    entry.mkdir(parents=True)
    fields = [b"S", b"1", *([b"0"] * 17), b"456"]
    (entry / "stat").write_bytes(b"321 (renamed) " + b" ".join(fields))
    parent = {"comm_sha256": "b" * 64, "pid": 321, "start_ticks": 456}
    with pytest.raises(launcher.DetachedLaunchV3Error, match="still live"):
        launcher._assert_startup_parent_gone(parent, proc_root=proc)
    parent["start_ticks"] = 457
    launcher._assert_startup_parent_gone(parent, proc_root=proc)
    with pytest.raises(execution.CausalExecutionV3Error, match="remains live"):
        execution._assert_process_identity_gone(321, 456, proc_root=proc)
    execution._assert_process_identity_gone(321, 457, proc_root=proc)


def test_branch_contracts_bind_all_authoritative_paths(tmp_path: Path) -> None:
    durable = tmp_path / "attempt-002"
    tooling = durable / "control" / "verifier" / ("a" * 40)
    tooling.mkdir(parents=True)
    for filename in execution.BRANCH_ADAPTER_FILENAMES.values():
        (tooling / filename).write_text(filename)
    contracts = execution._branch_adapter_contracts(
        tooling=tooling, durable=durable, causal_root=tmp_path / "causal"
    )
    expected_names = {
        "failure_closure",
        "completion_fence",
        "execution_plan",
        "launch_claim",
        "detached_receipt",
        "completion_attestation",
        "revalidated_decision",
        "revalidation_receipt",
        "execution_seal",
    }
    for name, contract in contracts.items():
        assert set(contract["fixed_authoritative_paths"]) == expected_names
        assert contract["source"] == _binding(
            tooling / execution.BRANCH_ADAPTER_FILENAMES[name]
        )
        assert contract["cli_exposed"] is False
        assert contract["publication"] is False
        assert contract["future_argv"] == []
        assert contract["post_reveal_child_plan_required"] is name.startswith(
            "online_icl"
        )


def test_no_symlink_check_allows_absent_final_one_shot_path(tmp_path: Path) -> None:
    control = tmp_path / "attempt-002" / "control"
    control.mkdir(parents=True)
    target = control / execution.LAUNCH_CLAIM_FILENAME
    execution._assert_no_symlink_descendant(
        target, root=tmp_path / "attempt-002", label="future claim"
    )
    assert not os.path.lexists(target)


def test_launcher_rejects_symlinked_durable_control_ancestor(tmp_path: Path) -> None:
    durable = tmp_path / "attempt-002"
    real = tmp_path / "real-control"
    durable.mkdir()
    real.mkdir()
    (durable / "control").symlink_to(real, target_is_directory=True)
    claim = durable / "control" / execution.LAUNCH_CLAIM_FILENAME
    with pytest.raises(launcher.DetachedLaunchV3Error, match="symlink"):
        launcher._assert_no_symlink_components(
            claim, root=durable, label="V3 launch claim"
        )
