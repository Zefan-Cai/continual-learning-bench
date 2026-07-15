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
