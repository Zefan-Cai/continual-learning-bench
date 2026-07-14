from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from build_cohort_online_icl_formal_wrapper_contract import (
    BUILDER_FILENAME,
    CHECKOUT_GIT_AUTHORIZATION_SCOPE,
    CONTRACT_EXPECTATION_RELATIVE_PATH,
    CONTRACT_RELATIVE_PATH,
    DIRECT_INPUT_RELATIVE_PATHS,
    DIRECT_INPUT_NAMES,
    LAUNCHER_FILENAME,
    MARKER_RELATIVE_PATH,
    ONLINE_SOURCE_COMMIT,
    PAIRED_CAUSAL_SOURCE_COMMIT,
    PID_RELATIVE_PATH,
    PROTOCOL,
    PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH,
    WRAPPER_FILENAME,
    ContractError,
    _default_git_checker,
    canonical_bytes,
    canonical_sha256,
    create_contract as _create_contract,
    create_contract_expectation,
    create_prospective_execution_plan,
    load_contract as _load_contract,
    load_contract_expectation,
    load_prospective_execution_plan,
    publish_contract as _publish_contract,
    publish_contract_expectation,
    publish_prospective_execution_plan,
    verify_contract as _verify_contract,
)


COMMIT = "a" * 40


def _git_ok(_root: Path, _expected_commit: str) -> None:
    return None


def _runtime_ok(tooling: Path, online: Path) -> dict:
    return {
        "cwd": str(online),
        "environment": {
            "HOME": "/sealed-home",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": f"{tooling}/runtime-bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TZ": "UTC",
        },
        "executables": {"python": {"sha256": "1" * 64}},
        "forbidden_environment_keys": [
            "BASH_ENV",
            "ENV",
            "LD_PRELOAD",
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONSTARTUP",
        ],
        "python_shim_target": "/usr/bin/python3.10",
    }


def _chain_ok(_paths: dict[str, Path], _checkout: Path, _durable: Path) -> dict:
    return {
        "decision": "pass",
        "decision_scope": "internal_gate_pass",
        "decision_status": "valid",
        "execution_plan_sha256": "2" * 64,
        "hard_gate": {
            "decision": "pass",
            "decision_scope": "internal_gate_pass",
            "status": "valid",
        },
        "semantic_revalidation_status": "not_semantically_revalidated",
        "status": "synthetic_shape_only",
    }


def create_contract(**kwargs):
    kwargs.setdefault("runtime_binding_provider", _runtime_ok)
    kwargs.setdefault("causal_chain_validator", _chain_ok)
    return _create_contract(**kwargs)


def verify_contract(contract, **kwargs):
    kwargs.setdefault("runtime_binding_provider", _runtime_ok)
    kwargs.setdefault("causal_chain_validator", _chain_ok)
    return _verify_contract(contract, **kwargs)


def load_contract(path, **kwargs):
    kwargs.setdefault("runtime_binding_provider", _runtime_ok)
    kwargs.setdefault("causal_chain_validator", _chain_ok)
    return _load_contract(path, **kwargs)


def publish_contract(path, contract, **kwargs):
    kwargs.setdefault("runtime_binding_provider", _runtime_ok)
    kwargs.setdefault("causal_chain_validator", _chain_ok)
    return _publish_contract(path, contract, **kwargs)


def _write(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _fixture(tmp_path: Path) -> tuple[dict, dict[str, Path]]:
    online = tmp_path / "online-checkout"
    causal = tmp_path / "causal-checkout"
    causal_durable = tmp_path / "causal-durable" / "attempt-002"
    durable = tmp_path / "durable" / "attempt-002"
    tooling = durable / "control" / "wrapper" / COMMIT
    for root in (online, causal, causal_durable, durable, tooling):
        root.mkdir(parents=True)
    online_artifact = durable / "artifacts" / "cohort_online_icl"
    causal_artifact = causal_durable / "artifacts" / "cohort_causal"
    online_artifact.mkdir(parents=True)
    causal_artifact.mkdir(parents=True)
    (online / "artifacts").mkdir()
    (online / "artifacts" / "cohort_online_icl").symlink_to(online_artifact)
    (causal / "artifacts").symlink_to(causal_durable / "artifacts")
    _write(online / LAUNCHER_FILENAME, b"#!/bin/sh\nexit 0\n")
    _write(tooling / WRAPPER_FILENAME, b"# runtime wrapper\n")
    _write(tooling / BUILDER_FILENAME, b"# exact contract builder\n")

    direct: dict[str, Path] = {}
    for index, name in enumerate(DIRECT_INPUT_NAMES):
        root = causal_durable if name.startswith("causal_") else durable
        direct[name] = _write(
            root / DIRECT_INPUT_RELATIVE_PATHS[name], f"{index}\n".encode()
        )
    contract = create_contract(
        tooling_source_commit=COMMIT,
        online_attempt_checkout=online.resolve(),
        paired_causal_attempt_checkout=causal.resolve(),
        paired_causal_durable_attempt_root=causal_durable.resolve(),
        durable_attempt_root=durable.resolve(),
        wrapper_tooling_root=tooling.resolve(),
        direct_inputs=direct,
        created_at_utc="2026-07-14T12:00:00.000000Z",
        git_checker=_git_ok,
    )
    return contract, {
        "online": online.resolve(),
        "causal": causal.resolve(),
        "causal_durable": causal_durable.resolve(),
        "durable": durable.resolve(),
        "tooling": tooling.resolve(),
        **direct,
    }


def _reseal(contract: dict) -> dict:
    contract = copy.deepcopy(contract)
    contract.pop("contract_sha256", None)
    contract["contract_sha256"] = canonical_sha256(contract)
    return contract


def test_contract_binds_separate_roots_three_source_hashes_and_exact_argv(
    tmp_path: Path,
) -> None:
    contract, paths = _fixture(tmp_path)
    assert verify_contract(contract, git_checker=_git_ok) is contract
    assert contract["protocol"] == PROTOCOL
    assert contract["online_source_commit"] == ONLINE_SOURCE_COMMIT
    assert contract["paired_causal_source_commit"] == PAIRED_CAUSAL_SOURCE_COMMIT
    assert contract["checkout_git_state"] == {
        "authorization_scope": CHECKOUT_GIT_AUTHORIZATION_SCOPE,
        "online": {
            "source_commit": ONLINE_SOURCE_COMMIT,
            "tracked_checkout_clean": True,
        },
        "paired_causal": {
            "source_commit": PAIRED_CAUSAL_SOURCE_COMMIT,
            "tracked_checkout_clean": True,
        },
    }
    assert contract["tooling_source_commit"] == COMMIT
    assert set(contract["source_files"]) == {
        "contract_builder",
        "online_launcher",
        "runtime_wrapper",
    }
    for record in contract["source_files"].values():
        assert len(record["sha256"]) == 64
        assert record["size_bytes"] > 0
    assert Path(contract["wrapper_tooling_root"]) == (
        paths["durable"] / "control" / "wrapper" / COMMIT
    )
    assert contract["paired_causal_durable_attempt_root"] == str(
        paths["causal_durable"]
    )
    for name in (
        "causal_completion_attestation",
        "causal_decision",
        "causal_launch_expectation",
        "causal_manifest",
        "causal_revalidated_decision",
        "causal_revalidation_receipt",
        "causal_terminal_execution_plan",
    ):
        assert Path(contract["direct_inputs"][name]["path"]).is_relative_to(
            paths["causal_durable"]
        )
    expected = [
        str(paths["online"] / LAUNCHER_FILENAME),
        "formal",
        "--provenance",
        str(paths["online_provenance"]),
        "--protocol-seal",
        str(paths["protocol_seal"]),
        "--gpus",
        "0,2,3",
        "--causal-smoke-gate",
        str(paths["causal_smoke_gate"]),
        "--causal-provenance",
        str(paths["causal_provenance"]),
        "--causal-root",
        str(paths["causal"]),
        "--causal-manifest",
        str(paths["causal_manifest"]),
        "--causal-decision",
        str(paths["causal_revalidated_decision"]),
        "--icl-smoke-gate",
        str(paths["icl_smoke_gate"]),
        "--max-used-memory-mib",
        "1024",
    ]
    assert contract["exact_formal_argv"] == expected
    assert contract["exact_formal_argv_sha256"] == canonical_sha256(expected)
    assert contract["fixed_paths"]["pid_file"] == str(
        paths["durable"] / PID_RELATIVE_PATH
    )
    assert contract["fixed_paths"]["completion_marker"] == str(
        paths["durable"] / MARKER_RELATIVE_PATH
    )
    assert contract["direct_input_layout"] == {
        name: {
            "relative_path": DIRECT_INPUT_RELATIVE_PATHS[name].as_posix(),
            "root": (
                "paired_causal_durable_attempt_root"
                if name.startswith("causal_")
                else "durable_attempt_root"
            ),
        }
        for name in DIRECT_INPUT_NAMES
    }
    assert contract["runtime"] == _runtime_ok(paths["tooling"], paths["online"])
    assert contract["causal_chain_binding"]["status"] == "synthetic_shape_only"
    assert Path(contract["artifact_mappings"]["online"]["durable_path"]) == (
        paths["durable"] / "artifacts" / "cohort_online_icl"
    )
    assert Path(contract["direct_inputs"]["online_provenance"]["path"]) == (
        paths["durable"] / "meta" / "provenance.json"
    )
    assert Path(contract["direct_inputs"]["protocol_seal"]["path"]) == (
        paths["durable"] / "meta" / "protocol_seal.json"
    )
    causal_mapping = contract["artifact_mappings"]["paired_causal"]
    assert Path(causal_mapping["checkout_path"]) == paths["causal"] / "artifacts"
    assert Path(causal_mapping["durable_path"]) == paths["causal_durable"] / "artifacts"
    assert Path(causal_mapping["cohort_child_durable_path"]) == (
        paths["causal_durable"] / "artifacts" / "cohort_causal"
    )


def test_publish_is_canonical_o_excl_and_strictly_reloadable(tmp_path: Path) -> None:
    contract, paths = _fixture(tmp_path)
    output = paths["durable"] / CONTRACT_RELATIVE_PATH
    publish_contract(output, contract, git_checker=_git_ok)
    assert output.read_bytes() == canonical_bytes(contract) + b"\n"
    assert stat.S_IMODE(output.stat().st_mode) == 0o444
    assert load_contract(output, git_checker=_git_ok) == contract
    with pytest.raises(FileExistsError, match="overwrite"):
        publish_contract(output, contract, git_checker=_git_ok)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"extra": 1}), "exact-key schema"),
        (
            lambda value: value["fixed_paths"].update(
                {"pid_file": value["fixed_paths"]["pid_file"] + ".other"}
            ),
            "fixed control/prep paths",
        ),
        (
            lambda value: value["exact_formal_argv"].append("--unregistered"),
            "exact formal argv differs",
        ),
        (
            lambda value: value["source_files"]["runtime_wrapper"].update(
                {"path": value["source_files"]["contract_builder"]["path"]}
            ),
            "source file path differs",
        ),
    ],
)
def test_strict_verify_rejects_resealed_schema_path_and_argv_tampering(
    tmp_path: Path, mutation, message: str
) -> None:
    contract, _paths = _fixture(tmp_path)
    mutation(contract)
    contract = _reseal(contract)
    with pytest.raises(ContractError, match=message):
        verify_contract(contract, verify_current_files=False, git_checker=_git_ok)


def test_verify_rejects_self_digest_and_current_file_drift(tmp_path: Path) -> None:
    contract, paths = _fixture(tmp_path)
    changed = copy.deepcopy(contract)
    changed["created_at_utc"] = "2026-07-14T12:00:01.000000Z"
    with pytest.raises(ContractError, match="self-digest"):
        verify_contract(changed, verify_current_files=False, git_checker=_git_ok)

    paths["online_provenance"].write_bytes(b"changed\n")
    with pytest.raises(ContractError, match="current file differs"):
        verify_contract(contract, verify_current_files=True, git_checker=_git_ok)


def test_root_overlap_or_wrong_tooling_commit_is_rejected(tmp_path: Path) -> None:
    _contract, paths = _fixture(tmp_path)
    direct = {name: paths[name] for name in DIRECT_INPUT_NAMES}
    with pytest.raises(ContractError, match="separate directory trees"):
        create_contract(
            tooling_source_commit=COMMIT,
            online_attempt_checkout=paths["online"],
            paired_causal_attempt_checkout=paths["online"] / "causal",
            paired_causal_durable_attempt_root=paths["causal_durable"],
            durable_attempt_root=paths["durable"],
            wrapper_tooling_root=paths["tooling"],
            direct_inputs=direct,
            git_checker=_git_ok,
        )
    wrong = paths["durable"] / "control" / "other-wrapper" / COMMIT
    wrong.mkdir(parents=True)
    _write(wrong / WRAPPER_FILENAME, b"wrapper")
    _write(wrong / BUILDER_FILENAME, b"builder")
    with pytest.raises(ContractError, match="durable/control/wrapper"):
        create_contract(
            tooling_source_commit=COMMIT,
            online_attempt_checkout=paths["online"],
            paired_causal_attempt_checkout=paths["causal"],
            paired_causal_durable_attempt_root=paths["causal_durable"],
            durable_attempt_root=paths["durable"],
            wrapper_tooling_root=wrong.resolve(),
            direct_inputs=direct,
            git_checker=_git_ok,
        )


def test_symlinked_source_is_rejected(tmp_path: Path) -> None:
    _contract, paths = _fixture(tmp_path)
    wrapper = paths["tooling"] / WRAPPER_FILENAME
    target = paths["tooling"] / "real-wrapper.py"
    wrapper.rename(target)
    wrapper.symlink_to(target.name)
    with pytest.raises(ContractError, match="symlink"):
        create_contract(
            tooling_source_commit=COMMIT,
            online_attempt_checkout=paths["online"],
            paired_causal_attempt_checkout=paths["causal"],
            paired_causal_durable_attempt_root=paths["causal_durable"],
            durable_attempt_root=paths["durable"],
            wrapper_tooling_root=paths["tooling"],
            direct_inputs={name: paths[name] for name in DIRECT_INPUT_NAMES},
            git_checker=_git_ok,
        )


def test_contract_file_must_be_canonical_duplicate_free_json(tmp_path: Path) -> None:
    contract, paths = _fixture(tmp_path)
    output = paths["durable"] / CONTRACT_RELATIVE_PATH
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(contract, indent=2) + "\n")
    with pytest.raises(ContractError, match="not canonical"):
        load_contract(output, verify_current_files=False, git_checker=_git_ok)

    duplicate = b'{"protocol":"x","protocol":"y"}\n'
    output.write_bytes(duplicate)
    with pytest.raises(ContractError, match="duplicate"):
        load_contract(output, verify_current_files=False, git_checker=_git_ok)


def test_direct_input_hashes_are_raw_file_hashes(tmp_path: Path) -> None:
    contract, paths = _fixture(tmp_path)
    for name in DIRECT_INPUT_NAMES:
        record = contract["direct_inputs"][name]
        payload = paths[name].read_bytes()
        assert record == {
            "path": str(paths[name]),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }


def test_publish_refuses_nonfixed_output_even_when_empty(tmp_path: Path) -> None:
    contract, paths = _fixture(tmp_path)
    with pytest.raises(ContractError, match="fixed durable path"):
        publish_contract(
            paths["durable"] / "elsewhere.json",
            contract,
            git_checker=_git_ok,
        )


def test_direct_input_must_belong_to_registered_durable_root(
    tmp_path: Path,
) -> None:
    _contract, paths = _fixture(tmp_path)
    outside = _write(tmp_path / "outside.json", b"outside\n").resolve()
    direct = {name: paths[name] for name in DIRECT_INPUT_NAMES}
    direct["protocol_seal"] = outside
    with pytest.raises(ContractError, match="exact durable relative path"):
        create_contract(
            tooling_source_commit=COMMIT,
            online_attempt_checkout=paths["online"],
            paired_causal_attempt_checkout=paths["causal"],
            paired_causal_durable_attempt_root=paths["causal_durable"],
            durable_attempt_root=paths["durable"],
            wrapper_tooling_root=paths["tooling"],
            direct_inputs=direct,
            git_checker=_git_ok,
        )


def test_publish_never_replaces_symlink(tmp_path: Path) -> None:
    contract, paths = _fixture(tmp_path)
    output = paths["durable"] / CONTRACT_RELATIVE_PATH
    output.parent.mkdir(parents=True, exist_ok=True)
    victim = _write(tmp_path / "victim", b"keep\n")
    output.symlink_to(victim)
    with pytest.raises(FileExistsError, match="overwrite"):
        publish_contract(output, contract, git_checker=_git_ok)
    assert victim.read_bytes() == b"keep\n"
    assert os.path.islink(output)


def test_publish_uses_literal_o_creat_o_excl_for_final_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract, paths = _fixture(tmp_path)
    output = paths["durable"] / CONTRACT_RELATIVE_PATH
    real_open = os.open
    observed_flags: list[int] = []

    def recording_open(path, flags, mode=0o777):
        if Path(path) == output:
            observed_flags.append(flags)
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", recording_open)
    publish_contract(output, contract, git_checker=_git_ok)
    assert len(observed_flags) == 1
    assert observed_flags[0] & os.O_CREAT
    assert observed_flags[0] & os.O_EXCL


def test_directory_fsync_open_is_no_follow_and_directory_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract, paths = _fixture(tmp_path)
    output = paths["durable"] / CONTRACT_RELATIVE_PATH
    real_open = os.open
    directory_flags: list[int] = []

    def recording_open(path, flags, mode=0o777):
        if Path(path) == output.parent:
            directory_flags.append(flags)
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", recording_open)
    publish_contract(output, contract, git_checker=_git_ok)
    assert len(directory_flags) == 1
    if hasattr(os, "O_DIRECTORY"):
        assert directory_flags[0] & os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        assert directory_flags[0] & os.O_NOFOLLOW


def test_git_checker_binds_both_exact_sealed_source_commits(tmp_path: Path) -> None:
    contract, paths = _fixture(tmp_path)
    calls: list[tuple[Path, str]] = []

    def recording_checker(root: Path, commit: str) -> None:
        calls.append((root, commit))

    verify_contract(contract, git_checker=recording_checker)
    assert calls == [
        (paths["online"], ONLINE_SOURCE_COMMIT),
        (paths["causal"], PAIRED_CAUSAL_SOURCE_COMMIT),
    ]


def test_partial_o_excl_publish_is_never_unlinked_or_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract, paths = _fixture(tmp_path)
    output = paths["durable"] / CONTRACT_RELATIVE_PATH
    real_fsync = os.fsync
    calls = 0

    def fail_first_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected file fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_first_fsync)
    with pytest.raises(OSError, match="injected"):
        publish_contract(output, contract, git_checker=_git_ok)
    assert output.exists()
    with pytest.raises(FileExistsError, match="overwrite"):
        publish_contract(output, contract, git_checker=_git_ok)


def test_publish_rejects_symlinked_existing_parent_without_following_it(
    tmp_path: Path,
) -> None:
    contract, paths = _fixture(tmp_path)
    control = paths["durable"] / "control"
    real_control = paths["durable"] / "control-real"
    control.rename(real_control)
    control.symlink_to(real_control.name)
    output = paths["durable"] / CONTRACT_RELATIVE_PATH
    with pytest.raises(ContractError, match="real directory tree"):
        publish_contract(output, contract, git_checker=_git_ok)
    assert not (real_control / CONTRACT_RELATIVE_PATH.name).exists()


def test_inside_root_but_wrong_direct_input_relative_path_is_rejected(
    tmp_path: Path,
) -> None:
    _contract, paths = _fixture(tmp_path)
    direct = {name: paths[name] for name in DIRECT_INPUT_NAMES}
    wrong = _write(paths["durable"] / "prep" / "wrong-protocol-seal.json", b"x\n")
    direct["protocol_seal"] = wrong
    with pytest.raises(ContractError, match="exact durable relative path"):
        create_contract(
            tooling_source_commit=COMMIT,
            online_attempt_checkout=paths["online"],
            paired_causal_attempt_checkout=paths["causal"],
            paired_causal_durable_attempt_root=paths["causal_durable"],
            durable_attempt_root=paths["durable"],
            wrapper_tooling_root=paths["tooling"],
            direct_inputs=direct,
            git_checker=_git_ok,
        )


def test_direct_input_paths_must_be_pairwise_distinct(tmp_path: Path) -> None:
    _contract, paths = _fixture(tmp_path)
    direct = {name: paths[name] for name in DIRECT_INPUT_NAMES}
    direct["protocol_seal"] = direct["online_provenance"]
    with pytest.raises(ContractError, match="pairwise distinct"):
        create_contract(
            tooling_source_commit=COMMIT,
            online_attempt_checkout=paths["online"],
            paired_causal_attempt_checkout=paths["causal"],
            paired_causal_durable_attempt_root=paths["causal_durable"],
            durable_attempt_root=paths["durable"],
            wrapper_tooling_root=paths["tooling"],
            direct_inputs=direct,
            git_checker=_git_ok,
        )


def test_artifact_symlink_must_resolve_to_exact_durable_root(tmp_path: Path) -> None:
    _contract, paths = _fixture(tmp_path)
    mapping = paths["online"] / "artifacts" / "cohort_online_icl"
    mapping.unlink()
    wrong = tmp_path / "wrong-artifact"
    wrong.mkdir()
    mapping.symlink_to(wrong)
    with pytest.raises(ContractError, match="symlink target differs"):
        create_contract(
            tooling_source_commit=COMMIT,
            online_attempt_checkout=paths["online"],
            paired_causal_attempt_checkout=paths["causal"],
            paired_causal_durable_attempt_root=paths["causal_durable"],
            durable_attempt_root=paths["durable"],
            wrapper_tooling_root=paths["tooling"],
            direct_inputs={name: paths[name] for name in DIRECT_INPUT_NAMES},
            git_checker=_git_ok,
        )


def test_causal_mapping_rejects_old_child_symlink_layout(tmp_path: Path) -> None:
    contract, paths = _fixture(tmp_path)
    mapping = paths["causal"] / "artifacts"
    mapping.unlink()
    mapping.mkdir()
    (mapping / "cohort_causal").symlink_to(
        paths["causal_durable"] / "artifacts" / "cohort_causal"
    )
    with pytest.raises(ContractError, match="must be a symlink"):
        verify_contract(contract, git_checker=_git_ok)


def test_contract_expectation_is_independent_readonly_one_way_binding(
    tmp_path: Path,
) -> None:
    contract, paths = _fixture(tmp_path)
    contract_path = paths["durable"] / CONTRACT_RELATIVE_PATH
    publish_contract(contract_path, contract, git_checker=_git_ok)
    expectation = create_contract_expectation(
        contract_path,
        created_at_utc="2026-07-14T12:00:01.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    expectation_path = paths["durable"] / CONTRACT_EXPECTATION_RELATIVE_PATH
    publish_contract_expectation(
        expectation_path, expectation, contract_path=contract_path
    )
    assert stat.S_IMODE(expectation_path.stat().st_mode) == 0o444
    assert (
        expectation["contract_file_sha256"]
        == hashlib.sha256(contract_path.read_bytes()).hexdigest()
    )
    assert expectation["contract_canonical_sha256"] == contract["contract_sha256"]
    assert (
        load_contract_expectation(expectation_path, contract_path=contract_path)
        == expectation
    )


def test_contract_expectation_rejects_tooling_commit_substitution(
    tmp_path: Path,
) -> None:
    contract, paths = _fixture(tmp_path)
    contract_path = paths["durable"] / CONTRACT_RELATIVE_PATH
    publish_contract(contract_path, contract, git_checker=_git_ok)
    expectation = create_contract_expectation(
        contract_path,
        created_at_utc="2026-07-14T12:00:01.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    expectation["tooling_source_commit"] = "d" * 40
    expectation.pop("expectation_sha256")
    expectation["expectation_sha256"] = canonical_sha256(expectation)
    expectation_path = paths["durable"] / CONTRACT_EXPECTATION_RELATIVE_PATH
    expectation_path.parent.mkdir(parents=True, exist_ok=True)
    expectation_path.write_bytes(canonical_bytes(expectation) + b"\n")
    expectation_path.chmod(0o444)
    with pytest.raises(ContractError, match="tooling commit differs"):
        load_contract_expectation(expectation_path, contract_path=contract_path)


def test_prospective_plan_one_way_binds_contract_expectation_sources_and_argv(
    tmp_path: Path,
) -> None:
    contract, paths = _fixture(tmp_path)
    contract_path = paths["durable"] / CONTRACT_RELATIVE_PATH
    publish_contract(contract_path, contract, git_checker=_git_ok)
    expectation = create_contract_expectation(
        contract_path,
        created_at_utc="2026-07-14T12:00:01.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    expectation_path = paths["durable"] / CONTRACT_EXPECTATION_RELATIVE_PATH
    publish_contract_expectation(
        expectation_path, expectation, contract_path=contract_path
    )
    plan = create_prospective_execution_plan(
        contract_path,
        expectation_path,
        created_at_utc="2026-07-14T12:00:02.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    assert plan["launch_authorized"] is False
    assert plan["source_files"] == contract["source_files"]
    assert plan["exact_formal_argv"] == contract["exact_formal_argv"]
    assert plan["production_blockers"]
    output = paths["durable"] / PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH
    publish_prospective_execution_plan(
        output,
        plan,
        contract_path=contract_path,
        expectation_path=expectation_path,
    )
    assert stat.S_IMODE(output.stat().st_mode) == 0o444
    assert (
        load_prospective_execution_plan(
            output,
            contract_path=contract_path,
            expectation_path=expectation_path,
        )
        == plan
    )


def test_prospective_plan_rejects_alternate_expectation_before_poisoning_output(
    tmp_path: Path,
) -> None:
    contract, paths = _fixture(tmp_path)
    contract_path = paths["durable"] / CONTRACT_RELATIVE_PATH
    publish_contract(contract_path, contract, git_checker=_git_ok)
    expectation = create_contract_expectation(
        contract_path,
        created_at_utc="2026-07-14T12:00:01.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    expectation_path = paths["durable"] / CONTRACT_EXPECTATION_RELATIVE_PATH
    publish_contract_expectation(
        expectation_path, expectation, contract_path=contract_path
    )
    plan = create_prospective_execution_plan(
        contract_path,
        expectation_path,
        created_at_utc="2026-07-14T12:00:02.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    alternate = expectation_path.with_name("alternate_expectation.json")
    alternate.write_bytes(expectation_path.read_bytes())
    alternate.chmod(0o444)
    with pytest.raises(ContractError, match="fixed paths"):
        create_prospective_execution_plan(
            contract_path,
            alternate,
            git_checker=_git_ok,
            runtime_binding_provider=_runtime_ok,
            causal_chain_validator=_chain_ok,
        )

    poisoned_plan = copy.deepcopy(plan)
    poisoned_plan["contract_expectation_path"] = alternate.as_posix()
    poisoned_plan.pop("plan_sha256")
    poisoned_plan["plan_sha256"] = canonical_sha256(poisoned_plan)
    output = paths["durable"] / PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH
    with pytest.raises(ContractError, match="fixed input paths"):
        publish_prospective_execution_plan(
            output,
            poisoned_plan,
            contract_path=contract_path,
            expectation_path=alternate,
        )
    assert not output.exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [("noncanonical", "canonical JSON"), ("writable", "0444")],
)
def test_prospective_plan_requires_canonical_readonly_expectation_before_publish(
    tmp_path: Path, mutation: str, message: str
) -> None:
    contract, paths = _fixture(tmp_path)
    contract_path = paths["durable"] / CONTRACT_RELATIVE_PATH
    publish_contract(contract_path, contract, git_checker=_git_ok)
    expectation = create_contract_expectation(
        contract_path,
        created_at_utc="2026-07-14T12:00:01.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    expectation_path = paths["durable"] / CONTRACT_EXPECTATION_RELATIVE_PATH
    publish_contract_expectation(
        expectation_path, expectation, contract_path=contract_path
    )
    plan = create_prospective_execution_plan(
        contract_path,
        expectation_path,
        created_at_utc="2026-07-14T12:00:02.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    expectation_path.chmod(0o600)
    if mutation == "noncanonical":
        expectation_path.write_text(json.dumps(expectation, indent=2) + "\n")
        expectation_path.chmod(0o444)

    with pytest.raises(ContractError, match=message):
        create_prospective_execution_plan(
            contract_path,
            expectation_path,
            git_checker=_git_ok,
            runtime_binding_provider=_runtime_ok,
            causal_chain_validator=_chain_ok,
        )
    output = paths["durable"] / PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH
    with pytest.raises(ContractError, match=message):
        publish_prospective_execution_plan(
            output,
            plan,
            contract_path=contract_path,
            expectation_path=expectation_path,
        )
    assert not output.exists()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def test_real_git_checker_rejects_wrong_head_dirty_index_and_untracked_shadow(
    tmp_path: Path,
) -> None:
    sealed_home = tmp_path / "sealed-git-home"
    sealed_home.mkdir()
    sealed_home.chmod(0o555)
    check_git = lambda root, commit: _default_git_checker(  # noqa: E731
        root, commit, sealed_home=sealed_home
    )
    repo = tmp_path / "git-checkout"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    tracked = _write(repo / "tracked.txt", b"sealed\n")
    _write(repo / ".gitignore", b"ignored-shadow.pyc\n")
    _git(repo, "add", "tracked.txt", ".gitignore")
    _git(repo, "commit", "-m", "sealed")
    head = _git(repo, "rev-parse", "HEAD")
    git_runtime = check_git(repo.resolve(), head)
    assert git_runtime["executable"]["lookup_path"] == "/usr/bin/git"
    assert git_runtime["executable"]["sha256"]
    assert git_runtime["environment"] == {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": str(sealed_home),
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    with pytest.raises(ContractError, match="source commit differs"):
        check_git(repo.resolve(), "0" * 40)

    tracked.write_bytes(b"dirty\n")
    with pytest.raises(ContractError, match="tracked/index"):
        check_git(repo.resolve(), head)
    _git(repo, "restore", "tracked.txt")
    tracked.write_bytes(b"staged\n")
    _git(repo, "add", "tracked.txt")
    with pytest.raises(ContractError, match="tracked/index"):
        check_git(repo.resolve(), head)
    _git(repo, "reset", "--hard", "HEAD")

    _write(repo / "launch_cohort_online_icl.sh", b"shadow\n")
    with pytest.raises(ContractError, match="untracked shadow"):
        check_git(repo.resolve(), head)
    (repo / "launch_cohort_online_icl.sh").unlink()
    _write(repo / "ignored-shadow.pyc", b"ignored shadow\n")
    with pytest.raises(ContractError, match="untracked shadow"):
        check_git(repo.resolve(), head)


def test_real_git_checker_allows_only_registered_artifact_symlink(
    tmp_path: Path,
) -> None:
    sealed_home = tmp_path / "sealed-git-home"
    sealed_home.mkdir()
    sealed_home.chmod(0o555)
    repo = tmp_path / "git-checkout"
    target = tmp_path / "durable-artifact"
    repo.mkdir()
    target.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    _write(repo / "tracked.txt", b"sealed\n")
    _write(repo / ".gitignore", b"artifacts/\n")
    _git(repo, "add", "tracked.txt", ".gitignore")
    _git(repo, "commit", "-m", "sealed")
    head = _git(repo, "rev-parse", "HEAD")
    (repo / "artifacts").mkdir()
    (repo / "artifacts" / "cohort_online_icl").symlink_to(target)
    _default_git_checker(repo.resolve(), head, sealed_home=sealed_home)


def test_real_git_checker_allows_causal_root_artifacts_symlink(tmp_path: Path) -> None:
    sealed_home = tmp_path / "sealed-git-home"
    sealed_home.mkdir()
    sealed_home.chmod(0o555)
    repo = tmp_path / "causal-git-checkout"
    durable_artifacts = tmp_path / "causal-durable" / "artifacts"
    repo.mkdir()
    (durable_artifacts / "cohort_causal").mkdir(parents=True)
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    _write(repo / "tracked.txt", b"sealed\n")
    _write(repo / ".gitignore", b"artifacts\n")
    _git(repo, "add", "tracked.txt", ".gitignore")
    _git(repo, "commit", "-m", "sealed")
    head = _git(repo, "rev-parse", "HEAD")
    (repo / "artifacts").symlink_to(durable_artifacts)
    _default_git_checker(repo.resolve(), head, sealed_home=sealed_home)


def test_default_runtime_binding_scrubs_inherited_environment_and_binds_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import build_cohort_online_icl_formal_wrapper_contract as module

    tooling = tmp_path / "tooling"
    online = tmp_path / "online"
    shim = _write(
        tooling / "runtime-bin" / "python",
        module.PYTHON_SHIM_BYTES,
    )
    shim.chmod(0o555)
    (tooling / "runtime-bin").chmod(0o555)
    sealed_home = tooling / "sealed-home"
    sealed_home.mkdir()
    sealed_home.chmod(0o555)
    online.mkdir()
    for key in module.FORBIDDEN_ENVIRONMENT_KEYS:
        monkeypatch.setenv(key, "must-not-leak")

    def fake_which(name: str, *, path: str) -> str:
        assert path == f"{tooling}/runtime-bin:/usr/bin:/bin"
        return str(shim if name == "python" else Path("/usr/bin") / name)

    def fake_executable_record(path: Path, *, label: str) -> dict:
        del label
        resolved = str(path)
        return {
            "lookup_path": str(path),
            "resolved_path": resolved,
            "sha256": hashlib.sha256(str(path).encode()).hexdigest(),
            "size_bytes": 1,
        }

    monkeypatch.setattr(module.shutil, "which", fake_which)
    monkeypatch.setattr(module, "_executable_record", fake_executable_record)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Python 3.10.12\n", stderr=""
        ),
    )
    binding = module._default_runtime_binding_provider(tooling, online)
    assert binding["cwd"] == str(online)
    assert set(binding["environment"]) == {
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "TZ",
    }
    assert not set(module.FORBIDDEN_ENVIRONMENT_KEYS) & set(binding["environment"])
    assert binding["executables"]["python"]["lookup_path"] == str(shim)
    assert binding["executables"]["python_target"]["resolved_path"] == (
        "/usr/bin/python3.10"
    )
    assert binding["environment"]["HOME"] == str(sealed_home)
    assert binding["runtime_bin"]["inventory"] == ["python"]
    assert binding["sealed_home"]["inventory"] == []
    assert binding["python_version_output"] == "Python 3.10.12"


@pytest.mark.parametrize(
    ("decision_value", "decision_status", "decision_scope", "passes"),
    [
        ("pass", "valid", "internal_gate_pass", True),
        ("no_go", "valid", "internal_gate_pass", False),
        ("pass", "invalid", "internal_gate_pass", False),
        ("pass", "valid", "wrong_scope", False),
    ],
)
def test_default_causal_validator_synthetic_shape_and_hard_gate(
    tmp_path: Path,
    decision_value: str,
    decision_status: str,
    decision_scope: str,
    passes: bool,
) -> None:
    import build_cohort_online_icl_formal_wrapper_contract as module
    from build_cohort_structured_state_execution_seal import make_execution_plan

    checkout = (tmp_path / "causal-checkout").resolve()
    durable = (tmp_path / "causal-durable" / "attempt-002").resolve()
    artifact = durable / "artifacts" / "cohort_causal"
    prep = durable / "prep"
    control = durable / "control"
    tooling_commit = "c" * 40
    tooling = control / "verifier" / tooling_commit
    for path in (checkout, artifact, prep, tooling):
        path.mkdir(parents=True, exist_ok=True)
    for name in (
        "attest_cohort_causal_completion.py",
        "revalidate_cohort_causal_terminal.py",
        "build_cohort_structured_state_execution_seal.py",
    ):
        _write(tooling / name, f"# sealed {name}\n".encode())
    _write(
        tooling / "COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md",
        b"sealed preregistration\n",
    )
    provenance = b'{"source":"synthetic"}\n'
    provenance_path = _write(artifact / "provenance.json", provenance)
    provenance_details_path = _write(
        artifact / "provenance.details.json", b'{"synthetic":true}\n'
    )
    manifest_raw = b'{"synthetic":true}\n'
    manifest_path = _write(artifact / "formal_manifest.json", manifest_raw)
    decision = {key: None for key in module._CAUSAL_DECISION_KEYS}
    decision.update(
        {
            "decision": decision_value,
            "decision_scope": decision_scope,
            "protocol": "cohort_qonly_frozen_tape_weight_update_ablation_v1",
            "schema_version": 1,
            "status": decision_status,
        }
    )
    decision_raw = (json.dumps(decision, indent=2, sort_keys=True) + "\n").encode()
    decision_path = _write(artifact / "formal_decision.json", decision_raw)
    revalidated_path = _write(prep / "causal_formal.revalidated.json", decision_raw)
    expectation_path = control / "CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json"
    sha = "3" * 64
    pid_path = prep / "causal.pid"
    exit_path = prep / "causal.exit.json"
    expectation = {
        "artifact_root": artifact.as_posix(),
        "attempt_id": "attempt-002",
        "boot_id": "synthetic-boot",
        "checkout_root": checkout.as_posix(),
        "collector_gpus": [0],
        "created_at_utc": "2026-07-14T11:00:00.000000Z",
        "durable_attempt_root": durable.as_posix(),
        "eval_gpus": [1],
        "exit_file": exit_path.as_posix(),
        "expected_final_inventory": module._CAUSAL_REGISTERED_COUNTS,
        "formal_grid_file_sha256": sha,
        "launch_mode": "formal",
        "launcher_file_sha256": sha,
        "max_used_memory_mib": 1024,
        "node_hostname": "synthetic",
        "pid_file": pid_path.as_posix(),
        "pid_file_sha256_at_registration": sha,
        "protocol": "cohort_causal_formal_launch_expectation_v1",
        "provenance_file_sha256": hashlib.sha256(provenance).hexdigest(),
        "schema_version": 1,
        "source_commit": PAIRED_CAUSAL_SOURCE_COMMIT,
        "wrapper_cmdline_sha256_at_registration": sha,
        "wrapper_pid": 123,
        "wrapper_start_ticks": 456,
    }
    expectation_raw = canonical_bytes(expectation)
    _write(expectation_path, expectation_raw)
    plan = make_execution_plan(
        tooling_source_commit=tooling_commit,
        causal_checkout_root=checkout,
        durable_attempt_root=durable,
        created_at_utc="2026-07-14T11:01:00.000000Z",
    )
    plan_path = _write(
        control / "CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN.json",
        canonical_bytes(plan),
    )
    plan_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    snapshot_record = {
        "device": 1,
        "inode": 1,
        "mtime_ns": 1,
        "path": provenance_path.as_posix(),
        "roles": ["provenance"],
        "sha256": hashlib.sha256(provenance).hexdigest(),
        "size_bytes": len(provenance),
    }
    inventory_sha = canonical_sha256([snapshot_record])
    snapshots = [
        {
            "captured_at_utc": f"2026-07-14T11:02:0{index}.000000Z",
            "file_count": 1,
            "files": [snapshot_record],
            "inventory_sha256": inventory_sha,
            "sequence": index + 1,
        }
        for index in range(2)
    ]
    no_live = {
        "forbidden_match_count": 0,
        "roots": [artifact.as_posix()],
        "status": "pass",
    }
    no_live["audit_sha256"] = canonical_sha256(no_live)
    process_absence = {
        "artifact_root_path": artifact.as_posix(),
        "attempt_checkout_path": checkout.as_posix(),
        "method": "linux_procfs_cmdline_and_cwd",
        "status": "pass",
    }
    process_absence["audit_sha256"] = canonical_sha256(process_absence)
    attestation = {
        "causal_pre_attestation_inventory_sha256": inventory_sha,
        "completed_at_utc": "2026-07-14T11:03:00.000000Z",
        "execution_plan_path": plan_path.as_posix(),
        "execution_plan_sha256": plan_sha,
        "expected_launcher": {
            "formal_grid_file_sha256": sha,
            "launch_expectation_path": expectation_path.as_posix(),
            "launch_expectation_sha256": hashlib.sha256(expectation_raw).hexdigest(),
            "launcher_file_sha256": sha,
            "provenance_file_sha256": hashlib.sha256(provenance).hexdigest(),
            "source_commit": PAIRED_CAUSAL_SOURCE_COMMIT,
            "wrapper_cmdline_sha256_at_registration": sha,
        },
        "no_live_or_temporary": no_live,
        "pid_exit": {
            "exit_after_outputs_status": "pass",
            "exit_file_mtime_ns": 1,
            "exit_file_path": exit_path.as_posix(),
            "exit_file_sha256": sha,
            "exit_file_size_bytes": 1,
            "exit_zero_status": "pass",
            "pid_ascii_status": "pass",
            "pid_file_mtime_ns": 1,
            "pid_file_path": pid_path.as_posix(),
            "pid_file_sha256": sha,
            "pid_file_size_bytes": 1,
            "pid_liveness_status": "dead",
        },
        "process_absence": process_absence,
        "protocol": "cohort_causal_terminal_completion_attestation_v1",
        "registered_counts": module._CAUSAL_REGISTERED_COUNTS,
        "schema_version": 1,
        "snapshots": snapshots,
        "stability": {
            "minimum_interval_seconds": 1.0,
            "observed_interval_seconds": 1.0,
            "snapshots_identical": True,
        },
        "status": "complete",
    }
    attestation_path = _write(
        prep / "causal_trigger_completion_attestation.json",
        canonical_bytes(attestation),
    )
    receipt = {
        "decision": decision["decision"],
        "decision_scope": decision["decision_scope"],
        "execution_plan_path": plan_path.as_posix(),
        "execution_plan_sha256": plan_sha,
        "formal_decision_file_sha256": hashlib.sha256(decision_raw).hexdigest(),
        "formal_manifest_file_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "status": decision_status,
    }
    receipt_path = _write(
        prep / "causal_formal.revalidation_receipt.json",
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
    )
    paths = {
        "causal_completion_attestation": attestation_path,
        "causal_decision": decision_path,
        "causal_launch_expectation": expectation_path.resolve(),
        "causal_manifest": manifest_path,
        "causal_provenance": provenance_path,
        "causal_provenance_details": provenance_details_path,
        "causal_revalidated_decision": revalidated_path,
        "causal_revalidation_receipt": receipt_path,
        "causal_smoke_gate": _write(artifact / "smoke_gate.json", b"{}\n"),
        "causal_terminal_execution_plan": plan_path,
    }
    if not passes:
        with pytest.raises(ContractError, match="hard gate"):
            module._default_causal_chain_validator(paths, checkout, durable)
        return
    result = module._default_causal_chain_validator(paths, checkout, durable)
    assert result["status"] == "synthetic_shape_only"
    assert result["semantic_revalidation_status"] == "not_semantically_revalidated"
    assert result["hard_gate"] == {
        "status": "valid",
        "decision": "pass",
        "decision_scope": "internal_gate_pass",
    }
    assert result["execution_plan_sha256"] == plan_sha
