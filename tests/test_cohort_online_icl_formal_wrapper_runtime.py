from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from build_cohort_online_icl_formal_wrapper_contract import (
    BUILDER_FILENAME,
    CONTRACT_EXPECTATION_RELATIVE_PATH,
    CONTRACT_RELATIVE_PATH,
    DIRECT_INPUT_NAMES,
    DIRECT_INPUT_RELATIVE_PATHS,
    LAUNCHER_FILENAME,
    PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH,
    WRAPPER_FILENAME,
    canonical_bytes,
    canonical_sha256,
    create_contract,
    create_contract_expectation,
    create_prospective_execution_plan,
    publish_contract,
    publish_contract_expectation,
    publish_prospective_execution_plan,
)
from run_cohort_online_icl_formal_wrapper import WrapperError, run_registered_formal


COMMIT = "b" * 40


def _git_ok(_root: Path, _commit: str) -> None:
    return None


def _runtime_ok(tooling: Path, online: Path) -> dict:
    return {
        "cwd": str(online),
        "environment": {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(tooling / "sealed-home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": f"{tooling}/runtime-bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TZ": "UTC",
        },
        "python_version_output": "Python 3.10.12",
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


def _write(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path.resolve()


def _fixture(tmp_path: Path) -> tuple[Path, dict, dict]:
    repo_root = Path(__file__).resolve().parents[1]
    online = (tmp_path / "online").resolve()
    causal = (tmp_path / "causal").resolve()
    durable = (tmp_path / "online-durable" / "attempt-002").resolve()
    causal_durable = (tmp_path / "causal-durable" / "attempt-002").resolve()
    tooling = durable / "control" / "wrapper" / COMMIT
    for path in (online, causal, durable / "control", durable / "prep", tooling):
        path.mkdir(parents=True, exist_ok=True)
    online_artifact = durable / "artifacts" / "cohort_online_icl"
    causal_artifact = causal_durable / "artifacts" / "cohort_causal"
    online_artifact.mkdir(parents=True)
    causal_artifact.mkdir(parents=True)
    (online / "artifacts").mkdir()
    (online / "artifacts" / "cohort_online_icl").symlink_to(online_artifact)
    (causal / "artifacts").symlink_to(causal_durable / "artifacts")
    _write(online / LAUNCHER_FILENAME, b"#!/bin/sh\nexit 0\n")
    runtime_source = _write(
        tooling / WRAPPER_FILENAME, (repo_root / WRAPPER_FILENAME).read_bytes()
    )
    builder_source = _write(
        tooling / BUILDER_FILENAME, (repo_root / BUILDER_FILENAME).read_bytes()
    )
    direct = {}
    for index, name in enumerate(DIRECT_INPUT_NAMES):
        root = causal_durable if name.startswith("causal_") else durable
        direct[name] = _write(
            root / DIRECT_INPUT_RELATIVE_PATHS[name], f"{index}\n".encode()
        )
    contract = create_contract(
        tooling_source_commit=COMMIT,
        online_attempt_checkout=online,
        paired_causal_attempt_checkout=causal,
        paired_causal_durable_attempt_root=causal_durable,
        durable_attempt_root=durable,
        wrapper_tooling_root=tooling,
        direct_inputs=direct,
        created_at_utc="2026-07-14T12:00:00.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    contract_path = durable / CONTRACT_RELATIVE_PATH
    publish_contract(
        contract_path,
        contract,
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    expectation = create_contract_expectation(
        contract_path,
        created_at_utc="2026-07-14T12:00:01.000000Z",
        git_checker=_git_ok,
        runtime_binding_provider=_runtime_ok,
        causal_chain_validator=_chain_ok,
    )
    expectation_path = durable / CONTRACT_EXPECTATION_RELATIVE_PATH
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
    plan_path = durable / PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH
    publish_prospective_execution_plan(
        plan_path,
        plan,
        contract_path=contract_path,
        expectation_path=expectation_path,
    )
    spec = importlib.util.spec_from_file_location(
        f"sealed_runtime_{tmp_path.name}", runtime_source
    )
    assert spec is not None and spec.loader is not None
    runtime_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime_module)
    return (
        contract_path,
        contract,
        {
            "builder_source": builder_source,
            "direct_inputs": direct,
            "expectation": expectation_path,
            "launcher_source": online / LAUNCHER_FILENAME,
            "plan": plan_path,
            "runtime_module": runtime_module,
            "runtime_source": runtime_source,
        },
    )


def _validate(contract_path: Path, paths: dict) -> dict:
    return paths["runtime_module"].validate_prospective_launch_spec(contract_path)


def test_validator_returns_launch_disabled_bound_spec(tmp_path: Path) -> None:
    contract_path, contract, paths = _fixture(tmp_path)
    spec = _validate(contract_path, paths)
    assert spec["status"] == "local_integrity_only"
    assert spec["local_integrity_only"] is True
    assert spec["launch_authorized"] is False
    assert spec["exact_formal_argv"] == contract["exact_formal_argv"]
    assert spec["runtime"] == contract["runtime"]
    assert spec["production_blockers"]
    for fixed_name in (
        "pid_file",
        "exit_record",
        "launch_inventory",
        "completion_marker",
    ):
        assert not Path(contract["fixed_paths"][fixed_name]).exists()


def test_public_run_api_is_unconditionally_disabled() -> None:
    with pytest.raises(WrapperError, match="hard-disabled"):
        run_registered_formal(Path("/must/not/be-opened"))


def test_missing_prospective_plan_fails_closed(tmp_path: Path) -> None:
    contract_path, _contract, paths = _fixture(tmp_path)
    paths["plan"].unlink()
    with pytest.raises(paths["runtime_module"].WrapperError):
        _validate(contract_path, paths)


@pytest.mark.parametrize("drift", ["source", "direct_input"])
def test_current_source_and_direct_input_drift_fail_closed(
    tmp_path: Path, drift: str
) -> None:
    contract_path, _contract, paths = _fixture(tmp_path)
    target = (
        paths["launcher_source"]
        if drift == "source"
        else paths["direct_inputs"]["protocol_seal"]
    )
    target.write_bytes(b"drifted after contract publication\n")
    with pytest.raises(paths["runtime_module"].WrapperError, match="bytes differ"):
        _validate(contract_path, paths)


def test_runtime_rejects_expectation_tooling_commit_substitution(
    tmp_path: Path,
) -> None:
    contract_path, _contract, paths = _fixture(tmp_path)
    expectation_path = paths["expectation"]
    expectation = json.loads(expectation_path.read_text())
    expectation["tooling_source_commit"] = "d" * 40
    expectation.pop("expectation_sha256")
    expectation["expectation_sha256"] = canonical_sha256(expectation)
    expectation_path.chmod(0o600)
    expectation_path.write_bytes(canonical_bytes(expectation) + b"\n")
    expectation_path.chmod(0o444)

    plan_path = paths["plan"]
    plan = json.loads(plan_path.read_text())
    plan["contract_expectation_file_sha256"] = hashlib.sha256(
        expectation_path.read_bytes()
    ).hexdigest()
    plan.pop("plan_sha256")
    plan["plan_sha256"] = canonical_sha256(plan)
    plan_path.chmod(0o600)
    plan_path.write_bytes(canonical_bytes(plan) + b"\n")
    plan_path.chmod(0o444)
    with pytest.raises(
        paths["runtime_module"].WrapperError, match="expectation binding differs"
    ):
        _validate(contract_path, paths)


def test_runtime_rejects_resealed_direct_input_path_and_layout_substitution(
    tmp_path: Path,
) -> None:
    contract_path, contract, paths = _fixture(tmp_path)
    original = paths["direct_inputs"]["protocol_seal"]
    alternate = original.with_name("alternate_protocol_seal.json")
    alternate.write_bytes(original.read_bytes())
    mutated = json.loads(json.dumps(contract))
    mutated["direct_inputs"]["protocol_seal"]["path"] = alternate.as_posix()
    mutated["direct_input_layout"]["protocol_seal"]["relative_path"] = (
        "meta/alternate_protocol_seal.json"
    )
    mutated.pop("contract_sha256")
    mutated["contract_sha256"] = canonical_sha256(mutated)
    contract_path.chmod(0o600)
    contract_path.write_bytes(canonical_bytes(mutated) + b"\n")
    contract_path.chmod(0o444)

    expectation_path = paths["expectation"]
    expectation = json.loads(expectation_path.read_text())
    expectation["contract_file_sha256"] = hashlib.sha256(
        contract_path.read_bytes()
    ).hexdigest()
    expectation["contract_canonical_sha256"] = mutated["contract_sha256"]
    expectation.pop("expectation_sha256")
    expectation["expectation_sha256"] = canonical_sha256(expectation)
    expectation_path.chmod(0o600)
    expectation_path.write_bytes(canonical_bytes(expectation) + b"\n")
    expectation_path.chmod(0o444)

    plan_path = paths["plan"]
    plan = json.loads(plan_path.read_text())
    plan["contract_file_sha256"] = hashlib.sha256(
        contract_path.read_bytes()
    ).hexdigest()
    plan["contract_canonical_sha256"] = mutated["contract_sha256"]
    plan["contract_expectation_file_sha256"] = hashlib.sha256(
        expectation_path.read_bytes()
    ).hexdigest()
    plan.pop("plan_sha256")
    plan["plan_sha256"] = canonical_sha256(plan)
    plan_path.chmod(0o600)
    plan_path.write_bytes(canonical_bytes(plan) + b"\n")
    plan_path.chmod(0o444)
    with pytest.raises(paths["runtime_module"].WrapperError, match="direct-input"):
        _validate(contract_path, paths)


@pytest.mark.parametrize("special", ["fifo", "device"])
def test_stable_reader_rejects_nonregular_inputs_without_blocking(
    tmp_path: Path, special: str
) -> None:
    _contract_path, _contract, paths = _fixture(tmp_path)
    if special == "fifo":
        target = tmp_path / "untrusted.fifo"
        os.mkfifo(target)
    else:
        target = Path("/dev/null")
    started = time.monotonic()
    with pytest.raises(paths["runtime_module"].WrapperError, match="regular file"):
        paths["runtime_module"]._read_stable(target.resolve(), label=special)
    assert time.monotonic() - started < 1.0


def test_resealed_plan_cannot_authorize_launch(tmp_path: Path) -> None:
    contract_path, _contract, paths = _fixture(tmp_path)
    plan_path = paths["plan"]
    plan = json.loads(plan_path.read_text())
    plan["launch_authorized"] = True
    plan.pop("plan_sha256")
    plan["plan_sha256"] = canonical_sha256(plan)
    plan_path.chmod(0o600)
    plan_path.write_bytes(canonical_bytes(plan) + b"\n")
    plan_path.chmod(0o444)
    with pytest.raises(paths["runtime_module"].WrapperError):
        _validate(contract_path, paths)


def test_runtime_public_validator_signature_has_no_dependency_injection(
    tmp_path: Path,
) -> None:
    _contract_path, _contract, paths = _fixture(tmp_path)
    signature = inspect.signature(
        paths["runtime_module"].validate_prospective_launch_spec
    )
    assert list(signature.parameters) == ["contract_path"]


def test_production_module_contains_no_launch_or_state_machine_capability() -> None:
    source_path = Path(__file__).resolve().parents[1] / WRAPPER_FILENAME
    source = source_path.read_text()
    tree = ast.parse(source)
    allowed_imports = {"argparse", "hashlib", "json", "os", "re", "stat"}
    allowed_from = {"__future__", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert {alias.name for alias in node.names} <= allowed_imports
        if isinstance(node, ast.ImportFrom):
            assert node.module in allowed_from
    forbidden_attributes = {
        "Popen",
        "chmod",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fork",
        "forkpty",
        "fchmod",
        "link",
        "mkdir",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "symlink",
        "symlink_to",
        "system",
        "touch",
        "unlink",
        "rename",
        "replace",
        "write",
        "write_bytes",
        "write_text",
    }
    observed_attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert not observed_attributes & forbidden_attributes
    assert not {name for name in observed_attributes if name.startswith("write_")}
    assert all(
        forbidden not in source
        for forbidden in ("subprocess", "importlib", "ctypes", "_TEST_CAPABILITY")
    )


def test_import_and_failed_cli_are_side_effect_free(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    missing = tmp_path / "missing" / "contract.json"
    imported = subprocess.run(
        [sys.executable, "-c", "import run_cohort_online_icl_formal_wrapper"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    assert imported.returncode == 0
    cli = subprocess.run(
        [sys.executable, str(repo / WRAPPER_FILENAME), "--contract", str(missing)],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    assert cli.returncode != 0
    assert not missing.parent.exists()
    assert os.listdir(tmp_path) == []
