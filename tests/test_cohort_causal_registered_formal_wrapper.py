from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from assemble_cohort_causal_manifest import _atomic_write_json
import validate_cohort_causal_results as result_validator
from validate_cohort_causal_results import _publish_no_overwrite as publish_decision
from validate_cohort_causal_smoke import _atomic_write as publish_smoke
import run_cohort_causal_formal_registered as wrapper


@pytest.fixture(autouse=True)
def _linux_boot_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        wrapper, "_boot_id", lambda: "11111111-1111-1111-1111-111111111111"
    )
    monkeypatch.setattr(wrapper, "_revalidate_smoke_gate", lambda **_kwargs: None)
    monkeypatch.setattr(wrapper, "PUBLISHED_STABILITY_SECONDS", 0.0)
    monkeypatch.setattr(result_validator, "PUBLISHED_STABILITY_SECONDS", 0.0)


def test_retry_002_protocol_identity_is_literal() -> None:
    assert wrapper.RETRY_ID == "causal-retry-002"
    assert wrapper.ATTEMPT_ID == "attempt-002"
    assert wrapper.CLOSED_SOURCE_COMMITS == {
        "1caf142f6ce611da8da8691d4c336388a4c3c4b3",
        "059b26b45180b5a295c4c1b36a180cb2a91d5405",
    }
    assert (
        wrapper.RETRY_AMENDMENT_FILENAME
        == "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V2.md"
    )
    assert wrapper.RETRY_AMENDMENT_FILENAME in wrapper.CRITICAL_TRACKED_FILES
    assert "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V1.md" in (
        wrapper.CRITICAL_TRACKED_FILES
    )
    assert "wait_cohort_causal_phase_outputs.py" in wrapper.CRITICAL_TRACKED_FILES


def _write(path: Path, payload: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _smoke_gate(provenance: dict[str, Any]) -> bytes:
    value = {
        "decision": "pass",
        "errors": [],
        "limitation": "not exact historical replication",
        "mechanism_label": "frozen-tape weight-update ablation",
        "provenance_sha256": wrapper._canonical_object_sha256(provenance),
        "schema_version": 1,
        "statistical_addendum_sha256": provenance.get("statistical_addendum_sha256"),
        "status": "pass",
        "tape_sha256": "4" * 64,
        "terminal_actions": {"active": {}, "lr0": {}},
        "trainable_param_sha256_initial": "5" * 64,
    }
    return json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"


def _git(checkout: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", checkout.as_posix(), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_real_handoff_round_trip_binds_fresh_commit_scoped_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    for filename in wrapper.CRITICAL_TRACKED_FILES:
        _write(
            staging / filename, (Path(wrapper.__file__).parent / filename).read_bytes()
        )
    _write(staging / ".gitignore", b"__pycache__/\n")
    _git(staging, "init", "-q")
    _git(staging, "config", "user.name", "Test")
    _git(staging, "config", "user.email", "test@example.com")
    _git(staging, "add", ".")
    _git(staging, "commit", "-qm", "fresh retry")
    commit = _git(staging, "rev-parse", "HEAD")

    checkout_base = tmp_path / "checkout"
    durable_base = tmp_path / "durable"
    monkeypatch.setattr(wrapper, "CHECKOUT_BASE", checkout_base)
    monkeypatch.setattr(wrapper, "DURABLE_BASE", durable_base)
    monkeypatch.setattr(wrapper, "REQUIRE_PUSHED_REMOTE_REF", False)
    checkout = checkout_base / commit / wrapper.RETRY_ID / wrapper.ATTEMPT_ID
    checkout.parent.mkdir(parents=True)
    staging.rename(checkout)
    durable = (
        durable_base
        / commit
        / "retries"
        / wrapper.RETRY_ID
        / "attempts"
        / wrapper.ATTEMPT_ID
    )
    artifact = durable / "artifacts" / "cohort_causal"
    for directory in (artifact, durable / "control", durable / "prep"):
        directory.mkdir(parents=True, exist_ok=True)
    tooling = durable / "control" / "verifier" / commit
    tooling.mkdir(parents=True)
    for filename in (
        "build_cohort_structured_state_execution_seal.py",
        "build_cohort_structured_state_execution_seal_v2.py",
    ):
        _write(tooling / filename, (checkout / filename).read_bytes())
    (checkout / "artifacts").symlink_to(durable / "artifacts", target_is_directory=True)
    provenance_value = {
        "source_commit": commit,
        "statistical_addendum_sha256": "6" * 64,
    }
    provenance = _write(
        artifact / "provenance.json", wrapper._canonical_bytes(provenance_value)
    )
    _write(artifact / "smoke_gate.json", _smoke_gate(provenance_value))
    transport = Path("/tmp/cohort-causal-formal-retry") / commit
    handoff_path = transport / wrapper.HANDOFF_FILENAME
    shutil.rmtree(transport, ignore_errors=True)
    try:
        handoff = wrapper.make_handoff(
            checkout_root=checkout,
            durable_attempt_root=durable,
            provenance_path=provenance,
            handoff_path=handoff_path,
        )
        wrapper.publish_handoff(handoff_path, handoff)
        loaded, raw = wrapper.load_handoff(handoff_path)
        assert loaded == handoff
        assert raw == wrapper._canonical_bytes(handoff)
        assert loaded["source_commit"] == commit
        module = wrapper._load_commit_qualified_v2(
            loaded, {"tooling_root": tooling.as_posix()}
        )
        assert (
            module.v1.__file__
            == (tooling / module.v1.__file__.split("/")[-1]).as_posix()
        )
        _write(checkout / "__pycache__" / "sitecustomize.cpython-310.pyc", b"shadow")
        with pytest.raises(wrapper.RegisteredFormalError, match="artifacts symlink"):
            wrapper.load_handoff(handoff_path)
    finally:
        shutil.rmtree(transport, ignore_errors=True)


def _minimal_handoff(tmp_path: Path) -> dict[str, Any]:
    commit = "1" * 40
    checkout = tmp_path / wrapper.RETRY_ID / ("1" * 40) / wrapper.ATTEMPT_ID
    durable = (
        tmp_path
        / "durable"
        / wrapper.RETRY_ID
        / ("1" * 40)
        / "attempts"
        / wrapper.ATTEMPT_ID
    )
    artifact = durable / "artifacts" / "cohort_causal"
    control = durable / "control"
    prep = durable / "prep"
    transport = tmp_path / "transport"
    tooling = control / "verifier" / commit
    for directory in (checkout, artifact, control, prep, transport, tooling):
        directory.mkdir(parents=True, exist_ok=True)
    provenance_value: dict[str, Any] = {}
    files = {
        "provenance": _write(
            artifact / "provenance.json", wrapper._canonical_bytes(provenance_value)
        ),
        "smoke_gate": _write(
            artifact / "smoke_gate.json", _smoke_gate(provenance_value)
        ),
        "smoke_validator": _write(
            checkout / "validate_cohort_causal_smoke.py", b"validator"
        ),
        "wrapper_source": _write(checkout / Path(wrapper.__file__).name, b"source"),
        "formal_grid": _write(checkout / "grid_cohort_causal_formal.json", b"{}"),
        "launcher": _write(checkout / "launch_cohort_causal.sh", b"#!/bin/sh\n"),
        "retry_amendment": _write(checkout / "retry-amendment.md", b"amendment"),
        "v1_plan_loader": _write(
            checkout / "build_cohort_structured_state_execution_seal.py", b"v1-loader"
        ),
        "v2_plan_loader": _write(
            checkout / "build_cohort_structured_state_execution_seal_v2.py",
            b"v2-loader",
        ),
    }
    _write(tooling / files["v1_plan_loader"].name, files["v1_plan_loader"].read_bytes())
    _write(tooling / files["v2_plan_loader"].name, files["v2_plan_loader"].read_bytes())
    wrapper_transport = _write(transport / Path(wrapper.__file__).name, b"source")
    handoff_path = transport / wrapper.HANDOFF_FILENAME
    handoff = {
        "artifact_root": artifact.as_posix(),
        "attempt_id": wrapper.ATTEMPT_ID,
        "authorization_path": (control / wrapper.AUTHORIZATION_FILENAME).as_posix(),
        "authorization_timeout_seconds": 10,
        "checkout_root": checkout.as_posix(),
        "collector_gpus": list(wrapper.COLLECTOR_GPUS),
        "durable_attempt_root": durable.as_posix(),
        "eval_gpus": list(wrapper.EVAL_GPUS),
        "exit_path": (prep / "causal_formal.exit").as_posix(),
        "formal_decision_path": (artifact / "formal_decision.json").as_posix(),
        "formal_grid": wrapper._binding(files["formal_grid"], "grid"),
        "formal_manifest_path": (artifact / "formal_manifest.json").as_posix(),
        "handoff_path": handoff_path.as_posix(),
        "launch_expectation_path": (control / wrapper.EXPECTATION_FILENAME).as_posix(),
        "launcher": wrapper._binding(files["launcher"], "launcher"),
        "max_used_memory_mib": 1024,
        "outcome_blind": True,
        "pid_path": (prep / "causal_formal.pid").as_posix(),
        "poll_interval_seconds": 0.01,
        "protocol": wrapper.HANDOFF_PROTOCOL,
        "provenance": wrapper._binding(files["provenance"], "provenance"),
        "pushed_remote_refs": [],
        "ready_path": (transport / wrapper.READY_FILENAME).as_posix(),
        "retry_amendment": wrapper._binding(
            files["retry_amendment"], "retry amendment"
        ),
        "retry_id": wrapper.RETRY_ID,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "smoke_gate": wrapper._binding(files["smoke_gate"], "smoke gate"),
        "smoke_validator": wrapper._binding(
            files["smoke_validator"], "smoke validator"
        ),
        "source_commit": "1" * 40,
        "source_tree_sha256": "3" * 64,
        "status": wrapper.HANDOFF_STATUS,
        "v1_execution_plan_path": (control / wrapper.V1_PLAN_FILENAME).as_posix(),
        "v1_plan_loader": wrapper._binding(
            tooling / files["v1_plan_loader"].name, "v1 loader"
        ),
        "v2_detached_handoff_path": (
            transport / wrapper.V2_HANDOFF_FILENAME
        ).as_posix(),
        "v2_execution_plan_path": (control / wrapper.V2_PLAN_FILENAME).as_posix(),
        "v2_plan_loader": wrapper._binding(
            tooling / files["v2_plan_loader"].name, "v2 loader"
        ),
        "v2_procfs_inventory_path": (
            control / wrapper.V2_INVENTORY_FILENAME
        ).as_posix(),
        "wrapper_source": wrapper._binding(files["wrapper_source"], "wrapper"),
        "wrapper_transport": wrapper._binding(wrapper_transport, "wrapper transport"),
    }
    _write(handoff_path, wrapper._canonical_bytes(handoff))
    return handoff


def _expectation(handoff: dict[str, Any], *, pid: int = 7001, ticks: int = 9001):
    pid_raw = f"{pid}\n".encode()
    value = {
        "artifact_root": handoff["artifact_root"],
        "attempt_id": wrapper.ATTEMPT_ID,
        "boot_id": wrapper._boot_id(),
        "checkout_root": handoff["checkout_root"],
        "collector_gpus": list(wrapper.COLLECTOR_GPUS),
        "created_at_utc": "2026-07-15T00:00:00Z",
        "durable_attempt_root": handoff["durable_attempt_root"],
        "eval_gpus": list(wrapper.EVAL_GPUS),
        "exit_file": handoff["exit_path"],
        "expected_final_inventory": dict(wrapper.EXPECTED_FINAL_INVENTORY),
        "formal_grid_file_sha256": handoff["formal_grid"]["sha256"],
        "launch_mode": "formal",
        "launcher_file_sha256": handoff["launcher"]["sha256"],
        "max_used_memory_mib": 1024,
        "node_hostname": wrapper.socket.gethostname(),
        "pid_file": handoff["pid_path"],
        "pid_file_sha256_at_registration": wrapper._sha256(pid_raw),
        "protocol": "cohort_causal_formal_launch_expectation_v1",
        "provenance_file_sha256": handoff["provenance"]["sha256"],
        "schema_version": 1,
        "source_commit": handoff["source_commit"],
        "wrapper_cmdline_sha256_at_registration": wrapper._sha256(b"cmdline"),
        "wrapper_pid": pid,
        "wrapper_start_ticks": ticks,
    }
    return value, pid_raw


def test_registers_pid_expectation_and_ready_before_any_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _minimal_handoff(tmp_path)
    expectation, pid_raw = _expectation(handoff)
    monkeypatch.setattr(
        wrapper,
        "load_handoff",
        lambda _path: (handoff, Path(handoff["handoff_path"]).read_bytes()),
    )
    monkeypatch.setattr(
        wrapper, "_make_expectation", lambda _handoff: (expectation, pid_raw)
    )
    events: list[tuple[str, str]] = []
    original_publish = wrapper._publish_no_overwrite
    original_wait = wrapper._wait_for_stable_regular

    def publish(path: Path, payload: bytes) -> None:
        events.append(("publish", path.name))
        original_publish(path, payload)

    def wait(path: Path, label: str, **kwargs: Any) -> bytes:
        events.append(("wait", label))
        return original_wait(path, label, **kwargs)

    monkeypatch.setattr(wrapper, "_publish_no_overwrite", publish)
    monkeypatch.setattr(wrapper, "_wait_for_stable_regular", wait)

    observed_handoff, ready = wrapper.register_wrapper(
        Path(handoff["handoff_path"]), validate_runtime=False
    )

    assert observed_handoff is handoff
    assert Path(handoff["pid_path"]).read_bytes() == pid_raw
    assert (
        json.loads(Path(handoff["launch_expectation_path"]).read_bytes()) == expectation
    )
    assert ready["status"] == wrapper.READY_STATUS
    ready_publish = events.index(("publish", wrapper.READY_FILENAME))
    assert events.index(("wait", "wrapper PID file")) < ready_publish
    assert events.index(("wait", "launch expectation")) < ready_publish
    assert not Path(handoff["formal_manifest_path"]).exists()
    assert not Path(handoff["formal_decision_path"]).exists()
    assert not Path(handoff["exit_path"]).exists()


def test_runner_cannot_start_before_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _minimal_handoff(tmp_path)
    called = False

    monkeypatch.setattr(os, "getppid", lambda: 1)
    monkeypatch.setattr(wrapper, "register_wrapper", lambda _path: (handoff, {}))
    monkeypatch.setattr(
        wrapper,
        "_wait_for_authorization",
        lambda _handoff: (_ for _ in ()).throw(
            wrapper.RegisteredFormalError("no auth")
        ),
    )

    def runner(*_args: Any, **_kwargs: Any):
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0)

    with pytest.raises(wrapper.RegisteredFormalError, match="no auth"):
        wrapper.run_registered_wrapper(Path(handoff["handoff_path"]), runner=runner)
    assert called is False


def test_wait_for_authorization_fences_before_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _minimal_handoff(tmp_path)
    authorization = _write(Path(handoff["authorization_path"]), b"authorization")
    events: list[str] = []

    def wait(path: Path, label: str, **_kwargs: Any) -> bytes:
        assert path == authorization
        assert label == "formal start authorization"
        events.append("stable")
        return authorization.read_bytes()

    def validate(_handoff: dict[str, Any], path: Path) -> dict[str, Any]:
        assert _handoff is handoff
        assert path == authorization
        events.append("validate")
        return {"status": "authorized"}

    monkeypatch.setattr(wrapper, "_wait_for_stable_regular", wait)
    monkeypatch.setattr(wrapper, "_validate_authorization", validate)

    result = wrapper._wait_for_authorization(handoff)

    assert result == {"status": "authorized"}
    assert events == ["stable", "validate"]


def test_nonzero_runner_passes_both_outcomes_to_exit_publisher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _minimal_handoff(tmp_path)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(os, "getppid", lambda: 1)
    monkeypatch.setattr(wrapper, "register_wrapper", lambda _path: (handoff, {}))
    monkeypatch.setattr(wrapper, "_wait_for_authorization", lambda _handoff: {})
    monkeypatch.setattr(
        wrapper, "_validate_authorization", lambda *_args, **_kwargs: {}
    )

    def publish_exit(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(wrapper, "publish_exit_marker", publish_exit)
    return_code = wrapper.run_registered_wrapper(
        Path(handoff["handoff_path"]),
        runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=2),
    )

    assert return_code == 2
    assert captured["return_code"] == 2
    assert captured["outcome_paths"] == [
        Path(handoff["formal_manifest_path"]),
        Path(handoff["formal_decision_path"]),
    ]


def test_no_overwrite_collision_preserves_existing_authority(tmp_path: Path) -> None:
    target = _write(tmp_path / "authority.json", b"keep-me")
    with pytest.raises(FileExistsError):
        wrapper._publish_no_overwrite(target, b"replacement")
    assert target.read_bytes() == b"keep-me"
    assert not list(tmp_path.glob(".authority.json.tmp.publish.*"))


def test_stable_reader_rejects_hardlink_alias(tmp_path: Path) -> None:
    target = _write(tmp_path / "authority.json", b"authority")
    os.link(target, tmp_path / "alias.json")
    with pytest.raises(wrapper.RegisteredFormalError, match="single-link"):
        wrapper._read_regular(target, "authority")


def test_formal_manifest_and_decision_publishers_never_overwrite(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "formal_manifest.json"
    decision = tmp_path / "formal_decision.json"
    smoke = tmp_path / "smoke_gate.json"
    _atomic_write_json(manifest, {"status": "opaque"})
    publish_decision(decision, b"opaque-decision\n")
    publish_smoke(smoke, {"status": "pass"})
    assert manifest.stat().st_nlink == 1
    assert decision.stat().st_nlink == 1
    assert smoke.stat().st_nlink == 1
    with pytest.raises(FileExistsError):
        _atomic_write_json(manifest, {"status": "replacement"})
    with pytest.raises(FileExistsError):
        publish_decision(decision, b"replacement\n")
    with pytest.raises(FileExistsError):
        publish_smoke(smoke, {"status": "replacement"})
    assert json.loads(manifest.read_bytes()) == {"status": "opaque"}
    assert decision.read_bytes() == b"opaque-decision\n"
    assert json.loads(smoke.read_bytes()) == {"status": "pass"}


def _prepare_authorization_controls(
    handoff: dict[str, Any], *, pid: int = 7001, ticks: int = 9001
) -> dict[str, Any]:
    expectation, pid_raw = _expectation(handoff, pid=pid, ticks=ticks)
    _write(Path(handoff["pid_path"]), pid_raw)
    _write(
        Path(handoff["launch_expectation_path"]), wrapper._canonical_bytes(expectation)
    )
    ready = {
        "handoff": wrapper._binding(Path(handoff["handoff_path"]), "handoff"),
        "launch_expectation": wrapper._binding(
            Path(handoff["launch_expectation_path"]), "expectation"
        ),
        "outcome_blind": True,
        "pid_file": wrapper._binding(Path(handoff["pid_path"]), "pid"),
        "protocol": wrapper.READY_PROTOCOL,
        "retry_id": wrapper.RETRY_ID,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "source_commit": handoff["source_commit"],
        "status": wrapper.READY_STATUS,
        "wrapper_pid": pid,
        "wrapper_start_ticks": ticks,
    }
    _write(Path(handoff["ready_path"]), wrapper._canonical_bytes(ready))
    ready["_expectation"] = expectation
    invocations = {
        stage: {
            "argv": [wrapper.EXPECTED_PYTHON_PATH, f"/{stage}.py"],
            "inputs": {"input": f"/{stage}.input"},
            "outputs": {"output": f"/{stage}.output"},
            "parameters": {},
        }
        for stage in wrapper.STAGES
    }
    plan = {"invocations": invocations, "tooling_root": "/tmp/tooling"}
    _write(Path(handoff["v2_execution_plan_path"]), json.dumps(plan).encode())
    _write(Path(handoff["v1_execution_plan_path"]), b"v1")
    _write(Path(handoff["v2_detached_handoff_path"]), b"v2-handoff")
    _write(Path(handoff["v2_procfs_inventory_path"]), b"v2-inventory")
    return ready


def test_authorization_executes_all_three_registered_stage_preflights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _minimal_handoff(tmp_path)
    ready = _prepare_authorization_controls(handoff)
    calls: list[str] = []
    monkeypatch.setattr(
        wrapper,
        "load_handoff",
        lambda _path: (handoff, Path(handoff["handoff_path"]).read_bytes()),
    )
    monkeypatch.setattr(
        wrapper,
        "_load_ready",
        lambda _handoff: (ready, Path(handoff["ready_path"]).read_bytes()),
    )
    monkeypatch.setattr(
        wrapper, "_assert_terminal_launcher_not_started", lambda *_args: None
    )

    def validate(**kwargs: Any) -> None:
        calls.append(kwargs["stage"])
        assert kwargs["actual_argv"][1] == f"/{kwargs['stage']}.py"

    authorization = wrapper.authorize_formal_start(
        Path(handoff["handoff_path"]),
        validator=validate,
        identity_fn=lambda _pid: (ready["wrapper_start_ticks"], b"cmdline"),
    )
    assert calls == list(wrapper.STAGES)
    assert authorization["preflight_stages"] == list(wrapper.STAGES)
    assert Path(handoff["authorization_path"]).is_file()


def test_authorization_binding_drift_fails_before_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _minimal_handoff(tmp_path)
    ready = _prepare_authorization_controls(handoff, pid=os.getpid(), ticks=123)
    monkeypatch.setattr(wrapper, "_process_identity", lambda _pid: (123, b"cmdline"))
    monkeypatch.setattr(wrapper, "_pid_start_ticks", lambda _pid: 123)
    monkeypatch.setattr(wrapper, "_preflight_v2_stages", lambda _handoff: None)
    monkeypatch.setattr(
        wrapper,
        "load_handoff",
        lambda _path: (handoff, Path(handoff["handoff_path"]).read_bytes()),
    )
    bindings = {
        name: wrapper._binding(path, name)
        for name, path in wrapper._authorization_paths(handoff).items()
    }
    auth = {
        "authorized_at_utc": "2026-07-15T00:01:00Z",
        "control_bindings": bindings,
        "outcome_blind": True,
        "preflight_stages": list(wrapper.STAGES),
        "protocol": wrapper.AUTHORIZATION_PROTOCOL,
        "retry_id": wrapper.RETRY_ID,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "source_commit": handoff["source_commit"],
        "status": wrapper.AUTHORIZATION_STATUS,
        "wrapper_pid": os.getpid(),
        "wrapper_start_ticks": ready["wrapper_start_ticks"],
    }
    auth_path = Path(handoff["authorization_path"])
    _write(auth_path, wrapper._canonical_bytes(auth))
    Path(handoff["v1_execution_plan_path"]).write_bytes(b"drift")
    with pytest.raises(wrapper.RegisteredFormalError, match="bytes drifted"):
        wrapper._validate_authorization(handoff, auth_path)


def test_ready_join_and_authorization_bind_pid_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _minimal_handoff(tmp_path)
    ready = _prepare_authorization_controls(handoff, pid=os.getpid(), ticks=123)
    ready_path = Path(handoff["ready_path"])
    ready_document = json.loads(ready_path.read_bytes())
    ready_document["wrapper_pid"] += 1
    ready_path.write_bytes(wrapper._canonical_bytes(ready_document))
    with pytest.raises(wrapper.RegisteredFormalError, match="identity differ"):
        wrapper._load_ready(handoff)

    ready_path.unlink()
    ready = _prepare_authorization_controls(handoff, pid=os.getpid(), ticks=123)
    monkeypatch.setattr(wrapper, "_pid_start_ticks", lambda _pid: 123)
    monkeypatch.setattr(wrapper, "_process_identity", lambda _pid: (123, b"cmdline"))
    monkeypatch.setattr(wrapper, "_preflight_v2_stages", lambda _handoff: None)
    monkeypatch.setattr(
        wrapper,
        "load_handoff",
        lambda _path: (handoff, Path(handoff["handoff_path"]).read_bytes()),
    )
    bindings = {
        name: wrapper._binding(path, name)
        for name, path in wrapper._authorization_paths(handoff).items()
    }
    auth = {
        "authorized_at_utc": "2026-07-15T00:01:00Z",
        "control_bindings": bindings,
        "outcome_blind": True,
        "preflight_stages": list(wrapper.STAGES),
        "protocol": wrapper.AUTHORIZATION_PROTOCOL,
        "retry_id": wrapper.RETRY_ID,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "source_commit": handoff["source_commit"],
        "status": wrapper.AUTHORIZATION_STATUS,
        "wrapper_pid": os.getpid(),
        "wrapper_start_ticks": ready["wrapper_start_ticks"],
    }
    auth_path = _write(
        Path(handoff["authorization_path"]), wrapper._canonical_bytes(auth)
    )
    Path(handoff["pid_path"]).write_bytes(b"999999\n")
    with pytest.raises(wrapper.RegisteredFormalError, match="bytes drifted"):
        wrapper._validate_authorization(handoff, auth_path)
    Path(handoff["pid_path"]).write_bytes(f"{os.getpid()}\n".encode())
    Path(handoff["smoke_gate"]["path"]).write_bytes(b"tampered-smoke")
    with pytest.raises(wrapper.RegisteredFormalError, match="bytes drifted"):
        wrapper._validate_authorization(handoff, auth_path)


def test_exit_marker_waits_past_equal_second_then_publishes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write(tmp_path / "formal_manifest.json", b"opaque-manifest")
    decision = _write(tmp_path / "formal_decision.json", b"opaque-decision")
    exit_path = tmp_path / "causal_formal.exit"
    threshold = max(manifest.stat().st_mtime_ns, decision.stat().st_mtime_ns)
    probe_calls = 0

    def mtime(path: Path) -> int:
        nonlocal probe_calls
        if path == exit_path:
            return threshold + 1
        if path.name.startswith(".causal_formal.exit.tmp.candidate"):
            probe_calls += 1
            return threshold if probe_calls == 1 else threshold + 1
        return path.stat().st_mtime_ns

    monkeypatch.setattr(wrapper, "_mtime_ns", mtime)
    result = wrapper.publish_exit_marker(
        exit_path=exit_path,
        return_code=0,
        outcome_paths=[manifest, decision],
        sleep_fn=lambda _seconds: None,
    )
    assert probe_calls == 2
    assert exit_path.read_bytes() == b"0\n"
    assert result["strictly_later"] is True
    with pytest.raises(FileExistsError):
        wrapper.publish_exit_marker(
            exit_path=exit_path,
            return_code=0,
            outcome_paths=[manifest, decision],
        )


def test_exit_marker_never_semantically_decodes_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write(tmp_path / "formal_manifest.json", b"not-json-manifest")
    decision = _write(tmp_path / "formal_decision.json", b"not-json-decision")
    exit_path = tmp_path / "causal_formal.exit"
    threshold = max(manifest.stat().st_mtime_ns, decision.stat().st_mtime_ns)
    monkeypatch.setattr(wrapper, "_mtime_ns", lambda path: threshold + 1)
    monkeypatch.setattr(
        wrapper.json,
        "loads",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("decoded")),
    )
    wrapper.publish_exit_marker(
        exit_path=exit_path,
        return_code=0,
        outcome_paths=[manifest, decision],
    )
    assert exit_path.read_bytes() == b"0\n"


def test_exit_marker_rejects_outcome_inode_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write(tmp_path / "formal_manifest.json", b"opaque-manifest")
    decision = _write(tmp_path / "formal_decision.json", b"opaque-decision")
    exit_path = tmp_path / "causal_formal.exit"
    original_publish = wrapper._publish_no_overwrite
    swapped = False

    def publish(path: Path, payload: bytes) -> None:
        nonlocal swapped
        original_publish(path, payload)
        if ".tmp.candidate." in path.name and not swapped:
            replacement = _write(tmp_path / "replacement", b"replacement-decision")
            os.replace(replacement, decision)
            swapped = True

    monkeypatch.setattr(wrapper, "_publish_no_overwrite", publish)
    monkeypatch.setattr(
        wrapper,
        "_mtime_ns",
        lambda path: max(manifest.stat().st_mtime_ns, decision.stat().st_mtime_ns) + 1,
    )
    with pytest.raises(wrapper.RegisteredFormalError, match="changed"):
        wrapper.publish_exit_marker(
            exit_path=exit_path,
            return_code=0,
            outcome_paths=[manifest, decision],
        )
    assert not exit_path.exists()
    assert list(tmp_path.glob(".causal_formal.exit.tmp.candidate.*"))
