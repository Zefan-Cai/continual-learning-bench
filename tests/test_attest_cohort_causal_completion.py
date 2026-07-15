from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

import attest_cohort_causal_completion as att
import build_cohort_structured_state_execution_seal as seal_builder


SOURCE_COMMIT = "1" * 40
BOOT_ID = "12345678-1234-1234-1234-123456789abc"
HOSTNAME = "completion-test-node"
WRAPPER_PID = 99_999_991


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write(path: Path, payload: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = payload.encode() if isinstance(payload, str) else payload
    path.write_bytes(data)
    return path


def _write_json(path: Path, value: Any) -> Path:
    return _write(path, json.dumps(value, sort_keys=True) + "\n")


def _record(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    payload = path.read_bytes()
    return {
        "path": relative,
        "role": "evaluation_code",
        "sha256": _sha256(payload),
        "size_bytes": len(payload),
    }


class _Clock:
    def __init__(self, mutation=None) -> None:
        self.value = 100.0
        self.mutation = mutation
        self.sleep_calls: list[float] = []
        self.now_index = 0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)
        if self.mutation is not None:
            self.mutation()
        self.value += seconds

    def now(self) -> str:
        self.now_index += 1
        return f"2026-07-14T12:00:0{self.now_index}Z"


def _passing_process_audit(*, attempt_checkout: Path, artifact_root: Path):
    payload = {
        "status": "pass",
        "attempt_checkout_path": attempt_checkout.as_posix(),
        "artifact_root_path": artifact_root.as_posix(),
        "method": "focused_test_process_audit",
    }
    return {**payload, "audit_sha256": att.canonical_sha256(payload)}


@pytest.fixture
def completed_attempt(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path / "checkout"
    durable = tmp_path / "durable" / "attempt-002"
    artifact_root = durable / "artifacts" / "cohort_causal"
    prep = durable / "prep"
    control = durable / "control"
    tooling_root = control / "verifier" / ("a" * 40)
    for path in (root, artifact_root, prep, control, tooling_root):
        path.mkdir(parents=True, exist_ok=True)

    launcher = _write(root / "launch_cohort_causal.sh", "#!/bin/sh\nexit 0\n")
    prereg = _write(root / "COHORT_QONLY_CAUSAL_PREREG.md", "frozen prereg\n")
    addendum = _write(
        root / "COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md",
        "frozen addendum\n",
    )

    datasets: dict[str, dict[str, Any]] = {}
    for role in ("adaptation", "heldout"):
        schedule_id = f"causal_{role}_test"
        schedule = _write(
            root / "src/tasks/cohort_studies/schedules" / f"{schedule_id}.json",
            f"schedule-{role}\n",
        )
        dataset_relative = Path("data/cohort_studies") / schedule_id
        dataset_root = root / dataset_relative
        ground_truth = _write(dataset_root / "ground_truth.bin", b"\xffGT-" + role.encode())
        database = _write(dataset_root / "dbs" / "study.db", b"\x00DB-" + role.encode())
        artifact_records = []
        for path in (ground_truth, database):
            relative = path.relative_to(dataset_root).as_posix()
            payload = path.read_bytes()
            artifact_records.append(
                {
                    "path": relative,
                    "sha256": _sha256(payload),
                    "size_bytes": len(payload),
                }
            )
        corpus_sha256 = _sha256(f"corpus-{role}".encode())
        schedule_sha256 = _sha256(schedule.read_bytes())
        _write_json(
            dataset_root / "manifest.json",
            {
                "artifacts": artifact_records,
                "corpus_sha256": corpus_sha256,
                "schedule_id": schedule_id,
                "schedule_sha256": schedule_sha256,
            },
        )
        datasets[role] = {
            "path": dataset_relative.as_posix(),
            "schedule": schedule_id,
            "seed": 1 if role == "adaptation" else 2,
            "corpus_sha256": corpus_sha256,
            "schedule_sha256": schedule_sha256,
        }

    collectors = []
    cells = []
    formal_paths: list[Path] = []
    for index in range(3):
        cfg_id = f"collector_formal_{index}"
        tape_relative = Path("artifacts/cohort_causal/tapes") / f"{cfg_id}.json"
        collectors.append({"cfg_id": cfg_id, "tape_path": tape_relative.as_posix()})
        formal_paths.extend(
            [
                _write(artifact_root / "tapes" / f"{cfg_id}.json", b"\xfftape"),
                _write(
                    artifact_root / "collectors" / f"{cfg_id}.manifest.json",
                    b"not-json-collector",
                ),
                _write(
                    artifact_root / "traces" / f"{cfg_id}.trace.json",
                    b"\x80collector-trace",
                ),
                _write(
                    artifact_root
                    / "sealed_logs"
                    / "formal"
                    / f"{cfg_id}.stdout_stderr.age",
                    b"age-encrypted-collector-log",
                ),
                _write(
                    artifact_root
                    / "sealed_logs"
                    / "formal"
                    / f"{cfg_id}.receipt.json",
                    b"opaque-sealed-collector-receipt",
                ),
                _write(
                    artifact_root
                    / "sealed_logs"
                    / "formal"
                    / f"{cfg_id}.start.json",
                    b"opaque-sealed-collector-start-receipt",
                ),
            ]
        )
    for index in range(6):
        cfg_id = f"cell_formal_{index}"
        manifest_relative = (
            Path("artifacts/cohort_causal/cells") / f"{cfg_id}.manifest.json"
        )
        cells.append(
            {"cfg_id": cfg_id, "cell_manifest_path": manifest_relative.as_posix()}
        )
        formal_paths.extend(
            [
                _write(
                    artifact_root / "cells" / f"{cfg_id}.manifest.json",
                    b"\xffcell-manifest",
                ),
                _write(
                    artifact_root / "traces" / f"{cfg_id}.trace.json",
                    b"\x81cell-trace",
                ),
                _write(
                    artifact_root
                    / "sealed_logs"
                    / "formal"
                    / f"{cfg_id}.stdout_stderr.age",
                    b"age-encrypted-cell-log",
                ),
                _write(
                    artifact_root
                    / "sealed_logs"
                    / "formal"
                    / f"{cfg_id}.receipt.json",
                    b"opaque-sealed-cell-receipt",
                ),
                _write(
                    artifact_root
                    / "sealed_logs"
                    / "formal"
                    / f"{cfg_id}.start.json",
                    b"opaque-sealed-cell-start-receipt",
                ),
            ]
        )
    formal_manifest = _write(
        artifact_root / "formal_manifest.json", b"\xffopaque-formal-manifest"
    )
    formal_decision = _write(
        artifact_root / "formal_decision.json", b"\xfeopaque-formal-decision"
    )
    formal_paths.extend([formal_manifest, formal_decision])
    _write(artifact_root / "smoke_gate.json", b"opaque-smoke-gate")

    grid = {
        "schema_version": 1,
        "protocol": "test-causal",
        "mechanism_label": "test",
        "prereg_commit": SOURCE_COMMIT,
        "adapter_init_seed": 7,
        "kind": "formal",
        "datasets": datasets,
        "collectors": collectors,
        "evaluation_cells": cells,
    }
    grid_path = _write_json(root / "grid_cohort_causal_formal.json", grid)

    evaluation_allowlist = sorted(
        [
            prereg.relative_to(root).as_posix(),
            addendum.relative_to(root).as_posix(),
            grid_path.relative_to(root).as_posix(),
            launcher.relative_to(root).as_posix(),
        ]
    )
    evaluation_records = [_record(root, path) for path in evaluation_allowlist]
    evaluation_sha256 = att.canonical_sha256(evaluation_records)
    model_files = [
        {
            "path": "model.bin",
            "role": "weight",
            "sha256": _sha256(b"model"),
            "size_bytes": len(b"model"),
        }
    ]
    tokenizer_files = [
        {
            "path": "tokenizer.json",
            "role": "tokenizer",
            "sha256": _sha256(b"tokenizer"),
            "size_bytes": len(b"tokenizer"),
        }
    ]
    model_inventory_sha256 = att.canonical_sha256(model_files)
    tokenizer_inventory_sha256 = att.canonical_sha256(tokenizer_files)
    environment_payload: dict[str, Any] = {}
    environment_sha256 = att.canonical_sha256(environment_payload)
    provenance = {
        "adapter_init_seed": 7,
        "environment_lock_sha256": environment_sha256,
        "evaluation_code_sha256": evaluation_sha256,
        "model_path": "/models/test",
        "model_sha256": model_inventory_sha256,
        "preregistered_parent_commit": SOURCE_COMMIT,
        "source_commit": SOURCE_COMMIT,
        "statistical_addendum_sha256": _sha256(addendum.read_bytes()),
        "tokenizer_sha256": tokenizer_inventory_sha256,
    }
    provenance_path = _write_json(artifact_root / "provenance.json", provenance)
    details = {
        "canonicalization": "UTF-8 canonical JSON; sorted keys; compact separators",
        "environment": {
            "payload": environment_payload,
            "sha256": environment_sha256,
        },
        "evaluation_code": {
            "allowlist": evaluation_allowlist,
            "files": evaluation_records,
            "inventory_sha256": evaluation_sha256,
        },
        "git": {"source_commit": SOURCE_COMMIT, "tracked_checkout_clean": True},
        "hash_algorithm": "sha256",
        "kind": "cohort_causal_provenance_audit",
        "model": {
            "files": model_files,
            "inventory_sha256": model_inventory_sha256,
            "path": "/models/test",
        },
        "provenance": provenance,
        "schema_version": 1,
        "statistical_addendum": {
            "path": addendum.relative_to(root).as_posix(),
            "sha256": _sha256(addendum.read_bytes()),
            "size_bytes": addendum.stat().st_size,
        },
        "tokenizer": {
            "files": tokenizer_files,
            "inventory_sha256": tokenizer_inventory_sha256,
            "path": "/models/test",
        },
    }
    details_path = _write_json(artifact_root / "provenance.details.json", details)

    pid_path = _write(prep / "causal_formal.pid", f"{WRAPPER_PID}\n")
    exit_path = _write(prep / "causal_formal.exit", "0\n")
    old_ns = 1_700_000_000_000_000_000
    for path in (formal_manifest, formal_decision):
        os.utime(path, ns=(old_ns, old_ns))
    os.utime(exit_path, ns=(old_ns + 10_000_000, old_ns + 10_000_000))

    expectation = {
        "artifact_root": artifact_root.as_posix(),
        "attempt_id": "attempt-002",
        "boot_id": BOOT_ID,
        "checkout_root": root.as_posix(),
        "collector_gpus": [0, 2, 3],
        "created_at_utc": "2026-07-14T11:09:26Z",
        "durable_attempt_root": durable.as_posix(),
        "eval_gpus": [0, 2, 3, 4, 5, 6],
        "exit_file": exit_path.as_posix(),
        "expected_final_inventory": dict(att._EXPECTED_INVENTORY),
        "formal_grid_file_sha256": _sha256(grid_path.read_bytes()),
        "launch_mode": "formal",
        "launcher_file_sha256": _sha256(launcher.read_bytes()),
        "max_used_memory_mib": 1024,
        "node_hostname": HOSTNAME,
        "pid_file": pid_path.as_posix(),
        "pid_file_sha256_at_registration": _sha256(pid_path.read_bytes()),
        "protocol": "cohort_causal_formal_launch_expectation_v1",
        "provenance_file_sha256": _sha256(provenance_path.read_bytes()),
        "schema_version": 1,
        "source_commit": SOURCE_COMMIT,
        "wrapper_cmdline_sha256_at_registration": _sha256(b"wrapper command"),
        "wrapper_pid": WRAPPER_PID,
        "wrapper_start_ticks": 123456,
    }
    expectation_path = _write_json(
        control / seal_builder.LAUNCH_EXPECTATION_FILENAME, expectation
    )
    structured_preregistration = _write(
        tooling_root / seal_builder.STRUCTURED_PREREGISTRATION_FILENAME,
        b"prospective structured preregistration\n",
    )
    tool_sources = {
        "attester": Path(att.__file__).resolve(),
        "revalidator": Path(__file__).resolve().parents[1]
        / "revalidate_cohort_causal_terminal.py",
        "execution_seal_builder": Path(seal_builder.__file__).resolve(),
    }
    tools: dict[str, dict[str, str]] = {}
    for name, source in tool_sources.items():
        destination = tooling_root / source.name
        _write(destination, source.read_bytes())
        tools[name] = {
            "path": destination.as_posix(),
            "sha256": _sha256(destination.read_bytes()),
        }
    plan_path = control / seal_builder.PLAN_FILENAME
    revalidated = prep / seal_builder.REVALIDATED_FILENAME
    receipt = prep / seal_builder.REVALIDATION_RECEIPT_FILENAME
    seal_output = prep / seal_builder.SEAL_FILENAME
    attester_inputs = {
        "execution_plan": plan_path.as_posix(),
        "root": root.as_posix(),
        "launch_expectation": expectation_path.as_posix(),
        "provenance": provenance_path.as_posix(),
        "provenance_details": details_path.as_posix(),
    }
    revalidator_inputs = {
        "execution_plan": plan_path.as_posix(),
        "root": root.as_posix(),
        "attestation": (prep / seal_builder.ATTESTATION_FILENAME).as_posix(),
        "launch_expectation": expectation_path.as_posix(),
        "grid": grid_path.as_posix(),
        "provenance": provenance_path.as_posix(),
        "formal_manifest": formal_manifest.as_posix(),
        "formal_decision": formal_decision.as_posix(),
        "preregistration": prereg.as_posix(),
        "statistical_addendum": addendum.as_posix(),
    }
    builder_inputs = {
        "execution_plan": plan_path.as_posix(),
        "attestation": (prep / seal_builder.ATTESTATION_FILENAME).as_posix(),
        "launch_expectation": expectation_path.as_posix(),
        "causal_original": formal_decision.as_posix(),
        "causal_revalidated": revalidated.as_posix(),
        "revalidation_receipt": receipt.as_posix(),
        "structured_preregistration": structured_preregistration.as_posix(),
    }
    plan = {
        "attempt_id": "attempt-002",
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": seal_builder.CAUSAL_PROTOCOL_SEAL_STATUS,
        "causal_checkout_root": root.as_posix(),
        "created_at_utc": "2026-07-14T11:10:00Z",
        "durable_attempt_root": durable.as_posix(),
        "invocations": {
            "attester": {
                "argv": [],
                "inputs": attester_inputs,
                "outputs": {
                    "attestation": (prep / seal_builder.ATTESTATION_FILENAME).as_posix()
                },
                "parameters": {"stability_seconds": "1.0"},
            },
            "revalidator": {
                "argv": [],
                "inputs": revalidator_inputs,
                "outputs": {
                    "revalidated_decision": revalidated.as_posix(),
                    "revalidation_receipt": receipt.as_posix(),
                },
                "parameters": {},
            },
            "execution_seal_builder": {
                "argv": [],
                "inputs": builder_inputs,
                "outputs": {"execution_seal": seal_output.as_posix()},
                "parameters": {},
            },
        },
        "launch_expectation": {
            "path": expectation_path.as_posix(),
            "sha256": _sha256(expectation_path.read_bytes()),
        },
        "online_icl": None,
        "protocol": seal_builder.PLAN_PROTOCOL,
        "runtime": {
            "python_path": seal_builder.EXPECTED_PYTHON_PATH,
            "python_version": seal_builder.EXPECTED_PYTHON_VERSION,
        },
        "schema_version": 1,
        "status": "registered",
        "structured_preregistration": {
            "path": structured_preregistration.as_posix(),
            "sha256": _sha256(structured_preregistration.read_bytes()),
        },
        "tooling_root": tooling_root.as_posix(),
        "tooling_source_commit": "a" * 40,
        "tools": tools,
    }
    for stage in seal_builder.PLAN_INVOCATION_NAMES:
        plan["invocations"][stage]["argv"] = seal_builder._expected_argv(plan, stage)
    _write(plan_path, seal_builder._canonical_bytes(plan))
    return {
        "root": root,
        "durable": durable,
        "artifact_root": artifact_root,
        "prep": prep,
        "grid": grid,
        "grid_path": grid_path,
        "formal_paths": formal_paths,
        "formal_manifest": formal_manifest,
        "formal_decision": formal_decision,
        "pid_path": pid_path,
        "exit_path": exit_path,
        "expectation_path": expectation_path,
        "provenance_path": provenance_path,
        "details_path": details_path,
        "output": prep / seal_builder.ATTESTATION_FILENAME,
        "plan": plan,
        "plan_path": plan_path,
    }


def _run(completed_attempt: dict[str, Any], *, clock=None, **overrides):
    clock = clock or _Clock()
    kwargs = {
        "root": completed_attempt["root"],
        "execution_plan_path": completed_attempt["plan_path"],
        "launch_expectation_path": completed_attempt["expectation_path"],
        "provenance_path": completed_attempt["provenance_path"],
        "provenance_details_path": completed_attempt["details_path"],
        "output": completed_attempt["output"],
        "stability_seconds": 1.0,
        "sleep_fn": clock.sleep,
        "monotonic_fn": clock.monotonic,
        "now_fn": clock.now,
        "pid_is_live_fn": lambda _pid: False,
        "process_audit_fn": _passing_process_audit,
        "temporary_audit_fn": att._scan_live_or_temporary,
        "boot_id_fn": lambda: BOOT_ID,
        "hostname_fn": lambda: HOSTNAME,
        "source_commit_fn": lambda _root: SOURCE_COMMIT,
        "actual_argv": completed_attempt["plan"]["invocations"]["attester"][
            "argv"
        ],
        "runtime_python_path": seal_builder.EXPECTED_PYTHON_PATH,
        "runtime_python_version": seal_builder.EXPECTED_PYTHON_VERSION,
    }
    kwargs.update(overrides)
    return att.build_and_publish_attestation(**kwargs)


def test_attests_opaque_non_json_formal_bytes_without_semantic_parse(
    completed_attempt,
):
    result = _run(completed_attempt)
    assert result["status"] == "complete"
    assert set(result) == {
        "attestation_sha256",
        "causal_pre_attestation_inventory_sha256",
        "path",
        "status",
    }
    assert completed_attempt["output"].is_file()
    output_bytes = completed_attempt["output"].read_bytes()
    report = json.loads(output_bytes)
    assert output_bytes == att.canonical_bytes(report)
    assert set(report) == att.ATTESTATION_KEYS
    assert report["protocol"] == att.PROTOCOL
    assert report["registered_counts"] == att._EXPECTED_INVENTORY
    assert report["stability"]["snapshots_identical"] is True
    assert report["snapshots"][0]["files"] == report["snapshots"][1]["files"]
    assert report["causal_pre_attestation_inventory_sha256"] == att.inventory_sha256(
        report["snapshots"][0]["files"]
    )
    assert completed_attempt["output"].as_posix() not in {
        item["path"] for item in report["snapshots"][0]["files"]
    }
    assert report["expected_launcher"]["launch_expectation_sha256"] == _sha256(
        completed_attempt["expectation_path"].read_bytes()
    )


def test_rejects_duplicate_registered_cfg_id(completed_attempt):
    grid = copy.deepcopy(completed_attempt["grid"])
    grid["evaluation_cells"][1]["cfg_id"] = grid["evaluation_cells"][0]["cfg_id"]
    builder = att._InventoryBuilder(
        permitted_roots=(completed_attempt["root"], completed_attempt["durable"])
    )
    with pytest.raises(att.AttestationError, match="cfg_id"):
        att._add_formal_inventory(
            root=completed_attempt["root"],
            artifact_root=completed_attempt["artifact_root"],
            grid=grid,
            builder=builder,
        )


def test_rejects_registered_path_escape(completed_attempt):
    grid = copy.deepcopy(completed_attempt["grid"])
    grid["collectors"][0]["tape_path"] = "../escape.json"
    builder = att._InventoryBuilder(
        permitted_roots=(completed_attempt["root"], completed_attempt["durable"])
    )
    with pytest.raises(att.AttestationError, match="registered path"):
        att._add_formal_inventory(
            root=completed_attempt["root"],
            artifact_root=completed_attempt["artifact_root"],
            grid=grid,
            builder=builder,
        )


def test_rejects_symlinked_registered_artifact(completed_attempt):
    tape = completed_attempt["formal_paths"][0]
    target = tape.with_name("real-tape.bin")
    target.write_bytes(tape.read_bytes())
    tape.unlink()
    tape.symlink_to(target)
    with pytest.raises(att.AttestationError, match="symlink"):
        _run(completed_attempt)


def test_rejects_symlinked_registered_parent(completed_attempt):
    tapes = completed_attempt["artifact_root"] / "tapes"
    real_tapes = tapes.with_name("real-tapes")
    tapes.rename(real_tapes)
    tapes.symlink_to(real_tapes, target_is_directory=True)
    with pytest.raises(att.AttestationError, match="symlink"):
        _run(completed_attempt)


def test_rejects_snapshot_race(completed_attempt):
    decision = completed_attempt["formal_decision"]

    def mutate():
        decision.write_bytes(decision.read_bytes() + b"changed")

    with pytest.raises(att.AttestationError, match="changed between snapshots"):
        _run(completed_attempt, clock=_Clock(mutation=mutate))
    assert not completed_attempt["output"].exists()


def test_refuses_overwrite_without_changing_existing_bytes(completed_attempt):
    completed_attempt["output"].write_bytes(b"keep-me")
    with pytest.raises(FileExistsError, match="overwrite"):
        _run(completed_attempt)
    assert completed_attempt["output"].read_bytes() == b"keep-me"


def test_post_link_fsync_failure_never_rolls_back_published_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = tmp_path / "completion.json"
    real_fsync = os.fsync
    calls = 0

    def fail_first_directory_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(att.os, "fsync", fail_first_directory_fsync)
    with pytest.raises(OSError, match="injected"):
        att._atomic_publish_no_overwrite(output, b"published")
    assert output.read_bytes() == b"published"
    assert list(tmp_path.glob(".completion.json.tmp.*")) == []


def test_rejects_empty_partial_formal_artifact(completed_attempt):
    completed_attempt["formal_manifest"].write_bytes(b"")
    with pytest.raises(att.AttestationError, match="empty file"):
        _run(completed_attempt)


@pytest.mark.parametrize("pid_bytes", [b"0\n", b"+12\n", b"12 \n", b"12\n13\n"])
def test_rejects_noncanonical_pid_bytes(completed_attempt, pid_bytes):
    completed_attempt["pid_path"].write_bytes(pid_bytes)
    with pytest.raises(att.AttestationError, match="canonical ASCII"):
        _run(completed_attempt)


def test_rejects_live_registered_pid(completed_attempt):
    with pytest.raises(att.AttestationError, match="still live"):
        _run(completed_attempt, pid_is_live_fn=lambda _pid: True)


def test_rejects_nonzero_exit(completed_attempt):
    completed_attempt["exit_path"].write_text("1\n")
    with pytest.raises(att.AttestationError, match="exact zero"):
        _run(completed_attempt)


def test_rejects_exit_mtime_not_after_manifest_and_decision(completed_attempt):
    output_mtime = completed_attempt["formal_decision"].stat().st_mtime_ns
    os.utime(completed_attempt["exit_path"], ns=(output_mtime, output_mtime))
    with pytest.raises(att.AttestationError, match="mtime"):
        _run(completed_attempt)


@pytest.mark.parametrize("name", ["leftover.trace.live.json", ".decision.tmp.7"])
def test_rejects_live_or_temporary_artifact(completed_attempt, name):
    _write(completed_attempt["artifact_root"] / "traces" / name, b"partial")
    with pytest.raises(att.AttestationError, match="temporary"):
        _run(completed_attempt)


def test_rejects_stability_interval_below_one_second(completed_attempt):
    with pytest.raises(att.AttestationError, match="at least one second"):
        _run(completed_attempt, stability_seconds=0.999)


def test_rejects_launch_expectation_schema_drift(completed_attempt):
    expectation = json.loads(completed_attempt["expectation_path"].read_text())
    expectation["unregistered_field"] = True
    _write_json(completed_attempt["expectation_path"], expectation)
    with pytest.raises(att.AttestationError, match="target digest"):
        _run(completed_attempt)


def test_rejects_nonfinite_launch_expectation_constant(completed_attempt):
    payload = completed_attempt["expectation_path"].read_bytes()
    assert b'"max_used_memory_mib": 1024' in payload
    completed_attempt["expectation_path"].write_bytes(
        payload.replace(b'"max_used_memory_mib": 1024', b'"max_used_memory_mib": NaN')
    )
    with pytest.raises(att.AttestationError, match="target digest"):
        _run(completed_attempt)


def test_rejects_nonfinite_control_constant(completed_attempt):
    details = json.loads(completed_attempt["details_path"].read_text())
    details["environment"]["payload"] = {"invalid": float("inf")}
    _write_json(completed_attempt["details_path"], details)
    with pytest.raises(att.AttestationError, match="non-finite"):
        _run(completed_attempt)


def test_rejects_pid_file_drift_from_live_registration(completed_attempt):
    completed_attempt["pid_path"].write_text(f"{WRAPPER_PID + 1}\n")
    with pytest.raises(att.AttestationError, match="PID differs"):
        _run(completed_attempt)


def test_rejects_process_reference_audit_failure(completed_attempt):
    def fail_process_audit(**_kwargs):
        raise att.AttestationError("live process reference")

    with pytest.raises(att.AttestationError, match="live process reference"):
        _run(completed_attempt, process_audit_fn=fail_process_audit)
