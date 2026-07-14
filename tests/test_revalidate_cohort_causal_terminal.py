from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

import attest_cohort_causal_completion as attester
import build_cohort_structured_state_execution_seal as seal_builder
import revalidate_cohort_causal_terminal as revalidator


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _write_json(path: Path, value: Any, *, pretty: bool = False) -> Path:
    payload = (
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        if pretty
        else _canonical(value) + b"\n"
    )
    return _write(path, payload)


def _valid_report(decision: str) -> dict[str, Any]:
    scope = "internal_gate_pass" if decision == "pass" else "internal_gate_no_go"
    return {
        "decision": decision,
        "decision_scope": scope,
        "errors": [],
        "experiment": revalidator.EXPERIMENT,
        "protocol": revalidator.PROTOCOL,
        "publication_grade": False,
        "schema_version": 1,
        "status": "valid",
    }


def _invalid_report() -> dict[str, Any]:
    return {
        "decision": "invalid",
        "decision_scope": "invalid",
        "errors": ["synthetic integrity failure"],
        "experiment": revalidator.EXPERIMENT,
        "protocol": revalidator.PROTOCOL,
        "publication_grade": False,
        "schema_version": 1,
        "status": "invalid",
    }


def _record(path: Path, roles: list[str]) -> dict[str, Any]:
    metadata = path.stat()
    payload = path.read_bytes()
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mtime_ns": metadata.st_mtime_ns,
        "path": path.as_posix(),
        "roles": sorted(roles),
        "sha256": _sha(payload),
        "size_bytes": metadata.st_size,
    }


def _terminal_fixture(
    tmp_path: Path,
    *,
    decision: str = "pass",
    exit_bytes: bytes = b"0\n",
    duplicate_raw_json: bool = False,
    duplicate_decision_json: bool = False,
) -> dict[str, Any]:
    root = (tmp_path / "checkout").resolve()
    durable = (tmp_path / "durable" / "attempt-002").resolve()
    artifact_root = durable / "artifacts" / "cohort_causal"
    prep = durable / "prep"
    root.mkdir(parents=True)
    artifact_root.mkdir(parents=True)
    prep.mkdir(parents=True)
    (root / "artifacts").mkdir()
    (root / "artifacts/cohort_causal").symlink_to(
        artifact_root, target_is_directory=True
    )

    launcher = _write(root / "launch_cohort_causal.sh", b"#!/bin/sh\nexit 0\n")
    prereg = _write(root / revalidator.PREREGISTRATION_FILENAME, b"registered\n")
    addendum = _write(root / revalidator.STATISTICAL_ADDENDUM_FILENAME, b"addendum\n")
    evaluation_code = _write(root / "registered_eval.py", b"VALUE = 1\n")

    datasets: dict[str, Any] = {}
    for role in ("adaptation", "heldout"):
        dataset_relative = Path("data") / role
        dataset_root = root / dataset_relative
        artifact = _write(dataset_root / "payload.bin", f"{role}-bytes".encode())
        schedule_id = f"registered_{role}"
        schedule = _write_json(
            root / "src/tasks/cohort_studies/schedules" / f"{schedule_id}.json",
            {"schedule": role},
        )
        manifest = {
            "artifacts": [
                {
                    "path": artifact.name,
                    "sha256": _sha(artifact.read_bytes()),
                    "size_bytes": artifact.stat().st_size,
                }
            ],
            "schedule_id": schedule_id,
            "schedule_sha256": _sha(schedule.read_bytes()),
        }
        _write_json(dataset_root / "manifest.json", manifest)
        datasets[role] = {
            "path": dataset_relative.as_posix(),
            "schedule": schedule_id,
        }

    collectors = []
    cells = []
    raw_json_paths: list[Path] = []
    for index in range(3):
        cfg_id = f"collector-{index}"
        tape_relative = Path("artifacts/cohort_causal/tapes") / f"{cfg_id}.json"
        tape = artifact_root / "tapes" / f"{cfg_id}.json"
        raw_json_paths.append(_write_json(tape, {"collector": index}))
        raw_json_paths.append(
            _write_json(
                artifact_root / "collectors" / f"{cfg_id}.manifest.json",
                {"collector": index},
            )
        )
        raw_json_paths.append(
            _write_json(
                artifact_root / "traces" / f"{cfg_id}.trace.json",
                {"trace": cfg_id},
            )
        )
        collectors.append(
            {"cfg_id": cfg_id, "run_seed": index + 1, "tape_path": tape_relative.as_posix()}
        )
        for arm in ("active", "lr0"):
            cell_id = f"cell-{index}-{arm}"
            manifest_relative = (
                Path("artifacts/cohort_causal/cells") / f"{cell_id}.manifest.json"
            )
            raw_json_paths.append(
                _write_json(
                    artifact_root / "cells" / f"{cell_id}.manifest.json",
                    {"arm": arm},
                )
            )
            raw_json_paths.append(
                _write_json(
                    artifact_root / "traces" / f"{cell_id}.trace.json",
                    {"trace": cell_id},
                )
            )
            cells.append(
                {
                    "arm": arm,
                    "cell_manifest_path": manifest_relative.as_posix(),
                    "cfg_id": cell_id,
                    "run_seed": index + 1,
                }
            )

    if duplicate_raw_json:
        raw_json_paths[0].write_bytes(b'{"duplicate":1,"duplicate":2}\n')

    grid = {
        "collectors": collectors,
        "datasets": datasets,
        "evaluation_cells": cells,
        "kind": "formal",
        "protocol": revalidator.PROTOCOL,
    }
    grid_path = _write_json(root / "grid_cohort_causal_formal.json", grid, pretty=True)

    evaluation_record = {
        "path": evaluation_code.relative_to(root).as_posix(),
        "role": "evaluation_code",
        "sha256": _sha(evaluation_code.read_bytes()),
        "size_bytes": evaluation_code.stat().st_size,
    }
    evaluation_records = [evaluation_record]
    source_commit = "1" * 40
    provenance = {
        "adapter_init_seed": 2026071400,
        "environment_lock_sha256": "2" * 64,
        "evaluation_code_sha256": _sha(_canonical(evaluation_records)),
        "model_path": "/registered/model",
        "model_sha256": "3" * 64,
        "preregistered_parent_commit": revalidator.PREREGISTERED_PARENT_COMMIT,
        "source_commit": source_commit,
        "statistical_addendum_sha256": _sha(addendum.read_bytes()),
        "tokenizer_sha256": "4" * 64,
    }
    provenance_path = _write_json(artifact_root / "provenance.json", provenance)
    details = {
        "canonicalization": "test",
        "environment": {},
        "evaluation_code": {
            "allowlist": [evaluation_record["path"]],
            "files": evaluation_records,
            "inventory_sha256": provenance["evaluation_code_sha256"],
        },
        "git": {},
        "hash_algorithm": "sha256",
        "kind": "cohort_causal_provenance_audit",
        "model": {},
        "provenance": provenance,
        "schema_version": 1,
        "statistical_addendum": {},
        "tokenizer": {},
    }
    details_path = _write_json(artifact_root / "provenance.details.json", details)

    pid_path = _write(prep / "causal_formal.pid", b"99999999\n")
    report = _valid_report(decision) if decision != "invalid" else _invalid_report()
    rebuilt_manifest = {"formal": "independently rebuilt"}
    formal_manifest = _write(
        artifact_root / "formal_manifest.json", _canonical(rebuilt_manifest) + b"\n"
    )
    decision_payload = (
        b'{"duplicate":1,"duplicate":2}\n'
        if duplicate_decision_json
        else (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    )
    formal_decision = _write(artifact_root / "formal_decision.json", decision_payload)
    exit_path = _write(prep / "causal_formal.exit", exit_bytes)
    now_ns = time.time_ns()
    os.utime(formal_manifest, ns=(now_ns - 2_000_000_000, now_ns - 2_000_000_000))
    os.utime(formal_decision, ns=(now_ns - 2_000_000_000, now_ns - 2_000_000_000))
    os.utime(exit_path, ns=(now_ns, now_ns))

    expectation = {
        "artifact_root": artifact_root.as_posix(),
        "attempt_id": "attempt-002",
        "boot_id": "11111111-1111-1111-1111-111111111111",
        "checkout_root": root.as_posix(),
        "collector_gpus": [0, 1, 2],
        "created_at_utc": "2026-07-14T00:00:00Z",
        "durable_attempt_root": durable.as_posix(),
        "eval_gpus": [0, 1, 2, 3, 4, 5],
        "exit_file": exit_path.as_posix(),
        "expected_final_inventory": dict(revalidator._EXPECTED_REGISTERED_COUNTS),
        "formal_grid_file_sha256": _sha(grid_path.read_bytes()),
        "launch_mode": "formal",
        "launcher_file_sha256": _sha(launcher.read_bytes()),
        "max_used_memory_mib": 1024,
        "node_hostname": "test-node",
        "pid_file": pid_path.as_posix(),
        "pid_file_sha256_at_registration": _sha(pid_path.read_bytes()),
        "protocol": revalidator.LAUNCH_EXPECTATION_PROTOCOL,
        "provenance_file_sha256": _sha(provenance_path.read_bytes()),
        "schema_version": 1,
        "source_commit": source_commit,
        "wrapper_cmdline_sha256_at_registration": "5" * 64,
        "wrapper_pid": 99999999,
        "wrapper_start_ticks": 1,
    }
    control = durable / "control"
    tooling_root = control / "verifier" / ("a" * 40)
    expectation_path = _write_json(
        control / seal_builder.LAUNCH_EXPECTATION_FILENAME, expectation, pretty=True
    )
    structured_preregistration = _write(
        tooling_root / seal_builder.STRUCTURED_PREREGISTRATION_FILENAME,
        b"prospective structured preregistration\n",
    )
    tool_sources = {
        "attester": Path(attester.__file__).resolve(),
        "revalidator": Path(revalidator.__file__).resolve(),
        "execution_seal_builder": Path(seal_builder.__file__).resolve(),
    }
    tools: dict[str, dict[str, str]] = {}
    for name, source in tool_sources.items():
        destination = _write(tooling_root / source.name, source.read_bytes())
        tools[name] = {
            "path": destination.as_posix(),
            "sha256": _sha(destination.read_bytes()),
        }
    plan_path = control / seal_builder.PLAN_FILENAME
    attestation_output = prep / seal_builder.ATTESTATION_FILENAME
    revalidated_output = prep / revalidator.REVALIDATED_FILENAME
    receipt_output = prep / revalidator.RECEIPT_FILENAME
    seal_output = prep / seal_builder.SEAL_FILENAME
    plan: dict[str, Any] = {
        "attempt_id": "attempt-002",
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": seal_builder.CAUSAL_PROTOCOL_SEAL_STATUS,
        "causal_checkout_root": root.as_posix(),
        "created_at_utc": "2026-07-14T00:00:00Z",
        "durable_attempt_root": durable.as_posix(),
        "invocations": {
            "attester": {
                "argv": [],
                "inputs": {
                    "execution_plan": plan_path.as_posix(),
                    "root": root.as_posix(),
                    "launch_expectation": expectation_path.as_posix(),
                    "provenance": provenance_path.as_posix(),
                    "provenance_details": details_path.as_posix(),
                },
                "outputs": {"attestation": attestation_output.as_posix()},
                "parameters": {"stability_seconds": "1.0"},
            },
            "revalidator": {
                "argv": [],
                "inputs": {
                    "execution_plan": plan_path.as_posix(),
                    "root": root.as_posix(),
                    "attestation": attestation_output.as_posix(),
                    "launch_expectation": expectation_path.as_posix(),
                    "grid": grid_path.as_posix(),
                    "provenance": provenance_path.as_posix(),
                    "formal_manifest": formal_manifest.as_posix(),
                    "formal_decision": formal_decision.as_posix(),
                    "preregistration": prereg.as_posix(),
                    "statistical_addendum": addendum.as_posix(),
                },
                "outputs": {
                    "revalidated_decision": revalidated_output.as_posix(),
                    "revalidation_receipt": receipt_output.as_posix(),
                },
                "parameters": {},
            },
            "execution_seal_builder": {
                "argv": [],
                "inputs": {
                    "execution_plan": plan_path.as_posix(),
                    "attestation": attestation_output.as_posix(),
                    "launch_expectation": expectation_path.as_posix(),
                    "causal_original": formal_decision.as_posix(),
                    "causal_revalidated": revalidated_output.as_posix(),
                    "revalidation_receipt": receipt_output.as_posix(),
                    "structured_preregistration": structured_preregistration.as_posix(),
                },
                "outputs": {"execution_seal": seal_output.as_posix()},
                "parameters": {},
            },
        },
        "launch_expectation": {
            "path": expectation_path.as_posix(),
            "sha256": _sha(expectation_path.read_bytes()),
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
            "sha256": _sha(structured_preregistration.read_bytes()),
        },
        "tooling_root": tooling_root.as_posix(),
        "tooling_source_commit": "a" * 40,
        "tools": tools,
    }
    for stage in seal_builder.PLAN_INVOCATION_NAMES:
        plan["invocations"][stage]["argv"] = seal_builder._expected_argv(plan, stage)
    _write(plan_path, _canonical(plan))
    plan_sha256 = _sha(plan_path.read_bytes())

    role_paths: dict[Path, list[str]] = {
        expectation_path: ["launch_expectation"],
        grid_path: ["formal_grid"],
        launcher: ["launcher_source"],
        prereg: ["causal_prereg"],
        addendum: ["statistical_addendum"],
        evaluation_code: ["evaluation_code"],
        provenance_path: ["compact_provenance"],
        details_path: ["detailed_provenance"],
        pid_path: ["wrapper_pid_file"],
        exit_path: ["wrapper_exit_file"],
        formal_manifest: ["formal_manifest"],
        formal_decision: ["formal_decision"],
    }
    for role in ("adaptation", "heldout"):
        dataset_root = root / datasets[role]["path"]
        role_paths[dataset_root / "manifest.json"] = [f"{role}_corpus_manifest"]
        role_paths[dataset_root / "payload.bin"] = [f"{role}_corpus_artifact"]
        role_paths[
            root
            / "src/tasks/cohort_studies/schedules"
            / f"{datasets[role]['schedule']}.json"
        ] = [f"{role}_schedule"]
    for path in raw_json_paths:
        if "/tapes/" in path.as_posix():
            role = "formal_tape"
        elif "/collectors/" in path.as_posix():
            role = "collector_manifest"
        elif "/cells/" in path.as_posix():
            role = "cell_manifest"
        elif path.stem.startswith("collector-"):
            role = "collector_final_trace"
        else:
            role = "cell_final_trace"
        role_paths[path] = [role]

    records = [_record(path, role_paths[path]) for path in sorted(role_paths, key=lambda p: p.as_posix())]
    inventory_digest = _sha(_canonical(records))
    process_payload = {
        "artifact_root_path": artifact_root.as_posix(),
        "attempt_checkout_path": root.as_posix(),
        "method": "linux_procfs_cmdline_and_cwd",
        "status": "pass",
    }
    temporary_payload = {
        "forbidden_match_count": 0,
        "roots": sorted([artifact_root.as_posix(), prep.as_posix()]),
        "status": "pass",
    }
    pid_record = next(record for record in records if "wrapper_pid_file" in record["roles"])
    exit_record = next(record for record in records if "wrapper_exit_file" in record["roles"])
    attestation = {
        "causal_pre_attestation_inventory_sha256": inventory_digest,
        "completed_at_utc": "2026-07-14T00:00:02Z",
        "execution_plan_path": plan_path.as_posix(),
        "execution_plan_sha256": plan_sha256,
        "expected_launcher": {
            "formal_grid_file_sha256": expectation["formal_grid_file_sha256"],
            "launch_expectation_path": expectation_path.as_posix(),
            "launch_expectation_sha256": _sha(expectation_path.read_bytes()),
            "launcher_file_sha256": expectation["launcher_file_sha256"],
            "provenance_file_sha256": expectation["provenance_file_sha256"],
            "source_commit": source_commit,
            "wrapper_cmdline_sha256_at_registration": expectation[
                "wrapper_cmdline_sha256_at_registration"
            ],
        },
        "no_live_or_temporary": {
            **temporary_payload,
            "audit_sha256": _sha(_canonical(temporary_payload)),
        },
        "pid_exit": {
            "exit_after_outputs_status": "pass",
            "exit_file_mtime_ns": exit_record["mtime_ns"],
            "exit_file_path": exit_path.as_posix(),
            "exit_file_sha256": exit_record["sha256"],
            "exit_file_size_bytes": exit_record["size_bytes"],
            "exit_zero_status": "pass",
            "pid_ascii_status": "pass",
            "pid_file_mtime_ns": pid_record["mtime_ns"],
            "pid_file_path": pid_path.as_posix(),
            "pid_file_sha256": pid_record["sha256"],
            "pid_file_size_bytes": pid_record["size_bytes"],
            "pid_liveness_status": "dead",
        },
        "process_absence": {
            **process_payload,
            "audit_sha256": _sha(_canonical(process_payload)),
        },
        "protocol": revalidator.ATTESTATION_PROTOCOL,
        "registered_counts": dict(revalidator._EXPECTED_REGISTERED_COUNTS),
        "schema_version": 1,
        "snapshots": [
            {
                "captured_at_utc": "2026-07-14T00:00:00Z",
                "file_count": len(records),
                "files": records,
                "inventory_sha256": inventory_digest,
                "sequence": 1,
            },
            {
                "captured_at_utc": "2026-07-14T00:00:01Z",
                "file_count": len(records),
                "files": records,
                "inventory_sha256": inventory_digest,
                "sequence": 2,
            },
        ],
        "stability": {
            "minimum_interval_seconds": 1.0,
            "observed_interval_seconds": 1.1,
            "snapshots_identical": True,
        },
        "status": "complete",
    }
    attestation_path = _write(attestation_output, _canonical(attestation))
    return {
        "artifact": artifact_root,
        "assemble": lambda **_: rebuilt_manifest,
        "attestation": attestation_path,
        "decision": formal_decision,
        "evaluate": lambda _: report,
        "expectation": expectation_path,
        "grid": grid,
        "grid_path": grid_path,
        "manifest": formal_manifest,
        "provenance": provenance_path,
        "raw": raw_json_paths[0],
        "receipt": prep / revalidator.RECEIPT_FILENAME,
        "revalidated": prep / revalidator.REVALIDATED_FILENAME,
        "root": root,
        "plan": plan,
        "plan_path": plan_path,
    }


def _run(fixture: dict[str, Any]) -> dict[str, Any]:
    return revalidator.revalidate_terminal(
        root=fixture["root"],
        execution_plan_path=fixture["plan_path"],
        attestation_path=fixture["attestation"],
        launch_expectation_path=fixture["expectation"],
        grid_path=fixture["grid_path"],
        provenance_path=fixture["provenance"],
        formal_manifest_path=fixture["manifest"],
        formal_decision_path=fixture["decision"],
        revalidated_output=fixture["revalidated"],
        receipt_output=fixture["receipt"],
        assemble_fn=fixture["assemble"],
        evaluate_fn=fixture["evaluate"],
        make_grid_fn=lambda *, smoke: fixture["grid"],
        actual_argv=fixture["plan"]["invocations"]["revalidator"]["argv"],
        runtime_python_path=seal_builder.EXPECTED_PYTHON_PATH,
        runtime_python_version=seal_builder.EXPECTED_PYTHON_VERSION,
    )


def test_revalidator_consumes_exact_attester_public_interface() -> None:
    assert revalidator.ATTESTATION_PROTOCOL == attester.PROTOCOL
    assert revalidator._ATTESTATION_KEYS == set(attester.ATTESTATION_KEYS)
    assert revalidator._EXPECTED_LAUNCHER_KEYS == set(attester.EXPECTED_LAUNCHER_KEYS)
    assert revalidator._PROCESS_ABSENCE_KEYS == set(attester.PROCESS_AUDIT_KEYS)
    assert revalidator._NO_LIVE_OR_TEMPORARY_KEYS == set(
        attester.TEMPORARY_AUDIT_KEYS
    )
    assert revalidator._SNAPSHOT_KEYS == set(attester.SNAPSHOT_KEYS)
    assert revalidator._FILE_RECORD_KEYS == set(attester.FILE_RECORD_KEYS)
    sample = [{"path": "/registered", "sha256": "0" * 64}]
    assert _sha(_canonical(sample)) == attester.inventory_sha256(sample)


def test_registered_runtime_loader_restores_sys_modules() -> None:
    names = (
        "assemble_cohort_causal_manifest",
        "generate_cohort_causal_grid",
        "run_cohort_causal",
        "validate_cohort_causal_results",
    )
    prior = {name: importlib.import_module(name) for name in names}

    revalidator._load_registered_runtime(Path(__file__).resolve().parents[1])

    assert all(sys.modules[name] is module for name, module in prior.items())


@pytest.mark.parametrize(
    ("decision", "scope"),
    [("pass", "internal_gate_pass"), ("valid_no_go", "internal_gate_no_go")],
)
def test_valid_branches_publish_byte_identical_decision_and_redacted_receipt(
    tmp_path: Path, decision: str, scope: str
) -> None:
    fixture = _terminal_fixture(tmp_path, decision=decision)

    receipt = _run(fixture)

    assert fixture["revalidated"].read_bytes() == fixture["decision"].read_bytes()
    assert set(receipt) == revalidator.RECEIPT_KEYS
    assert receipt["decision"] == decision
    assert receipt["decision_scope"] == scope
    assert not ({"aggregate", "pairs", "deltas", "threshold_checks"} & set(receipt))
    assert json.loads(fixture["receipt"].read_text()) == receipt


def test_attested_raw_tamper_fails_before_recomputation(tmp_path: Path) -> None:
    fixture = _terminal_fixture(tmp_path)
    called = False

    def evaluate(_: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return _valid_report("pass")

    fixture["evaluate"] = evaluate
    fixture["raw"].write_bytes(b'{"tampered":true}\n')

    with pytest.raises(revalidator.RevalidationError, match="inventory differs"):
        _run(fixture)
    assert called is False
    assert not fixture["revalidated"].exists()
    assert not fixture["receipt"].exists()


def test_duplicate_key_in_attested_raw_json_fails_closed(tmp_path: Path) -> None:
    fixture = _terminal_fixture(tmp_path, duplicate_raw_json=True)

    with pytest.raises(revalidator.RevalidationError, match="duplicate JSON key"):
        _run(fixture)
    assert not fixture["revalidated"].exists()


def test_nonzero_exit_never_semantically_opens_decision(tmp_path: Path) -> None:
    fixture = _terminal_fixture(
        tmp_path, exit_bytes=b"1\n", duplicate_decision_json=True
    )

    with pytest.raises(revalidator.RevalidationError, match="exit file is nonzero"):
        _run(fixture)
    assert not fixture["revalidated"].exists()
    assert not fixture["receipt"].exists()


def test_attestation_digest_drift_fails_closed(tmp_path: Path) -> None:
    fixture = _terminal_fixture(tmp_path)
    attestation = json.loads(fixture["attestation"].read_text())
    attestation["causal_pre_attestation_inventory_sha256"] = "0" * 64
    fixture["attestation"].write_bytes(_canonical(attestation))

    with pytest.raises(revalidator.RevalidationError, match="digest bindings disagree"):
        _run(fixture)
    assert not fixture["revalidated"].exists()


def test_preexisting_output_is_never_overwritten(tmp_path: Path) -> None:
    fixture = _terminal_fixture(tmp_path)
    fixture["revalidated"].write_bytes(b"existing")

    with pytest.raises(FileExistsError, match="pre-existing"):
        _run(fixture)
    assert fixture["revalidated"].read_bytes() == b"existing"
    assert not fixture["receipt"].exists()


def test_second_link_race_leaves_monotonic_partial_and_forbids_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = (tmp_path / "first.json").resolve()
    second = (tmp_path / "second.json").resolve()
    real_link = os.link
    calls = 0

    def racing_link(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            Path(destination).write_bytes(b"racing-writer")
        real_link(source, destination)

    monkeypatch.setattr(revalidator.os, "link", racing_link)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        revalidator._publish_pair_no_overwrite(
            [(first, b"first-evidence"), (second, b"second-evidence")]
        )

    assert first.read_bytes() == b"first-evidence"
    assert second.read_bytes() == b"racing-writer"
    monkeypatch.setattr(revalidator.os, "link", real_link)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        revalidator._publish_pair_no_overwrite(
            [(first, b"retry-first"), (second, b"retry-second")]
        )
    assert first.read_bytes() == b"first-evidence"
    assert second.read_bytes() == b"racing-writer"


def test_output_paths_are_fixed_under_durable_prep(tmp_path: Path) -> None:
    fixture = _terminal_fixture(tmp_path)
    fixture["revalidated"] = fixture["artifact"] / "misrouted.json"

    with pytest.raises(revalidator.RevalidationError, match="inputs/outputs differ"):
        _run(fixture)
    assert not fixture["revalidated"].exists()
    assert not fixture["receipt"].exists()


def test_output_path_with_parent_traversal_is_rejected(tmp_path: Path) -> None:
    fixture = _terminal_fixture(tmp_path)
    prep = fixture["revalidated"].parent
    fixture["revalidated"] = (
        prep / ".." / "prep" / revalidator.REVALIDATED_FILENAME
    )

    with pytest.raises(revalidator.RevalidationError, match="normalized absolute"):
        _run(fixture)
    assert not (prep / revalidator.REVALIDATED_FILENAME).exists()
    assert not fixture["receipt"].exists()


def test_fixed_output_parent_rejects_symlink(tmp_path: Path) -> None:
    durable = (tmp_path / "durable").resolve()
    target = (tmp_path / "actual-prep").resolve()
    durable.mkdir()
    target.mkdir()
    (durable / "prep").symlink_to(target, target_is_directory=True)
    output = durable / "prep" / revalidator.REVALIDATED_FILENAME

    with pytest.raises(revalidator.RevalidationError, match="may not be a symlink"):
        revalidator._require_fixed_output_parent(
            path=output,
            durable_root=durable,
            expected_name=revalidator.REVALIDATED_FILENAME,
            label="test output",
        )
    assert not output.exists()


def test_invalid_recomputation_publishes_nothing(tmp_path: Path) -> None:
    fixture = _terminal_fixture(tmp_path, decision="invalid")

    with pytest.raises(revalidator.RevalidationError, match="decision is invalid"):
        _run(fixture)
    assert not fixture["revalidated"].exists()
    assert not fixture["receipt"].exists()
