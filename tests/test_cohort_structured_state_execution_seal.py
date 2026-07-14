from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import build_cohort_structured_state_execution_seal as seal


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write(path: Path, payload: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload.encode() if isinstance(payload, str) else payload)
    return path


def _write_json(path: Path, value: Any, *, pretty: bool = False) -> Path:
    payload = (
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        if pretty
        else _canonical(value)
    )
    return _write(path, payload)


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


def _causal_report(decision: str = "valid_no_go") -> dict[str, Any]:
    return {
        "aggregate": {
            "ci_95_lower": -0.1,
            "ci_95_upper": 0.1,
            "mean_delta": 0.0,
            "positive_seeds": 1,
        },
        "bootstrap": {
            "ci_95": [-0.1, 0.1],
            "fixed_scoring_conditions": 20,
            "method": "registered",
            "publication_grade": False,
            "replicates": 50000,
            "seed": 2026071499,
        },
        "decision": decision,
        "decision_scope": (
            "internal_gate_no_go" if decision == "valid_no_go" else "internal_gate_pass"
        ),
        "errors": [],
        "experiment": seal.CAUSAL_EXPERIMENT,
        "limitation": "not exact historical replication",
        "mechanism_label": "frozen-tape weight-update ablation",
        "pairs": [],
        "preregistered_thresholds": {
            "all_seed_deltas_gt": 0.0,
            "bootstrap_ci_lower_gt": 0.0,
            "mean_delta_gte": 0.02,
        },
        "protocol": seal.CAUSAL_PROTOCOL,
        "publication_inference": {
            "effective_n": 3,
            "publication_grade": False,
            "status": "confirmation_required_not_publication_grade",
        },
        "publication_grade": False,
        "schema_version": 1,
        "status": "valid",
        "threshold_checks": {
            "all_3_seed_deltas_gt_0": False,
            "ci_95_lower_gt_0": False,
            "integrity_gate_passed": True,
            "mean_delta_gte_0_02": False,
            "no_schema_format_regression": True,
        },
    }


def _execution_plan(
    *,
    root: Path,
    durable: Path,
    expectation: Path,
    structured_preregistration: Path,
    tools: dict[str, dict[str, str]],
    provenance: Path,
    provenance_details: Path,
    grid: Path,
    formal_manifest: Path,
    formal_decision: Path,
    causal_preregistration: Path,
    statistical_addendum: Path,
) -> dict[str, Any]:
    prep = durable / "prep"
    tooling_source_commit = "a" * 40
    tooling_root = durable / "control" / "verifier" / tooling_source_commit
    plan_path = durable / "control" / seal.PLAN_FILENAME
    attestation = prep / seal.ATTESTATION_FILENAME
    revalidated = prep / seal.REVALIDATED_FILENAME
    receipt = prep / seal.REVALIDATION_RECEIPT_FILENAME
    output = prep / seal.SEAL_FILENAME
    plan: dict[str, Any] = {
        "attempt_id": "attempt-002",
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": seal.CAUSAL_PROTOCOL_SEAL_STATUS,
        "causal_checkout_root": root.as_posix(),
        "created_at_utc": "2026-07-14T12:00:00Z",
        "durable_attempt_root": durable.as_posix(),
        "invocations": {
            "attester": {
                "argv": [],
                "inputs": {
                    "execution_plan": plan_path.as_posix(),
                    "launch_expectation": expectation.as_posix(),
                    "provenance": provenance.as_posix(),
                    "provenance_details": provenance_details.as_posix(),
                    "root": root.as_posix(),
                },
                "outputs": {"attestation": attestation.as_posix()},
                "parameters": {"stability_seconds": "1.0"},
            },
            "revalidator": {
                "argv": [],
                "inputs": {
                    "attestation": attestation.as_posix(),
                    "execution_plan": plan_path.as_posix(),
                    "formal_decision": formal_decision.as_posix(),
                    "formal_manifest": formal_manifest.as_posix(),
                    "grid": grid.as_posix(),
                    "launch_expectation": expectation.as_posix(),
                    "preregistration": causal_preregistration.as_posix(),
                    "provenance": provenance.as_posix(),
                    "root": root.as_posix(),
                    "statistical_addendum": statistical_addendum.as_posix(),
                },
                "outputs": {
                    "revalidated_decision": revalidated.as_posix(),
                    "revalidation_receipt": receipt.as_posix(),
                },
                "parameters": {},
            },
            "execution_seal_builder": {
                "argv": [],
                "inputs": {
                    "attestation": attestation.as_posix(),
                    "causal_original": formal_decision.as_posix(),
                    "causal_revalidated": revalidated.as_posix(),
                    "execution_plan": plan_path.as_posix(),
                    "launch_expectation": expectation.as_posix(),
                    "revalidation_receipt": receipt.as_posix(),
                    "structured_preregistration": structured_preregistration.as_posix(),
                },
                "outputs": {"execution_seal": output.as_posix()},
                "parameters": {},
            },
        },
        "launch_expectation": {
            "path": expectation.as_posix(),
            "sha256": _sha(expectation.read_bytes()),
        },
        "online_icl": None,
        "protocol": seal.PLAN_PROTOCOL,
        "runtime": {
            "python_path": seal.EXPECTED_PYTHON_PATH,
            "python_version": seal.EXPECTED_PYTHON_VERSION,
        },
        "schema_version": 1,
        "status": seal.PLAN_STATUS,
        "structured_preregistration": {
            "path": structured_preregistration.as_posix(),
            "sha256": _sha(structured_preregistration.read_bytes()),
        },
        "tooling_root": tooling_root.as_posix(),
        "tooling_source_commit": tooling_source_commit,
        "tools": tools,
    }
    for stage in seal.PLAN_INVOCATION_NAMES:
        plan["invocations"][stage]["argv"] = seal._expected_argv(plan, stage)
    return plan


@pytest.fixture
def sealed_trigger_fixture(tmp_path: Path) -> dict[str, Any]:
    root = (tmp_path / "checkout").resolve()
    durable = (tmp_path / "durable" / "attempt-002").resolve()
    prep = durable / "prep"
    artifact_root = durable / "artifacts" / "cohort_causal"
    tooling_root = durable / "control" / "verifier" / ("a" * 40)
    for directory in (root, prep, artifact_root, tooling_root):
        directory.mkdir(parents=True, exist_ok=True)

    structured_preregistration = _write(
        tooling_root / seal.STRUCTURED_PREREGISTRATION_FILENAME,
        b"structured prereg v1\n",
    )
    causal_preregistration = _write(
        root / seal.CAUSAL_PREREGISTRATION_FILENAME, b"causal prereg\n"
    )
    statistical_addendum = _write(
        root / seal.CAUSAL_STATISTICAL_ADDENDUM_FILENAME, b"statistical addendum\n"
    )
    launcher = _write(root / "launch_cohort_causal.sh", b"#!/bin/sh\nexit 0\n")
    grid = _write_json(root / "grid_cohort_causal_formal.json", {"kind": "formal"})
    provenance = _write_json(artifact_root / "provenance.json", {"source": "registered"})
    provenance_details = _write_json(
        artifact_root / "provenance.details.json", {"evaluation_code": "registered"}
    )
    smoke_gate = _write_json(artifact_root / "smoke_gate.json", {"status": "pass"})
    evaluation_code = _write(root / "registered_evaluator.py", b"VALUE = 1\n")
    adaptation_manifest = _write_json(
        root / "data/adaptation/manifest.json", {"role": "adaptation"}
    )
    adaptation_artifact = _write(root / "data/adaptation/payload.bin", b"adaptation")
    adaptation_schedule = _write_json(
        root / "src/tasks/cohort_studies/schedules/adaptation.json", {"schedule": 1}
    )
    heldout_manifest = _write_json(root / "data/heldout/manifest.json", {"role": "heldout"})
    heldout_artifact = _write(root / "data/heldout/payload.bin", b"heldout")
    heldout_schedule = _write_json(
        root / "src/tasks/cohort_studies/schedules/heldout.json", {"schedule": 2}
    )
    pid = _write(prep / "causal_formal.pid", b"99999999\n")
    formal_manifest = _write_json(
        artifact_root / "formal_manifest.json", {"formal": "registered"}
    )
    report = _causal_report()
    formal_decision = _write_json(
        artifact_root / "formal_decision.json", report, pretty=True
    )
    exit_file = _write(prep / "causal_formal.exit", b"0\n")

    formal_roles: dict[Path, list[str]] = {}
    for index in range(3):
        formal_roles[
            _write_json(artifact_root / "tapes" / f"collector-{index}.json", {"i": index})
        ] = ["formal_tape"]
        formal_roles[
            _write_json(
                artifact_root / "collectors" / f"collector-{index}.manifest.json",
                {"i": index},
            )
        ] = ["collector_manifest"]
        formal_roles[
            _write_json(
                artifact_root / "traces" / f"collector-{index}.trace.json",
                {"i": index},
            )
        ] = ["collector_final_trace"]
    for index in range(6):
        formal_roles[
            _write_json(
                artifact_root / "cells" / f"cell-{index}.manifest.json", {"i": index}
            )
        ] = ["cell_manifest"]
        formal_roles[
            _write_json(
                artifact_root / "traces" / f"cell-{index}.trace.json", {"i": index}
            )
        ] = ["cell_final_trace"]

    expectation = {
        "artifact_root": artifact_root.as_posix(),
        "attempt_id": "attempt-002",
        "boot_id": "11111111-1111-1111-1111-111111111111",
        "checkout_root": root.as_posix(),
        "collector_gpus": [0, 2, 3],
        "created_at_utc": "2026-07-14T11:00:00Z",
        "durable_attempt_root": durable.as_posix(),
        "eval_gpus": [0, 2, 3, 4, 5, 6],
        "exit_file": exit_file.as_posix(),
        "expected_final_inventory": dict(seal.EXPECTED_REGISTERED_COUNTS),
        "formal_grid_file_sha256": _sha(grid.read_bytes()),
        "launch_mode": "formal",
        "launcher_file_sha256": _sha(launcher.read_bytes()),
        "max_used_memory_mib": 1024,
        "node_hostname": "test-node",
        "pid_file": pid.as_posix(),
        "pid_file_sha256_at_registration": _sha(pid.read_bytes()),
        "protocol": seal.LAUNCH_EXPECTATION_PROTOCOL,
        "provenance_file_sha256": _sha(provenance.read_bytes()),
        "schema_version": 1,
        "source_commit": "1" * 40,
        "wrapper_cmdline_sha256_at_registration": "2" * 64,
        "wrapper_pid": 99999999,
        "wrapper_start_ticks": 123,
    }
    expectation_path = _write_json(
        durable / "control" / seal.LAUNCH_EXPECTATION_FILENAME,
        expectation,
        pretty=True,
    )

    tools: dict[str, dict[str, str]] = {}
    repository_root = Path(__file__).resolve().parents[1]
    tool_sources = {
        "attester": repository_root / "attest_cohort_causal_completion.py",
        "revalidator": repository_root / "revalidate_cohort_causal_terminal.py",
        "execution_seal_builder": repository_root
        / "build_cohort_structured_state_execution_seal.py",
    }
    for name, source in tool_sources.items():
        destination = _write(tooling_root / source.name, source.read_bytes())
        tools[name] = {
            "path": destination.as_posix(),
            "sha256": _sha(destination.read_bytes()),
        }
    plan = _execution_plan(
        root=root,
        durable=durable,
        expectation=expectation_path,
        structured_preregistration=structured_preregistration,
        tools=tools,
        provenance=provenance,
        provenance_details=provenance_details,
        grid=grid,
        formal_manifest=formal_manifest,
        formal_decision=formal_decision,
        causal_preregistration=causal_preregistration,
        statistical_addendum=statistical_addendum,
    )
    plan_path = _write(
        durable / "control" / seal.PLAN_FILENAME, _canonical(plan)
    )
    plan_sha = _sha(plan_path.read_bytes())

    role_paths: dict[Path, list[str]] = {
        adaptation_artifact: ["adaptation_corpus_artifact"],
        adaptation_manifest: ["adaptation_corpus_manifest"],
        adaptation_schedule: ["adaptation_schedule"],
        causal_preregistration: ["causal_prereg"],
        evaluation_code: ["evaluation_code"],
        exit_file: ["wrapper_exit_file"],
        formal_decision: ["formal_decision"],
        formal_manifest: ["formal_manifest"],
        grid: ["formal_grid"],
        heldout_artifact: ["heldout_corpus_artifact"],
        heldout_manifest: ["heldout_corpus_manifest"],
        heldout_schedule: ["heldout_schedule"],
        launcher: ["launcher_source"],
        expectation_path: ["launch_expectation"],
        pid: ["wrapper_pid_file"],
        provenance: ["compact_provenance"],
        provenance_details: ["detailed_provenance"],
        smoke_gate: ["causal_smoke_gate"],
        statistical_addendum: ["statistical_addendum"],
        **formal_roles,
    }
    records = [
        _record(path, role_paths[path]) for path in sorted(role_paths, key=lambda item: item.as_posix())
    ]
    inventory_sha = _sha(_canonical(records))
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
    pid_record = next(row for row in records if "wrapper_pid_file" in row["roles"])
    exit_record = next(row for row in records if "wrapper_exit_file" in row["roles"])
    attestation = {
        "causal_pre_attestation_inventory_sha256": inventory_sha,
        "completed_at_utc": "2026-07-14T12:00:02Z",
        "execution_plan_path": plan_path.as_posix(),
        "execution_plan_sha256": plan_sha,
        "expected_launcher": {
            "formal_grid_file_sha256": expectation["formal_grid_file_sha256"],
            "launch_expectation_path": expectation_path.as_posix(),
            "launch_expectation_sha256": _sha(expectation_path.read_bytes()),
            "launcher_file_sha256": expectation["launcher_file_sha256"],
            "provenance_file_sha256": expectation["provenance_file_sha256"],
            "source_commit": expectation["source_commit"],
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
            "exit_file_path": exit_file.as_posix(),
            "exit_file_sha256": exit_record["sha256"],
            "exit_file_size_bytes": exit_record["size_bytes"],
            "exit_zero_status": "pass",
            "pid_ascii_status": "pass",
            "pid_file_mtime_ns": pid_record["mtime_ns"],
            "pid_file_path": pid.as_posix(),
            "pid_file_sha256": pid_record["sha256"],
            "pid_file_size_bytes": pid_record["size_bytes"],
            "pid_liveness_status": "dead",
        },
        "process_absence": {
            **process_payload,
            "audit_sha256": _sha(_canonical(process_payload)),
        },
        "protocol": seal.ATTESTATION_PROTOCOL,
        "registered_counts": dict(seal.EXPECTED_REGISTERED_COUNTS),
        "schema_version": 1,
        "snapshots": [
            {
                "captured_at_utc": "2026-07-14T12:00:00Z",
                "file_count": len(records),
                "files": records,
                "inventory_sha256": inventory_sha,
                "sequence": 1,
            },
            {
                "captured_at_utc": "2026-07-14T12:00:01Z",
                "file_count": len(records),
                "files": records,
                "inventory_sha256": inventory_sha,
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
    attestation_path = _write_json(prep / seal.ATTESTATION_FILENAME, attestation)
    revalidated = _write(prep / seal.REVALIDATED_FILENAME, formal_decision.read_bytes())
    receipt_value = {
        "decision": report["decision"],
        "decision_scope": report["decision_scope"],
        "execution_plan_path": plan_path.as_posix(),
        "execution_plan_sha256": plan_sha,
        "formal_decision_file_sha256": _sha(formal_decision.read_bytes()),
        "formal_manifest_file_sha256": _sha(formal_manifest.read_bytes()),
        "status": "valid",
    }
    receipt = _write_json(prep / seal.REVALIDATION_RECEIPT_FILENAME, receipt_value, pretty=True)
    return {
        "artifact": artifact_root,
        "attestation": attestation_path,
        "decision": formal_decision,
        "expectation": expectation_path,
        "inventory_raw": adaptation_artifact,
        "output": prep / seal.SEAL_FILENAME,
        "plan": plan,
        "plan_path": plan_path,
        "receipt": receipt,
        "revalidated": revalidated,
        "structured_preregistration": structured_preregistration,
        "tool": Path(tools["attester"]["path"]),
    }


def _run(fixture: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    kwargs = {
        "execution_plan_path": fixture["plan_path"],
        "attestation_path": fixture["attestation"],
        "launch_expectation_path": fixture["expectation"],
        "causal_original_path": fixture["decision"],
        "causal_revalidated_path": fixture["revalidated"],
        "revalidation_receipt_path": fixture["receipt"],
        "structured_preregistration_path": fixture["structured_preregistration"],
        "output": fixture["output"],
        "now_fn": lambda: "2026-07-14T12:00:03Z",
        "actual_argv": fixture["plan"]["invocations"]["execution_seal_builder"][
            "argv"
        ],
        "runtime_python_path": seal.EXPECTED_PYTHON_PATH,
        "runtime_python_version": seal.EXPECTED_PYTHON_VERSION,
    }
    kwargs.update(overrides)
    return seal.build_and_publish_execution_seal(**kwargs)


def _retarget_decision_bytes(
    fixture: dict[str, Any], payload: bytes, *, decision: str, decision_scope: str
) -> None:
    fixture["decision"].write_bytes(payload)
    fixture["revalidated"].write_bytes(payload)
    attestation = json.loads(fixture["attestation"].read_text())
    for snapshot in attestation["snapshots"]:
        for position, record in enumerate(snapshot["files"]):
            if "formal_decision" in record["roles"]:
                snapshot["files"][position] = _record(
                    fixture["decision"], ["formal_decision"]
                )
                break
        snapshot["inventory_sha256"] = _sha(_canonical(snapshot["files"]))
    attestation["causal_pre_attestation_inventory_sha256"] = attestation["snapshots"][
        0
    ]["inventory_sha256"]
    _write_json(fixture["attestation"], attestation)
    receipt = json.loads(fixture["receipt"].read_text())
    receipt["decision"] = decision
    receipt["decision_scope"] = decision_scope
    receipt["formal_decision_file_sha256"] = _sha(payload)
    _write_json(fixture["receipt"], receipt, pretty=True)


def test_trigger_a_publishes_canonical_bound_execution_seal(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    result = _run(sealed_trigger_fixture)

    payload = sealed_trigger_fixture["output"].read_bytes()
    report = json.loads(payload)
    assert payload == _canonical(report)
    assert result["trigger_branch"] == "causal_valid_no_go"
    assert result["seal_sha256"] == _sha(payload)
    assert report["causal_protocol_seal_sha256"] is None
    assert report["causal_protocol_seal_status"] == seal.CAUSAL_PROTOCOL_SEAL_STATUS
    assert report["online_icl_decision_sha256"] is None
    assert report["causal_inventory_recheck_matches_attestation"] is True
    assert report["causal_inventory_sha256"] == _sha(
        _canonical(report["causal_inventory"])
    )
    assert report["terminal_verifier_execution_plan_sha256"] == _sha(
        sealed_trigger_fixture["plan_path"].read_bytes()
    )
    assert set(report["verifier_execution"]["tools"]) == seal.PLAN_TOOL_NAMES
    causal_paths = {record["path"] for record in report["causal_inventory"]}
    for binding_name in (
        "causal_revalidated",
        "causal_revalidation_receipt",
        "execution_plan",
        "attester_code",
        "revalidator_code",
        "execution_seal_builder_code",
    ):
        assert report["bindings"][binding_name]["path"] not in causal_paths


def test_pure_plan_generator_reproduces_registered_plan(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    plan = sealed_trigger_fixture["plan"]
    generated = seal.make_execution_plan(
        tooling_source_commit=plan["tooling_source_commit"],
        causal_checkout_root=Path(plan["causal_checkout_root"]),
        durable_attempt_root=Path(plan["durable_attempt_root"]),
        created_at_utc=plan["created_at_utc"],
    )
    assert generated == plan


def test_pre_attestation_inventory_tamper_fails_before_seal(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    sealed_trigger_fixture["inventory_raw"].write_bytes(b"tampered")

    with pytest.raises(seal.ExecutionSealError, match="differs byte-for-byte"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()


def test_duplicate_key_in_original_fails_closed(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    duplicate = b'{"decision":"valid_no_go","decision":"pass"}'
    _retarget_decision_bytes(
        sealed_trigger_fixture,
        duplicate,
        decision="valid_no_go",
        decision_scope="internal_gate_no_go",
    )

    with pytest.raises(seal.ExecutionSealError, match="duplicate JSON key"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()


def test_byte_different_revalidation_is_rejected_even_if_object_matches(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    report = json.loads(sealed_trigger_fixture["decision"].read_text())
    sealed_trigger_fixture["revalidated"].write_bytes(_canonical(report))

    with pytest.raises(seal.ExecutionSealError, match="file bytes differ"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()


def test_causal_pass_cannot_misfire_trigger_a(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    report = _causal_report("pass")
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    _retarget_decision_bytes(
        sealed_trigger_fixture,
        payload,
        decision="pass",
        decision_scope="internal_gate_pass",
    )

    with pytest.raises(seal.ExecutionSealError, match="Trigger A is forbidden"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()


def test_plan_tool_drift_fails_before_any_trigger_parse(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    sealed_trigger_fixture["tool"].write_bytes(b"changed verifier")

    with pytest.raises(seal.ExecutionSealError, match="tool digest differs"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()


def test_symlinked_tooling_root_is_rejected_before_tool_open(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    tooling_root = Path(sealed_trigger_fixture["plan"]["tooling_root"])
    real_tooling_root = tooling_root.with_name("real-" + tooling_root.name)
    tooling_root.rename(real_tooling_root)
    tooling_root.symlink_to(real_tooling_root, target_is_directory=True)

    with pytest.raises(seal.ExecutionSealError, match="tooling root must be a real directory"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()


def test_plan_argv_drift_is_rejected(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    observed = list(
        sealed_trigger_fixture["plan"]["invocations"]["execution_seal_builder"][
            "argv"
        ]
    )
    observed[-1] += ".wrong"

    with pytest.raises(seal.ExecutionSealError, match="current .* argv differs"):
        _run(sealed_trigger_fixture, actual_argv=observed)
    assert not sealed_trigger_fixture["output"].exists()


def test_attestation_plan_binding_drift_fails_closed(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    attestation = json.loads(sealed_trigger_fixture["attestation"].read_text())
    attestation["execution_plan_sha256"] = "0" * 64
    _write_json(sealed_trigger_fixture["attestation"], attestation)

    with pytest.raises(seal.ExecutionSealError, match="execution-plan binding"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()


def test_receipt_exact_schema_rejects_extra_key(
    sealed_trigger_fixture: dict[str, Any],
) -> None:
    receipt = json.loads(sealed_trigger_fixture["receipt"].read_text())
    receipt["unregistered"] = True
    _write_json(sealed_trigger_fixture["receipt"], receipt, pretty=True)

    with pytest.raises(seal.ExecutionSealError, match="exact-key schema"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()


def test_output_path_is_fixed_and_no_overwrite(
    sealed_trigger_fixture: dict[str, Any], tmp_path: Path
) -> None:
    with pytest.raises(seal.ExecutionSealError, match="inputs/outputs differ"):
        _run(sealed_trigger_fixture, output=tmp_path / "elsewhere.json")
    sealed_trigger_fixture["output"].write_bytes(b"existing")
    with pytest.raises(FileExistsError, match="pre-existing"):
        _run(sealed_trigger_fixture)
    assert sealed_trigger_fixture["output"].read_bytes() == b"existing"


def test_future_online_inputs_cannot_bypass_null_plan(
    sealed_trigger_fixture: dict[str, Any]
) -> None:
    with pytest.raises(seal.ExecutionSealError, match="Trigger B is unavailable"):
        _run(
            sealed_trigger_fixture,
            online_inputs={"online_original": sealed_trigger_fixture["decision"]},
        )
    assert not sealed_trigger_fixture["output"].exists()


def test_final_inventory_race_aborts_publication(
    sealed_trigger_fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    original = seal._recompute_attested_inventory
    calls = 0

    def race(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        nonlocal calls
        calls += 1
        if calls == 2:
            sealed_trigger_fixture["inventory_raw"].write_bytes(b"raced")
        return original(files)

    monkeypatch.setattr(seal, "_recompute_attested_inventory", race)
    with pytest.raises(seal.ExecutionSealError, match="differs byte-for-byte"):
        _run(sealed_trigger_fixture)
    assert not sealed_trigger_fixture["output"].exists()
