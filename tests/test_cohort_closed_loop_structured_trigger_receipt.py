from __future__ import annotations

import hashlib
import json
import math
import os
import statistics
from pathlib import Path
from typing import Any

import pytest

import cohort_closed_loop_structured_atomic_publish as atomic
import cohort_closed_loop_structured_trigger_absence_adapter as absence_adapter
import cohort_closed_loop_structured_trigger_receipt as trigger


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _legacy(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _binding(path: str, raw: bytes) -> dict[str, object]:
    return {"path": path, "sha256": _sha(raw), "size_bytes": len(raw)}


def _legacy_binding(path: str, raw: bytes) -> dict[str, object]:
    return {"path": path, "sha256": _sha(raw)}


def _record(
    path: str,
    roles: list[str],
    raw: bytes,
    *,
    inode: int,
    mtime_ns: int = 100,
) -> dict[str, object]:
    return {
        "device": 7,
        "inode": inode,
        "mtime_ns": mtime_ns,
        "path": path,
        "roles": sorted(roles),
        "sha256": _sha(raw),
        "size_bytes": len(raw),
    }


def _audit(value: dict[str, object]) -> dict[str, object]:
    result = dict(value)
    result["audit_sha256"] = _sha(_legacy(value))
    return result


def _terminal_action(tag: str) -> dict[str, object]:
    return {
        "canonical_sha256": [_sha(tag.encode())],
        "count": 20,
        "unique_count": 1,
        "zero_value_count": 0,
    }


def _sign_test(deltas: list[float]) -> dict[str, object]:
    positives = sum(delta > 0.0 for delta in deltas)
    negatives = sum(delta < 0.0 for delta in deltas)
    zeros = len(deltas) - positives - negatives
    nonzero = positives + negatives
    if nonzero == 0:
        p_value = 1.0
    else:
        extreme = max(positives, negatives)
        tail = sum(
            math.comb(nonzero, value) for value in range(extreme, nonzero + 1)
        ) / (2**nonzero)
        p_value = round(min(1.0, 2.0 * tail), 12)
    return {
        "alternative": "two_sided",
        "method": "exact_binomial_sign_test_zero_deltas_excluded",
        "negative_seed_deltas": negatives,
        "nonzero_seed_deltas": nonzero,
        "p_value": p_value,
        "positive_seed_deltas": positives,
        "zero_seed_deltas": zeros,
    }


def _decision() -> dict[str, object]:
    deltas = [0.03, -0.01, 0.02]
    active = [0.53, 0.49, 0.52]
    lr0 = [0.50, 0.50, 0.50]
    mean_delta = statistics.mean(deltas)
    sample_sd = statistics.stdev(deltas)
    half_width = trigger.EXPECTED_T_CRITICAL * sample_sd / math.sqrt(3)
    ci = [-0.01, 0.04]
    pairs = []
    for index, seed in enumerate(trigger.EXPECTED_RUN_SEEDS):
        pairs.append(
            {
                "active_score": active[index],
                "delta_seed": deltas[index],
                "lr0_score": lr0[index],
                "pair_id": f"seed-{seed}",
                "run_seed": seed,
                "tape_sha256": _sha(f"tape-{seed}".encode()),
                "terminal_actions": {
                    "active": _terminal_action(f"active-{seed}"),
                    "lr0": _terminal_action(f"lr0-{seed}"),
                },
            }
        )
    checks = {
        "all_3_seed_deltas_gt_0": False,
        "ci_95_lower_gt_0": False,
        "integrity_gate_passed": True,
        "mean_delta_gte_0_02": False,
        "no_schema_format_regression": True,
    }
    return {
        "aggregate": {
            "ci_95_lower": ci[0],
            "ci_95_upper": ci[1],
            "mean_delta": round(mean_delta, 12),
            "positive_seeds": 2,
        },
        "bootstrap": {
            "ci_95": ci,
            "fixed_scoring_conditions": 20,
            "method": "hierarchical_paired_common_instance_ids_percentile_type7",
            "publication_grade": False,
            "replicates": 50_000,
            "seed": 2026071499,
        },
        "decision": "valid_no_go",
        "decision_scope": "internal_gate_no_go",
        "errors": [],
        "experiment": trigger.CAUSAL_EXPERIMENT,
        "limitation": trigger.CAUSAL_LIMITATION,
        "mechanism_label": trigger.CAUSAL_MECHANISM_LABEL,
        "pairs": pairs,
        "preregistered_thresholds": {
            "all_seed_deltas_gt": 0.0,
            "bootstrap_ci_lower_gt": 0.0,
            "mean_delta_gte": 0.02,
        },
        "protocol": trigger.CAUSAL_PROTOCOL,
        "publication_inference": {
            "confirmation_contract": {
                "causal_component_ablations_required": True,
                "fixed_population_scope_only_if_dgp_requirement_not_met": True,
                "independent_dgp_population_per_seed_preferred": True,
                "mean_seed_delta_gte": 0.02,
                "minimum_new_adaptation_seeds": 6,
                "minimum_independent_frozen_dgp_populations": 2,
                "must_exclude_screen_seeds": list(trigger.EXPECTED_RUN_SEEDS),
                "primary_inference": "two_sided_exact_sign_flip",
                "primary_inferential_unit": "adaptation_seed",
                "seed_level_interval_95_lower_gt": 0.0,
                "seed_to_population_mapping_preregistered_required": True,
                "separate_preregistration_required": True,
            },
            "effective_n": 3,
            "exact_sign_test": _sign_test(deltas),
            "fixed_scoring_conditions": 20,
            "internal_screen_status": "internal_gate_no_go",
            "legacy_hierarchical_bootstrap_publication_grade": False,
            "negative_interpretation": {
                "harm_established": False,
                "harm_requires": "publication_grade_seed_level_one_sided_95_upper_lt_0",
                "practical_benefit_at_least_0_02_ruled_out": False,
                "practical_benefit_exclusion_requires": "publication_grade_seed_level_one_sided_95_upper_lt_0_02",
                "valid_no_go_establishes_zero_or_harm": False,
            },
            "primary_inferential_unit": "adaptation_seed",
            "publication_grade": False,
            "raw_seed_deltas": deltas,
            "sample_sd": round(sample_sd, 12),
            "seed_level_t_interval_95": {
                "critical_value": trigger.EXPECTED_T_CRITICAL,
                "df": 2,
                "lower": round(mean_delta - half_width, 12),
                "method": "two_sided_student_t_interval_over_seed_deltas",
                "normality_dependent_descriptive": True,
                "upper": round(mean_delta + half_width, 12),
            },
            "seed_mean_delta": round(mean_delta, 12),
            "status": "confirmation_required_not_publication_grade",
        },
        "publication_grade": False,
        "schema_version": 1,
        "status": "valid",
        "threshold_checks": checks,
    }


def _expected_argv(plan: dict[str, Any], stage: str) -> list[str]:
    runtime = plan["runtime"]["python_path"]
    tool = plan["tools"][stage]["path"]
    invocation = plan["invocations"][stage]
    inputs = invocation["inputs"]
    outputs = invocation["outputs"]
    if stage == "attester":
        return [
            runtime,
            tool,
            "--execution-plan",
            inputs["execution_plan"],
            "--root",
            inputs["root"],
            "--launch-expectation",
            inputs["launch_expectation"],
            "--provenance",
            inputs["provenance"],
            "--provenance-details",
            inputs["provenance_details"],
            "--output",
            outputs["attestation"],
            "--stability-seconds",
            "1.0",
        ]
    if stage == "revalidator":
        return [
            runtime,
            tool,
            "--execution-plan",
            inputs["execution_plan"],
            "--root",
            inputs["root"],
            "--attestation",
            inputs["attestation"],
            "--launch-expectation",
            inputs["launch_expectation"],
            "--grid",
            inputs["grid"],
            "--provenance",
            inputs["provenance"],
            "--formal-manifest",
            inputs["formal_manifest"],
            "--formal-decision",
            inputs["formal_decision"],
            "--preregistration",
            inputs["preregistration"],
            "--statistical-addendum",
            inputs["statistical_addendum"],
            "--output",
            outputs["revalidated_decision"],
            "--receipt",
            outputs["revalidation_receipt"],
        ]
    return [
        runtime,
        tool,
        "--execution-plan",
        inputs["execution_plan"],
        "--attestation",
        inputs["attestation"],
        "--launch-expectation",
        inputs["launch_expectation"],
        "--causal-original",
        inputs["causal_original"],
        "--causal-revalidated",
        inputs["causal_revalidated"],
        "--revalidation-receipt",
        inputs["revalidation_receipt"],
        "--structured-preregistration",
        inputs["structured_preregistration"],
        "--output",
        outputs["execution_seal"],
    ]


def _fixture() -> dict[str, Any]:
    source_commit = "1" * 40
    tooling_commit = "a" * 40
    structured_tooling_commit = "b" * 40
    causal_root = "/registered/causal/checkout"
    durable = "/registered/causal/durable/attempt-002"
    control = f"{durable}/control"
    prep = f"{durable}/prep"
    artifact = f"{durable}/artifacts/cohort_causal"
    tooling = f"{control}/verifier/{tooling_commit}"
    plan_path = f"{control}/CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN.json"
    launch_path = f"{control}/CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json"
    attestation_path = f"{prep}/causal_trigger_completion_attestation.json"
    original_path = f"{artifact}/formal_decision.json"
    revalidated_path = f"{prep}/causal_formal.revalidated.json"
    revalidation_receipt_path = f"{prep}/causal_formal.revalidation_receipt.json"
    execution_seal_path = (
        f"{prep}/cohort_closed_loop_structured_state.execution_seal.json"
    )
    structured_prereg_path = (
        f"{tooling}/COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md"
    )
    pid_path = f"{prep}/causal_formal.pid"
    exit_path = f"{prep}/causal_formal.exit"
    formal_manifest_path = f"{artifact}/formal_manifest.json"

    attester_source = b"# attester source\n"
    revalidator_source = b"# revalidator source\n"
    execution_seal_builder_source = b"# execution seal builder source\n"
    trigger_receipt_builder_source = b"# strict trigger receipt builder source\n"
    trigger_receipt_revalidator_source = (
        b"# independent trigger receipt revalidator source\n"
    )
    structured_atomic_publisher_source = b"# structured atomic publisher source\n"
    trigger_receipt_publisher_source = b"# trigger receipt publisher source\n"
    absence_adapter_source = b"# independent absence adapter source\n"
    prereg_raw = b"# structured preregistration v1\n"
    original_raw = (json.dumps(_decision(), indent=2, sort_keys=True) + "\n").encode()
    revalidated_raw = original_raw
    pid_raw = b"99123\n"
    exit_raw = b"0\n"
    formal_manifest_raw = b'{"formal":"registered"}'

    launch = {
        "artifact_root": artifact,
        "attempt_id": "attempt-002",
        "boot_id": "11111111-1111-1111-1111-111111111111",
        "checkout_root": causal_root,
        "collector_gpus": [0, 2, 3],
        "created_at_utc": "2026-07-14T10:00:00Z",
        "durable_attempt_root": durable,
        "eval_gpus": [0, 2, 3, 4, 5, 6],
        "exit_file": exit_path,
        "expected_final_inventory": dict(trigger.EXPECTED_REGISTERED_COUNTS),
        "formal_grid_file_sha256": _sha(b"grid"),
        "launch_mode": "formal",
        "launcher_file_sha256": _sha(b"launcher"),
        "max_used_memory_mib": 1024,
        "node_hostname": "test-a100-节点",
        "pid_file": pid_path,
        "pid_file_sha256_at_registration": _sha(pid_raw),
        "protocol": trigger.CAUSAL_LAUNCH_EXPECTATION_PROTOCOL,
        "provenance_file_sha256": _sha(b"provenance"),
        "schema_version": 1,
        "source_commit": source_commit,
        "wrapper_cmdline_sha256_at_registration": _sha(b"cmdline"),
        "wrapper_pid": 99123,
        "wrapper_start_ticks": 1234,
    }
    launch_raw = _legacy(launch)
    tools = {
        "attester": _legacy_binding(
            f"{tooling}/attest_cohort_causal_completion.py", attester_source
        ),
        "revalidator": _legacy_binding(
            f"{tooling}/revalidate_cohort_causal_terminal.py", revalidator_source
        ),
        "execution_seal_builder": _legacy_binding(
            f"{tooling}/build_cohort_structured_state_execution_seal.py",
            execution_seal_builder_source,
        ),
    }
    plan: dict[str, Any] = {
        "attempt_id": "attempt-002",
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": trigger.CAUSAL_PROTOCOL_SEAL_STATUS,
        "causal_checkout_root": causal_root,
        "created_at_utc": "2026-07-14T10:01:00Z",
        "durable_attempt_root": durable,
        "invocations": {
            "attester": {
                "argv": [],
                "inputs": {
                    "execution_plan": plan_path,
                    "launch_expectation": launch_path,
                    "provenance": f"{artifact}/provenance.json",
                    "provenance_details": f"{artifact}/provenance.details.json",
                    "root": causal_root,
                },
                "outputs": {"attestation": attestation_path},
                "parameters": {"stability_seconds": "1.0"},
            },
            "revalidator": {
                "argv": [],
                "inputs": {
                    "attestation": attestation_path,
                    "execution_plan": plan_path,
                    "formal_decision": original_path,
                    "formal_manifest": formal_manifest_path,
                    "grid": f"{causal_root}/grid_cohort_causal_formal.json",
                    "launch_expectation": launch_path,
                    "preregistration": f"{causal_root}/COHORT_QONLY_CAUSAL_PREREG.md",
                    "provenance": f"{artifact}/provenance.json",
                    "root": causal_root,
                    "statistical_addendum": f"{causal_root}/COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md",
                },
                "outputs": {
                    "revalidated_decision": revalidated_path,
                    "revalidation_receipt": revalidation_receipt_path,
                },
                "parameters": {},
            },
            "execution_seal_builder": {
                "argv": [],
                "inputs": {
                    "attestation": attestation_path,
                    "causal_original": original_path,
                    "causal_revalidated": revalidated_path,
                    "execution_plan": plan_path,
                    "launch_expectation": launch_path,
                    "revalidation_receipt": revalidation_receipt_path,
                    "structured_preregistration": structured_prereg_path,
                },
                "outputs": {"execution_seal": execution_seal_path},
                "parameters": {},
            },
        },
        "launch_expectation": _legacy_binding(launch_path, launch_raw),
        "online_icl": None,
        "protocol": trigger.TERMINAL_PLAN_PROTOCOL,
        "runtime": {
            "python_path": trigger.EXPECTED_PYTHON_PATH,
            "python_version": trigger.EXPECTED_PYTHON_VERSION,
        },
        "schema_version": 1,
        "status": "registered",
        "structured_preregistration": _legacy_binding(
            structured_prereg_path, prereg_raw
        ),
        "tooling_root": tooling,
        "tooling_source_commit": tooling_commit,
        "tools": tools,
    }
    for stage in tools:
        plan["invocations"][stage]["argv"] = _expected_argv(plan, stage)
    plan_raw = _legacy(plan)

    opaque: list[tuple[str, list[str], bytes, int]] = [
        (
            f"{causal_root}/data/adaptation/manifest.json",
            ["adaptation_corpus_manifest"],
            b"adapt-manifest",
            100,
        ),
        (
            f"{causal_root}/data/adaptation/payload.bin",
            ["adaptation_corpus_artifact"],
            b"adapt",
            100,
        ),
        (
            f"{causal_root}/data/heldout/manifest.json",
            ["heldout_corpus_manifest"],
            b"held-manifest",
            100,
        ),
        (
            f"{causal_root}/data/heldout/payload.bin",
            ["heldout_corpus_artifact"],
            b"held",
            100,
        ),
        (
            f"{causal_root}/src/tasks/cohort_studies/schedules/adaptation.json",
            ["adaptation_schedule"],
            b"adapt-schedule",
            100,
        ),
        (
            f"{causal_root}/src/tasks/cohort_studies/schedules/heldout.json",
            ["heldout_schedule"],
            b"held-schedule",
            100,
        ),
        (
            f"{causal_root}/COHORT_QONLY_CAUSAL_PREREG.md",
            ["causal_prereg"],
            b"causal-prereg",
            100,
        ),
        (
            f"{causal_root}/COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md",
            ["statistical_addendum"],
            b"addendum",
            100,
        ),
        (
            f"{causal_root}/grid_cohort_causal_formal.json",
            ["formal_grid"],
            b"grid",
            100,
        ),
        (
            f"{causal_root}/launch_cohort_causal.sh",
            ["launcher_source"],
            b"launcher",
            100,
        ),
        (
            f"{causal_root}/validate_cohort_因果_results.py",
            ["evaluation_code"],
            b"eval",
            100,
        ),
        (f"{artifact}/smoke_gate.json", ["causal_smoke_gate"], b"smoke", 100),
        (f"{artifact}/provenance.json", ["compact_provenance"], b"provenance", 100),
        (
            f"{artifact}/provenance.details.json",
            ["detailed_provenance"],
            b"details",
            100,
        ),
        (formal_manifest_path, ["formal_manifest"], formal_manifest_raw, 100),
        (original_path, ["formal_decision"], original_raw, 100),
        (launch_path, ["launch_expectation"], launch_raw, 100),
        (pid_path, ["wrapper_pid_file"], pid_raw, 90),
        (exit_path, ["wrapper_exit_file"], exit_raw, 200),
    ]
    for index in range(3):
        opaque.extend(
            [
                (
                    f"{artifact}/tapes/{index}.json",
                    ["formal_tape"],
                    f"tape{index}".encode(),
                    100,
                ),
                (
                    f"{artifact}/collectors/{index}.manifest.json",
                    ["collector_manifest"],
                    f"cm{index}".encode(),
                    100,
                ),
                (
                    f"{artifact}/traces/collector-{index}.json",
                    ["collector_final_trace"],
                    f"ct{index}".encode(),
                    100,
                ),
            ]
        )
    for index in range(6):
        opaque.extend(
            [
                (
                    f"{artifact}/cells/{index}.manifest.json",
                    ["cell_manifest"],
                    f"cellm{index}".encode(),
                    100,
                ),
                (
                    f"{artifact}/traces/cell-{index}.json",
                    ["cell_final_trace"],
                    f"cellt{index}".encode(),
                    100,
                ),
            ]
        )
    pre_records = sorted(
        [
            _record(path, roles, raw, inode=index + 10, mtime_ns=mtime)
            for index, (path, roles, raw, mtime) in enumerate(opaque)
        ],
        key=lambda row: row["path"],
    )
    inventory_sha = _sha(_legacy(pre_records))
    process = _audit(
        {
            "artifact_root_path": artifact,
            "attempt_checkout_path": causal_root,
            "method": "linux_procfs_cmdline_and_cwd",
            "status": "pass",
        }
    )
    temporary = _audit(
        {
            "forbidden_match_count": 0,
            "roots": sorted([artifact, prep]),
            "status": "pass",
        }
    )
    pid_record = next(row for row in pre_records if "wrapper_pid_file" in row["roles"])
    exit_record = next(
        row for row in pre_records if "wrapper_exit_file" in row["roles"]
    )
    attestation = {
        "causal_pre_attestation_inventory_sha256": inventory_sha,
        "completed_at_utc": "2026-07-14T11:00:03Z",
        "execution_plan_path": plan_path,
        "execution_plan_sha256": _sha(plan_raw),
        "expected_launcher": {
            "formal_grid_file_sha256": launch["formal_grid_file_sha256"],
            "launch_expectation_path": launch_path,
            "launch_expectation_sha256": _sha(launch_raw),
            "launcher_file_sha256": launch["launcher_file_sha256"],
            "provenance_file_sha256": launch["provenance_file_sha256"],
            "source_commit": source_commit,
            "wrapper_cmdline_sha256_at_registration": launch[
                "wrapper_cmdline_sha256_at_registration"
            ],
        },
        "no_live_or_temporary": temporary,
        "pid_exit": {
            "exit_after_outputs_status": "pass",
            "exit_file_mtime_ns": exit_record["mtime_ns"],
            "exit_file_path": exit_path,
            "exit_file_sha256": _sha(exit_raw),
            "exit_file_size_bytes": len(exit_raw),
            "exit_zero_status": "pass",
            "pid_ascii_status": "pass",
            "pid_file_mtime_ns": pid_record["mtime_ns"],
            "pid_file_path": pid_path,
            "pid_file_sha256": _sha(pid_raw),
            "pid_file_size_bytes": len(pid_raw),
            "pid_liveness_status": "dead",
        },
        "process_absence": process,
        "protocol": trigger.CAUSAL_ATTESTATION_PROTOCOL,
        "registered_counts": dict(trigger.EXPECTED_REGISTERED_COUNTS),
        "schema_version": 1,
        "snapshots": [
            {
                "captured_at_utc": "2026-07-14T11:00:00Z",
                "file_count": len(pre_records),
                "files": pre_records,
                "inventory_sha256": inventory_sha,
                "sequence": 1,
            },
            {
                "captured_at_utc": "2026-07-14T11:00:02Z",
                "file_count": len(pre_records),
                "files": pre_records,
                "inventory_sha256": inventory_sha,
                "sequence": 2,
            },
        ],
        "stability": {
            "minimum_interval_seconds": 1.0,
            "observed_interval_seconds": 2.0,
            "snapshots_identical": True,
        },
        "status": "complete",
    }
    attestation_raw = _legacy(attestation)
    full_inventory = sorted(
        [
            *pre_records,
            _record(
                attestation_path,
                ["causal_trigger_completion_attestation"],
                attestation_raw,
                inode=999,
                mtime_ns=210,
            ),
        ],
        key=lambda row: row["path"],
    )
    inventory_raw = _legacy(full_inventory)
    receipt = {
        "decision": "valid_no_go",
        "decision_scope": "internal_gate_no_go",
        "execution_plan_path": plan_path,
        "execution_plan_sha256": _sha(plan_raw),
        "formal_decision_file_sha256": _sha(original_raw),
        "formal_manifest_file_sha256": _sha(formal_manifest_raw),
        "status": "valid",
    }
    receipt_raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    bindings = {
        "attester_code": _binding(tools["attester"]["path"], attester_source),
        "causal_original": _binding(original_path, original_raw),
        "causal_revalidated": _binding(revalidated_path, revalidated_raw),
        "causal_revalidation_receipt": _binding(revalidation_receipt_path, receipt_raw),
        "causal_trigger_completion_attestation": _binding(
            attestation_path, attestation_raw
        ),
        "execution_plan": _binding(plan_path, plan_raw),
        "execution_seal_builder_code": _binding(
            tools["execution_seal_builder"]["path"], execution_seal_builder_source
        ),
        "launch_expectation": _binding(launch_path, launch_raw),
        "revalidator_code": _binding(tools["revalidator"]["path"], revalidator_source),
        "structured_preregistration": _binding(structured_prereg_path, prereg_raw),
    }
    verifier_execution = {
        "invocations": plan["invocations"],
        "invocations_sha256": _sha(_legacy(plan["invocations"])),
        "runtime": plan["runtime"],
        "tools": plan["tools"],
    }
    seal = {
        "bindings": bindings,
        "causal_completion_attestation_sha256": _sha(attestation_raw),
        "causal_decision_sha256": _sha(_legacy(_decision())),
        "causal_exit_file_sha256": _sha(exit_raw),
        "causal_inventory": full_inventory,
        "causal_inventory_recheck_matches_attestation": True,
        "causal_inventory_sha256": _sha(inventory_raw),
        "causal_original_file_sha256": _sha(original_raw),
        "causal_pid_file_sha256": _sha(pid_raw),
        "causal_pre_attestation_inventory_sha256": inventory_sha,
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": trigger.CAUSAL_PROTOCOL_SEAL_STATUS,
        "causal_revalidation_file_sha256": _sha(revalidated_raw),
        "causal_source_commit": source_commit,
        "created_at_utc": "2026-07-14T11:00:04Z",
        "online_icl_decision_sha256": None,
        "online_icl_inventory_recheck_matches_marker": None,
        "online_icl_inventory_sha256": None,
        "online_icl_original_file_sha256": None,
        "online_icl_protocol_seal_sha256": None,
        "online_icl_revalidation_file_sha256": None,
        "online_icl_wrapper_contract_sha256": None,
        "online_icl_wrapper_exit_marker_sha256": None,
        "protocol": trigger.TRIGGER_EXECUTION_SEAL_PROTOCOL,
        "schema_version": 1,
        "status": "sealed",
        "terminal_verifier_execution_plan_path": plan_path,
        "terminal_verifier_execution_plan_sha256": _sha(plan_raw),
        "tooling_source_commit": tooling_commit,
        "trigger_branch": trigger.TRIGGER_A,
        "verifier_execution": verifier_execution,
    }
    seal_raw = _legacy(seal)

    validator_paths = {
        "causal_completion_attester": tools["attester"]["path"],
        "causal_terminal_revalidator": tools["revalidator"]["path"],
        "pretrigger_absence_adapter": "/registered/structured/tools/attest_pretrigger_缺席.py",
        "structured_atomic_publisher": "/registered/structured/tools/cohort_closed_loop_structured_atomic_publish.py",
        "trigger_execution_seal_builder": tools["execution_seal_builder"]["path"],
        "trigger_receipt_builder": "/registered/structured/tools/cohort_closed_loop_structured_trigger_receipt.py",
        "trigger_receipt_publisher": "/registered/structured/tools/publish_cohort_closed_loop_structured_trigger_receipt.py",
        "trigger_receipt_revalidator": "/registered/structured/tools/revalidate_cohort_closed_loop_structured_trigger_receipt.py",
    }
    source_by_id = {
        "causal_completion_attester": attester_source,
        "causal_terminal_revalidator": revalidator_source,
        "pretrigger_absence_adapter": absence_adapter_source,
        "structured_atomic_publisher": structured_atomic_publisher_source,
        "trigger_execution_seal_builder": execution_seal_builder_source,
        "trigger_receipt_builder": trigger_receipt_builder_source,
        "trigger_receipt_publisher": trigger_receipt_publisher_source,
        "trigger_receipt_revalidator": trigger_receipt_revalidator_source,
    }
    binding_rows = [
        {
            "binding_id": binding_id,
            **_binding(validator_paths[binding_id], source_by_id[binding_id]),
        }
        for binding_id in trigger.REQUIRED_VALIDATOR_BINDING_IDS
    ]
    validator_raw = trigger.build_trigger_validator_inventory_bytes(
        binding_records_bytes=_canonical(binding_rows),
        tooling_source_commit=structured_tooling_commit,
        created_at_utc="2026-07-14T09:00:00Z",
    )
    structured_attempt = "attempt-001"
    structured_root = (
        "/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
        f"{structured_tooling_commit}/attempts/{structured_attempt}"
    )
    created_at = "2026-07-14T11:00:06Z"
    absence_unsigned = {
        "protocol": trigger.PRETRIGGER_ABSENCE_PROTOCOL,
        "schema_version": 1,
        "status": "attested_absent",
        "attempt_id": structured_attempt,
        "structured_durable_root": structured_root,
        "method": "root_relative_no_follow_full_walk_v1",
        "service_identity": trigger.PRETRIGGER_ABSENCE_SERVICE_IDENTITY,
        "service_uid": trigger.PRETRIGGER_ABSENCE_SERVICE_UID,
        "adapter_source_path": validator_paths["pretrigger_absence_adapter"],
        "adapter_source_sha256": _sha(absence_adapter_source),
        "filesystem_root_identity": {
            "access_boundary": "dedicated_absence_adapter_lstat_boundary_v1",
            "device": 19,
            "inode": 20,
            "mode": 0o700,
            "mount_id": "sensei-fs:structured-root-v1",
            "owner_uid": trigger.PRETRIGGER_ABSENCE_SERVICE_UID,
        },
        "checked_at_utc": "2026-07-14T11:00:05Z",
        "receipt_created_at_utc": created_at,
        "trigger_execution_seal_sha256": _sha(seal_raw),
        "forbidden_classes": list(trigger.ABSENCE_FORBIDDEN_CLASSES),
        "forbidden_match_count": 0,
        "forbidden_matches": [],
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    absence = dict(absence_unsigned)
    absence["absence_attestation_sha256"] = _sha(_canonical(absence_unsigned))
    absence_raw = _canonical(absence)
    return {
        "trigger_execution_seal_bytes": seal_raw,
        "causal_original_decision_bytes": original_raw,
        "causal_revalidated_decision_bytes": revalidated_raw,
        "causal_completion_attestation_bytes": attestation_raw,
        "causal_revalidation_receipt_bytes": receipt_raw,
        "causal_pid_file_bytes": pid_raw,
        "causal_exit_file_bytes": exit_raw,
        "terminal_verifier_execution_plan_bytes": plan_raw,
        "causal_launch_expectation_bytes": launch_raw,
        "causal_inventory_bytes": inventory_raw,
        "structured_preregistration_bytes": prereg_raw,
        "trigger_validator_inventory_bytes": validator_raw,
        "attester_source_bytes": attester_source,
        "causal_revalidator_source_bytes": revalidator_source,
        "execution_seal_builder_source_bytes": execution_seal_builder_source,
        "trigger_receipt_builder_source_bytes": trigger_receipt_builder_source,
        "trigger_receipt_revalidator_source_bytes": trigger_receipt_revalidator_source,
        "pretrigger_absence_adapter_source_bytes": absence_adapter_source,
        "structured_atomic_publisher_source_bytes": structured_atomic_publisher_source,
        "trigger_receipt_publisher_source_bytes": trigger_receipt_publisher_source,
        "pretrigger_absence_evidence_bytes": absence_raw,
        "structured_attempt_id": structured_attempt,
        "created_at_utc": created_at,
    }


def _build(evidence: dict[str, Any]) -> bytes:
    return trigger.build_trigger_a_receipt_bytes(**evidence)


def _retarget_seal(evidence: dict[str, Any], mutate: Any) -> None:
    seal = json.loads(evidence["trigger_execution_seal_bytes"])
    mutate(seal)
    evidence["trigger_execution_seal_bytes"] = _legacy(seal)


def _retarget_absence(evidence: dict[str, Any], mutate: Any) -> None:
    claim = json.loads(evidence["pretrigger_absence_evidence_bytes"])
    mutate(claim)
    unsigned = {key: claim[key] for key in trigger._ABSENCE_UNSIGNED_KEYS}
    claim["absence_attestation_sha256"] = _sha(_canonical(unsigned))
    evidence["pretrigger_absence_evidence_bytes"] = _canonical(claim)


def _real_adapter_absence_bytes(
    evidence: dict[str, Any], *, physical_root: Path
) -> bytes:
    """Replace synthetic absence evidence with the publication-chain adapter output."""

    control = physical_root / "control"
    control.mkdir(parents=True)
    physical_root.chmod(0o700)
    control.chmod(0o700)

    adapter_path = Path(absence_adapter.__file__).resolve()
    adapter_raw = adapter_path.read_bytes()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    rows = inventory["bindings"]
    adapter_binding = next(
        row for row in rows if row["binding_id"] == "pretrigger_absence_adapter"
    )
    adapter_binding.update(
        {
            "path": adapter_path.as_posix(),
            "sha256": _sha(adapter_raw),
            "size_bytes": len(adapter_raw),
        }
    )
    inventory_raw = trigger.build_trigger_validator_inventory_bytes(
        binding_records_bytes=_canonical(rows),
        tooling_source_commit=inventory["tooling_source_commit"],
        created_at_utc=inventory["created_at_utc"],
    )
    evidence["trigger_validator_inventory_bytes"] = inventory_raw
    evidence["pretrigger_absence_adapter_source_bytes"] = adapter_raw
    atomic.publish_readonly_no_overwrite(
        root=physical_root,
        relative_path="control/trigger_validator_inventory.json",
        payload=inventory_raw,
    )

    metadata = physical_root.stat()
    major_minor = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    mountinfo = (
        f"101 1 {major_minor} / {physical_root} rw,nosuid - testfs /dev/test rw\n"
    ).encode("ascii")
    synthetic_absence = json.loads(evidence["pretrigger_absence_evidence_bytes"])
    raw = absence_adapter.attest_pretrigger_absence(
        root=physical_root,
        structured_durable_root=synthetic_absence["structured_durable_root"],
        source_commit=inventory["tooling_source_commit"],
        attempt_id=synthetic_absence["attempt_id"],
        trigger_execution_seal_bytes=evidence["trigger_execution_seal_bytes"],
        trigger_validator_inventory_bytes=inventory_raw,
        runtime=absence_adapter.AbsenceRuntime(
            euid=lambda: trigger.PRETRIGGER_ABSENCE_SERVICE_UID,
            identity_for_uid=lambda uid: trigger.PRETRIGGER_ABSENCE_SERVICE_IDENTITY,
            mountinfo_bytes=lambda: mountinfo,
            now_utc=lambda: evidence["created_at_utc"],
            uid_translate=lambda uid: trigger.PRETRIGGER_ABSENCE_SERVICE_UID,
            physical_root_override=physical_root,
        ),
    )
    evidence["pretrigger_absence_evidence_bytes"] = raw
    return raw


def test_valid_trigger_a_receipt_is_canonical_exact_and_non_authorizing() -> None:
    evidence = _fixture()
    raw = _build(evidence)
    obj = json.loads(raw)

    assert raw == _canonical(obj)
    assert set(obj) == trigger._TRIGGER_RECEIPT_KEYS
    assert obj["trigger_branch"] == trigger.TRIGGER_A
    assert obj["tooling_source_commit"] == "b" * 40
    assert obj["trigger_execution_seal"]["payload"]["tooling_source_commit"] == "a" * 40
    assert obj["online_icl"] is None
    validator_ids = tuple(
        row["binding_id"]
        for row in obj["trigger_validator_inventory"]["payload"]["bindings"]
    )
    assert validator_ids == trigger.REQUIRED_VALIDATOR_BINDING_IDS
    assert len(validator_ids) == 8
    assert obj["causal"]["decision"] == "valid_no_go"
    assert obj["causal"]["decision_scope"] == "internal_gate_no_go"
    assert obj["causal"]["model_calls_authorized"] is False
    assert obj["causal"]["operational_authorization"] is False
    assert (
        obj["pretrigger_absence_evidence"]["payload"]["operational_authorization"]
        is False
    )
    assert not hasattr(trigger, "validate_trigger_a_receipt_bytes")


def test_dual_serializers_preserve_legacy_utf8_and_escape_new_control_bytes() -> None:
    evidence = _fixture()
    assert "因果".encode() in evidence["causal_inventory_bytes"]
    assert b"\\u56e0\\u679c" not in evidence["causal_inventory_bytes"]
    assert "节点".encode() in evidence["causal_launch_expectation_bytes"]
    assert b"\\u7f3a\\u5e2d" in evidence["trigger_validator_inventory_bytes"]
    assert "缺席".encode() not in evidence["trigger_validator_inventory_bytes"]

    receipt = _build(evidence)
    assert receipt.isascii()
    assert b"\\u56e0\\u679c" in receipt
    assert trigger.legacy_canonical_json_bytes({"value": "因果"}) == (
        b'{"value":"' + "因果".encode() + b'"}'
    )
    assert trigger.canonical_json_bytes({"value": "因果"}) == (
        b'{"value":"\\u56e0\\u679c"}'
    )


def test_legacy_plan_bindings_are_exactly_path_and_sha_only() -> None:
    evidence = _fixture()
    plan = json.loads(evidence["terminal_verifier_execution_plan_bytes"])
    assert set(plan["launch_expectation"]) == {"path", "sha256"}
    assert set(plan["structured_preregistration"]) == {"path", "sha256"}
    assert all(set(binding) == {"path", "sha256"} for binding in plan["tools"].values())

    plan["launch_expectation"]["size_bytes"] = 1
    evidence["terminal_verifier_execution_plan_bytes"] = _legacy(plan)
    with pytest.raises(trigger.TriggerReceiptError, match="exact-key schema differs"):
        _build(evidence)


def test_public_builder_cannot_accept_a_hand_written_seal_alone() -> None:
    evidence = _fixture()
    with pytest.raises(TypeError):
        trigger.build_trigger_a_receipt_bytes(
            trigger_execution_seal_bytes=evidence["trigger_execution_seal_bytes"]
        )


@pytest.mark.parametrize(
    "missing_input",
    (
        "structured_atomic_publisher_source_bytes",
        "trigger_receipt_publisher_source_bytes",
    ),
)
def test_both_publisher_source_byte_edges_are_mandatory(missing_input: str) -> None:
    evidence = _fixture()
    del evidence[missing_input]
    with pytest.raises(TypeError, match=missing_input):
        _build(evidence)


@pytest.mark.parametrize(
    "source_input",
    (
        "structured_atomic_publisher_source_bytes",
        "trigger_receipt_publisher_source_bytes",
    ),
)
def test_publisher_source_bytes_are_hash_and_size_bound(source_input: str) -> None:
    evidence = _fixture()
    evidence[source_input] += b"# byte substitution\n"
    with pytest.raises(trigger.TriggerReceiptError, match="validator source differs"):
        _build(evidence)


def test_forged_execution_seal_digest_is_rejected() -> None:
    evidence = _fixture()
    _retarget_seal(
        evidence,
        lambda seal: seal.__setitem__("causal_decision_sha256", "0" * 64),
    )
    with pytest.raises(trigger.TriggerReceiptError, match="direct digest differs"):
        _build(evidence)


def test_substituted_revalidated_report_is_rejected_byte_exactly() -> None:
    evidence = _fixture()
    report = json.loads(evidence["causal_revalidated_decision_bytes"])
    report["aggregate"]["ci_95_upper"] = 0.05
    evidence["causal_revalidated_decision_bytes"] = (
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    ).encode()
    with pytest.raises(trigger.TriggerReceiptError, match="bytes differ"):
        _build(evidence)


def test_duplicate_key_and_nonfinite_decision_fail_closed() -> None:
    duplicate = _fixture()
    duplicate["causal_original_decision_bytes"] = (
        b'{"decision":"valid_no_go","decision":"pass"}'
    )
    duplicate["causal_revalidated_decision_bytes"] = duplicate[
        "causal_original_decision_bytes"
    ]
    with pytest.raises(trigger.TriggerReceiptError, match="duplicate JSON key"):
        _build(duplicate)

    nonfinite = _fixture()
    report = json.loads(nonfinite["causal_original_decision_bytes"])
    report["aggregate"]["mean_delta"] = float("nan")
    raw = json.dumps(report, sort_keys=True).encode()
    nonfinite["causal_original_decision_bytes"] = raw
    nonfinite["causal_revalidated_decision_bytes"] = raw
    with pytest.raises(trigger.TriggerReceiptError, match="non-finite"):
        _build(nonfinite)


def test_bool_cannot_substitute_for_integer_schema_version() -> None:
    evidence = _fixture()
    plan = json.loads(evidence["terminal_verifier_execution_plan_bytes"])
    plan["schema_version"] = True
    evidence["terminal_verifier_execution_plan_bytes"] = _legacy(plan)
    with pytest.raises(trigger.TriggerReceiptError, match="schema_version"):
        _build(evidence)


def test_frozen_float_fields_reject_json_integers() -> None:
    evidence = _fixture()
    report = json.loads(evidence["causal_original_decision_bytes"])
    report["aggregate"]["ci_95_lower"] = 0
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    evidence["causal_original_decision_bytes"] = raw
    evidence["causal_revalidated_decision_bytes"] = raw
    with pytest.raises(trigger.TriggerReceiptError, match="exact finite JSON float"):
        _build(evidence)

    evidence = _fixture()
    attestation = json.loads(evidence["causal_completion_attestation_bytes"])
    attestation["stability"]["minimum_interval_seconds"] = 1
    evidence["causal_completion_attestation_bytes"] = _legacy(attestation)
    with pytest.raises(trigger.TriggerReceiptError, match="exact finite JSON float"):
        _build(evidence)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("checkout_root", "/registered/causal/other-checkout"),
        ("durable_attempt_root", "/registered/causal/other-durable/attempt-002"),
        ("artifact_root", "/registered/causal/durable/attempt-002/artifacts/other"),
        ("pid_file", "/registered/causal/durable/attempt-002/prep/other.pid"),
        ("exit_file", "/registered/causal/durable/attempt-002/prep/other.exit"),
    ),
)
def test_plan_launch_root_pid_exit_and_artifact_joins_are_exact(
    field: str, replacement: str
) -> None:
    evidence = _fixture()
    launch = json.loads(evidence["causal_launch_expectation_bytes"])
    launch[field] = replacement
    evidence["causal_launch_expectation_bytes"] = _legacy(launch)
    with pytest.raises(
        trigger.TriggerReceiptError, match="plan/launch exact join differs"
    ):
        _build(evidence)


def test_causal_inventory_cannot_escape_registered_roots() -> None:
    evidence = _fixture()
    inventory = json.loads(evidence["causal_inventory_bytes"])
    inventory.append(
        {
            "device": 7,
            "inode": 99999,
            "mtime_ns": 100,
            "path": "/etc/passwd",
            "roles": ["evaluation_code"],
            "sha256": _sha(b"outside"),
            "size_bytes": 7,
        }
    )
    inventory.sort(key=lambda row: row["path"])
    evidence["causal_inventory_bytes"] = _legacy(inventory)
    with pytest.raises(trigger.TriggerReceiptError, match="escapes the registered"):
        _build(evidence)


def test_missing_full_inventory_record_fails_closed() -> None:
    evidence = _fixture()
    inventory = json.loads(evidence["causal_inventory_bytes"])
    inventory = [
        row
        for row in inventory
        if "causal_trigger_completion_attestation" not in row["roles"]
    ]
    evidence["causal_inventory_bytes"] = _legacy(inventory)
    with pytest.raises(trigger.TriggerReceiptError, match="full causal inventory"):
        _build(evidence)


def test_non_null_online_arm_and_trigger_b_fail_closed() -> None:
    evidence = _fixture()
    _retarget_seal(
        evidence,
        lambda seal: seal.__setitem__("online_icl_decision_sha256", "2" * 64),
    )
    with pytest.raises(trigger.TriggerReceiptError, match="exactly null online"):
        _build(evidence)

    trigger_b = _fixture()
    _retarget_seal(
        trigger_b,
        lambda seal: seal.__setitem__("trigger_branch", trigger.TRIGGER_B),
    )
    with pytest.raises(trigger.TriggerReceiptError, match="Trigger B is fail-closed"):
        _build(trigger_b)


def test_validator_source_substitution_and_absence_source_forgery_fail() -> None:
    evidence = _fixture()
    evidence["trigger_receipt_revalidator_source_bytes"] = b"substituted"
    with pytest.raises(trigger.TriggerReceiptError, match="validator source differs"):
        _build(evidence)

    absence = _fixture()
    claim = json.loads(absence["pretrigger_absence_evidence_bytes"])
    claim["adapter_source_sha256"] = "3" * 64
    unsigned = {key: claim[key] for key in trigger._ABSENCE_UNSIGNED_KEYS}
    claim["absence_attestation_sha256"] = _sha(_canonical(unsigned))
    absence["pretrigger_absence_evidence_bytes"] = _canonical(claim)
    with pytest.raises(trigger.TriggerReceiptError, match="adapter source differs"):
        _build(absence)


def test_absence_must_be_complete_fresh_and_empty() -> None:
    evidence = _fixture()
    claim = json.loads(evidence["pretrigger_absence_evidence_bytes"])
    claim["forbidden_classes"] = claim["forbidden_classes"][:-1]
    unsigned = {key: claim[key] for key in trigger._ABSENCE_UNSIGNED_KEYS}
    claim["absence_attestation_sha256"] = _sha(_canonical(unsigned))
    evidence["pretrigger_absence_evidence_bytes"] = _canonical(claim)
    with pytest.raises(trigger.TriggerReceiptError, match="forbidden classes"):
        _build(evidence)

    evidence = _fixture()
    claim = json.loads(evidence["pretrigger_absence_evidence_bytes"])
    claim["forbidden_match_count"] = 1
    claim["forbidden_matches"] = ["raw_traces/existing.json"]
    unsigned = {key: claim[key] for key in trigger._ABSENCE_UNSIGNED_KEYS}
    claim["absence_attestation_sha256"] = _sha(_canonical(unsigned))
    evidence["pretrigger_absence_evidence_bytes"] = _canonical(claim)
    with pytest.raises(trigger.TriggerReceiptError, match="already exist"):
        _build(evidence)

    evidence = _fixture()
    evidence["created_at_utc"] = "2026-07-14T11:00:07Z"
    with pytest.raises(trigger.TriggerReceiptError, match="freshness join"):
        _build(evidence)

    evidence = _fixture()
    claim = json.loads(evidence["pretrigger_absence_evidence_bytes"])
    claim["checked_at_utc"] = "2026-07-14T10:58:00Z"
    unsigned = {key: claim[key] for key in trigger._ABSENCE_UNSIGNED_KEYS}
    claim["absence_attestation_sha256"] = _sha(_canonical(unsigned))
    evidence["pretrigger_absence_evidence_bytes"] = _canonical(claim)
    with pytest.raises(trigger.TriggerReceiptError, match="60 seconds old"):
        _build(evidence)


def test_absence_service_identity_uid_and_root_owner_are_frozen() -> None:
    evidence = _fixture()
    _retarget_absence(
        evidence,
        lambda claim: claim.__setitem__("service_identity", "another-service"),
    )
    with pytest.raises(trigger.TriggerReceiptError, match="service identity differs"):
        _build(evidence)

    evidence = _fixture()
    _retarget_absence(
        evidence,
        lambda claim: claim.__setitem__("service_uid", 41002),
    )
    with pytest.raises(trigger.TriggerReceiptError, match="service UID differs"):
        _build(evidence)

    evidence = _fixture()
    _retarget_absence(
        evidence,
        lambda claim: claim["filesystem_root_identity"].__setitem__("owner_uid", 41002),
    )
    with pytest.raises(
        trigger.TriggerReceiptError, match="must equal filesystem owner_uid"
    ):
        _build(evidence)


def test_real_publication_chain_absence_adapter_mode_0700_builds_receipt(
    tmp_path: Path,
) -> None:
    evidence = _fixture()
    raw = _real_adapter_absence_bytes(
        evidence, physical_root=tmp_path / "structured-trigger-root"
    )
    claim = json.loads(raw)
    assert claim["filesystem_root_identity"]["mode"] == 0o700

    receipt = json.loads(_build(evidence))
    assert (
        receipt["pretrigger_absence_evidence"]["payload"]["filesystem_root_identity"][
            "mode"
        ]
        == 0o700
    )


def test_legacy_absence_without_root_mode_is_rejected() -> None:
    evidence = _fixture()

    def remove_mode(claim: dict[str, Any]) -> None:
        del claim["filesystem_root_identity"]["mode"]

    _retarget_absence(evidence, remove_mode)
    with pytest.raises(trigger.TriggerReceiptError, match="exact-key schema differs"):
        _build(evidence)


@pytest.mark.parametrize("bad_mode", (0o755, 0o770, True))
def test_absence_root_mode_must_be_exact_integer_0700(bad_mode: object) -> None:
    evidence = _fixture()
    _retarget_absence(
        evidence,
        lambda claim: claim["filesystem_root_identity"].__setitem__("mode", bad_mode),
    )
    expected = "integer" if bad_mode is True else "exactly 0700"
    with pytest.raises(trigger.TriggerReceiptError, match=expected):
        _build(evidence)


@pytest.mark.parametrize(
    "registered_at",
    ("2026-07-14T11:00:04Z", "2026-07-14T11:00:05Z"),
)
def test_validator_inventory_must_be_strictly_earlier_than_seal(
    registered_at: str,
) -> None:
    evidence = _fixture()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    inventory["created_at_utc"] = registered_at
    unsigned = {
        key: inventory[key] for key in trigger._VALIDATOR_INVENTORY_UNSIGNED_KEYS
    }
    inventory["binding_inventory_sha256"] = _sha(_canonical(unsigned))
    evidence["trigger_validator_inventory_bytes"] = _canonical(inventory)
    with pytest.raises(trigger.TriggerReceiptError, match="strictly earlier"):
        _build(evidence)


def test_validator_inventory_genuinely_earlier_than_seal_is_accepted() -> None:
    evidence = _fixture()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    inventory["created_at_utc"] = "2026-07-14T11:00:03Z"
    unsigned = {
        key: inventory[key] for key in trigger._VALIDATOR_INVENTORY_UNSIGNED_KEYS
    }
    inventory["binding_inventory_sha256"] = _sha(_canonical(unsigned))
    evidence["trigger_validator_inventory_bytes"] = _canonical(inventory)

    receipt = json.loads(_build(evidence))
    assert (
        receipt["trigger_validator_inventory"]["payload"]["created_at_utc"]
        == "2026-07-14T11:00:03Z"
    )


def test_threshold_branch_is_independently_reconstructed() -> None:
    evidence = _fixture()
    report = json.loads(evidence["causal_original_decision_bytes"])
    report["decision"] = "pass"
    report["decision_scope"] = "internal_gate_pass"
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    evidence["causal_original_decision_bytes"] = raw
    evidence["causal_revalidated_decision_bytes"] = raw
    with pytest.raises(trigger.TriggerReceiptError, match="do not follow thresholds"):
        _build(evidence)


def test_noncanonical_seal_and_inventory_bytes_are_rejected() -> None:
    evidence = _fixture()
    seal = json.loads(evidence["trigger_execution_seal_bytes"])
    evidence["trigger_execution_seal_bytes"] = (
        json.dumps(seal, indent=2, sort_keys=True) + "\n"
    ).encode()
    with pytest.raises(trigger.TriggerReceiptError, match="canonical JSON"):
        _build(evidence)

    evidence = _fixture()
    inventory = json.loads(evidence["causal_inventory_bytes"])
    evidence["causal_inventory_bytes"] = (
        json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    ).encode()
    with pytest.raises(trigger.TriggerReceiptError, match="canonical JSON"):
        _build(evidence)


def test_validator_inventory_exact_id_set_is_closed() -> None:
    evidence = _fixture()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    inventory["bindings"] = inventory["bindings"][:-1]
    unsigned = {
        key: inventory[key] for key in trigger._VALIDATOR_INVENTORY_UNSIGNED_KEYS
    }
    inventory["binding_inventory_sha256"] = _sha(_canonical(unsigned))
    evidence["trigger_validator_inventory_bytes"] = _canonical(inventory)
    with pytest.raises(trigger.TriggerReceiptError, match="ids/order differ"):
        _build(evidence)


def test_validator_inventory_paths_are_unique_and_builder_revalidator_are_independent() -> (
    None
):
    evidence = _fixture()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    rows = inventory["bindings"]
    by_id = {row["binding_id"]: row for row in rows}
    by_id["trigger_receipt_revalidator"]["path"] = by_id["trigger_receipt_builder"][
        "path"
    ]
    with pytest.raises(trigger.TriggerReceiptError, match="paths must be unique"):
        trigger.build_trigger_validator_inventory_bytes(
            binding_records_bytes=_canonical(rows),
            tooling_source_commit=inventory["tooling_source_commit"],
            created_at_utc=inventory["created_at_utc"],
        )

    evidence = _fixture()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    rows = inventory["bindings"]
    by_id = {row["binding_id"]: row for row in rows}
    by_id["trigger_receipt_revalidator"]["sha256"] = by_id["trigger_receipt_builder"][
        "sha256"
    ]
    with pytest.raises(
        trigger.TriggerReceiptError, match="source digest must be distinct"
    ):
        trigger.build_trigger_validator_inventory_bytes(
            binding_records_bytes=_canonical(rows),
            tooling_source_commit=inventory["tooling_source_commit"],
            created_at_utc=inventory["created_at_utc"],
        )


@pytest.mark.parametrize(
    "publisher_id",
    ("structured_atomic_publisher", "trigger_receipt_publisher"),
)
def test_publisher_path_and_source_digest_cannot_reuse_another_role(
    publisher_id: str,
) -> None:
    evidence = _fixture()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    rows = inventory["bindings"]
    by_id = {row["binding_id"]: row for row in rows}
    by_id[publisher_id]["path"] = by_id["causal_completion_attester"]["path"]
    with pytest.raises(trigger.TriggerReceiptError, match="paths must be unique"):
        trigger.build_trigger_validator_inventory_bytes(
            binding_records_bytes=_canonical(rows),
            tooling_source_commit=inventory["tooling_source_commit"],
            created_at_utc=inventory["created_at_utc"],
        )

    evidence = _fixture()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    rows = inventory["bindings"]
    by_id = {row["binding_id"]: row for row in rows}
    by_id[publisher_id]["sha256"] = by_id["causal_completion_attester"]["sha256"]
    with pytest.raises(trigger.TriggerReceiptError, match="must not be reused"):
        trigger.build_trigger_validator_inventory_bytes(
            binding_records_bytes=_canonical(rows),
            tooling_source_commit=inventory["tooling_source_commit"],
            created_at_utc=inventory["created_at_utc"],
        )
