#!/usr/bin/env python3
"""Build the preregistered structured-state conditional execution seal.

The builder is intentionally downstream of the causal completion attester and
independent revalidator.  It accepts only a prospectively registered terminal
verifier execution plan, re-hashes the complete attested pre-attestation
inventory immediately before publication, and can currently emit Trigger A
only.  Trigger B remains fail-closed until a separate prospective online-ICL
plan extension exists before that experiment's first model call.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable


PLAN_PROTOCOL = "cohort_causal_terminal_verifier_execution_plan_v1"
PLAN_SCHEMA_VERSION = 1
PLAN_FILENAME = "CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN.json"
LAUNCH_EXPECTATION_FILENAME = "CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json"
PLAN_STATUS = "registered"
ATTESTATION_PROTOCOL = "cohort_causal_terminal_completion_attestation_v1"
CAUSAL_PROTOCOL = "cohort_qonly_frozen_tape_weight_update_ablation_v1"
CAUSAL_EXPERIMENT = "cohort_qonly_frozen_tape_causal_formal"
LAUNCH_EXPECTATION_PROTOCOL = "cohort_causal_formal_launch_expectation_v1"
SEAL_PROTOCOL = "cohort_closed_loop_structured_state_trigger_execution_seal_v1"
SEAL_SCHEMA_VERSION = 1
STRUCTURED_PREREGISTRATION_FILENAME = (
    "COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md"
)
CAUSAL_PREREGISTRATION_FILENAME = "COHORT_QONLY_CAUSAL_PREREG.md"
CAUSAL_STATISTICAL_ADDENDUM_FILENAME = (
    "COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md"
)
ATTESTATION_FILENAME = "causal_trigger_completion_attestation.json"
REVALIDATED_FILENAME = "causal_formal.revalidated.json"
REVALIDATION_RECEIPT_FILENAME = "causal_formal.revalidation_receipt.json"
SEAL_FILENAME = "cohort_closed_loop_structured_state.execution_seal.json"
EXPECTED_PYTHON_PATH = "/usr/bin/python3.10"
EXPECTED_PYTHON_VERSION = "3.10.12"
CAUSAL_PROTOCOL_SEAL_STATUS = (
    "not_applicable_existing_implementation_has_none"
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")

PLAN_KEYS = frozenset(
    {
        "attempt_id",
        "causal_protocol_seal_sha256",
        "causal_protocol_seal_status",
        "causal_checkout_root",
        "created_at_utc",
        "durable_attempt_root",
        "invocations",
        "launch_expectation",
        "online_icl",
        "protocol",
        "runtime",
        "schema_version",
        "status",
        "structured_preregistration",
        "tooling_source_commit",
        "tooling_root",
        "tools",
    }
)
PLAN_BINDING_KEYS = frozenset({"path", "sha256"})
PLAN_RUNTIME_KEYS = frozenset({"python_path", "python_version"})
PLAN_TOOL_NAMES = frozenset(
    {"attester", "revalidator", "execution_seal_builder"}
)
PLAN_INVOCATION_KEYS = frozenset({"argv", "inputs", "outputs", "parameters"})
PLAN_INVOCATION_NAMES = PLAN_TOOL_NAMES

ATTESTATION_KEYS = frozenset(
    {
        "causal_pre_attestation_inventory_sha256",
        "completed_at_utc",
        "execution_plan_path",
        "execution_plan_sha256",
        "expected_launcher",
        "no_live_or_temporary",
        "pid_exit",
        "process_absence",
        "protocol",
        "registered_counts",
        "schema_version",
        "snapshots",
        "stability",
        "status",
    }
)
EXPECTED_LAUNCHER_KEYS = frozenset(
    {
        "formal_grid_file_sha256",
        "launch_expectation_path",
        "launch_expectation_sha256",
        "launcher_file_sha256",
        "provenance_file_sha256",
        "source_commit",
        "wrapper_cmdline_sha256_at_registration",
    }
)
REGISTERED_COUNTS_KEYS = frozenset(
    {
        "cell_final_traces",
        "cell_manifests",
        "collector_final_traces",
        "collector_manifests",
        "formal_decisions",
        "formal_manifests",
        "sealed_cell_log_receipts",
        "sealed_cell_log_start_receipts",
        "sealed_cell_logs",
        "tapes",
        "total",
    }
)
EXPECTED_REGISTERED_COUNTS = {
    "cell_final_traces": 6,
    "cell_manifests": 6,
    "collector_final_traces": 3,
    "collector_manifests": 3,
    "formal_decisions": 1,
    "formal_manifests": 1,
    "sealed_cell_log_receipts": 9,
    "sealed_cell_log_start_receipts": 9,
    "sealed_cell_logs": 9,
    "tapes": 3,
    "total": 50,
}
PID_EXIT_KEYS = frozenset(
    {
        "exit_after_outputs_status",
        "exit_file_mtime_ns",
        "exit_file_path",
        "exit_file_sha256",
        "exit_file_size_bytes",
        "exit_zero_status",
        "pid_ascii_status",
        "pid_file_mtime_ns",
        "pid_file_path",
        "pid_file_sha256",
        "pid_file_size_bytes",
        "pid_liveness_status",
    }
)
STABILITY_KEYS = frozenset(
    {"minimum_interval_seconds", "observed_interval_seconds", "snapshots_identical"}
)
SNAPSHOT_KEYS = frozenset(
    {"captured_at_utc", "file_count", "files", "inventory_sha256", "sequence"}
)
FILE_RECORD_KEYS = frozenset(
    {"device", "inode", "mtime_ns", "path", "roles", "sha256", "size_bytes"}
)
PROCESS_ABSENCE_KEYS = frozenset(
    {"artifact_root_path", "attempt_checkout_path", "audit_sha256", "method", "status"}
)
NO_LIVE_OR_TEMPORARY_KEYS = frozenset(
    {"audit_sha256", "forbidden_match_count", "roots", "status"}
)
LAUNCH_EXPECTATION_KEYS = frozenset(
    {
        "artifact_root",
        "attempt_id",
        "boot_id",
        "checkout_root",
        "collector_gpus",
        "created_at_utc",
        "durable_attempt_root",
        "eval_gpus",
        "exit_file",
        "expected_final_inventory",
        "formal_grid_file_sha256",
        "launch_mode",
        "launcher_file_sha256",
        "max_used_memory_mib",
        "node_hostname",
        "pid_file",
        "pid_file_sha256_at_registration",
        "protocol",
        "provenance_file_sha256",
        "schema_version",
        "source_commit",
        "wrapper_cmdline_sha256_at_registration",
        "wrapper_pid",
        "wrapper_start_ticks",
    }
)
CAUSAL_DECISION_KEYS = frozenset(
    {
        "aggregate",
        "bootstrap",
        "decision",
        "decision_scope",
        "errors",
        "experiment",
        "limitation",
        "mechanism_label",
        "pairs",
        "preregistered_thresholds",
        "protocol",
        "publication_inference",
        "publication_grade",
        "schema_version",
        "status",
        "threshold_checks",
    }
)
REVALIDATION_RECEIPT_KEYS = frozenset(
    {
        "decision",
        "decision_scope",
        "execution_plan_path",
        "execution_plan_sha256",
        "formal_decision_file_sha256",
        "formal_manifest_file_sha256",
        "status",
    }
)
BINDING_RECORD_KEYS = frozenset({"path", "sha256", "size_bytes"})

_INVOCATION_SCHEMAS: dict[str, tuple[frozenset[str], frozenset[str], frozenset[str]]] = {
    "attester": (
        frozenset(
            {
                "execution_plan",
                "launch_expectation",
                "provenance",
                "provenance_details",
                "root",
            }
        ),
        frozenset({"attestation"}),
        frozenset({"stability_seconds"}),
    ),
    "revalidator": (
        frozenset(
            {
                "attestation",
                "execution_plan",
                "formal_decision",
                "formal_manifest",
                "grid",
                "launch_expectation",
                "preregistration",
                "provenance",
                "root",
                "statistical_addendum",
            }
        ),
        frozenset({"revalidated_decision", "revalidation_receipt"}),
        frozenset(),
    ),
    "execution_seal_builder": (
        frozenset(
            {
                "attestation",
                "causal_original",
                "causal_revalidated",
                "execution_plan",
                "launch_expectation",
                "revalidation_receipt",
                "structured_preregistration",
            }
        ),
        frozenset({"execution_seal"}),
        frozenset(),
    ),
}


class ExecutionSealError(RuntimeError):
    """A fail-closed trigger or execution-seal validation failure."""


class DuplicateKeyError(ValueError):
    """A JSON object contained a duplicate key."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _pretty_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _load_json_bytes(payload: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        raise ExecutionSealError(f"strict JSON load failed for {label}: {exc}") from exc


def _expect_exact_keys(value: Any, keys: frozenset[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise ExecutionSealError(
            f"{label} exact-key schema differs; expected {sorted(keys)!r}, "
            f"observed {observed!r}"
        )
    return value


def _normalized_absolute(path: Path | str, *, label: str) -> Path:
    candidate = Path(path).expanduser()
    text = os.fspath(candidate)
    if (
        not candidate.is_absolute()
        or ".." in candidate.parts
        or os.path.normpath(text) != text
    ):
        raise ExecutionSealError(f"{label} must be a normalized absolute path")
    return candidate


def _assert_real_directory(path: Path, *, label: str) -> None:
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise ExecutionSealError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise ExecutionSealError(f"{label} must be a real directory, not a symlink")


def _read_stable_file(path: Path, *, label: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ExecutionSealError(f"cannot open {label}: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ExecutionSealError(f"{label} is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after:
        raise ExecutionSealError(f"{label} changed while reading: {path}")
    try:
        pathname = os.lstat(path)
    except OSError as exc:
        raise ExecutionSealError(f"{label} pathname changed while reading: {path}") from exc
    if stat.S_ISLNK(pathname.st_mode) or (
        pathname.st_dev,
        pathname.st_ino,
        pathname.st_size,
        pathname.st_mtime_ns,
    ) != identity_after:
        raise ExecutionSealError(f"{label} pathname changed while reading: {path}")
    return b"".join(chunks), after


def _binding_record(path: Path, *, label: str) -> dict[str, Any]:
    payload, metadata = _read_stable_file(path, label=label)
    return {
        "path": path.as_posix(),
        "sha256": _sha256(payload),
        "size_bytes": metadata.st_size,
    }


def _full_file_record(path: Path, roles: Sequence[str], *, label: str) -> dict[str, Any]:
    payload, metadata = _read_stable_file(path, label=label)
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mtime_ns": metadata.st_mtime_ns,
        "path": path.as_posix(),
        "roles": sorted(set(roles)),
        "sha256": _sha256(payload),
        "size_bytes": metadata.st_size,
    }


def _validate_plan_binding(value: Any, *, label: str) -> dict[str, Any]:
    binding = _expect_exact_keys(value, PLAN_BINDING_KEYS, label=label)
    binding["path"] = _normalized_absolute(binding["path"], label=f"{label}.path").as_posix()
    if not _is_sha256(binding["sha256"]):
        raise ExecutionSealError(f"{label}.sha256 must be lowercase SHA-256")
    return binding


def _validate_path_map(value: Any, keys: frozenset[str], *, label: str) -> dict[str, str]:
    mapping = _expect_exact_keys(value, keys, label=label)
    normalized: dict[str, str] = {}
    for key, item in mapping.items():
        normalized[key] = _normalized_absolute(
            item, label=f"{label}.{key}"
        ).as_posix()
    return normalized


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
            invocation["parameters"]["stability_seconds"],
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
    if stage == "execution_seal_builder":
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
    raise ExecutionSealError(f"unknown execution-plan stage: {stage}")


def _default_invocation_argv(stage_tool_path: str) -> list[str]:
    executable = Path(sys.executable).resolve().as_posix()
    invoked = _normalized_absolute(Path(sys.argv[0]).absolute(), label="invoked tool path")
    if invoked.as_posix() != stage_tool_path:
        raise ExecutionSealError("invoked tool path differs from execution plan")
    return [executable, invoked.as_posix(), *sys.argv[1:]]


def _runtime_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def make_execution_plan(
    *,
    tooling_source_commit: str,
    causal_checkout_root: Path,
    durable_attempt_root: Path,
    created_at_utc: str,
) -> dict[str, Any]:
    """Build the deterministic prospective plan object without publishing it.

    The caller first deploys the three verifier files and this preregistration
    into the fixed tooling root.  This helper reads and hashes those exact
    bytes plus the fixed launch expectation, and emits all three future argv
    vectors and their closed input/output topology.  Publication remains a
    separate canonical O_EXCL/no-overwrite operation.
    """

    if _COMMIT_RE.fullmatch(tooling_source_commit) is None:
        raise ExecutionSealError("tooling_source_commit must be a 40-hex commit")
    if not isinstance(created_at_utc, str) or not created_at_utc.endswith("Z"):
        raise ExecutionSealError("execution plan creation time must be UTC Z text")
    causal_root = _normalized_absolute(
        causal_checkout_root, label="causal checkout root"
    )
    durable_root = _normalized_absolute(
        durable_attempt_root, label="durable attempt root"
    )
    control = durable_root / "control"
    tooling_root = control / "verifier" / tooling_source_commit
    prep = durable_root / "prep"
    artifact_root = durable_root / "artifacts" / "cohort_causal"
    for directory, label in (
        (causal_root, "causal checkout root"),
        (durable_root, "durable attempt root"),
        (control, "durable control root"),
        (control / "verifier", "durable verifier root"),
        (tooling_root, "tooling root"),
        (prep, "durable prep root"),
        (artifact_root, "causal artifact root"),
    ):
        _assert_real_directory(directory, label=label)
    if durable_root.name != "attempt-002":
        raise ExecutionSealError("execution plan is fixed to attempt-002")

    plan_path = control / PLAN_FILENAME
    expectation_path = control / LAUNCH_EXPECTATION_FILENAME
    structured_preregistration = tooling_root / STRUCTURED_PREREGISTRATION_FILENAME
    expectation_raw, _ = _read_stable_file(
        expectation_path, label="plan launch expectation"
    )
    expectation = _validate_launch_expectation(
        _load_json_bytes(expectation_raw, label="plan launch expectation")
    )
    if (
        expectation["attempt_id"] != durable_root.name
        or expectation["checkout_root"] != causal_root.as_posix()
        or expectation["durable_attempt_root"] != durable_root.as_posix()
        or expectation["artifact_root"] != artifact_root.as_posix()
    ):
        raise ExecutionSealError("launch expectation roots differ from plan arguments")

    tool_paths = {
        "attester": tooling_root / "attest_cohort_causal_completion.py",
        "revalidator": tooling_root / "revalidate_cohort_causal_terminal.py",
        "execution_seal_builder": tooling_root
        / "build_cohort_structured_state_execution_seal.py",
    }
    tools = {
        name: {
            "path": path.as_posix(),
            "sha256": _binding_record(path, label=f"deployed plan tool {name}")[
                "sha256"
            ],
        }
        for name, path in sorted(tool_paths.items())
    }
    preregistration_record = _binding_record(
        structured_preregistration,
        label="deployed structured preregistration",
    )
    attestation = prep / ATTESTATION_FILENAME
    revalidated = prep / REVALIDATED_FILENAME
    receipt = prep / REVALIDATION_RECEIPT_FILENAME
    execution_seal = prep / SEAL_FILENAME
    provenance = artifact_root / "provenance.json"
    provenance_details = artifact_root / "provenance.details.json"
    formal_manifest = artifact_root / "formal_manifest.json"
    formal_decision = artifact_root / "formal_decision.json"
    plan: dict[str, Any] = {
        "attempt_id": durable_root.name,
        "causal_checkout_root": causal_root.as_posix(),
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": CAUSAL_PROTOCOL_SEAL_STATUS,
        "created_at_utc": created_at_utc,
        "durable_attempt_root": durable_root.as_posix(),
        "invocations": {
            "attester": {
                "argv": [],
                "inputs": {
                    "execution_plan": plan_path.as_posix(),
                    "launch_expectation": expectation_path.as_posix(),
                    "provenance": provenance.as_posix(),
                    "provenance_details": provenance_details.as_posix(),
                    "root": causal_root.as_posix(),
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
                    "grid": (causal_root / "grid_cohort_causal_formal.json").as_posix(),
                    "launch_expectation": expectation_path.as_posix(),
                    "preregistration": (
                        causal_root / CAUSAL_PREREGISTRATION_FILENAME
                    ).as_posix(),
                    "provenance": provenance.as_posix(),
                    "root": causal_root.as_posix(),
                    "statistical_addendum": (
                        causal_root / CAUSAL_STATISTICAL_ADDENDUM_FILENAME
                    ).as_posix(),
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
                    "launch_expectation": expectation_path.as_posix(),
                    "revalidation_receipt": receipt.as_posix(),
                    "structured_preregistration": structured_preregistration.as_posix(),
                },
                "outputs": {"execution_seal": execution_seal.as_posix()},
                "parameters": {},
            },
        },
        "launch_expectation": {
            "path": expectation_path.as_posix(),
            "sha256": _sha256(expectation_raw),
        },
        "online_icl": None,
        "protocol": PLAN_PROTOCOL,
        "runtime": {
            "python_path": EXPECTED_PYTHON_PATH,
            "python_version": EXPECTED_PYTHON_VERSION,
        },
        "schema_version": PLAN_SCHEMA_VERSION,
        "status": PLAN_STATUS,
        "structured_preregistration": {
            "path": structured_preregistration.as_posix(),
            "sha256": preregistration_record["sha256"],
        },
        "tooling_root": tooling_root.as_posix(),
        "tooling_source_commit": tooling_source_commit,
        "tools": tools,
    }
    for stage in sorted(PLAN_INVOCATION_NAMES):
        plan["invocations"][stage]["argv"] = _expected_argv(plan, stage)
    if set(plan) != PLAN_KEYS:
        raise AssertionError("generated execution-plan schema drift")
    return plan


def load_and_validate_execution_plan_stage(
    *,
    execution_plan_path: Path,
    stage: str,
    expected_inputs: Mapping[str, str | Path],
    expected_outputs: Mapping[str, str | Path],
    expected_parameters: Mapping[str, str] | None = None,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Strictly validate the prospective plan and one stage invocation.

    Runtime and argv overrides exist solely for hermetic focused tests.  CLI
    callers use the real interpreter, version, and argv.
    """

    if stage not in PLAN_TOOL_NAMES:
        raise ExecutionSealError(f"unknown execution-plan stage: {stage}")
    execution_plan_path = _normalized_absolute(
        execution_plan_path, label="execution plan path"
    )
    payload, _ = _read_stable_file(execution_plan_path, label="execution plan")
    plan = _expect_exact_keys(
        _load_json_bytes(payload, label="execution plan"), PLAN_KEYS, label="execution plan"
    )
    if payload != _canonical_bytes(plan):
        raise ExecutionSealError("execution plan is not canonical JSON bytes")
    if (
        plan["protocol"] != PLAN_PROTOCOL
        or plan["schema_version"] != PLAN_SCHEMA_VERSION
        or plan["status"] != PLAN_STATUS
    ):
        raise ExecutionSealError("execution plan protocol, schema, or status differs")
    if not isinstance(plan["created_at_utc"], str) or not plan["created_at_utc"].endswith("Z"):
        raise ExecutionSealError("execution plan creation time is invalid")
    if not isinstance(plan["attempt_id"], str) or not plan["attempt_id"]:
        raise ExecutionSealError("execution plan attempt_id is invalid")
    causal_checkout_root = _normalized_absolute(
        plan["causal_checkout_root"], label="plan causal_checkout_root"
    )
    durable_root = _normalized_absolute(
        plan["durable_attempt_root"], label="plan durable_attempt_root"
    )
    tooling_root = _normalized_absolute(plan["tooling_root"], label="plan tooling_root")
    plan["causal_checkout_root"] = causal_checkout_root.as_posix()
    plan["durable_attempt_root"] = durable_root.as_posix()
    plan["tooling_root"] = tooling_root.as_posix()
    for directory, label in (
        (causal_checkout_root, "causal checkout root"),
        (durable_root, "durable attempt root"),
        (durable_root / "control", "durable control root"),
        (durable_root / "control" / "verifier", "durable verifier root"),
        (tooling_root, "tooling root"),
    ):
        _assert_real_directory(directory, label=label)
    if _COMMIT_RE.fullmatch(plan["tooling_source_commit"] or "") is None:
        raise ExecutionSealError("execution plan tooling_source_commit is invalid")
    if plan["causal_protocol_seal_sha256"] is not None or plan[
        "causal_protocol_seal_status"
    ] != CAUSAL_PROTOCOL_SEAL_STATUS:
        raise ExecutionSealError("execution plan invents a causal protocol seal")
    if plan["online_icl"] is not None:
        raise ExecutionSealError(
            "plan v1 must keep online_icl null; Trigger B needs a prospective extension"
        )
    launch_binding = _validate_plan_binding(
        plan["launch_expectation"], label="plan.launch_expectation"
    )
    prereg_binding = _validate_plan_binding(
        plan["structured_preregistration"], label="plan.structured_preregistration"
    )
    expected_tooling_root = (
        durable_root / "control" / "verifier" / plan["tooling_source_commit"]
    )
    if tooling_root != expected_tooling_root:
        raise ExecutionSealError("tooling_root is not suffixed by tooling_source_commit")
    if execution_plan_path != durable_root / "control" / PLAN_FILENAME:
        raise ExecutionSealError("execution plan path differs from fixed durable/control path")
    if launch_binding["path"] != (
        durable_root / "control" / LAUNCH_EXPECTATION_FILENAME
    ).as_posix():
        raise ExecutionSealError("launch expectation path is not fixed")
    if prereg_binding["path"] != (
        tooling_root / STRUCTURED_PREREGISTRATION_FILENAME
    ).as_posix():
        raise ExecutionSealError("structured preregistration path is not fixed")

    runtime = _expect_exact_keys(plan["runtime"], PLAN_RUNTIME_KEYS, label="plan.runtime")
    if runtime != {
        "python_path": EXPECTED_PYTHON_PATH,
        "python_version": EXPECTED_PYTHON_VERSION,
    }:
        raise ExecutionSealError("execution plan runtime is not Python 3.10.12")
    tools = _expect_exact_keys(plan["tools"], PLAN_TOOL_NAMES, label="plan.tools")
    fixed_tool_paths = {
        "attester": tooling_root / "attest_cohort_causal_completion.py",
        "revalidator": tooling_root / "revalidate_cohort_causal_terminal.py",
        "execution_seal_builder": tooling_root
        / "build_cohort_structured_state_execution_seal.py",
    }
    for name in sorted(PLAN_TOOL_NAMES):
        binding = _validate_plan_binding(tools[name], label=f"plan.tools.{name}")
        if binding["path"] != fixed_tool_paths[name].as_posix():
            raise ExecutionSealError(f"plan tool path is not fixed: {name}")
        record = _binding_record(Path(binding["path"]), label=f"plan tool {name}")
        if record["sha256"] != binding["sha256"]:
            raise ExecutionSealError(f"plan tool digest differs: {name}")

    launch_record = _binding_record(
        Path(launch_binding["path"]), label="plan-bound launch expectation"
    )
    if launch_record["sha256"] != launch_binding["sha256"]:
        raise ExecutionSealError("plan launch-expectation target digest differs")
    prereg_record = _binding_record(
        Path(prereg_binding["path"]), label="plan-bound structured preregistration"
    )
    if prereg_record["sha256"] != prereg_binding["sha256"]:
        raise ExecutionSealError("plan structured-preregistration digest differs")

    invocations = _expect_exact_keys(
        plan["invocations"], PLAN_INVOCATION_NAMES, label="plan.invocations"
    )
    for name in sorted(PLAN_INVOCATION_NAMES):
        invocation = _expect_exact_keys(
            invocations[name], PLAN_INVOCATION_KEYS, label=f"plan.invocations.{name}"
        )
        input_keys, output_keys, parameter_keys = _INVOCATION_SCHEMAS[name]
        invocation["inputs"] = _validate_path_map(
            invocation["inputs"], input_keys, label=f"plan.invocations.{name}.inputs"
        )
        invocation["outputs"] = _validate_path_map(
            invocation["outputs"], output_keys, label=f"plan.invocations.{name}.outputs"
        )
        parameters = _expect_exact_keys(
            invocation["parameters"], parameter_keys, label=f"plan.invocations.{name}.parameters"
        )
        if any(not isinstance(value, str) or not value for value in parameters.values()):
            raise ExecutionSealError(f"plan invocation parameters are invalid: {name}")
        if name == "attester" and parameters != {"stability_seconds": "1.0"}:
            raise ExecutionSealError("attester stability interval must be exact 1.0")
        argv = invocation["argv"]
        if (
            not isinstance(argv, list)
            or any(not isinstance(item, str) or not item for item in argv)
            or argv != _expected_argv(plan, name)
        ):
            raise ExecutionSealError(f"plan invocation argv differs: {name}")

    prep = durable_root / "prep"
    artifact_root = durable_root / "artifacts" / "cohort_causal"
    if durable_root.name != plan["attempt_id"]:
        raise ExecutionSealError("durable attempt root does not match plan attempt_id")
    attester_inputs = invocations["attester"]["inputs"]
    attester_outputs = invocations["attester"]["outputs"]
    revalidator_inputs = invocations["revalidator"]["inputs"]
    revalidator_outputs = invocations["revalidator"]["outputs"]
    builder_inputs = invocations["execution_seal_builder"]["inputs"]
    builder_outputs = invocations["execution_seal_builder"]["outputs"]
    fixed_topology = {
        "attester execution plan": attester_inputs["execution_plan"],
        "revalidator execution plan": revalidator_inputs["execution_plan"],
        "builder execution plan": builder_inputs["execution_plan"],
        "attester root": attester_inputs["root"],
        "revalidator root": revalidator_inputs["root"],
        "attester launch expectation": attester_inputs["launch_expectation"],
        "revalidator launch expectation": revalidator_inputs["launch_expectation"],
        "builder launch expectation": builder_inputs["launch_expectation"],
        "attester output": attester_outputs["attestation"],
        "revalidator attestation": revalidator_inputs["attestation"],
        "builder attestation": builder_inputs["attestation"],
        "attester provenance": attester_inputs["provenance"],
        "attester provenance details": attester_inputs["provenance_details"],
        "revalidator provenance": revalidator_inputs["provenance"],
        "revalidator grid": revalidator_inputs["grid"],
        "revalidator formal manifest": revalidator_inputs["formal_manifest"],
        "revalidator formal decision": revalidator_inputs["formal_decision"],
        "builder causal original": builder_inputs["causal_original"],
        "revalidator preregistration": revalidator_inputs["preregistration"],
        "revalidator statistical addendum": revalidator_inputs[
            "statistical_addendum"
        ],
        "revalidator output": revalidator_outputs["revalidated_decision"],
        "builder causal revalidated": builder_inputs["causal_revalidated"],
        "revalidation receipt output": revalidator_outputs[
            "revalidation_receipt"
        ],
        "builder revalidation receipt": builder_inputs["revalidation_receipt"],
        "builder structured preregistration": builder_inputs[
            "structured_preregistration"
        ],
        "builder output": builder_outputs["execution_seal"],
    }
    expected_topology = {
        "attester execution plan": execution_plan_path.as_posix(),
        "revalidator execution plan": execution_plan_path.as_posix(),
        "builder execution plan": execution_plan_path.as_posix(),
        "attester root": causal_checkout_root.as_posix(),
        "revalidator root": causal_checkout_root.as_posix(),
        "attester launch expectation": launch_binding["path"],
        "revalidator launch expectation": launch_binding["path"],
        "builder launch expectation": launch_binding["path"],
        "attester output": (prep / ATTESTATION_FILENAME).as_posix(),
        "revalidator attestation": (prep / ATTESTATION_FILENAME).as_posix(),
        "builder attestation": (prep / ATTESTATION_FILENAME).as_posix(),
        "attester provenance": (artifact_root / "provenance.json").as_posix(),
        "attester provenance details": (
            artifact_root / "provenance.details.json"
        ).as_posix(),
        "revalidator provenance": (artifact_root / "provenance.json").as_posix(),
        "revalidator grid": (
            causal_checkout_root / "grid_cohort_causal_formal.json"
        ).as_posix(),
        "revalidator formal manifest": (
            artifact_root / "formal_manifest.json"
        ).as_posix(),
        "revalidator formal decision": (
            artifact_root / "formal_decision.json"
        ).as_posix(),
        "builder causal original": (
            artifact_root / "formal_decision.json"
        ).as_posix(),
        "revalidator preregistration": (
            causal_checkout_root / CAUSAL_PREREGISTRATION_FILENAME
        ).as_posix(),
        "revalidator statistical addendum": (
            causal_checkout_root / CAUSAL_STATISTICAL_ADDENDUM_FILENAME
        ).as_posix(),
        "revalidator output": (prep / REVALIDATED_FILENAME).as_posix(),
        "builder causal revalidated": (prep / REVALIDATED_FILENAME).as_posix(),
        "revalidation receipt output": (
            prep / REVALIDATION_RECEIPT_FILENAME
        ).as_posix(),
        "builder revalidation receipt": (
            prep / REVALIDATION_RECEIPT_FILENAME
        ).as_posix(),
        "builder structured preregistration": prereg_binding["path"],
        "builder output": (prep / SEAL_FILENAME).as_posix(),
    }
    if fixed_topology != expected_topology:
        raise ExecutionSealError("execution plan fixed path topology differs")
    plan_inputs = plan["invocations"][stage]["inputs"]
    plan_outputs = plan["invocations"][stage]["outputs"]
    normalized_inputs = {
        key: _normalized_absolute(value, label=f"expected {stage} input {key}").as_posix()
        for key, value in expected_inputs.items()
    }
    normalized_outputs = {
        key: _normalized_absolute(value, label=f"expected {stage} output {key}").as_posix()
        for key, value in expected_outputs.items()
    }
    if normalized_inputs != plan_inputs or normalized_outputs != plan_outputs:
        raise ExecutionSealError(f"current {stage} inputs/outputs differ from execution plan")
    normalized_parameters = dict(expected_parameters or {})
    if normalized_parameters != plan["invocations"][stage]["parameters"]:
        raise ExecutionSealError(f"current {stage} parameters differ from execution plan")

    current_runtime_path = (
        Path(runtime_python_path).as_posix()
        if runtime_python_path is not None
        else Path(sys.executable).resolve().as_posix()
    )
    current_runtime_version = (
        runtime_python_version
        if runtime_python_version is not None
        else _runtime_version()
    )
    if current_runtime_path != runtime["python_path"] or current_runtime_version != runtime[
        "python_version"
    ]:
        raise ExecutionSealError("current Python runtime differs from execution plan")
    observed_argv = (
        list(actual_argv)
        if actual_argv is not None
        else _default_invocation_argv(plan["tools"][stage]["path"])
    )
    if observed_argv != plan["invocations"][stage]["argv"]:
        raise ExecutionSealError(f"current {stage} argv differs from execution plan")
    return plan, payload


def _validate_launch_expectation(value: Any) -> dict[str, Any]:
    expectation = _expect_exact_keys(
        value, LAUNCH_EXPECTATION_KEYS, label="launch expectation"
    )
    if (
        expectation["protocol"] != LAUNCH_EXPECTATION_PROTOCOL
        or expectation["schema_version"] != 1
        or expectation["launch_mode"] != "formal"
        or expectation["expected_final_inventory"] != EXPECTED_REGISTERED_COUNTS
    ):
        raise ExecutionSealError("launch expectation protocol or formal counts differ")
    for key in (
        "formal_grid_file_sha256",
        "launcher_file_sha256",
        "pid_file_sha256_at_registration",
        "provenance_file_sha256",
        "wrapper_cmdline_sha256_at_registration",
    ):
        if not _is_sha256(expectation[key]):
            raise ExecutionSealError(f"launch expectation digest is invalid: {key}")
    if _COMMIT_RE.fullmatch(expectation["source_commit"] or "") is None:
        raise ExecutionSealError("launch expectation source_commit is invalid")
    for key in (
        "artifact_root",
        "checkout_root",
        "durable_attempt_root",
        "exit_file",
        "pid_file",
    ):
        expectation[key] = _normalized_absolute(
            expectation[key], label=f"launch expectation {key}"
        ).as_posix()
    return expectation


def _validate_file_record(value: Any, *, label: str) -> dict[str, Any]:
    record = _expect_exact_keys(value, FILE_RECORD_KEYS, label=label)
    record["path"] = _normalized_absolute(record["path"], label=f"{label}.path").as_posix()
    roles = record["roles"]
    if (
        not isinstance(roles, list)
        or not roles
        or any(not isinstance(role, str) or not role for role in roles)
        or roles != sorted(set(roles))
    ):
        raise ExecutionSealError(f"{label}.roles must be sorted unique strings")
    for key in ("device", "inode", "mtime_ns", "size_bytes"):
        if not _is_int(record[key]) or record[key] < 0:
            raise ExecutionSealError(f"{label}.{key} is invalid")
    if not _is_sha256(record["sha256"]):
        raise ExecutionSealError(f"{label}.sha256 is invalid")
    return record


def _validate_snapshot(value: Any, *, sequence: int) -> dict[str, Any]:
    snapshot = _expect_exact_keys(value, SNAPSHOT_KEYS, label=f"snapshot[{sequence}]")
    if snapshot["sequence"] != sequence:
        raise ExecutionSealError("attestation snapshot sequence differs")
    if not isinstance(snapshot["captured_at_utc"], str) or not snapshot[
        "captured_at_utc"
    ]:
        raise ExecutionSealError("attestation snapshot time is invalid")
    files = snapshot["files"]
    if not isinstance(files, list) or not files:
        raise ExecutionSealError("attestation snapshot files are missing")
    validated = [
        _validate_file_record(item, label=f"snapshot[{sequence}].files[{position}]")
        for position, item in enumerate(files)
    ]
    paths = [item["path"] for item in validated]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ExecutionSealError("attestation snapshot paths are not sorted unique")
    if snapshot["file_count"] != len(validated):
        raise ExecutionSealError("attestation snapshot file_count differs")
    digest = _sha256(_canonical_bytes(validated))
    if snapshot["inventory_sha256"] != digest:
        raise ExecutionSealError("attestation snapshot inventory digest differs")
    return snapshot


def _validate_audit(value: Any, keys: frozenset[str], *, label: str) -> dict[str, Any]:
    audit = _expect_exact_keys(value, keys, label=label)
    payload = {key: audit[key] for key in audit if key != "audit_sha256"}
    if audit.get("status") != "pass" or audit.get("audit_sha256") != _sha256(
        _canonical_bytes(payload)
    ):
        raise ExecutionSealError(f"{label} is not a valid pass audit")
    return audit


def _validate_attestation(
    value: Any,
    *,
    execution_plan_path: Path,
    execution_plan_sha256: str,
    expectation: dict[str, Any],
    launch_expectation_path: Path,
    launch_expectation_sha256: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    attestation = _expect_exact_keys(value, ATTESTATION_KEYS, label="completion attestation")
    if (
        attestation["protocol"] != ATTESTATION_PROTOCOL
        or attestation["schema_version"] != 1
        or attestation["status"] != "complete"
    ):
        raise ExecutionSealError("completion attestation is not terminal-complete")
    if (
        attestation["execution_plan_path"] != execution_plan_path.as_posix()
        or attestation["execution_plan_sha256"] != execution_plan_sha256
    ):
        raise ExecutionSealError("completion attestation execution-plan binding differs")
    if attestation["registered_counts"] != EXPECTED_REGISTERED_COUNTS:
        raise ExecutionSealError("completion attestation formal counts differ")
    expected_launcher = _expect_exact_keys(
        attestation["expected_launcher"], EXPECTED_LAUNCHER_KEYS, label="expected launcher"
    )
    expected_binding = {
        "formal_grid_file_sha256": expectation["formal_grid_file_sha256"],
        "launch_expectation_path": launch_expectation_path.as_posix(),
        "launch_expectation_sha256": launch_expectation_sha256,
        "launcher_file_sha256": expectation["launcher_file_sha256"],
        "provenance_file_sha256": expectation["provenance_file_sha256"],
        "source_commit": expectation["source_commit"],
        "wrapper_cmdline_sha256_at_registration": expectation[
            "wrapper_cmdline_sha256_at_registration"
        ],
    }
    if expected_launcher != expected_binding:
        raise ExecutionSealError("completion attestation launcher binding differs")
    if attestation["registered_counts"] != _expect_exact_keys(
        attestation["registered_counts"], REGISTERED_COUNTS_KEYS, label="registered counts"
    ):
        raise AssertionError("unreachable registered-count normalization")

    pid_exit = _expect_exact_keys(attestation["pid_exit"], PID_EXIT_KEYS, label="pid_exit")
    if {
        "exit_after_outputs_status": pid_exit["exit_after_outputs_status"],
        "exit_zero_status": pid_exit["exit_zero_status"],
        "pid_ascii_status": pid_exit["pid_ascii_status"],
        "pid_liveness_status": pid_exit["pid_liveness_status"],
    } != {
        "exit_after_outputs_status": "pass",
        "exit_zero_status": "pass",
        "pid_ascii_status": "pass",
        "pid_liveness_status": "dead",
    }:
        raise ExecutionSealError("completion attestation PID/exit statuses differ")
    for key in ("pid_file_path", "exit_file_path"):
        pid_exit[key] = _normalized_absolute(pid_exit[key], label=f"pid_exit.{key}").as_posix()
    for key in ("pid_file_sha256", "exit_file_sha256"):
        if not _is_sha256(pid_exit[key]):
            raise ExecutionSealError(f"pid_exit.{key} is invalid")
    for key in (
        "pid_file_mtime_ns",
        "pid_file_size_bytes",
        "exit_file_mtime_ns",
        "exit_file_size_bytes",
    ):
        if not _is_int(pid_exit[key]) or pid_exit[key] < 0:
            raise ExecutionSealError(f"pid_exit.{key} is invalid")
    if (
        pid_exit["pid_file_path"] != expectation["pid_file"]
        or pid_exit["exit_file_path"] != expectation["exit_file"]
    ):
        raise ExecutionSealError("attested PID/exit paths differ from launch expectation")

    stability = _expect_exact_keys(
        attestation["stability"], STABILITY_KEYS, label="attestation stability"
    )
    minimum = stability["minimum_interval_seconds"]
    observed = stability["observed_interval_seconds"]
    if (
        stability["snapshots_identical"] is not True
        or isinstance(minimum, bool)
        or not isinstance(minimum, (int, float))
        or isinstance(observed, bool)
        or not isinstance(observed, (int, float))
        or minimum < 1.0
        or observed < minimum
    ):
        raise ExecutionSealError("attestation stability proof is invalid")
    snapshots = attestation["snapshots"]
    if not isinstance(snapshots, list) or len(snapshots) != 2:
        raise ExecutionSealError("completion attestation must contain two snapshots")
    first = _validate_snapshot(snapshots[0], sequence=1)
    second = _validate_snapshot(snapshots[1], sequence=2)
    if _canonical_bytes(first["files"]) != _canonical_bytes(second["files"]):
        raise ExecutionSealError("completion attestation snapshots differ byte-for-byte")
    if (
        first["inventory_sha256"] != second["inventory_sha256"]
        or attestation["causal_pre_attestation_inventory_sha256"]
        != first["inventory_sha256"]
    ):
        raise ExecutionSealError("completion attestation inventory bindings differ")
    process = _validate_audit(
        attestation["process_absence"], PROCESS_ABSENCE_KEYS, label="process absence audit"
    )
    temporary = _validate_audit(
        attestation["no_live_or_temporary"],
        NO_LIVE_OR_TEMPORARY_KEYS,
        label="no-live/no-temporary audit",
    )
    if (
        process["attempt_checkout_path"] != expectation["checkout_root"]
        or process["artifact_root_path"] != expectation["artifact_root"]
        or process["method"] != "linux_procfs_cmdline_and_cwd"
    ):
        raise ExecutionSealError("process absence audit paths or method differ")
    expected_roots = sorted(
        [expectation["artifact_root"], (Path(expectation["durable_attempt_root"]) / "prep").as_posix()]
    )
    if (
        temporary["roots"] != expected_roots
        or temporary["forbidden_match_count"] != 0
    ):
        raise ExecutionSealError("temporary-artifact audit roots or counts differ")
    return attestation, first["files"]


def _recompute_attested_inventory(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    current = [
        _full_file_record(
            Path(record["path"]), record["roles"], label=f"attested inventory file {record['path']}"
        )
        for record in files
    ]
    if _canonical_bytes(current) != _canonical_bytes(files):
        raise ExecutionSealError(
            "current causal pre-attestation inventory differs byte-for-byte from snapshot"
        )
    return current


def _role_paths(files: list[dict[str, Any]], role: str) -> list[Path]:
    return [Path(record["path"]) for record in files if role in record["roles"]]


def _unique_role_path(files: list[dict[str, Any]], role: str) -> Path:
    matches = _role_paths(files, role)
    if len(matches) != 1:
        raise ExecutionSealError(f"causal inventory must contain exactly one {role}")
    return matches[0]


def _validate_role_inventory(
    files: list[dict[str, Any]], *, expectation: dict[str, Any], original: Path
) -> None:
    singleton_roles = (
        "adaptation_corpus_manifest",
        "adaptation_schedule",
        "causal_prereg",
        "causal_smoke_gate",
        "compact_provenance",
        "detailed_provenance",
        "formal_decision",
        "formal_grid",
        "formal_manifest",
        "heldout_corpus_manifest",
        "heldout_schedule",
        "launch_expectation",
        "launcher_source",
        "statistical_addendum",
        "wrapper_exit_file",
        "wrapper_pid_file",
    )
    for role in singleton_roles:
        _unique_role_path(files, role)
    exact_counts = {
        "formal_tape": 3,
        "collector_manifest": 3,
        "collector_final_trace": 3,
        "cell_manifest": 6,
        "cell_final_trace": 6,
        "sealed_cell_log": 9,
        "sealed_cell_log_receipt": 9,
        "sealed_cell_log_start_receipt": 9,
    }
    for role, count in exact_counts.items():
        if len(_role_paths(files, role)) != count:
            raise ExecutionSealError(f"causal inventory count differs for {role}")
    if not _role_paths(files, "evaluation_code"):
        raise ExecutionSealError("causal inventory omits evaluation-code allowlist")
    if not _role_paths(files, "adaptation_corpus_artifact") or not _role_paths(
        files, "heldout_corpus_artifact"
    ):
        raise ExecutionSealError("causal inventory omits exact corpus artifacts")
    expected_paths = {
        "formal_decision": original,
        "formal_manifest": Path(expectation["artifact_root"]) / "formal_manifest.json",
        "wrapper_pid_file": Path(expectation["pid_file"]),
        "wrapper_exit_file": Path(expectation["exit_file"]),
    }
    for role, path in expected_paths.items():
        if _unique_role_path(files, role) != path:
            raise ExecutionSealError(f"causal inventory substitutes registered {role}")


def _validate_causal_decision(value: Any) -> tuple[dict[str, Any], str, str]:
    report = _expect_exact_keys(value, CAUSAL_DECISION_KEYS, label="causal decision")
    required = {
        "protocol": CAUSAL_PROTOCOL,
        "schema_version": 1,
        "experiment": CAUSAL_EXPERIMENT,
        "status": "valid",
        "errors": [],
        "publication_grade": False,
    }
    for key, expected in required.items():
        if report[key] != expected:
            raise ExecutionSealError(f"causal decision violates registered {key}")
    branch = (report["decision"], report["decision_scope"])
    if branch not in {
        ("valid_no_go", "internal_gate_no_go"),
        ("pass", "internal_gate_pass"),
    }:
        raise ExecutionSealError("causal decision is not a registered valid branch")
    return report, branch[0], branch[1]


def _validate_receipt(
    value: Any,
    *,
    decision: str,
    decision_scope: str,
    original_sha256: str,
    formal_manifest_sha256: str,
    execution_plan_path: Path,
    execution_plan_sha256: str,
) -> dict[str, Any]:
    receipt = _expect_exact_keys(
        value, REVALIDATION_RECEIPT_KEYS, label="causal revalidation receipt"
    )
    expected = {
        "decision": decision,
        "decision_scope": decision_scope,
        "execution_plan_path": execution_plan_path.as_posix(),
        "execution_plan_sha256": execution_plan_sha256,
        "formal_decision_file_sha256": original_sha256,
        "formal_manifest_file_sha256": formal_manifest_sha256,
        "status": "valid",
    }
    if receipt != expected:
        raise ExecutionSealError("causal revalidation receipt bindings differ")
    return receipt


def _fixed_paths(
    *, plan: dict[str, Any], expectation: dict[str, Any]
) -> dict[str, Path]:
    root = Path(plan["causal_checkout_root"])
    tooling_root = Path(plan["tooling_root"])
    durable = Path(plan["durable_attempt_root"])
    prep = durable / "prep"
    artifact = durable / "artifacts" / "cohort_causal"
    if (
        plan["attempt_id"] != expectation["attempt_id"]
        or root.as_posix() != expectation["checkout_root"]
        or durable.as_posix() != expectation["durable_attempt_root"]
        or artifact.as_posix() != expectation["artifact_root"]
    ):
        raise ExecutionSealError("execution plan and launch expectation roots differ")
    return {
        "root": root,
        "durable": durable,
        "prep": prep,
        "artifact": artifact,
        "tooling_root": tooling_root,
        "plan": durable / "control" / PLAN_FILENAME,
        "launch_expectation": Path(plan["launch_expectation"]["path"]),
        "structured_preregistration": tooling_root
        / STRUCTURED_PREREGISTRATION_FILENAME,
        "attestation": prep / ATTESTATION_FILENAME,
        "original": artifact / "formal_decision.json",
        "revalidated": prep / REVALIDATED_FILENAME,
        "receipt": prep / REVALIDATION_RECEIPT_FILENAME,
        "seal": prep / SEAL_FILENAME,
    }


def _publish_no_overwrite(path: Path, payload: bytes) -> None:
    if os.path.lexists(path):
        raise FileExistsError(f"refusing to overwrite execution seal: {path}")
    _assert_real_directory(path.parent, label="execution-seal parent")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.tmp."
    )
    temporary = Path(temporary_name)
    linked = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
            linked = True
        except FileExistsError as exc:
            raise FileExistsError(f"refusing to overwrite execution seal: {path}") from exc
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if linked:
            # A visible O_EXCL-equivalent hard link is immutable evidence.  Do
            # not erase it after a later fsync error and create a replace race.
            pass
        raise
    finally:
        temporary.unlink(missing_ok=True)


def _stable_binding_set(bindings: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    return {
        name: _binding_record(path, label=f"seal binding {name}")
        for name, path in sorted(bindings.items())
    }


def build_and_publish_execution_seal(
    *,
    execution_plan_path: Path,
    attestation_path: Path,
    launch_expectation_path: Path,
    causal_original_path: Path,
    causal_revalidated_path: Path,
    revalidation_receipt_path: Path,
    structured_preregistration_path: Path,
    output: Path,
    online_inputs: Mapping[str, Path] | None = None,
    now_fn: Callable[[], str] | None = None,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
) -> dict[str, Any]:
    """Validate a causal trigger and atomically publish its execution seal."""

    normalized = {
        "execution_plan": _normalized_absolute(execution_plan_path, label="execution plan"),
        "attestation": _normalized_absolute(attestation_path, label="completion attestation"),
        "launch_expectation": _normalized_absolute(
            launch_expectation_path, label="launch expectation"
        ),
        "causal_original": _normalized_absolute(causal_original_path, label="causal original"),
        "causal_revalidated": _normalized_absolute(
            causal_revalidated_path, label="causal revalidated"
        ),
        "revalidation_receipt": _normalized_absolute(
            revalidation_receipt_path, label="revalidation receipt"
        ),
        "structured_preregistration": _normalized_absolute(
            structured_preregistration_path, label="structured preregistration"
        ),
        "execution_seal": _normalized_absolute(output, label="execution seal"),
    }
    if online_inputs:
        raise ExecutionSealError(
            "Trigger B is unavailable in plan v1; online inputs require a prospective plan extension"
        )
    if os.path.lexists(normalized["execution_seal"]):
        raise FileExistsError("refusing pre-existing structured execution seal")

    plan, plan_raw = load_and_validate_execution_plan_stage(
        execution_plan_path=normalized["execution_plan"],
        stage="execution_seal_builder",
        expected_inputs={
            key: normalized[key]
            for key in (
                "execution_plan",
                "attestation",
                "launch_expectation",
                "causal_original",
                "causal_revalidated",
                "revalidation_receipt",
                "structured_preregistration",
            )
        },
        expected_outputs={"execution_seal": normalized["execution_seal"]},
        expected_parameters={},
        actual_argv=actual_argv,
        runtime_python_path=runtime_python_path,
        runtime_python_version=runtime_python_version,
    )
    plan_sha256 = _sha256(plan_raw)
    expectation_raw, _ = _read_stable_file(
        normalized["launch_expectation"], label="launch expectation"
    )
    expectation = _validate_launch_expectation(
        _load_json_bytes(expectation_raw, label="launch expectation")
    )
    fixed = _fixed_paths(plan=plan, expectation=expectation)
    for key in (
        "plan",
        "launch_expectation",
        "structured_preregistration",
        "attestation",
        "original",
        "revalidated",
        "receipt",
        "seal",
    ):
        normalized_key = {
            "plan": "execution_plan",
            "original": "causal_original",
            "revalidated": "causal_revalidated",
            "receipt": "revalidation_receipt",
            "seal": "execution_seal",
        }.get(key, key)
        if fixed[key] != normalized[normalized_key]:
            raise ExecutionSealError(f"{normalized_key} differs from fixed registered path")
    for directory, label in (
        (fixed["root"], "checkout root"),
        (fixed["durable"], "durable attempt root"),
        (fixed["durable"] / "control", "durable control root"),
        (fixed["tooling_root"], "tooling root"),
        (fixed["prep"], "durable prep root"),
        (fixed["artifact"], "causal artifact root"),
    ):
        _assert_real_directory(directory, label=label)

    attestation_raw, _ = _read_stable_file(
        normalized["attestation"], label="completion attestation"
    )
    attestation_object = _load_json_bytes(
        attestation_raw, label="completion attestation"
    )
    if attestation_raw != _canonical_bytes(attestation_object):
        raise ExecutionSealError("completion attestation is not canonical JSON bytes")
    attestation, attested_files = _validate_attestation(
        attestation_object,
        execution_plan_path=normalized["execution_plan"],
        execution_plan_sha256=plan_sha256,
        expectation=expectation,
        launch_expectation_path=normalized["launch_expectation"],
        launch_expectation_sha256=_sha256(expectation_raw),
    )
    excluded_paths = {
        normalized["attestation"].as_posix(),
        normalized["causal_revalidated"].as_posix(),
        normalized["revalidation_receipt"].as_posix(),
        normalized["execution_seal"].as_posix(),
    }
    if excluded_paths & {record["path"] for record in attested_files}:
        raise ExecutionSealError("pre-attestation inventory is recursive or includes later outputs")
    _validate_role_inventory(
        attested_files, expectation=expectation, original=normalized["causal_original"]
    )

    # Gate semantic opening on a fresh full inventory byte match.
    current_files = _recompute_attested_inventory(attested_files)
    inventory_by_path = {record["path"]: record for record in current_files}
    original_record = inventory_by_path.get(normalized["causal_original"].as_posix())
    manifest_path = _unique_role_path(current_files, "formal_manifest")
    manifest_record = inventory_by_path[manifest_path.as_posix()]
    if original_record is None or "formal_decision" not in original_record["roles"]:
        raise ExecutionSealError("C_original is absent from causal pre-attestation inventory")

    original_raw, _ = _read_stable_file(
        normalized["causal_original"], label="C_original"
    )
    revalidated_raw, _ = _read_stable_file(
        normalized["causal_revalidated"], label="C_revalidated"
    )
    original_object = _load_json_bytes(original_raw, label="C_original")
    revalidated_object = _load_json_bytes(revalidated_raw, label="C_revalidated")
    original_report, decision, decision_scope = _validate_causal_decision(original_object)
    revalidated_report, revalidated_decision, revalidated_scope = _validate_causal_decision(
        revalidated_object
    )
    if original_raw != revalidated_raw:
        raise ExecutionSealError("C_original and C_revalidated file bytes differ")
    if _canonical_bytes(original_report) != _canonical_bytes(revalidated_report):
        raise ExecutionSealError("C_original and C_revalidated canonical objects differ")
    if (decision, decision_scope) != (revalidated_decision, revalidated_scope):
        raise ExecutionSealError("causal decision branch differs after revalidation")

    receipt_raw, _ = _read_stable_file(
        normalized["revalidation_receipt"], label="causal revalidation receipt"
    )
    _validate_receipt(
        _load_json_bytes(receipt_raw, label="causal revalidation receipt"),
        decision=decision,
        decision_scope=decision_scope,
        original_sha256=_sha256(original_raw),
        formal_manifest_sha256=manifest_record["sha256"],
        execution_plan_path=normalized["execution_plan"],
        execution_plan_sha256=plan_sha256,
    )
    if decision == "pass":
        raise ExecutionSealError(
            "causal internal gate passed; Trigger A is forbidden and Trigger B lacks a prospective online plan"
        )
    if (decision, decision_scope) != ("valid_no_go", "internal_gate_no_go"):
        raise ExecutionSealError("Trigger A requires causal valid_no_go")

    tool_paths = {
        name: Path(plan["tools"][name]["path"]) for name in sorted(PLAN_TOOL_NAMES)
    }
    binding_paths = {
        "causal_trigger_completion_attestation": normalized["attestation"],
        "causal_original": normalized["causal_original"],
        "causal_revalidated": normalized["causal_revalidated"],
        "causal_revalidation_receipt": normalized["revalidation_receipt"],
        "execution_plan": normalized["execution_plan"],
        "launch_expectation": normalized["launch_expectation"],
        "structured_preregistration": normalized["structured_preregistration"],
        "attester_code": tool_paths["attester"],
        "revalidator_code": tool_paths["revalidator"],
        "execution_seal_builder_code": tool_paths["execution_seal_builder"],
    }
    initial_bindings = _stable_binding_set(binding_paths)
    attestation_record = _full_file_record(
        normalized["attestation"],
        ["causal_trigger_completion_attestation"],
        label="causal completion attestation",
    )
    # ``causal_inventory`` has the preregistered nonrecursive meaning: the
    # complete attested pre-attestation inventory plus the completion
    # attestation itself.  Revalidated output, receipt, execution plan, newer
    # verifier code, structured preregistration, and this seal are deliberately
    # outside it and are bound separately by ``bindings``.
    causal_inventory = sorted([*current_files, attestation_record], key=lambda row: row["path"])
    causal_inventory_sha256 = _sha256(_canonical_bytes(causal_inventory))
    pid_path = Path(attestation["pid_exit"]["pid_file_path"])
    exit_path = Path(attestation["pid_exit"]["exit_file_path"])

    created_at = (
        now_fn()
        if now_fn is not None
        else __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat().replace("+00:00", "Z")
    )
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        raise ExecutionSealError("execution-seal timestamp must be UTC Z text")
    seal = {
        "bindings": initial_bindings,
        "causal_completion_attestation_sha256": _sha256(attestation_raw),
        "causal_decision_sha256": _sha256(_canonical_bytes(revalidated_report)),
        "causal_exit_file_sha256": attestation["pid_exit"]["exit_file_sha256"],
        "causal_inventory": causal_inventory,
        "causal_inventory_recheck_matches_attestation": True,
        "causal_inventory_sha256": causal_inventory_sha256,
        "causal_original_file_sha256": _sha256(original_raw),
        "causal_pid_file_sha256": attestation["pid_exit"]["pid_file_sha256"],
        "causal_pre_attestation_inventory_sha256": attestation[
            "causal_pre_attestation_inventory_sha256"
        ],
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": CAUSAL_PROTOCOL_SEAL_STATUS,
        "causal_revalidation_file_sha256": _sha256(revalidated_raw),
        "causal_source_commit": expectation["source_commit"],
        "created_at_utc": created_at,
        "online_icl_decision_sha256": None,
        "online_icl_inventory_recheck_matches_marker": None,
        "online_icl_inventory_sha256": None,
        "online_icl_original_file_sha256": None,
        "online_icl_protocol_seal_sha256": None,
        "online_icl_revalidation_file_sha256": None,
        "online_icl_wrapper_contract_sha256": None,
        "online_icl_wrapper_exit_marker_sha256": None,
        "protocol": SEAL_PROTOCOL,
        "schema_version": SEAL_SCHEMA_VERSION,
        "status": "sealed",
        "terminal_verifier_execution_plan_path": normalized[
            "execution_plan"
        ].as_posix(),
        "terminal_verifier_execution_plan_sha256": plan_sha256,
        "tooling_source_commit": plan["tooling_source_commit"],
        "trigger_branch": "causal_valid_no_go",
        "verifier_execution": {
            "invocations": plan["invocations"],
            "invocations_sha256": _sha256(_canonical_bytes(plan["invocations"])),
            "runtime": plan["runtime"],
            "tools": plan["tools"],
        },
    }

    # Final publication gate: re-hash every pre-attestation file, literal
    # PID/exit bytes, all post-attestation evidence, the plan, and all three
    # verifier sources.  Any byte or metadata drift aborts publication.
    final_files = _recompute_attested_inventory(attested_files)
    if _canonical_bytes(final_files) != _canonical_bytes(current_files):
        raise ExecutionSealError("causal inventory changed during seal construction")
    final_bindings = _stable_binding_set(binding_paths)
    if _canonical_bytes(final_bindings) != _canonical_bytes(initial_bindings):
        raise ExecutionSealError("execution-seal binding changed before publication")
    final_pid = _binding_record(pid_path, label="final PID-file recheck")
    final_exit = _binding_record(exit_path, label="final exit-file recheck")
    if (
        final_pid["sha256"] != attestation["pid_exit"]["pid_file_sha256"]
        or final_exit["sha256"] != attestation["pid_exit"]["exit_file_sha256"]
    ):
        raise ExecutionSealError("literal PID/exit file digest drifted before publication")
    final_attestation_record = _full_file_record(
        normalized["attestation"],
        ["causal_trigger_completion_attestation"],
        label="final completion-attestation recheck",
    )
    if final_attestation_record != attestation_record:
        raise ExecutionSealError("completion attestation changed before publication")
    final_inventory = sorted([*final_files, final_attestation_record], key=lambda row: row["path"])
    if _sha256(_canonical_bytes(final_inventory)) != causal_inventory_sha256:
        raise ExecutionSealError("causal inventory digest changed before publication")
    if _sha256(_canonical_bytes(seal["causal_inventory"])) != seal[
        "causal_inventory_sha256"
    ]:
        raise AssertionError("execution-seal causal inventory digest drift")

    payload = _canonical_bytes(seal)
    _publish_no_overwrite(normalized["execution_seal"], payload)
    return {
        "path": normalized["execution_seal"].as_posix(),
        "seal_sha256": _sha256(payload),
        "status": "sealed",
        "trigger_branch": "causal_valid_no_go",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--causal-original", type=Path, required=True)
    parser.add_argument("--causal-revalidated", type=Path, required=True)
    parser.add_argument("--revalidation-receipt", type=Path, required=True)
    parser.add_argument("--structured-preregistration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_and_publish_execution_seal(
            execution_plan_path=args.execution_plan,
            attestation_path=args.attestation,
            launch_expectation_path=args.launch_expectation,
            causal_original_path=args.causal_original,
            causal_revalidated_path=args.causal_revalidated,
            revalidation_receipt_path=args.revalidation_receipt,
            structured_preregistration_path=args.structured_preregistration,
            output=args.output,
        )
    except (ExecutionSealError, FileExistsError, OSError, ValueError) as exc:
        raise SystemExit(f"structured execution-seal build failed: {exc}") from exc
    print(_canonical_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
