#!/usr/bin/env python3
"""Build and validate the outcome-blind, one-shot V3 recovery execution plan.

V3 overlays immutable V2 control evidence only.  This module never opens or
parses efficacy-bearing formal decisions, manifests, or model outputs.
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import build_cohort_structured_state_execution_seal_v2 as v2
import freeze_cohort_causal_terminal_recovery_v3 as recovery
import launch_cohort_causal_terminal_verifier_v2_detached as launcher_v2
import launch_cohort_causal_terminal_verifier_v3_detached as launcher_v3


PLAN_PROTOCOL = "cohort_causal_terminal_verifier_execution_plan_v3"
PLAN_SCHEMA_VERSION = 3
PLAN_STATUS = "registered_one_shot_recovery"
PLAN_FILENAME = "CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V3.json"
FAILURE_CLOSURE_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V2_FAILURE_CLOSURE_V1.json"
COMPLETION_FENCE_FILENAME = "CAUSAL_TERMINAL_VERIFIER_COMPLETION_FENCE_V3.json"
DETACHED_HANDOFF_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V3_DETACHED_HANDOFF.json"
LAUNCH_CLAIM_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V3_LAUNCH_CLAIM.json"
DETACHED_RECEIPT_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V3_DETACHED_RECEIPT.json"
ATTESTATION_FILENAME = "causal_trigger_completion_attestation.v3.json"
REVALIDATED_FILENAME = "causal_formal.revalidated.v3.json"
REVALIDATION_RECEIPT_FILENAME = "causal_formal.revalidation_receipt.v3.json"
SEAL_FILENAME = "cohort_closed_loop_structured_state.execution_seal.v3.json"
AMENDMENT_FILENAME = "CAUSAL_TERMINAL_VERIFIER_V3_RECOVERY_AMENDMENT.md"
STRUCTURED_PREREGISTRATION_FILENAME = "COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md"

HANDOFF_PROTOCOL = "cohort_causal_terminal_verifier_v3_detached_handoff_v1"
CLAIM_PROTOCOL = "cohort_causal_terminal_verifier_v3_launch_claim_v1"
DETACHED_RECEIPT_PROTOCOL = "cohort_causal_terminal_verifier_v3_detached_receipt_v1"
EXPECTED_PYTHON_PATH = "/usr/bin/python3.10"
EXPECTED_PYTHON_VERSION = "3.10.12"

TOOL_FILENAMES = {
    "attester": "attest_cohort_causal_completion_v3.py",
    "execution_plan_builder": "build_cohort_causal_terminal_execution_v3.py",
    "execution_seal_builder": "build_cohort_structured_state_execution_seal_v3.py",
    "revalidator": "revalidate_cohort_causal_terminal_v3.py",
    "transport_launcher": "launch_cohort_causal_terminal_verifier_v3_detached.py",
}
BRANCH_ADAPTER_FILENAMES = {
    "online_icl_formal_wrapper_contract_adapter": (
        "build_cohort_online_icl_formal_wrapper_contract_v3_adapter.py"
    ),
    "structured_trigger_receipt_adapter": (
        "cohort_closed_loop_structured_trigger_receipt_v3_adapter.py"
    ),
    "structured_trigger_receipt_revalidator_adapter": (
        "cohort_closed_loop_structured_trigger_receipt_revalidator_v3_adapter.py"
    ),
}
DEPENDENCY_FILENAMES = {
    "recovery_freezer": "freeze_cohort_causal_terminal_recovery_v3.py",
    "v1_completion_attester": "attest_cohort_causal_completion.py",
    "v2_completion_attester": "attest_cohort_causal_completion_v2.py",
    "v1_execution_seal_engine": "build_cohort_structured_state_execution_seal.py",
    "v2_execution_seal_engine": "build_cohort_structured_state_execution_seal_v2.py",
    "v1_revalidator_engine": "revalidate_cohort_causal_terminal.py",
    "v2_transport_launcher": "launch_cohort_causal_terminal_verifier_v2_detached.py",
    "legacy_online_icl_contract_engine": (
        "build_cohort_online_icl_formal_wrapper_contract.py"
    ),
    "legacy_structured_trigger_receipt_engine": (
        "cohort_closed_loop_structured_trigger_receipt.py"
    ),
    "legacy_structured_trigger_receipt_revalidator_engine": (
        "cohort_closed_loop_structured_trigger_receipt_revalidator.py"
    ),
    **BRANCH_ADAPTER_FILENAMES,
}

PLAN_TOOL_NAMES = frozenset({"attester", "revalidator", "execution_seal_builder"})
PLAN_INVOCATION_NAMES = PLAN_TOOL_NAMES
BINDING_KEYS = frozenset({"path", "sha256"})
BASE_V2_KEYS = frozenset(
    {"execution_plan", "detached_receipt", "procfs_exception_inventory"}
)
RECOVERY_CONTROL_KEYS = frozenset({"v2_failure_closure", "v3_completion_fence"})
INVOCATION_KEYS = frozenset({"argv", "inputs", "outputs", "parameters"})
PLAN_KEYS = frozenset(
    {
        "amendment",
        "attempt_id",
        "base_v2",
        "branch_adapter_contracts",
        "causal_checkout_root",
        "created_at_utc",
        "detached_launch_contract",
        "detached_transport",
        "durable_attempt_root",
        "implementation_dependencies",
        "invocations",
        "outcome_blind",
        "protocol",
        "public_truth",
        "recovery_controls",
        "runtime",
        "schema_version",
        "science_invariants",
        "semantic_artifacts_opened",
        "status",
        "structured_preregistration",
        "tooling_root",
        "tooling_source_commit",
        "tools",
    }
)


class CausalExecutionV3Error(RuntimeError):
    """A fail-closed V3 control-plan or transport validation error."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=lambda pairs: _reject_duplicate_keys(pairs, label),
            parse_constant=lambda item: _reject_constant(item, label),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CausalExecutionV3Error(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict) or payload != canonical_bytes(value):
        raise CausalExecutionV3Error(f"{label} is not canonical object bytes")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CausalExecutionV3Error(f"{label} has a duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str, label: str) -> None:
    raise CausalExecutionV3Error(f"{label} has non-finite constant {value}")


def _absolute(value: str | Path, label: str) -> Path:
    text = os.fspath(value)
    path = Path(text)
    if not path.is_absolute() or os.path.normpath(text) != text:
        raise CausalExecutionV3Error(f"{label} is not a normalized absolute path")
    return path


def _assert_no_symlink_descendant(path: Path, *, root: Path, label: str) -> None:
    target = _absolute(path, label)
    fixed_root = _absolute(root, f"{label} root")
    try:
        relative = target.relative_to(fixed_root)
    except ValueError as exc:
        raise CausalExecutionV3Error(f"{label} escapes its fixed root") from exc
    candidates = [fixed_root]
    current = fixed_root
    for part in relative.parts:
        current /= part
        candidates.append(current)
    for candidate in candidates:
        try:
            metadata = os.lstat(candidate)
        except FileNotFoundError:
            if candidate == target:
                continue
            raise CausalExecutionV3Error(f"{label} ancestor is absent") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise CausalExecutionV3Error(f"{label} has a symlink component")


def _read_stable(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CausalExecutionV3Error(f"cannot open {label}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CausalExecutionV3Error(f"{label} is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    def identity(item: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if identity(before) != identity(after):
        raise CausalExecutionV3Error(f"{label} changed while reading")
    return b"".join(chunks)


def _binding(path: Path, label: str) -> dict[str, str]:
    absolute = _absolute(path, f"{label} path")
    return {"path": absolute.as_posix(), "sha256": _sha(_read_stable(absolute, label))}


def _validate_binding(
    value: Any, *, expected_path: Path | None, label: str
) -> tuple[Path, bytes]:
    if not isinstance(value, dict) or set(value) != BINDING_KEYS:
        raise CausalExecutionV3Error(f"{label} binding schema differs")
    path = _absolute(value["path"], f"{label} path")
    if expected_path is not None and path != expected_path:
        raise CausalExecutionV3Error(f"{label} path differs")
    digest = value["sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise CausalExecutionV3Error(f"{label} digest is invalid")
    raw = _read_stable(path, label)
    if _sha(raw) != digest:
        raise CausalExecutionV3Error(f"{label} bytes differ")
    return path, raw


def _publish_no_overwrite(path: Path, payload: bytes, label: str) -> None:
    if os.path.lexists(path):
        raise FileExistsError(f"refusing to overwrite {label}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.tmp."
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
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
    finally:
        temporary.unlink(missing_ok=True)


def _parse_time(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise CausalExecutionV3Error("created_at_utc is invalid") from exc
    if (
        parsed.tzinfo != timezone.utc
        or parsed.isoformat().replace("+00:00", "Z") != value
    ):
        raise CausalExecutionV3Error("created_at_utc is not canonical UTC")


def _load_base_v2_controls(
    *,
    durable_root: Path,
    plan_path: Path,
    receipt_path: Path,
    inventory_path: Path,
) -> dict[str, Any]:
    control = durable_root / "control"
    if (
        plan_path != control / v2.PLAN_FILENAME
        or receipt_path != control / v2.DETACHED_RECEIPT_FILENAME
        or inventory_path != control / v2.EXCEPTION_INVENTORY_FILENAME
    ):
        raise CausalExecutionV3Error("base V2 control paths are not fixed")
    plan_raw = _read_stable(plan_path, "base V2 execution plan")
    receipt_raw = _read_stable(receipt_path, "base V2 detached receipt")
    inventory_raw = _read_stable(inventory_path, "base V2 procfs inventory")
    plan = _strict_json(plan_raw, "base V2 execution plan")
    receipt = _strict_json(receipt_raw, "base V2 detached receipt")
    inventory = _strict_json(inventory_raw, "base V2 procfs inventory")
    if (
        set(plan) != v2.PLAN_KEYS
        or plan["protocol"] != v2.PLAN_PROTOCOL
        or plan["schema_version"] != v2.PLAN_SCHEMA_VERSION
        or plan["status"] != v2.PLAN_STATUS
        or set(receipt) != launcher_v2.RECEIPT_KEYS
        or receipt["protocol"] != launcher_v2.RECEIPT_PROTOCOL
        or receipt["schema_version"] != 1
        or receipt["status"] != "ready_to_exec_exact_attester"
        or receipt["outcome_blind"] is not True
        or set(inventory) != v2.EXCEPTION_INVENTORY_KEYS
        or inventory["protocol"] != v2.EXCEPTION_INVENTORY_PROTOCOL
        or inventory["schema_version"] != v2.EXCEPTION_INVENTORY_SCHEMA_VERSION
        or inventory["outcome_blind"] is not True
        or inventory["semantic_artifacts_opened"] is not False
    ):
        raise CausalExecutionV3Error("base V2 control document contract differs")
    if (
        plan["procfs_exception_inventory"]
        != {"path": inventory_path.as_posix(), "sha256": _sha(inventory_raw)}
        or plan["detached_transport"]["receipt_path"] != receipt_path.as_posix()
        or receipt["plan"] != {"path": plan_path.as_posix(), "sha256": _sha(plan_raw)}
    ):
        raise CausalExecutionV3Error("base V2 control bindings differ")
    # A dead V2 receipt is historical static evidence only.  Deliberately do
    # not compare its PID/start identity with this V3 process.
    return {
        "base_v2_execution_plan": plan,
        "base_v2_execution_plan_raw": plan_raw,
        "base_v2_detached_receipt": receipt,
        "base_v2_detached_receipt_raw": receipt_raw,
        "base_v2_procfs_exception_inventory": inventory,
        "base_v2_procfs_exception_inventory_raw": inventory_raw,
    }


def _load_recovery_controls(
    *,
    durable_root: Path,
    closure_path: Path,
    fence_path: Path,
) -> dict[str, Any]:
    control = durable_root / "control"
    if (
        closure_path != control / FAILURE_CLOSURE_FILENAME
        or fence_path != control / COMPLETION_FENCE_FILENAME
    ):
        raise CausalExecutionV3Error("V3 recovery control paths are not fixed")
    closure_raw = _read_stable(closure_path, "V2 failure closure")
    fence_raw = _read_stable(fence_path, "V3 completion fence")
    closure = _strict_json(closure_raw, "V2 failure closure")
    fence = _strict_json(fence_raw, "V3 completion fence")
    try:
        validated_closure = recovery.validate_failure_closure_document(
            closure,
            durable_attempt_root=durable_root,
            expected_path=closure_path,
        )
        validated_fence, fence_inventory = recovery.validate_completion_fence_document(
            fence,
            durable_attempt_root=durable_root,
            expected_path=fence_path,
            failure_closure_path=closure_path,
            failure_closure_sha256=_sha(closure_raw),
        )
    except recovery.RecoveryV3Error as exc:
        raise CausalExecutionV3Error("V3 recovery control validation failed") from exc
    return {
        "closure": validated_closure,
        "closure_raw": closure_raw,
        "fence": validated_fence,
        "fence_raw": fence_raw,
        "fence_inventory_files": fence_inventory,
    }


def _load_plan_document(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_stable(path, "V3 execution plan")
    plan = _strict_json(raw, "V3 execution plan")
    if set(plan) != PLAN_KEYS or (
        plan["protocol"] != PLAN_PROTOCOL
        or plan["schema_version"] != PLAN_SCHEMA_VERSION
        or plan["status"] != PLAN_STATUS
        or plan["outcome_blind"] is not True
        or plan["semantic_artifacts_opened"] is not False
        or plan["detached_launch_contract"] != launcher_v3.DETACHED_LAUNCH_CONTRACT
    ):
        raise CausalExecutionV3Error("V3 plan header or exact schema differs")
    durable = _absolute(plan["durable_attempt_root"], "V3 durable root")
    commit = plan["tooling_source_commit"]
    if (
        not isinstance(commit, str)
        or _COMMIT_RE.fullmatch(commit) is None
        or path != durable / "control" / PLAN_FILENAME
        or _absolute(plan["tooling_root"], "V3 tooling root")
        != durable / "control" / "verifier" / commit
    ):
        raise CausalExecutionV3Error("V3 plan fixed identity differs")
    return plan, raw


def _transport_paths(commit: str, durable: Path) -> tuple[Path, Path, Path, Path]:
    root = Path("/tmp") / "cohort-causal-terminal-verifier-v3" / commit
    return (
        root / TOOL_FILENAMES["transport_launcher"],
        root / DETACHED_HANDOFF_FILENAME,
        durable / "control" / LAUNCH_CLAIM_FILENAME,
        durable / "control" / DETACHED_RECEIPT_FILENAME,
    )


def _fixed_topology(
    *, causal_root: Path, durable: Path, tooling: Path, base_plan: Mapping[str, Any]
) -> dict[str, Any]:
    control = durable / "control"
    prep = durable / "prep"
    plan = control / PLAN_FILENAME
    base_control = {
        "base_v2_execution_plan": control / v2.PLAN_FILENAME,
        "base_v2_detached_receipt": control / v2.DETACHED_RECEIPT_FILENAME,
        "base_v2_procfs_exception_inventory": control / v2.EXCEPTION_INVENTORY_FILENAME,
        "v2_failure_closure": control / FAILURE_CLOSURE_FILENAME,
        "completion_fence": control / COMPLETION_FENCE_FILENAME,
        "detached_launch_receipt": control / DETACHED_RECEIPT_FILENAME,
    }
    v2_attester = base_plan["invocations"]["attester"]["inputs"]
    v2_revalidator = base_plan["invocations"]["revalidator"]["inputs"]
    v2_seal = base_plan["invocations"]["execution_seal_builder"]["inputs"]
    invocations = {
        "attester": {
            "argv": [],
            "inputs": {
                "execution_plan": plan.as_posix(),
                **{key: value.as_posix() for key, value in base_control.items()},
                "launch_expectation": v2_attester["launch_expectation"],
                "provenance": v2_attester["provenance"],
                "provenance_details": v2_attester["provenance_details"],
                "root": causal_root.as_posix(),
            },
            "outputs": {"attestation": (prep / ATTESTATION_FILENAME).as_posix()},
            "parameters": {"stability_seconds": "1.0"},
        },
        "revalidator": {
            "argv": [],
            "inputs": {
                "execution_plan": plan.as_posix(),
                "v2_failure_closure": base_control["v2_failure_closure"].as_posix(),
                "completion_fence": base_control["completion_fence"].as_posix(),
                "attestation": (prep / ATTESTATION_FILENAME).as_posix(),
                "launch_expectation": v2_revalidator["launch_expectation"],
                "grid": v2_revalidator["grid"],
                "provenance": v2_revalidator["provenance"],
                "formal_manifest": v2_revalidator["formal_manifest"],
                "formal_decision": v2_revalidator["formal_decision"],
                "preregistration": v2_revalidator["preregistration"],
                "statistical_addendum": v2_revalidator["statistical_addendum"],
                "root": causal_root.as_posix(),
            },
            "outputs": {
                "revalidated_decision": (prep / REVALIDATED_FILENAME).as_posix(),
                "revalidation_receipt": (
                    prep / REVALIDATION_RECEIPT_FILENAME
                ).as_posix(),
            },
            "parameters": {},
        },
        "execution_seal_builder": {
            "argv": [],
            "inputs": {
                "execution_plan": plan.as_posix(),
                "v2_failure_closure": base_control["v2_failure_closure"].as_posix(),
                "completion_fence": base_control["completion_fence"].as_posix(),
                "attestation": (prep / ATTESTATION_FILENAME).as_posix(),
                "launch_expectation": v2_seal["launch_expectation"],
                "causal_original": v2_seal["causal_original"],
                "causal_revalidated": (prep / REVALIDATED_FILENAME).as_posix(),
                "revalidation_receipt": (
                    prep / REVALIDATION_RECEIPT_FILENAME
                ).as_posix(),
                "structured_preregistration": (
                    tooling / STRUCTURED_PREREGISTRATION_FILENAME
                ).as_posix(),
            },
            "outputs": {"execution_seal": (prep / SEAL_FILENAME).as_posix()},
            "parameters": {},
        },
    }
    for stage in sorted(invocations):
        invocations[stage]["argv"] = _expected_argv(
            stage, invocations[stage], tooling / TOOL_FILENAMES[stage]
        )
    return invocations


def _expected_argv(stage: str, invocation: Mapping[str, Any], tool: Path) -> list[str]:
    inputs = invocation["inputs"]
    outputs = invocation["outputs"]
    if stage == "attester":
        ordered = (
            "execution_plan",
            "base_v2_execution_plan",
            "base_v2_detached_receipt",
            "base_v2_procfs_exception_inventory",
            "v2_failure_closure",
            "completion_fence",
            "root",
            "launch_expectation",
            "provenance",
            "provenance_details",
            "detached_launch_receipt",
        )
        flags = {name: "--" + name.replace("_", "-") for name in ordered}
        argv = [EXPECTED_PYTHON_PATH, tool.as_posix()]
        for name in ordered:
            argv.extend((flags[name], inputs[name]))
        return [
            *argv,
            "--output",
            outputs["attestation"],
            "--stability-seconds",
            invocation["parameters"]["stability_seconds"],
        ]
    if stage == "revalidator":
        ordered = (
            "execution_plan",
            "v2_failure_closure",
            "completion_fence",
            "attestation",
            "launch_expectation",
            "grid",
            "provenance",
            "formal_manifest",
            "formal_decision",
            "preregistration",
            "statistical_addendum",
            "root",
        )
        argv = [EXPECTED_PYTHON_PATH, tool.as_posix()]
        for name in ordered:
            argv.extend(("--" + name.replace("_", "-"), inputs[name]))
        return [
            *argv,
            "--output",
            outputs["revalidated_decision"],
            "--receipt",
            outputs["revalidation_receipt"],
        ]
    if stage == "execution_seal_builder":
        ordered = (
            "execution_plan",
            "v2_failure_closure",
            "completion_fence",
            "attestation",
            "launch_expectation",
            "causal_original",
            "causal_revalidated",
            "revalidation_receipt",
            "structured_preregistration",
        )
        argv = [EXPECTED_PYTHON_PATH, tool.as_posix()]
        for name in ordered:
            argv.extend(("--" + name.replace("_", "-"), inputs[name]))
        return [*argv, "--output", outputs["execution_seal"]]
    raise CausalExecutionV3Error(f"unknown V3 stage: {stage}")


def _branch_adapter_contracts(
    *, tooling: Path, durable: Path, causal_root: Path
) -> dict[str, Any]:
    fixed_controls = {
        "completion_attestation": (durable / "prep" / ATTESTATION_FILENAME).as_posix(),
        "completion_fence": (
            durable / "control" / COMPLETION_FENCE_FILENAME
        ).as_posix(),
        "detached_receipt": (
            durable / "control" / DETACHED_RECEIPT_FILENAME
        ).as_posix(),
        "execution_plan": (durable / "control" / PLAN_FILENAME).as_posix(),
        "execution_seal": (durable / "prep" / SEAL_FILENAME).as_posix(),
        "failure_closure": (durable / "control" / FAILURE_CLOSURE_FILENAME).as_posix(),
        "launch_claim": (durable / "control" / LAUNCH_CLAIM_FILENAME).as_posix(),
        "revalidated_decision": (durable / "prep" / REVALIDATED_FILENAME).as_posix(),
        "revalidation_receipt": (
            durable / "prep" / REVALIDATION_RECEIPT_FILENAME
        ).as_posix(),
    }
    protocols = {
        "online_icl_formal_wrapper_contract_adapter": (
            "cohort_online_icl_formal_wrapper_contract_v3_adapter_v1"
        ),
        "structured_trigger_receipt_adapter": (
            "cohort_structured_trigger_receipt_v3_adapter_v1"
        ),
        "structured_trigger_receipt_revalidator_adapter": (
            "cohort_structured_trigger_receipt_revalidator_v3_adapter_v1"
        ),
    }
    return {
        name: {
            "causal_checkout_root": causal_root.as_posix(),
            "cli_exposed": False,
            "fixed_authoritative_paths": fixed_controls,
            "future_argv": [],
            "post_reveal_child_plan_required": name.startswith("online_icl"),
            "protocol": protocols[name],
            "publication": False,
            "schema_version": 1,
            "source": _binding(tooling / filename, f"V3 branch adapter {name}"),
        }
        for name, filename in sorted(BRANCH_ADAPTER_FILENAMES.items())
    }


def make_detached_handoff(
    *,
    tooling_source_commit: str,
    causal_checkout_root: Path,
    durable_attempt_root: Path,
) -> dict[str, Any]:
    """Construct the fixed V3 handoff before execution-plan publication."""

    if _COMMIT_RE.fullmatch(tooling_source_commit) is None:
        raise CausalExecutionV3Error("tooling source commit is invalid")
    causal = _absolute(causal_checkout_root, "causal checkout root")
    durable = _absolute(durable_attempt_root, "durable attempt root")
    tooling = durable / "control" / "verifier" / tooling_source_commit
    base = _load_base_v2_controls(
        durable_root=durable,
        plan_path=durable / "control" / v2.PLAN_FILENAME,
        receipt_path=durable / "control" / v2.DETACHED_RECEIPT_FILENAME,
        inventory_path=durable / "control" / v2.EXCEPTION_INVENTORY_FILENAME,
    )
    invocations = _fixed_topology(
        causal_root=causal,
        durable=durable,
        tooling=tooling,
        base_plan=base["base_v2_execution_plan"],
    )
    launcher, handoff, claim, receipt = _transport_paths(tooling_source_commit, durable)
    launcher_binding = _binding(launcher, "V3 transport launcher")
    source_binding = _binding(
        tooling / TOOL_FILENAMES["transport_launcher"], "V3 launcher source"
    )
    if launcher_binding["sha256"] != source_binding["sha256"]:
        raise CausalExecutionV3Error("transport launcher differs from tooling source")
    launcher_argv = [
        EXPECTED_PYTHON_PATH,
        "-I",
        launcher.as_posix(),
        "--handoff",
        handoff.as_posix(),
        "--delay-seconds",
        str(launcher_v3.MINIMUM_DELAY_SECONDS),
    ]
    document = {
        "attester_argv": invocations["attester"]["argv"],
        "detached_launch_contract": launcher_v3.DETACHED_LAUNCH_CONTRACT,
        "launch_claim_path": claim.as_posix(),
        "launcher": launcher_binding,
        "launcher_argv": launcher_argv,
        "minimum_delay_seconds": launcher_v3.MINIMUM_DELAY_SECONDS,
        "outcome_blind": True,
        "plan_path": (durable / "control" / PLAN_FILENAME).as_posix(),
        "protocol": HANDOFF_PROTOCOL,
        "receipt_path": receipt.as_posix(),
        "required_cwd": "/tmp",
        "required_parent_pid": 1,
        "schema_version": 1,
        "semantic_artifacts_opened": False,
        "status": "registered_one_shot",
        "transport_only_no_scientific_authority": True,
    }
    if set(document) != launcher_v3.HANDOFF_KEYS:
        raise AssertionError("V3 handoff schema drift")
    return document


def publish_detached_handoff_no_overwrite(
    path: Path, handoff: Mapping[str, Any]
) -> None:
    """Publish the canonical V3 handoff exactly once."""

    output = _absolute(path, "V3 detached handoff")
    if (
        output.name != DETACHED_HANDOFF_FILENAME
        or not output.as_posix().startswith("/tmp/cohort-causal-terminal-verifier-v3/")
        or set(handoff) != launcher_v3.HANDOFF_KEYS
    ):
        raise CausalExecutionV3Error("V3 handoff output or schema differs")
    _assert_no_symlink_descendant(
        output, root=output.parent, label="V3 detached handoff"
    )
    _publish_no_overwrite(output, canonical_bytes(dict(handoff)), "V3 handoff")


def make_execution_plan(
    *,
    tooling_source_commit: str,
    causal_checkout_root: Path,
    durable_attempt_root: Path,
    created_at_utc: str,
) -> dict[str, Any]:
    """Construct the V3 plan over immutable V2 and recovery controls."""

    if _COMMIT_RE.fullmatch(tooling_source_commit) is None:
        raise CausalExecutionV3Error("tooling source commit is invalid")
    _parse_time(created_at_utc)
    causal = _absolute(causal_checkout_root, "causal checkout root")
    durable = _absolute(durable_attempt_root, "durable attempt root")
    if durable.name != "attempt-002":
        raise CausalExecutionV3Error("V3 is fixed to attempt-002")
    control = durable / "control"
    prep = durable / "prep"
    tooling = control / "verifier" / tooling_source_commit
    for directory in (causal, durable, control, prep, tooling):
        if not directory.is_dir() or directory.is_symlink():
            raise CausalExecutionV3Error("V3 fixed root is absent or a symlink")
    base = _load_base_v2_controls(
        durable_root=durable,
        plan_path=control / v2.PLAN_FILENAME,
        receipt_path=control / v2.DETACHED_RECEIPT_FILENAME,
        inventory_path=control / v2.EXCEPTION_INVENTORY_FILENAME,
    )
    controls = _load_recovery_controls(
        durable_root=durable,
        closure_path=control / FAILURE_CLOSURE_FILENAME,
        fence_path=control / COMPLETION_FENCE_FILENAME,
    )
    base_plan = base["base_v2_execution_plan"]
    if (
        base_plan["causal_checkout_root"] != causal.as_posix()
        or base_plan["durable_attempt_root"] != durable.as_posix()
    ):
        raise CausalExecutionV3Error("V3 roots differ from immutable V2 plan")
    launcher, handoff, claim, receipt = _transport_paths(tooling_source_commit, durable)
    for future in (
        control / PLAN_FILENAME,
        claim,
        receipt,
        prep / ATTESTATION_FILENAME,
        prep / REVALIDATED_FILENAME,
        prep / REVALIDATION_RECEIPT_FILENAME,
        prep / SEAL_FILENAME,
    ):
        if os.path.lexists(future):
            raise CausalExecutionV3Error(
                f"V3 future path already exists: {future.name}"
            )
    tools = {
        name: _binding(tooling / filename, f"V3 tool {name}")
        for name, filename in sorted(TOOL_FILENAMES.items())
    }
    dependencies = {
        name: _binding(tooling / filename, f"V3 dependency {name}")
        for name, filename in sorted(DEPENDENCY_FILENAMES.items())
    }
    launcher_binding = _binding(launcher, "V3 transport launcher")
    if launcher_binding["sha256"] != tools["transport_launcher"]["sha256"]:
        raise CausalExecutionV3Error("V3 transport copy differs from source")
    invocations = _fixed_topology(
        causal_root=causal, durable=durable, tooling=tooling, base_plan=base_plan
    )
    handoff_raw = _read_stable(handoff, "V3 detached handoff")
    expected_handoff = make_detached_handoff(
        tooling_source_commit=tooling_source_commit,
        causal_checkout_root=causal,
        durable_attempt_root=durable,
    )
    if _strict_json(handoff_raw, "V3 detached handoff") != expected_handoff:
        raise CausalExecutionV3Error("V3 handoff semantics differ")
    revalidator_inputs = base_plan["invocations"]["revalidator"]["inputs"]
    science_paths = {
        "grid": Path(revalidator_inputs["grid"]),
        "preregistration": Path(revalidator_inputs["preregistration"]),
        "statistical_addendum": Path(revalidator_inputs["statistical_addendum"]),
    }
    plan = {
        "amendment": _binding(tooling / AMENDMENT_FILENAME, "V3 amendment"),
        "attempt_id": durable.name,
        "base_v2": {
            "execution_plan": {
                "path": (control / v2.PLAN_FILENAME).as_posix(),
                "sha256": _sha(base["base_v2_execution_plan_raw"]),
            },
            "detached_receipt": {
                "path": (control / v2.DETACHED_RECEIPT_FILENAME).as_posix(),
                "sha256": _sha(base["base_v2_detached_receipt_raw"]),
            },
            "procfs_exception_inventory": {
                "path": (control / v2.EXCEPTION_INVENTORY_FILENAME).as_posix(),
                "sha256": _sha(base["base_v2_procfs_exception_inventory_raw"]),
            },
        },
        "branch_adapter_contracts": _branch_adapter_contracts(
            tooling=tooling, durable=durable, causal_root=causal
        ),
        "causal_checkout_root": causal.as_posix(),
        "created_at_utc": created_at_utc,
        "detached_launch_contract": launcher_v3.DETACHED_LAUNCH_CONTRACT,
        "detached_transport": {
            "handoff": {"path": handoff.as_posix(), "sha256": _sha(handoff_raw)},
            "launch_claim_path": claim.as_posix(),
            "launcher": launcher_binding,
            "receipt_path": receipt.as_posix(),
        },
        "durable_attempt_root": durable.as_posix(),
        "implementation_dependencies": dependencies,
        "invocations": invocations,
        "outcome_blind": True,
        "protocol": PLAN_PROTOCOL,
        "public_truth": {
            "completion_method": "post-wrapper-death two-snapshot fence",
            "historical_exit_order_claimed": False,
            "legacy_strict_mtime_proof": False,
            "mtime_relation": (
                "formal_manifest_before_formal_decision_equal_wrapper_exit"
            ),
        },
        "recovery_controls": {
            "v2_failure_closure": {
                "path": (control / FAILURE_CLOSURE_FILENAME).as_posix(),
                "sha256": _sha(controls["closure_raw"]),
            },
            "v3_completion_fence": {
                "path": (control / COMPLETION_FENCE_FILENAME).as_posix(),
                "sha256": _sha(controls["fence_raw"]),
            },
        },
        "runtime": {
            "python_path": EXPECTED_PYTHON_PATH,
            "python_version": EXPECTED_PYTHON_VERSION,
        },
        "schema_version": PLAN_SCHEMA_VERSION,
        "science_invariants": {
            "base_v2_invocations_sha256": canonical_sha256(base_plan["invocations"]),
            "changed": False,
            "estimator_and_thresholds_changed": False,
            "grid": _binding(science_paths["grid"], "causal grid"),
            "preregistration": _binding(
                science_paths["preregistration"], "causal preregistration"
            ),
            "statistical_addendum": _binding(
                science_paths["statistical_addendum"], "statistical addendum"
            ),
        },
        "semantic_artifacts_opened": False,
        "status": PLAN_STATUS,
        "structured_preregistration": _binding(
            tooling / STRUCTURED_PREREGISTRATION_FILENAME,
            "V3 structured preregistration",
        ),
        "tooling_root": tooling.as_posix(),
        "tooling_source_commit": tooling_source_commit,
        "tools": tools,
    }
    if set(plan) != PLAN_KEYS:
        raise AssertionError("V3 plan schema drift")
    return plan


def publish_execution_plan_no_overwrite(path: Path, plan: Mapping[str, Any]) -> None:
    """Publish the canonical V3 execution plan exactly once."""

    output = _absolute(path, "V3 execution plan")
    if set(plan) != PLAN_KEYS:
        raise CausalExecutionV3Error("V3 plan output or schema differs")
    durable = _absolute(plan["durable_attempt_root"], "V3 durable root")
    if output != durable / "control" / PLAN_FILENAME:
        raise CausalExecutionV3Error("V3 plan output or schema differs")
    _assert_no_symlink_descendant(output, root=durable, label="V3 execution plan")
    _publish_no_overwrite(output, canonical_bytes(dict(plan)), "V3 execution plan")


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
    """Validate every plan binding and one exact future invocation."""

    if stage not in PLAN_INVOCATION_NAMES:
        raise CausalExecutionV3Error("unknown V3 execution-plan stage")
    path = _absolute(execution_plan_path, "V3 execution plan")
    plan, raw = _load_plan_document(path)
    causal = _absolute(plan["causal_checkout_root"], "V3 causal root")
    durable = _absolute(plan["durable_attempt_root"], "V3 durable root")
    tooling = _absolute(plan["tooling_root"], "V3 tooling root")
    _parse_time(plan["created_at_utc"])
    expected_truth = {
        "completion_method": "post-wrapper-death two-snapshot fence",
        "historical_exit_order_claimed": False,
        "legacy_strict_mtime_proof": False,
        "mtime_relation": "formal_manifest_before_formal_decision_equal_wrapper_exit",
    }
    if (
        plan["attempt_id"] != durable.name
        or durable.name != "attempt-002"
        or plan["public_truth"] != expected_truth
        or plan["runtime"]
        != {
            "python_path": EXPECTED_PYTHON_PATH,
            "python_version": EXPECTED_PYTHON_VERSION,
        }
    ):
        raise CausalExecutionV3Error("V3 fixed runtime/public truth differs")
    control = durable / "control"
    if (
        not isinstance(plan["base_v2"], dict)
        or set(plan["base_v2"]) != BASE_V2_KEYS
        or not isinstance(plan["recovery_controls"], dict)
        or set(plan["recovery_controls"]) != RECOVERY_CONTROL_KEYS
        or not isinstance(plan["detached_transport"], dict)
        or set(plan["detached_transport"]) != launcher_v3.DETACHED_TRANSPORT_KEYS
    ):
        raise CausalExecutionV3Error("V3 nested control schema differs")
    _assert_no_symlink_descendant(path, root=durable, label="V3 execution plan")
    for group_name in (
        "base_v2",
        "recovery_controls",
        "tools",
        "implementation_dependencies",
    ):
        group = plan[group_name]
        if not isinstance(group, dict):
            raise CausalExecutionV3Error(f"V3 {group_name} schema differs")
        for name, binding in group.items():
            bound_path = _absolute(binding["path"], f"{group_name}.{name}")
            _assert_no_symlink_descendant(
                bound_path, root=durable, label=f"{group_name}.{name}"
            )
    for name in ("amendment", "structured_preregistration"):
        bound_path = _absolute(plan[name]["path"], f"V3 {name}")
        _assert_no_symlink_descendant(bound_path, root=durable, label=f"V3 {name}")
    base_paths = {
        "execution_plan": control / v2.PLAN_FILENAME,
        "detached_receipt": control / v2.DETACHED_RECEIPT_FILENAME,
        "procfs_exception_inventory": control / v2.EXCEPTION_INVENTORY_FILENAME,
    }
    base = _load_base_v2_controls(
        durable_root=durable,
        plan_path=base_paths["execution_plan"],
        receipt_path=base_paths["detached_receipt"],
        inventory_path=base_paths["procfs_exception_inventory"],
    )
    if (
        base["base_v2_execution_plan"]["causal_checkout_root"] != causal.as_posix()
        or base["base_v2_execution_plan"]["durable_attempt_root"] != durable.as_posix()
    ):
        raise CausalExecutionV3Error("V3 roots differ from base V2 plan")
    for name, fixed_path in base_paths.items():
        _, bound_raw = _validate_binding(
            plan["base_v2"][name], expected_path=fixed_path, label=f"base V2 {name}"
        )
        if bound_raw != base[f"base_v2_{name}_raw"]:
            raise CausalExecutionV3Error(f"base V2 bytes differ: {name}")
    controls = _load_recovery_controls(
        durable_root=durable,
        closure_path=control / FAILURE_CLOSURE_FILENAME,
        fence_path=control / COMPLETION_FENCE_FILENAME,
    )
    for name, fixed_path, raw_key in (
        (
            "v2_failure_closure",
            control / FAILURE_CLOSURE_FILENAME,
            "closure_raw",
        ),
        (
            "v3_completion_fence",
            control / COMPLETION_FENCE_FILENAME,
            "fence_raw",
        ),
    ):
        _, bound_raw = _validate_binding(
            plan["recovery_controls"][name],
            expected_path=fixed_path,
            label=name,
        )
        if bound_raw != controls[raw_key]:
            raise CausalExecutionV3Error(f"recovery bytes differ: {name}")
    _validate_binding(
        plan["amendment"],
        expected_path=tooling / AMENDMENT_FILENAME,
        label="V3 amendment",
    )
    if set(plan["tools"]) != set(TOOL_FILENAMES):
        raise CausalExecutionV3Error("V3 tool manifest differs")
    for name, filename in TOOL_FILENAMES.items():
        _validate_binding(
            plan["tools"][name],
            expected_path=tooling / filename,
            label=f"V3 tool {name}",
        )
    expected_dependencies = DEPENDENCY_FILENAMES
    if set(plan["implementation_dependencies"]) != set(expected_dependencies):
        raise CausalExecutionV3Error("V3 implementation dependency manifest differs")
    for name, filename in expected_dependencies.items():
        _validate_binding(
            plan["implementation_dependencies"][name],
            expected_path=tooling / filename,
            label=f"V3 dependency {name}",
        )
    _validate_binding(
        plan["structured_preregistration"],
        expected_path=tooling / STRUCTURED_PREREGISTRATION_FILENAME,
        label="V3 structured preregistration",
    )
    if plan["branch_adapter_contracts"] != _branch_adapter_contracts(
        tooling=tooling, durable=durable, causal_root=causal
    ):
        raise CausalExecutionV3Error("V3 branch adapter contracts differ")
    invariants = plan["science_invariants"]
    v2_revalidator_inputs = base["base_v2_execution_plan"]["invocations"][
        "revalidator"
    ]["inputs"]
    expected_science = {
        "base_v2_invocations_sha256": canonical_sha256(
            base["base_v2_execution_plan"]["invocations"]
        ),
        "changed": False,
        "estimator_and_thresholds_changed": False,
        "grid": _binding(Path(v2_revalidator_inputs["grid"]), "causal grid"),
        "preregistration": _binding(
            Path(v2_revalidator_inputs["preregistration"]), "causal preregistration"
        ),
        "statistical_addendum": _binding(
            Path(v2_revalidator_inputs["statistical_addendum"]),
            "statistical addendum",
        ),
    }
    if invariants != expected_science:
        raise CausalExecutionV3Error("V3 science invariants differ")
    for name in ("grid", "preregistration", "statistical_addendum"):
        science_path = Path(v2_revalidator_inputs[name])
        _assert_no_symlink_descendant(
            science_path, root=causal, label=f"science {name}"
        )
        _validate_binding(
            invariants[name],
            expected_path=science_path,
            label=f"science {name}",
        )
    expected_topology = _fixed_topology(
        causal_root=causal,
        durable=durable,
        tooling=tooling,
        base_plan=base["base_v2_execution_plan"],
    )
    if plan["invocations"] != expected_topology:
        raise CausalExecutionV3Error("V3 future invocation topology differs")
    for stage, invocation in plan["invocations"].items():
        if set(invocation) != INVOCATION_KEYS:
            raise CausalExecutionV3Error(f"V3 invocation schema differs: {stage}")
        for group_name in ("inputs", "outputs"):
            group = invocation[group_name]
            if not isinstance(group, dict):
                raise CausalExecutionV3Error(
                    f"V3 invocation {group_name} differs: {stage}"
                )
            for name, value in group.items():
                artifact_path = _absolute(value, f"{stage} {group_name} {name}")
                for fixed_root in (durable, causal):
                    try:
                        artifact_path.relative_to(fixed_root)
                    except ValueError:
                        continue
                    _assert_no_symlink_descendant(
                        artifact_path,
                        root=fixed_root,
                        label=f"{stage} {group_name} {name}",
                    )
                    break
                else:
                    raise CausalExecutionV3Error(
                        f"V3 invocation path escapes fixed roots: {stage}.{name}"
                    )
    transport = plan["detached_transport"]
    launcher, handoff, claim, receipt = _transport_paths(
        plan["tooling_source_commit"], durable
    )
    _validate_binding(
        transport["launcher"], expected_path=launcher, label="V3 transport launcher"
    )
    _, handoff_raw = _validate_binding(
        transport["handoff"], expected_path=handoff, label="V3 transport handoff"
    )
    _assert_no_symlink_descendant(
        launcher, root=launcher.parent, label="V3 transport launcher"
    )
    _assert_no_symlink_descendant(
        handoff, root=launcher.parent, label="V3 transport handoff"
    )
    if (
        _strict_json(handoff_raw, "V3 transport handoff")
        != make_detached_handoff(
            tooling_source_commit=plan["tooling_source_commit"],
            causal_checkout_root=causal,
            durable_attempt_root=durable,
        )
        or transport["launch_claim_path"] != claim.as_posix()
        or transport["receipt_path"] != receipt.as_posix()
    ):
        raise CausalExecutionV3Error("V3 detached transport contract differs")
    selected = plan["invocations"][stage]
    normalized_inputs = {
        name: _absolute(value, f"expected {stage} input {name}").as_posix()
        for name, value in expected_inputs.items()
    }
    normalized_outputs = {
        name: _absolute(value, f"expected {stage} output {name}").as_posix()
        for name, value in expected_outputs.items()
    }
    if (
        selected["inputs"] != normalized_inputs
        or selected["outputs"] != normalized_outputs
        or selected["parameters"] != dict(expected_parameters or {})
    ):
        raise CausalExecutionV3Error("actual V3 stage topology differs")
    argv = (
        list(actual_argv)
        if actual_argv is not None
        else [
            Path(sys.executable).resolve().as_posix(),
            _absolute(Path(sys.argv[0]).absolute(), "invoked V3 tool").as_posix(),
            *sys.argv[1:],
        ]
    )
    if argv != selected["argv"]:
        raise CausalExecutionV3Error("actual V3 stage argv differs")
    python_path = runtime_python_path or Path(sys.executable).resolve().as_posix()
    python_version = runtime_python_version or (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    if plan["runtime"] != {
        "python_path": EXPECTED_PYTHON_PATH,
        "python_version": EXPECTED_PYTHON_VERSION,
    } or (python_path, python_version) != (
        EXPECTED_PYTHON_PATH,
        EXPECTED_PYTHON_VERSION,
    ):
        raise CausalExecutionV3Error("actual V3 Python runtime differs")
    return plan, raw


def validate_detached_receipt_document(
    *,
    path: Path,
    plan: Mapping[str, Any],
    plan_raw: bytes,
    expected_runtime_namespace: Mapping[str, Any],
    **live_overrides: Any,
) -> tuple[dict[str, Any], bytes]:
    """Validate the fresh same-PID V3 receipt; V2 receipt remains static-only."""

    receipt_path = _absolute(path, "V3 detached receipt")
    raw = _read_stable(receipt_path, "V3 detached receipt")
    receipt = _strict_json(raw, "V3 detached receipt")
    if set(receipt) != launcher_v3.RECEIPT_KEYS or (
        receipt["protocol"] != DETACHED_RECEIPT_PROTOCOL
        or receipt["schema_version"] != 1
        or receipt["status"] != "ready_to_same_pid_exec_exact_v3_attester"
        or receipt["outcome_blind"] is not True
        or receipt["semantic_artifacts_opened"] is not False
        or receipt["detached_launch_contract"] != launcher_v3.DETACHED_LAUNCH_CONTRACT
        or receipt["minimum_delay_seconds"] != launcher_v3.MINIMUM_DELAY_SECONDS
        or receipt["cwd"] != "/tmp"
        or receipt["ppid"] != 1
        or receipt["tty_nr"] != 0
        or receipt["no_pts_fds"] is not True
    ):
        raise CausalExecutionV3Error("V3 detached receipt contract differs")
    plan_binding = {
        "path": (
            Path(plan["durable_attempt_root"]) / "control" / PLAN_FILENAME
        ).as_posix(),
        "sha256": _sha(plan_raw),
    }
    if receipt["plan"] != plan_binding:
        raise CausalExecutionV3Error("V3 receipt plan binding differs")
    transport = plan["detached_transport"]
    if (
        receipt_path.as_posix() != transport["receipt_path"]
        or receipt["handoff"] != transport["handoff"]
        or receipt["launcher"] != transport["launcher"]
        or receipt["runtime_namespace"] != dict(expected_runtime_namespace)
        or receipt["exec_argv_sha256"]
        != canonical_sha256(plan["invocations"]["attester"]["argv"])
        or receipt["exec_env_sha256"] != canonical_sha256(launcher_v3.EXEC_ENV)
    ):
        raise CausalExecutionV3Error("V3 receipt frozen bindings differ")
    claim_path, claim_raw = _validate_binding(
        receipt["launch_claim"],
        expected_path=_absolute(transport["launch_claim_path"], "claim path"),
        label="V3 launch claim",
    )
    claim = _strict_json(claim_raw, "V3 launch claim")
    ancestors = receipt["startup_ancestors"]
    if (
        set(claim) != launcher_v3.CLAIM_KEYS
        or claim["protocol"] != CLAIM_PROTOCOL
        or claim["schema_version"] != 1
        or claim["status"] != "claimed_once_permanent_no_retry"
        or claim["outcome_blind"] is not True
        or claim["semantic_artifacts_opened"] is not False
        or claim["handoff"] != transport["handoff"]
        or claim["launcher"] != transport["launcher"]
        or claim["plan"] != plan_binding
        or claim["receipt_path"] != receipt_path.as_posix()
        or claim["attester_exec_argv_sha256"] != receipt["exec_argv_sha256"]
        or claim["attester_exec_env_sha256"] != receipt["exec_env_sha256"]
        or not isinstance(ancestors, list)
        or len(ancestors) != 1
        or claim["claimant"] != ancestors[0]
        or receipt["startup_ancestors_sha256"] != canonical_sha256(ancestors)
    ):
        raise CausalExecutionV3Error("V3 one-shot claim binding differs")
    handoff_path, handoff_raw = _validate_binding(
        receipt["handoff"],
        expected_path=Path(transport["handoff"]["path"]),
        label="V3 handoff",
    )
    handoff = _strict_json(handoff_raw, "V3 handoff")
    if (
        set(handoff) != launcher_v3.HANDOFF_KEYS
        or handoff["protocol"] != HANDOFF_PROTOCOL
        or handoff["schema_version"] != 1
        or handoff["status"] != "registered_one_shot"
        or handoff["outcome_blind"] is not True
        or handoff["semantic_artifacts_opened"] is not False
        or handoff["detached_launch_contract"] != launcher_v3.DETACHED_LAUNCH_CONTRACT
        or handoff["attester_argv"] != plan["invocations"]["attester"]["argv"]
        or handoff["plan_path"] != plan_binding["path"]
        or handoff["launch_claim_path"] != claim_path.as_posix()
        or handoff["receipt_path"] != receipt_path.as_posix()
        or handoff["launcher"] != transport["launcher"]
        or claim["launcher_argv_sha256"] != canonical_sha256(handoff["launcher_argv"])
    ):
        raise CausalExecutionV3Error("V3 handoff/claim exact binding differs")
    _validate_binding(
        receipt["launcher"],
        expected_path=Path(transport["launcher"]["path"]),
        label="V3 launcher",
    )
    if (
        set(ancestors[0]) != launcher_v3.ANCESTOR_RECORD_KEYS
        or not isinstance(ancestors[0]["pid"], int)
        or isinstance(ancestors[0]["pid"], bool)
        or ancestors[0]["pid"] <= 1
        or not isinstance(ancestors[0]["start_ticks"], int)
        or isinstance(ancestors[0]["start_ticks"], bool)
        or ancestors[0]["start_ticks"] <= 0
        or not isinstance(receipt["pid"], int)
        or isinstance(receipt["pid"], bool)
        or receipt["pid"] <= 1
        or not isinstance(receipt["process_start_ticks"], int)
        or isinstance(receipt["process_start_ticks"], bool)
        or receipt["process_start_ticks"] <= 0
        or receipt["session_id"] != receipt["pid"]
        or receipt["process_group_id"] != receipt["pid"]
        or receipt["clock_ticks_per_second"] <= 0
        or receipt["observed_age_ticks"]
        < launcher_v3.MINIMUM_DELAY_SECONDS * receipt["clock_ticks_per_second"]
        or receipt["stdio_targets_sha256"]
        != canonical_sha256(["/dev/null", "/dev/null", "/dev/null"])
    ):
        raise CausalExecutionV3Error("V3 static detached receipt proof differs")

    if live_overrides.pop("validate_live", True) is False:
        process_gone_fn = live_overrides.pop(
            "process_gone_fn", _assert_process_identity_gone
        )
        if live_overrides:
            raise CausalExecutionV3Error("unused static receipt validation override")
        process_gone_fn(receipt["pid"], receipt["process_start_ticks"])
        return receipt, raw

    def default_identity() -> tuple[int, int, int, int, int, int]:
        pid, ppid, start_ticks, tty_nr, _ = launcher_v3._proc_identity()
        clock_ticks = os.sysconf("SC_CLK_TCK")
        age = launcher_v3._uptime_ticks(clock_ticks) - start_ticks
        return pid, ppid, start_ticks, tty_nr, clock_ticks, age

    def default_stdio() -> tuple[list[str], bool]:
        try:
            targets = [os.readlink(f"/proc/self/fd/{item}") for item in (0, 1, 2)]
            no_pts = True
            for entry in Path("/proc/self/fd").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    target = os.readlink(entry)
                except FileNotFoundError:
                    continue
                if target.startswith("/dev/pts"):
                    no_pts = False
        except OSError as exc:
            raise CausalExecutionV3Error("cannot inspect live V3 stdio") from exc
        return targets, no_pts

    identity_fn = live_overrides.get("proc_identity_fn", default_identity)
    getppid_fn = live_overrides.get("getppid_fn", os.getppid)
    getcwd_fn = live_overrides.get("getcwd_fn", os.getcwd)
    getsid_fn = live_overrides.get("getsid_fn", os.getsid)
    getpgrp_fn = live_overrides.get("getpgrp_fn", os.getpgrp)
    namespace_fn = live_overrides.get(
        "runtime_namespace_fn", launcher_v3._runtime_namespace_identity
    )
    environ_fn = live_overrides.get("environ_fn", lambda: dict(os.environ))
    cmdline_fn = live_overrides.get(
        "cmdline_fn", lambda: Path("/proc/self/cmdline").read_bytes()
    )
    stdio_fn = live_overrides.get("stdio_fn", default_stdio)
    parent_gone_fn = live_overrides.get(
        "startup_parent_gone_fn", launcher_v3._assert_startup_parent_gone
    )
    pid, ppid, start_ticks, tty_nr, clock_ticks, age_ticks = identity_fn()
    targets, no_pts = stdio_fn()
    parent_gone_fn(ancestors[0])
    attester_argv = plan["invocations"]["attester"]["argv"]
    if (
        (pid, ppid, start_ticks, tty_nr)
        != (
            receipt["pid"],
            receipt["ppid"],
            receipt["process_start_ticks"],
            receipt["tty_nr"],
        )
        or getppid_fn() != 1
        or getcwd_fn() != "/tmp"
        or getsid_fn(0) != receipt["session_id"]
        or receipt["session_id"] <= 1
        or getpgrp_fn() != receipt["process_group_id"]
        or receipt["session_id"] != pid
        or receipt["process_group_id"] != pid
        or clock_ticks != receipt["clock_ticks_per_second"]
        or age_ticks < receipt["observed_age_ticks"]
        or receipt["observed_age_ticks"]
        < launcher_v3.MINIMUM_DELAY_SECONDS * clock_ticks
        or namespace_fn() != dict(expected_runtime_namespace)
        or environ_fn() != launcher_v3.EXEC_ENV
        or cmdline_fn()
        != b"\0".join(item.encode("utf-8") for item in attester_argv) + b"\0"
        or targets != ["/dev/null", "/dev/null", "/dev/null"]
        or no_pts is not True
        or receipt["stdio_targets_sha256"] != canonical_sha256(targets)
    ):
        raise CausalExecutionV3Error("fresh V3 same-PID live receipt proof differs")
    if claim_path != Path(transport["launch_claim_path"]) or handoff_path != Path(
        transport["handoff"]["path"]
    ):
        raise CausalExecutionV3Error("V3 claim path differs from plan")
    return receipt, raw


def _assert_process_identity_gone(
    pid: int, start_ticks: int, *, proc_root: Path = Path("/proc")
) -> None:
    try:
        _, observed_start, _, _ = launcher_v3._parse_stat(
            (proc_root / str(pid) / "stat").read_bytes()
        )
    except FileNotFoundError:
        return
    if observed_start == start_ticks:
        raise CausalExecutionV3Error("V3 detached receipt process remains live")


def validate_detached_receipt_static_document(
    *,
    path: Path,
    plan: Mapping[str, Any],
    plan_raw: bytes,
    expected_runtime_namespace: Mapping[str, Any],
    process_gone_fn: Any = _assert_process_identity_gone,
) -> tuple[dict[str, Any], bytes]:
    """Validate immutable V3 receipt/claim bytes after its exact PID has gone."""

    return validate_detached_receipt_document(
        path=path,
        plan=plan,
        plan_raw=plan_raw,
        expected_runtime_namespace=expected_runtime_namespace,
        validate_live=False,
        process_gone_fn=process_gone_fn,
    )


def validate_authoritative_v3_control_chain(
    *,
    execution_plan_path: Path,
    base_v2_execution_plan_path: Path,
    base_v2_detached_receipt_path: Path,
    base_v2_procfs_exception_inventory_path: Path,
    v2_failure_closure_path: Path,
    completion_fence_path: Path,
    detached_launch_receipt_path: Path,
) -> dict[str, Any]:
    """Validate and return the complete authoritative, outcome-blind chain.

    The stable return keys consumed by the V3 attester include ``plan_raw``,
    ``closure_raw``, ``fence_raw``, ``receipt``, ``receipt_raw``, and
    ``base_v2_procfs_exception_inventory_raw``.
    """

    plan_path = _absolute(execution_plan_path, "V3 execution plan")
    plan, plan_raw = _load_plan_document(plan_path)
    attester_invocation = plan.get("invocations", {}).get("attester")
    if (
        not isinstance(attester_invocation, dict)
        or set(attester_invocation) != INVOCATION_KEYS
    ):
        raise CausalExecutionV3Error("V3 attester invocation schema differs")
    validated_plan, validated_raw = load_and_validate_execution_plan_stage(
        execution_plan_path=plan_path,
        stage="attester",
        expected_inputs=attester_invocation["inputs"],
        expected_outputs=attester_invocation["outputs"],
        expected_parameters=attester_invocation["parameters"],
        actual_argv=attester_invocation["argv"],
        runtime_python_path=EXPECTED_PYTHON_PATH,
        runtime_python_version=EXPECTED_PYTHON_VERSION,
    )
    if validated_plan != plan or validated_raw != plan_raw:
        raise CausalExecutionV3Error("V3 plan drifted during chain validation")
    durable = _absolute(plan["durable_attempt_root"], "V3 durable root")
    base_paths = {
        "execution_plan": _absolute(
            base_v2_execution_plan_path, "base V2 execution plan"
        ),
        "detached_receipt": _absolute(
            base_v2_detached_receipt_path, "base V2 detached receipt"
        ),
        "procfs_exception_inventory": _absolute(
            base_v2_procfs_exception_inventory_path, "base V2 procfs inventory"
        ),
    }
    base = _load_base_v2_controls(
        durable_root=durable,
        plan_path=base_paths["execution_plan"],
        receipt_path=base_paths["detached_receipt"],
        inventory_path=base_paths["procfs_exception_inventory"],
    )
    for name, path in base_paths.items():
        raw = base[f"base_v2_{name}_raw"]
        if plan["base_v2"][name] != {
            "path": path.as_posix(),
            "sha256": _sha(raw),
        }:
            raise CausalExecutionV3Error(f"V3 plan base V2 binding differs: {name}")
    closure_path = _absolute(v2_failure_closure_path, "V2 failure closure")
    fence_path = _absolute(completion_fence_path, "V3 completion fence")
    controls = _load_recovery_controls(
        durable_root=durable,
        closure_path=closure_path,
        fence_path=fence_path,
    )
    if plan["recovery_controls"] != {
        "v2_failure_closure": {
            "path": closure_path.as_posix(),
            "sha256": _sha(controls["closure_raw"]),
        },
        "v3_completion_fence": {
            "path": fence_path.as_posix(),
            "sha256": _sha(controls["fence_raw"]),
        },
    }:
        raise CausalExecutionV3Error("V3 plan recovery-control bindings differ")
    closure = controls["closure"]
    fence = controls["fence"]
    expected_base_bindings = {
        "v2_execution_plan": (
            base_paths["execution_plan"],
            base["base_v2_execution_plan_raw"],
        ),
        "v2_detached_launch_receipt": (
            base_paths["detached_receipt"],
            base["base_v2_detached_receipt_raw"],
        ),
        "v2_procfs_exception_inventory": (
            base_paths["procfs_exception_inventory"],
            base["base_v2_procfs_exception_inventory_raw"],
        ),
    }
    for document in (closure, fence):
        for key, (path, raw) in expected_base_bindings.items():
            if document[key]["path"] != path.as_posix() or document[key][
                "sha256"
            ] != _sha(raw):
                raise CausalExecutionV3Error(
                    f"recovery control base binding differs: {key}"
                )
    inventory = base["base_v2_procfs_exception_inventory"]
    receipt, receipt_raw = validate_detached_receipt_document(
        path=_absolute(detached_launch_receipt_path, "fresh V3 detached receipt"),
        plan=plan,
        plan_raw=plan_raw,
        expected_runtime_namespace=inventory["runtime_namespace"],
    )
    return {
        "base_v2_detached_receipt": base["base_v2_detached_receipt"],
        "base_v2_detached_receipt_raw": base["base_v2_detached_receipt_raw"],
        "base_v2_execution_plan": base["base_v2_execution_plan"],
        "base_v2_execution_plan_raw": base["base_v2_execution_plan_raw"],
        "base_v2_procfs_exception_inventory": inventory,
        "base_v2_procfs_exception_inventory_raw": base[
            "base_v2_procfs_exception_inventory_raw"
        ],
        "closure": closure,
        "closure_raw": controls["closure_raw"],
        "fence": fence,
        "fence_inventory_files": controls["fence_inventory_files"],
        "fence_raw": controls["fence_raw"],
        "plan": plan,
        "plan_raw": plan_raw,
        "receipt": receipt,
        "receipt_raw": receipt_raw,
        "semantic_open_sentinel": {
            "base_v2_receipt_live_validated": False,
            "efficacy_artifacts_parsed": False,
            "fresh_v3_receipt_same_pid_validated": True,
            "recovery_controls_validated": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("handoff", "plan"), required=True)
    parser.add_argument("--tooling-source-commit", required=True)
    parser.add_argument("--causal-checkout-root", type=Path, required=True)
    parser.add_argument("--durable-attempt-root", type=Path, required=True)
    parser.add_argument("--created-at-utc")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode == "handoff":
            if args.created_at_utc is not None:
                raise CausalExecutionV3Error("handoff mode forbids created-at-utc")
            handoff = make_detached_handoff(
                tooling_source_commit=args.tooling_source_commit,
                causal_checkout_root=args.causal_checkout_root,
                durable_attempt_root=args.durable_attempt_root,
            )
            publish_detached_handoff_no_overwrite(args.output, handoff)
        else:
            if args.created_at_utc is None:
                raise CausalExecutionV3Error("plan mode requires created-at-utc")
            plan = make_execution_plan(
                tooling_source_commit=args.tooling_source_commit,
                causal_checkout_root=args.causal_checkout_root,
                durable_attempt_root=args.durable_attempt_root,
                created_at_utc=args.created_at_utc,
            )
            publish_execution_plan_no_overwrite(args.output, plan)
    except (CausalExecutionV3Error, FileExistsError, OSError) as exc:
        raise SystemExit(f"V3 execution-control build failed: {exc}") from exc
    print(json.dumps({"status": "complete"}, sort_keys=True))


if __name__ == "__main__":
    main()
