#!/usr/bin/env python3
"""Self-contained, side-effect-free prospective online-ICL integrity validator.

This module uses only the Python standard library.  It cannot launch or manage
processes and does not import any repository-local module.  It validates the
fixed contract -> local expectation -> prospective plan byte chain and returns
an explicitly launch-disabled, local-integrity-only specification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


CONTRACT_RELATIVE_PATH = Path("control/online_icl_formal_wrapper_contract.json")
EXPECTATION_RELATIVE_PATH = Path("control/online_icl_formal_contract_expectation.json")
PLAN_RELATIVE_PATH = Path("control/online_icl_formal_prospective_execution_plan.json")
LAUNCH_INVENTORY_RELATIVE_PATH = Path("control/online_icl_formal_launch_inventory.json")
PID_RELATIVE_PATH = Path("prep/online_icl_formal_wrapper.pid")
LOCK_RELATIVE_PATH = Path("prep/online_icl_formal_wrapper.lock")
EXIT_RELATIVE_PATH = Path("prep/online_icl_formal_wrapper.exit.json")
MARKER_RELATIVE_PATH = Path("prep/online_icl_formal_completion_marker.json")
CONTRACT_PROTOCOL = "cohort_online_icl_formal_wrapper_contract_v1"
EXPECTATION_PROTOCOL = "cohort_online_icl_formal_contract_expectation_v1"
PLAN_PROTOCOL = "cohort_online_icl_formal_prospective_execution_plan_v1"
RUNTIME_PROTOCOL = "cohort_online_icl_formal_local_integrity_validator_v1"
ANCHOR_SCOPE = "local_one_way_integrity_not_external_authorization"
CHECKOUT_GIT_AUTHORIZATION_SCOPE = (
    "checkout_outcome_only_not_git_executable_hash_authorization"
)
ONLINE_SOURCE_COMMIT = "eaa6a68a1c707b4fd92619dfcc4eb53f1cd6b08e"
PAIRED_CAUSAL_SOURCE_COMMIT = "1caf142f6ce611da8da8691d4c336388a4c3c4b3"
SCHEMA_VERSION = 1
PRODUCTION_BLOCKERS = (
    "descriptor-relative openat ancestor-swap proof",
    "hardlink-safe immutable-input proof",
    "orphan-safe child lifetime and wait proof",
    "opaque launch inventory and atomic completion-marker publication",
    "external authorization anchor",
    "real causal artifact integration and semantic attester/revalidator replay",
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_CONTRACT_KEYS = frozenset(
    {
        "artifact_mappings",
        "artifact_root",
        "canonicalization",
        "causal_chain_binding",
        "checkout_git_state",
        "contract_sha256",
        "created_at_utc",
        "direct_input_layout",
        "direct_inputs",
        "durable_attempt_root",
        "exact_formal_argv",
        "exact_formal_argv_sha256",
        "fixed_paths",
        "online_attempt_checkout",
        "online_source_commit",
        "paired_causal_attempt_checkout",
        "paired_causal_durable_attempt_root",
        "paired_causal_source_commit",
        "protocol",
        "runtime",
        "schema_version",
        "source_files",
        "tooling_source_commit",
        "wrapper_tooling_root",
    }
)
_SOURCE_NAMES = frozenset({"contract_builder", "online_launcher", "runtime_wrapper"})
_FILE_RECORD_KEYS = frozenset({"path", "sha256", "size_bytes"})
_FIXED_PATH_KEYS = frozenset(
    {
        "completion_marker",
        "contract",
        "contract_expectation",
        "exit_record",
        "launch_inventory",
        "lifetime_lock",
        "pid_file",
        "prospective_execution_plan",
    }
)
_CHECKOUT_GIT_STATE_KEYS = frozenset({"authorization_scope", "online", "paired_causal"})
_CHECKOUT_GIT_ENTRY_KEYS = frozenset({"source_commit", "tracked_checkout_clean"})
_DIRECT_INPUT_LAYOUT_KEYS = frozenset({"relative_path", "root"})
_DIRECT_INPUT_RELATIVE_PATHS = {
    "causal_completion_attestation": "prep/causal_trigger_completion_attestation.json",
    "causal_decision": "artifacts/cohort_causal/formal_decision.json",
    "causal_launch_expectation": (
        "control/CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json"
    ),
    "causal_manifest": "artifacts/cohort_causal/formal_manifest.json",
    "causal_provenance": "artifacts/cohort_causal/provenance.json",
    "causal_provenance_details": "artifacts/cohort_causal/provenance.details.json",
    "causal_revalidated_decision": "prep/causal_formal.revalidated.json",
    "causal_revalidation_receipt": ("prep/causal_formal.revalidation_receipt.json"),
    "causal_smoke_gate": "artifacts/cohort_causal/smoke_gate.json",
    "causal_terminal_execution_plan": (
        "control/CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN.json"
    ),
    "icl_smoke_gate": "artifacts/cohort_online_icl/smoke_gate.json",
    "online_provenance": "meta/provenance.json",
    "online_provenance_details": "meta/provenance.details.json",
    "protocol_seal": "meta/protocol_seal.json",
}
_DIRECT_INPUT_NAMES = frozenset(_DIRECT_INPUT_RELATIVE_PATHS)
_EXPECTATION_KEYS = frozenset(
    {
        "anchor_scope",
        "contract_canonical_sha256",
        "contract_file_sha256",
        "contract_path",
        "created_at_utc",
        "expectation_sha256",
        "protocol",
        "schema_version",
        "tooling_source_commit",
    }
)
_PLAN_KEYS = frozenset(
    {
        "anchor_scope",
        "contract_canonical_sha256",
        "contract_expectation_file_sha256",
        "contract_expectation_path",
        "contract_file_sha256",
        "contract_path",
        "created_at_utc",
        "exact_formal_argv",
        "exact_formal_argv_sha256",
        "launch_authorized",
        "plan_sha256",
        "production_blockers",
        "protocol",
        "runtime_sha256",
        "schema_version",
        "source_files",
        "tooling_source_commit",
    }
)


class WrapperError(RuntimeError):
    """A fail-closed local integrity validation error."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WrapperError("value is not canonical JSON") from exc


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, nested in pairs:
        if key in value:
            raise WrapperError("JSON contains a duplicate key")
        value[key] = nested
    return value


def _reject_nonfinite(value: str) -> None:
    raise WrapperError(f"JSON contains non-finite value {value}")


def _load_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WrapperError(f"{label} is not duplicate-free JSON") from exc
    if not isinstance(value, dict):
        raise WrapperError(f"{label} must be a JSON object")
    return value


def _absolute(path: Path, *, label: str) -> Path:
    raw = os.fspath(path.expanduser())
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise WrapperError(f"{label} must be a normalized absolute path")
    return Path(raw)


def _read_stable(path: Path, *, label: str) -> bytes:
    absolute = _absolute(path, label=label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise WrapperError(f"cannot open {label}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise WrapperError(f"{label} is not one single-link regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (  # noqa: E731
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
    )
    linked = os.lstat(absolute)
    if (
        not stat.S_ISREG(before.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or before.st_nlink != 1
        or after.st_nlink != 1
        or linked.st_nlink != 1
        or identity(before) != identity(after)
        or identity(after) != identity(linked)
    ):
        raise WrapperError(f"{label} is not one stable single-link regular file")
    return b"".join(chunks)


def _read_canonical_readonly(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_stable(path, label=label)
    value = _load_object(raw, label=label)
    if raw != _canonical_bytes(value) + b"\n":
        raise WrapperError(f"{label} is not canonical JSON")
    if stat.S_IMODE(os.lstat(path).st_mode) != 0o444:
        raise WrapperError(f"{label} mode must be exactly 0444")
    return value, raw


def _require_keys(value: Any, expected: frozenset[str], *, label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise WrapperError(f"{label} exact-key schema differs")


def _require_sha(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise WrapperError(f"{label} is not lowercase SHA-256")
    return value


def _require_commit(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise WrapperError(f"{label} is not a lowercase Git commit")
    return value


def _verify_file_record(
    value: Any, *, label: str, expected_path: Path
) -> dict[str, Any]:
    _require_keys(value, _FILE_RECORD_KEYS, label=label)
    assert isinstance(value, dict)
    if not isinstance(value["path"], str):
        raise WrapperError(f"{label}.path is not a string")
    path = _absolute(Path(value["path"]), label=f"{label}.path")
    if path != expected_path:
        raise WrapperError(f"{label}.path differs from fixed location")
    digest = _require_sha(value["sha256"], label=f"{label}.sha256")
    size = value["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise WrapperError(f"{label}.size_bytes is invalid")
    raw = _read_stable(path, label=label)
    if digest != hashlib.sha256(raw).hexdigest() or size != len(raw):
        raise WrapperError(f"{label} bytes differ")
    return value


def validate_prospective_launch_spec(contract_path: Path) -> dict[str, Any]:
    """Validate local bytes and return an explicitly unauthorized specification."""

    supplied = _absolute(contract_path, label="contract path")
    durable_root = supplied.parent.parent
    if supplied != durable_root / CONTRACT_RELATIVE_PATH:
        raise WrapperError("contract path differs from fixed location")
    expectation_path = durable_root / EXPECTATION_RELATIVE_PATH
    plan_path = durable_root / PLAN_RELATIVE_PATH
    contract, contract_raw = _read_canonical_readonly(supplied, label="contract")
    _require_keys(contract, _CONTRACT_KEYS, label="contract")
    if (
        contract["protocol"] != CONTRACT_PROTOCOL
        or contract["schema_version"] != SCHEMA_VERSION
    ):
        raise WrapperError("contract protocol/schema differs")
    embedded_contract_sha = _require_sha(
        contract["contract_sha256"], label="contract SHA-256"
    )
    unsigned_contract = dict(contract)
    unsigned_contract.pop("contract_sha256")
    if embedded_contract_sha != _canonical_sha256(unsigned_contract):
        raise WrapperError("contract self-digest differs")
    if contract["durable_attempt_root"] != durable_root.as_posix():
        raise WrapperError("contract durable root differs")
    fixed = contract["fixed_paths"]
    _require_keys(fixed, _FIXED_PATH_KEYS, label="contract fixed paths")
    expected_fixed = {
        "completion_marker": (durable_root / MARKER_RELATIVE_PATH).as_posix(),
        "contract": supplied.as_posix(),
        "contract_expectation": expectation_path.as_posix(),
        "exit_record": (durable_root / EXIT_RELATIVE_PATH).as_posix(),
        "launch_inventory": (durable_root / LAUNCH_INVENTORY_RELATIVE_PATH).as_posix(),
        "lifetime_lock": (durable_root / LOCK_RELATIVE_PATH).as_posix(),
        "pid_file": (durable_root / PID_RELATIVE_PATH).as_posix(),
        "prospective_execution_plan": plan_path.as_posix(),
    }
    if fixed != expected_fixed:
        raise WrapperError("contract fixed control paths differ")
    tooling_commit = _require_commit(
        contract["tooling_source_commit"], label="contract tooling commit"
    )
    online_root = _absolute(
        Path(contract["online_attempt_checkout"]), label="online checkout"
    )
    _absolute(Path(contract["paired_causal_attempt_checkout"]), label="causal checkout")
    causal_durable_root = _absolute(
        Path(contract["paired_causal_durable_attempt_root"]),
        label="causal durable root",
    )
    tooling_root = _absolute(
        Path(contract["wrapper_tooling_root"]), label="wrapper tooling root"
    )
    if tooling_root != durable_root / "control" / "wrapper" / tooling_commit:
        raise WrapperError("wrapper tooling root differs from fixed location")
    if (
        contract["online_source_commit"] != ONLINE_SOURCE_COMMIT
        or contract["paired_causal_source_commit"] != PAIRED_CAUSAL_SOURCE_COMMIT
    ):
        raise WrapperError("contract checkout commit differs")
    checkout_state = contract["checkout_git_state"]
    _require_keys(checkout_state, _CHECKOUT_GIT_STATE_KEYS, label="checkout Git state")
    expected_checkout_state = {
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
    for name in ("online", "paired_causal"):
        _require_keys(
            checkout_state[name],
            _CHECKOUT_GIT_ENTRY_KEYS,
            label=f"checkout Git state {name}",
        )
    if checkout_state != expected_checkout_state:
        raise WrapperError("checkout Git-state binding differs")
    if contract["canonicalization"] != {
        "allow_nan": False,
        "encoding": "utf-8",
        "separators": [",", ":"],
        "sort_keys": True,
        "trailing_newline": True,
    }:
        raise WrapperError("contract canonicalization differs")
    argv = contract["exact_formal_argv"]
    if (
        not isinstance(argv, list)
        or any(not isinstance(item, str) or not item for item in argv)
        or contract["exact_formal_argv_sha256"] != _canonical_sha256(argv)
    ):
        raise WrapperError("contract exact argv binding differs")
    _require_keys(contract["source_files"], _SOURCE_NAMES, label="source files")
    expected_source_paths = {
        "contract_builder": tooling_root
        / "build_cohort_online_icl_formal_wrapper_contract.py",
        "online_launcher": online_root / "launch_cohort_online_icl.sh",
        "runtime_wrapper": tooling_root / "run_cohort_online_icl_formal_wrapper.py",
    }
    for name in sorted(_SOURCE_NAMES):
        _verify_file_record(
            contract["source_files"][name],
            label=f"source {name}",
            expected_path=expected_source_paths[name],
        )
    direct_inputs = contract["direct_inputs"]
    _require_keys(direct_inputs, _DIRECT_INPUT_NAMES, label="contract direct inputs")
    direct_layout = contract["direct_input_layout"]
    _require_keys(
        direct_layout, _DIRECT_INPUT_NAMES, label="contract direct-input layout"
    )
    for name in sorted(_DIRECT_INPUT_NAMES):
        causal_input = name.startswith("causal_")
        expected_root_name = (
            "paired_causal_durable_attempt_root"
            if causal_input
            else "durable_attempt_root"
        )
        expected_root = causal_durable_root if causal_input else durable_root
        expected_relative = _DIRECT_INPUT_RELATIVE_PATHS[name]
        _require_keys(
            direct_layout[name],
            _DIRECT_INPUT_LAYOUT_KEYS,
            label=f"direct-input layout {name}",
        )
        if direct_layout[name] != {
            "relative_path": expected_relative,
            "root": expected_root_name,
        }:
            raise WrapperError(f"direct-input layout differs: {name}")
        _verify_file_record(
            direct_inputs[name],
            label=f"direct input {name}",
            expected_path=expected_root / expected_relative,
        )
    causal_binding = contract["causal_chain_binding"]
    required_gate = {
        "decision": "pass",
        "decision_scope": "internal_gate_pass",
        "status": "valid",
    }
    if (
        not isinstance(causal_binding, dict)
        or causal_binding.get("status") != "synthetic_shape_only"
        or causal_binding.get("semantic_revalidation_status")
        != "not_semantically_revalidated"
        or causal_binding.get("hard_gate") != required_gate
        or causal_binding.get("decision") != "pass"
        or causal_binding.get("decision_scope") != "internal_gate_pass"
        or causal_binding.get("decision_status") != "valid"
    ):
        raise WrapperError("contract causal synthetic hard-gate binding differs")
    executing_path = _absolute(Path(__file__), label="executing runtime path")
    if executing_path.as_posix() != contract["source_files"]["runtime_wrapper"]["path"]:
        raise WrapperError("executing runtime path differs from contract")

    expectation, expectation_raw = _read_canonical_readonly(
        expectation_path, label="contract expectation"
    )
    _require_keys(expectation, _EXPECTATION_KEYS, label="contract expectation")
    if (
        expectation["protocol"] != EXPECTATION_PROTOCOL
        or expectation["schema_version"] != SCHEMA_VERSION
        or expectation["anchor_scope"] != ANCHOR_SCOPE
        or expectation["contract_path"] != supplied.as_posix()
        or expectation["contract_file_sha256"]
        != hashlib.sha256(contract_raw).hexdigest()
        or expectation["contract_canonical_sha256"] != embedded_contract_sha
        or expectation["tooling_source_commit"] != tooling_commit
    ):
        raise WrapperError("contract expectation binding differs")
    _require_commit(
        expectation["tooling_source_commit"], label="expectation tooling commit"
    )
    expectation_sha = _require_sha(
        expectation["expectation_sha256"], label="expectation SHA-256"
    )
    unsigned_expectation = dict(expectation)
    unsigned_expectation.pop("expectation_sha256")
    if expectation_sha != _canonical_sha256(unsigned_expectation):
        raise WrapperError("contract expectation self-digest differs")

    plan, plan_raw = _read_canonical_readonly(plan_path, label="prospective plan")
    _require_keys(plan, _PLAN_KEYS, label="prospective plan")
    if (
        plan["protocol"] != PLAN_PROTOCOL
        or plan["schema_version"] != SCHEMA_VERSION
        or plan["anchor_scope"] != ANCHOR_SCOPE
        or plan["launch_authorized"] is not False
        or plan["production_blockers"] != list(PRODUCTION_BLOCKERS)
        or plan["contract_path"] != supplied.as_posix()
        or plan["contract_expectation_path"] != expectation_path.as_posix()
        or plan["contract_file_sha256"] != hashlib.sha256(contract_raw).hexdigest()
        or plan["contract_expectation_file_sha256"]
        != hashlib.sha256(expectation_raw).hexdigest()
        or plan["contract_canonical_sha256"] != embedded_contract_sha
        or plan["source_files"] != contract["source_files"]
        or plan["exact_formal_argv"] != argv
        or plan["exact_formal_argv_sha256"] != contract["exact_formal_argv_sha256"]
        or plan["runtime_sha256"] != _canonical_sha256(contract["runtime"])
        or plan["tooling_source_commit"] != contract["tooling_source_commit"]
    ):
        raise WrapperError("prospective plan binding/state differs")
    plan_sha = _require_sha(plan["plan_sha256"], label="prospective plan SHA-256")
    _require_commit(plan["tooling_source_commit"], label="plan tooling commit")
    unsigned_plan = dict(plan)
    unsigned_plan.pop("plan_sha256")
    if plan_sha != _canonical_sha256(unsigned_plan):
        raise WrapperError("prospective plan self-digest differs")
    return {
        "anchor_scope": ANCHOR_SCOPE,
        "contract_sha256": embedded_contract_sha,
        "exact_formal_argv": argv,
        "exact_formal_argv_sha256": contract["exact_formal_argv_sha256"],
        "launch_authorized": False,
        "local_integrity_only": True,
        "production_blockers": list(PRODUCTION_BLOCKERS),
        "prospective_plan_file_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "prospective_plan_sha256": plan_sha,
        "protocol": RUNTIME_PROTOCOL,
        "runtime": contract["runtime"],
        "runtime_sha256": _canonical_sha256(contract["runtime"]),
        "status": "local_integrity_only",
    }


def run_registered_formal(*_args: Any, **_kwargs: Any) -> None:
    """Reject every launch attempt before inspecting arguments."""

    raise WrapperError("production formal execution is hard-disabled")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    args = parser.parse_args()
    print(_canonical_bytes(validate_prospective_launch_spec(args.contract)).decode())


if __name__ == "__main__":
    main()
