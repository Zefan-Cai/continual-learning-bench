#!/usr/bin/env python3
"""Build or strictly verify the prospective online-ICL formal wrapper contract.

This module is outcome-blind.  It reads only the wrapper tooling, the sealed
launcher, and direct launcher inputs as opaque bytes.  It never opens any
online-ICL result.  The runtime wrapper and completion marker are deliberately
implemented elsewhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


PROTOCOL = "cohort_online_icl_formal_wrapper_contract_v1"
SCHEMA_VERSION = 1
WRAPPER_FILENAME = "run_cohort_online_icl_formal_wrapper.py"
BUILDER_FILENAME = "build_cohort_online_icl_formal_wrapper_contract.py"
LAUNCHER_FILENAME = "launch_cohort_online_icl.sh"
FORMAL_GPU_CSV = "0,2,3"
MAX_USED_MEMORY_MIB = "1024"
ONLINE_SOURCE_COMMIT = "eaa6a68a1c707b4fd92619dfcc4eb53f1cd6b08e"
PAIRED_CAUSAL_SOURCE_COMMIT = "1caf142f6ce611da8da8691d4c336388a4c3c4b3"

CONTRACT_RELATIVE_PATH = Path("control/online_icl_formal_wrapper_contract.json")
LAUNCH_INVENTORY_RELATIVE_PATH = Path("control/online_icl_formal_launch_inventory.json")
PID_RELATIVE_PATH = Path("prep/online_icl_formal_wrapper.pid")
LOCK_RELATIVE_PATH = Path("prep/online_icl_formal_wrapper.lock")
EXIT_RELATIVE_PATH = Path("prep/online_icl_formal_wrapper.exit.json")
MARKER_RELATIVE_PATH = Path("prep/online_icl_formal_completion_marker.json")
ARTIFACT_RELATIVE_PATH = Path("artifacts/cohort_online_icl")
CONTRACT_EXPECTATION_RELATIVE_PATH = Path(
    "control/online_icl_formal_contract_expectation.json"
)
CONTRACT_EXPECTATION_PROTOCOL = "cohort_online_icl_formal_contract_expectation_v1"
PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH = Path(
    "control/online_icl_formal_prospective_execution_plan.json"
)
PROSPECTIVE_EXECUTION_PLAN_PROTOCOL = (
    "cohort_online_icl_formal_prospective_execution_plan_v1"
)
LOCAL_INTEGRITY_ANCHOR_SCOPE = "local_one_way_integrity_not_external_authorization"
CHECKOUT_GIT_AUTHORIZATION_SCOPE = (
    "checkout_outcome_only_not_git_executable_hash_authorization"
)
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
_UTC_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z"
)

DIRECT_INPUT_NAMES = (
    "causal_completion_attestation",
    "causal_decision",
    "causal_launch_expectation",
    "causal_manifest",
    "causal_provenance",
    "causal_provenance_details",
    "causal_revalidated_decision",
    "causal_revalidation_receipt",
    "causal_smoke_gate",
    "causal_terminal_execution_plan",
    "icl_smoke_gate",
    "online_provenance",
    "online_provenance_details",
    "protocol_seal",
)
CAUSAL_DURABLE_INPUT_NAMES = tuple(
    name for name in DIRECT_INPUT_NAMES if name.startswith("causal_")
)
ONLINE_DURABLE_INPUT_NAMES = tuple(
    name for name in DIRECT_INPUT_NAMES if not name.startswith("causal_")
)
DIRECT_INPUT_RELATIVE_PATHS = {
    "causal_completion_attestation": Path(
        "prep/causal_trigger_completion_attestation.json"
    ),
    "causal_decision": Path("artifacts/cohort_causal/formal_decision.json"),
    "causal_launch_expectation": Path(
        "control/CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json"
    ),
    "causal_manifest": Path("artifacts/cohort_causal/formal_manifest.json"),
    "causal_provenance": Path("artifacts/cohort_causal/provenance.json"),
    "causal_provenance_details": Path(
        "artifacts/cohort_causal/provenance.details.json"
    ),
    "causal_revalidated_decision": Path("prep/causal_formal.revalidated.json"),
    "causal_revalidation_receipt": Path("prep/causal_formal.revalidation_receipt.json"),
    "causal_smoke_gate": Path("artifacts/cohort_causal/smoke_gate.json"),
    "causal_terminal_execution_plan": Path(
        "control/CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN.json"
    ),
    "icl_smoke_gate": Path("artifacts/cohort_online_icl/smoke_gate.json"),
    "online_provenance": Path("meta/provenance.json"),
    "online_provenance_details": Path("meta/provenance.details.json"),
    "protocol_seal": Path("meta/protocol_seal.json"),
}
if set(DIRECT_INPUT_RELATIVE_PATHS) != set(DIRECT_INPUT_NAMES):
    raise AssertionError("direct-input relative-path map drift")

FORBIDDEN_ENVIRONMENT_KEYS = (
    "BASH_ENV",
    "ENV",
    "LD_PRELOAD",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
)
RUNTIME_COMMAND_NAMES = (
    "bash",
    "dirname",
    "env",
    "git",
    "mkdir",
    "nvidia-smi",
    "python",
    "sort",
    "tr",
    "wc",
)

_TOP_LEVEL_KEYS = frozenset(
    {
        "artifact_root",
        "artifact_mappings",
        "canonicalization",
        "checkout_git_state",
        "causal_chain_binding",
        "contract_sha256",
        "created_at_utc",
        "direct_inputs",
        "direct_input_layout",
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
_FILE_RECORD_KEYS = frozenset({"path", "sha256", "size_bytes"})
_SOURCE_FILE_KEYS = frozenset(
    {"contract_builder", "online_launcher", "runtime_wrapper"}
)
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
_PROSPECTIVE_PLAN_KEYS = frozenset(
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


class ContractError(RuntimeError):
    """A fail-closed contract construction or verification error."""


GitChecker = Callable[[Path, str], None]
RuntimeBindingProvider = Callable[[Path, Path], dict[str, Any]]
CausalChainValidator = Callable[[Mapping[str, Path], Path, Path], dict[str, Any]]

PYTHON_SHIM_BYTES = b'#!/usr/bin/bash\nexec /usr/bin/python3.10 "$@"\n'

_CAUSAL_PLAN_KEYS = frozenset(
    {
        "attempt_id",
        "causal_checkout_root",
        "causal_protocol_seal_sha256",
        "causal_protocol_seal_status",
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
        "tooling_root",
        "tooling_source_commit",
        "tools",
    }
)
_CAUSAL_PLAN_STAGES = frozenset({"attester", "revalidator", "execution_seal_builder"})
_CAUSAL_PLAN_INVOCATION_KEYS = frozenset({"argv", "inputs", "outputs", "parameters"})
_CAUSAL_PLAN_BINDING_KEYS = frozenset({"path", "sha256"})
_CAUSAL_PLAN_INVOCATION_SCHEMAS = {
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
_CAUSAL_ATTESTATION_KEYS = frozenset(
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
_CAUSAL_EXPECTED_LAUNCHER_KEYS = frozenset(
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
_CAUSAL_PID_EXIT_KEYS = frozenset(
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
_CAUSAL_REGISTERED_COUNTS = {
    "cell_final_traces": 6,
    "cell_manifests": 6,
    "collector_final_traces": 3,
    "collector_manifests": 3,
    "formal_decisions": 1,
    "formal_manifests": 1,
    "tapes": 3,
    "total": 23,
}
_CAUSAL_STABILITY_KEYS = frozenset(
    {"minimum_interval_seconds", "observed_interval_seconds", "snapshots_identical"}
)
_CAUSAL_PROCESS_ABSENCE_KEYS = frozenset(
    {"artifact_root_path", "attempt_checkout_path", "audit_sha256", "method", "status"}
)
_CAUSAL_NO_LIVE_KEYS = frozenset(
    {"audit_sha256", "forbidden_match_count", "roots", "status"}
)
_CAUSAL_SNAPSHOT_KEYS = frozenset(
    {"captured_at_utc", "file_count", "files", "inventory_sha256", "sequence"}
)
_CAUSAL_SNAPSHOT_FILE_KEYS = frozenset(
    {"device", "inode", "mtime_ns", "path", "roles", "sha256", "size_bytes"}
)
_CAUSAL_LAUNCH_EXPECTATION_KEYS = frozenset(
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
_CAUSAL_RECEIPT_KEYS = frozenset(
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
_CAUSAL_DECISION_KEYS = frozenset(
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


def canonical_bytes(value: Any) -> bytes:
    """Return the one registered canonical JSON encoding."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError("value is not canonical-JSON encodable") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _absolute_normalized(path: Path, label: str) -> Path:
    raw = os.fspath(path.expanduser())
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise ContractError(f"{label} must be a normalized absolute path")
    return Path(raw)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _require_distinct_roots(roots: Mapping[str, Path]) -> None:
    items = list(roots.items())
    for index, (left_name, left) in enumerate(items):
        for right_name, right in items[index + 1 :]:
            if (
                left == right
                or _is_relative_to(left, right)
                or _is_relative_to(right, left)
            ):
                raise ContractError(
                    f"{left_name} and {right_name} must be separate directory trees"
                )


def _require_root_layout(
    *,
    online_root: Path,
    causal_root: Path,
    causal_durable_root: Path,
    durable_root: Path,
    tooling_root: Path,
    source_commit: str,
) -> None:
    """Enforce checkout isolation and the registered durable tooling location."""

    _require_distinct_roots(
        {
            "online_attempt_checkout": online_root,
            "paired_causal_attempt_checkout": causal_root,
            "paired_causal_durable_attempt_root": causal_durable_root,
            "durable_attempt_root": durable_root,
        }
    )
    expected_tooling = durable_root / "control" / "wrapper" / source_commit
    if tooling_root != expected_tooling:
        raise ContractError(
            "wrapper_tooling_root must equal durable/control/wrapper/source_commit"
        )


def _system_executable_record(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_absolute() or Path(os.path.realpath(path)) != path:
        raise ContractError(f"{label} must resolve to its exact absolute path")
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        raise ContractError(f"{label} is not an executable regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or (after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise ContractError(f"{label} changed while hashing")
    payload = b"".join(chunks)
    return {
        "lookup_path": path.as_posix(),
        "resolved_path": path.as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


def _default_git_checker(
    root: Path,
    expected_commit: str,
    *,
    sealed_home: Path,
) -> dict[str, Any]:
    """Require the exact commit and reject every unregistered checkout entry."""

    git_lookup = shutil.which("git", path="/usr/bin:/bin")
    if git_lookup is None:
        raise ContractError("absolute Git executable is missing")
    git_path = Path(git_lookup)
    if git_path != Path("/usr/bin/git"):
        raise ContractError("Git must resolve exactly to /usr/bin/git")
    git_record = _system_executable_record(git_path, label="sealed Git executable")
    sealed_home = _absolute_normalized(sealed_home, "sealed Git HOME")
    _assert_real_directory_path(
        sealed_home, root=Path(sealed_home.anchor), label="sealed Git HOME"
    )
    if os.listdir(sealed_home):
        raise ContractError("sealed Git HOME must be empty")
    git_environment = {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": sealed_home.as_posix(),
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        top_level = subprocess.run(
            [git_path.as_posix(), "rev-parse", "--show-toplevel"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            env=git_environment,
        ).stdout.strip()
        head = subprocess.run(
            [git_path.as_posix(), "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            env=git_environment,
        ).stdout.strip()
        tracked_status = subprocess.run(
            [
                git_path.as_posix(),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            env=git_environment,
        ).stdout
        untracked_status = subprocess.run(
            [
                git_path.as_posix(),
                "ls-files",
                "--others",
                "--exclude-standard",
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            env=git_environment,
        ).stdout
        ignored_status = subprocess.run(
            [
                git_path.as_posix(),
                "ls-files",
                "--others",
                "-i",
                "--exclude-standard",
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            env=git_environment,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ContractError("cannot verify sealed Git checkout") from exc
    if os.path.abspath(top_level) != root.as_posix():
        raise ContractError("registered checkout is not the Git top-level directory")
    if head != expected_commit:
        raise ContractError("sealed checkout source commit differs")
    if tracked_status:
        raise ContractError("sealed checkout has tracked/index modifications")
    if expected_commit == ONLINE_SOURCE_COMMIT:
        allowed_untracked_symlinks = {"artifacts/cohort_online_icl"}
    elif expected_commit == PAIRED_CAUSAL_SOURCE_COMMIT:
        allowed_untracked_symlinks = {"artifacts"}
    else:
        # This branch supports hermetic tests of the checker at fresh commits.
        allowed_untracked_symlinks = {
            "artifacts/cohort_online_icl",
            "artifacts",
        }
    unregistered = set(untracked_status.splitlines()) | set(ignored_status.splitlines())
    for relative in sorted(unregistered):
        candidate = root / relative
        if relative not in allowed_untracked_symlinks:
            raise ContractError("sealed checkout has an untracked shadow entry")
        try:
            if not stat.S_ISLNK(os.lstat(candidate).st_mode):
                raise ContractError("registered artifact mapping is not a symlink")
        except FileNotFoundError as exc:
            raise ContractError("untracked checkout entry disappeared") from exc
    return {
        "environment": git_environment,
        "executable": git_record,
        "sealed_home_mode_octal": format(
            stat.S_IMODE(os.lstat(sealed_home).st_mode), "04o"
        ),
    }


def _executable_record(lookup_path: Path, *, label: str) -> dict[str, Any]:
    if not lookup_path.is_absolute():
        raise ContractError(f"{label} lookup path is not absolute")
    try:
        mode = os.stat(lookup_path).st_mode
    except OSError as exc:
        raise ContractError(f"{label} executable is missing") from exc
    if not stat.S_ISREG(mode) or mode & 0o111 == 0:
        raise ContractError(f"{label} is not an executable regular file")
    resolved = Path(os.path.realpath(lookup_path))
    record = _file_record(resolved, root=Path(resolved.anchor), label=label)
    return {
        "lookup_path": lookup_path.as_posix(),
        "resolved_path": resolved.as_posix(),
        "sha256": record["sha256"],
        "size_bytes": record["size_bytes"],
    }


def _default_runtime_binding_provider(
    tooling_root: Path, online_checkout: Path
) -> dict[str, Any]:
    runtime_bin = tooling_root / "runtime-bin"
    python_shim = runtime_bin / "python"
    sealed_home = tooling_root / "sealed-home"
    _assert_real_directory_path(
        runtime_bin, root=tooling_root, label="registered runtime-bin"
    )
    _assert_real_directory_path(
        sealed_home, root=tooling_root, label="registered sealed HOME"
    )
    if stat.S_IMODE(os.lstat(runtime_bin).st_mode) != 0o555:
        raise ContractError("registered runtime-bin mode must be exactly 0555")
    if stat.S_IMODE(os.lstat(sealed_home).st_mode) != 0o555:
        raise ContractError("registered sealed HOME mode must be exactly 0555")
    runtime_inventory = sorted(os.listdir(runtime_bin))
    home_inventory = sorted(os.listdir(sealed_home))
    if runtime_inventory != ["python"]:
        raise ContractError("registered runtime-bin inventory must contain only python")
    if home_inventory:
        raise ContractError("registered sealed HOME inventory must be empty")
    if (
        _read_stable_bytes(
            python_shim, root=tooling_root, label="registered Python 3.10 shim"
        )
        != PYTHON_SHIM_BYTES
    ):
        raise ContractError("registered Python shim bytes differ")
    if stat.S_IMODE(os.lstat(python_shim).st_mode) != 0o555:
        raise ContractError("registered Python shim mode must be exactly 0555")
    path_value = f"{runtime_bin.as_posix()}:/usr/bin:/bin"
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": sealed_home.as_posix(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": path_value,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TZ": "UTC",
    }
    if set(environment) & set(FORBIDDEN_ENVIRONMENT_KEYS):
        raise ContractError("minimal runtime environment contains a forbidden key")
    executables: dict[str, dict[str, Any]] = {}
    for name in RUNTIME_COMMAND_NAMES:
        lookup = shutil.which(name, path=path_value)
        if lookup is None:
            raise ContractError(f"required runtime executable is missing: {name}")
        executables[name] = _executable_record(
            Path(lookup), label=f"runtime executable {name}"
        )
    python_target = Path("/usr/bin/python3.10")
    executables["python_target"] = _executable_record(
        python_target, label="runtime Python 3.10 target"
    )
    absolute_executables = {
        path.as_posix(): _executable_record(path, label=f"absolute executable {path}")
        for path in (
            Path("/usr/bin/env"),
            Path("/usr/bin/bash"),
            python_target,
        )
    }
    for path, record in absolute_executables.items():
        if record["lookup_path"] != path or record["resolved_path"] != path:
            raise ContractError(f"absolute executable does not resolve exactly: {path}")
    if executables["python"]["lookup_path"] != python_shim.as_posix():
        raise ContractError("bare python does not resolve to the registered shim")
    if executables["python"]["resolved_path"] != python_shim.as_posix():
        raise ContractError("registered Python shim may not be a symlink")
    if executables["python_target"]["resolved_path"] != "/usr/bin/python3.10":
        raise ContractError("Python target does not resolve to /usr/bin/python3.10")
    try:
        completed = subprocess.run(
            ["/usr/bin/python3.10", "--version"],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ContractError("cannot verify registered Python 3.10 version") from exc
    version_output = (completed.stdout + completed.stderr).strip()
    if version_output != "Python 3.10.12":
        raise ContractError("registered Python version must be exactly 3.10.12")
    return {
        "absolute_executables": absolute_executables,
        "cwd": online_checkout.as_posix(),
        "environment": environment,
        "executables": executables,
        "forbidden_environment_keys": list(FORBIDDEN_ENVIRONMENT_KEYS),
        "python_version_output": version_output,
        "python_shim_target": "/usr/bin/python3.10",
        "runtime_bin": {
            "inventory": runtime_inventory,
            "inventory_sha256": canonical_sha256(runtime_inventory),
            "mode_octal": "0555",
            "path": runtime_bin.as_posix(),
        },
        "sealed_home": {
            "inventory": home_inventory,
            "inventory_sha256": canonical_sha256(home_inventory),
            "mode_octal": "0555",
            "path": sealed_home.as_posix(),
        },
    }


def _assert_real_directory_path(path: Path, *, root: Path, label: str) -> None:
    """Require an existing all-directory path without following symlinks."""

    if not _is_relative_to(path, root):
        raise ContractError(f"{label} escapes its registered root")
    try:
        if not path.is_absolute():
            raise ContractError(f"{label} must be absolute")
        current = Path(path.anchor)
        candidates = [current]
        for part in path.parts[1:]:
            current = current / part
            candidates.append(current)
        for current in candidates:
            mode = os.lstat(current).st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise ContractError(f"{label} must be a real directory tree")
    except FileNotFoundError as exc:
        raise ContractError(f"{label} directory is missing") from exc


def _assert_regular_no_symlink(path: Path, *, root: Path, label: str) -> None:
    if not _is_relative_to(path, root):
        raise ContractError(f"{label} escapes its registered root")
    _assert_real_directory_path(root, root=Path(root.anchor), label=f"{label} root")
    current = root
    try:
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise ContractError(f"{label} root may not be a symlink")
        for part in path.relative_to(root).parts:
            current = current / part
            mode = os.lstat(current).st_mode
            if stat.S_ISLNK(mode):
                raise ContractError(f"{label} has a symlink component")
    except FileNotFoundError as exc:
        raise ContractError(f"{label} is missing") from exc
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise ContractError(f"{label} must be a regular file")


def _read_stable_bytes(path: Path, *, root: Path, label: str) -> bytes:
    """Read one regular file without following its leaf and reject hash races."""

    _assert_regular_no_symlink(path, root=root, label=label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContractError(f"cannot open {label}") from exc
    try:
        before = os.fstat(descriptor)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (  # noqa: E731
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(before) != identity(after):
        raise ContractError(f"{label} changed while hashing")
    if before.st_nlink != 1 or after.st_nlink != 1:
        raise ContractError(f"{label} must have exactly one hard link")
    linked = os.lstat(path)
    if (
        not stat.S_ISREG(linked.st_mode)
        or linked.st_nlink != 1
        or identity(linked) != identity(after)
    ):
        raise ContractError(f"{label} path changed while hashing")
    return b"".join(chunks)


def _file_record(path: Path, *, root: Path, label: str) -> dict[str, Any]:
    payload = _read_stable_bytes(path, root=root, label=label)
    return {
        "path": path.as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, nested in pairs:
        if key in value:
            raise ContractError("contract JSON contains a duplicate key")
        value[key] = nested
    return value


def _reject_nonfinite(value: str) -> None:
    raise ContractError(f"contract JSON contains non-finite value {value}")


def _load_object_bytes(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("contract is not duplicate-free JSON") from exc
    if not isinstance(value, dict):
        raise ContractError("contract must be a JSON object")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ContractError(f"{label} is not a lowercase SHA-256")
    return value


def _require_commit(value: Any) -> str:
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise ContractError("tooling_source_commit is not a lowercase Git commit")
    return value


def _require_exact_keys(value: Any, expected: frozenset[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError(f"{label} exact-key schema differs")


def _expected_fixed_paths(durable_root: Path) -> dict[str, str]:
    return {
        "completion_marker": (durable_root / MARKER_RELATIVE_PATH).as_posix(),
        "contract": (durable_root / CONTRACT_RELATIVE_PATH).as_posix(),
        "contract_expectation": (
            durable_root / CONTRACT_EXPECTATION_RELATIVE_PATH
        ).as_posix(),
        "exit_record": (durable_root / EXIT_RELATIVE_PATH).as_posix(),
        "launch_inventory": (durable_root / LAUNCH_INVENTORY_RELATIVE_PATH).as_posix(),
        "lifetime_lock": (durable_root / LOCK_RELATIVE_PATH).as_posix(),
        "pid_file": (durable_root / PID_RELATIVE_PATH).as_posix(),
        "prospective_execution_plan": (
            durable_root / PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH
        ).as_posix(),
    }


def _expected_direct_input_layout() -> dict[str, dict[str, str]]:
    return {
        name: {
            "relative_path": DIRECT_INPUT_RELATIVE_PATHS[name].as_posix(),
            "root": (
                "paired_causal_durable_attempt_root"
                if name in CAUSAL_DURABLE_INPUT_NAMES
                else "durable_attempt_root"
            ),
        }
        for name in DIRECT_INPUT_NAMES
    }


def _validate_artifact_mapping(
    *, checkout_root: Path, durable_artifact_root: Path, relative_path: Path, label: str
) -> dict[str, str]:
    checkout_path = checkout_root / relative_path
    _assert_real_directory_path(
        checkout_path.parent, root=checkout_root, label=f"{label} checkout parent"
    )
    _assert_real_directory_path(
        durable_artifact_root,
        root=Path(durable_artifact_root.anchor),
        label=f"{label} durable artifact root",
    )
    try:
        mode = os.lstat(checkout_path).st_mode
    except FileNotFoundError as exc:
        raise ContractError(f"{label} checkout artifact mapping is missing") from exc
    if not stat.S_ISLNK(mode):
        raise ContractError(f"{label} checkout artifact mapping must be a symlink")
    target_text = os.readlink(checkout_path)
    target = Path(target_text)
    if not target.is_absolute():
        target = Path(os.path.abspath(checkout_path.parent / target))
    if Path(os.path.realpath(checkout_path)) != durable_artifact_root:
        raise ContractError(f"{label} checkout artifact symlink target differs")
    if Path(os.path.realpath(target)) != durable_artifact_root:
        raise ContractError(f"{label} artifact target contains an unexpected mapping")
    return {
        "checkout_path": checkout_path.as_posix(),
        "durable_path": durable_artifact_root.as_posix(),
        "symlink_target": target_text,
    }


def _validate_causal_artifact_mapping(
    *, checkout_root: Path, durable_root: Path
) -> dict[str, str]:
    durable_artifacts = durable_root / "artifacts"
    record = _validate_artifact_mapping(
        checkout_root=checkout_root,
        durable_artifact_root=durable_artifacts,
        relative_path=Path("artifacts"),
        label="paired causal artifacts",
    )
    durable_child = durable_artifacts / "cohort_causal"
    _assert_real_directory_path(
        durable_child,
        root=durable_root,
        label="paired causal cohort artifact child",
    )
    checkout_child = checkout_root / "artifacts" / "cohort_causal"
    if Path(os.path.realpath(checkout_child)) != durable_child:
        raise ContractError("paired causal cohort child mapping differs")
    return {
        **record,
        "cohort_child_checkout_path": checkout_child.as_posix(),
        "cohort_child_durable_path": durable_child.as_posix(),
    }


def _load_direct_json(
    path: Path, *, root: Path, label: str
) -> tuple[dict[str, Any], bytes]:
    raw = _read_stable_bytes(path, root=root, label=label)
    return _load_object_bytes(raw), raw


def _validate_causal_snapshot(
    value: Any, *, label: str, expected_sequence: int
) -> dict[str, Any]:
    _require_exact_keys(value, _CAUSAL_SNAPSHOT_KEYS, label)
    assert isinstance(value, dict)
    files = value["files"]
    if not isinstance(files, list) or not files:
        raise ContractError(f"{label}.files must be a non-empty list")
    if (
        value["sequence"] != expected_sequence
        or not isinstance(value["captured_at_utc"], str)
        or not value["captured_at_utc"]
    ):
        raise ContractError(f"{label} sequence/time differs")
    normalized: list[dict[str, Any]] = []
    for index, record in enumerate(files):
        _require_exact_keys(
            record,
            _CAUSAL_SNAPSHOT_FILE_KEYS,
            f"{label}.files[{index}]",
        )
        assert isinstance(record, dict)
        _absolute_normalized(Path(record["path"]), f"{label}.files[{index}].path")
        _require_sha256(record["sha256"], f"{label}.files[{index}].sha256")
        if (
            not isinstance(record["roles"], list)
            or not record["roles"]
            or any(not isinstance(role, str) or not role for role in record["roles"])
            or record["roles"] != sorted(set(record["roles"]))
        ):
            raise ContractError(f"{label}.files[{index}].roles differs")
        for key in ("device", "inode", "mtime_ns", "size_bytes"):
            if (
                isinstance(record[key], bool)
                or not isinstance(record[key], int)
                or record[key] < 0
            ):
                raise ContractError(f"{label}.files[{index}].{key} is invalid")
        normalized.append(record)
    paths = [record["path"] for record in normalized]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ContractError(f"{label} file paths are not sorted and unique")
    if value["file_count"] != len(normalized):
        raise ContractError(f"{label} file count differs")
    digest = canonical_sha256(normalized)
    if value["inventory_sha256"] != digest:
        raise ContractError(f"{label} inventory digest differs")
    return value


def _causal_plan_expected_argv(plan: Mapping[str, Any], stage: str) -> list[str]:
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
    raise ContractError("unknown causal execution-plan stage")


def _default_causal_chain_validator(
    paths: Mapping[str, Path], causal_checkout: Path, causal_durable: Path
) -> dict[str, Any]:
    """Validate the causal chain inline, without importing mutable checkout code."""

    plan_path = paths["causal_terminal_execution_plan"]
    plan, plan_raw = _load_direct_json(
        plan_path, root=causal_durable, label="causal terminal execution plan"
    )
    _require_exact_keys(plan, _CAUSAL_PLAN_KEYS, "causal execution plan")
    if plan_raw != canonical_bytes(plan):
        raise ContractError("causal execution plan is not canonical JSON bytes")
    if (
        plan["protocol"] != "cohort_causal_terminal_verifier_execution_plan_v1"
        or plan["schema_version"] != 1
        or plan["status"] != "registered"
        or plan["online_icl"] is not None
        or plan["causal_protocol_seal_sha256"] is not None
        or plan["causal_protocol_seal_status"]
        != "not_applicable_existing_implementation_has_none"
    ):
        raise ContractError("causal execution plan protocol/state differs")
    if (
        plan["attempt_id"] != causal_durable.name
        or plan["causal_checkout_root"] != causal_checkout.as_posix()
        or plan["durable_attempt_root"] != causal_durable.as_posix()
        or plan["runtime"]
        != {"python_path": "/usr/bin/python3.10", "python_version": "3.10.12"}
    ):
        raise ContractError("causal execution plan roots/runtime differ")
    tooling_commit = _require_commit(plan["tooling_source_commit"])
    tooling_root = causal_durable / "control" / "verifier" / tooling_commit
    if plan["tooling_root"] != tooling_root.as_posix():
        raise ContractError("causal execution plan tooling root differs")
    expected_tools = {
        "attester": tooling_root / "attest_cohort_causal_completion.py",
        "revalidator": tooling_root / "revalidate_cohort_causal_terminal.py",
        "execution_seal_builder": tooling_root
        / "build_cohort_structured_state_execution_seal.py",
    }
    _require_exact_keys(plan["tools"], _CAUSAL_PLAN_STAGES, "causal plan tools")
    for stage, expected_path in expected_tools.items():
        binding = plan["tools"][stage]
        _require_exact_keys(
            binding, _CAUSAL_PLAN_BINDING_KEYS, f"causal plan tool {stage}"
        )
        if binding["path"] != expected_path.as_posix():
            raise ContractError(f"causal plan tool path differs: {stage}")
        current = _file_record(
            expected_path, root=tooling_root, label=f"causal plan tool {stage}"
        )
        if binding["sha256"] != current["sha256"]:
            raise ContractError(f"causal plan tool digest differs: {stage}")
    structured_path = tooling_root / "COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md"
    structured_binding = plan["structured_preregistration"]
    _require_exact_keys(
        structured_binding,
        _CAUSAL_PLAN_BINDING_KEYS,
        "causal structured preregistration binding",
    )
    structured_record = _file_record(
        structured_path,
        root=tooling_root,
        label="causal structured preregistration",
    )
    if structured_binding != {
        "path": structured_path.as_posix(),
        "sha256": structured_record["sha256"],
    }:
        raise ContractError("causal structured preregistration binding differs")
    launch_binding = plan["launch_expectation"]
    _require_exact_keys(
        launch_binding,
        _CAUSAL_PLAN_BINDING_KEYS,
        "causal plan launch expectation binding",
    )
    expected_invocations = {
        "attester": {
            "inputs": {
                "execution_plan": plan_path.as_posix(),
                "launch_expectation": paths["causal_launch_expectation"].as_posix(),
                "provenance": paths["causal_provenance"].as_posix(),
                "provenance_details": paths["causal_provenance_details"].as_posix(),
                "root": causal_checkout.as_posix(),
            },
            "outputs": {
                "attestation": paths["causal_completion_attestation"].as_posix()
            },
            "parameters": {"stability_seconds": "1.0"},
        },
        "revalidator": {
            "inputs": {
                "attestation": paths["causal_completion_attestation"].as_posix(),
                "execution_plan": plan_path.as_posix(),
                "formal_decision": paths["causal_decision"].as_posix(),
                "formal_manifest": paths["causal_manifest"].as_posix(),
                "grid": (causal_checkout / "grid_cohort_causal_formal.json").as_posix(),
                "launch_expectation": paths["causal_launch_expectation"].as_posix(),
                "preregistration": (
                    causal_checkout / "COHORT_QONLY_CAUSAL_PREREG.md"
                ).as_posix(),
                "provenance": paths["causal_provenance"].as_posix(),
                "root": causal_checkout.as_posix(),
                "statistical_addendum": (
                    causal_checkout / "COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md"
                ).as_posix(),
            },
            "outputs": {
                "revalidated_decision": paths["causal_revalidated_decision"].as_posix(),
                "revalidation_receipt": paths["causal_revalidation_receipt"].as_posix(),
            },
            "parameters": {},
        },
        "execution_seal_builder": {
            "inputs": {
                "attestation": paths["causal_completion_attestation"].as_posix(),
                "causal_original": paths["causal_decision"].as_posix(),
                "causal_revalidated": paths["causal_revalidated_decision"].as_posix(),
                "execution_plan": plan_path.as_posix(),
                "launch_expectation": paths["causal_launch_expectation"].as_posix(),
                "revalidation_receipt": paths["causal_revalidation_receipt"].as_posix(),
                "structured_preregistration": structured_path.as_posix(),
            },
            "outputs": {
                "execution_seal": (
                    causal_durable
                    / "prep"
                    / "cohort_closed_loop_structured_state.execution_seal.json"
                ).as_posix()
            },
            "parameters": {},
        },
    }
    _require_exact_keys(
        plan["invocations"], _CAUSAL_PLAN_STAGES, "causal plan invocations"
    )
    for stage in sorted(_CAUSAL_PLAN_STAGES):
        invocation = plan["invocations"][stage]
        _require_exact_keys(
            invocation,
            _CAUSAL_PLAN_INVOCATION_KEYS,
            f"causal plan invocation {stage}",
        )
        input_keys, output_keys, parameter_keys = _CAUSAL_PLAN_INVOCATION_SCHEMAS[stage]
        _require_exact_keys(
            invocation["inputs"], input_keys, f"causal plan {stage} inputs"
        )
        _require_exact_keys(
            invocation["outputs"], output_keys, f"causal plan {stage} outputs"
        )
        _require_exact_keys(
            invocation["parameters"],
            parameter_keys,
            f"causal plan {stage} parameters",
        )
        expected = expected_invocations[stage]
        if any(invocation[key] != expected[key] for key in expected):
            raise ContractError(f"causal plan invocation topology differs: {stage}")
        if invocation["argv"] != _causal_plan_expected_argv(plan, stage):
            raise ContractError(f"causal plan invocation argv differs: {stage}")
    plan_sha = hashlib.sha256(plan_raw).hexdigest()

    attestation_object, attestation_raw = _load_direct_json(
        paths["causal_completion_attestation"],
        root=causal_durable,
        label="causal completion attestation",
    )
    expectation_object, expectation_raw = _load_direct_json(
        paths["causal_launch_expectation"],
        root=causal_durable,
        label="causal launch expectation",
    )
    receipt, receipt_raw = _load_direct_json(
        paths["causal_revalidation_receipt"],
        root=causal_durable,
        label="causal revalidation receipt",
    )
    if attestation_raw != canonical_bytes(attestation_object):
        raise ContractError("causal completion attestation is not canonical bytes")
    expected_receipt_raw = (
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if receipt_raw != expected_receipt_raw:
        raise ContractError("causal revalidation receipt is not canonical report bytes")
    _require_exact_keys(
        attestation_object, _CAUSAL_ATTESTATION_KEYS, "causal attestation"
    )
    attestation = attestation_object
    if (
        attestation["protocol"] != "cohort_causal_terminal_completion_attestation_v1"
        or attestation["schema_version"] != 1
        or attestation["status"] != "complete"
    ):
        raise ContractError("causal attestation protocol/status differs")
    _require_exact_keys(
        attestation["expected_launcher"],
        _CAUSAL_EXPECTED_LAUNCHER_KEYS,
        "causal attestation expected launcher",
    )
    if attestation["registered_counts"] != _CAUSAL_REGISTERED_COUNTS:
        raise ContractError("causal attestation registered counts differ")
    _require_exact_keys(
        attestation["pid_exit"], _CAUSAL_PID_EXIT_KEYS, "causal attestation PID/exit"
    )
    pid_exit = attestation["pid_exit"]
    if {
        "pid_ascii_status": pid_exit["pid_ascii_status"],
        "pid_liveness_status": pid_exit["pid_liveness_status"],
        "exit_zero_status": pid_exit["exit_zero_status"],
        "exit_after_outputs_status": pid_exit["exit_after_outputs_status"],
    } != {
        "pid_ascii_status": "pass",
        "pid_liveness_status": "dead",
        "exit_zero_status": "pass",
        "exit_after_outputs_status": "pass",
    }:
        raise ContractError("causal attestation PID/exit status differs")
    for field in ("pid_file_sha256", "exit_file_sha256"):
        _require_sha256(pid_exit[field], f"causal attestation {field}")
    for field in (
        "pid_file_mtime_ns",
        "pid_file_size_bytes",
        "exit_file_mtime_ns",
        "exit_file_size_bytes",
    ):
        if (
            isinstance(pid_exit[field], bool)
            or not isinstance(pid_exit[field], int)
            or pid_exit[field] < 0
        ):
            raise ContractError(f"causal attestation {field} is invalid")
    _require_exact_keys(
        attestation["stability"],
        _CAUSAL_STABILITY_KEYS,
        "causal attestation stability",
    )
    stability = attestation["stability"]
    if (
        stability["snapshots_identical"] is not True
        or isinstance(stability["minimum_interval_seconds"], bool)
        or not isinstance(stability["minimum_interval_seconds"], (int, float))
        or isinstance(stability["observed_interval_seconds"], bool)
        or not isinstance(stability["observed_interval_seconds"], (int, float))
        or stability["minimum_interval_seconds"] < 1.0
        or stability["observed_interval_seconds"]
        < stability["minimum_interval_seconds"]
    ):
        raise ContractError("causal attestation stability differs")
    snapshots_raw = attestation["snapshots"]
    if not isinstance(snapshots_raw, list) or len(snapshots_raw) != 2:
        raise ContractError("causal attestation must contain two snapshots")
    snapshots = [
        _validate_causal_snapshot(
            value,
            label=f"causal snapshot {index + 1}",
            expected_sequence=index + 1,
        )
        for index, value in enumerate(snapshots_raw)
    ]
    if canonical_bytes(snapshots[0]["files"]) != canonical_bytes(snapshots[1]["files"]):
        raise ContractError("causal attestation snapshots differ")
    inventory_sha = snapshots[0]["inventory_sha256"]
    if (
        snapshots[1]["inventory_sha256"] != inventory_sha
        or attestation["causal_pre_attestation_inventory_sha256"] != inventory_sha
    ):
        raise ContractError("causal attestation inventory binding differs")
    _require_exact_keys(
        attestation["process_absence"],
        _CAUSAL_PROCESS_ABSENCE_KEYS,
        "causal process absence",
    )
    process_audit = attestation["process_absence"]
    process_payload = {
        key: process_audit[key]
        for key in _CAUSAL_PROCESS_ABSENCE_KEYS
        if key != "audit_sha256"
    }
    if (
        process_audit["status"] != "pass"
        or process_audit["method"] != "linux_procfs_cmdline_and_cwd"
        or process_audit["attempt_checkout_path"] != causal_checkout.as_posix()
        or process_audit["artifact_root_path"]
        != (causal_durable / "artifacts" / "cohort_causal").as_posix()
        or process_audit["audit_sha256"] != canonical_sha256(process_payload)
    ):
        raise ContractError("causal process absence did not pass")
    _require_exact_keys(
        attestation["no_live_or_temporary"],
        _CAUSAL_NO_LIVE_KEYS,
        "causal no-live audit",
    )
    no_live = attestation["no_live_or_temporary"]
    no_live_payload = {
        key: no_live[key] for key in _CAUSAL_NO_LIVE_KEYS if key != "audit_sha256"
    }
    if (
        no_live["status"] != "pass"
        or no_live["forbidden_match_count"] != 0
        or not isinstance(no_live["roots"], list)
        or not no_live["roots"]
        or no_live["roots"] != sorted(set(no_live["roots"]))
        or no_live["audit_sha256"] != canonical_sha256(no_live_payload)
    ):
        raise ContractError("causal no-live audit did not pass")

    _require_exact_keys(
        expectation_object,
        _CAUSAL_LAUNCH_EXPECTATION_KEYS,
        "causal launch expectation",
    )
    expectation = expectation_object
    if (
        expectation["protocol"] != "cohort_causal_formal_launch_expectation_v1"
        or expectation["schema_version"] != 1
        or expectation["launch_mode"] != "formal"
        or expectation["expected_final_inventory"] != _CAUSAL_REGISTERED_COUNTS
    ):
        raise ContractError("causal launch expectation protocol/counts differ")
    for field in (
        "formal_grid_file_sha256",
        "launcher_file_sha256",
        "pid_file_sha256_at_registration",
        "provenance_file_sha256",
        "wrapper_cmdline_sha256_at_registration",
    ):
        _require_sha256(expectation[field], f"causal launch expectation {field}")

    _require_exact_keys(receipt, _CAUSAL_RECEIPT_KEYS, "causal receipt")
    if receipt.get("status") != "valid":
        raise ContractError("causal decision/receipt hard gate is not exact pass")
    for field in (
        "execution_plan_sha256",
        "formal_decision_file_sha256",
        "formal_manifest_file_sha256",
    ):
        _require_sha256(receipt.get(field), f"causal receipt {field}")

    plan_path_text = plan_path.as_posix()
    expectation_path_text = paths["causal_launch_expectation"].as_posix()
    if (
        attestation["execution_plan_path"] != plan_path_text
        or attestation["execution_plan_sha256"] != plan_sha
        or receipt["execution_plan_path"] != plan_path_text
        or receipt["execution_plan_sha256"] != plan_sha
    ):
        raise ContractError("causal plan/attestation/receipt binding differs")
    expectation_sha = hashlib.sha256(expectation_raw).hexdigest()
    expected_launcher = attestation["expected_launcher"]
    expected_launcher_binding = {
        "formal_grid_file_sha256": expectation["formal_grid_file_sha256"],
        "launch_expectation_path": expectation_path_text,
        "launch_expectation_sha256": expectation_sha,
        "launcher_file_sha256": expectation["launcher_file_sha256"],
        "provenance_file_sha256": expectation["provenance_file_sha256"],
        "source_commit": expectation["source_commit"],
        "wrapper_cmdline_sha256_at_registration": expectation[
            "wrapper_cmdline_sha256_at_registration"
        ],
    }
    if (
        expected_launcher != expected_launcher_binding
        or plan["launch_expectation"]["path"] != expectation_path_text
        or plan["launch_expectation"]["sha256"] != expectation_sha
    ):
        raise ContractError("causal launch expectation chain binding differs")
    causal_artifact = causal_durable / "artifacts" / "cohort_causal"
    if (
        expectation["checkout_root"] != causal_checkout.as_posix()
        or expectation["durable_attempt_root"] != causal_durable.as_posix()
        or expectation["artifact_root"] != causal_artifact.as_posix()
        or expectation["source_commit"] != PAIRED_CAUSAL_SOURCE_COMMIT
        or plan["causal_checkout_root"] != causal_checkout.as_posix()
        or plan["durable_attempt_root"] != causal_durable.as_posix()
    ):
        raise ContractError("causal chain roots or source commit differ")
    provenance_raw = _read_stable_bytes(
        paths["causal_provenance"],
        root=causal_durable,
        label="causal provenance",
    )
    if (
        expectation["provenance_file_sha256"]
        != hashlib.sha256(provenance_raw).hexdigest()
    ):
        raise ContractError("causal launch expectation provenance digest differs")
    if (
        expectation["pid_file"] != attestation["pid_exit"]["pid_file_path"]
        or expectation["exit_file"] != attestation["pid_exit"]["exit_file_path"]
    ):
        raise ContractError("causal launch expectation PID/exit binding differs")
    original_raw = _read_stable_bytes(
        paths["causal_decision"], root=causal_durable, label="causal original decision"
    )
    revalidated_raw = _read_stable_bytes(
        paths["causal_revalidated_decision"],
        root=causal_durable,
        label="causal revalidated decision",
    )
    manifest_raw = _read_stable_bytes(
        paths["causal_manifest"], root=causal_durable, label="causal formal manifest"
    )
    decision_object = _load_object_bytes(original_raw)
    _require_exact_keys(
        decision_object, _CAUSAL_DECISION_KEYS, "causal formal decision"
    )
    required_gate = {
        "status": "valid",
        "decision": "pass",
        "decision_scope": "internal_gate_pass",
    }
    if {key: decision_object.get(key) for key in required_gate} != required_gate or {
        key: receipt.get(key) for key in required_gate
    } != required_gate:
        raise ContractError("causal decision/receipt hard gate is not exact pass")
    expected_decision_raw = (
        json.dumps(decision_object, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if original_raw != expected_decision_raw:
        raise ContractError("causal formal decision is not canonical report bytes")
    _load_object_bytes(manifest_raw)
    decision_sha = hashlib.sha256(original_raw).hexdigest()
    if original_raw != revalidated_raw:
        raise ContractError("causal original/revalidated decision bytes differ")
    if (
        receipt["formal_decision_file_sha256"] != decision_sha
        or receipt["formal_manifest_file_sha256"]
        != hashlib.sha256(manifest_raw).hexdigest()
        or receipt["decision"] != decision_object["decision"]
        or receipt["decision_scope"] != decision_object["decision_scope"]
    ):
        raise ContractError("causal receipt formal-file digest chain differs")
    return {
        "attestation_sha256": hashlib.sha256(attestation_raw).hexdigest(),
        "decision": decision_object["decision"],
        "decision_scope": decision_object["decision_scope"],
        "decision_status": decision_object["status"],
        "execution_plan_sha256": plan_sha,
        "launch_expectation_sha256": expectation_sha,
        "original_and_revalidated_decision_sha256": decision_sha,
        "revalidation_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "hard_gate": required_gate,
        "semantic_revalidation_status": "not_semantically_revalidated",
        "status": "synthetic_shape_only",
        "verifier_sources": plan["tools"],
    }


def exact_formal_argv(
    *,
    online_checkout: Path,
    paired_causal_checkout: Path,
    direct_inputs: Mapping[str, Path],
) -> list[str]:
    """Return the only launcher argv admitted by this contract version."""

    missing = set(DIRECT_INPUT_NAMES) - set(direct_inputs)
    extra = set(direct_inputs) - set(DIRECT_INPUT_NAMES)
    if missing or extra:
        raise ContractError(
            f"direct launcher input names differ; missing={sorted(missing)}, "
            f"extra={sorted(extra)}"
        )
    return [
        (online_checkout / LAUNCHER_FILENAME).as_posix(),
        "formal",
        "--provenance",
        direct_inputs["online_provenance"].as_posix(),
        "--protocol-seal",
        direct_inputs["protocol_seal"].as_posix(),
        "--gpus",
        FORMAL_GPU_CSV,
        "--causal-smoke-gate",
        direct_inputs["causal_smoke_gate"].as_posix(),
        "--causal-provenance",
        direct_inputs["causal_provenance"].as_posix(),
        "--causal-root",
        paired_causal_checkout.as_posix(),
        "--causal-manifest",
        direct_inputs["causal_manifest"].as_posix(),
        "--causal-decision",
        direct_inputs["causal_revalidated_decision"].as_posix(),
        "--icl-smoke-gate",
        direct_inputs["icl_smoke_gate"].as_posix(),
        "--max-used-memory-mib",
        MAX_USED_MEMORY_MIB,
    ]


def create_contract(
    *,
    tooling_source_commit: str,
    online_attempt_checkout: Path,
    paired_causal_attempt_checkout: Path,
    paired_causal_durable_attempt_root: Path,
    durable_attempt_root: Path,
    wrapper_tooling_root: Path,
    direct_inputs: Mapping[str, Path],
    created_at_utc: str | None = None,
    git_checker: GitChecker | None = None,
    runtime_binding_provider: RuntimeBindingProvider | None = None,
    causal_chain_validator: CausalChainValidator | None = None,
) -> dict[str, Any]:
    """Construct the strict contract without publishing it."""

    commit = _require_commit(tooling_source_commit)
    online_root = _absolute_normalized(
        online_attempt_checkout, "online_attempt_checkout"
    )
    causal_root = _absolute_normalized(
        paired_causal_attempt_checkout, "paired_causal_attempt_checkout"
    )
    causal_durable_root = _absolute_normalized(
        paired_causal_durable_attempt_root,
        "paired_causal_durable_attempt_root",
    )
    durable_root = _absolute_normalized(durable_attempt_root, "durable_attempt_root")
    tooling_root = _absolute_normalized(wrapper_tooling_root, "wrapper_tooling_root")
    _require_root_layout(
        online_root=online_root,
        causal_root=causal_root,
        causal_durable_root=causal_durable_root,
        durable_root=durable_root,
        tooling_root=tooling_root,
        source_commit=commit,
    )
    if git_checker is None:
        sealed_git_home = tooling_root / "sealed-home"
        _default_git_checker(
            online_root, ONLINE_SOURCE_COMMIT, sealed_home=sealed_git_home
        )
        _default_git_checker(
            causal_root, PAIRED_CAUSAL_SOURCE_COMMIT, sealed_home=sealed_git_home
        )
    else:
        git_checker(online_root, ONLINE_SOURCE_COMMIT)
        git_checker(causal_root, PAIRED_CAUSAL_SOURCE_COMMIT)

    normalized_inputs = {
        name: _absolute_normalized(path, f"direct_inputs.{name}")
        for name, path in direct_inputs.items()
    }
    if set(normalized_inputs) != set(DIRECT_INPUT_NAMES):
        exact_formal_argv(
            online_checkout=online_root,
            paired_causal_checkout=causal_root,
            direct_inputs=normalized_inputs,
        )
    if len(set(normalized_inputs.values())) != len(normalized_inputs):
        raise ContractError("all direct launcher input paths must be pairwise distinct")
    input_records: dict[str, dict[str, Any]] = {}
    for name in DIRECT_INPUT_NAMES:
        path = normalized_inputs[name]
        required_root = (
            causal_durable_root if name in CAUSAL_DURABLE_INPUT_NAMES else durable_root
        )
        expected_path = required_root / DIRECT_INPUT_RELATIVE_PATHS[name]
        if path != expected_path:
            raise ContractError(
                f"direct_inputs.{name} differs from its exact durable relative path"
            )
        input_records[name] = _file_record(
            path, root=required_root, label=f"direct_inputs.{name}"
        )

    source_paths = {
        "contract_builder": tooling_root / BUILDER_FILENAME,
        "online_launcher": online_root / LAUNCHER_FILENAME,
        "runtime_wrapper": tooling_root / WRAPPER_FILENAME,
    }
    source_records = {
        "contract_builder": _file_record(
            source_paths["contract_builder"],
            root=tooling_root,
            label="contract_builder",
        ),
        "online_launcher": _file_record(
            source_paths["online_launcher"],
            root=online_root,
            label="online_launcher",
        ),
        "runtime_wrapper": _file_record(
            source_paths["runtime_wrapper"],
            root=tooling_root,
            label="runtime_wrapper",
        ),
    }
    argv = exact_formal_argv(
        online_checkout=online_root,
        paired_causal_checkout=causal_root,
        direct_inputs=normalized_inputs,
    )
    created = created_at_utc or datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if not isinstance(created, str) or _UTC_TIMESTAMP_RE.fullmatch(created) is None:
        raise ContractError("created_at_utc must be a UTC Z timestamp")

    artifact_mappings = {
        "online": _validate_artifact_mapping(
            checkout_root=online_root,
            durable_artifact_root=durable_root / ARTIFACT_RELATIVE_PATH,
            relative_path=ARTIFACT_RELATIVE_PATH,
            label="online artifact",
        ),
        "paired_causal": _validate_causal_artifact_mapping(
            checkout_root=causal_root,
            durable_root=causal_durable_root,
        ),
    }
    bind_runtime = runtime_binding_provider or _default_runtime_binding_provider
    validate_chain = causal_chain_validator or _default_causal_chain_validator
    runtime = bind_runtime(tooling_root, online_root)
    causal_chain = validate_chain(normalized_inputs, causal_root, causal_durable_root)

    contract: dict[str, Any] = {
        "artifact_root": (durable_root / ARTIFACT_RELATIVE_PATH).as_posix(),
        "artifact_mappings": artifact_mappings,
        "canonicalization": {
            "allow_nan": False,
            "encoding": "utf-8",
            "separators": [",", ":"],
            "sort_keys": True,
            "trailing_newline": True,
        },
        "checkout_git_state": {
            "authorization_scope": CHECKOUT_GIT_AUTHORIZATION_SCOPE,
            "online": {
                "source_commit": ONLINE_SOURCE_COMMIT,
                "tracked_checkout_clean": True,
            },
            "paired_causal": {
                "source_commit": PAIRED_CAUSAL_SOURCE_COMMIT,
                "tracked_checkout_clean": True,
            },
        },
        "causal_chain_binding": causal_chain,
        "created_at_utc": created,
        "direct_inputs": input_records,
        "direct_input_layout": _expected_direct_input_layout(),
        "durable_attempt_root": durable_root.as_posix(),
        "exact_formal_argv": argv,
        "exact_formal_argv_sha256": canonical_sha256(argv),
        "fixed_paths": _expected_fixed_paths(durable_root),
        "online_attempt_checkout": online_root.as_posix(),
        "online_source_commit": ONLINE_SOURCE_COMMIT,
        "paired_causal_attempt_checkout": causal_root.as_posix(),
        "paired_causal_durable_attempt_root": causal_durable_root.as_posix(),
        "paired_causal_source_commit": PAIRED_CAUSAL_SOURCE_COMMIT,
        "protocol": PROTOCOL,
        "runtime": runtime,
        "schema_version": SCHEMA_VERSION,
        "source_files": source_records,
        "tooling_source_commit": commit,
        "wrapper_tooling_root": tooling_root.as_posix(),
    }
    contract["contract_sha256"] = canonical_sha256(contract)
    return contract


def _validate_file_record(value: Any, label: str) -> dict[str, Any]:
    _require_exact_keys(value, _FILE_RECORD_KEYS, label)
    assert isinstance(value, dict)
    path = _absolute_normalized(Path(value["path"]), f"{label}.path")
    _require_sha256(value["sha256"], f"{label}.sha256")
    size = value["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ContractError(f"{label}.size_bytes is invalid")
    return {**value, "path": path.as_posix()}


def verify_contract(
    contract: dict[str, Any],
    *,
    verify_current_files: bool = True,
    git_checker: GitChecker | None = None,
    runtime_binding_provider: RuntimeBindingProvider | None = None,
    causal_chain_validator: CausalChainValidator | None = None,
) -> dict[str, Any]:
    """Strictly verify schema, path algebra, digests, argv, and current files."""

    _require_exact_keys(contract, _TOP_LEVEL_KEYS, "contract")
    if (
        contract.get("protocol") != PROTOCOL
        or contract.get("schema_version") != SCHEMA_VERSION
    ):
        raise ContractError("contract protocol or schema version differs")
    if contract.get("online_source_commit") != ONLINE_SOURCE_COMMIT:
        raise ContractError("online source commit differs")
    if contract.get("paired_causal_source_commit") != PAIRED_CAUSAL_SOURCE_COMMIT:
        raise ContractError("paired causal source commit differs")
    if contract.get("checkout_git_state") != {
        "authorization_scope": CHECKOUT_GIT_AUTHORIZATION_SCOPE,
        "online": {
            "source_commit": ONLINE_SOURCE_COMMIT,
            "tracked_checkout_clean": True,
        },
        "paired_causal": {
            "source_commit": PAIRED_CAUSAL_SOURCE_COMMIT,
            "tracked_checkout_clean": True,
        },
    }:
        raise ContractError("sealed checkout Git-state binding differs")
    embedded = _require_sha256(contract["contract_sha256"], "contract_sha256")
    without_digest = dict(contract)
    without_digest.pop("contract_sha256")
    if embedded != canonical_sha256(without_digest):
        raise ContractError("contract self-digest differs")
    commit = _require_commit(contract["tooling_source_commit"])
    created = contract["created_at_utc"]
    if not isinstance(created, str) or _UTC_TIMESTAMP_RE.fullmatch(created) is None:
        raise ContractError("contract creation time is invalid")
    if contract.get("canonicalization") != {
        "allow_nan": False,
        "encoding": "utf-8",
        "separators": [",", ":"],
        "sort_keys": True,
        "trailing_newline": True,
    }:
        raise ContractError("contract canonicalization differs")

    online_root = _absolute_normalized(
        Path(contract["online_attempt_checkout"]), "online_attempt_checkout"
    )
    causal_root = _absolute_normalized(
        Path(contract["paired_causal_attempt_checkout"]),
        "paired_causal_attempt_checkout",
    )
    causal_durable_root = _absolute_normalized(
        Path(contract["paired_causal_durable_attempt_root"]),
        "paired_causal_durable_attempt_root",
    )
    durable_root = _absolute_normalized(
        Path(contract["durable_attempt_root"]), "durable_attempt_root"
    )
    tooling_root = _absolute_normalized(
        Path(contract["wrapper_tooling_root"]), "wrapper_tooling_root"
    )
    _require_root_layout(
        online_root=online_root,
        causal_root=causal_root,
        causal_durable_root=causal_durable_root,
        durable_root=durable_root,
        tooling_root=tooling_root,
        source_commit=commit,
    )
    if git_checker is None:
        sealed_git_home = tooling_root / "sealed-home"
        _default_git_checker(
            online_root, ONLINE_SOURCE_COMMIT, sealed_home=sealed_git_home
        )
        _default_git_checker(
            causal_root, PAIRED_CAUSAL_SOURCE_COMMIT, sealed_home=sealed_git_home
        )
    else:
        git_checker(online_root, ONLINE_SOURCE_COMMIT)
        git_checker(causal_root, PAIRED_CAUSAL_SOURCE_COMMIT)
    if contract["artifact_root"] != (durable_root / ARTIFACT_RELATIVE_PATH).as_posix():
        raise ContractError("artifact root differs from fixed durable layout")
    if contract["direct_input_layout"] != _expected_direct_input_layout():
        raise ContractError("direct input relative-path layout differs")
    _require_exact_keys(contract["fixed_paths"], _FIXED_PATH_KEYS, "fixed_paths")
    if contract["fixed_paths"] != _expected_fixed_paths(durable_root):
        raise ContractError("fixed control/prep paths differ")

    _require_exact_keys(contract["source_files"], _SOURCE_FILE_KEYS, "source_files")
    source_records = {
        name: _validate_file_record(contract["source_files"][name], f"source.{name}")
        for name in sorted(_SOURCE_FILE_KEYS)
    }
    expected_source_paths = {
        "contract_builder": tooling_root / BUILDER_FILENAME,
        "online_launcher": online_root / LAUNCHER_FILENAME,
        "runtime_wrapper": tooling_root / WRAPPER_FILENAME,
    }
    for name, expected in expected_source_paths.items():
        if source_records[name]["path"] != expected.as_posix():
            raise ContractError(f"source file path differs: {name}")

    if not isinstance(contract["direct_inputs"], dict) or set(
        contract["direct_inputs"]
    ) != set(DIRECT_INPUT_NAMES):
        raise ContractError("direct input exact-key schema differs")
    input_records = {
        name: _validate_file_record(
            contract["direct_inputs"][name], f"direct_inputs.{name}"
        )
        for name in DIRECT_INPUT_NAMES
    }
    for name, record in input_records.items():
        required_root = (
            causal_durable_root if name in CAUSAL_DURABLE_INPUT_NAMES else durable_root
        )
        if Path(record["path"]) != required_root / DIRECT_INPUT_RELATIVE_PATHS[name]:
            raise ContractError(
                f"direct_inputs.{name} differs from its exact durable relative path"
            )
    input_paths = {name: Path(record["path"]) for name, record in input_records.items()}
    if len(set(input_paths.values())) != len(input_paths):
        raise ContractError("all direct launcher input paths must be pairwise distinct")
    expected_argv = exact_formal_argv(
        online_checkout=online_root,
        paired_causal_checkout=causal_root,
        direct_inputs=input_paths,
    )
    if contract["exact_formal_argv"] != expected_argv:
        raise ContractError("exact formal argv differs")
    if contract["exact_formal_argv_sha256"] != canonical_sha256(expected_argv):
        raise ContractError("exact formal argv digest differs")

    if verify_current_files:
        expected_mappings = {
            "online": _validate_artifact_mapping(
                checkout_root=online_root,
                durable_artifact_root=durable_root / ARTIFACT_RELATIVE_PATH,
                relative_path=ARTIFACT_RELATIVE_PATH,
                label="online artifact",
            ),
            "paired_causal": _validate_causal_artifact_mapping(
                checkout_root=causal_root,
                durable_root=causal_durable_root,
            ),
        }
        if contract["artifact_mappings"] != expected_mappings:
            raise ContractError("artifact mapping binding differs")
        bind_runtime = runtime_binding_provider or _default_runtime_binding_provider
        if contract["runtime"] != bind_runtime(tooling_root, online_root):
            raise ContractError("runtime cwd/environment/executable binding differs")
        validate_chain = causal_chain_validator or _default_causal_chain_validator
        if contract["causal_chain_binding"] != validate_chain(
            input_paths, causal_root, causal_durable_root
        ):
            raise ContractError("causal chain binding differs")
        source_roots = {
            "contract_builder": tooling_root,
            "online_launcher": online_root,
            "runtime_wrapper": tooling_root,
        }
        for name, record in source_records.items():
            label = f"source.{name}"
            path = Path(record["path"])
            current = _file_record(path, root=source_roots[name], label=label)
            if current != record:
                raise ContractError(f"current file differs from contract: {label}")
        for name, record in input_records.items():
            label = f"direct_inputs.{name}"
            path = Path(record["path"])
            required_root = (
                causal_durable_root
                if name in CAUSAL_DURABLE_INPUT_NAMES
                else durable_root
            )
            current = _file_record(path, root=required_root, label=label)
            if current != record:
                raise ContractError(f"current file differs from contract: {label}")
    return contract


def load_contract(
    path: Path,
    *,
    verify_current_files: bool = True,
    git_checker: GitChecker | None = None,
    runtime_binding_provider: RuntimeBindingProvider | None = None,
    causal_chain_validator: CausalChainValidator | None = None,
) -> dict[str, Any]:
    absolute = _absolute_normalized(path, "contract path")
    payload = _read_stable_bytes(absolute, root=absolute.parent, label="contract")
    if payload != payload.rstrip(b"\n") + b"\n" or payload.endswith(b"\n\n"):
        raise ContractError("contract must have exactly one trailing newline")
    contract = _load_object_bytes(payload)
    if payload != canonical_bytes(contract) + b"\n":
        raise ContractError("contract file is not canonical JSON")
    if stat.S_IMODE(os.lstat(absolute).st_mode) != 0o444:
        raise ContractError("published contract mode must be exactly 0444")
    return verify_contract(
        contract,
        verify_current_files=verify_current_files,
        git_checker=git_checker,
        runtime_binding_provider=runtime_binding_provider,
        causal_chain_validator=causal_chain_validator,
    )


def _fsync_directory(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ContractError("fsync target is not a real directory")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_contract(
    path: Path,
    contract: dict[str, Any],
    *,
    git_checker: GitChecker | None = None,
    runtime_binding_provider: RuntimeBindingProvider | None = None,
    causal_chain_validator: CausalChainValidator | None = None,
) -> None:
    """Publish canonical JSON with a literal ``O_CREAT|O_EXCL`` final open."""

    verify_contract(
        contract,
        verify_current_files=True,
        git_checker=git_checker,
        runtime_binding_provider=runtime_binding_provider,
        causal_chain_validator=causal_chain_validator,
    )
    durable_root = Path(contract["durable_attempt_root"])
    expected = durable_root / CONTRACT_RELATIVE_PATH
    requested = _absolute_normalized(path, "contract output")
    if requested != expected:
        raise ContractError("contract output differs from fixed durable path")
    _assert_real_directory_path(
        requested.parent,
        root=durable_root,
        label="contract parent",
    )
    if requested.exists() or requested.is_symlink():
        raise FileExistsError(f"refusing to overwrite contract: {requested}")
    payload = canonical_bytes(contract) + b"\n"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(requested, flags, 0o600)
    except FileExistsError as exc:
        raise FileExistsError(f"refusing to overwrite contract: {requested}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fchmod(handle.fileno(), 0o444)
            os.fsync(handle.fileno())
        _fsync_directory(requested.parent)
    except BaseException:
        # Once O_EXCL creates the final pathname it is permanent fail-closed
        # evidence.  Never unlink or retry it after a partial write/fsync.
        raise


def create_contract_expectation(
    contract_path: Path,
    *,
    created_at_utc: str | None = None,
    git_checker: GitChecker | None = None,
    runtime_binding_provider: RuntimeBindingProvider | None = None,
    causal_chain_validator: CausalChainValidator | None = None,
) -> dict[str, Any]:
    """Build an independently published one-way expectation for a contract file."""

    absolute = _absolute_normalized(contract_path, "contract path")
    contract = load_contract(
        absolute,
        verify_current_files=True,
        git_checker=git_checker,
        runtime_binding_provider=runtime_binding_provider,
        causal_chain_validator=causal_chain_validator,
    )
    raw = _read_stable_bytes(absolute, root=absolute.parent, label="contract")
    created = created_at_utc or datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if not isinstance(created, str) or _UTC_TIMESTAMP_RE.fullmatch(created) is None:
        raise ContractError("created_at_utc must be a UTC Z timestamp")
    expectation: dict[str, Any] = {
        "anchor_scope": LOCAL_INTEGRITY_ANCHOR_SCOPE,
        "contract_canonical_sha256": contract["contract_sha256"],
        "contract_file_sha256": hashlib.sha256(raw).hexdigest(),
        "contract_path": absolute.as_posix(),
        "created_at_utc": created,
        "protocol": CONTRACT_EXPECTATION_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "tooling_source_commit": contract["tooling_source_commit"],
    }
    expectation["expectation_sha256"] = canonical_sha256(expectation)
    return expectation


def verify_contract_expectation(
    expectation: dict[str, Any], contract_path: Path
) -> dict[str, Any]:
    _require_exact_keys(expectation, _EXPECTATION_KEYS, "contract expectation")
    if (
        expectation.get("protocol") != CONTRACT_EXPECTATION_PROTOCOL
        or expectation.get("schema_version") != SCHEMA_VERSION
        or expectation.get("anchor_scope") != LOCAL_INTEGRITY_ANCHOR_SCOPE
    ):
        raise ContractError("contract expectation protocol differs")
    embedded = _require_sha256(expectation["expectation_sha256"], "expectation_sha256")
    unsigned = dict(expectation)
    unsigned.pop("expectation_sha256")
    if embedded != canonical_sha256(unsigned):
        raise ContractError("contract expectation self-digest differs")
    absolute = _absolute_normalized(contract_path, "contract path")
    if expectation["contract_path"] != absolute.as_posix():
        raise ContractError("contract expectation path differs")
    raw = _read_stable_bytes(absolute, root=absolute.parent, label="contract")
    if expectation["contract_file_sha256"] != hashlib.sha256(raw).hexdigest():
        raise ContractError("contract expectation file digest differs")
    contract_object = _load_object_bytes(raw)
    if expectation["contract_canonical_sha256"] != contract_object.get(
        "contract_sha256"
    ):
        raise ContractError("contract expectation canonical digest differs")
    expectation_commit = _require_commit(expectation["tooling_source_commit"])
    if expectation_commit != contract_object.get("tooling_source_commit"):
        raise ContractError("contract expectation tooling commit differs")
    created = expectation["created_at_utc"]
    if not isinstance(created, str) or _UTC_TIMESTAMP_RE.fullmatch(created) is None:
        raise ContractError("contract expectation creation time is invalid")
    return expectation


def publish_contract_expectation(
    path: Path, expectation: dict[str, Any], *, contract_path: Path
) -> None:
    verify_contract_expectation(expectation, contract_path)
    contract_absolute = _absolute_normalized(contract_path, "contract path")
    expected = contract_absolute.parent.parent / CONTRACT_EXPECTATION_RELATIVE_PATH
    requested = _absolute_normalized(path, "contract expectation output")
    if requested != expected:
        raise ContractError("contract expectation output differs from fixed path")
    _assert_real_directory_path(
        requested.parent,
        root=contract_absolute.parent.parent,
        label="contract expectation parent",
    )
    if requested.exists() or requested.is_symlink():
        raise FileExistsError(
            f"refusing to overwrite contract expectation: {requested}"
        )
    payload = canonical_bytes(expectation) + b"\n"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(requested, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fchmod(handle.fileno(), 0o444)
        os.fsync(handle.fileno())
    _fsync_directory(requested.parent)


def load_contract_expectation(path: Path, *, contract_path: Path) -> dict[str, Any]:
    absolute = _absolute_normalized(path, "contract expectation path")
    raw = _read_stable_bytes(
        absolute, root=absolute.parent, label="contract expectation"
    )
    expectation = _load_object_bytes(raw)
    if raw != canonical_bytes(expectation) + b"\n":
        raise ContractError("contract expectation is not canonical JSON")
    if stat.S_IMODE(os.lstat(absolute).st_mode) != 0o444:
        raise ContractError("published contract expectation mode must be exactly 0444")
    return verify_contract_expectation(expectation, contract_path)


def create_prospective_execution_plan(
    contract_path: Path,
    expectation_path: Path,
    *,
    created_at_utc: str | None = None,
    git_checker: GitChecker | None = None,
    runtime_binding_provider: RuntimeBindingProvider | None = None,
    causal_chain_validator: CausalChainValidator | None = None,
) -> dict[str, Any]:
    """Create a one-way local integrity plan that never authorizes launch."""

    contract_absolute = _absolute_normalized(contract_path, "contract path")
    expectation_absolute = _absolute_normalized(
        expectation_path, "contract expectation path"
    )
    contract = load_contract(
        contract_absolute,
        verify_current_files=True,
        git_checker=git_checker,
        runtime_binding_provider=runtime_binding_provider,
        causal_chain_validator=causal_chain_validator,
    )
    if contract_absolute != Path(
        contract["fixed_paths"]["contract"]
    ) or expectation_absolute != Path(contract["fixed_paths"]["contract_expectation"]):
        raise ContractError("prospective plan inputs differ from contract fixed paths")
    expectation = load_contract_expectation(
        expectation_absolute, contract_path=contract_absolute
    )
    if expectation["anchor_scope"] != LOCAL_INTEGRITY_ANCHOR_SCOPE:
        raise ContractError("contract expectation is not the local integrity anchor")
    contract_raw = _read_stable_bytes(
        contract_absolute, root=contract_absolute.parent, label="contract"
    )
    fixed = contract.get("fixed_paths")
    if (
        not isinstance(fixed, dict)
        or fixed.get("contract") != contract_absolute.as_posix()
        or fixed.get("contract_expectation") != expectation_absolute.as_posix()
        or fixed.get("prospective_execution_plan")
        != (
            contract_absolute.parent.parent / PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH
        ).as_posix()
    ):
        raise ContractError("prospective execution plan fixed paths differ")
    expectation_raw = _read_stable_bytes(
        expectation_absolute,
        root=expectation_absolute.parent,
        label="contract expectation",
    )
    created = created_at_utc or datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if not isinstance(created, str) or _UTC_TIMESTAMP_RE.fullmatch(created) is None:
        raise ContractError("created_at_utc must be a UTC Z timestamp")
    plan: dict[str, Any] = {
        "anchor_scope": LOCAL_INTEGRITY_ANCHOR_SCOPE,
        "contract_canonical_sha256": contract["contract_sha256"],
        "contract_expectation_file_sha256": hashlib.sha256(expectation_raw).hexdigest(),
        "contract_expectation_path": expectation_absolute.as_posix(),
        "contract_file_sha256": hashlib.sha256(contract_raw).hexdigest(),
        "contract_path": contract_absolute.as_posix(),
        "created_at_utc": created,
        "exact_formal_argv": contract["exact_formal_argv"],
        "exact_formal_argv_sha256": contract["exact_formal_argv_sha256"],
        "launch_authorized": False,
        "production_blockers": list(PRODUCTION_BLOCKERS),
        "protocol": PROSPECTIVE_EXECUTION_PLAN_PROTOCOL,
        "runtime_sha256": canonical_sha256(contract["runtime"]),
        "schema_version": SCHEMA_VERSION,
        "source_files": contract["source_files"],
        "tooling_source_commit": contract["tooling_source_commit"],
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    return plan


def verify_prospective_execution_plan(
    plan: dict[str, Any], *, contract_path: Path, expectation_path: Path
) -> dict[str, Any]:
    _require_exact_keys(plan, _PROSPECTIVE_PLAN_KEYS, "prospective execution plan")
    if (
        plan.get("protocol") != PROSPECTIVE_EXECUTION_PLAN_PROTOCOL
        or plan.get("schema_version") != SCHEMA_VERSION
        or plan.get("anchor_scope") != LOCAL_INTEGRITY_ANCHOR_SCOPE
        or plan.get("launch_authorized") is not False
        or plan.get("production_blockers") != list(PRODUCTION_BLOCKERS)
    ):
        raise ContractError("prospective execution plan state differs")
    embedded = _require_sha256(plan["plan_sha256"], "prospective plan SHA-256")
    unsigned = dict(plan)
    unsigned.pop("plan_sha256")
    if embedded != canonical_sha256(unsigned):
        raise ContractError("prospective execution plan self-digest differs")
    contract_absolute = _absolute_normalized(contract_path, "contract path")
    expectation_absolute = _absolute_normalized(
        expectation_path, "contract expectation path"
    )
    contract_raw = _read_stable_bytes(
        contract_absolute, root=contract_absolute.parent, label="contract"
    )
    contract = _load_object_bytes(contract_raw)
    durable_root = contract_absolute.parent.parent
    fixed = contract.get("fixed_paths")
    if (
        contract_absolute != durable_root / CONTRACT_RELATIVE_PATH
        or not isinstance(fixed, dict)
        or fixed != _expected_fixed_paths(durable_root)
        or contract_absolute != Path(fixed["contract"])
        or expectation_absolute != Path(fixed["contract_expectation"])
    ):
        raise ContractError("prospective execution plan fixed input paths differ")
    if (
        plan["contract_path"] != contract_absolute.as_posix()
        or plan["contract_expectation_path"] != expectation_absolute.as_posix()
    ):
        raise ContractError("prospective execution plan input path differs")
    expectation = load_contract_expectation(
        expectation_absolute, contract_path=contract_absolute
    )
    expectation_raw = _read_stable_bytes(
        expectation_absolute,
        root=expectation_absolute.parent,
        label="contract expectation",
    )
    if (
        plan["contract_file_sha256"] != hashlib.sha256(contract_raw).hexdigest()
        or plan["contract_expectation_file_sha256"]
        != hashlib.sha256(expectation_raw).hexdigest()
        or plan["contract_canonical_sha256"] != contract.get("contract_sha256")
        or expectation.get("contract_canonical_sha256")
        != contract.get("contract_sha256")
        or expectation.get("anchor_scope") != LOCAL_INTEGRITY_ANCHOR_SCOPE
    ):
        raise ContractError("prospective execution plan input digest chain differs")
    if (
        plan["source_files"] != contract.get("source_files")
        or plan["exact_formal_argv"] != contract.get("exact_formal_argv")
        or plan["exact_formal_argv_sha256"] != contract.get("exact_formal_argv_sha256")
        or plan["runtime_sha256"] != canonical_sha256(contract.get("runtime"))
        or plan["tooling_source_commit"] != contract.get("tooling_source_commit")
    ):
        raise ContractError("prospective execution plan launch-spec binding differs")
    _require_sha256(plan["exact_formal_argv_sha256"], "plan argv SHA-256")
    _require_commit(plan["tooling_source_commit"])
    created = plan["created_at_utc"]
    if not isinstance(created, str) or _UTC_TIMESTAMP_RE.fullmatch(created) is None:
        raise ContractError("prospective execution plan creation time is invalid")
    return plan


def publish_prospective_execution_plan(
    path: Path,
    plan: dict[str, Any],
    *,
    contract_path: Path,
    expectation_path: Path,
) -> None:
    verify_prospective_execution_plan(
        plan, contract_path=contract_path, expectation_path=expectation_path
    )
    contract_absolute = _absolute_normalized(contract_path, "contract path")
    requested = _absolute_normalized(path, "prospective execution plan output")
    contract_raw = _read_stable_bytes(
        contract_absolute, root=contract_absolute.parent, label="contract"
    )
    contract_object = _load_object_bytes(contract_raw)
    fixed = contract_object.get("fixed_paths")
    if not isinstance(fixed, dict):
        raise ContractError("contract fixed paths are missing")
    expected = _absolute_normalized(
        Path(fixed.get("prospective_execution_plan", "")),
        "contract prospective execution plan path",
    )
    if requested != expected:
        raise ContractError("prospective execution plan output differs from fixed path")
    _assert_real_directory_path(
        requested.parent,
        root=contract_absolute.parent.parent,
        label="prospective execution plan parent",
    )
    if requested.exists() or requested.is_symlink():
        raise FileExistsError(
            f"refusing to overwrite prospective execution plan: {requested}"
        )
    payload = canonical_bytes(plan) + b"\n"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(requested, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fchmod(handle.fileno(), 0o444)
        os.fsync(handle.fileno())
    _fsync_directory(requested.parent)


def load_prospective_execution_plan(
    path: Path, *, contract_path: Path, expectation_path: Path
) -> dict[str, Any]:
    absolute = _absolute_normalized(path, "prospective execution plan path")
    raw = _read_stable_bytes(
        absolute, root=absolute.parent, label="prospective execution plan"
    )
    plan = _load_object_bytes(raw)
    if raw != canonical_bytes(plan) + b"\n":
        raise ContractError("prospective execution plan is not canonical JSON")
    if stat.S_IMODE(os.lstat(absolute).st_mode) != 0o444:
        raise ContractError("published prospective execution plan mode must be 0444")
    return verify_prospective_execution_plan(
        plan, contract_path=contract_path, expectation_path=expectation_path
    )


def _direct_input_arguments(parser: argparse.ArgumentParser) -> None:
    for name in DIRECT_INPUT_NAMES:
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)


def _direct_inputs_from_args(args: argparse.Namespace) -> dict[str, Path]:
    return {name: getattr(args, name) for name in DIRECT_INPUT_NAMES}


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build and O_EXCL-publish contract")
    build.add_argument("--tooling-source-commit", required=True)
    build.add_argument("--online-attempt-checkout", type=Path, required=True)
    build.add_argument("--paired-causal-attempt-checkout", type=Path, required=True)
    build.add_argument("--paired-causal-durable-attempt-root", type=Path, required=True)
    build.add_argument("--durable-attempt-root", type=Path, required=True)
    build.add_argument("--wrapper-tooling-root", type=Path, required=True)
    _direct_input_arguments(build)

    verify = subparsers.add_parser("verify", help="strictly verify current contract")
    verify.add_argument("--contract", type=Path, required=True)
    expectation_parser = subparsers.add_parser(
        "expectation",
        help="independently build and O_EXCL-publish the contract expectation",
    )
    expectation_parser.add_argument("--contract", type=Path, required=True)
    plan_parser = subparsers.add_parser(
        "plan",
        help="build and O_EXCL-publish a launch-disabled prospective plan",
    )
    plan_parser.add_argument("--contract", type=Path, required=True)
    plan_parser.add_argument("--expectation", type=Path, required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "verify":
        contract = load_contract(args.contract, verify_current_files=True)
        print(contract["contract_sha256"])
        return
    if args.command == "expectation":
        expectation = create_contract_expectation(args.contract)
        contract_path = _absolute_normalized(args.contract, "contract path")
        output = contract_path.parent.parent / CONTRACT_EXPECTATION_RELATIVE_PATH
        publish_contract_expectation(output, expectation, contract_path=contract_path)
        print(output)
        print(expectation["expectation_sha256"])
        return
    if args.command == "plan":
        plan = create_prospective_execution_plan(args.contract, args.expectation)
        contract_path = _absolute_normalized(args.contract, "contract path")
        expectation_path = _absolute_normalized(
            args.expectation, "contract expectation path"
        )
        output = contract_path.parent.parent / PROSPECTIVE_EXECUTION_PLAN_RELATIVE_PATH
        publish_prospective_execution_plan(
            output,
            plan,
            contract_path=contract_path,
            expectation_path=expectation_path,
        )
        print(output)
        print(plan["plan_sha256"])
        return
    contract = create_contract(
        tooling_source_commit=args.tooling_source_commit,
        online_attempt_checkout=args.online_attempt_checkout,
        paired_causal_attempt_checkout=args.paired_causal_attempt_checkout,
        paired_causal_durable_attempt_root=args.paired_causal_durable_attempt_root,
        durable_attempt_root=args.durable_attempt_root,
        wrapper_tooling_root=args.wrapper_tooling_root,
        direct_inputs=_direct_inputs_from_args(args),
    )
    output = Path(contract["fixed_paths"]["contract"])
    publish_contract(output, contract)
    print(output)
    print(contract["contract_sha256"])


if __name__ == "__main__":
    main()
