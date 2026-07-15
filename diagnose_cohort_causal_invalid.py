#!/usr/bin/env python3
"""Outcome-safe diagnosis for the invalid causal-retry-004 formal run.

``freeze`` binds the completed retry without decoding either formal artifact.
``diagnose`` rechecks every binding and process absence before decoding only the
formal decision.  Its result intentionally cannot contain efficacy fields or
validator error text.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence


sys.dont_write_bytecode = True


SOURCE_COMMIT = "fd9ab294a939350ee5f174acbab0ad279e33ee1e"
RETRY_ID = "causal-retry-004"
ATTEMPT_ID = "attempt-002"
SCRIPT_FILENAME = "diagnose_cohort_causal_invalid.py"
AMENDMENT_FILENAME = "CAUSAL_FORMAL_INVALID_DIAGNOSTIC_AMENDMENT_V1.md"
VALIDATOR_FILENAME = "validate_cohort_causal_results.py"
VALIDATOR_SHA256 = "4f9ddc55ce7e62e6a8cb7540910f770aef179508bf5511a431ec98072f2b5a4f"
PLAN_FILENAME = "CAUSAL_FORMAL_INVALID_DIAGNOSTIC_PLAN_V1.json"
RESULT_FILENAME = "CAUSAL_FORMAL_INVALID_DIAGNOSTIC_RECEIPT_V1.json"
PLAN_PROTOCOL = "cohort_causal_invalid_diagnostic_plan_v1"
RECEIPT_PROTOCOL = "cohort_causal_invalid_diagnostic_receipt_v1"
EXPECTED_PYTHON_PATH = "/usr/bin/python3.10"
EXPECTED_PYTHON_VERSION = "3.10.12"
MINIMUM_FREEZE_STABILITY_SECONDS = 1.0
PUBLISH_VISIBILITY_TIMEOUT_SECONDS = 60.0
PUBLISH_POLL_SECONDS = 0.25
TOOLING_REMOTE_REF = (
    "refs/remotes/origin/codex/cohort-closed-loop-state-prereg"
)
TOOLING_REMOTE_FETCHSPEC = (
    "+refs/heads/codex/cohort-closed-loop-state-prereg:"
    "refs/remotes/origin/codex/cohort-closed-loop-state-prereg"
)
DIAGNOSTIC_ENV = {
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
}

_PID_RE = re.compile(rb"[1-9][0-9]*\n")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

INVALID_DECISION_KEYS = frozenset(
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
        "protocol",
        "publication_inference",
        "publication_grade",
        "schema_version",
        "status",
        "threshold_checks",
    }
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


@dataclass(frozen=True)
class ReasonRule:
    rule_id: str
    category: str
    terms: tuple[str, ...]


# Ordered and hashed into the frozen plan.  The last rule is the sole fallback.
REASON_RULES = (
    ReasonRule(
        "vcr_2879_active_final_hash_unchanged",
        "update_contract",
        ("active final parameter hash did not change",),
    ),
    ReasonRule(
        "vcr_2881_no_audited_active_parameter_change",
        "update_contract",
        ("no audited active replay update changed parameters",),
    ),
    ReasonRule(
        "vcr_2862_lr0_final_hash_changed",
        "update_contract",
        ("lr0 final parameter hash changed",),
    ),
    ReasonRule(
        "vcr_2873_lr0_operation_hash_changed",
        "update_contract",
        ("lr0 replay operation hash changed",),
    ),
    ReasonRule(
        "vcr_3170_active_lr0_operation_sequence_mismatch",
        "update_contract",
        ("active/lr0 ordered operation sequence mismatch",),
    ),
    ReasonRule(
        "vcr_3178_paired_initial_hash_mismatch",
        "update_contract",
        ("paired initial parameter hashes differ",),
    ),
    ReasonRule(
        "vcr_3183_collector_evaluation_initial_hash_mismatch",
        "update_contract",
        ("collector/evaluation initial parameter hashes differ",),
    ),
    ReasonRule(
        "vcr_3204_active_format_regression",
        "format_stability",
        ("active parse retry/repair total exceeds lr0",),
    ),
    ReasonRule(
        "vcr_3196_paired_terminal_signature_mismatch",
        "format_stability",
        ("paired terminal prompt/schema/study signatures differ",),
    ),
    ReasonRule(
        "update_replay_integrity",
        "update_contract",
        ("replay", "ordered operation", "hash chain"),
    ),
    ReasonRule(
        "update_parameter_transition",
        "update_contract",
        (
            "trainable parameter",
            "trainable-parameter",
            "initial parameter",
            "parameter hash",
            "parameter sha-256",
            "optimizer",
            "gradient",
            "learning-rate",
            "learning rate",
            "lr0",
        ),
    ),
    ReasonRule(
        "tape_candidate_diversity",
        "tape_integrity",
        ("candidate", "env-bon", "best/worst", "valid_unique"),
    ),
    ReasonRule(
        "tape_sampling_contract",
        "tape_integrity",
        ("sampling", "sample_attempt", "draw accounting"),
    ),
    ReasonRule(
        "tape_reward_contract",
        "tape_integrity",
        ("reward-pg", "committed reward", "selected_batches"),
    ),
    ReasonRule(
        "tape_integrity",
        "tape_integrity",
        ("tape", "collector"),
    ),
    ReasonRule(
        "format_schema_regression",
        "format_stability",
        (
            "schema_valid",
            "fallback",
            "truncated",
            "extraction",
            "parse retr",
            "repair",
            "format regression",
        ),
    ),
    ReasonRule(
        "evaluation_heldout_identity",
        "evaluation_integrity",
        ("held-out", "heldout", "outcome identity", "outcome order"),
    ),
    ReasonRule(
        "evaluation_scoring_contract",
        "evaluation_integrity",
        ("scoring", "reward mean", "terminal prompt", "terminal action"),
    ),
    ReasonRule(
        "evaluation_outcome_integrity",
        "evaluation_integrity",
        ("outcome", "score", "reward_sha256"),
    ),
    ReasonRule(
        "endpoint_seed_pair_completeness",
        "endpoint_completeness",
        ("three seed", "three complete", "run seeds", "seed pairs"),
    ),
    ReasonRule(
        "endpoint_matched_pairing",
        "endpoint_completeness",
        ("paired", "pair_id", "configs differ", "all six"),
    ),
    ReasonRule(
        "provenance_source_binding",
        "provenance_binding",
        (
            "provenance",
            "source_commit",
            "source commit",
            "preregister",
            "addendum",
        ),
    ),
    ReasonRule(
        "provenance_artifact_binding",
        "provenance_binding",
        (
            "checked-in",
            "corpus",
            "manifest.json",
            "artifact path",
            "sha-256 mismatch",
            "sha-256 drift",
            "config",
        ),
    ),
    ReasonRule(
        "schema_contract",
        "schema_contract",
        (
            "schema",
            "must be an object",
            "must be a list",
            "must be a non-empty",
            "must contain",
            "must be exactly",
            "invalid name",
            "nonnegative integer",
            "duplicate",
            "not unique",
        ),
    ),
    ReasonRule("UNKNOWN_INTEGRITY_FAILURE", "other_integrity", ()),
)


class InvalidDiagnosticError(RuntimeError):
    """A fail-closed diagnostic contract error with no scientific payload."""


@dataclass(frozen=True)
class AttemptLayout:
    tooling_commit: str
    checkout_base: Path = Path("/mnt/localssd/ttt-rl-cohort-causal")
    durable_base: Path = Path(
        "/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal"
    )

    @property
    def checkout_root(self) -> Path:
        return self.checkout_base / SOURCE_COMMIT / RETRY_ID / ATTEMPT_ID

    @property
    def durable_root(self) -> Path:
        return (
            self.durable_base
            / SOURCE_COMMIT
            / "retries"
            / RETRY_ID
            / "attempts"
            / ATTEMPT_ID
        )

    @property
    def artifact_root(self) -> Path:
        return self.durable_root / "artifacts" / "cohort_causal"

    @property
    def control_root(self) -> Path:
        return self.durable_root / "control"

    @property
    def prep_root(self) -> Path:
        return self.durable_root / "prep"

    @property
    def tooling_root(self) -> Path:
        return self.control_root / "invalid-verifier" / self.tooling_commit

    @property
    def formal_tooling_root(self) -> Path:
        return self.control_root / "verifier" / SOURCE_COMMIT

    @property
    def self_path(self) -> Path:
        return self.tooling_root / SCRIPT_FILENAME

    @property
    def plan_path(self) -> Path:
        return self.control_root / PLAN_FILENAME

    @property
    def result_path(self) -> Path:
        return self.control_root / RESULT_FILENAME

    def amendment_path(self) -> Path:
        return self.tooling_root / AMENDMENT_FILENAME

    def inputs(self) -> dict[str, Path]:
        return {
            "attester_v1_source": self.formal_tooling_root
            / "attest_cohort_causal_completion.py",
            "attester_v2_source": self.formal_tooling_root
            / "attest_cohort_causal_completion_v2.py",
            "formal_decision": self.artifact_root / "formal_decision.json",
            "formal_manifest": self.artifact_root / "formal_manifest.json",
            "launch_expectation": self.control_root
            / "CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json",
            "procfs_exception_inventory": self.control_root
            / "CAUSAL_TERMINAL_VERIFIER_PROCFS_EXCEPTION_INVENTORY_V2.json",
            "seal_v1_source": self.formal_tooling_root
            / "build_cohort_structured_state_execution_seal.py",
            "seal_v2_source": self.formal_tooling_root
            / "build_cohort_structured_state_execution_seal_v2.py",
            "validator_source": self.checkout_root / VALIDATOR_FILENAME,
            "wrapper_exit": self.prep_root / "causal_formal.exit",
            "wrapper_pid": self.prep_root / "causal_formal.pid",
        }


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _absolute(path: Path, label: str) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(path.as_posix())) != path:
        raise InvalidDiagnosticError(f"{label} is not a canonical absolute path")
    return path


def _assert_no_symlink_components(path: Path, label: str) -> None:
    target = _absolute(path, label)
    current = Path(target.anchor)
    try:
        for part in target.parts[1:]:
            current = current / part
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise InvalidDiagnosticError(f"{label} has a symlink path component")
    except FileNotFoundError as exc:
        raise InvalidDiagnosticError(f"{label} path component is missing") from exc


def _stat_record(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "nlink": info.st_nlink,
        "size_bytes": info.st_size,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _read_opaque(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    target = _absolute(path, label)
    _assert_no_symlink_components(target, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise InvalidDiagnosticError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InvalidDiagnosticError(f"{label} is not a single-link regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        pathname = target.lstat()
    except OSError as exc:
        raise InvalidDiagnosticError(f"{label} pathname is not stable") from exc
    raw = b"".join(chunks)
    if (
        _stat_record(before) != _stat_record(after)
        or _stat_record(after) != _stat_record(pathname)
        or stat.S_ISLNK(pathname.st_mode)
        or len(raw) != after.st_size
    ):
        raise InvalidDiagnosticError(f"{label} changed during opaque read")
    return raw, {
        "path": target.as_posix(),
        "sha256": _sha256(raw),
        "stat": _stat_record(after),
    }


def _publication_identity(info: Mapping[str, int]) -> dict[str, int]:
    return {
        key: info[key]
        for key in ("device", "inode", "mode", "size_bytes", "uid", "gid", "mtime_ns")
    }


def _wait_for_published_stability(
    path: Path,
    payload: bytes,
    *,
    expected_identity: Mapping[str, int],
    timeout_seconds: float = PUBLISH_VISIBILITY_TIMEOUT_SECONDS,
    poll_seconds: float = PUBLISH_POLL_SECONDS,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
    read_fn: Callable[[Path, str], tuple[bytes, dict[str, Any]]] = _read_opaque,
) -> None:
    if timeout_seconds <= 0 or poll_seconds <= 0:
        raise InvalidDiagnosticError("publication stability timing is invalid")
    deadline = monotonic_fn() + timeout_seconds
    prior: dict[str, Any] | None = None
    consecutive = 0
    while monotonic_fn() <= deadline:
        try:
            raw, binding = read_fn(path, "published diagnostic artifact")
        except (InvalidDiagnosticError, OSError):
            prior = None
            consecutive = 0
        else:
            if raw != payload:
                raise InvalidDiagnosticError("published diagnostic bytes differ")
            if _publication_identity(binding["stat"]) != dict(expected_identity):
                raise InvalidDiagnosticError("published diagnostic inode identity differs")
            if binding == prior:
                consecutive += 1
            else:
                prior = binding
                consecutive = 1
            if consecutive >= 2:
                return
        remaining = deadline - monotonic_fn()
        if remaining <= 0:
            break
        sleep_fn(min(poll_seconds, remaining))
    raise InvalidDiagnosticError("published diagnostic did not become stably visible")


def _publish_no_overwrite(
    path: Path,
    payload: bytes,
    *,
    timeout_seconds: float = PUBLISH_VISIBILITY_TIMEOUT_SECONDS,
    poll_seconds: float = PUBLISH_POLL_SECONDS,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    target = _absolute(path, "publication path")
    _assert_no_symlink_components(target.parent, "publication parent")
    try:
        parent = target.parent.lstat()
    except OSError as exc:
        raise InvalidDiagnosticError("publication parent is unavailable") from exc
    if not stat.S_ISDIR(parent.st_mode) or target.parent.is_symlink():
        raise InvalidDiagnosticError("publication parent is not a real directory")
    descriptor, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.tmp.")
    temporary = Path(name)
    expected_identity: dict[str, int] | None = None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o444)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            expected_identity = _publication_identity(
                _stat_record(os.fstat(handle.fileno()))
            )
        os.link(temporary, target)
        directory_fd = os.open(
            target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as exc:
        raise InvalidDiagnosticError(
            "no-overwrite publication target already exists"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)
    if expected_identity is None:
        raise InvalidDiagnosticError("publication identity was not captured")
    directory_fd = os.open(
        target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    _wait_for_published_stability(
        target,
        payload,
        expected_identity=expected_identity,
        timeout_seconds=timeout_seconds,
        poll_seconds=poll_seconds,
        monotonic_fn=monotonic_fn,
        sleep_fn=sleep_fn,
    )


def _pid_is_live(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _rule_contract_sha256() -> str:
    return _sha256(
        _canonical_bytes(
            [
                {"category": rule.category, "rule_id": rule.rule_id, "terms": rule.terms}
                for rule in REASON_RULES
            ]
        )
    )


def _parse_wrapper_pid(raw: bytes) -> int:
    if _PID_RE.fullmatch(raw) is None:
        raise InvalidDiagnosticError("wrapper PID file is not canonical")
    pid = int(raw[:-1], 10)
    if pid <= 1:
        raise InvalidDiagnosticError("wrapper PID is not a user process")
    return pid


def _current_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
    except OSError as exc:
        raise InvalidDiagnosticError("current boot ID is unavailable") from exc


def _validate_launch_expectation(
    raw: bytes,
    *,
    layout: AttemptLayout,
    pid_raw: bytes,
    hostname_fn: Callable[[], str] = socket.gethostname,
    boot_id_fn: Callable[[], str] = _current_boot_id,
) -> dict[str, int]:
    value = _strict_json(raw, "launch expectation")
    if not isinstance(value, dict) or set(value) != LAUNCH_EXPECTATION_KEYS:
        raise InvalidDiagnosticError("launch expectation schema differs")
    pid = _parse_wrapper_pid(pid_raw)
    start_ticks = value.get("wrapper_start_ticks")
    if (
        value.get("protocol") != "cohort_causal_formal_launch_expectation_v1"
        or value.get("schema_version") != 1
        or value.get("launch_mode") != "formal"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("source_commit") != SOURCE_COMMIT
        or value.get("checkout_root") != layout.checkout_root.as_posix()
        or value.get("durable_attempt_root") != layout.durable_root.as_posix()
        or value.get("artifact_root") != layout.artifact_root.as_posix()
        or value.get("pid_file") != layout.inputs()["wrapper_pid"].as_posix()
        or value.get("exit_file") != layout.inputs()["wrapper_exit"].as_posix()
        or value.get("wrapper_pid") != pid
        or value.get("node_hostname") != hostname_fn()
        or value.get("boot_id") != boot_id_fn()
        or not isinstance(start_ticks, int)
        or isinstance(start_ticks, bool)
        or start_ticks <= 0
        or value.get("pid_file_sha256_at_registration") != _sha256(pid_raw)
    ):
        raise InvalidDiagnosticError("launch expectation identity differs")
    return {"pid": pid, "start_ticks": start_ticks}


def _fixed_roots(layout: AttemptLayout) -> dict[str, str]:
    if (
        re.fullmatch(r"[0-9a-f]{40}", layout.tooling_commit) is None
        or layout.tooling_commit == SOURCE_COMMIT
    ):
        raise InvalidDiagnosticError("diagnostic tooling commit is invalid")
    _absolute(layout.checkout_base, "checkout base")
    _absolute(layout.durable_base, "durable base")
    return {
        "artifact_root": layout.artifact_root.as_posix(),
        "checkout_root": layout.checkout_root.as_posix(),
        "control_root": layout.control_root.as_posix(),
        "durable_root": layout.durable_root.as_posix(),
        "prep_root": layout.prep_root.as_posix(),
        "tooling_root": layout.tooling_root.as_posix(),
    }


def _attempt_binding(layout: AttemptLayout) -> dict[str, str]:
    return {
        "attempt_id": ATTEMPT_ID,
        "diagnostic_tooling_commit": layout.tooling_commit,
        "formal_source_commit": SOURCE_COMMIT,
        "retry_id": RETRY_ID,
    }


def _phase_argv(layout: AttemptLayout, phase: str) -> list[str]:
    prefix = [EXPECTED_PYTHON_PATH, "-I", layout.self_path.as_posix(), phase]
    if phase == "freeze":
        return [*prefix, "--tooling-commit", layout.tooling_commit]
    if phase == "diagnose":
        return [*prefix, "--plan", layout.plan_path.as_posix()]
    raise InvalidDiagnosticError("diagnostic phase is invalid")


def _validate_runtime(
    *,
    layout: AttemptLayout,
    phase: str,
    runtime_python_path: str,
    runtime_python_version: str,
    actual_argv: Sequence[str],
    cwd_fn: Callable[[], str],
    environ_fn: Callable[[], Mapping[str, str]],
    isolated: int,
) -> None:
    if (
        runtime_python_path != EXPECTED_PYTHON_PATH
        or runtime_python_version != EXPECTED_PYTHON_VERSION
        or list(actual_argv) != _phase_argv(layout, phase)
        or cwd_fn() != "/tmp"
        or dict(environ_fn()) != DIAGNOSTIC_ENV
        or isolated != 1
    ):
        raise InvalidDiagnosticError("diagnostic runtime contract differs")


def _git_output(checkout: Path, *args: str, binary: bool = False) -> bytes | str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=checkout,
            check=True,
            capture_output=True,
            text=not binary,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InvalidDiagnosticError("scientific checkout git audit failed") from exc
    return completed.stdout if binary else completed.stdout.strip()


def _git_success(checkout: Path, *args: str) -> None:
    try:
        subprocess.run(
            ["git", *args],
            cwd=checkout,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InvalidDiagnosticError("tooling commit ancestry audit failed") from exc


def _validate_tooling_commit_provenance(
    layout: AttemptLayout, source_raw: bytes, amendment_raw: bytes
) -> dict[str, Any]:
    checkout = layout.checkout_root
    commit_type = _git_output(checkout, "cat-file", "-t", layout.tooling_commit)
    fetchspecs = _git_output(checkout, "config", "--get-all", "remote.origin.fetch")
    if commit_type != "commit" or not isinstance(fetchspecs, str):
        raise InvalidDiagnosticError("diagnostic tooling object is not a commit")
    if fetchspecs.splitlines() != [TOOLING_REMOTE_FETCHSPEC]:
        raise InvalidDiagnosticError("diagnostic tooling fetchspec differs")
    _git_success(checkout, "rev-parse", "--verify", f"{TOOLING_REMOTE_REF}^{{commit}}")
    _git_success(
        checkout,
        "merge-base",
        "--is-ancestor",
        SOURCE_COMMIT,
        layout.tooling_commit,
    )
    _git_success(
        checkout,
        "merge-base",
        "--is-ancestor",
        layout.tooling_commit,
        TOOLING_REMOTE_REF,
    )
    script_blob = _git_output(
        checkout,
        "cat-file",
        "blob",
        f"{layout.tooling_commit}:{SCRIPT_FILENAME}",
        binary=True,
    )
    amendment_blob = _git_output(
        checkout,
        "cat-file",
        "blob",
        f"{layout.tooling_commit}:{AMENDMENT_FILENAME}",
        binary=True,
    )
    if (
        not isinstance(script_blob, bytes)
        or not isinstance(amendment_blob, bytes)
        or script_blob != source_raw
        or amendment_blob != amendment_raw
    ):
        raise InvalidDiagnosticError("deployed diagnostic tooling differs from commit")
    return {
        "amendment_blob_sha256": _sha256(amendment_blob),
        "deployed_blobs_match_commit": True,
        "fetched_remote_ref": TOOLING_REMOTE_REF,
        "formal_source_is_ancestor": True,
        "remote_ref_contains_tooling_commit": True,
        "script_blob_sha256": _sha256(script_blob),
        "tooling_commit": layout.tooling_commit,
    }


def _validate_clean_checkout(layout: AttemptLayout) -> dict[str, str]:
    checkout = layout.checkout_root
    if (
        _git_output(checkout, "rev-parse", "--show-toplevel")
        != checkout.as_posix()
        or _git_output(checkout, "rev-parse", "HEAD") != SOURCE_COMMIT
    ):
        raise InvalidDiagnosticError("scientific checkout identity differs")
    status = _git_output(
        checkout,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        binary=True,
    )
    if not isinstance(status, bytes):
        raise AssertionError("binary git output was decoded")
    records = [record for record in status.split(b"\0") if record]
    allowed = {b"?? artifacts", b"?? artifacts/", b"!! artifacts", b"!! artifacts/"}
    if len(records) != 1 or records[0] not in allowed:
        raise InvalidDiagnosticError("scientific checkout is not clean at fixed HEAD")
    return {"head": SOURCE_COMMIT, "status": "clean_artifacts_link_only"}


def _audit_temporary_artifacts(layout: AttemptLayout) -> None:
    for root in (layout.artifact_root, layout.prep_root):
        _assert_no_symlink_components(root, "temporary-audit root")
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            for name in [*dirnames, *filenames]:
                path = Path(directory) / name
                try:
                    mode = os.lstat(path).st_mode
                except OSError as exc:
                    raise InvalidDiagnosticError(
                        "temporary artifact audit is unstable"
                    ) from exc
                if (
                    stat.S_ISLNK(mode)
                    or name.endswith(".live.json")
                    or (name.startswith(".") and ".tmp." in name)
                    or name.endswith(".partial")
                    or name.endswith(".part")
                ):
                    raise InvalidDiagnosticError(
                        "live, temporary, partial, or symlink artifact remains"
                    )


def _verify_formal_tool_sources(
    layout: AttemptLayout, input_raw: Mapping[str, bytes]
) -> None:
    source_names = {
        "attester_v1_source": "attest_cohort_causal_completion.py",
        "attester_v2_source": "attest_cohort_causal_completion_v2.py",
        "seal_v1_source": "build_cohort_structured_state_execution_seal.py",
        "seal_v2_source": "build_cohort_structured_state_execution_seal_v2.py",
    }
    for role, filename in source_names.items():
        tracked, _ = _read_opaque(layout.checkout_root / filename, f"tracked {role}")
        if input_raw[role] != tracked:
            raise InvalidDiagnosticError("deployed formal verifier source differs")


def _opaque_snapshot(
    *,
    layout: AttemptLayout,
    source: Path,
    pid_is_live_fn: Callable[[int], bool],
    hostname_fn: Callable[[], str],
    boot_id_fn: Callable[[], str],
    tooling_check_fn: Callable[[AttemptLayout, bytes, bytes], Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    source_raw, source_binding = _read_opaque(source, "diagnostic source")
    amendment_raw, amendment_binding = _read_opaque(
        layout.amendment_path(), "diagnostic amendment"
    )
    if not source_raw or not amendment_raw:
        raise InvalidDiagnosticError("diagnostic tooling input is empty")
    input_bindings: dict[str, dict[str, Any]] = {}
    input_raw: dict[str, bytes] = {}
    for name, path in layout.inputs().items():
        raw, binding = _read_opaque(path, name)
        input_raw[name] = raw
        input_bindings[name] = binding
    if input_raw["wrapper_exit"] != b"1\n":
        raise InvalidDiagnosticError("wrapper exit is not exact invalid code one")
    pid = _parse_wrapper_pid(input_raw["wrapper_pid"])
    if pid_is_live_fn(pid):
        raise InvalidDiagnosticError("registered wrapper remains live")
    if input_bindings["validator_source"]["sha256"] != VALIDATOR_SHA256:
        raise InvalidDiagnosticError("validator source differs from the formal commit")
    _verify_formal_tool_sources(layout, input_raw)
    wrapper_identity = _validate_launch_expectation(
        input_raw["launch_expectation"],
        layout=layout,
        pid_raw=input_raw["wrapper_pid"],
        hostname_fn=hostname_fn,
        boot_id_fn=boot_id_fn,
    )
    exit_mtime = input_bindings["wrapper_exit"]["stat"]["mtime_ns"]
    if exit_mtime <= max(
        input_bindings["formal_manifest"]["stat"]["mtime_ns"],
        input_bindings["formal_decision"]["stat"]["mtime_ns"],
    ):
        raise InvalidDiagnosticError("wrapper exit does not strictly postdate outputs")
    return {
        "amendment_binding": amendment_binding,
        "input_bindings": input_bindings,
        "self_binding": source_binding,
        "tooling_provenance": dict(
            tooling_check_fn(layout, source_raw, amendment_raw)
        ),
        "wrapper_identity": wrapper_identity,
    }, input_raw


def freeze(
    *,
    layout: AttemptLayout,
    actual_argv: Sequence[str],
    source_path: Path | None = None,
    pid_is_live_fn: Callable[[int], bool] = _pid_is_live,
    scan_fn: Callable[[AttemptLayout], None] | None = None,
    git_check_fn: Callable[[AttemptLayout], Mapping[str, str]] = (
        _validate_clean_checkout
    ),
    tooling_check_fn: Callable[
        [AttemptLayout, bytes, bytes], Mapping[str, Any]
    ] = _validate_tooling_commit_provenance,
    temporary_audit_fn: Callable[[AttemptLayout], None] = _audit_temporary_artifacts,
    hostname_fn: Callable[[], str] = socket.gethostname,
    boot_id_fn: Callable[[], str] = _current_boot_id,
    cwd_fn: Callable[[], str] = os.getcwd,
    environ_fn: Callable[[], Mapping[str, str]] = lambda: dict(os.environ),
    isolated: int = sys.flags.isolated,
    sleep_fn: Callable[[float], None] = time.sleep,
    stability_seconds: float = MINIMUM_FREEZE_STABILITY_SECONDS,
    runtime_python_path: str = EXPECTED_PYTHON_PATH,
    runtime_python_version: str = EXPECTED_PYTHON_VERSION,
    now_fn: Callable[[], str] = _now_utc,
    publish_fn: Callable[[Path, bytes], None] = _publish_no_overwrite,
) -> dict[str, Any]:
    """Freeze opaque retry inputs into the canonical no-overwrite plan."""

    source = Path(__file__).absolute() if source_path is None else source_path
    if source != layout.self_path:
        raise InvalidDiagnosticError("diagnostic source is outside fixed tooling path")
    _fixed_roots(layout)
    if stability_seconds < MINIMUM_FREEZE_STABILITY_SECONDS:
        raise InvalidDiagnosticError("freeze stability interval is too short")
    _validate_runtime(
        layout=layout,
        phase="freeze",
        runtime_python_path=runtime_python_path,
        runtime_python_version=runtime_python_version,
        actual_argv=actual_argv,
        cwd_fn=cwd_fn,
        environ_fn=environ_fn,
        isolated=isolated,
    )
    process_scan = (
        (
            lambda selected: _scan_with_v2_policy(
                selected, hostname_fn=hostname_fn, boot_id_fn=boot_id_fn
            )
        )
        if scan_fn is None
        else scan_fn
    )
    first_git = dict(git_check_fn(layout))
    temporary_audit_fn(layout)
    process_scan(layout)
    first, _ = _opaque_snapshot(
        layout=layout,
        source=source,
        pid_is_live_fn=pid_is_live_fn,
        hostname_fn=hostname_fn,
        boot_id_fn=boot_id_fn,
        tooling_check_fn=tooling_check_fn,
    )
    sleep_fn(stability_seconds)
    second, _ = _opaque_snapshot(
        layout=layout,
        source=source,
        pid_is_live_fn=pid_is_live_fn,
        hostname_fn=hostname_fn,
        boot_id_fn=boot_id_fn,
        tooling_check_fn=tooling_check_fn,
    )
    if first != second:
        raise InvalidDiagnosticError("opaque bindings changed across freeze snapshots")
    process_scan(layout)
    temporary_audit_fn(layout)
    second_git = dict(git_check_fn(layout))
    if first_git != second_git:
        raise InvalidDiagnosticError("scientific checkout changed across freeze")
    plan = {
        "amendment_binding": second["amendment_binding"],
        "attempt_binding": _attempt_binding(layout),
        "classifier_contract_sha256": _rule_contract_sha256(),
        "efficacy_fields_emitted": False,
        "formal_manifest_parsed": False,
        "frozen_at_utc": now_fn(),
        "input_bindings": second["input_bindings"],
        "invocations": {
            "diagnose": _phase_argv(layout, "diagnose"),
            "freeze": _phase_argv(layout, "freeze"),
        },
        "plan_path": layout.plan_path.as_posix(),
        "protocol": PLAN_PROTOCOL,
        "raw_errors_emitted": False,
        "result_path": layout.result_path.as_posix(),
        "roots": _fixed_roots(layout),
        "runtime": {
            "cwd": "/tmp",
            "environment_sha256": _sha256(_canonical_bytes(DIAGNOSTIC_ENV)),
            "isolated": True,
            "python_path": EXPECTED_PYTHON_PATH,
            "python_version": EXPECTED_PYTHON_VERSION,
        },
        "schema_version": 1,
        "self_binding": second["self_binding"],
        "semantic_artifacts_opened": False,
        "status": "frozen_outcome_blind",
        "source_checkout": first_git,
        "tooling_provenance": second["tooling_provenance"],
        "wrapper_identity": second["wrapper_identity"],
    }
    publish_fn(layout.plan_path, _canonical_bytes(plan))
    return plan


def _strict_json(raw: bytes, label: str) -> Any:
    def reject_constant(_: str) -> None:
        raise ValueError

    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidDiagnosticError(f"{label} is not strict JSON") from exc


def _validate_binding(value: Any, expected_path: Path, label: str) -> bytes:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "stat"}:
        raise InvalidDiagnosticError(f"{label} binding schema differs")
    if value.get("path") != expected_path.as_posix() or _SHA256_RE.fullmatch(
        value.get("sha256", "")
    ) is None:
        raise InvalidDiagnosticError(f"{label} binding path or digest differs")
    raw, current = _read_opaque(expected_path, label)
    if current != value:
        raise InvalidDiagnosticError(f"{label} binding changed after freeze")
    return raw


def _load_and_validate_plan(
    layout: AttemptLayout,
    source_path: Path,
    *,
    hostname_fn: Callable[[], str],
    boot_id_fn: Callable[[], str],
    tooling_check_fn: Callable[[AttemptLayout, bytes, bytes], Mapping[str, Any]],
) -> tuple[dict[str, Any], bytes, dict[str, Any], dict[str, bytes]]:
    plan_raw, plan_binding = _read_opaque(layout.plan_path, "diagnostic plan")
    plan = _strict_json(plan_raw, "diagnostic plan")
    expected_keys = {
        "amendment_binding",
        "attempt_binding",
        "classifier_contract_sha256",
        "efficacy_fields_emitted",
        "formal_manifest_parsed",
        "frozen_at_utc",
        "input_bindings",
        "invocations",
        "plan_path",
        "protocol",
        "raw_errors_emitted",
        "result_path",
        "roots",
        "runtime",
        "schema_version",
        "self_binding",
        "semantic_artifacts_opened",
        "status",
        "source_checkout",
        "tooling_provenance",
        "wrapper_identity",
    }
    if not isinstance(plan, dict) or set(plan) != expected_keys:
        raise InvalidDiagnosticError("diagnostic plan schema differs")
    if plan_raw != _canonical_bytes(plan):
        raise InvalidDiagnosticError("diagnostic plan is not canonical")
    if (
        plan["schema_version"] != 1
        or plan["protocol"] != PLAN_PROTOCOL
        or plan["status"] != "frozen_outcome_blind"
        or plan["attempt_binding"] != _attempt_binding(layout)
        or plan["roots"] != _fixed_roots(layout)
        or plan["plan_path"] != layout.plan_path.as_posix()
        or plan["result_path"] != layout.result_path.as_posix()
        or plan["classifier_contract_sha256"] != _rule_contract_sha256()
        or plan["efficacy_fields_emitted"] is not False
        or plan["formal_manifest_parsed"] is not False
        or plan["raw_errors_emitted"] is not False
        or plan["semantic_artifacts_opened"] is not False
        or plan["source_checkout"]
        != {"head": SOURCE_COMMIT, "status": "clean_artifacts_link_only"}
        or not isinstance(plan["frozen_at_utc"], str)
        or not plan["frozen_at_utc"].endswith("Z")
        or plan["runtime"]
        != {
            "cwd": "/tmp",
            "environment_sha256": _sha256(_canonical_bytes(DIAGNOSTIC_ENV)),
            "isolated": True,
            "python_path": EXPECTED_PYTHON_PATH,
            "python_version": EXPECTED_PYTHON_VERSION,
        }
        or plan["invocations"]
        != {
            "diagnose": _phase_argv(layout, "diagnose"),
            "freeze": _phase_argv(layout, "freeze"),
        }
    ):
        raise InvalidDiagnosticError("diagnostic plan contract differs")
    source_raw = _validate_binding(
        plan["self_binding"], source_path, "diagnostic source"
    )
    amendment_raw = _validate_binding(
        plan["amendment_binding"], layout.amendment_path(), "retry amendment"
    )
    if plan["tooling_provenance"] != dict(
        tooling_check_fn(layout, source_raw, amendment_raw)
    ):
        raise InvalidDiagnosticError("tooling provenance binding differs")
    if not isinstance(plan["input_bindings"], dict) or set(
        plan["input_bindings"]
    ) != set(layout.inputs()):
        raise InvalidDiagnosticError("diagnostic input set differs")
    raws = {
        name: _validate_binding(plan["input_bindings"][name], path, name)
        for name, path in layout.inputs().items()
    }
    if raws["wrapper_exit"] != b"1\n":
        raise InvalidDiagnosticError("wrapper exit binding is not exact code one")
    if plan["input_bindings"]["validator_source"]["sha256"] != VALIDATOR_SHA256:
        raise InvalidDiagnosticError("validator source binding differs")
    _verify_formal_tool_sources(layout, raws)
    if plan["wrapper_identity"] != _validate_launch_expectation(
        raws["launch_expectation"],
        layout=layout,
        pid_raw=raws["wrapper_pid"],
        hostname_fn=hostname_fn,
        boot_id_fn=boot_id_fn,
    ):
        raise InvalidDiagnosticError("wrapper identity binding differs")
    return plan, plan_raw, plan_binding, raws


def _path_within(candidate: Path, root: Path) -> bool:
    candidate_text = Path(os.path.normpath(candidate.as_posix()))
    return candidate_text == root or root in candidate_text.parents


def _scan_process_references(
    layout: AttemptLayout,
    *,
    proc_root: Path = Path("/proc"),
    self_pid: int | None = None,
) -> None:
    if not proc_root.is_dir():
        raise InvalidDiagnosticError("Linux procfs is required")
    own_pid = os.getpid() if self_pid is None else self_pid
    targets = (layout.checkout_root, layout.durable_root)
    target_bytes = tuple(path.as_posix().encode("utf-8") for path in targets)
    try:
        entries = sorted(
            (entry for entry in proc_root.iterdir() if entry.name.isdigit()),
            key=lambda entry: int(entry.name),
        )
    except OSError as exc:
        raise InvalidDiagnosticError("cannot enumerate Linux procfs") from exc
    for entry in entries:
        if int(entry.name) == own_pid:
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise InvalidDiagnosticError("a process cmdline is unreadable") from exc
        if any(target in cmdline for target in target_bytes):
            raise InvalidDiagnosticError("a live process references the retry")
        try:
            cwd = Path(os.readlink(entry / "cwd"))
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise InvalidDiagnosticError("a process cwd is unreadable") from exc
        if any(_path_within(cwd, target) for target in targets):
            raise InvalidDiagnosticError("a live process references the retry")


@contextmanager
def _formal_verifier_modules(
    layout: AttemptLayout,
) -> Iterator[tuple[Any, Any]]:
    def audit_cache() -> None:
        for directory, dirnames, filenames in os.walk(
            layout.formal_tooling_root, followlinks=False
        ):
            if "__pycache__" in dirnames or any(
                name.endswith((".pyc", ".pyo")) for name in filenames
            ):
                raise InvalidDiagnosticError(
                    "formal verifier import cache is not permitted"
                )
            for name in [*dirnames, *filenames]:
                if stat.S_ISLNK(os.lstat(Path(directory) / name).st_mode):
                    raise InvalidDiagnosticError(
                        "formal verifier tooling contains a symlink"
                    )

    audit_cache()
    names = (
        "build_cohort_structured_state_execution_seal",
        "build_cohort_structured_state_execution_seal_v2",
        "attest_cohort_causal_completion",
        "attest_cohort_causal_completion_v2",
    )
    previous = {name: sys.modules.get(name) for name in names}
    for name in names:
        sys.modules.pop(name, None)
    sys.path.insert(0, layout.formal_tooling_root.as_posix())
    try:
        importlib.invalidate_caches()
        seal_v2 = importlib.import_module(
            "build_cohort_structured_state_execution_seal_v2"
        )
        attester_v2 = importlib.import_module("attest_cohort_causal_completion_v2")
        yield seal_v2, attester_v2
    except Exception as exc:
        raise InvalidDiagnosticError("pinned V2 process policy could not load") from exc
    finally:
        sys.path.pop(0)
        for name in names:
            sys.modules.pop(name, None)
            if previous[name] is not None:
                sys.modules[name] = previous[name]
        audit_cache()


def _scan_with_v2_policy(
    layout: AttemptLayout,
    *,
    hostname_fn: Callable[[], str] = socket.gethostname,
    boot_id_fn: Callable[[], str] = _current_boot_id,
    proc_root: Path = Path("/proc"),
) -> None:
    raw_by_name = {
        name: _read_opaque(path, f"policy input {name}")[0]
        for name, path in layout.inputs().items()
        if name
        in {
            "attester_v1_source",
            "attester_v2_source",
            "launch_expectation",
            "procfs_exception_inventory",
            "seal_v1_source",
            "seal_v2_source",
            "wrapper_pid",
        }
    }
    _verify_formal_tool_sources(layout, raw_by_name)
    wrapper = _validate_launch_expectation(
        raw_by_name["launch_expectation"],
        layout=layout,
        pid_raw=raw_by_name["wrapper_pid"],
        hostname_fn=hostname_fn,
        boot_id_fn=boot_id_fn,
    )
    inventory = _strict_json(
        raw_by_name["procfs_exception_inventory"], "V2 procfs exception inventory"
    )
    try:
        with _formal_verifier_modules(layout) as (seal_v2, attester_v2):
            validated, static_records = seal_v2.validate_exception_inventory(
                inventory,
                launch_expectation_path=layout.inputs()["launch_expectation"],
                launch_expectation_sha256=_sha256(
                    raw_by_name["launch_expectation"]
                ),
                wrapper_pid=wrapper["pid"],
                wrapper_start_ticks=wrapper["start_ticks"],
            )
            attester_v2._scan_process_references(
                attempt_checkout=layout.checkout_root,
                artifact_root=layout.artifact_root,
                exception_records=static_records,
                dynamic_policy=validated["dynamic_policy"],
                dynamic_policy_sha256=validated["dynamic_policy_sha256"],
                wrapper_start_ticks=wrapper["start_ticks"],
                exception_file_sha256=_sha256(
                    raw_by_name["procfs_exception_inventory"]
                ),
                proc_root=proc_root,
            )
    except InvalidDiagnosticError:
        raise
    except Exception as exc:
        raise InvalidDiagnosticError("V2 process policy audit failed") from exc


def _validate_invalid_decision(value: Any) -> list[str]:
    if not isinstance(value, dict) or set(value) != INVALID_DECISION_KEYS:
        raise InvalidDiagnosticError("formal decision top-level contract differs")
    if (
        value["aggregate"] is not None
        or value["bootstrap"] is not None
        or value["decision"] != "invalid"
        or value["decision_scope"] != "invalid"
        or value["experiment"] != "cohort_qonly_frozen_tape_causal_formal"
        or value["limitation"] != "not exact historical replication"
        or value["mechanism_label"] != "frozen-tape weight-update ablation"
        or not isinstance(value["pairs"], list)
        or value["protocol"] != "cohort_qonly_frozen_tape_weight_update_ablation_v1"
        or value["publication_inference"]
        != {
            "effective_n": None,
            "publication_grade": False,
            "status": "invalid_not_publication_grade",
        }
        or value["publication_grade"] is not False
        or value["schema_version"] != 1
        or value["status"] != "invalid"
        or value["threshold_checks"] is not None
    ):
        raise InvalidDiagnosticError("formal decision invalid envelope differs")
    errors = value["errors"]
    if (
        not isinstance(errors, list)
        or not errors
        or any(not isinstance(item, str) or not item for item in errors)
        or errors != sorted(set(errors))
    ):
        raise InvalidDiagnosticError("formal decision error contract differs")
    return errors


def _classify(message: str) -> ReasonRule:
    lowered = message.casefold()
    for rule in REASON_RULES[:-1]:
        if any(term in lowered for term in rule.terms):
            return rule
    return REASON_RULES[-1]


def _safe_result(
    *,
    plan_raw: bytes,
    plan: Mapping[str, Any],
    plan_binding: Mapping[str, Any],
    errors: Sequence[str],
    diagnosed_at_utc: str,
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for message in errors:
        rule = _classify(message)
        counts[rule.rule_id] = counts.get(rule.rule_id, 0) + 1
    rules_by_id = {rule.rule_id: rule for rule in REASON_RULES}
    reason_counts = [
        {
            "category": rules_by_id[rule_id].category,
            "count": counts[rule_id],
            "reason_rule_id": rule_id,
        }
        for rule_id in (rule.rule_id for rule in REASON_RULES)
        if rule_id in counts
    ]
    category_counts: dict[str, int] = {}
    for item in reason_counts:
        category = item["category"]
        category_counts[category] = category_counts.get(category, 0) + item["count"]
    input_hashes = {
        "diagnostic_plan": _sha256(plan_raw),
        "diagnostic_self": plan["self_binding"]["sha256"],
        "retry_amendment": plan["amendment_binding"]["sha256"],
        **{
            name: binding["sha256"]
            for name, binding in sorted(plan["input_bindings"].items())
        },
    }
    return {
        "attempt_binding": dict(plan["attempt_binding"]),
        "diagnosed_at_utc": diagnosed_at_utc,
        "efficacy_fields_emitted": False,
        "input_hashes": input_hashes,
        "formal_manifest_parsed": False,
        "plan_binding": dict(plan_binding),
        "protocol": RECEIPT_PROTOCOL,
        "raw_errors_emitted": False,
        "reason_category_counts": [
            {"category": category, "count": category_counts[category]}
            for category in (
                "update_contract",
                "tape_integrity",
                "schema_contract",
                "provenance_binding",
                "evaluation_integrity",
                "format_stability",
                "endpoint_completeness",
                "other_integrity",
            )
            if category in category_counts
        ],
        "reason_rule_counts": reason_counts,
        "schema_version": 1,
        "status": "invalid_integrity_diagnosed",
    }


def diagnose(
    *,
    layout: AttemptLayout,
    actual_argv: Sequence[str],
    source_path: Path | None = None,
    pid_is_live_fn: Callable[[int], bool] = _pid_is_live,
    scan_fn: Callable[[AttemptLayout], None] | None = None,
    git_check_fn: Callable[[AttemptLayout], Mapping[str, str]] = (
        _validate_clean_checkout
    ),
    tooling_check_fn: Callable[
        [AttemptLayout, bytes, bytes], Mapping[str, Any]
    ] = _validate_tooling_commit_provenance,
    temporary_audit_fn: Callable[[AttemptLayout], None] = _audit_temporary_artifacts,
    hostname_fn: Callable[[], str] = socket.gethostname,
    boot_id_fn: Callable[[], str] = _current_boot_id,
    cwd_fn: Callable[[], str] = os.getcwd,
    environ_fn: Callable[[], Mapping[str, str]] = lambda: dict(os.environ),
    isolated: int = sys.flags.isolated,
    runtime_python_path: str = EXPECTED_PYTHON_PATH,
    runtime_python_version: str = EXPECTED_PYTHON_VERSION,
    now_fn: Callable[[], str] = _now_utc,
    publish_fn: Callable[[Path, bytes], None] = _publish_no_overwrite,
) -> dict[str, Any]:
    """Diagnose only integrity reasons and publish an efficacy-free result."""

    source = Path(__file__).absolute() if source_path is None else source_path
    if source != layout.self_path:
        raise InvalidDiagnosticError("diagnostic source is outside fixed tooling path")
    _validate_runtime(
        layout=layout,
        phase="diagnose",
        runtime_python_path=runtime_python_path,
        runtime_python_version=runtime_python_version,
        actual_argv=actual_argv,
        cwd_fn=cwd_fn,
        environ_fn=environ_fn,
        isolated=isolated,
    )
    process_scan = (
        (
            lambda selected: _scan_with_v2_policy(
                selected, hostname_fn=hostname_fn, boot_id_fn=boot_id_fn
            )
        )
        if scan_fn is None
        else scan_fn
    )
    plan, plan_raw, plan_binding, raws = _load_and_validate_plan(
        layout,
        source,
        hostname_fn=hostname_fn,
        boot_id_fn=boot_id_fn,
        tooling_check_fn=tooling_check_fn,
    )
    first_git = dict(git_check_fn(layout))
    if first_git != plan["source_checkout"]:
        raise InvalidDiagnosticError("scientific checkout differs from frozen plan")
    pid = _parse_wrapper_pid(raws["wrapper_pid"])
    if pid_is_live_fn(pid):
        raise InvalidDiagnosticError("registered wrapper remains live")
    temporary_audit_fn(layout)
    process_scan(layout)
    # formal_manifest remains opaque by construction; only this input is decoded.
    decision = _strict_json(raws["formal_decision"], "formal decision")
    errors = _validate_invalid_decision(decision)
    result = _safe_result(
        plan_raw=plan_raw,
        plan=plan,
        plan_binding=plan_binding,
        errors=errors,
        diagnosed_at_utc=now_fn(),
    )
    # Revalidate every opaque binding and process absence after semantic parsing.
    post_plan, post_raw, post_binding, post_raws = _load_and_validate_plan(
        layout,
        source,
        hostname_fn=hostname_fn,
        boot_id_fn=boot_id_fn,
        tooling_check_fn=tooling_check_fn,
    )
    second_git = dict(git_check_fn(layout))
    if (
        post_plan != plan
        or post_raw != plan_raw
        or post_binding != plan_binding
        or post_raws != raws
        or second_git != first_git
        or pid_is_live_fn(pid)
    ):
        raise InvalidDiagnosticError("diagnostic bindings changed after classification")
    process_scan(layout)
    temporary_audit_fn(layout)
    publish_fn(layout.result_path, _canonical_bytes(result))
    return result


def _layout_from_plan_authority(
    plan_path: Path,
    *,
    source_path: Path,
    checkout_base: Path = Path("/mnt/localssd/ttt-rl-cohort-causal"),
    durable_base: Path = Path(
        "/sensei-fs/users/zcai/TTT-RL/cohort-qonly-causal"
    ),
) -> AttemptLayout:
    production_plan = AttemptLayout(
        tooling_commit="0" * 40,
        checkout_base=checkout_base,
        durable_base=durable_base,
    ).plan_path
    if plan_path != production_plan:
        raise InvalidDiagnosticError("diagnose plan path is not the fixed authority")
    raw, _ = _read_opaque(plan_path, "diagnose plan authority")
    value = _strict_json(raw, "diagnose plan authority")
    if not isinstance(value, dict) or raw != _canonical_bytes(value):
        raise InvalidDiagnosticError("diagnose plan authority is not canonical")
    attempt = value.get("attempt_binding")
    if not isinstance(attempt, dict):
        raise InvalidDiagnosticError("diagnose plan attempt binding is missing")
    tooling_commit = attempt.get("diagnostic_tooling_commit")
    if not isinstance(tooling_commit, str):
        raise InvalidDiagnosticError("diagnose tooling commit is missing")
    layout = AttemptLayout(
        tooling_commit=tooling_commit,
        checkout_base=checkout_base,
        durable_base=durable_base,
    )
    _fixed_roots(layout)
    if source_path != layout.self_path:
        raise InvalidDiagnosticError("diagnose source is outside the plan tooling root")
    return layout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)
    freeze_parser = phases.add_parser("freeze")
    freeze_parser.add_argument("--tooling-commit", required=True)
    diagnose_parser = phases.add_parser("diagnose")
    diagnose_parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args()
    source = Path(__file__).absolute()
    version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    actual_argv = list(getattr(sys, "orig_argv", [sys.executable, *sys.argv]))
    try:
        if args.phase == "freeze":
            layout = AttemptLayout(tooling_commit=args.tooling_commit)
            freeze(
                layout=layout,
                source_path=source,
                runtime_python_path=sys.executable,
                runtime_python_version=version,
                actual_argv=actual_argv,
            )
            token = "CAUSAL_FORMAL_INVALID_DIAGNOSTIC_FREEZE_OK"
        else:
            layout = _layout_from_plan_authority(args.plan, source_path=source)
            diagnose(
                layout=layout,
                source_path=source,
                runtime_python_path=sys.executable,
                runtime_python_version=version,
                actual_argv=actual_argv,
            )
            token = "CAUSAL_FORMAL_INVALID_DIAGNOSTIC_DIAGNOSE_OK"
    except (InvalidDiagnosticError, OSError) as exc:
        print("CAUSAL_FORMAL_INVALID_DIAGNOSTIC_FAILED", file=sys.stderr)
        raise SystemExit(1) from exc
    print(token)


if __name__ == "__main__":
    main()
