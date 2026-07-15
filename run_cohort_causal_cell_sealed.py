"""Run one causal cell with stdout/stderr encrypted before reaching disk."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
PUBLISHED_VISIBILITY_TIMEOUT_SECONDS = 60.0
PUBLISHED_STABILITY_SECONDS = 1.0
PUBLISHED_POLL_SECONDS = 0.25
_CFG_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_KINDS = frozenset({"formal", "smoke"})
_PHASES = frozenset({"collectors", "evaluation_cells"})
_RUNTIME_KEYS = frozenset(
    {
        "age_archive_sha256",
        "age_archive_url",
        "age_binary_sha256",
        "age_version",
        "private_identity_on_experiment_host",
        "recipient_file",
        "recipient_sha256",
        "schema_version",
    }
)
_START_KEYS = frozenset(
    {
        "age_binary_sha256",
        "age_version",
        "boot_id",
        "cfg_id",
        "event",
        "experiment_kind",
        "phase",
        "published_at_utc",
        "private_identity_absence_verified",
        "recipient_sha256",
        "runner_pid",
        "runner_start_time_ticks",
        "schema_version",
        "sealer_pid",
        "sealer_start_time_ticks",
        "supervisor_pid",
        "supervisor_start_time_ticks",
        "runtime_contract_sha256",
        "runtime_home_sha256",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "age_binary_sha256",
        "age_version",
        "boot_id",
        "cfg_id",
        "ciphertext_sha256",
        "ciphertext_size_bytes",
        "event",
        "experiment_kind",
        "phase",
        "published_at_utc",
        "private_identity_absence_verified",
        "recipient_sha256",
        "runner_exit_code",
        "runner_pid",
        "runner_start_time_ticks",
        "schema_version",
        "sealer_exit_code",
        "sealer_pid",
        "sealer_start_time_ticks",
        "start_receipt_sha256",
        "supervisor_pid",
        "supervisor_start_time_ticks",
        "runtime_contract_sha256",
        "runtime_home_sha256",
    }
)


class SealedCellError(RuntimeError):
    """A sealed-log transport or liveness contract failed closed."""


class _SignalInterruption(BaseException):
    """A terminating signal interrupted the supervisor."""


@dataclass
class _PinnedRuntime:
    descriptor: int
    executable_path: str
    pass_fds: tuple[int, ...]
    binary_sha256: str
    version: str
    recipient: str
    recipient_sha256: str
    runtime_contract_sha256: str


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_regular_bytes(path: Path, *, label: str) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise SealedCellError(f"{label}_unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SealedCellError(f"{label}_identity_invalid")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        pathname = path.lstat()
    except OSError as exc:
        raise SealedCellError(f"{label}_unavailable") from exc
    if (
        stat.S_ISLNK(pathname.st_mode)
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(pathname)
    ):
        raise SealedCellError(f"{label}_identity_changed")
    return b"".join(chunks)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SealedCellError("ciphertext_temporary_identity_invalid")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError as exc:
        raise SealedCellError("boot_identity_unavailable") from exc


def _process_start_time_ticks(pid: int) -> int:
    try:
        value = Path(f"/proc/{pid}/stat").read_text()
    except OSError as exc:
        raise SealedCellError("process_identity_unavailable") from exc
    closing = value.rfind(")")
    if closing < 0:
        raise SealedCellError("process_identity_malformed")
    fields = value[closing + 2 :].split()
    try:
        return int(fields[19])
    except (IndexError, ValueError) as exc:
        raise SealedCellError("process_identity_malformed") from exc


def _safe_regular_snapshot(path: Path) -> tuple[Any, ...]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise SealedCellError("sealed_artifact_unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SealedCellError("sealed_artifact_identity_invalid")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        pathname = path.lstat()
    except OSError as exc:
        raise SealedCellError("sealed_artifact_unavailable") from exc
    if (
        stat.S_ISLNK(pathname.st_mode)
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(pathname)
    ):
        raise SealedCellError("sealed_artifact_identity_changed")
    return (*_stat_identity(after), digest.hexdigest())


def _wait_stable(path: Path, *, expected: tuple[Any, ...]) -> None:
    deadline = time.monotonic() + PUBLISHED_VISIBILITY_TIMEOUT_SECONDS
    previous: tuple[Any, ...] | None = None
    previous_at = 0.0
    while time.monotonic() <= deadline:
        try:
            current = _safe_regular_snapshot(path)
        except SealedCellError:
            previous = None
        else:
            now = time.monotonic()
            if current != expected:
                raise SealedCellError("sealed_artifact_changed_after_publication")
            if previous == current and now - previous_at >= PUBLISHED_STABILITY_SECONDS:
                return
            if previous != current:
                previous = current
                previous_at = now
        time.sleep(PUBLISHED_POLL_SECONDS)
    raise SealedCellError("sealed_artifact_visibility_timeout")


def _publish_bytes(path: Path, payload: bytes) -> tuple[Any, ...]:
    if _lexists(path):
        raise FileExistsError("sealed_artifact_exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    linked = False
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        linked = True
    finally:
        if linked:
            temporary.unlink()
            _fsync_directory(path.parent)
    snapshot = _safe_regular_snapshot(path)
    _wait_stable(path, expected=snapshot)
    return snapshot


def _publish_existing(path: Path, temporary: Path) -> tuple[Any, ...]:
    if _lexists(path):
        raise FileExistsError("sealed_artifact_exists")
    metadata = temporary.lstat()
    if (
        temporary.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
    ):
        raise SealedCellError("ciphertext_temporary_identity_invalid")
    _fsync_file(temporary)
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()
    _fsync_directory(path.parent)
    snapshot = _safe_regular_snapshot(path)
    _wait_stable(path, expected=snapshot)
    return snapshot


def _load_runtime_contract(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular_bytes(path, label="runtime_contract")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SealedCellError("runtime_contract_invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != _RUNTIME_KEYS
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("private_identity_on_experiment_host") is not False
        or _SHA256_RE.fullmatch(str(value.get("age_binary_sha256"))) is None
        or _SHA256_RE.fullmatch(str(value.get("recipient_sha256"))) is None
    ):
        raise SealedCellError("runtime_contract_invalid")
    return value, payload


def _validate_runtime(
    *, age_binary: Path, recipient_file: Path, runtime_contract: Path
) -> _PinnedRuntime:
    contract, contract_payload = _load_runtime_contract(runtime_contract)
    descriptor = -1
    try:
        descriptor = os.open(
            age_binary,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SealedCellError("age_binary_identity_invalid")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        pathname = age_binary.lstat()
        if (
            stat.S_ISLNK(pathname.st_mode)
            or _stat_identity(before) != _stat_identity(after)
            or _stat_identity(after) != _stat_identity(pathname)
        ):
            raise SealedCellError("age_binary_identity_changed")
        binary_sha256 = digest.hexdigest()
        if binary_sha256 != contract["age_binary_sha256"]:
            raise SealedCellError("age_binary_digest_mismatch")
        fd_root = Path("/proc/self/fd")
        if sys.platform.startswith("linux") and fd_root.is_dir():
            executable_path = os.fspath(fd_root / str(descriptor))
            pass_fds = (descriptor,)
        else:
            # macOS does not permit executable images through /dev/fd. The
            # experiment host is Linux and therefore always takes the pinned-FD path.
            executable_path = os.fspath(age_binary)
            pass_fds = ()
        completed = subprocess.run(
            [executable_path, "--version"],
            check=False,
            capture_output=True,
            pass_fds=pass_fds,
            text=True,
            timeout=10,
        )
        if completed.returncode != 0 or completed.stdout.strip() != contract["age_version"]:
            raise SealedCellError("age_binary_version_mismatch")
        recipient_payload = _read_regular_bytes(recipient_file, label="recipient")
    except (OSError, subprocess.SubprocessError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise SealedCellError("sealed_runtime_unavailable") from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    recipient_sha256 = _sha256(recipient_payload)
    if (
        recipient_file.name != contract["recipient_file"]
        or recipient_sha256 != contract["recipient_sha256"]
    ):
        os.close(descriptor)
        raise SealedCellError("recipient_binding_mismatch")
    try:
        recipient = recipient_payload.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError as exc:
        os.close(descriptor)
        raise SealedCellError("recipient_invalid") from exc
    if (
        not recipient.startswith("age1")
        or recipient_payload != f"{recipient}\n".encode("ascii")
        or "\n" in recipient
    ):
        os.close(descriptor)
        raise SealedCellError("recipient_invalid")
    return _PinnedRuntime(
        descriptor=descriptor,
        executable_path=executable_path,
        pass_fds=pass_fds,
        binary_sha256=binary_sha256,
        version=contract["age_version"],
        recipient=recipient,
        recipient_sha256=recipient_sha256,
        runtime_contract_sha256=_sha256(contract_payload),
    )


def _reject_private_identity(command: Sequence[str], environment: Mapping[str, str]) -> None:
    if any("AGE-SECRET-KEY-" in value for value in command):
        raise SealedCellError("private_identity_in_command")
    forbidden_names = {
        "AGE_IDENTITY",
        "AGE_IDENTITIES",
        "SOPS_AGE_KEY",
        "SOPS_AGE_KEY_CMD",
        "SOPS_AGE_KEY_FILE",
    }
    for name, value in environment.items():
        if name in forbidden_names or "AGE-SECRET-KEY-" in value:
            raise SealedCellError("private_identity_in_environment")


def _validate_identity(*, kind: str, phase: str, cfg_id: str) -> None:
    if kind not in _KINDS or phase not in _PHASES:
        raise SealedCellError("cell_identity_invalid")
    if _CFG_ID_RE.fullmatch(cfg_id) is None:
        raise SealedCellError("cell_identity_invalid")


def _prepare_runtime_home(*, path: Path, cwd: Path, cfg_id: str) -> str:
    if (
        not path.is_absolute()
        or path.name != cfg_id
        or _lexists(path)
        or _lexists(cwd / ".private")
    ):
        raise SealedCellError("private_identity_absence_unverified")
    try:
        parent = path.parent
        metadata = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise SealedCellError("runtime_home_parent_invalid")
        path.mkdir(mode=0o700)
        _fsync_directory(parent)
    except OSError as exc:
        raise SealedCellError("runtime_home_unavailable") from exc
    if any(path.iterdir()):
        raise SealedCellError("runtime_home_not_fresh")
    return _sha256(os.fspath(path).encode("utf-8"))


def _resolve_output_layout(
    *,
    cwd: Path,
    kind: str,
    cfg_id: str,
    ciphertext_path: Path,
    start_receipt_path: Path,
    receipt_path: Path,
) -> tuple[Path, Path, Path]:
    try:
        cwd_real = cwd.resolve(strict=True)
        if cwd_real != cwd or cwd.is_symlink():
            raise SealedCellError("runner_cwd_identity_invalid")
        sealed_root = (
            cwd / "artifacts" / "cohort_causal" / "sealed_logs" / kind
        ).resolve(strict=True)
        root_metadata = sealed_root.lstat()
    except OSError as exc:
        raise SealedCellError("sealed_output_parent_unavailable") from exc
    if sealed_root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise SealedCellError("sealed_output_parent_invalid")
    requested = (
        (ciphertext_path, f"{cfg_id}.stdout_stderr.age"),
        (start_receipt_path, f"{cfg_id}.start.json"),
        (receipt_path, f"{cfg_id}.receipt.json"),
    )
    resolved: list[Path] = []
    for path, expected_name in requested:
        if (
            not path.is_absolute()
            or path.name != expected_name
            or path.parent.resolve(strict=True) != sealed_root
        ):
            raise SealedCellError("sealed_output_path_invalid")
        resolved.append(sealed_root / expected_name)
    return resolved[0], resolved[1], resolved[2]


def _install_signal_handlers() -> dict[int, Any]:
    previous: dict[int, Any] = {}

    def interrupt(signum: int, _frame: Any) -> None:
        raise _SignalInterruption(signum)

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt)
    return previous


def _restore_signal_handlers(previous: Mapping[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _terminate_group(process: subprocess.Popen[Any] | None) -> None:
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    except PermissionError:
        if process.poll() is None:
            process.terminate()
    if process.poll() is None:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return
    except PermissionError:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    if process.poll() is None:
        process.wait(timeout=10)


def run_sealed_cell(
    *,
    age_binary: Path,
    recipient_file: Path,
    runtime_contract: Path,
    ciphertext_path: Path,
    start_receipt_path: Path,
    receipt_path: Path,
    cwd: Path,
    runtime_home: Path,
    kind: str,
    phase: str,
    cfg_id: str,
    command: Sequence[str],
) -> int:
    """Encrypt one exact runner stream and publish only ciphertext plus receipts."""

    _validate_identity(kind=kind, phase=phase, cfg_id=cfg_id)
    if not command or not cwd.is_absolute() or not cwd.is_dir():
        raise SealedCellError("runner_command_invalid")
    for path in (ciphertext_path, start_receipt_path, receipt_path):
        if not path.is_absolute() or _lexists(path):
            raise SealedCellError("sealed_output_path_invalid")
    ciphertext_path, start_receipt_path, receipt_path = _resolve_output_layout(
        cwd=cwd,
        kind=kind,
        cfg_id=cfg_id,
        ciphertext_path=ciphertext_path,
        start_receipt_path=start_receipt_path,
        receipt_path=receipt_path,
    )
    for path in (ciphertext_path, start_receipt_path, receipt_path):
        if _lexists(path):
            raise SealedCellError("sealed_output_path_invalid")
    _reject_private_identity(command, os.environ)
    runtime = _validate_runtime(
        age_binary=age_binary,
        recipient_file=recipient_file,
        runtime_contract=runtime_contract,
    )
    try:
        runtime_home_sha256 = _prepare_runtime_home(
            path=runtime_home,
            cwd=cwd,
            cfg_id=cfg_id,
        )
    except BaseException:
        os.close(runtime.descriptor)
        raise
    isolated_environment = dict(os.environ)
    isolated_environment.update(
        {
            "COHORT_CAUSAL_AGE_BINARY": os.fspath(age_binary),
            "HOME": os.fspath(runtime_home),
            "XDG_CONFIG_HOME": os.fspath(runtime_home / ".config"),
        }
    )
    _reject_private_identity(command, isolated_environment)
    temporary = ciphertext_path.with_name(
        f".{ciphertext_path.name}.tmp.{os.getpid()}.{time.time_ns()}"
    )
    ciphertext_descriptor = -1
    sealer: subprocess.Popen[Any] | None = None
    runner: subprocess.Popen[Any] | None = None
    previous_signals = _install_signal_handlers()
    try:
        ciphertext_descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        sealer = subprocess.Popen(
            [
                runtime.executable_path,
                "--encrypt",
                "--recipient",
                runtime.recipient,
            ],
            stdin=subprocess.PIPE,
            stdout=ciphertext_descriptor,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env=isolated_environment,
            pass_fds=runtime.pass_fds,
            start_new_session=True,
        )
        os.close(runtime.descriptor)
        runtime.descriptor = -1
        os.close(ciphertext_descriptor)
        ciphertext_descriptor = -1
        if sealer.stdin is None:
            raise SealedCellError("sealer_pipe_unavailable")
        runner = subprocess.Popen(
            list(command),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=sealer.stdin,
            stderr=subprocess.STDOUT,
            close_fds=True,
            env=isolated_environment,
            start_new_session=True,
        )
        sealer.stdin.close()
        start = {
            "age_binary_sha256": runtime.binary_sha256,
            "age_version": runtime.version,
            "boot_id": _boot_id(),
            "cfg_id": cfg_id,
            "event": "start",
            "experiment_kind": kind,
            "phase": phase,
            "published_at_utc": _utc_now(),
            "private_identity_absence_verified": True,
            "recipient_sha256": runtime.recipient_sha256,
            "runner_pid": runner.pid,
            "runner_start_time_ticks": _process_start_time_ticks(runner.pid),
            "schema_version": SCHEMA_VERSION,
            "sealer_pid": sealer.pid,
            "sealer_start_time_ticks": _process_start_time_ticks(sealer.pid),
            "supervisor_pid": os.getpid(),
            "supervisor_start_time_ticks": _process_start_time_ticks(os.getpid()),
            "runtime_contract_sha256": runtime.runtime_contract_sha256,
            "runtime_home_sha256": runtime_home_sha256,
        }
        start_payload = _canonical_bytes(start)
        _publish_bytes(start_receipt_path, start_payload)
        runner_rc = runner.wait()
        sealer_rc = sealer.wait()
        ciphertext_snapshot = _publish_existing(ciphertext_path, temporary)
        receipt = {
            "age_binary_sha256": start["age_binary_sha256"],
            "age_version": start["age_version"],
            "boot_id": start["boot_id"],
            "cfg_id": cfg_id,
            "ciphertext_sha256": ciphertext_snapshot[-1],
            "ciphertext_size_bytes": ciphertext_snapshot[4],
            "event": "finish",
            "experiment_kind": kind,
            "phase": phase,
            "published_at_utc": _utc_now(),
            "private_identity_absence_verified": True,
            "recipient_sha256": start["recipient_sha256"],
            "runner_exit_code": runner_rc,
            "runner_pid": runner.pid,
            "runner_start_time_ticks": start["runner_start_time_ticks"],
            "schema_version": SCHEMA_VERSION,
            "sealer_exit_code": sealer_rc,
            "sealer_pid": sealer.pid,
            "sealer_start_time_ticks": start["sealer_start_time_ticks"],
            "start_receipt_sha256": _sha256(start_payload),
            "supervisor_pid": os.getpid(),
            "supervisor_start_time_ticks": start["supervisor_start_time_ticks"],
            "runtime_contract_sha256": start["runtime_contract_sha256"],
            "runtime_home_sha256": start["runtime_home_sha256"],
        }
        _publish_bytes(receipt_path, _canonical_bytes(receipt))
        return 0 if runner_rc == 0 and sealer_rc == 0 else 1
    finally:
        if runtime.descriptor >= 0:
            os.close(runtime.descriptor)
        if ciphertext_descriptor >= 0:
            os.close(ciphertext_descriptor)
        _terminate_group(runner)
        _terminate_group(sealer)
        _restore_signal_handlers(previous_signals)


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validate_receipt_fields(value: Mapping[str, Any], *, start: bool) -> None:
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("event") != ("start" if start else "finish")
        or value.get("experiment_kind") not in _KINDS
        or value.get("phase") not in _PHASES
        or not isinstance(value.get("cfg_id"), str)
        or _CFG_ID_RE.fullmatch(value["cfg_id"]) is None
        or not isinstance(value.get("boot_id"), str)
        or not value["boot_id"]
        or not isinstance(value.get("published_at_utc"), str)
        or not value["published_at_utc"]
        or not isinstance(value.get("age_version"), str)
        or not value["age_version"]
        or value.get("private_identity_absence_verified") is not True
    ):
        raise SealedCellError("liveness_receipt_invalid")
    for name in (
        "age_binary_sha256",
        "recipient_sha256",
        "runtime_contract_sha256",
        "runtime_home_sha256",
    ):
        if not isinstance(value.get(name), str) or _SHA256_RE.fullmatch(value[name]) is None:
            raise SealedCellError("liveness_receipt_invalid")
    for prefix in ("runner", "sealer", "supervisor"):
        if not _positive_int(value.get(f"{prefix}_pid")) or not _positive_int(
            value.get(f"{prefix}_start_time_ticks")
        ):
            raise SealedCellError("liveness_receipt_invalid")
    if not start:
        for name in ("runner_exit_code", "sealer_exit_code"):
            if not isinstance(value.get(name), int) or isinstance(value[name], bool):
                raise SealedCellError("liveness_receipt_invalid")
        if (
            not _positive_int(value.get("ciphertext_size_bytes"))
            or not isinstance(value.get("ciphertext_sha256"), str)
            or _SHA256_RE.fullmatch(value["ciphertext_sha256"]) is None
            or not isinstance(value.get("start_receipt_sha256"), str)
            or _SHA256_RE.fullmatch(value["start_receipt_sha256"]) is None
        ):
            raise SealedCellError("liveness_receipt_invalid")


def _load_receipt(path: Path, *, expected_keys: frozenset[str]) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular_bytes(path, label="liveness_receipt")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SealedCellError("liveness_receipt_invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or payload != _canonical_bytes(value)
    ):
        raise SealedCellError("liveness_receipt_invalid")
    _validate_receipt_fields(value, start=expected_keys == _START_KEYS)
    return value, payload


def validate_sealed_phase_value(
    *, root: Path, grid: Mapping[str, Any], section: str, recipient_file: Path
) -> int:
    """Bind ciphertext and fixed-schema receipts without decrypting any bytes."""

    recipient_payload = _read_regular_bytes(recipient_file, label="recipient")
    recipient_sha256 = _sha256(recipient_payload)
    contract, contract_payload = _load_runtime_contract(
        root / "COHORT_CAUSAL_SEALED_LOG_RUNTIME_V1.json"
    )
    contract_sha256 = _sha256(contract_payload)
    kind = grid.get("kind") if isinstance(grid, dict) else None
    rows = grid.get(section) if isinstance(grid, dict) else None
    if kind not in _KINDS or section not in _PHASES or not isinstance(rows, list):
        raise SealedCellError("sealed_phase_inputs_invalid")
    phase_root = root / "artifacts" / "cohort_causal" / "sealed_logs" / kind
    seen: set[str] = set()
    for row in rows:
        cfg_id = row.get("cfg_id") if isinstance(row, dict) else None
        if not isinstance(cfg_id, str) or cfg_id in seen:
            raise SealedCellError("sealed_phase_inventory_invalid")
        seen.add(cfg_id)
        start_path = phase_root / f"{cfg_id}.start.json"
        receipt_path = phase_root / f"{cfg_id}.receipt.json"
        ciphertext_path = phase_root / f"{cfg_id}.stdout_stderr.age"
        start, start_payload = _load_receipt(start_path, expected_keys=_START_KEYS)
        receipt, _ = _load_receipt(receipt_path, expected_keys=_RECEIPT_KEYS)
        ciphertext = _safe_regular_snapshot(ciphertext_path)
        identity_fields = (
            "age_binary_sha256",
            "age_version",
            "boot_id",
            "cfg_id",
            "experiment_kind",
            "phase",
            "private_identity_absence_verified",
            "recipient_sha256",
            "runner_pid",
            "runner_start_time_ticks",
            "runtime_contract_sha256",
            "runtime_home_sha256",
            "schema_version",
            "sealer_pid",
            "sealer_start_time_ticks",
            "supervisor_pid",
            "supervisor_start_time_ticks",
        )
        if (
            start.get("event") != "start"
            or receipt.get("event") != "finish"
            or start.get("cfg_id") != cfg_id
            or receipt.get("cfg_id") != cfg_id
            or start.get("experiment_kind") != kind
            or receipt.get("experiment_kind") != kind
            or start.get("phase") != section
            or receipt.get("phase") != section
            or start.get("recipient_sha256") != recipient_sha256
            or receipt.get("recipient_sha256") != recipient_sha256
            or start.get("age_binary_sha256") != contract["age_binary_sha256"]
            or start.get("age_version") != contract["age_version"]
            or start.get("runtime_contract_sha256") != contract_sha256
            or any(start.get(field) != receipt.get(field) for field in identity_fields)
            or receipt.get("start_receipt_sha256") != _sha256(start_payload)
            or receipt.get("runner_exit_code") != 0
            or receipt.get("sealer_exit_code") != 0
            or receipt.get("ciphertext_size_bytes") != ciphertext[4]
            or receipt.get("ciphertext_sha256") != ciphertext[-1]
        ):
            raise SealedCellError("sealed_phase_binding_invalid")
    return len(seen)


def validate_sealed_phase(
    *, root: Path, grid_path: Path, section: str, recipient_file: Path
) -> int:
    try:
        grid = json.loads(grid_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SealedCellError("sealed_phase_inputs_invalid") from exc
    if not isinstance(grid, dict):
        raise SealedCellError("sealed_phase_inputs_invalid")
    return validate_sealed_phase_value(
        root=root,
        grid=grid,
        section=section,
        recipient_file=recipient_file,
    )


def _process_matches(value: Mapping[str, Any], prefix: str) -> bool:
    try:
        return (
            value["boot_id"] == _boot_id()
            and value[f"{prefix}_start_time_ticks"]
            == _process_start_time_ticks(value[f"{prefix}_pid"])
        )
    except (KeyError, SealedCellError):
        return False


def liveness_status(directory: Path) -> dict[str, Any]:
    """Read only liveness receipts; never open ciphertext or result artifacts."""

    if not directory.is_dir() or directory.is_symlink():
        raise SealedCellError("liveness_directory_invalid")
    records = []
    starts = sorted(directory.glob("*.start.json"))
    for start_path in starts:
        start, start_payload = _load_receipt(start_path, expected_keys=_START_KEYS)
        cfg_id = start["cfg_id"]
        if start_path.name != f"{cfg_id}.start.json":
            raise SealedCellError("liveness_inventory_invalid")
        receipt_path = directory / f"{cfg_id}.receipt.json"
        if _lexists(receipt_path):
            receipt, _ = _load_receipt(receipt_path, expected_keys=_RECEIPT_KEYS)
            if (
                receipt.get("cfg_id") != cfg_id
                or receipt.get("start_receipt_sha256") != _sha256(start_payload)
            ):
                raise SealedCellError("liveness_receipt_binding_invalid")
            state = "finished"
            runner_exit_code = receipt["runner_exit_code"]
            sealer_exit_code = receipt["sealer_exit_code"]
        else:
            state = (
                "running"
                if _process_matches(start, "runner")
                and _process_matches(start, "sealer")
                and _process_matches(start, "supervisor")
                else "process_missing"
            )
            runner_exit_code = None
            sealer_exit_code = None
        records.append(
            {
                "cfg_id": cfg_id,
                "experiment_kind": start["experiment_kind"],
                "phase": start["phase"],
                "runner_exit_code": runner_exit_code,
                "sealer_exit_code": sealer_exit_code,
                "state": state,
            }
        )
    return {
        "kind": "cohort_causal_outcome_blind_liveness",
        "records": records,
        "schema_version": SCHEMA_VERSION,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--age-binary", type=Path, required=True)
    run.add_argument("--recipient-file", type=Path, required=True)
    run.add_argument("--runtime-contract", type=Path, required=True)
    run.add_argument("--ciphertext", type=Path, required=True)
    run.add_argument("--start-receipt", type=Path, required=True)
    run.add_argument("--receipt", type=Path, required=True)
    run.add_argument("--cwd", type=Path, required=True)
    run.add_argument("--runtime-home", type=Path, required=True)
    run.add_argument("--kind", choices=sorted(_KINDS), required=True)
    run.add_argument("--phase", choices=sorted(_PHASES), required=True)
    run.add_argument("--cfg-id", required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--directory", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--grid", type=Path, required=True)
    verify.add_argument("--section", choices=sorted(_PHASES), required=True)
    verify.add_argument("--recipient-file", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.subcommand == "status":
            print(_canonical_bytes(liveness_status(args.directory)).decode(), end="")
            return
        if args.subcommand == "verify":
            count = validate_sealed_phase(
                root=args.root,
                grid_path=args.grid,
                section=args.section,
                recipient_file=args.recipient_file,
            )
            print(f"SEALED_PHASE_OK count={count}")
            return
        command = list(args.command)
        if command and command[0] == "--":
            command = command[1:]
        return_code = run_sealed_cell(
            age_binary=args.age_binary,
            recipient_file=args.recipient_file,
            runtime_contract=args.runtime_contract,
            ciphertext_path=args.ciphertext,
            start_receipt_path=args.start_receipt,
            receipt_path=args.receipt,
            cwd=args.cwd,
            runtime_home=args.runtime_home,
            kind=args.kind,
            phase=args.phase,
            cfg_id=args.cfg_id,
            command=command,
        )
    except BaseException:
        print("SEALED_CELL_INFRASTRUCTURE_ERROR", flush=True)
        raise SystemExit(70) from None
    print("SEALED_CELL_FINISHED", flush=True)
    raise SystemExit(return_code)


if __name__ == "__main__":
    main()
