"""Impure, source-bound pre-Trigger-A structured-root absence adapter.

The adapter is intentionally narrow.  It observes exactly one registered
structured attempt root through ``O_NOFOLLOW`` directory descriptors and emits
the absence object consumed by the pure Trigger-A receipt builder.  It neither
imports scientific code nor grants model, scorer, DGP, or launch authority.

Production calls use the process identity and ``/proc/self/mountinfo``.  The
``AbsenceRuntime`` hooks exist only so the same fail-closed traversal can be
tested on macOS, where the dedicated uid and Linux mount table do not exist.
The command-line publisher never exposes those hooks.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cohort_closed_loop_structured_atomic_publish import (
    publication_sidecar_relative_paths,
    read_and_validate_readonly_artifact,
)

__all__ = (
    "ABSENCE_FORBIDDEN_CLASSES",
    "AbsenceAdapterError",
    "AbsenceRuntime",
    "PRETRIGGER_ABSENCE_SERVICE_IDENTITY",
    "PRETRIGGER_ABSENCE_SERVICE_UID",
    "attest_pretrigger_absence",
    "validate_prereceipt_root_after_absence",
    "validate_preinventory_root",
)


class AbsenceAdapterError(RuntimeError):
    """Raised when a structured-root absence observation is not exact."""


PRETRIGGER_ABSENCE_PROTOCOL = "cohort_structured_pretrigger_absence_attestation_v1"
PRETRIGGER_ABSENCE_SERVICE_IDENTITY = "cohort-structured-trigger-absence-v1"
PRETRIGGER_ABSENCE_SERVICE_UID = 41001
TRIGGER_VALIDATOR_INVENTORY_PROTOCOL = (
    "cohort_structured_trigger_validator_inventory_v1"
)
SCHEMA_VERSION = 1
ABSENCE_FORBIDDEN_CLASSES = tuple(
    sorted(
        (
            "context_registry",
            "decision",
            "model_output",
            "precommit",
            "production_structured_dgp",
            "raw_trace",
            "receipt",
            "report",
        )
    )
)
REQUIRED_VALIDATOR_BINDING_IDS = tuple(
    sorted(
        (
            "causal_completion_attester",
            "causal_terminal_revalidator",
            "pretrigger_absence_adapter",
            "structured_atomic_publisher",
            "trigger_execution_seal_builder",
            "trigger_receipt_builder",
            "trigger_receipt_publisher",
            "trigger_receipt_revalidator",
        )
    )
)

INVENTORY_RELATIVE_PATH = "control/trigger_validator_inventory.json"
ABSENCE_RELATIVE_PATH = "control/pretrigger_absence_attestation.json"

_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_PRODUCTION_ROOT_RE = re.compile(
    r"/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
    r"(?P<commit>[0-9a-f]{40})/attempts/(?P<attempt>attempt-[0-9]{3})\Z"
)
_MOUNT_ESCAPE_RE = re.compile(r"\\([0-7]{3})")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW

_INVENTORY_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "tooling_source_commit",
        "bindings",
        "created_at_utc",
        "operational_authorization",
    }
)
_INVENTORY_KEYS = _INVENTORY_UNSIGNED_KEYS | {"binding_inventory_sha256"}
_BINDING_KEYS = frozenset({"binding_id", "path", "sha256", "size_bytes"})


def _default_identity(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError as exc:
        raise AbsenceAdapterError(
            "dedicated absence service account is missing"
        ) from exc


def _default_mountinfo() -> bytes:
    try:
        return Path("/proc/self/mountinfo").read_bytes()
    except OSError as exc:
        raise AbsenceAdapterError("cannot read /proc/self/mountinfo") from exc


def _default_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class AbsenceRuntime:
    """Injectable process/filesystem observations; production uses defaults.

    ``uid_translate`` and ``physical_root_override`` are for macOS tests only.
    The publisher CLI never accepts or constructs a non-default runtime.
    """

    euid: Callable[[], int] = os.geteuid
    identity_for_uid: Callable[[int], str] = _default_identity
    mountinfo_bytes: Callable[[], bytes] = _default_mountinfo
    now_utc: Callable[[], str] = _default_now
    uid_translate: Callable[[int], int] = lambda value: value
    physical_root_override: Path | None = None


@dataclass(frozen=True, slots=True)
class _MountRecord:
    mount_id: str
    major_minor: str
    mount_root: str
    mount_point: str
    filesystem_type: str
    source: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AbsenceAdapterError("canonical JSON encoding failed") from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AbsenceAdapterError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AbsenceAdapterError(f"nonfinite JSON constant is forbidden: {value}")


def _parse_canonical(raw: bytes, *, label: str) -> object:
    if type(raw) is not bytes:
        raise AbsenceAdapterError(f"{label} must be exact bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AbsenceAdapterError(f"{label} is not canonical JSON") from exc
    if raw != _canonical(value):
        raise AbsenceAdapterError(f"{label} bytes are not canonical")
    return value


def _exact_dict(
    value: object, keys: frozenset[str], *, label: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise AbsenceAdapterError(f"{label} exact schema differs")
    return value


def _exact_int(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise AbsenceAdapterError(f"{label} must be an exact integer")
    return value


def _normalized_absolute(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise AbsenceAdapterError(f"{label} must be an absolute pathlib.Path")
    normalized = Path(os.path.normpath(os.fspath(path)))
    if normalized != path or normalized == Path("/"):
        raise AbsenceAdapterError(f"{label} must be normalized and non-root")
    return normalized


def _validate_logical_root(
    logical_root: str, *, source_commit: str, attempt_id: str
) -> None:
    if type(logical_root) is not str:
        raise AbsenceAdapterError("structured durable root must be exact text")
    match = _PRODUCTION_ROOT_RE.fullmatch(logical_root)
    if (
        match is None
        or match.group("commit") != source_commit
        or match.group("attempt") != attempt_id
    ):
        raise AbsenceAdapterError("structured durable root/commit/attempt differs")


def _decode_mount_path(value: str) -> str:
    return _MOUNT_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _parse_mountinfo(raw: bytes) -> tuple[_MountRecord, ...]:
    if type(raw) is not bytes or not raw:
        raise AbsenceAdapterError("mountinfo must be nonempty exact bytes")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AbsenceAdapterError("mountinfo must be ASCII") from exc
    rows: list[_MountRecord] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        halves = line.split(" - ")
        if len(halves) != 2:
            raise AbsenceAdapterError(f"mountinfo line {line_number} is malformed")
        left = halves[0].split()
        right = halves[1].split()
        if len(left) < 6 or len(right) < 3 or not left[0].isdigit():
            raise AbsenceAdapterError(f"mountinfo line {line_number} is malformed")
        rows.append(
            _MountRecord(
                mount_id=left[0],
                major_minor=left[2],
                mount_root=_decode_mount_path(left[3]),
                mount_point=_decode_mount_path(left[4]),
                filesystem_type=right[0],
                source=_decode_mount_path(right[1]),
            )
        )
    if not rows:
        raise AbsenceAdapterError("mountinfo contains no records")
    return tuple(rows)


def _path_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _mount_for(path: Path, records: tuple[_MountRecord, ...]) -> _MountRecord:
    path_text = path.as_posix()
    candidates = [row for row in records if _path_within(path_text, row.mount_point)]
    if not candidates:
        raise AbsenceAdapterError(f"no mountinfo record covers {path_text}")
    longest_length = max(len(row.mount_point) for row in candidates)
    longest = [row for row in candidates if len(row.mount_point) == longest_length]
    if len(longest) != 1:
        raise AbsenceAdapterError(
            f"mountinfo has a non-unique longest mountpoint for {path_text}"
        )
    return longest[0]


def _translated_uid(metadata: os.stat_result, runtime: AbsenceRuntime) -> int:
    value = runtime.uid_translate(metadata.st_uid)
    if type(value) is not int:
        raise AbsenceAdapterError("translated filesystem uid must be an exact integer")
    return value


def _validate_identity(
    metadata: os.stat_result,
    *,
    runtime: AbsenceRuntime,
    label: str,
    directory: bool,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(metadata.st_mode):
        raise AbsenceAdapterError(f"{label} has the wrong filesystem type")
    if _translated_uid(metadata, runtime) != PRETRIGGER_ABSENCE_SERVICE_UID:
        raise AbsenceAdapterError(f"{label} is not owned by uid 41001")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AbsenceAdapterError(f"{label} is group/other writable")


def _open_root(root: Path, runtime: AbsenceRuntime) -> tuple[int, os.stat_result]:
    root = _normalized_absolute(root, label="physical root")
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    current = Path("/")
    try:
        for component in root.parts[1:]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            current /= component
        metadata = os.fstat(descriptor)
        _validate_identity(
            metadata, runtime=runtime, label="structured root", directory=True
        )
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise AbsenceAdapterError("structured root mode must be exactly 0700")
        path_metadata = os.stat(root, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ):
            raise AbsenceAdapterError("structured root pathname identity changed")
        return descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


def _open_child_directory(
    parent: int, name: str, *, runtime: AbsenceRuntime, label: str
) -> tuple[int, os.stat_result]:
    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        metadata = os.fstat(descriptor)
        _validate_identity(metadata, runtime=runtime, label=label, directory=True)
        return descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


def _stat_regular(
    parent: int, name: str, *, runtime: AbsenceRuntime, label: str
) -> os.stat_result:
    metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _validate_identity(metadata, runtime=runtime, label=label, directory=False)
    if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o444:
        raise AbsenceAdapterError(f"{label} must be single-link mode 0444")
    descriptor = os.open(name, _READ_FLAGS, dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise AbsenceAdapterError(f"{label} pathname changed while opening")
    finally:
        os.close(descriptor)
    return metadata


def _require_same_mount(
    *,
    path: Path,
    metadata: os.stat_result,
    root_metadata: os.stat_result,
    root_mount: _MountRecord,
    mounts: tuple[_MountRecord, ...],
) -> None:
    observed = _mount_for(path, mounts)
    if metadata.st_dev != root_metadata.st_dev:
        raise AbsenceAdapterError(f"cross-device entry is forbidden: {path}")
    if observed != root_mount:
        raise AbsenceAdapterError(f"alternate mount is forbidden: {path}")
    try:
        major_minor = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    except (AttributeError, ValueError, OSError) as exc:
        raise AbsenceAdapterError("cannot derive filesystem device identity") from exc
    if root_mount.major_minor != major_minor:
        raise AbsenceAdapterError("mountinfo device identity differs from stat device")


def _expected_tree(
    *, include_inventory: bool, include_absence: bool
) -> dict[str, set[str]]:
    control: set[str] = set()
    if include_inventory:
        inventory_intent, _ = publication_sidecar_relative_paths(
            INVENTORY_RELATIVE_PATH
        )
        control.update(
            {
                Path(INVENTORY_RELATIVE_PATH).name,
                Path(inventory_intent).name,
            }
        )
    if include_absence:
        absence_intent, _ = publication_sidecar_relative_paths(ABSENCE_RELATIVE_PATH)
        control.update({Path(ABSENCE_RELATIVE_PATH).name, Path(absence_intent).name})
    return {"root": {"control"}, "control": control}


def _scan_exact_tree(
    *,
    root: Path,
    runtime: AbsenceRuntime,
    include_inventory: bool,
    include_absence: bool,
) -> tuple[os.stat_result, _MountRecord]:
    mounts = _parse_mountinfo(runtime.mountinfo_bytes())
    root_descriptor, root_metadata = _open_root(root, runtime)
    control_descriptor = -1
    try:
        root_mount = _mount_for(root, mounts)
        _require_same_mount(
            path=root,
            metadata=root_metadata,
            root_metadata=root_metadata,
            root_mount=root_mount,
            mounts=mounts,
        )
        expected = _expected_tree(
            include_inventory=include_inventory, include_absence=include_absence
        )
        if set(os.listdir(root_descriptor)) != expected["root"]:
            raise AbsenceAdapterError("structured root contains an unexpected entry")
        control_descriptor, control_metadata = _open_child_directory(
            root_descriptor,
            "control",
            runtime=runtime,
            label="structured control directory",
        )
        control_path = root / "control"
        _require_same_mount(
            path=control_path,
            metadata=control_metadata,
            root_metadata=root_metadata,
            root_mount=root_mount,
            mounts=mounts,
        )
        observed_names = set(os.listdir(control_descriptor))
        if observed_names != expected["control"]:
            raise AbsenceAdapterError("structured control contains an unexpected entry")
        for name in sorted(observed_names):
            metadata = _stat_regular(
                control_descriptor,
                name,
                runtime=runtime,
                label=f"structured control entry {name}",
            )
            _require_same_mount(
                path=control_path / name,
                metadata=metadata,
                root_metadata=root_metadata,
                root_mount=root_mount,
                mounts=mounts,
            )
        return root_metadata, root_mount
    except (AbsenceAdapterError, OSError):
        raise
    finally:
        if control_descriptor >= 0:
            os.close(control_descriptor)
        os.close(root_descriptor)


def _root_identity(metadata: os.stat_result, mount: _MountRecord) -> dict[str, object]:
    mount_binding = {
        "filesystem_type": mount.filesystem_type,
        "major_minor": mount.major_minor,
        "mount_id": mount.mount_id,
        "mount_point": mount.mount_point,
        "mount_root": mount.mount_root,
        "source": mount.source,
    }
    return {
        "access_boundary": "dedicated_absence_adapter_lstat_boundary_v1",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "mount_id": f"mountinfo-v1:{mount.mount_id}:{_sha(_canonical(mount_binding))}",
        "owner_uid": PRETRIGGER_ABSENCE_SERVICE_UID,
    }


def _validate_runtime(runtime: AbsenceRuntime) -> None:
    euid = runtime.euid()
    if type(euid) is not int or euid != PRETRIGGER_ABSENCE_SERVICE_UID:
        raise AbsenceAdapterError("absence adapter requires effective uid 41001")
    if runtime.identity_for_uid(euid) != PRETRIGGER_ABSENCE_SERVICE_IDENTITY:
        raise AbsenceAdapterError("absence adapter service identity differs")


def _physical_root(
    *, logical_root: str, requested_root: Path, runtime: AbsenceRuntime
) -> Path:
    requested_root = _normalized_absolute(requested_root, label="requested root")
    if runtime.physical_root_override is None:
        if requested_root.as_posix() != logical_root:
            raise AbsenceAdapterError("production physical/logical root differs")
        return requested_root
    override = _normalized_absolute(
        runtime.physical_root_override, label="test physical root override"
    )
    if requested_root != override:
        raise AbsenceAdapterError("requested root differs from injected test root")
    return override


def _parse_inventory(
    raw: bytes,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    inventory = _exact_dict(
        _parse_canonical(raw, label="trigger validator inventory"),
        _INVENTORY_KEYS,
        label="trigger validator inventory",
    )
    if (
        inventory["protocol"] != TRIGGER_VALIDATOR_INVENTORY_PROTOCOL
        or inventory["schema_version"] != SCHEMA_VERSION
        or inventory["status"] != "prospectively_registered"
        or inventory["operational_authorization"] is not False
        or type(inventory["tooling_source_commit"]) is not str
        or _COMMIT_RE.fullmatch(inventory["tooling_source_commit"]) is None
        or type(inventory["created_at_utc"]) is not str
        or _UTC_RE.fullmatch(inventory["created_at_utc"]) is None
    ):
        raise AbsenceAdapterError("trigger validator inventory contract differs")
    rows_value = inventory["bindings"]
    if type(rows_value) is not list:
        raise AbsenceAdapterError("trigger validator inventory bindings must be a list")
    rows: list[dict[str, object]] = []
    for index, value in enumerate(rows_value):
        row = _exact_dict(value, _BINDING_KEYS, label=f"binding[{index}]")
        if (
            type(row["binding_id"]) is not str
            or type(row["path"]) is not str
            or not str(row["path"]).startswith("/")
            or type(row["sha256"]) is not str
            or _SHA256_RE.fullmatch(row["sha256"]) is None
            or _exact_int(row["size_bytes"], label=f"binding[{index}].size_bytes") <= 0
        ):
            raise AbsenceAdapterError(f"binding[{index}] differs")
        rows.append(row)
    ids = tuple(str(row["binding_id"]) for row in rows)
    if ids != REQUIRED_VALIDATOR_BINDING_IDS:
        raise AbsenceAdapterError("trigger validator binding ids/order differ")
    paths = [str(row["path"]) for row in rows]
    if len(paths) != len(set(paths)):
        raise AbsenceAdapterError("trigger validator binding paths must be unique")
    unsigned = {key: inventory[key] for key in _INVENTORY_UNSIGNED_KEYS}
    if inventory["binding_inventory_sha256"] != _sha(_canonical(unsigned)):
        raise AbsenceAdapterError("trigger validator inventory self digest differs")
    return inventory, {str(row["binding_id"]): row for row in rows}


def _stable_regular_bytes(path_text: str, *, label: str) -> bytes:
    path = Path(path_text)
    if not path.is_absolute() or Path(os.path.normpath(path_text)) != path:
        raise AbsenceAdapterError(f"{label} path is not normalized absolute")
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")

    def read_once() -> tuple[bytes, tuple[tuple[int, int], ...], tuple[int, ...]]:
        directory = os.open("/", _DIRECTORY_FLAGS)
        chain: list[tuple[int, int]] = []
        descriptor = -1
        try:
            root_metadata = os.fstat(directory)
            chain.append((root_metadata.st_dev, root_metadata.st_ino))
            for component in path.parts[1:-1]:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=directory)
                os.close(directory)
                directory = child
                metadata = os.fstat(directory)
                chain.append((metadata.st_dev, metadata.st_ino))
            descriptor = os.open(path.name, _READ_FLAGS, dir_fd=directory)
            before = os.fstat(descriptor)
            path_metadata = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (
                path_metadata.st_dev,
                path_metadata.st_ino,
            ):
                raise AbsenceAdapterError(
                    f"{label} source is not a stable regular non-symlink"
                )
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor)
            before_fields = tuple(getattr(before, key) for key in stable)
            if before_fields != tuple(getattr(after, key) for key in stable):
                raise AbsenceAdapterError(f"{label} source changed while reading")
            return b"".join(chunks), tuple(chain), before_fields
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory)

    try:
        first = read_once()
        second = read_once()
    except AbsenceAdapterError:
        raise
    except OSError as exc:
        raise AbsenceAdapterError(f"anchored source read failed: {label}") from exc
    if first != second:
        raise AbsenceAdapterError(f"{label} source changed across anchored reads")
    return second[0]


def validate_preinventory_root(
    *,
    root: Path,
    structured_durable_root: str,
    source_commit: str,
    attempt_id: str,
    runtime: AbsenceRuntime | None = None,
) -> None:
    """Require the exact empty root/control tree before inventory publication."""

    runtime = runtime or AbsenceRuntime()
    _validate_runtime(runtime)
    if (
        _COMMIT_RE.fullmatch(source_commit) is None
        or _ATTEMPT_RE.fullmatch(attempt_id) is None
    ):
        raise AbsenceAdapterError("source commit or attempt id differs")
    _validate_logical_root(
        structured_durable_root, source_commit=source_commit, attempt_id=attempt_id
    )
    physical = _physical_root(
        logical_root=structured_durable_root,
        requested_root=root,
        runtime=runtime,
    )
    _scan_exact_tree(
        root=physical,
        runtime=runtime,
        include_inventory=False,
        include_absence=False,
    )


def validate_prereceipt_root_after_absence(
    *,
    root: Path,
    structured_durable_root: str,
    source_commit: str,
    attempt_id: str,
    expected_root_identity: dict[str, object],
    runtime: AbsenceRuntime | None = None,
) -> None:
    """Require exactly the committed inventory and absence before receipt commit."""

    runtime = runtime or AbsenceRuntime()
    _validate_runtime(runtime)
    if (
        _COMMIT_RE.fullmatch(source_commit) is None
        or _ATTEMPT_RE.fullmatch(attempt_id) is None
    ):
        raise AbsenceAdapterError("source commit or attempt id differs")
    _validate_logical_root(
        structured_durable_root, source_commit=source_commit, attempt_id=attempt_id
    )
    physical = _physical_root(
        logical_root=structured_durable_root,
        requested_root=root,
        runtime=runtime,
    )
    root_metadata, root_mount = _scan_exact_tree(
        root=physical,
        runtime=runtime,
        include_inventory=True,
        include_absence=True,
    )
    if type(
        expected_root_identity
    ) is not dict or expected_root_identity != _root_identity(
        root_metadata, root_mount
    ):
        raise AbsenceAdapterError(
            "structured root identity changed between absence and receipt"
        )


def attest_pretrigger_absence(
    *,
    root: Path,
    structured_durable_root: str,
    source_commit: str,
    attempt_id: str,
    trigger_execution_seal_bytes: bytes,
    trigger_validator_inventory_bytes: bytes,
    runtime: AbsenceRuntime | None = None,
) -> bytes:
    """Observe the exact pre-receipt tree and emit a non-authorizing attestation."""

    runtime = runtime or AbsenceRuntime()
    _validate_runtime(runtime)
    if (
        _COMMIT_RE.fullmatch(source_commit) is None
        or _ATTEMPT_RE.fullmatch(attempt_id) is None
    ):
        raise AbsenceAdapterError("source commit or attempt id differs")
    _validate_logical_root(
        structured_durable_root, source_commit=source_commit, attempt_id=attempt_id
    )
    if (
        type(trigger_execution_seal_bytes) is not bytes
        or not trigger_execution_seal_bytes
    ):
        raise AbsenceAdapterError("trigger execution seal must be nonempty exact bytes")
    inventory, bindings = _parse_inventory(trigger_validator_inventory_bytes)
    if inventory["tooling_source_commit"] != source_commit:
        raise AbsenceAdapterError("inventory/source commit join differs")

    physical = _physical_root(
        logical_root=structured_durable_root,
        requested_root=root,
        runtime=runtime,
    )
    observed_inventory, _ = read_and_validate_readonly_artifact(
        root=physical,
        relative_path=INVENTORY_RELATIVE_PATH,
        expected_payload=trigger_validator_inventory_bytes,
    )
    if observed_inventory != trigger_validator_inventory_bytes:
        raise AbsenceAdapterError("committed validator inventory differs")

    adapter_binding = bindings["pretrigger_absence_adapter"]
    actual_source = Path(__file__).resolve(strict=True)
    registered_source = Path(str(adapter_binding["path"]))
    if registered_source != actual_source:
        raise AbsenceAdapterError("registered absence adapter path is not this source")
    adapter_raw = _stable_regular_bytes(
        str(registered_source), label="pretrigger absence adapter"
    )
    if (
        _sha(adapter_raw) != adapter_binding["sha256"]
        or len(adapter_raw) != adapter_binding["size_bytes"]
    ):
        raise AbsenceAdapterError("registered absence adapter source differs")

    root_metadata, root_mount = _scan_exact_tree(
        root=physical,
        runtime=runtime,
        include_inventory=True,
        include_absence=False,
    )
    root_identity = _root_identity(root_metadata, root_mount)
    checked_at = runtime.now_utc()
    if type(checked_at) is not str or _UTC_RE.fullmatch(checked_at) is None:
        raise AbsenceAdapterError("absence clock did not return canonical UTC seconds")
    unsigned = {
        "protocol": PRETRIGGER_ABSENCE_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": "attested_absent",
        "attempt_id": attempt_id,
        "structured_durable_root": structured_durable_root,
        "method": "root_relative_no_follow_full_walk_v1",
        "service_identity": PRETRIGGER_ABSENCE_SERVICE_IDENTITY,
        "service_uid": PRETRIGGER_ABSENCE_SERVICE_UID,
        "adapter_source_path": str(adapter_binding["path"]),
        "adapter_source_sha256": str(adapter_binding["sha256"]),
        "filesystem_root_identity": root_identity,
        "checked_at_utc": checked_at,
        "receipt_created_at_utc": checked_at,
        "trigger_execution_seal_sha256": _sha(trigger_execution_seal_bytes),
        "forbidden_classes": list(ABSENCE_FORBIDDEN_CLASSES),
        "forbidden_match_count": 0,
        "forbidden_matches": [],
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    payload = dict(unsigned)
    payload["absence_attestation_sha256"] = _sha(_canonical(unsigned))
    return _canonical(payload)
