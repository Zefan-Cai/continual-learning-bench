"""Clean-checkout and closed-asset snapshot for structured-state execution.

``capture_and_publish_production_deployment_snapshot`` is the Phase-2 impure
adapter.  Under one non-reusable held lease, it reads a prospectively named
checkout and asset roots twice, verifies Git and filesystem facts, and
atomically publishes both canonical observations followed by the snapshot.  It
does not inspect results, import a model/scorer, or grant launch authority.

``validate_deployment_snapshot_bytes`` is pure.  It requires the raw source,
asset, contract, preregistration, inventory, lease, and observation bytes and
recomputes every content join instead of accepting embedded path/hash claims.
"""

from __future__ import annotations

import base64
import binascii
import errno
import fcntl
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Mapping

import cohort_closed_loop_structured_atomic_publish as atomic_publish

__all__ = (
    "ASSET_ROLE_IDS",
    "CONTROL_DOCUMENT_RELATIVE_PATHS",
    "SOURCE_ROLE_IDS",
    "DeploymentSnapshotArtifacts",
    "DeploymentSnapshotError",
    "DeploymentSnapshotRuntime",
    "DeploymentSnapshotValidation",
    "AnchoredFileCapture",
    "AnchoredRootCapture",
    "FileMetadata",
    "capture_and_publish_production_deployment_snapshot",
    "validate_deployment_snapshot_bytes",
)


class DeploymentSnapshotError(ValueError):
    """Raised when a deployment snapshot cannot be proven exactly."""


SCHEMA_VERSION = 1
SNAPSHOT_PROTOCOL = "cohort_structured_deployment_snapshot_v1"
SOURCE_INVENTORY_PROTOCOL = "cohort_structured_source_inventory_v1"
ASSET_INVENTORY_PROTOCOL = "cohort_structured_closed_asset_inventory_v1"
LEASE_PROTOCOL = "cohort_structured_deployment_capture_lease_v1"
OBSERVATION_PROTOCOL = "cohort_structured_deployment_observation_v1"
SNAPSHOT_STATUS = "clean_committed_closed_snapshot_non_authorizing"
CHECKOUT_BASE = "/mnt/localssd/ttt-rl-cohort-structured-state"
DURABLE_BASE = "/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state"
CAPTURE_SERVICE_UID = 41001
CAPTURE_SERVICE_GID = 41001
DEPLOYMENT_OWNER_UID = 41002
DEPLOYMENT_OWNER_GID = 41002
CAPTURE_ROOT_MODE = 0o700
CAPTURE_CONTROL_MODE = 0o700
DEPLOYMENT_DIRECTORY_MODE = 0o550
DEPLOYMENT_FILE_MODE = 0o440
LEASE_FILE_MODE = 0o400
LEASE_RELATIVE_PATH = "control/deployment_snapshot.capture.lease.json"
OBSERVATION_RELATIVE_PATHS = (
    "control/deployment_snapshot.observation-1.json",
    "control/deployment_snapshot.observation-2.json",
)
SNAPSHOT_RELATIVE_PATH = "control/deployment_snapshot.json"

CONTROL_DOCUMENT_RELATIVE_PATHS: dict[str, str] = {
    "execution_contract": "COHORT_CLOSED_LOOP_STRUCTURED_EXECUTION_CONTRACT_V1.md",
    "structured_preregistration": ("COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md"),
}

SOURCE_ROLE_IDS: tuple[str, ...] = tuple(
    sorted(
        {
            "context_registrar",
            "dgp_completion_validator",
            "dgp_generator",
            "environment_lock",
            "formal_validator",
            "independent_private_validator",
            "launch_expectation_builder",
            "launcher",
            "prelaunch_gate_builder",
            "private_access_probe_source",
            "private_context_access_boundary",
            "protocol_seal_builder",
            "provenance_builder",
            "pure_scorer",
            "report_serializer",
            "runner",
            "smoke_validator",
            "stage_assembler",
            "stage_grid_builder",
            "stage_plan_builder",
            "stage_protocol_seal_builder",
            "structured_atomic_publisher",
            "structured_commitments",
            "structured_deployment_snapshot",
            "structured_dgp_claim_adapter",
            "structured_dgp_completion_adapter",
            "structured_dgp_context_validation",
            "structured_execution_validation",
            "structured_protocol_plan",
            "structured_stage_authorization",
            "structured_state",
            "structured_trigger_bridge",
            "trigger_receipt_builder",
            "trigger_receipt_revalidator",
            "wrapper",
        }
    )
)

ASSET_ROLE_IDS: tuple[str, ...] = tuple(
    sorted(
        {
            "canonical_online_icl_config",
            "cohort_layer_inventory",
            "environment",
            "model_config",
            "model_state_dict",
            "official_scorer",
            "private_access_probe_binary",
            "schema",
            "structured_raw_policy_config",
            "task",
            "tokenizer",
        }
    )
)

_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_MAJOR_MINOR_RE = re.compile(r"[0-9]+:[0-9]+\Z")
_BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"

_FILE_RECORD_KEYS = frozenset({"path", "relative_path", "role", "sha256", "size_bytes"})
_ROOT_IDENTITY_KEYS = frozenset(
    {
        "device",
        "inode",
        "mode_octal",
        "mount",
        "owner_gid",
        "owner_uid",
        "path",
    }
)
_MOUNT_KEYS = frozenset(
    {
        "filesystem_type",
        "major_minor",
        "mount_id",
        "mount_options",
        "mount_point",
        "mount_source",
        "parent_id",
        "read_only",
        "root",
        "super_options",
    }
)
_BINDING_KEYS = frozenset({"sha256", "size_bytes"})
_PATH_BINDING_KEYS = frozenset({"path", "sha256", "size_bytes"})
_OBSERVATION_BINDING_KEYS = frozenset(
    {"ordinal", "path", "sha256", "size_bytes", "state_sha256"}
)
_METADATA_KEYS = frozenset(
    {
        "device",
        "inode",
        "mode_octal",
        "mtime_ns",
        "owner_gid",
        "owner_uid",
        "size_bytes",
    }
)
_INLINE_RAW_KEYS = frozenset({"base64", "sha256", "size_bytes"})
_MOUNT_NAMESPACE_KEYS = frozenset({"device", "inode", "link_target"})
_LEASE_IDENTITY_KEYS = frozenset(
    {
        "device",
        "inode",
        "mode_octal",
        "owner_gid",
        "owner_uid",
        "size_bytes",
    }
)
_CONTROL_BINDING_KEYS = frozenset(
    {"document_id", "path", "relative_path", "sha256", "size_bytes"}
)
_ASSET_BINDING_KEYS = frozenset({"role", "root", "sha256", "size_bytes"})
_SOURCE_UNSIGNED_KEYS = frozenset(
    {"protocol", "schema_version", "source_commit", "checkout_root", "records"}
)
_SOURCE_KEYS = _SOURCE_UNSIGNED_KEYS | {"source_inventory_sha256"}
_ASSET_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "source_commit",
        "attempt_id",
        "role",
        "root_identity",
        "file_count",
        "files",
    }
)
_ASSET_KEYS = _ASSET_UNSIGNED_KEYS | {"asset_inventory_sha256"}
_GIT_KEYS = frozenset(
    {
        "head_matches_source_commit",
        "index_stage_z_sha256",
        "gitlinks_absent",
        "status_porcelain_v1_z_sha256",
        "status_clean",
        "submodule_status_sha256",
        "submodules_absent",
        "untracked_files_absent",
    }
)
_LEASE_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "attempt_id",
        "lease_path",
        "capture_service_uid",
        "deployment_owner_uid",
        "boot_id",
        "process_id",
        "process_start_ticks",
        "mount_namespace",
        "lease_file_identity",
        "created_at_utc",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_LEASE_KEYS = _LEASE_UNSIGNED_KEYS | {"lease_receipt_sha256"}
_OBSERVATION_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "attempt_id",
        "ordinal",
        "observed_at_utc",
        "state",
        "state_sha256",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_OBSERVATION_KEYS = _OBSERVATION_UNSIGNED_KEYS | {"observation_sha256"}
_OBSERVATION_STATE_KEYS = frozenset(
    {
        "lease",
        "boot_id",
        "process",
        "mount_namespace",
        "mountinfo",
        "git",
        "checkout",
        "assets",
        "capture_service_uid",
        "deployment_owner_uid",
        "read_only_mounts_verified",
    }
)
_LEASE_STATE_KEYS = frozenset({"receipt", "fd_identity"})
_PROCESS_STATE_KEYS = frozenset({"process_id", "start_ticks"})
_GIT_STATE_KEYS = frozenset(
    {"head", "status_porcelain_v1_z", "submodule_status", "index_stage_z"}
)
_CHECKOUT_STATE_KEYS = frozenset(
    {"root_identity", "directories", "source_files", "control_files"}
)
_DIRECTORY_OBSERVATION_KEYS = frozenset({"relative_path", "metadata"})
_SOURCE_OBSERVATION_KEYS = frozenset({"role", "relative_path", "metadata", "raw"})
_CONTROL_OBSERVATION_KEYS = frozenset(
    {"document_id", "relative_path", "metadata", "raw"}
)
_ASSET_OBSERVATION_KEYS = frozenset(
    {"role", "root", "root_identity", "directories", "files"}
)
_ASSET_FILE_OBSERVATION_KEYS = frozenset({"relative_path", "metadata", "raw"})
_SNAPSHOT_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "attempt_id",
        "checkout_root_identity",
        "git",
        "control_documents",
        "source_inventory",
        "asset_inventories",
        "deployment_capture_lease",
        "deployment_observations",
        "normalized_observations_equal",
        "read_only_mounts_verified",
        "capture_service_uid",
        "deployment_owner_uid",
        "fresh_consumer_revalidation_required",
        "fresh_consumer_revalidation_available",
        "dgp_generation_authorized",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_SNAPSHOT_KEYS = _SNAPSHOT_UNSIGNED_KEYS | {"deployment_snapshot_sha256"}


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """Small, deterministic subset of ``lstat`` used by the adapter."""

    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int
    size_bytes: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class AnchoredFileCapture:
    """One regular file observed through an anchored no-follow traversal."""

    relative_path: str
    metadata: FileMetadata
    raw: bytes


@dataclass(frozen=True, slots=True)
class AnchoredRootCapture:
    """A root identity plus the exact directories and files observed below it."""

    root_metadata: FileMetadata
    directories: tuple[tuple[str, FileMetadata], ...]
    files: tuple[AnchoredFileCapture, ...]


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    process_id: int
    start_ticks: int


@dataclass(frozen=True, slots=True)
class MountNamespaceIdentity:
    device: int
    inode: int
    link_target: str


def _default_git(checkout_root: PurePosixPath, arguments: tuple[str, ...]) -> bytes:
    try:
        return subprocess.run(
            ("git", "-C", str(checkout_root), *arguments),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise DeploymentSnapshotError(
            f"git command failed: {' '.join(arguments)}"
        ) from exc


def _default_lstat(path: PurePosixPath) -> FileMetadata:
    try:
        value = Path(str(path)).lstat()
    except OSError as exc:
        raise DeploymentSnapshotError(f"cannot lstat deployment path: {path}") from exc
    return FileMetadata(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        owner_uid=value.st_uid,
        owner_gid=value.st_gid,
        size_bytes=value.st_size,
        mtime_ns=value.st_mtime_ns,
    )


def _default_read_bytes(path: PurePosixPath) -> bytes:
    try:
        return Path(str(path)).read_bytes()
    except OSError as exc:
        raise DeploymentSnapshotError(f"cannot read deployment path: {path}") from exc


def _default_listdir(path: PurePosixPath) -> tuple[str, ...]:
    try:
        return tuple(sorted(entry.name for entry in os.scandir(str(path))))
    except OSError as exc:
        raise DeploymentSnapshotError(
            f"cannot enumerate asset directory: {path}"
        ) from exc


def _default_mountinfo() -> bytes:
    try:
        return Path("/proc/self/mountinfo").read_bytes()
    except OSError as exc:
        raise DeploymentSnapshotError("cannot read /proc/self/mountinfo") from exc


def _default_boot_id() -> str:
    try:
        value = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        )
    except OSError as exc:
        raise DeploymentSnapshotError("cannot read Linux boot_id") from exc
    if _BOOT_ID_RE.fullmatch(value) is None:
        raise DeploymentSnapshotError("Linux boot_id format differs")
    return value


def _default_process_identity() -> ProcessIdentity:
    try:
        raw = Path("/proc/self/stat").read_text(encoding="ascii")
    except OSError as exc:
        raise DeploymentSnapshotError("cannot read /proc/self/stat") from exc
    closing = raw.rfind(")")
    if closing <= 0:
        raise DeploymentSnapshotError("/proc/self/stat format differs")
    try:
        process_id = int(raw[: raw.index(" ")])
        fields_from_state = raw[closing + 2 :].split()
        start_ticks = int(fields_from_state[19])
    except (ValueError, IndexError) as exc:
        raise DeploymentSnapshotError("/proc/self/stat identity differs") from exc
    if process_id != os.getpid() or start_ticks <= 0:
        raise DeploymentSnapshotError("process identity differs")
    return ProcessIdentity(process_id, start_ticks)


def _default_mount_namespace() -> MountNamespaceIdentity:
    path = "/proc/self/ns/mnt"
    try:
        link_target = os.readlink(path)
        metadata = os.stat(path, follow_symlinks=True)
    except OSError as exc:
        raise DeploymentSnapshotError("cannot inspect mount namespace") from exc
    if not re.fullmatch(r"mnt:\[[0-9]+\]", link_target):
        raise DeploymentSnapshotError("mount namespace link target differs")
    return MountNamespaceIdentity(metadata.st_dev, metadata.st_ino, link_target)


def _default_clock_utc() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _default_lease_metadata(descriptor: int) -> FileMetadata:
    try:
        return _metadata_from_stat(os.fstat(descriptor))
    except OSError as exc:
        raise DeploymentSnapshotError("cannot inspect held lease descriptor") from exc


def _default_lease_bytes(descriptor: int) -> bytes:
    try:
        metadata = os.fstat(descriptor)
        return os.pread(descriptor, metadata.st_size, 0)
    except OSError as exc:
        raise DeploymentSnapshotError("cannot reread held lease descriptor") from exc


def _metadata_from_stat(value: os.stat_result) -> FileMetadata:
    return FileMetadata(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        owner_uid=value.st_uid,
        owner_gid=value.st_gid,
        size_bytes=value.st_size,
        mtime_ns=value.st_mtime_ns,
    )


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


def _open_absolute_directory_no_follow(path: PurePosixPath) -> int:
    """Open every component from ``/`` with directory-fd + ``O_NOFOLLOW``."""

    descriptor = -1
    try:
        descriptor = os.open("/", _DIRECTORY_OPEN_FLAGS)
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise DeploymentSnapshotError(
            f"cannot open anchored non-symlink directory: {path}"
        ) from exc


def _read_regular_descriptor(
    descriptor: int,
    *,
    relative_path: str,
    root_device: int,
) -> AnchoredFileCapture:
    before = _metadata_from_stat(os.fstat(descriptor))
    if not stat.S_ISREG(before.mode):
        raise DeploymentSnapshotError(
            f"anchored path is not a regular file: {relative_path}"
        )
    if before.device != root_device:
        raise DeploymentSnapshotError(
            f"anchored path crosses a filesystem device: {relative_path}"
        )
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    raw = b"".join(chunks)
    after = _metadata_from_stat(os.fstat(descriptor))
    if before != after or before.size_bytes != len(raw):
        raise DeploymentSnapshotError(
            f"anchored regular file changed while being read: {relative_path}"
        )
    return AnchoredFileCapture(relative_path, before, raw)


def _open_relative_directory_chain(
    root_descriptor: int,
    components: tuple[str, ...],
    *,
    root_device: int,
    directories: dict[str, FileMetadata],
) -> int:
    """Duplicate a root fd and open a normalized relative directory chain."""

    descriptor = os.dup(root_descriptor)
    traversed: list[str] = []
    try:
        for component in components:
            next_descriptor = os.open(
                component,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            traversed.append(component)
            relative = "/".join(traversed)
            metadata = _metadata_from_stat(os.fstat(descriptor))
            if not stat.S_ISDIR(metadata.mode) or metadata.device != root_device:
                raise DeploymentSnapshotError(
                    f"anchored directory crosses a device or changes type: {relative}"
                )
            prior = directories.setdefault(relative, metadata)
            if prior != metadata:
                raise DeploymentSnapshotError(
                    f"anchored directory identity drifted: {relative}"
                )
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise DeploymentSnapshotError(
            "anchored relative directory traversal failed"
        ) from exc
    except Exception:
        os.close(descriptor)
        raise


def _default_capture_selected_root(
    root: PurePosixPath,
    relative_paths: tuple[str, ...],
) -> AnchoredRootCapture:
    root_descriptor = _open_absolute_directory_no_follow(root)
    directories: dict[str, FileMetadata] = {}
    files: list[AnchoredFileCapture] = []
    try:
        root_before = _metadata_from_stat(os.fstat(root_descriptor))
        if not stat.S_ISDIR(root_before.mode):
            raise DeploymentSnapshotError(f"anchored root is not a directory: {root}")
        for relative in relative_paths:
            parts = tuple(relative.split("/"))
            parent_descriptor = _open_relative_directory_chain(
                root_descriptor,
                parts[:-1],
                root_device=root_before.device,
                directories=directories,
            )
            try:
                file_descriptor = os.open(
                    parts[-1],
                    _FILE_OPEN_FLAGS,
                    dir_fd=parent_descriptor,
                )
            except OSError as exc:
                raise DeploymentSnapshotError(
                    f"cannot open anchored non-symlink regular file: {relative}"
                ) from exc
            finally:
                os.close(parent_descriptor)
            try:
                files.append(
                    _read_regular_descriptor(
                        file_descriptor,
                        relative_path=relative,
                        root_device=root_before.device,
                    )
                )
            finally:
                os.close(file_descriptor)
        root_after = _metadata_from_stat(os.fstat(root_descriptor))
        if root_before != root_after:
            raise DeploymentSnapshotError(f"anchored root changed: {root}")
        return AnchoredRootCapture(
            root_metadata=root_before,
            directories=tuple(sorted(directories.items())),
            files=tuple(sorted(files, key=lambda row: row.relative_path)),
        )
    finally:
        os.close(root_descriptor)


def _default_capture_tree_root(root: PurePosixPath) -> AnchoredRootCapture:
    root_descriptor = _open_absolute_directory_no_follow(root)
    directories: dict[str, FileMetadata] = {}
    files: list[AnchoredFileCapture] = []
    try:
        root_before = _metadata_from_stat(os.fstat(root_descriptor))
        if not stat.S_ISDIR(root_before.mode):
            raise DeploymentSnapshotError(f"anchored root is not a directory: {root}")

        def visit(descriptor: int, parent_relative: str) -> None:
            directory_before = _metadata_from_stat(os.fstat(descriptor))
            if (
                not stat.S_ISDIR(directory_before.mode)
                or directory_before.device != root_before.device
            ):
                raise DeploymentSnapshotError(
                    f"asset directory crosses a device: {parent_relative or '.'}"
                )
            try:
                names = sorted(os.listdir(descriptor))
            except OSError as exc:
                raise DeploymentSnapshotError(
                    f"cannot enumerate anchored asset directory: {parent_relative or '.'}"
                ) from exc
            if len(names) != len(set(names)):
                raise DeploymentSnapshotError("anchored directory entry is duplicated")
            for name in names:
                if (
                    type(name) is not str
                    or not name
                    or name in {".", ".."}
                    or "/" in name
                    or "\x00" in name
                ):
                    raise DeploymentSnapshotError("anchored directory entry is unsafe")
                relative = f"{parent_relative}/{name}" if parent_relative else name
                try:
                    child_descriptor = os.open(
                        name,
                        _DIRECTORY_OPEN_FLAGS,
                        dir_fd=descriptor,
                    )
                except OSError as directory_error:
                    if directory_error.errno not in {errno.ELOOP, errno.ENOTDIR}:
                        raise DeploymentSnapshotError(
                            f"cannot open anchored asset entry: {relative}"
                        ) from directory_error
                    try:
                        file_descriptor = os.open(
                            name,
                            _FILE_OPEN_FLAGS,
                            dir_fd=descriptor,
                        )
                    except OSError as file_error:
                        raise DeploymentSnapshotError(
                            f"asset tree contains a symlink or special entry: {relative}"
                        ) from file_error
                    try:
                        files.append(
                            _read_regular_descriptor(
                                file_descriptor,
                                relative_path=relative,
                                root_device=root_before.device,
                            )
                        )
                    finally:
                        os.close(file_descriptor)
                    continue
                try:
                    child_metadata = _metadata_from_stat(os.fstat(child_descriptor))
                    if child_metadata.device != root_before.device:
                        raise DeploymentSnapshotError(
                            f"asset directory crosses a device: {relative}"
                        )
                    directories[relative] = child_metadata
                    visit(child_descriptor, relative)
                    if (
                        _metadata_from_stat(os.fstat(child_descriptor))
                        != child_metadata
                    ):
                        raise DeploymentSnapshotError(
                            f"asset directory identity drifted: {relative}"
                        )
                finally:
                    os.close(child_descriptor)
            if _metadata_from_stat(os.fstat(descriptor)) != directory_before:
                raise DeploymentSnapshotError(
                    f"asset directory changed during enumeration: {parent_relative or '.'}"
                )

        visit(root_descriptor, "")
        root_after = _metadata_from_stat(os.fstat(root_descriptor))
        if root_before != root_after:
            raise DeploymentSnapshotError(f"anchored root changed: {root}")
        return AnchoredRootCapture(
            root_metadata=root_before,
            directories=tuple(sorted(directories.items())),
            files=tuple(sorted(files, key=lambda row: row.relative_path)),
        )
    finally:
        os.close(root_descriptor)


@dataclass(frozen=True, slots=True)
class DeploymentSnapshotRuntime:
    """Injectable I/O surface; the default implementation is local and bounded."""

    git: Callable[[PurePosixPath, tuple[str, ...]], bytes] = _default_git
    lstat: Callable[[PurePosixPath], FileMetadata] = _default_lstat
    read_bytes: Callable[[PurePosixPath], bytes] = _default_read_bytes
    listdir: Callable[[PurePosixPath], tuple[str, ...]] = _default_listdir
    mountinfo: Callable[[], bytes] = _default_mountinfo
    boot_id: Callable[[], str] = _default_boot_id
    process_identity: Callable[[], ProcessIdentity] = _default_process_identity
    mount_namespace: Callable[[], MountNamespaceIdentity] = _default_mount_namespace
    clock_utc: Callable[[], str] = _default_clock_utc
    lease_metadata: Callable[[int], FileMetadata] = _default_lease_metadata
    lease_bytes: Callable[[int], bytes] = _default_lease_bytes
    capture_root: (
        Callable[[PurePosixPath, tuple[str, ...] | None], AnchoredRootCapture] | None
    ) = None


@dataclass(frozen=True, slots=True)
class DeploymentSnapshotArtifacts:
    """Raw capture outputs; mappings are represented as sorted immutable pairs."""

    deployment_snapshot_bytes: bytes
    source_inventory_bytes: bytes
    asset_inventory_bytes: tuple[tuple[str, bytes], ...]
    source_file_bytes: tuple[tuple[str, bytes], ...]
    asset_file_bytes: tuple[tuple[str, tuple[tuple[str, bytes], ...]], ...]
    execution_contract_bytes: bytes
    structured_preregistration_bytes: bytes
    git_index_bytes: bytes
    lease_receipt_bytes: bytes
    observation_bytes: tuple[bytes, bytes]
    published_artifacts: tuple[atomic_publish.PublishedArtifactObservation, ...] = ()


@dataclass(frozen=True, slots=True)
class DeploymentSnapshotValidation:
    source_commit: str
    attempt_id: str
    checkout_root: str
    deployment_snapshot_sha256: str
    source_inventory_sha256: str
    source_bindings: tuple[tuple[str, str], ...]
    asset_inventory_bindings: tuple[tuple[str, str], ...]
    execution_contract_sha256: str
    structured_preregistration_sha256: str
    lease_receipt_sha256: str
    observation_state_sha256: str
    normalized_observations_equal: bool
    read_only_mounts_verified: bool
    fresh_consumer_revalidation_required: bool
    dgp_generation_authorized: bool = False
    model_calls_authorized: bool = False
    operational_authorization: bool = False


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
        raise DeploymentSnapshotError("artifact is not canonical ASCII JSON") from exc


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentSnapshotError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise DeploymentSnapshotError(f"non-finite JSON constant: {value}")


def _parse(raw: object, label: str) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise DeploymentSnapshotError(f"{label} must be exact bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentSnapshotError(f"{label} is not strict ASCII JSON") from exc
    if type(value) is not dict or _canonical(value) != raw:
        raise DeploymentSnapshotError(f"{label} is not exact canonical JSON")
    return value


def _object(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise DeploymentSnapshotError(f"{label} schema differs")
    return value


def _list(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise DeploymentSnapshotError(f"{label} must be an exact list")
    return value


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _with_digest(unsigned: dict[str, object], key: str) -> bytes:
    payload = dict(unsigned)
    payload[key] = _sha(_canonical(unsigned))
    return _canonical(payload)


def _absolute(value: object, label: str) -> PurePosixPath:
    if type(value) is not str or not value.startswith("/") or "\x00" in value:
        raise DeploymentSnapshotError(f"{label} must be an absolute POSIX path")
    if posixpath.normpath(value) != value or (
        value != "/"
        and any(component in {"", ".", ".."} for component in value.split("/")[1:])
    ):
        raise DeploymentSnapshotError(f"{label} is not normalized")
    return PurePosixPath(value)


def _relative(value: object, label: str) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\x00" in value:
        raise DeploymentSnapshotError(f"{label} must be a relative POSIX path")
    if posixpath.normpath(value) != value or any(
        component in {"", ".", ".."} for component in value.split("/")
    ):
        raise DeploymentSnapshotError(f"{label} is not normalized")
    return value


def _legacy_capture_root(
    runtime: DeploymentSnapshotRuntime,
    root: PurePosixPath,
    relative_paths: tuple[str, ...] | None,
) -> AnchoredRootCapture:
    """Compatibility adapter for injected tests predating the fd capture hook."""

    _assert_no_symlink_ancestors(runtime, root / "__anchor__", label="capture root")
    root_before = runtime.lstat(root)
    if stat.S_ISLNK(root_before.mode) or not stat.S_ISDIR(root_before.mode):
        raise DeploymentSnapshotError(f"root is not a non-symlink directory: {root}")
    directories: dict[str, FileMetadata] = {}
    files: list[AnchoredFileCapture] = []

    def observe_file(path: PurePosixPath, relative: str) -> None:
        _assert_no_symlink_ancestors(runtime, path, label=f"anchored file {relative}")
        before = runtime.lstat(path)
        if stat.S_ISLNK(before.mode) or not stat.S_ISREG(before.mode):
            raise DeploymentSnapshotError(
                f"anchored path is not a non-symlink regular file: {relative}"
            )
        if before.device != root_before.device:
            raise DeploymentSnapshotError(
                f"anchored path crosses a filesystem device: {relative}"
            )
        raw = runtime.read_bytes(path)
        after = runtime.lstat(path)
        if before != after or before.size_bytes != len(raw):
            raise DeploymentSnapshotError(
                f"anchored regular file changed while being read: {relative}"
            )
        files.append(AnchoredFileCapture(relative, before, raw))

    if relative_paths is not None:
        for relative in relative_paths:
            parts = relative.split("/")
            for index in range(1, len(parts)):
                directory_relative = "/".join(parts[:index])
                metadata = runtime.lstat(root / directory_relative)
                if (
                    stat.S_ISLNK(metadata.mode)
                    or not stat.S_ISDIR(metadata.mode)
                    or metadata.device != root_before.device
                ):
                    raise DeploymentSnapshotError(
                        f"anchored directory crosses a device or changes type: "
                        f"{directory_relative}"
                    )
                prior = directories.setdefault(directory_relative, metadata)
                if prior != metadata:
                    raise DeploymentSnapshotError(
                        f"anchored directory identity drifted: {directory_relative}"
                    )
            observe_file(root / relative, relative)
    else:

        def visit(directory: PurePosixPath, parent_relative: str) -> None:
            before = runtime.lstat(directory)
            if (
                stat.S_ISLNK(before.mode)
                or not stat.S_ISDIR(before.mode)
                or before.device != root_before.device
            ):
                raise DeploymentSnapshotError(
                    f"asset directory crosses a device: {parent_relative or '.'}"
                )
            names = runtime.listdir(directory)
            if tuple(sorted(names)) != names or len(names) != len(set(names)):
                raise DeploymentSnapshotError(
                    f"asset directory order differs: {directory}"
                )
            for name in names:
                if (
                    type(name) is not str
                    or not name
                    or name in {".", ".."}
                    or "/" in name
                    or "\x00" in name
                ):
                    raise DeploymentSnapshotError("asset directory entry is unsafe")
                relative = f"{parent_relative}/{name}" if parent_relative else name
                path = directory / name
                metadata = runtime.lstat(path)
                if metadata.device != root_before.device:
                    raise DeploymentSnapshotError("asset tree crosses a device")
                if stat.S_ISLNK(metadata.mode):
                    raise DeploymentSnapshotError("asset tree contains a symlink")
                if stat.S_ISDIR(metadata.mode):
                    directories[relative] = metadata
                    visit(path, relative)
                elif stat.S_ISREG(metadata.mode):
                    observe_file(path, relative)
                else:
                    raise DeploymentSnapshotError("asset tree contains a special file")
            if runtime.lstat(directory) != before:
                raise DeploymentSnapshotError(
                    f"asset directory changed during enumeration: {directory}"
                )

        visit(root, "")

    root_after = runtime.lstat(root)
    if root_before != root_after:
        raise DeploymentSnapshotError(f"anchored root changed: {root}")
    return AnchoredRootCapture(
        root_metadata=root_before,
        directories=tuple(sorted(directories.items())),
        files=tuple(sorted(files, key=lambda row: row.relative_path)),
    )


def _capture_root(
    runtime: DeploymentSnapshotRuntime,
    root: PurePosixPath,
    relative_paths: tuple[str, ...] | None,
) -> AnchoredRootCapture:
    if relative_paths is not None:
        normalized = tuple(
            _relative(value, "anchored selected path") for value in relative_paths
        )
        if normalized != tuple(sorted(set(normalized))):
            raise DeploymentSnapshotError(
                "anchored selected paths must be unique and sorted"
            )
        relative_paths = normalized
    if runtime.capture_root is not None:
        capture = runtime.capture_root(root, relative_paths)
        if type(capture) is not AnchoredRootCapture:
            raise DeploymentSnapshotError("capture_root returned the wrong type")
        return capture
    if (
        runtime.lstat is _default_lstat
        and runtime.read_bytes is _default_read_bytes
        and runtime.listdir is _default_listdir
    ):
        if relative_paths is None:
            return _default_capture_tree_root(root)
        return _default_capture_selected_root(root, relative_paths)
    return _legacy_capture_root(runtime, root, relative_paths)


def _exact_role_mapping(
    value: Mapping[str, object], expected: tuple[str, ...], label: str
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(expected):
        missing = (
            sorted(set(expected) - set(value)) if isinstance(value, Mapping) else []
        )
        extra = sorted(set(value) - set(expected)) if isinstance(value, Mapping) else []
        raise DeploymentSnapshotError(
            f"{label} role set differs; missing={missing!r}, extra={extra!r}"
        )
    return {role: value[role] for role in expected}


def _expected_checkout(source_commit: str, attempt_id: str) -> PurePosixPath:
    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise DeploymentSnapshotError("source_commit must be exact 40-hex")
    if _ATTEMPT_RE.fullmatch(attempt_id) is None:
        raise DeploymentSnapshotError("attempt_id must match attempt-[0-9]{3}")
    return PurePosixPath(CHECKOUT_BASE, source_commit, attempt_id)


def _stable_regular_bytes(
    runtime: DeploymentSnapshotRuntime,
    path: PurePosixPath,
    *,
    expected_device: int,
    label: str,
) -> bytes:
    before = runtime.lstat(path)
    if stat.S_ISLNK(before.mode) or not stat.S_ISREG(before.mode):
        raise DeploymentSnapshotError(f"{label} is not a non-symlink regular file")
    if before.device != expected_device:
        raise DeploymentSnapshotError(f"{label} crosses a filesystem device")
    raw = runtime.read_bytes(path)
    after = runtime.lstat(path)
    if before != after or before.size_bytes != len(raw):
        raise DeploymentSnapshotError(f"{label} changed while being read")
    if raw.startswith(_LFS_POINTER_PREFIX):
        raise DeploymentSnapshotError(f"{label} is an unresolved Git LFS pointer")
    return raw


def _assert_no_symlink_ancestors(
    runtime: DeploymentSnapshotRuntime, path: PurePosixPath, *, label: str
) -> None:
    current = PurePosixPath("/")
    for component in path.parts[1:-1]:
        current /= component
        metadata = runtime.lstat(current)
        if stat.S_ISLNK(metadata.mode) or not stat.S_ISDIR(metadata.mode):
            raise DeploymentSnapshotError(
                f"{label} has a symlink or nondirectory ancestor: {current}"
            )


def _parse_git_index(raw: bytes) -> dict[str, str]:
    rows = raw.split(b"\x00")
    if not rows or rows[-1] != b"":
        raise DeploymentSnapshotError("Git index stage output is not NUL terminated")
    result: dict[str, str] = {}
    for encoded in rows[:-1]:
        metadata, separator, path_raw = encoded.partition(b"\t")
        parts = metadata.split()
        if not separator or len(parts) != 3:
            raise DeploymentSnapshotError("Git index stage row is malformed")
        mode_raw, object_id, stage_raw = parts
        try:
            mode = mode_raw.decode("ascii")
            object_id_text = object_id.decode("ascii")
            stage = stage_raw.decode("ascii")
            path = path_raw.decode("utf-8")
        except UnicodeError as exc:
            raise DeploymentSnapshotError(
                "Git index stage row encoding differs"
            ) from exc
        if (
            not re.fullmatch(r"[0-7]{6}", mode)
            or not re.fullmatch(r"[0-9a-f]{40,64}", object_id_text)
            or stage != "0"
        ):
            raise DeploymentSnapshotError("Git index stage metadata differs")
        _relative(path, "Git index path")
        if path in result:
            raise DeploymentSnapshotError("Git index path is duplicated")
        if mode == "160000":
            raise DeploymentSnapshotError("Git index contains a submodule gitlink")
        result[path] = mode
    return result


def _decode_mount_field(value: str) -> str:
    replacements = {"\\040": " ", "\\011": "\t", "\\012": "\n", "\\134": "\\"}
    for encoded, decoded in replacements.items():
        value = value.replace(encoded, decoded)
    return value


def _mount_identity(raw: bytes, target: PurePosixPath) -> dict[str, object]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise DeploymentSnapshotError("mountinfo is not ASCII") from exc
    candidates: list[dict[str, object]] = []
    target_text = str(target)
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            raise DeploymentSnapshotError("mountinfo row is malformed")
        fields = left.split()
        trailing = right.split()
        if len(fields) < 6 or len(trailing) < 3:
            raise DeploymentSnapshotError("mountinfo row is incomplete")
        mount_point = _decode_mount_field(fields[4])
        if target_text != mount_point and not target_text.startswith(
            mount_point.rstrip("/") + "/"
        ):
            continue
        if _MAJOR_MINOR_RE.fullmatch(fields[2]) is None:
            raise DeploymentSnapshotError("mountinfo major:minor differs")
        mount_options = fields[5]
        super_options = trailing[2]
        read_only = (
            "ro" in mount_options.split(",")
            and "rw" not in mount_options.split(",")
            and "ro" in super_options.split(",")
            and "rw" not in super_options.split(",")
        )
        candidates.append(
            {
                "mount_id": int(fields[0]),
                "parent_id": int(fields[1]),
                "major_minor": fields[2],
                "root": _decode_mount_field(fields[3]),
                "mount_point": mount_point,
                "mount_options": mount_options,
                "filesystem_type": trailing[0],
                "mount_source": _decode_mount_field(trailing[1]),
                "super_options": super_options,
                "read_only": read_only,
            }
        )
    if not candidates:
        raise DeploymentSnapshotError(f"no mount identity covers {target}")
    longest = max(len(str(row["mount_point"])) for row in candidates)
    winners = [row for row in candidates if len(str(row["mount_point"])) == longest]
    if len(winners) != 1:
        raise DeploymentSnapshotError(
            f"non-unique longest mount identity covers {target}"
        )
    return winners[0]


def _device_major_minor(value: FileMetadata | int) -> str:
    device = value.device if isinstance(value, FileMetadata) else value
    return f"{os.major(device)}:{os.minor(device)}"


def _root_identity(
    path: PurePosixPath,
    metadata: FileMetadata,
    mountinfo_raw: bytes,
) -> dict[str, object]:
    if stat.S_ISLNK(metadata.mode) or not stat.S_ISDIR(metadata.mode):
        raise DeploymentSnapshotError(f"root is not a non-symlink directory: {path}")
    mount = _mount_identity(mountinfo_raw, path)
    if mount["major_minor"] != _device_major_minor(metadata):
        raise DeploymentSnapshotError(
            f"mount major:minor differs from root st_dev: {path}"
        )
    if mount["read_only"] is not True:
        raise DeploymentSnapshotError(f"deployment mount is not read-only: {path}")
    return {
        "path": str(path),
        "device": metadata.device,
        "inode": metadata.inode,
        "owner_uid": metadata.owner_uid,
        "owner_gid": metadata.owner_gid,
        "mode_octal": f"{stat.S_IMODE(metadata.mode):04o}",
        "mount": mount,
    }


def _validate_capture_mount_closure(
    mountinfo_raw: bytes,
    root: PurePosixPath,
    capture: AnchoredRootCapture,
) -> dict[str, object]:
    root_mount = _mount_identity(mountinfo_raw, root)
    if root_mount["major_minor"] != _device_major_minor(capture.root_metadata):
        raise DeploymentSnapshotError(
            f"mount major:minor differs from root st_dev: {root}"
        )
    if root_mount["read_only"] is not True:
        raise DeploymentSnapshotError(f"deployment mount is not read-only: {root}")
    rows = [*capture.directories]
    rows.extend((row.relative_path, row.metadata) for row in capture.files)
    for relative, metadata in rows:
        if metadata.device != capture.root_metadata.device:
            raise DeploymentSnapshotError(f"capture crosses a device below {root}")
        observed_mount = _mount_identity(mountinfo_raw, root / relative)
        if observed_mount != root_mount:
            raise DeploymentSnapshotError(
                f"capture crosses an alternate mount below {root}: {relative}"
            )
        if observed_mount["major_minor"] != _device_major_minor(metadata):
            raise DeploymentSnapshotError(
                f"mount major:minor differs from st_dev below {root}: {relative}"
            )
    return root_mount


def _validate_deployment_capture_permissions(
    capture: AnchoredRootCapture,
    *,
    label: str,
) -> None:
    directory_rows = [(".", capture.root_metadata), *capture.directories]
    for relative, metadata in directory_rows:
        if (
            not stat.S_ISDIR(metadata.mode)
            or stat.S_IMODE(metadata.mode) != DEPLOYMENT_DIRECTORY_MODE
            or metadata.owner_uid != DEPLOYMENT_OWNER_UID
            or metadata.owner_gid != DEPLOYMENT_OWNER_GID
        ):
            raise DeploymentSnapshotError(
                f"{label} directory owner or mode differs: {relative}"
            )
    for row in capture.files:
        metadata = row.metadata
        if (
            not stat.S_ISREG(metadata.mode)
            or stat.S_IMODE(metadata.mode) != DEPLOYMENT_FILE_MODE
            or metadata.owner_uid != DEPLOYMENT_OWNER_UID
            or metadata.owner_gid != DEPLOYMENT_OWNER_GID
        ):
            raise DeploymentSnapshotError(
                f"{label} file owner or mode differs: {row.relative_path}"
            )


def _relative_to(path: PurePosixPath, root: PurePosixPath, label: str) -> str:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise DeploymentSnapshotError(f"{label} escapes checkout root") from exc
    return _relative(relative, label)


def _git_committed_file(
    runtime: DeploymentSnapshotRuntime,
    checkout: PurePosixPath,
    relative: str,
    raw: bytes,
    *,
    label: str,
) -> None:
    tracked = runtime.git(checkout, ("ls-files", "--error-unmatch", "--", relative))
    if tracked != (relative + "\n").encode("utf-8"):
        raise DeploymentSnapshotError(f"{label} is not exactly tracked")
    committed = runtime.git(checkout, ("cat-file", "blob", f"HEAD:{relative}"))
    if committed != raw:
        raise DeploymentSnapshotError(f"{label} differs from HEAD bytes")


def _capture_git_state(
    runtime: DeploymentSnapshotRuntime,
    checkout: PurePosixPath,
    source_commit: str,
) -> tuple[bytes, bytes, bytes, bytes, dict[str, str]]:
    head = runtime.git(checkout, ("rev-parse", "--verify", "HEAD"))
    if head != (source_commit + "\n").encode("ascii"):
        raise DeploymentSnapshotError("Git HEAD differs from source_commit")
    status_raw = runtime.git(
        checkout,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
    )
    if status_raw:
        raise DeploymentSnapshotError("checkout is dirty or has untracked files")
    submodule_raw = runtime.git(checkout, ("submodule", "status", "--recursive"))
    if submodule_raw:
        raise DeploymentSnapshotError("submodules are forbidden")
    git_index_raw = runtime.git(checkout, ("ls-files", "--stage", "-z"))
    return (
        head,
        status_raw,
        submodule_raw,
        git_index_raw,
        _parse_git_index(git_index_raw),
    )


def _metadata_payload(metadata: FileMetadata) -> dict[str, object]:
    return {
        "device": metadata.device,
        "inode": metadata.inode,
        "mode_octal": f"{stat.S_IMODE(metadata.mode):04o}",
        "mtime_ns": metadata.mtime_ns,
        "owner_gid": metadata.owner_gid,
        "owner_uid": metadata.owner_uid,
        "size_bytes": metadata.size_bytes,
    }


def _lease_identity_payload(metadata: FileMetadata) -> dict[str, object]:
    payload = _metadata_payload(metadata)
    del payload["mtime_ns"]
    return payload


def _inline_raw(raw: bytes) -> dict[str, object]:
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "sha256": _sha(raw),
        "size_bytes": len(raw),
    }


def _mount_namespace_payload(
    identity: MountNamespaceIdentity,
) -> dict[str, object]:
    return {
        "device": identity.device,
        "inode": identity.inode,
        "link_target": identity.link_target,
    }


def _require_utc(value: object, label: str) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise DeploymentSnapshotError(f"{label} must be UTC text ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DeploymentSnapshotError(f"{label} is not ISO-8601 UTC") from exc
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if parsed.tzinfo != timezone.utc or canonical != value:
        raise DeploymentSnapshotError(f"{label} is not canonical microsecond UTC")
    return value


def _build_lease_receipt_bytes(
    *,
    source_commit: str,
    attempt_id: str,
    lease_path: str,
    boot_id: str,
    process_identity: ProcessIdentity,
    mount_namespace: MountNamespaceIdentity,
    lease_metadata: FileMetadata,
    created_at_utc: str,
) -> bytes:
    _expected_checkout(source_commit, attempt_id)
    _absolute(lease_path, "lease_path")
    _require_utc(created_at_utc, "lease created_at_utc")
    if _BOOT_ID_RE.fullmatch(boot_id) is None:
        raise DeploymentSnapshotError("lease boot_id differs")
    size_bytes = lease_metadata.size_bytes
    for _ in range(8):
        identity = _lease_identity_payload(lease_metadata)
        identity["size_bytes"] = size_bytes
        unsigned = {
            "protocol": LEASE_PROTOCOL,
            "schema_version": SCHEMA_VERSION,
            "status": "held_exclusive_non_reusable",
            "source_commit": source_commit,
            "attempt_id": attempt_id,
            "lease_path": lease_path,
            "capture_service_uid": CAPTURE_SERVICE_UID,
            "deployment_owner_uid": DEPLOYMENT_OWNER_UID,
            "boot_id": boot_id,
            "process_id": process_identity.process_id,
            "process_start_ticks": process_identity.start_ticks,
            "mount_namespace": _mount_namespace_payload(mount_namespace),
            "lease_file_identity": identity,
            "created_at_utc": created_at_utc,
            "model_calls_authorized": False,
            "operational_authorization": False,
        }
        raw = _with_digest(unsigned, "lease_receipt_sha256")
        if len(raw) == size_bytes:
            return raw
        size_bytes = len(raw)
    raise DeploymentSnapshotError("lease receipt size did not stabilize")


def _validate_lease_receipt_bytes(
    raw: object,
    *,
    source_commit: str,
    attempt_id: str,
    lease_path: str,
) -> dict[str, Any]:
    lease_raw = raw if type(raw) is bytes else b""
    lease = _object(
        _parse(raw, "lease_receipt_bytes"), _LEASE_KEYS, "deployment capture lease"
    )
    if (
        lease["protocol"] != LEASE_PROTOCOL
        or type(lease["schema_version"]) is not int
        or lease["schema_version"] != SCHEMA_VERSION
        or lease["status"] != "held_exclusive_non_reusable"
        or lease["source_commit"] != source_commit
        or lease["attempt_id"] != attempt_id
        or lease["lease_path"] != lease_path
        or type(lease["capture_service_uid"]) is not int
        or lease["capture_service_uid"] != CAPTURE_SERVICE_UID
        or type(lease["deployment_owner_uid"]) is not int
        or lease["deployment_owner_uid"] != DEPLOYMENT_OWNER_UID
        or CAPTURE_SERVICE_UID == DEPLOYMENT_OWNER_UID
        or lease["model_calls_authorized"] is not False
        or lease["operational_authorization"] is not False
    ):
        raise DeploymentSnapshotError("deployment capture lease contract differs")
    if (
        type(lease["boot_id"]) is not str
        or _BOOT_ID_RE.fullmatch(lease["boot_id"]) is None
    ):
        raise DeploymentSnapshotError("deployment capture lease boot_id differs")
    for key in ("process_id", "process_start_ticks"):
        if type(lease[key]) is not int or lease[key] <= 0:
            raise DeploymentSnapshotError(f"deployment capture lease {key} differs")
    namespace = _object(
        lease["mount_namespace"], _MOUNT_NAMESPACE_KEYS, "lease mount namespace"
    )
    if (
        type(namespace["device"]) is not int
        or namespace["device"] < 0
        or type(namespace["inode"]) is not int
        or namespace["inode"] <= 0
        or type(namespace["link_target"]) is not str
        or re.fullmatch(r"mnt:\[[0-9]+\]", namespace["link_target"]) is None
    ):
        raise DeploymentSnapshotError("lease mount namespace identity differs")
    identity = _object(
        lease["lease_file_identity"],
        _LEASE_IDENTITY_KEYS,
        "lease file identity",
    )
    if (
        type(identity["device"]) is not int
        or identity["device"] < 0
        or type(identity["inode"]) is not int
        or identity["inode"] <= 0
        or identity["owner_uid"] != CAPTURE_SERVICE_UID
        or identity["owner_gid"] != CAPTURE_SERVICE_GID
        or identity["mode_octal"] != f"{LEASE_FILE_MODE:04o}"
        or identity["size_bytes"] != len(lease_raw)
    ):
        raise DeploymentSnapshotError("lease file identity differs")
    _require_utc(lease["created_at_utc"], "lease created_at_utc")
    if lease["lease_receipt_sha256"] != _sha(
        _canonical({key: lease[key] for key in _LEASE_UNSIGNED_KEYS})
    ):
        raise DeploymentSnapshotError("lease receipt self digest differs")
    return lease


def _capture_state_payload(
    *,
    lease_receipt_bytes: bytes,
    lease_metadata: FileMetadata,
    boot_id: str,
    process_identity: ProcessIdentity,
    mount_namespace: MountNamespaceIdentity,
    mountinfo_raw: bytes,
    git_state: tuple[bytes, bytes, bytes, bytes, dict[str, str]],
    checkout_identity: dict[str, object],
    checkout_capture: AnchoredRootCapture,
    source_relatives: Mapping[str, str],
    asset_roots: Mapping[str, PurePosixPath],
    asset_identities: Mapping[str, dict[str, object]],
    asset_captures: Mapping[str, AnchoredRootCapture],
) -> dict[str, object]:
    checkout_files = {row.relative_path: row for row in checkout_capture.files}
    source_files = []
    for role in SOURCE_ROLE_IDS:
        relative = source_relatives[role]
        row = checkout_files[relative]
        source_files.append(
            {
                "role": role,
                "relative_path": relative,
                "metadata": _metadata_payload(row.metadata),
                "raw": _inline_raw(row.raw),
            }
        )
    controls = []
    for document_id, relative in sorted(CONTROL_DOCUMENT_RELATIVE_PATHS.items()):
        row = checkout_files[relative]
        controls.append(
            {
                "document_id": document_id,
                "relative_path": relative,
                "metadata": _metadata_payload(row.metadata),
                "raw": _inline_raw(row.raw),
            }
        )
    assets = []
    for role in ASSET_ROLE_IDS:
        capture = asset_captures[role]
        assets.append(
            {
                "role": role,
                "root": str(asset_roots[role]),
                "root_identity": asset_identities[role],
                "directories": [
                    {
                        "relative_path": relative,
                        "metadata": _metadata_payload(metadata),
                    }
                    for relative, metadata in capture.directories
                ],
                "files": [
                    {
                        "relative_path": row.relative_path,
                        "metadata": _metadata_payload(row.metadata),
                        "raw": _inline_raw(row.raw),
                    }
                    for row in capture.files
                ],
            }
        )
    head, status_raw, submodule_raw, index_raw, _ = git_state
    return {
        "lease": {
            "receipt": _inline_raw(lease_receipt_bytes),
            "fd_identity": _lease_identity_payload(lease_metadata),
        },
        "boot_id": boot_id,
        "process": {
            "process_id": process_identity.process_id,
            "start_ticks": process_identity.start_ticks,
        },
        "mount_namespace": _mount_namespace_payload(mount_namespace),
        "mountinfo": _inline_raw(mountinfo_raw),
        "git": {
            "head": _inline_raw(head),
            "status_porcelain_v1_z": _inline_raw(status_raw),
            "submodule_status": _inline_raw(submodule_raw),
            "index_stage_z": _inline_raw(index_raw),
        },
        "checkout": {
            "root_identity": checkout_identity,
            "directories": [
                {
                    "relative_path": relative,
                    "metadata": _metadata_payload(metadata),
                }
                for relative, metadata in checkout_capture.directories
            ],
            "source_files": source_files,
            "control_files": controls,
        },
        "assets": assets,
        "capture_service_uid": CAPTURE_SERVICE_UID,
        "deployment_owner_uid": DEPLOYMENT_OWNER_UID,
        "read_only_mounts_verified": True,
    }


def _observation_bytes(
    *,
    source_commit: str,
    attempt_id: str,
    ordinal: int,
    observed_at_utc: str,
    state: dict[str, object],
) -> bytes:
    _require_utc(observed_at_utc, "observation observed_at_utc")
    unsigned = {
        "protocol": OBSERVATION_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": "complete_global_observation_non_authorizing",
        "source_commit": source_commit,
        "attempt_id": attempt_id,
        "ordinal": ordinal,
        "observed_at_utc": observed_at_utc,
        "state": state,
        "state_sha256": _sha(_canonical(state)),
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    return _with_digest(unsigned, "observation_sha256")


def _capture_asset_once(
    runtime: DeploymentSnapshotRuntime,
    root: PurePosixPath,
    *,
    role: str,
    root_device: int,
) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    records: list[dict[str, object]] = []
    raws: dict[str, bytes] = {}

    def visit(directory: PurePosixPath) -> None:
        names = runtime.listdir(directory)
        if tuple(sorted(names)) != names or len(names) != len(set(names)):
            raise DeploymentSnapshotError(f"asset directory order differs: {directory}")
        for name in names:
            if (
                type(name) is not str
                or not name
                or name in {".", ".."}
                or "/" in name
                or "\x00" in name
            ):
                raise DeploymentSnapshotError("asset directory entry is unsafe")
            path = directory / name
            metadata = runtime.lstat(path)
            if metadata.device != root_device:
                raise DeploymentSnapshotError(f"asset {role} crosses a device")
            if stat.S_ISLNK(metadata.mode):
                raise DeploymentSnapshotError(f"asset {role} contains a symlink")
            if stat.S_ISDIR(metadata.mode):
                visit(path)
                continue
            if not stat.S_ISREG(metadata.mode):
                raise DeploymentSnapshotError(f"asset {role} contains a special file")
            raw = _stable_regular_bytes(
                runtime,
                path,
                expected_device=root_device,
                label=f"asset {role}",
            )
            relative = _relative_to(path, root, f"asset {role} relative path")
            records.append(
                {
                    "path": str(path),
                    "relative_path": relative,
                    "role": role,
                    "sha256": _sha(raw),
                    "size_bytes": len(raw),
                }
            )
            raws[relative] = raw

    visit(root)
    records.sort(key=lambda row: str(row["relative_path"]))
    if not records:
        raise DeploymentSnapshotError(f"asset {role} directory is empty")
    return records, raws


def _decode_inline_raw(value: object, label: str) -> bytes:
    row = _object(value, _INLINE_RAW_KEYS, label)
    if (
        type(row["base64"]) is not str
        or type(row["sha256"]) is not str
        or _SHA_RE.fullmatch(row["sha256"]) is None
        or type(row["size_bytes"]) is not int
        or row["size_bytes"] < 0
    ):
        raise DeploymentSnapshotError(f"{label} inline raw schema differs")
    try:
        raw = base64.b64decode(row["base64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DeploymentSnapshotError(f"{label} base64 differs") from exc
    if (
        base64.b64encode(raw).decode("ascii") != row["base64"]
        or _sha(raw) != row["sha256"]
        or len(raw) != row["size_bytes"]
    ):
        raise DeploymentSnapshotError(f"{label} inline raw binding differs")
    return raw


def _validate_observed_metadata(
    value: object,
    *,
    label: str,
    directory: bool,
    expected_size: int | None = None,
) -> dict[str, Any]:
    metadata = _object(value, _METADATA_KEYS, label)
    for key in ("device", "inode", "mtime_ns", "owner_gid", "owner_uid", "size_bytes"):
        if type(metadata[key]) is not int or metadata[key] < 0:
            raise DeploymentSnapshotError(f"{label}.{key} differs")
    expected_mode = DEPLOYMENT_DIRECTORY_MODE if directory else DEPLOYMENT_FILE_MODE
    if (
        metadata["mode_octal"] != f"{expected_mode:04o}"
        or metadata["owner_uid"] != DEPLOYMENT_OWNER_UID
        or metadata["owner_gid"] != DEPLOYMENT_OWNER_GID
        or (expected_size is not None and metadata["size_bytes"] != expected_size)
    ):
        raise DeploymentSnapshotError(f"{label} owner, mode, or size differs")
    return metadata


def _validate_mount_for_observed_path(
    *,
    mountinfo_raw: bytes,
    root_path: PurePosixPath,
    root_identity: Mapping[str, object],
    relative: str,
    metadata: Mapping[str, object],
    label: str,
) -> None:
    root_mount = root_identity["mount"]
    observed = _mount_identity(mountinfo_raw, root_path / relative)
    if (
        observed != root_mount
        or observed["read_only"] is not True
        or observed["major_minor"] != _device_major_minor(metadata["device"])
        or metadata["device"] != root_identity["device"]
    ):
        raise DeploymentSnapshotError(f"{label} mount closure differs")


def _validate_observation_state(
    state: object,
    *,
    lease_raw: bytes,
    lease: Mapping[str, object],
    source_commit: str,
    checkout_root: PurePosixPath,
    snapshot_checkout_identity: Mapping[str, object],
    git_index_raw: bytes,
    source_inventory: Mapping[str, object],
    source_file_bytes_by_role: Mapping[str, object],
    asset_inventory_bytes_by_role: Mapping[str, object],
    asset_file_bytes_by_role: Mapping[str, Mapping[str, object]],
    execution_contract_bytes: bytes,
    structured_preregistration_bytes: bytes,
) -> None:
    value = _object(state, _OBSERVATION_STATE_KEYS, "observation state")
    if (
        value["capture_service_uid"] != CAPTURE_SERVICE_UID
        or value["deployment_owner_uid"] != DEPLOYMENT_OWNER_UID
        or value["read_only_mounts_verified"] is not True
    ):
        raise DeploymentSnapshotError("observation state identity differs")
    lease_state = _object(value["lease"], _LEASE_STATE_KEYS, "observation lease")
    if (
        _decode_inline_raw(lease_state["receipt"], "observation lease receipt")
        != lease_raw
    ):
        raise DeploymentSnapshotError("observation lease raw bytes differ")
    lease_identity = _object(
        lease_state["fd_identity"],
        _LEASE_IDENTITY_KEYS,
        "observation lease fd identity",
    )
    if lease_identity != lease["lease_file_identity"]:
        raise DeploymentSnapshotError("observation lease fd identity differs")
    if value["boot_id"] != lease["boot_id"]:
        raise DeploymentSnapshotError("observation boot epoch differs")
    process = _object(value["process"], _PROCESS_STATE_KEYS, "observation process")
    if (
        process["process_id"] != lease["process_id"]
        or process["start_ticks"] != lease["process_start_ticks"]
    ):
        raise DeploymentSnapshotError("observation process epoch differs")
    namespace = _object(
        value["mount_namespace"],
        _MOUNT_NAMESPACE_KEYS,
        "observation mount namespace",
    )
    if namespace != lease["mount_namespace"]:
        raise DeploymentSnapshotError("observation mount namespace differs")
    mountinfo_raw = _decode_inline_raw(value["mountinfo"], "observation mountinfo")

    git = _object(value["git"], _GIT_STATE_KEYS, "observation git")
    if (
        _decode_inline_raw(git["head"], "observation git head")
        != (source_commit + "\n").encode("ascii")
        or _decode_inline_raw(git["status_porcelain_v1_z"], "observation git status")
        != b""
        or _decode_inline_raw(git["submodule_status"], "observation submodules") != b""
        or _decode_inline_raw(git["index_stage_z"], "observation git index")
        != git_index_raw
    ):
        raise DeploymentSnapshotError("observation Git raw state differs")

    checkout = _object(value["checkout"], _CHECKOUT_STATE_KEYS, "observation checkout")
    checkout_identity = _validate_root_identity(
        checkout["root_identity"], "observation checkout root"
    )
    if checkout_identity != snapshot_checkout_identity:
        raise DeploymentSnapshotError("observation checkout root identity differs")
    if (
        checkout_identity["mode_octal"] != f"{DEPLOYMENT_DIRECTORY_MODE:04o}"
        or checkout_identity["owner_uid"] != DEPLOYMENT_OWNER_UID
        or checkout_identity["owner_gid"] != DEPLOYMENT_OWNER_GID
        or _mount_identity(mountinfo_raw, checkout_root) != checkout_identity["mount"]
    ):
        raise DeploymentSnapshotError("observation checkout root policy differs")

    directories = _list(checkout["directories"], "observation checkout directories")
    observed_directory_paths: list[str] = []
    for index, raw_row in enumerate(directories):
        row = _object(
            raw_row, _DIRECTORY_OBSERVATION_KEYS, f"checkout directory[{index}]"
        )
        relative = _relative(row["relative_path"], "checkout directory relative")
        metadata = _validate_observed_metadata(
            row["metadata"], label=f"checkout directory[{index}]", directory=True
        )
        _validate_mount_for_observed_path(
            mountinfo_raw=mountinfo_raw,
            root_path=checkout_root,
            root_identity=checkout_identity,
            relative=relative,
            metadata=metadata,
            label=f"checkout directory[{index}]",
        )
        observed_directory_paths.append(relative)
    if observed_directory_paths != sorted(set(observed_directory_paths)):
        raise DeploymentSnapshotError("checkout directory observation order differs")

    source_records = {
        row["role"]: row for row in _list(source_inventory["records"], "source records")
    }
    source_rows = _list(checkout["source_files"], "observation source files")
    if len(source_rows) != len(SOURCE_ROLE_IDS):
        raise DeploymentSnapshotError("observation source count differs")
    for index, role in enumerate(SOURCE_ROLE_IDS):
        row = _object(
            source_rows[index], _SOURCE_OBSERVATION_KEYS, f"observation source {role}"
        )
        expected_raw = source_file_bytes_by_role[role]
        expected_record = source_records[role]
        if (
            row["role"] != role
            or row["relative_path"] != expected_record["relative_path"]
            or _decode_inline_raw(row["raw"], f"observation source {role} raw")
            != expected_raw
        ):
            raise DeploymentSnapshotError(f"observation source {role} join differs")
        metadata = _validate_observed_metadata(
            row["metadata"],
            label=f"observation source {role}",
            directory=False,
            expected_size=len(expected_raw),
        )
        _validate_mount_for_observed_path(
            mountinfo_raw=mountinfo_raw,
            root_path=checkout_root,
            root_identity=checkout_identity,
            relative=row["relative_path"],
            metadata=metadata,
            label=f"observation source {role}",
        )

    control_raws = {
        "execution_contract": execution_contract_bytes,
        "structured_preregistration": structured_preregistration_bytes,
    }
    control_rows = _list(checkout["control_files"], "observation control files")
    if len(control_rows) != len(CONTROL_DOCUMENT_RELATIVE_PATHS):
        raise DeploymentSnapshotError("observation control count differs")
    for index, (document_id, relative) in enumerate(
        sorted(CONTROL_DOCUMENT_RELATIVE_PATHS.items())
    ):
        row = _object(
            control_rows[index],
            _CONTROL_OBSERVATION_KEYS,
            f"observation control {document_id}",
        )
        expected_raw = control_raws[document_id]
        if (
            row["document_id"] != document_id
            or row["relative_path"] != relative
            or _decode_inline_raw(row["raw"], f"observation control {document_id} raw")
            != expected_raw
        ):
            raise DeploymentSnapshotError(
                f"observation control {document_id} join differs"
            )
        metadata = _validate_observed_metadata(
            row["metadata"],
            label=f"observation control {document_id}",
            directory=False,
            expected_size=len(expected_raw),
        )
        _validate_mount_for_observed_path(
            mountinfo_raw=mountinfo_raw,
            root_path=checkout_root,
            root_identity=checkout_identity,
            relative=relative,
            metadata=metadata,
            label=f"observation control {document_id}",
        )

    assets = _list(value["assets"], "observation assets")
    if len(assets) != len(ASSET_ROLE_IDS):
        raise DeploymentSnapshotError("observation asset count differs")
    for index, role in enumerate(ASSET_ROLE_IDS):
        row = _object(
            assets[index], _ASSET_OBSERVATION_KEYS, f"observation asset {role}"
        )
        inventory = _object(
            _parse(asset_inventory_bytes_by_role[role], f"asset inventory {role}"),
            _ASSET_KEYS,
            f"asset inventory {role}",
        )
        root_identity = _validate_root_identity(
            row["root_identity"], f"observation asset {role} root"
        )
        root_path = _absolute(row["root"], f"observation asset {role} root path")
        if (
            row["role"] != role
            or row["root"] != inventory["root_identity"]["path"]
            or root_identity != inventory["root_identity"]
            or root_identity["mode_octal"] != f"{DEPLOYMENT_DIRECTORY_MODE:04o}"
            or root_identity["owner_uid"] != DEPLOYMENT_OWNER_UID
            or root_identity["owner_gid"] != DEPLOYMENT_OWNER_GID
            or _mount_identity(mountinfo_raw, root_path) != root_identity["mount"]
        ):
            raise DeploymentSnapshotError(f"observation asset {role} root differs")
        directory_rows = _list(row["directories"], f"asset {role} directories")
        directory_paths: list[str] = []
        for directory_index, raw_directory in enumerate(directory_rows):
            directory = _object(
                raw_directory,
                _DIRECTORY_OBSERVATION_KEYS,
                f"asset {role} directory[{directory_index}]",
            )
            relative = _relative(
                directory["relative_path"], f"asset {role} directory relative"
            )
            metadata = _validate_observed_metadata(
                directory["metadata"],
                label=f"asset {role} directory[{directory_index}]",
                directory=True,
            )
            _validate_mount_for_observed_path(
                mountinfo_raw=mountinfo_raw,
                root_path=root_path,
                root_identity=root_identity,
                relative=relative,
                metadata=metadata,
                label=f"asset {role} directory[{directory_index}]",
            )
            directory_paths.append(relative)
        if directory_paths != sorted(set(directory_paths)):
            raise DeploymentSnapshotError(f"asset {role} directory order differs")
        inventory_files = {
            item["relative_path"]: item
            for item in _list(inventory["files"], f"asset {role} inventory files")
        }
        observed_files = _list(row["files"], f"observation asset {role} files")
        expected_file_map = asset_file_bytes_by_role[role]
        observed_relatives: list[str] = []
        for file_index, raw_file in enumerate(observed_files):
            file_row = _object(
                raw_file,
                _ASSET_FILE_OBSERVATION_KEYS,
                f"asset {role} file[{file_index}]",
            )
            relative = _relative(
                file_row["relative_path"], f"asset {role} file relative"
            )
            if relative not in inventory_files or relative not in expected_file_map:
                raise DeploymentSnapshotError(f"asset {role} observed file differs")
            expected_raw = expected_file_map[relative]
            if (
                _decode_inline_raw(
                    file_row["raw"], f"asset {role} file[{file_index}] raw"
                )
                != expected_raw
            ):
                raise DeploymentSnapshotError(f"asset {role} observed raw differs")
            metadata = _validate_observed_metadata(
                file_row["metadata"],
                label=f"asset {role} file[{file_index}]",
                directory=False,
                expected_size=len(expected_raw),
            )
            _validate_mount_for_observed_path(
                mountinfo_raw=mountinfo_raw,
                root_path=root_path,
                root_identity=root_identity,
                relative=relative,
                metadata=metadata,
                label=f"asset {role} file[{file_index}]",
            )
            observed_relatives.append(relative)
        if (
            observed_relatives != sorted(set(observed_relatives))
            or set(observed_relatives) != set(inventory_files)
            or set(observed_relatives) != set(expected_file_map)
        ):
            raise DeploymentSnapshotError(f"asset {role} observation closure differs")


def _validate_root_identity(value: object, label: str) -> dict[str, Any]:
    root = _object(value, _ROOT_IDENTITY_KEYS, label)
    _absolute(root["path"], f"{label}.path")
    for key in ("device", "inode", "owner_uid", "owner_gid"):
        if type(root[key]) is not int or root[key] < 0:
            raise DeploymentSnapshotError(f"{label}.{key} must be a nonnegative int")
    if type(root["mode_octal"]) is not str or not re.fullmatch(
        r"[0-7]{4}", root["mode_octal"]
    ):
        raise DeploymentSnapshotError(f"{label}.mode_octal differs")
    mount = _object(root["mount"], _MOUNT_KEYS, f"{label}.mount")
    if (
        type(mount["mount_id"]) is not int
        or type(mount["parent_id"]) is not int
        or type(mount["major_minor"]) is not str
        or _MAJOR_MINOR_RE.fullmatch(mount["major_minor"]) is None
        or type(mount["mount_options"]) is not str
        or type(mount["super_options"]) is not str
        or mount["read_only"] is not True
    ):
        raise DeploymentSnapshotError(f"{label}.mount identity differs")
    for key in ("root", "mount_point", "filesystem_type", "mount_source"):
        if type(mount[key]) is not str or not mount[key]:
            raise DeploymentSnapshotError(f"{label}.mount.{key} differs")
    mount_point = _absolute(mount["mount_point"], f"{label}.mount.mount_point")
    root_path = _absolute(root["path"], f"{label}.path")
    if root_path != mount_point and not str(root_path).startswith(
        str(mount_point).rstrip("/") + "/"
    ):
        raise DeploymentSnapshotError(f"{label}.mount does not cover root path")
    if mount["major_minor"] != _device_major_minor(root["device"]):
        raise DeploymentSnapshotError(f"{label}.mount major:minor differs from device")
    for options_key in ("mount_options", "super_options"):
        options = mount[options_key].split(",")
        if "ro" not in options or "rw" in options:
            raise DeploymentSnapshotError(f"{label}.{options_key} is not read-only")
    return root


def _validate_file_record(value: object, label: str, role: str) -> dict[str, Any]:
    row = _object(value, _FILE_RECORD_KEYS, label)
    _absolute(row["path"], f"{label}.path")
    _relative(row["relative_path"], f"{label}.relative_path")
    if row["role"] != role:
        raise DeploymentSnapshotError(f"{label}.role differs")
    if type(row["sha256"]) is not str or _SHA_RE.fullmatch(row["sha256"]) is None:
        raise DeploymentSnapshotError(f"{label}.sha256 differs")
    if type(row["size_bytes"]) is not int or row["size_bytes"] < 0:
        raise DeploymentSnapshotError(f"{label}.size_bytes differs")
    return row


def _capture_deployment_snapshot_core(
    *,
    source_commit: str,
    attempt_id: str,
    checkout_root: str,
    source_paths_by_role: Mapping[str, object],
    asset_roots_by_role: Mapping[str, object],
    lease_descriptor: int,
    lease_receipt_bytes: object,
    runtime: DeploymentSnapshotRuntime,
    lease_assertion: Callable[[], None] | None = None,
) -> DeploymentSnapshotArtifacts:
    """Internal two-observation core; callers must hold the exclusive lease."""

    io = runtime
    assert_lease = lease_assertion or (lambda: None)
    expected_checkout = _expected_checkout(source_commit, attempt_id)
    checkout = _absolute(checkout_root, "checkout_root")
    if checkout != expected_checkout:
        raise DeploymentSnapshotError("checkout_root is not the exact production root")
    durable_root = PurePosixPath(DURABLE_BASE, source_commit, "attempts", attempt_id)
    lease_path = str(durable_root / LEASE_RELATIVE_PATH)
    lease_raw = lease_receipt_bytes if type(lease_receipt_bytes) is bytes else b""
    lease = _validate_lease_receipt_bytes(
        lease_receipt_bytes,
        source_commit=source_commit,
        attempt_id=attempt_id,
        lease_path=lease_path,
    )
    source_inputs = _exact_role_mapping(
        source_paths_by_role, SOURCE_ROLE_IDS, "source_paths_by_role"
    )
    asset_inputs = _exact_role_mapping(
        asset_roots_by_role, ASSET_ROLE_IDS, "asset_roots_by_role"
    )
    assert_lease()
    first_lease_raw = io.lease_bytes(lease_descriptor)
    first_lease_metadata = io.lease_metadata(lease_descriptor)
    first_boot_id = io.boot_id()
    first_process = io.process_identity()
    first_mount_namespace = io.mount_namespace()
    if (
        first_lease_raw != lease_raw
        or _lease_identity_payload(first_lease_metadata) != lease["lease_file_identity"]
        or first_boot_id != lease["boot_id"]
        or first_process.process_id != lease["process_id"]
        or first_process.start_ticks != lease["process_start_ticks"]
        or _mount_namespace_payload(first_mount_namespace) != lease["mount_namespace"]
    ):
        raise DeploymentSnapshotError("held lease identity or process epoch differs")
    mountinfo_raw = io.mountinfo()
    git_state = _capture_git_state(io, checkout, source_commit)
    _, status_raw, submodule_raw, git_index_raw, git_index = git_state

    source_relatives: dict[str, str] = {}
    source_paths: set[str] = set()
    for role in SOURCE_ROLE_IDS:
        path = _absolute(source_inputs[role], f"source {role}")
        if str(path) in source_paths:
            raise DeploymentSnapshotError("distinct source roles share a path")
        source_paths.add(str(path))
        source_relatives[role] = _relative_to(path, checkout, f"source {role}")

    selected_checkout_relatives = tuple(
        sorted(
            {
                *source_relatives.values(),
                *CONTROL_DOCUMENT_RELATIVE_PATHS.values(),
            }
        )
    )
    checkout_capture = _capture_root(io, checkout, selected_checkout_relatives)
    _validate_capture_mount_closure(mountinfo_raw, checkout, checkout_capture)
    _validate_deployment_capture_permissions(checkout_capture, label="checkout")
    checkout_identity = _root_identity(
        checkout, checkout_capture.root_metadata, mountinfo_raw
    )
    checkout_files = {row.relative_path: row for row in checkout_capture.files}
    if set(checkout_files) != set(selected_checkout_relatives):
        raise DeploymentSnapshotError("checkout anchored capture is incomplete")

    source_records: list[dict[str, object]] = []
    source_raws: dict[str, bytes] = {}
    for role in SOURCE_ROLE_IDS:
        relative = source_relatives[role]
        observation = checkout_files[relative]
        raw = observation.raw
        if raw.startswith(_LFS_POINTER_PREFIX):
            raise DeploymentSnapshotError(
                f"source {role} is an unresolved Git LFS pointer"
            )
        _git_committed_file(io, checkout, relative, raw, label=f"source {role}")
        if relative not in git_index:
            raise DeploymentSnapshotError(f"source {role} is absent from Git index")
        source_records.append(
            {
                "path": str(checkout / relative),
                "relative_path": relative,
                "role": role,
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
        )
        source_raws[role] = raw
    source_records.sort(key=lambda row: str(row["role"]))
    source_unsigned = {
        "protocol": SOURCE_INVENTORY_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "source_commit": source_commit,
        "checkout_root": str(checkout),
        "records": source_records,
    }
    source_inventory_raw = _with_digest(source_unsigned, "source_inventory_sha256")

    control_rows: list[dict[str, object]] = []
    control_raws: dict[str, bytes] = {}
    for document_id, relative in sorted(CONTROL_DOCUMENT_RELATIVE_PATHS.items()):
        observation = checkout_files[relative]
        raw = observation.raw
        if raw.startswith(_LFS_POINTER_PREFIX):
            raise DeploymentSnapshotError(
                f"{document_id} is an unresolved Git LFS pointer"
            )
        _git_committed_file(io, checkout, relative, raw, label=document_id)
        if relative not in git_index:
            raise DeploymentSnapshotError(f"{document_id} is absent from Git index")
        control_rows.append(
            {
                "document_id": document_id,
                "path": str(checkout / relative),
                "relative_path": relative,
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
        )
        control_raws[document_id] = raw

    asset_inventory_raws: dict[str, bytes] = {}
    asset_raws: dict[str, dict[str, bytes]] = {}
    asset_bindings: list[dict[str, object]] = []
    asset_captures: dict[str, AnchoredRootCapture] = {}
    asset_identities: dict[str, dict[str, object]] = {}
    asset_roots: dict[str, PurePosixPath] = {}
    asset_root_paths: set[str] = set()
    for role in ASSET_ROLE_IDS:
        root = _absolute(asset_inputs[role], f"asset root {role}")
        if str(root) in asset_root_paths:
            raise DeploymentSnapshotError("distinct asset roles share a root")
        asset_root_paths.add(str(root))
        capture = _capture_root(io, root, None)
        _validate_capture_mount_closure(mountinfo_raw, root, capture)
        _validate_deployment_capture_permissions(capture, label=f"asset {role}")
        identity = _root_identity(root, capture.root_metadata, mountinfo_raw)
        records: list[dict[str, object]] = []
        raws: dict[str, bytes] = {}
        for observation in capture.files:
            raw = observation.raw
            if raw.startswith(_LFS_POINTER_PREFIX):
                raise DeploymentSnapshotError(
                    f"asset {role} is an unresolved Git LFS pointer"
                )
            records.append(
                {
                    "path": str(root / observation.relative_path),
                    "relative_path": observation.relative_path,
                    "role": role,
                    "sha256": _sha(raw),
                    "size_bytes": len(raw),
                }
            )
            raws[observation.relative_path] = raw
        if not records:
            raise DeploymentSnapshotError(f"asset {role} directory is empty")
        asset_unsigned = {
            "protocol": ASSET_INVENTORY_PROTOCOL,
            "schema_version": SCHEMA_VERSION,
            "source_commit": source_commit,
            "attempt_id": attempt_id,
            "role": role,
            "root_identity": identity,
            "file_count": len(records),
            "files": records,
        }
        inventory_raw = _with_digest(asset_unsigned, "asset_inventory_sha256")
        asset_inventory_raws[role] = inventory_raw
        asset_raws[role] = raws
        asset_captures[role] = capture
        asset_identities[role] = identity
        asset_roots[role] = root
        asset_bindings.append(
            {
                "role": role,
                "root": str(root),
                "sha256": _sha(inventory_raw),
                "size_bytes": len(inventory_raw),
            }
        )

    first_state = _capture_state_payload(
        lease_receipt_bytes=lease_raw,
        lease_metadata=first_lease_metadata,
        boot_id=first_boot_id,
        process_identity=first_process,
        mount_namespace=first_mount_namespace,
        mountinfo_raw=mountinfo_raw,
        git_state=git_state,
        checkout_identity=checkout_identity,
        checkout_capture=checkout_capture,
        source_relatives=source_relatives,
        asset_roots=asset_roots,
        asset_identities=asset_identities,
        asset_captures=asset_captures,
    )
    first_observed_at = io.clock_utc()
    assert_lease()

    assert_lease()
    second_lease_raw = io.lease_bytes(lease_descriptor)
    second_lease_metadata = io.lease_metadata(lease_descriptor)
    second_boot_id = io.boot_id()
    second_process = io.process_identity()
    second_mount_namespace = io.mount_namespace()
    if second_lease_raw != lease_raw:
        raise DeploymentSnapshotError("held lease bytes drifted")
    terminal_mountinfo_raw = io.mountinfo()
    terminal_git_state = _capture_git_state(io, checkout, source_commit)
    if terminal_git_state[:4] != git_state[:4]:
        raise DeploymentSnapshotError("Git state drifted during snapshot capture")
    terminal_checkout_capture = _capture_root(io, checkout, selected_checkout_relatives)
    _validate_capture_mount_closure(
        terminal_mountinfo_raw, checkout, terminal_checkout_capture
    )
    _validate_deployment_capture_permissions(
        terminal_checkout_capture, label="terminal checkout"
    )
    terminal_checkout_identity = _root_identity(
        checkout,
        terminal_checkout_capture.root_metadata,
        terminal_mountinfo_raw,
    )
    if (
        terminal_checkout_capture != checkout_capture
        or terminal_checkout_identity != checkout_identity
    ):
        raise DeploymentSnapshotError(
            "checkout source/control bytes, metadata, or root identity drifted"
        )
    terminal_asset_captures: dict[str, AnchoredRootCapture] = {}
    terminal_asset_identities: dict[str, dict[str, object]] = {}
    for role in ASSET_ROLE_IDS:
        root = asset_roots[role]
        terminal_capture = _capture_root(io, root, None)
        _validate_capture_mount_closure(terminal_mountinfo_raw, root, terminal_capture)
        _validate_deployment_capture_permissions(
            terminal_capture, label=f"terminal asset {role}"
        )
        terminal_identity = _root_identity(
            root, terminal_capture.root_metadata, terminal_mountinfo_raw
        )
        terminal_asset_captures[role] = terminal_capture
        terminal_asset_identities[role] = terminal_identity
        if (
            terminal_capture != asset_captures[role]
            or terminal_identity != asset_identities[role]
        ):
            raise DeploymentSnapshotError(
                f"asset {role} bytes, metadata, or root identity drifted"
            )

    second_state = _capture_state_payload(
        lease_receipt_bytes=lease_raw,
        lease_metadata=second_lease_metadata,
        boot_id=second_boot_id,
        process_identity=second_process,
        mount_namespace=second_mount_namespace,
        mountinfo_raw=terminal_mountinfo_raw,
        git_state=terminal_git_state,
        checkout_identity=terminal_checkout_identity,
        checkout_capture=terminal_checkout_capture,
        source_relatives=source_relatives,
        asset_roots=asset_roots,
        asset_identities=terminal_asset_identities,
        asset_captures=terminal_asset_captures,
    )
    second_observed_at = io.clock_utc()
    if first_state != second_state:
        raise DeploymentSnapshotError(
            "normalized deployment observations differ across the held lease"
        )
    if _require_utc(first_observed_at, "observation 1 time") >= _require_utc(
        second_observed_at, "observation 2 time"
    ):
        raise DeploymentSnapshotError("observation timestamps are not strictly ordered")
    observation_raws = (
        _observation_bytes(
            source_commit=source_commit,
            attempt_id=attempt_id,
            ordinal=1,
            observed_at_utc=first_observed_at,
            state=first_state,
        ),
        _observation_bytes(
            source_commit=source_commit,
            attempt_id=attempt_id,
            ordinal=2,
            observed_at_utc=second_observed_at,
            state=second_state,
        ),
    )
    assert_lease()
    state_sha256 = _sha(_canonical(first_state))

    snapshot_unsigned = {
        "protocol": SNAPSHOT_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": SNAPSHOT_STATUS,
        "source_commit": source_commit,
        "attempt_id": attempt_id,
        "checkout_root_identity": checkout_identity,
        "git": {
            "head_matches_source_commit": True,
            "index_stage_z_sha256": _sha(git_index_raw),
            "gitlinks_absent": True,
            "status_porcelain_v1_z_sha256": _sha(status_raw),
            "status_clean": True,
            "submodule_status_sha256": _sha(submodule_raw),
            "submodules_absent": True,
            "untracked_files_absent": True,
        },
        "control_documents": control_rows,
        "source_inventory": {
            "sha256": _sha(source_inventory_raw),
            "size_bytes": len(source_inventory_raw),
        },
        "asset_inventories": asset_bindings,
        "deployment_capture_lease": {
            "path": lease_path,
            "sha256": _sha(lease_raw),
            "size_bytes": len(lease_raw),
        },
        "deployment_observations": [
            {
                "ordinal": ordinal,
                "path": str(durable_root / OBSERVATION_RELATIVE_PATHS[ordinal - 1]),
                "sha256": _sha(observation_raws[ordinal - 1]),
                "size_bytes": len(observation_raws[ordinal - 1]),
                "state_sha256": state_sha256,
            }
            for ordinal in (1, 2)
        ],
        "normalized_observations_equal": True,
        "read_only_mounts_verified": True,
        "capture_service_uid": CAPTURE_SERVICE_UID,
        "deployment_owner_uid": DEPLOYMENT_OWNER_UID,
        "fresh_consumer_revalidation_required": True,
        "fresh_consumer_revalidation_available": False,
        "dgp_generation_authorized": False,
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    snapshot_raw = _with_digest(snapshot_unsigned, "deployment_snapshot_sha256")
    return DeploymentSnapshotArtifacts(
        deployment_snapshot_bytes=snapshot_raw,
        source_inventory_bytes=source_inventory_raw,
        asset_inventory_bytes=tuple(sorted(asset_inventory_raws.items())),
        source_file_bytes=tuple(sorted(source_raws.items())),
        asset_file_bytes=tuple(
            (role, tuple(sorted(files.items())))
            for role, files in sorted(asset_raws.items())
        ),
        execution_contract_bytes=control_raws["execution_contract"],
        structured_preregistration_bytes=control_raws["structured_preregistration"],
        git_index_bytes=git_index_raw,
        lease_receipt_bytes=lease_raw,
        observation_bytes=observation_raws,
    )


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise DeploymentSnapshotError("lease receipt write made no progress")
        offset += written


def _require_capture_directory(
    descriptor: int,
    *,
    label: str,
    expected_mode: int,
) -> FileMetadata:
    metadata = _metadata_from_stat(os.fstat(descriptor))
    if (
        not stat.S_ISDIR(metadata.mode)
        or metadata.owner_uid != CAPTURE_SERVICE_UID
        or metadata.owner_gid != CAPTURE_SERVICE_GID
        or stat.S_IMODE(metadata.mode) != expected_mode
    ):
        raise DeploymentSnapshotError(f"{label} capture owner or mode differs")
    return metadata


def _assert_exclusive_lease_held(
    descriptor: int,
    *,
    lease_path: PurePosixPath,
    expected_identity: Mapping[str, object],
) -> None:
    """Require the registered descriptor to still exclude an independent opener."""

    try:
        held_metadata = _metadata_from_stat(os.fstat(descriptor))
    except OSError as exc:
        raise DeploymentSnapshotError(
            "deployment capture lease descriptor is no longer open"
        ) from exc
    if _lease_identity_payload(held_metadata) != dict(expected_identity):
        raise DeploymentSnapshotError(
            "deployment capture lease descriptor identity changed"
        )

    parent_descriptor = -1
    probe_descriptor = -1
    probe_acquired = False
    try:
        parent_descriptor = _open_absolute_directory_no_follow(lease_path.parent)
        probe_descriptor = os.open(
            lease_path.name,
            _FILE_OPEN_FLAGS,
            dir_fd=parent_descriptor,
        )
        probe_metadata = _metadata_from_stat(os.fstat(probe_descriptor))
        if _lease_identity_payload(probe_metadata) != dict(expected_identity):
            raise DeploymentSnapshotError(
                "deployment capture lease pathname identity changed"
            )
        try:
            fcntl.flock(probe_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as owner_exc:
                    if owner_exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                        raise DeploymentSnapshotError(
                            "deployment capture lease original descriptor no longer "
                            "owns the exclusive lock"
                        ) from owner_exc
                    raise DeploymentSnapshotError(
                        "deployment capture lease owner assertion failed unexpectedly"
                    ) from owner_exc
                try:
                    reaffirmed_metadata = _metadata_from_stat(os.fstat(descriptor))
                except OSError as owner_exc:
                    raise DeploymentSnapshotError(
                        "deployment capture lease descriptor closed during assertion"
                    ) from owner_exc
                if _lease_identity_payload(reaffirmed_metadata) != dict(
                    expected_identity
                ):
                    raise DeploymentSnapshotError(
                        "deployment capture lease descriptor identity changed during "
                        "assertion"
                    )
                return
            raise DeploymentSnapshotError(
                "deployment capture lease probe failed unexpectedly"
            ) from exc
        probe_acquired = True
        raise DeploymentSnapshotError(
            "deployment capture lease is no longer held exclusively"
        )
    except DeploymentSnapshotError:
        raise
    except OSError as exc:
        raise DeploymentSnapshotError(
            "deployment capture lease probe operation failed"
        ) from exc
    finally:
        if probe_acquired and probe_descriptor >= 0:
            try:
                fcntl.flock(probe_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        for candidate in (probe_descriptor, parent_descriptor):
            if candidate >= 0:
                try:
                    os.close(candidate)
                except OSError:
                    pass


@contextmanager
def _production_capture_lease(
    *,
    durable_root: PurePosixPath,
    source_commit: str,
    attempt_id: str,
    runtime: DeploymentSnapshotRuntime,
) -> Iterator[tuple[int, bytes]]:
    root_descriptor = -1
    control_descriptor = -1
    lease_descriptor = -1
    try:
        root_descriptor = _open_absolute_directory_no_follow(durable_root)
        root_metadata = _require_capture_directory(
            root_descriptor,
            label="durable root",
            expected_mode=CAPTURE_ROOT_MODE,
        )
        control_descriptor = os.open(
            "control", _DIRECTORY_OPEN_FLAGS, dir_fd=root_descriptor
        )
        control_metadata = _require_capture_directory(
            control_descriptor,
            label="durable control",
            expected_mode=CAPTURE_CONTROL_MODE,
        )
        if control_metadata.device != root_metadata.device:
            raise DeploymentSnapshotError("durable control crosses a device")
        lease_name = PurePosixPath(LEASE_RELATIVE_PATH).name
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            lease_descriptor = os.open(
                lease_name,
                create_flags,
                0o600,
                dir_fd=control_descriptor,
            )
        except FileExistsError as exc:
            raise DeploymentSnapshotError(
                "deployment capture lease already exists; attempt is poisoned"
            ) from exc
        try:
            fcntl.flock(lease_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            raise DeploymentSnapshotError(
                "deployment capture lease cannot be locked exclusively"
            ) from exc
        os.fchmod(lease_descriptor, LEASE_FILE_MODE)
        initial_metadata = _metadata_from_stat(os.fstat(lease_descriptor))
        if (
            initial_metadata.owner_uid != CAPTURE_SERVICE_UID
            or initial_metadata.owner_gid != CAPTURE_SERVICE_GID
            or stat.S_IMODE(initial_metadata.mode) != LEASE_FILE_MODE
            or initial_metadata.size_bytes != 0
            or initial_metadata.device != control_metadata.device
        ):
            raise DeploymentSnapshotError(
                "new deployment capture lease identity differs"
            )
        boot_id = runtime.boot_id()
        process_identity = runtime.process_identity()
        mount_namespace = runtime.mount_namespace()
        created_at_utc = runtime.clock_utc()
        lease_path = str(durable_root / LEASE_RELATIVE_PATH)
        lease_raw = _build_lease_receipt_bytes(
            source_commit=source_commit,
            attempt_id=attempt_id,
            lease_path=lease_path,
            boot_id=boot_id,
            process_identity=process_identity,
            mount_namespace=mount_namespace,
            lease_metadata=initial_metadata,
            created_at_utc=created_at_utc,
        )
        _write_all(lease_descriptor, lease_raw)
        os.fsync(lease_descriptor)
        os.fsync(control_descriptor)
        final_metadata = _metadata_from_stat(os.fstat(lease_descriptor))
        expected_identity = json.loads(lease_raw)["lease_file_identity"]
        if _lease_identity_payload(final_metadata) != expected_identity:
            raise DeploymentSnapshotError("written lease receipt identity differs")
        yield lease_descriptor, lease_raw
    except DeploymentSnapshotError:
        raise
    except (OSError, ValueError) as exc:
        raise DeploymentSnapshotError(
            "deployment capture lease operation failed"
        ) from exc
    finally:
        for descriptor in (lease_descriptor, control_descriptor, root_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _publish_snapshot_artifacts(
    *,
    durable_root: PurePosixPath,
    artifacts: DeploymentSnapshotArtifacts,
    publisher: Callable[..., atomic_publish.PublishedArtifactObservation],
    lease_assertion: Callable[[], None] | None = None,
) -> DeploymentSnapshotArtifacts:
    assert_lease = lease_assertion or (lambda: None)

    def publish(
        relative_path: str, payload: bytes
    ) -> atomic_publish.PublishedArtifactObservation:
        assert_lease()
        try:
            return publisher(
                root=Path(str(durable_root)),
                relative_path=relative_path,
                payload=payload,
            )
        finally:
            assert_lease()

    published: list[atomic_publish.PublishedArtifactObservation] = []
    for relative, raw in zip(
        OBSERVATION_RELATIVE_PATHS, artifacts.observation_bytes, strict=True
    ):
        published.append(publish(relative, raw))
    published.append(
        publish(SNAPSHOT_RELATIVE_PATH, artifacts.deployment_snapshot_bytes)
    )
    return replace(artifacts, published_artifacts=tuple(published))


def capture_and_publish_production_deployment_snapshot(
    *,
    source_commit: str,
    attempt_id: str,
    checkout_root: str,
    durable_root: str,
    source_paths_by_role: Mapping[str, object],
    asset_roots_by_role: Mapping[str, object],
) -> DeploymentSnapshotArtifacts:
    """Production-only lease-held capture and atomic publication entry point."""

    if os.geteuid() != CAPTURE_SERVICE_UID or os.getegid() != CAPTURE_SERVICE_GID:
        raise DeploymentSnapshotError("production capture service identity differs")
    expected_checkout = _expected_checkout(source_commit, attempt_id)
    expected_durable = PurePosixPath(
        DURABLE_BASE, source_commit, "attempts", attempt_id
    )
    if _absolute(checkout_root, "checkout_root") != expected_checkout:
        raise DeploymentSnapshotError("checkout_root is not the exact production root")
    if _absolute(durable_root, "durable_root") != expected_durable:
        raise DeploymentSnapshotError("durable_root is not the exact production root")
    runtime = DeploymentSnapshotRuntime()
    with _production_capture_lease(
        durable_root=expected_durable,
        source_commit=source_commit,
        attempt_id=attempt_id,
        runtime=runtime,
    ) as (lease_descriptor, lease_raw):
        lease_path = expected_durable / LEASE_RELATIVE_PATH
        lease = _validate_lease_receipt_bytes(
            lease_raw,
            source_commit=source_commit,
            attempt_id=attempt_id,
            lease_path=str(lease_path),
        )

        def assert_lease() -> None:
            _assert_exclusive_lease_held(
                lease_descriptor,
                lease_path=lease_path,
                expected_identity=lease["lease_file_identity"],
            )

        artifacts = _capture_deployment_snapshot_core(
            source_commit=source_commit,
            attempt_id=attempt_id,
            checkout_root=checkout_root,
            source_paths_by_role=source_paths_by_role,
            asset_roots_by_role=asset_roots_by_role,
            lease_descriptor=lease_descriptor,
            lease_receipt_bytes=lease_raw,
            runtime=runtime,
            lease_assertion=assert_lease,
        )
        return _publish_snapshot_artifacts(
            durable_root=expected_durable,
            artifacts=artifacts,
            publisher=atomic_publish.publish_readonly_no_overwrite,
            lease_assertion=assert_lease,
        )


def _capture_and_publish_deployment_snapshot_for_test(
    *,
    checkout_root: str,
    durable_root: str,
    lease_context: Callable[[], Any],
    capture: Callable[[int, bytes], DeploymentSnapshotArtifacts],
    publisher: Callable[..., atomic_publish.PublishedArtifactObservation],
) -> DeploymentSnapshotArtifacts:
    """Private injected harness, deliberately unavailable for production roots."""

    checkout = _absolute(checkout_root, "test checkout_root")
    durable = _absolute(durable_root, "test durable_root")
    if str(checkout).startswith(CHECKOUT_BASE + "/") or str(durable).startswith(
        DURABLE_BASE + "/"
    ):
        raise DeploymentSnapshotError(
            "injected capture helper rejects production root grammar"
        )
    with lease_context() as (lease_descriptor, lease_raw):
        artifacts = capture(lease_descriptor, lease_raw)
        return _publish_snapshot_artifacts(
            durable_root=durable,
            artifacts=artifacts,
            publisher=publisher,
        )


def validate_deployment_snapshot_bytes(
    raw: object,
    *,
    source_inventory_bytes: object,
    asset_inventory_bytes_by_role: Mapping[str, object],
    source_file_bytes_by_role: Mapping[str, object],
    asset_file_bytes_by_role: Mapping[str, Mapping[str, object]],
    execution_contract_bytes: object,
    structured_preregistration_bytes: object,
    git_index_bytes: object,
    lease_receipt_bytes: object,
    observation_bytes: object,
) -> DeploymentSnapshotValidation:
    """Purely reconstruct every snapshot-to-raw-byte content join."""

    snapshot = _object(
        _parse(raw, "deployment_snapshot_bytes"),
        _SNAPSHOT_KEYS,
        "deployment snapshot",
    )
    if (
        snapshot["protocol"] != SNAPSHOT_PROTOCOL
        or type(snapshot["schema_version"]) is not int
        or snapshot["schema_version"] != SCHEMA_VERSION
        or snapshot["status"] != SNAPSHOT_STATUS
        or snapshot["normalized_observations_equal"] is not True
        or snapshot["read_only_mounts_verified"] is not True
        or snapshot["capture_service_uid"] != CAPTURE_SERVICE_UID
        or snapshot["deployment_owner_uid"] != DEPLOYMENT_OWNER_UID
        or snapshot["fresh_consumer_revalidation_required"] is not True
        or snapshot["fresh_consumer_revalidation_available"] is not False
        or snapshot["dgp_generation_authorized"] is not False
        or snapshot["model_calls_authorized"] is not False
        or snapshot["operational_authorization"] is not False
    ):
        raise DeploymentSnapshotError("deployment snapshot contract differs")
    source_commit = snapshot["source_commit"]
    attempt_id = snapshot["attempt_id"]
    if type(source_commit) is not str or type(attempt_id) is not str:
        raise DeploymentSnapshotError("deployment identity types differ")
    expected_checkout = _expected_checkout(source_commit, attempt_id)
    durable_root = PurePosixPath(DURABLE_BASE, source_commit, "attempts", attempt_id)
    lease_path = str(durable_root / LEASE_RELATIVE_PATH)
    lease_raw = lease_receipt_bytes if type(lease_receipt_bytes) is bytes else b""
    lease = _validate_lease_receipt_bytes(
        lease_receipt_bytes,
        source_commit=source_commit,
        attempt_id=attempt_id,
        lease_path=lease_path,
    )
    lease_binding = _object(
        snapshot["deployment_capture_lease"],
        _PATH_BINDING_KEYS,
        "deployment capture lease binding",
    )
    if lease_binding != {
        "path": lease_path,
        "sha256": _sha(lease_raw),
        "size_bytes": len(lease_raw),
    }:
        raise DeploymentSnapshotError("deployment capture lease binding differs")
    if (
        type(observation_bytes) is not tuple
        or len(observation_bytes) != 2
        or any(type(value) is not bytes for value in observation_bytes)
    ):
        raise DeploymentSnapshotError("observation_bytes must be an exact byte pair")
    parsed_observations: list[dict[str, Any]] = []
    observation_bindings = _list(
        snapshot["deployment_observations"], "deployment observation bindings"
    )
    if len(observation_bindings) != 2:
        raise DeploymentSnapshotError("deployment observation binding count differs")
    for index, observation_raw in enumerate(observation_bytes):
        ordinal = index + 1
        observation = _object(
            _parse(observation_raw, f"observation_bytes[{index}]"),
            _OBSERVATION_KEYS,
            f"deployment observation {ordinal}",
        )
        if (
            observation["protocol"] != OBSERVATION_PROTOCOL
            or type(observation["schema_version"]) is not int
            or observation["schema_version"] != SCHEMA_VERSION
            or observation["status"] != "complete_global_observation_non_authorizing"
            or observation["source_commit"] != source_commit
            or observation["attempt_id"] != attempt_id
            or type(observation["ordinal"]) is not int
            or observation["ordinal"] != ordinal
            or observation["model_calls_authorized"] is not False
            or observation["operational_authorization"] is not False
        ):
            raise DeploymentSnapshotError(
                f"deployment observation {ordinal} contract differs"
            )
        _require_utc(
            observation["observed_at_utc"], f"observation {ordinal} observed_at_utc"
        )
        if observation["state_sha256"] != _sha(_canonical(observation["state"])):
            raise DeploymentSnapshotError(
                f"deployment observation {ordinal} state digest differs"
            )
        if observation["observation_sha256"] != _sha(
            _canonical({key: observation[key] for key in _OBSERVATION_UNSIGNED_KEYS})
        ):
            raise DeploymentSnapshotError(
                f"deployment observation {ordinal} self digest differs"
            )
        binding = _object(
            observation_bindings[index],
            _OBSERVATION_BINDING_KEYS,
            f"deployment observation binding {ordinal}",
        )
        if type(binding["ordinal"]) is not int:
            raise DeploymentSnapshotError(
                f"deployment observation binding {ordinal} ordinal differs"
            )
        expected_binding = {
            "ordinal": ordinal,
            "path": str(durable_root / OBSERVATION_RELATIVE_PATHS[index]),
            "sha256": _sha(observation_raw),
            "size_bytes": len(observation_raw),
            "state_sha256": observation["state_sha256"],
        }
        if binding != expected_binding:
            raise DeploymentSnapshotError(
                f"deployment observation {ordinal} binding differs"
            )
        parsed_observations.append(observation)
    if (
        parsed_observations[0]["state"] != parsed_observations[1]["state"]
        or parsed_observations[0]["state_sha256"]
        != parsed_observations[1]["state_sha256"]
        or parsed_observations[0]["observed_at_utc"]
        >= parsed_observations[1]["observed_at_utc"]
    ):
        raise DeploymentSnapshotError("normalized deployment observations differ")
    root = _validate_root_identity(
        snapshot["checkout_root_identity"], "checkout_root_identity"
    )
    if (
        root["path"] != str(expected_checkout)
        or root["mode_octal"] != f"{DEPLOYMENT_DIRECTORY_MODE:04o}"
        or root["owner_uid"] != DEPLOYMENT_OWNER_UID
        or root["owner_gid"] != DEPLOYMENT_OWNER_GID
    ):
        raise DeploymentSnapshotError("checkout root identity differs")
    git = _object(snapshot["git"], _GIT_KEYS, "git")
    git_index_raw = git_index_bytes if type(git_index_bytes) is bytes else b""
    git_index = _parse_git_index(git_index_raw)
    if (
        git["head_matches_source_commit"] is not True
        or git["gitlinks_absent"] is not True
        or git["index_stage_z_sha256"] != _sha(git_index_raw)
        or git["status_clean"] is not True
        or git["untracked_files_absent"] is not True
        or git["submodules_absent"] is not True
        or git["status_porcelain_v1_z_sha256"] != _sha(b"")
        or git["submodule_status_sha256"] != _sha(b"")
    ):
        raise DeploymentSnapshotError("clean Git snapshot predicates differ")

    source_raw = (
        source_inventory_bytes if type(source_inventory_bytes) is bytes else b""
    )
    source_binding = _object(
        snapshot["source_inventory"], _BINDING_KEYS, "source inventory binding"
    )
    if source_binding != {"sha256": _sha(source_raw), "size_bytes": len(source_raw)}:
        raise DeploymentSnapshotError("source inventory raw-byte binding differs")
    source = _object(
        _parse(source_inventory_bytes, "source_inventory_bytes"),
        _SOURCE_KEYS,
        "source inventory",
    )
    if (
        source["protocol"] != SOURCE_INVENTORY_PROTOCOL
        or source["schema_version"] != SCHEMA_VERSION
        or source["source_commit"] != source_commit
        or source["checkout_root"] != str(expected_checkout)
    ):
        raise DeploymentSnapshotError("source inventory identity differs")
    if source["source_inventory_sha256"] != _sha(
        _canonical({key: source[key] for key in _SOURCE_UNSIGNED_KEYS})
    ):
        raise DeploymentSnapshotError("source inventory self digest differs")
    source_inputs = _exact_role_mapping(
        source_file_bytes_by_role, SOURCE_ROLE_IDS, "source_file_bytes_by_role"
    )
    records = _list(source["records"], "source records")
    if len(records) != len(SOURCE_ROLE_IDS):
        raise DeploymentSnapshotError("source record count differs")
    source_bindings: list[tuple[str, str]] = []
    observed_paths: set[str] = set()
    for index, role in enumerate(SOURCE_ROLE_IDS):
        row = _validate_file_record(records[index], f"source[{index}]", role)
        if row["path"] in observed_paths:
            raise DeploymentSnapshotError("distinct source roles share a path")
        observed_paths.add(row["path"])
        expected_path = str(expected_checkout / row["relative_path"])
        if row["path"] != expected_path:
            raise DeploymentSnapshotError(f"source {role} escapes checkout")
        if row["relative_path"] not in git_index:
            raise DeploymentSnapshotError(f"source {role} is absent from Git index")
        source_bytes = source_inputs[role]
        if type(source_bytes) is not bytes or source_bytes.startswith(
            _LFS_POINTER_PREFIX
        ):
            raise DeploymentSnapshotError(f"source {role} raw bytes differ")
        if row["sha256"] != _sha(source_bytes) or row["size_bytes"] != len(
            source_bytes
        ):
            raise DeploymentSnapshotError(f"source {role} content join differs")
        source_bindings.append((role, row["sha256"]))

    asset_inventory_inputs = _exact_role_mapping(
        asset_inventory_bytes_by_role,
        ASSET_ROLE_IDS,
        "asset_inventory_bytes_by_role",
    )
    asset_file_inputs = _exact_role_mapping(
        asset_file_bytes_by_role, ASSET_ROLE_IDS, "asset_file_bytes_by_role"
    )
    asset_binding_rows = _list(snapshot["asset_inventories"], "asset bindings")
    if len(asset_binding_rows) != len(ASSET_ROLE_IDS):
        raise DeploymentSnapshotError("asset binding count differs")
    asset_bindings: list[tuple[str, str]] = []
    asset_roots: set[str] = set()
    for index, role in enumerate(ASSET_ROLE_IDS):
        binding = _object(
            asset_binding_rows[index], _ASSET_BINDING_KEYS, f"asset binding {role}"
        )
        inventory_raw = asset_inventory_inputs[role]
        if type(inventory_raw) is not bytes:
            raise DeploymentSnapshotError(f"asset {role} inventory must be bytes")
        if binding != {
            "role": role,
            "root": binding["root"],
            "sha256": _sha(inventory_raw),
            "size_bytes": len(inventory_raw),
        }:
            raise DeploymentSnapshotError(f"asset {role} binding differs")
        inventory = _object(
            _parse(inventory_raw, f"asset inventory {role}"),
            _ASSET_KEYS,
            f"asset inventory {role}",
        )
        if (
            inventory["protocol"] != ASSET_INVENTORY_PROTOCOL
            or inventory["schema_version"] != SCHEMA_VERSION
            or inventory["source_commit"] != source_commit
            or inventory["attempt_id"] != attempt_id
            or inventory["role"] != role
        ):
            raise DeploymentSnapshotError(f"asset {role} identity differs")
        if inventory["asset_inventory_sha256"] != _sha(
            _canonical({key: inventory[key] for key in _ASSET_UNSIGNED_KEYS})
        ):
            raise DeploymentSnapshotError(f"asset {role} self digest differs")
        identity = _validate_root_identity(
            inventory["root_identity"], f"asset {role} root_identity"
        )
        if (
            binding["root"] != identity["path"]
            or binding["root"] in asset_roots
            or identity["mode_octal"] != f"{DEPLOYMENT_DIRECTORY_MODE:04o}"
            or identity["owner_uid"] != DEPLOYMENT_OWNER_UID
            or identity["owner_gid"] != DEPLOYMENT_OWNER_GID
        ):
            raise DeploymentSnapshotError(f"asset {role} root alias differs")
        asset_roots.add(binding["root"])
        file_map = asset_file_inputs[role]
        if not isinstance(file_map, Mapping):
            raise DeploymentSnapshotError(f"asset {role} file map differs")
        files = _list(inventory["files"], f"asset {role} files")
        if inventory["file_count"] != len(files) or len(files) == 0:
            raise DeploymentSnapshotError(f"asset {role} file count differs")
        expected_relatives = []
        for file_index, value in enumerate(files):
            row = _validate_file_record(value, f"asset {role}[{file_index}]", role)
            relative = row["relative_path"]
            expected_relatives.append(relative)
            if row["path"] != str(PurePosixPath(binding["root"], relative)):
                raise DeploymentSnapshotError(f"asset {role} file path differs")
            if relative not in file_map or type(file_map[relative]) is not bytes:
                raise DeploymentSnapshotError(f"asset {role} raw file is missing")
            file_raw = file_map[relative]
            if file_raw.startswith(_LFS_POINTER_PREFIX):
                raise DeploymentSnapshotError(f"asset {role} has an LFS pointer")
            if row["sha256"] != _sha(file_raw) or row["size_bytes"] != len(file_raw):
                raise DeploymentSnapshotError(f"asset {role} content join differs")
        if expected_relatives != sorted(expected_relatives) or set(file_map) != set(
            expected_relatives
        ):
            raise DeploymentSnapshotError(f"asset {role} closed inventory differs")
        asset_bindings.append((role, binding["sha256"]))

    controls = _list(snapshot["control_documents"], "control documents")
    if len(controls) != len(CONTROL_DOCUMENT_RELATIVE_PATHS):
        raise DeploymentSnapshotError("control document count differs")
    control_raw = {
        "execution_contract": execution_contract_bytes,
        "structured_preregistration": structured_preregistration_bytes,
    }
    for index, (document_id, relative) in enumerate(
        sorted(CONTROL_DOCUMENT_RELATIVE_PATHS.items())
    ):
        row = _object(
            controls[index], _CONTROL_BINDING_KEYS, f"control document {document_id}"
        )
        document_raw = control_raw[document_id]
        if type(document_raw) is not bytes:
            raise DeploymentSnapshotError(f"{document_id} must be exact bytes")
        expected = {
            "document_id": document_id,
            "path": str(expected_checkout / relative),
            "relative_path": relative,
            "sha256": _sha(document_raw),
            "size_bytes": len(document_raw),
        }
        if row != expected or document_raw.startswith(_LFS_POINTER_PREFIX):
            raise DeploymentSnapshotError(f"{document_id} raw-byte join differs")
        if relative not in git_index:
            raise DeploymentSnapshotError(f"{document_id} is absent from Git index")

    for observation in parsed_observations:
        _validate_observation_state(
            observation["state"],
            lease_raw=lease_raw,
            lease=lease,
            source_commit=source_commit,
            checkout_root=expected_checkout,
            snapshot_checkout_identity=root,
            git_index_raw=git_index_raw,
            source_inventory=source,
            source_file_bytes_by_role=source_inputs,
            asset_inventory_bytes_by_role=asset_inventory_inputs,
            asset_file_bytes_by_role=asset_file_inputs,
            execution_contract_bytes=execution_contract_bytes,
            structured_preregistration_bytes=structured_preregistration_bytes,
        )

    if snapshot["deployment_snapshot_sha256"] != _sha(
        _canonical({key: snapshot[key] for key in _SNAPSHOT_UNSIGNED_KEYS})
    ):
        raise DeploymentSnapshotError("deployment snapshot self digest differs")
    return DeploymentSnapshotValidation(
        source_commit=source_commit,
        attempt_id=attempt_id,
        checkout_root=str(expected_checkout),
        deployment_snapshot_sha256=snapshot["deployment_snapshot_sha256"],
        source_inventory_sha256=source["source_inventory_sha256"],
        source_bindings=tuple(source_bindings),
        asset_inventory_bindings=tuple(asset_bindings),
        execution_contract_sha256=_sha(execution_contract_bytes),
        structured_preregistration_sha256=_sha(structured_preregistration_bytes),
        lease_receipt_sha256=_sha(lease_raw),
        observation_state_sha256=parsed_observations[0]["state_sha256"],
        normalized_observations_equal=True,
        read_only_mounts_verified=True,
        fresh_consumer_revalidation_required=True,
    )
