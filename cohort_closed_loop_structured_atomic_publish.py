"""Anchored, no-replace publication for structured-state control artifacts.

This module provides one low-level filesystem commit primitive.  It does not
parse scientific artifacts, authorize a stage, inspect a process, import a
model or scorer, or prove that a higher-level builder completed.  A readable
artifact observation is never sufficient launch evidence; the enclosing
attempt-wide wrapper and authorization chain must also complete successfully.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


class AtomicPublicationError(RuntimeError):
    """Raised when an anchored publication or fresh observation fails closed."""


INTENT_PROTOCOL = "cohort_structured_atomic_publication_intent_v1"
INTENT_SCHEMA_VERSION = 1
_SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,254}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_REQUIRED_OS_FLAGS = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
if any(not hasattr(os, name) for name in _REQUIRED_OS_FLAGS):
    raise RuntimeError(
        "anchored publication requires O_CLOEXEC, O_DIRECTORY, and O_NOFOLLOW"
    )
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_DIRECTORY_FLAGS = _READ_FLAGS | os.O_DIRECTORY
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
_INTENT_KEYS = frozenset(
    {
        "artifact_relative_path",
        "artifact_sha256",
        "artifact_size_bytes",
        "pending_name",
        "protocol",
        "schema_version",
    }
)


@dataclass(frozen=True, slots=True)
class PublishedArtifactObservation:
    """An in-process observation, never a stand-alone authority token."""

    path: str
    relative_path: str
    publication_intent_path: str
    directory_chain: tuple[tuple[int, int], ...]
    size_bytes: int
    sha256: str
    device: int
    inode: int
    mode: int
    link_count: int
    uid: int
    gid: int
    mtime_ns: int
    ctime_ns: int
    publication_intent_size_bytes: int
    publication_intent_sha256: str
    publication_intent_device: int
    publication_intent_inode: int
    publication_intent_mode: int
    publication_intent_link_count: int
    publication_intent_uid: int
    publication_intent_gid: int
    publication_intent_mtime_ns: int
    publication_intent_ctime_ns: int


@dataclass(frozen=True, slots=True)
class _ReadObservation:
    payload: bytes
    metadata: os.stat_result
    directory_chain: tuple[tuple[int, int], ...]
    intent_raw: bytes
    intent_metadata: os.stat_result
    intent_name: str


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AtomicPublicationError("publication intent serialization failed") from exc


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AtomicPublicationError(f"duplicate publication-intent key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AtomicPublicationError(f"nonfinite JSON constant is forbidden: {value}")


def _parse_intent(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AtomicPublicationError(
            "publication intent is not canonical JSON"
        ) from exc
    if type(value) is not dict or set(value) != _INTENT_KEYS:
        raise AtomicPublicationError("publication intent exact schema differs")
    if raw != _canonical_bytes(value):
        raise AtomicPublicationError("publication intent bytes are not canonical")
    if (
        type(value["protocol"]) is not str
        or value["protocol"] != INTENT_PROTOCOL
        or type(value["schema_version"]) is not int
        or value["schema_version"] != INTENT_SCHEMA_VERSION
    ):
        raise AtomicPublicationError("publication intent protocol differs")
    if (
        type(value["artifact_relative_path"]) is not str
        or type(value["artifact_size_bytes"]) is not int
        or isinstance(value["artifact_size_bytes"], bool)
        or value["artifact_size_bytes"] <= 0
        or type(value["artifact_sha256"]) is not str
        or _SHA256_RE.fullmatch(value["artifact_sha256"]) is None
        or type(value["pending_name"]) is not str
        or _SAFE_COMPONENT_RE.fullmatch(value["pending_name"]) is None
    ):
        raise AtomicPublicationError("publication intent field type differs")
    return value


def _normalized_root(root: Path) -> Path:
    if not isinstance(root, Path):
        raise AtomicPublicationError("root must be a pathlib.Path")
    if not root.is_absolute():
        raise AtomicPublicationError("root must be absolute")
    normalized = Path(os.path.normpath(os.fspath(root)))
    if normalized != root or normalized == Path("/"):
        raise AtomicPublicationError("root must be normalized and non-root")
    return normalized


def _relative_components(relative_path: str) -> tuple[str, ...]:
    if type(relative_path) is not str or not relative_path:
        raise AtomicPublicationError("relative_path must be a nonempty exact string")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or pure.as_posix() != relative_path:
        raise AtomicPublicationError("relative_path must be normalized POSIX text")
    parts = pure.parts
    if not parts or any(
        part in {"", ".", ".."} or _SAFE_COMPONENT_RE.fullmatch(part) is None
        for part in parts
    ):
        raise AtomicPublicationError("relative_path has an unsafe component")
    return parts


def _require_directory(
    descriptor: int, *, label: str, require_service_boundary: bool
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise AtomicPublicationError(f"{label} is not a directory")
    if require_service_boundary and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise AtomicPublicationError(
            f"{label} is not owned by this service or is group/other writable"
        )
    return metadata


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _open_absolute_directory_without_symlinks(
    path: Path,
) -> tuple[int, os.stat_result, tuple[tuple[int, int], ...]]:
    """Open every absolute-path component with ``O_NOFOLLOW``."""

    current = os.open("/", _DIRECTORY_FLAGS)
    chain: list[tuple[int, int]] = []
    try:
        root_of_fs = _require_directory(
            current, label="filesystem root", require_service_boundary=False
        )
        chain.append(_identity(root_of_fs))
        for component in path.parts[1:]:
            next_descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            metadata = _require_directory(
                next_descriptor,
                label="absolute path ancestor",
                require_service_boundary=False,
            )
            chain.append(_identity(metadata))
            os.close(current)
            current = next_descriptor
        metadata = _require_directory(
            current, label="root", require_service_boundary=True
        )
        return current, metadata, tuple(chain)
    except BaseException:
        os.close(current)
        raise


def _open_parent(
    root_descriptor: int,
    root_metadata: os.stat_result,
    root_chain: tuple[tuple[int, int], ...],
    parent_components: tuple[str, ...],
) -> tuple[int, tuple[tuple[int, int], ...]]:
    current = os.dup(root_descriptor)
    chain = list(root_chain)
    try:
        for component in parent_components:
            next_descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            try:
                metadata = _require_directory(
                    next_descriptor,
                    label="artifact parent",
                    require_service_boundary=True,
                )
                if metadata.st_dev != root_metadata.st_dev:
                    raise AtomicPublicationError(
                        "artifact path crosses a device boundary"
                    )
            except BaseException:
                os.close(next_descriptor)
                raise
            chain.append(_identity(metadata))
            os.close(current)
            current = next_descriptor
        return current, tuple(chain)
    except BaseException:
        os.close(current)
        raise


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise AtomicPublicationError("filesystem write made no progress")
        offset += written


def _read_all(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _validate_regular_metadata(
    metadata: os.stat_result,
    *,
    root_metadata: os.stat_result,
    expected_size: int | None,
    expected_link_count: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise AtomicPublicationError("artifact is not a regular file")
    if metadata.st_uid != os.geteuid():
        raise AtomicPublicationError("artifact is not owned by the publisher service")
    if metadata.st_dev != root_metadata.st_dev:
        raise AtomicPublicationError("artifact is on a different device from its root")
    if metadata.st_nlink != expected_link_count:
        raise AtomicPublicationError(
            f"artifact link count must be exactly {expected_link_count}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o444:
        raise AtomicPublicationError("artifact mode must be exactly 0444")
    if expected_size is not None and metadata.st_size != expected_size:
        raise AtomicPublicationError("artifact size differs from expected bytes")


def _intent_name(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("ascii")).hexdigest()
    return f"publish-intent-{digest}.json"


def _pending_name(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("ascii")).hexdigest()
    return f"publish-pending-{digest}.bin"


def publication_sidecar_relative_paths(relative_path: str) -> tuple[str, str]:
    """Return the prospectively enumerable intent and pending paths.

    ``relative_path`` is always relative to the registered publication root.
    The pending pathname is deterministic and unique to that registered final
    path, while the intent's ``O_EXCL`` creation remains the concurrency
    serialization point.  This lets an upstream stage plan close the complete
    path inventory before any artifact is written.
    """

    components = _relative_components(relative_path)
    parent = "/".join(components[:-1])
    prefix = f"{parent}/" if parent else ""
    return (
        f"{prefix}{_intent_name(relative_path)}",
        f"{prefix}{_pending_name(relative_path)}",
    )


def _intent_bytes(*, relative_path: str, pending_name: str, payload: bytes) -> bytes:
    return _canonical_bytes(
        {
            "artifact_relative_path": relative_path,
            "artifact_sha256": hashlib.sha256(payload).hexdigest(),
            "artifact_size_bytes": len(payload),
            "pending_name": pending_name,
            "protocol": INTENT_PROTOCOL,
            "schema_version": INTENT_SCHEMA_VERSION,
        }
    )


def _open_and_read_regular(
    *,
    parent_descriptor: int,
    name: str,
    root_metadata: os.stat_result,
    expected_size: int | None,
    expected_link_count: int,
) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_descriptor)
    try:
        before = os.fstat(descriptor)
        _validate_regular_metadata(
            before,
            root_metadata=root_metadata,
            expected_size=expected_size,
            expected_link_count=expected_link_count,
        )
        payload = _read_all(descriptor)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_mode",
            "st_nlink",
        )
        if tuple(getattr(before, field) for field in stable_fields) != tuple(
            getattr(after, field) for field in stable_fields
        ):
            raise AtomicPublicationError("artifact metadata changed while reading")
        path_metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if tuple(getattr(after, field) for field in stable_fields) != tuple(
            getattr(path_metadata, field) for field in stable_fields
        ):
            raise AtomicPublicationError("artifact pathname changed while reading")
        return payload, after
    finally:
        os.close(descriptor)


def _pending_absent(parent_descriptor: int, pending_name: str) -> bool:
    try:
        os.stat(pending_name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _read_once(*, root: Path, relative_path: str) -> _ReadObservation:
    components = _relative_components(relative_path)
    root_descriptor, root_metadata, root_chain = (
        _open_absolute_directory_without_symlinks(root)
    )
    parent_descriptor = -1
    try:
        parent_descriptor, directory_chain = _open_parent(
            root_descriptor, root_metadata, root_chain, components[:-1]
        )
        intent_name = _intent_name(relative_path)
        intent_raw, intent_metadata = _open_and_read_regular(
            parent_descriptor=parent_descriptor,
            name=intent_name,
            root_metadata=root_metadata,
            expected_size=None,
            expected_link_count=1,
        )
        intent = _parse_intent(intent_raw)
        if intent["artifact_relative_path"] != relative_path:
            raise AtomicPublicationError("publication intent path differs")
        pending_name = str(intent["pending_name"])
        if pending_name != _pending_name(relative_path):
            raise AtomicPublicationError(
                "publication intent pending path is not the registered path"
            )
        if not _pending_absent(parent_descriptor, pending_name):
            raise AtomicPublicationError("publication pending file still exists")
        payload, metadata = _open_and_read_regular(
            parent_descriptor=parent_descriptor,
            name=components[-1],
            root_metadata=root_metadata,
            expected_size=int(intent["artifact_size_bytes"]),
            expected_link_count=1,
        )
        if hashlib.sha256(payload).hexdigest() != intent["artifact_sha256"]:
            raise AtomicPublicationError(
                "artifact digest differs from publication intent"
            )
        return _ReadObservation(
            payload=payload,
            metadata=metadata,
            directory_chain=directory_chain,
            intent_raw=intent_raw,
            intent_metadata=intent_metadata,
            intent_name=intent_name,
        )
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        os.close(root_descriptor)


def _matching_observations(left: _ReadObservation, right: _ReadObservation) -> bool:
    metadata_fields = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_mode",
        "st_nlink",
    )
    return (
        left.payload == right.payload
        and left.intent_raw == right.intent_raw
        and left.directory_chain == right.directory_chain
        and tuple(getattr(left.metadata, field) for field in metadata_fields)
        == tuple(getattr(right.metadata, field) for field in metadata_fields)
        and tuple(getattr(left.intent_metadata, field) for field in metadata_fields)
        == tuple(getattr(right.intent_metadata, field) for field in metadata_fields)
    )


def read_and_validate_readonly_artifact(
    *,
    root: Path,
    relative_path: str,
    expected_payload: bytes | None = None,
) -> tuple[bytes, PublishedArtifactObservation]:
    """Observe one committed file twice through fresh complete path traversals.

    This validates file and publication-intent shape only.  It cannot prove that
    a higher-level builder or wrapper returned success and is not an authority
    credential by itself.
    """

    root = _normalized_root(root)
    _relative_components(relative_path)
    if expected_payload is not None and type(expected_payload) is not bytes:
        raise AtomicPublicationError("expected_payload must be exact bytes or None")
    try:
        first = _read_once(root=root, relative_path=relative_path)
        second = _read_once(root=root, relative_path=relative_path)
    except AtomicPublicationError:
        raise
    except (OSError, ValueError) as exc:
        raise AtomicPublicationError("anchored artifact observation failed") from exc
    if not _matching_observations(first, second):
        raise AtomicPublicationError(
            "artifact or ancestor chain changed across fresh reads"
        )
    if expected_payload is not None and second.payload != expected_payload:
        raise AtomicPublicationError("artifact bytes differ from expected payload")
    intent_path = (root / relative_path).parent / second.intent_name
    observation = PublishedArtifactObservation(
        path=(root / relative_path).as_posix(),
        relative_path=relative_path,
        publication_intent_path=intent_path.as_posix(),
        directory_chain=second.directory_chain,
        size_bytes=len(second.payload),
        sha256=hashlib.sha256(second.payload).hexdigest(),
        device=second.metadata.st_dev,
        inode=second.metadata.st_ino,
        mode=stat.S_IMODE(second.metadata.st_mode),
        link_count=second.metadata.st_nlink,
        uid=second.metadata.st_uid,
        gid=second.metadata.st_gid,
        mtime_ns=second.metadata.st_mtime_ns,
        ctime_ns=second.metadata.st_ctime_ns,
        publication_intent_size_bytes=len(second.intent_raw),
        publication_intent_sha256=hashlib.sha256(second.intent_raw).hexdigest(),
        publication_intent_device=second.intent_metadata.st_dev,
        publication_intent_inode=second.intent_metadata.st_ino,
        publication_intent_mode=stat.S_IMODE(second.intent_metadata.st_mode),
        publication_intent_link_count=second.intent_metadata.st_nlink,
        publication_intent_uid=second.intent_metadata.st_uid,
        publication_intent_gid=second.intent_metadata.st_gid,
        publication_intent_mtime_ns=second.intent_metadata.st_mtime_ns,
        publication_intent_ctime_ns=second.intent_metadata.st_ctime_ns,
    )
    return second.payload, observation


def _publish_intent(
    *, parent_descriptor: int, intent_name: str, intent_raw: bytes
) -> None:
    descriptor = os.open(intent_name, _CREATE_FLAGS, 0o600, dir_fd=parent_descriptor)
    try:
        _write_all(descriptor, intent_raw)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(parent_descriptor)


def _verify_linked_candidate(
    *,
    root: Path,
    relative_path: str,
    expected_chain: tuple[tuple[int, int], ...],
    expected_intent: bytes,
    expected_payload: bytes,
    pending_name: str,
    expected_inode: tuple[int, int],
) -> None:
    components = _relative_components(relative_path)
    root_descriptor, root_metadata, root_chain = (
        _open_absolute_directory_without_symlinks(root)
    )
    parent_descriptor = -1
    try:
        parent_descriptor, observed_chain = _open_parent(
            root_descriptor, root_metadata, root_chain, components[:-1]
        )
        if observed_chain != expected_chain:
            raise AtomicPublicationError(
                "artifact ancestor chain changed before commit"
            )
        intent_raw, _ = _open_and_read_regular(
            parent_descriptor=parent_descriptor,
            name=_intent_name(relative_path),
            root_metadata=root_metadata,
            expected_size=len(expected_intent),
            expected_link_count=1,
        )
        final_raw, final_metadata = _open_and_read_regular(
            parent_descriptor=parent_descriptor,
            name=components[-1],
            root_metadata=root_metadata,
            expected_size=len(expected_payload),
            expected_link_count=2,
        )
        pending_raw, pending_metadata = _open_and_read_regular(
            parent_descriptor=parent_descriptor,
            name=pending_name,
            root_metadata=root_metadata,
            expected_size=len(expected_payload),
            expected_link_count=2,
        )
        if (
            intent_raw != expected_intent
            or final_raw != expected_payload
            or pending_raw != expected_payload
            or _identity(final_metadata) != expected_inode
            or _identity(pending_metadata) != expected_inode
        ):
            raise AtomicPublicationError("linked publication candidate differs")
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        os.close(root_descriptor)


def publish_readonly_no_overwrite(
    *, root: Path, relative_path: str, payload: bytes
) -> PublishedArtifactObservation:
    """Commit bytes with an O_EXCL intent and atomic no-replace hard link.

    Parent directories must already exist.  An intent reserves the textual
    attempt path.  The final path is linked only after complete file fsync, and
    remains invalid with link count two until the pending name is removed as the
    commit point.  Any pre-commit failure leaves the intent and, when created,
    the pending link as poison; this function never removes them on failure.
    """

    root = _normalized_root(root)
    components = _relative_components(relative_path)
    if type(payload) is not bytes or not payload:
        raise AtomicPublicationError("payload must be nonempty exact bytes")
    intent_name = _intent_name(relative_path)
    pending_name = _pending_name(relative_path)
    intent_raw = _intent_bytes(
        relative_path=relative_path, pending_name=pending_name, payload=payload
    )

    root_descriptor = -1
    parent_descriptor = -1
    try:
        root_descriptor, root_metadata, root_chain = (
            _open_absolute_directory_without_symlinks(root)
        )
        parent_descriptor, directory_chain = _open_parent(
            root_descriptor, root_metadata, root_chain, components[:-1]
        )
    except AtomicPublicationError:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        raise
    except (OSError, ValueError) as exc:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        raise AtomicPublicationError(
            "anchored publication root traversal failed"
        ) from exc

    pending_descriptor = -1
    commit_point_reached = False
    try:
        try:
            _publish_intent(
                parent_descriptor=parent_descriptor,
                intent_name=intent_name,
                intent_raw=intent_raw,
            )
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to reuse publication intent: {root / relative_path}"
            ) from exc

        pending_descriptor = os.open(
            pending_name, _CREATE_FLAGS, 0o600, dir_fd=parent_descriptor
        )
        os.fsync(parent_descriptor)
        _write_all(pending_descriptor, payload)
        os.fsync(pending_descriptor)
        os.fchmod(pending_descriptor, 0o444)
        os.fsync(pending_descriptor)
        pending_metadata = os.fstat(pending_descriptor)
        _validate_regular_metadata(
            pending_metadata,
            root_metadata=root_metadata,
            expected_size=len(payload),
            expected_link_count=1,
        )
        try:
            os.link(
                pending_name,
                components[-1],
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to overwrite artifact: {root / relative_path}"
            ) from exc
        os.fsync(parent_descriptor)
        _verify_linked_candidate(
            root=root,
            relative_path=relative_path,
            expected_chain=directory_chain,
            expected_intent=intent_raw,
            expected_payload=payload,
            pending_name=pending_name,
            expected_inode=_identity(pending_metadata),
        )

        # Removing the pending link is the commit point.  Durably record that
        # removal, then observe the committed pathname twice through fresh root
        # and ancestor traversals.  Never synthesize a success observation from
        # the stale parent descriptor used during publication.
        os.unlink(pending_name, dir_fd=parent_descriptor)
        commit_point_reached = True
        os.fsync(parent_descriptor)
        _, observation = read_and_validate_readonly_artifact(
            root=root,
            relative_path=relative_path,
            expected_payload=payload,
        )
        return observation
    except FileExistsError:
        raise
    except AtomicPublicationError as exc:
        if commit_point_reached:
            raise AtomicPublicationError(
                "artifact publication validation failed after commit"
            ) from exc
        raise
    except (OSError, ValueError) as exc:
        raise AtomicPublicationError(
            "artifact publication failed "
            + ("after commit" if commit_point_reached else "before commit")
        ) from exc
    finally:
        for descriptor in (pending_descriptor, parent_descriptor, root_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    if not commit_point_reached:
                        raise


__all__ = [
    "AtomicPublicationError",
    "INTENT_PROTOCOL",
    "PublishedArtifactObservation",
    "publication_sidecar_relative_paths",
    "publish_readonly_no_overwrite",
    "read_and_validate_readonly_artifact",
]
