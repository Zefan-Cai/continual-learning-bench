"""Fail-closed source freeze inventory for the structured closed loop.

This module contains no experiment-result reader and grants no scientific or
operational authority.  The public production builder and authorizer remain
disabled.  A private test seam can exercise the byte and Git invariants against
an explicit temporary repository without making those helpers production
providers.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Sequence

__all__ = (
    "PROVIDER_AVAILABLE",
    "FreezeInventoryError",
    "FreezeInventoryValidation",
    "authorize_semantic_open",
    "build_freeze_inventory",
    "validate_freeze_inventory_bytes",
)


PROVIDER_AVAILABLE = False
PROTOCOL = "cohort_structured_semantic_open_freeze_inventory_v1"
SCHEMA_VERSION = 1
STATUS = "sealed_non_authorizing_freeze_inventory_scaffold"
REGISTRAR_ROLE = "context_registrar"
REGISTRAR_SOURCE_SUFFIX = "/cohort_closed_loop_structured_context_registrar.py"

_SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ROLE_RE = re.compile(r"[a-z][a-z0-9_]{1,95}\Z")
_AUTHORITY_KEYS = frozenset(
    {
        "semantic_open_authorized",
        "model_calls_authorized",
        "scorer_calls_authorized",
    }
)
_TOP_LEVEL_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "source_commit",
        "structured_tip_commit",
        "semantic_open_authorized",
        "model_calls_authorized",
        "scorer_calls_authorized",
        "documents",
        "sources",
        "tests",
        "joins",
        "providers",
        "blockers",
        "freeze_inventory_sha256",
    }
)
_FILE_ROW_KEYS = frozenset(
    {
        "role",
        "path",
        "git_blob_sha1",
        "sha256",
        "size_bytes",
        "tracked",
        "required_before_semantic_open",
    }
)
_FILE_SPEC_KEYS = frozenset({"role", "path", "required_before_semantic_open"})
_JOIN_KEYS = frozenset(
    {
        "join_id",
        "from_role",
        "to_role",
        "validator_role",
        "bound_fields",
        "test_roles",
        "status",
    }
)
_PROVIDER_KEYS = frozenset(
    {
        "provider_id",
        "status",
        "implementation_role",
        "receipt_protocol",
        "acceptance_test_roles",
    }
)
_BLOCKER_KEYS = frozenset(
    {
        "blocker_id",
        "priority",
        "reason",
        "unblocks",
        "acceptance_checks",
    }
)


class FreezeInventoryError(RuntimeError):
    """Raised when a freeze inventory or its source closure fails closed."""


@dataclass(frozen=True, slots=True)
class FreezeInventoryValidation:
    """Public, outcome-blind validation summary with no authority."""

    source_commit: str
    structured_tip_commit: str
    document_count: int
    source_count: int
    test_count: int
    join_count: int
    provider_count: int
    blocker_count: int
    freeze_inventory_sha256: str
    semantic_open_authorized: bool = False
    model_calls_authorized: bool = False
    scorer_calls_authorized: bool = False


@dataclass(frozen=True, slots=True)
class _FileObservation:
    role: str
    path: str
    required_before_semantic_open: bool
    git_blob_sha1: str
    raw: bytes
    sha256: str
    size_bytes: int
    device: int
    inode: int
    mode: int
    link_count: int
    uid: int
    gid: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True, slots=True)
class _RootObservation:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class _FreezeInventoryTestRuntime:
    """Private mutation seam; production accepts no callback or test root."""

    before_final_revalidation: Callable[[], None]


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FreezeInventoryError("inventory value is not canonical JSON") from exc


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FreezeInventoryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise FreezeInventoryError(f"non-finite JSON number is forbidden: {value}")


def _parse_canonical(raw: object) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise FreezeInventoryError("freeze inventory must be nonempty exact bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except FreezeInventoryError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FreezeInventoryError(
            "freeze inventory is not strict canonical ASCII JSON"
        ) from exc
    if type(value) is not dict or _canonical(value) != raw:
        raise FreezeInventoryError(
            "freeze inventory is not strict canonical ASCII object bytes"
        )
    return value


def _exact_object(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise FreezeInventoryError(f"{label} has a non-exact schema")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _ROLE_RE.fullmatch(value) is None:
        raise FreezeInventoryError(f"{label} is not a canonical identifier")
    return value


def _sha1(value: object, label: str) -> str:
    if type(value) is not str or _SHA1_RE.fullmatch(value) is None:
        raise FreezeInventoryError(f"{label} is not a lowercase Git SHA-1")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise FreezeInventoryError(f"{label} is not a lowercase SHA-256")
    return value


def _relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\x00" in value:
        raise FreezeInventoryError(f"{label} is not relative POSIX text")
    pure = PurePosixPath(value)
    if (
        pure.as_posix() != value
        or posixpath.normpath(value) != value
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise FreezeInventoryError(f"{label} is not normalized relative POSIX text")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if type(value) is not list or any(
        type(item) is not str or not item for item in value
    ):
        raise FreezeInventoryError(f"{label} must be a list of nonempty strings")
    if value != sorted(value) or len(value) != len(set(value)):
        raise FreezeInventoryError(f"{label} must be sorted and unique")
    return value


def _assert_no_true_authority(value: object, label: str = "inventory") -> None:
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise FreezeInventoryError(f"{label} contains a non-string key")
            authority_like = (
                key in _AUTHORITY_KEYS
                or key.endswith("_authorized")
                or key.endswith("_authorization")
                or key.endswith("_authority")
            )
            if authority_like and child is True:
                raise FreezeInventoryError(f"authority field is true: {label}.{key}")
            _assert_no_true_authority(child, f"{label}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _assert_no_true_authority(child, f"{label}[{index}]")


def _validate_file_section(
    value: object, *, label: str
) -> tuple[list[dict[str, object]], list[str], list[str]]:
    if type(value) is not list or not value:
        raise FreezeInventoryError(f"{label} must be a nonempty file inventory")
    rows: list[dict[str, object]] = []
    roles: list[str] = []
    paths: list[str] = []
    for index, raw_row in enumerate(value):
        row = _exact_object(raw_row, _FILE_ROW_KEYS, f"{label}[{index}]")
        role = _identifier(row["role"], f"{label}[{index}].role")
        path = _relative_path(row["path"], f"{label}[{index}].path")
        _sha1(row["git_blob_sha1"], f"{label}[{index}].git_blob_sha1")
        _sha256(row["sha256"], f"{label}[{index}].sha256")
        if type(row["size_bytes"]) is not int or row["size_bytes"] <= 0:
            raise FreezeInventoryError(f"{label}[{index}].size_bytes is invalid")
        if row["tracked"] is not True:
            raise FreezeInventoryError(f"{label}[{index}] is not tracked")
        if type(row["required_before_semantic_open"]) is not bool:
            raise FreezeInventoryError(
                f"{label}[{index}].required_before_semantic_open is not bool"
            )
        rows.append(row)
        roles.append(role)
        paths.append(path)
    if roles != sorted(roles) or len(roles) != len(set(roles)):
        raise FreezeInventoryError(f"{label} roles must be sorted and unique")
    if len(paths) != len(set(paths)):
        raise FreezeInventoryError(f"{label} paths must be unique")
    return rows, roles, paths


def _validate_joins(
    value: object,
    *,
    known_roles: frozenset[str],
    source_roles: frozenset[str],
    test_roles: frozenset[str],
) -> list[dict[str, object]]:
    if type(value) is not list:
        raise FreezeInventoryError("joins must be a list")
    rows: list[dict[str, object]] = []
    ids: list[str] = []
    for index, raw_row in enumerate(value):
        row = _exact_object(raw_row, _JOIN_KEYS, f"joins[{index}]")
        join_id = _identifier(row["join_id"], f"joins[{index}].join_id")
        for key in ("from_role", "to_role"):
            role = _identifier(row[key], f"joins[{index}].{key}")
            if role not in known_roles:
                raise FreezeInventoryError(f"joins[{index}].{key} is not inventoried")
        validator_role = _identifier(
            row["validator_role"], f"joins[{index}].validator_role"
        )
        if validator_role not in source_roles:
            raise FreezeInventoryError(
                f"joins[{index}].validator_role is not a source role"
            )
        _string_list(row["bound_fields"], f"joins[{index}].bound_fields")
        joined_test_roles = _string_list(
            row["test_roles"], f"joins[{index}].test_roles"
        )
        if any(role not in test_roles for role in joined_test_roles):
            raise FreezeInventoryError(f"joins[{index}] test role is not in tests")
        if type(row["status"]) is not str or row["status"] not in {
            "committed",
            "synthetic_only",
            "missing",
        }:
            raise FreezeInventoryError(f"joins[{index}].status is invalid")
        ids.append(join_id)
        rows.append(row)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise FreezeInventoryError("join IDs must be sorted and unique")
    return rows


def _validate_providers(
    value: object,
    *,
    source_roles: frozenset[str],
    test_roles: frozenset[str],
) -> list[dict[str, object]]:
    if type(value) is not list:
        raise FreezeInventoryError("providers must be a list")
    rows: list[dict[str, object]] = []
    ids: list[str] = []
    for index, raw_row in enumerate(value):
        row = _exact_object(raw_row, _PROVIDER_KEYS, f"providers[{index}]")
        provider_id = _identifier(row["provider_id"], f"providers[{index}].provider_id")
        if type(row["status"]) is not str or row["status"] not in {
            "unavailable",
            "test_only",
            "implemented_non_authorizing",
        }:
            raise FreezeInventoryError(f"providers[{index}].status is invalid")
        implementation = row["implementation_role"]
        if implementation is not None:
            implementation = _identifier(
                implementation, f"providers[{index}].implementation_role"
            )
            if implementation not in source_roles:
                raise FreezeInventoryError(
                    f"providers[{index}].implementation_role is not a source role"
                )
        if row["status"] == "unavailable" and implementation is not None:
            raise FreezeInventoryError(
                "an unavailable provider cannot claim an implementation role"
            )
        if type(row["receipt_protocol"]) is not str or not row["receipt_protocol"]:
            raise FreezeInventoryError(
                f"providers[{index}].receipt_protocol is invalid"
            )
        acceptance_test_roles = _string_list(
            row["acceptance_test_roles"],
            f"providers[{index}].acceptance_test_roles",
        )
        if any(role not in test_roles for role in acceptance_test_roles):
            raise FreezeInventoryError(
                f"providers[{index}] acceptance test role is not in tests"
            )
        ids.append(provider_id)
        rows.append(row)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise FreezeInventoryError("provider IDs must be sorted and unique")
    return rows


def _validate_blockers(value: object) -> list[dict[str, object]]:
    if type(value) is not list:
        raise FreezeInventoryError("blockers must be a list")
    rows: list[dict[str, object]] = []
    ids: list[str] = []
    for index, raw_row in enumerate(value):
        row = _exact_object(raw_row, _BLOCKER_KEYS, f"blockers[{index}]")
        blocker_id = _identifier(row["blocker_id"], f"blockers[{index}].blocker_id")
        if type(row["priority"]) is not str or row["priority"] not in {"P0", "P1"}:
            raise FreezeInventoryError(f"blockers[{index}].priority is invalid")
        if type(row["reason"]) is not str or not row["reason"]:
            raise FreezeInventoryError(f"blockers[{index}].reason is invalid")
        _string_list(row["unblocks"], f"blockers[{index}].unblocks")
        _string_list(row["acceptance_checks"], f"blockers[{index}].acceptance_checks")
        ids.append(blocker_id)
        rows.append(row)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise FreezeInventoryError("blocker IDs must be sorted and unique")
    return rows


def validate_freeze_inventory_bytes(raw: bytes) -> FreezeInventoryValidation:
    """Validate exact public bytes without filesystem or result access."""

    payload = _exact_object(_parse_canonical(raw), _TOP_LEVEL_KEYS, "inventory")
    if (
        payload["protocol"] != PROTOCOL
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["status"] != STATUS
    ):
        raise FreezeInventoryError("freeze inventory header differs")
    source_commit = _sha1(payload["source_commit"], "source_commit")
    structured_tip = _sha1(payload["structured_tip_commit"], "structured_tip_commit")
    for key in sorted(_AUTHORITY_KEYS):
        if payload[key] is not False:
            raise FreezeInventoryError(f"{key} must be exactly false")
    _assert_no_true_authority(payload)

    documents, document_roles, document_paths = _validate_file_section(
        payload["documents"], label="documents"
    )
    sources, source_roles, source_paths = _validate_file_section(
        payload["sources"], label="sources"
    )
    tests, test_roles, test_paths = _validate_file_section(
        payload["tests"], label="tests"
    )
    all_roles = document_roles + source_roles + test_roles
    all_paths = document_paths + source_paths + test_paths
    if len(all_roles) != len(set(all_roles)):
        raise FreezeInventoryError("file roles must be globally unique")
    if len(all_paths) != len(set(all_paths)):
        raise FreezeInventoryError("file paths must be globally unique")
    if REGISTRAR_ROLE not in source_roles:
        raise FreezeInventoryError("required context registrar source is missing")
    registrar = sources[source_roles.index(REGISTRAR_ROLE)]
    if (
        not str(registrar["path"]).endswith(REGISTRAR_SOURCE_SUFFIX)
        and registrar["path"] != REGISTRAR_SOURCE_SUFFIX.removeprefix("/")
    ) or registrar["required_before_semantic_open"] is not True:
        raise FreezeInventoryError("context registrar source binding differs")

    known_roles = frozenset(all_roles)
    source_role_set = frozenset(source_roles)
    test_role_set = frozenset(test_roles)
    joins = _validate_joins(
        payload["joins"],
        known_roles=known_roles,
        source_roles=source_role_set,
        test_roles=test_role_set,
    )
    providers = _validate_providers(
        payload["providers"],
        source_roles=source_role_set,
        test_roles=test_role_set,
    )
    blockers = _validate_blockers(payload["blockers"])

    embedded = _sha256(payload["freeze_inventory_sha256"], "freeze_inventory_sha256")
    unsigned = dict(payload)
    del unsigned["freeze_inventory_sha256"]
    if embedded != hashlib.sha256(_canonical(unsigned)).hexdigest():
        raise FreezeInventoryError("freeze inventory self-digest differs")
    return FreezeInventoryValidation(
        source_commit=source_commit,
        structured_tip_commit=structured_tip,
        document_count=len(documents),
        source_count=len(sources),
        test_count=len(tests),
        join_count=len(joins),
        provider_count=len(providers),
        blocker_count=len(blockers),
        freeze_inventory_sha256=embedded,
    )


def build_freeze_inventory(
    *, git_root: Path, source_commit: str, structured_tip_commit: str
) -> bytes:
    """Production builder remains unavailable and accepts no private seam."""

    del git_root, source_commit, structured_tip_commit
    raise FreezeInventoryError(
        "production freeze-inventory provider is unavailable; committed source-role "
        "resolution and independent deployment capture are required"
    )


def authorize_semantic_open(*, inventory_bytes: bytes) -> None:
    """A freeze inventory is never itself semantic-opening authority."""

    del inventory_bytes
    raise FreezeInventoryError(
        "freeze inventory is non-authorizing; semantic opening provider is unavailable"
    )


def _git(root: Path, arguments: Sequence[str], *, allow_failure: bool = False) -> bytes:
    completed = subprocess.run(
        ["git", "-C", os.fspath(root), *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0 and not allow_failure:
        raise FreezeInventoryError("test Git repository query failed")
    return completed.stdout


def _clean_test_git_root(
    root: object, *, source_commit: object, structured_tip_commit: object
) -> tuple[Path, str, str]:
    if not isinstance(root, Path) or not root.is_absolute():
        raise FreezeInventoryError("test Git root must be an absolute pathlib.Path")
    normalized = Path(os.path.normpath(os.fspath(root)))
    if normalized != root or root == Path("/"):
        raise FreezeInventoryError("test Git root must be normalized and non-root")
    try:
        root_lstat = os.lstat(root)
    except OSError as exc:
        raise FreezeInventoryError("test Git root is unavailable") from exc
    if not stat.S_ISDIR(root_lstat.st_mode):
        raise FreezeInventoryError("test Git root must be a non-symlink directory")
    head = _sha1(source_commit, "test source_commit")
    tip = _sha1(structured_tip_commit, "test structured_tip_commit")
    try:
        top = _git(root, ("rev-parse", "--show-toplevel")).decode("utf-8").strip()
        current = _git(root, ("rev-parse", "HEAD")).decode("ascii").strip()
    except UnicodeError as exc:
        raise FreezeInventoryError("test Git identity is not canonical text") from exc
    if top != root.as_posix() or current != head:
        raise FreezeInventoryError("test Git root or pinned HEAD differs")
    if _git(root, ("status", "--porcelain=v1", "--untracked-files=all")):
        raise FreezeInventoryError("test Git worktree is dirty or has untracked files")
    if _git(
        root,
        ("ls-files", "-z", "--others", "--ignored", "--exclude-standard"),
    ):
        raise FreezeInventoryError("test Git worktree has ignored untracked files")
    if (
        subprocess.run(
            ["git", "-C", os.fspath(root), "cat-file", "-e", f"{tip}^{{commit}}"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        != 0
    ):
        raise FreezeInventoryError("structured tip is not a committed Git object")
    if (
        subprocess.run(
            ["git", "-C", os.fspath(root), "merge-base", "--is-ancestor", tip, head],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        != 0
    ):
        raise FreezeInventoryError("structured tip is not an ancestor of pinned HEAD")
    return root, head, tip


def _root_observation(metadata: os.stat_result) -> _RootObservation:
    return _RootObservation(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _validate_retained_root(
    *, root: Path, descriptor: int, expected: _RootObservation
) -> None:
    try:
        retained = os.fstat(descriptor)
        path_metadata = os.stat(root, follow_symlinks=False)
        reopened_descriptor = os.open(
            root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            reopened = os.fstat(reopened_descriptor)
        finally:
            os.close(reopened_descriptor)
    except OSError as exc:
        raise FreezeInventoryError("test Git root identity changed") from exc
    if any(
        _root_observation(item) != expected
        for item in (retained, path_metadata, reopened)
    ):
        raise FreezeInventoryError("test Git root identity changed")


def _open_parent(root_descriptor: int, path: str) -> tuple[int, str]:
    pure = PurePosixPath(path)
    descriptor = os.dup(root_descriptor)
    try:
        for component in pure.parts[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, pure.name
    except BaseException:
        os.close(descriptor)
        raise


def _git_blob(root: Path, *, head: str, path: str) -> tuple[str, bytes]:
    raw_tree = _git(root, ("ls-tree", "-z", head, "--", path))
    rows = [row for row in raw_tree.split(b"\x00") if row]
    if len(rows) != 1 or b"\t" not in rows[0]:
        raise FreezeInventoryError("required file is not uniquely tracked at HEAD")
    header, registered_path = rows[0].split(b"\t", 1)
    try:
        mode, kind, blob_raw = header.decode("ascii").split(" ")
        registered_text = registered_path.decode("utf-8")
    except (UnicodeError, ValueError) as exc:
        raise FreezeInventoryError("Git tree record is malformed") from exc
    blob = _sha1(blob_raw, "Git blob SHA-1")
    if mode not in {"100644", "100755"} or kind != "blob" or registered_text != path:
        raise FreezeInventoryError("required file is not a regular tracked Git blob")
    raw = _git(root, ("cat-file", "blob", blob))
    return blob, raw


def _capture_file(
    *,
    root: Path,
    root_descriptor: int,
    head: str,
    spec: Mapping[str, object],
) -> _FileObservation:
    row = _exact_object(spec, _FILE_SPEC_KEYS, "file specification")
    role = _identifier(row["role"], "file specification role")
    path = _relative_path(row["path"], "file specification path")
    required = row["required_before_semantic_open"]
    if type(required) is not bool:
        raise FreezeInventoryError("file required flag is not bool")
    blob, blob_raw = _git_blob(root, head=head, path=path)
    parent_descriptor, name = _open_parent(root_descriptor, path)
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            before = os.fstat(descriptor)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor)
            path_metadata = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False
            )
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise FreezeInventoryError(
            "required file cannot be opened without links"
        ) from exc
    finally:
        os.close(parent_descriptor)
    stable = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        tuple(getattr(before, key) for key in stable)
        != tuple(getattr(after, key) for key in stable)
        or tuple(getattr(after, key) for key in stable)
        != tuple(getattr(path_metadata, key) for key in stable)
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
    ):
        raise FreezeInventoryError("required file identity or link count differs")
    raw = b"".join(chunks)
    if not raw or raw != blob_raw:
        raise FreezeInventoryError(
            "required file bytes differ from the pinned Git blob"
        )
    return _FileObservation(
        role=role,
        path=path,
        required_before_semantic_open=required,
        git_blob_sha1=blob,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        device=after.st_dev,
        inode=after.st_ino,
        mode=stat.S_IMODE(after.st_mode),
        link_count=after.st_nlink,
        uid=after.st_uid,
        gid=after.st_gid,
        mtime_ns=after.st_mtime_ns,
        ctime_ns=after.st_ctime_ns,
    )


def _snapshot_rows(value: Sequence[Mapping[str, object]], label: str) -> list[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise FreezeInventoryError(f"{label} must be an explicit sequence")
    try:
        encoded = _canonical(list(value))
        decoded = json.loads(
            encoded.decode("ascii"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except FreezeInventoryError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FreezeInventoryError(f"{label} cannot be snapshotted") from exc
    if type(decoded) is not list:
        raise FreezeInventoryError(f"{label} snapshot differs")
    return decoded


def _file_row(observation: _FileObservation) -> dict[str, object]:
    return {
        "git_blob_sha1": observation.git_blob_sha1,
        "path": observation.path,
        "required_before_semantic_open": observation.required_before_semantic_open,
        "role": observation.role,
        "sha256": observation.sha256,
        "size_bytes": observation.size_bytes,
        "tracked": True,
    }


def _build_freeze_inventory_for_test(
    *,
    git_root: Path,
    source_commit: str,
    structured_tip_commit: str,
    documents: Sequence[Mapping[str, object]],
    sources: Sequence[Mapping[str, object]],
    tests: Sequence[Mapping[str, object]],
    joins: Sequence[Mapping[str, object]],
    providers: Sequence[Mapping[str, object]],
    blockers: Sequence[Mapping[str, object]],
    runtime: _FreezeInventoryTestRuntime,
) -> bytes:
    """Build deterministic bytes only against an explicit clean test Git root."""

    if not isinstance(runtime, _FreezeInventoryTestRuntime):
        raise FreezeInventoryError("runtime must be the private inventory test seam")
    root, head, tip = _clean_test_git_root(
        git_root,
        source_commit=source_commit,
        structured_tip_commit=structured_tip_commit,
    )
    section_specs = {
        "documents": _snapshot_rows(documents, "documents"),
        "sources": _snapshot_rows(sources, "sources"),
        "tests": _snapshot_rows(tests, "tests"),
    }
    join_rows = _snapshot_rows(joins, "joins")
    provider_rows = _snapshot_rows(providers, "providers")
    blocker_rows = _snapshot_rows(blockers, "blockers")
    flat_specs = [spec for rows in section_specs.values() for spec in rows]
    spec_roles: list[str] = []
    spec_paths: list[str] = []
    for spec in flat_specs:
        row = _exact_object(spec, _FILE_SPEC_KEYS, "file specification")
        spec_roles.append(_identifier(row["role"], "file specification role"))
        spec_paths.append(_relative_path(row["path"], "file specification path"))
    if len(spec_roles) != len(set(spec_roles)):
        raise FreezeInventoryError("file specification roles are not globally unique")
    if len(spec_paths) != len(set(spec_paths)):
        raise FreezeInventoryError("file specification paths are not globally unique")
    source_specs = section_specs["sources"]
    registrar_specs = [
        row
        for row in source_specs
        if type(row) is dict and row.get("role") == REGISTRAR_ROLE
    ]
    if len(registrar_specs) != 1:
        raise FreezeInventoryError("required context registrar source is missing")
    if registrar_specs[0].get("required_before_semantic_open") is not True:
        raise FreezeInventoryError("context registrar must be required before opening")

    root_descriptor = os.open(
        root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    initial_root = _root_observation(os.fstat(root_descriptor))
    try:
        _validate_retained_root(
            root=root, descriptor=root_descriptor, expected=initial_root
        )
        captured_by_section: dict[str, tuple[_FileObservation, ...]] = {}
        for section, specs in section_specs.items():
            captured_by_section[section] = tuple(
                sorted(
                    (
                        _capture_file(
                            root=root,
                            root_descriptor=root_descriptor,
                            head=head,
                            spec=spec,
                        )
                        for spec in specs
                    ),
                    key=lambda observation: observation.role,
                )
            )
        runtime.before_final_revalidation()
        root, final_head, final_tip = _clean_test_git_root(
            root,
            source_commit=head,
            structured_tip_commit=tip,
        )
        if final_head != head or final_tip != tip:
            raise FreezeInventoryError("pinned Git commits changed")
        _validate_retained_root(
            root=root, descriptor=root_descriptor, expected=initial_root
        )
        for section, specs in section_specs.items():
            second = tuple(
                sorted(
                    (
                        _capture_file(
                            root=root,
                            root_descriptor=root_descriptor,
                            head=head,
                            spec=spec,
                        )
                        for spec in specs
                    ),
                    key=lambda observation: observation.role,
                )
            )
            if second != captured_by_section[section]:
                raise FreezeInventoryError(
                    "required file identity changed during final revalidation"
                )
        final_root, terminal_head, terminal_tip = _clean_test_git_root(
            root,
            source_commit=head,
            structured_tip_commit=tip,
        )
        if final_root != root or terminal_head != head or terminal_tip != tip:
            raise FreezeInventoryError("terminal pinned Git identity changed")
        _validate_retained_root(
            root=root, descriptor=root_descriptor, expected=initial_root
        )
    except FreezeInventoryError:
        raise
    except OSError as exc:
        raise FreezeInventoryError(
            "test source inventory filesystem check failed"
        ) from exc
    finally:
        os.close(root_descriptor)

    payload: dict[str, object] = {
        "blockers": blocker_rows,
        "documents": [_file_row(row) for row in captured_by_section["documents"]],
        "joins": join_rows,
        "model_calls_authorized": False,
        "protocol": PROTOCOL,
        "providers": provider_rows,
        "schema_version": SCHEMA_VERSION,
        "scorer_calls_authorized": False,
        "semantic_open_authorized": False,
        "source_commit": head,
        "sources": [_file_row(row) for row in captured_by_section["sources"]],
        "status": STATUS,
        "structured_tip_commit": tip,
        "tests": [_file_row(row) for row in captured_by_section["tests"]],
    }
    payload["freeze_inventory_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    raw = _canonical(payload)
    validate_freeze_inventory_bytes(raw)
    return raw
