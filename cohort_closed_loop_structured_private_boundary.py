"""Two-stage private-context access-boundary attestations for structured TTT-RL.

The registration stage proves a dedicated read-write mount on which only the
registrar can create and remove a synthetic, non-secret probe.  The scorer and
independent private validator can read that exact probe while the launcher and
operator cannot read it or enumerate the root.  The probe is removed and an
``ENOENT`` receipt proves that it did not remain in the registry.

The sealed-prelaunch stage is a distinct protocol and schema.  It binds the
initial attestation and an exact registry-completion receipt, requires the same
registry to have been remounted read-only, repeats the positive and negative
read tests, and proves that the registrar can no longer create or open a record
for writing.  Only this second stage has a 60-second freshness statement.

Neither stage exposes hidden record bytes or grants DGP, model, scorer, launch,
or operational authority.  Production entry points have no injectable runtime;
the private test helper rejects production-root grammar before filesystem I/O.
"""

from __future__ import annotations

import errno
import ctypes
import hashlib
import grp
import json
import os
import posixpath
import pwd
import re
import select
import signal
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from cohort_closed_loop_structured_atomic_publish import (
    AtomicPublicationError,
    PublishedArtifactObservation,
    publication_sidecar_relative_paths,
    publish_readonly_no_overwrite,
    read_and_validate_readonly_artifact,
)

__all__ = (
    "ATTESTER_SERVICE_IDENTITY",
    "ATTESTER_UID",
    "INITIAL_PRIVATE_PROBE_IDS",
    "INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH",
    "LAUNCHER_UID",
    "OPERATOR_UID",
    "PRIVATE_READ_GID",
    "PRIVATE_VALIDATOR_UID",
    "PURE_SCORER_UID",
    "REGISTRAR_UID",
    "SEALED_PRIVATE_PROBE_IDS",
    "SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH",
    "REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH",
    "PrivateBoundaryArtifacts",
    "PrivateBoundaryError",
    "PrivateBoundaryValidation",
    "attest_initial_registration_boundary",
    "attest_sealed_prelaunch_boundary",
    "validate_initial_registration_boundary_bytes",
    "validate_sealed_prelaunch_boundary_bytes",
)


class PrivateBoundaryError(RuntimeError):
    """Raised when an exact private-context boundary proof fails closed."""


INITIAL_REGISTRATION_STAGE = "initial_registration_boundary"
SEALED_PRELAUNCH_STAGE = "sealed_prelaunch_boundary"
INITIAL_REGISTRATION_PROTOCOL = (
    "cohort_structured_private_context_initial_registration_boundary_v1"
)
SEALED_PRELAUNCH_PROTOCOL = (
    "cohort_structured_private_context_sealed_prelaunch_boundary_v2"
)
REGISTRY_COMPLETION_PROTOCOL = (
    "cohort_structured_private_context_registry_completion_receipt_v2"
)
INITIAL_ACCESS_PROBE_PROTOCOL = (
    "cohort_structured_private_context_initial_access_probe_v1"
)
SEALED_ACCESS_PROBE_PROTOCOL = (
    "cohort_structured_private_context_sealed_access_probe_v1"
)
INITIAL_SCHEMA_VERSION = 1
SEALED_SCHEMA_VERSION = 2
REGISTRY_COMPLETION_SCHEMA_VERSION = 2
PROBE_SCHEMA_VERSION = 1
INITIAL_STATUS = "initial_registration_boundary_attested_non_authorizing"
SEALED_STATUS = "sealed_prelaunch_boundary_attested_non_authorizing"
REGISTRY_COMPLETION_STATUS = "private_registry_complete_non_authorizing"
MAX_FRESH_SECONDS = 60

ATTESTER_UID = 41001
REGISTRAR_UID = 41011
PURE_SCORER_UID = 41012
PRIVATE_VALIDATOR_UID = 41013
LAUNCHER_UID = 41014
OPERATOR_UID = 41015
PRIVATE_READ_GID = 41016

ATTESTER_SERVICE_IDENTITY = "cohort-structured-private-boundary-v1"
REGISTRAR_SERVICE_IDENTITY = "cohort-structured-context-registrar-v1"
PURE_SCORER_SERVICE_IDENTITY = "cohort-structured-pure-scorer-v1"
PRIVATE_VALIDATOR_SERVICE_IDENTITY = "cohort-structured-private-validator-v1"
LAUNCHER_SERVICE_IDENTITY = "cohort-structured-launcher-v1"
OPERATOR_SERVICE_IDENTITY = "cohort-structured-operator-v1"

INITIAL_PRIVATE_PROBE_IDS: tuple[str, ...] = (
    "01_registrar_create_probe",
    "02_registrar_read_probe",
    "03_private_validator_read_probe",
    "04_private_validator_write_denied",
    "05_private_validator_create_denied",
    "06_scorer_read_probe",
    "07_scorer_write_denied",
    "08_scorer_create_denied",
    "09_launcher_enumerate",
    "10_launcher_read_probe",
    "11_operator_enumerate",
    "12_operator_read_probe",
    "13_registrar_remove_probe",
    "14_registrar_verify_no_leftover",
)
SEALED_PRIVATE_PROBE_IDS: tuple[str, ...] = (
    "01_private_validator_read_record",
    "02_scorer_read_record",
    "03_registrar_read_record",
    "04_launcher_enumerate",
    "05_launcher_read_record",
    "06_operator_enumerate",
    "07_operator_read_record",
    "08_registrar_create_denied",
    "09_registrar_write_denied",
)

SETUID_ADAPTER_PATH = Path(
    "/usr/local/libexec/cohort-structured-private-context-access-probe"
)
INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH = (
    "control/private_boundary/initial/attestation.json"
)
SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH = (
    "control/private_boundary/sealed/attestation.json"
)
REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH = (
    "control/private_boundary/registry/registry_completion.v2.json"
)
_TRANSIENT_PROBE_RELATIVE_PATH = ".private-boundary-registration-probe"

_PRODUCTION_PUBLIC_PREFIX = (
    "/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state"
)
_PRODUCTION_PRIVATE_PREFIX = (
    "/sensei-fs/private/zcai/TTT-RL/cohort-closed-loop-structured-state"
)

_PRODUCTION_PUBLIC_RE = re.compile(
    r"/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
    r"(?P<commit>[0-9a-f]{40})/attempts/(?P<experiment>attempt-[0-9]{3})/"
    r"stages/(?P<stage_kind>[a-z][a-z0-9-]{0,63})/"
    r"(?P<stage_attempt>attempt-[0-9]{3})\Z"
)
_PRODUCTION_PRIVATE_RE = re.compile(
    r"/sensei-fs/private/zcai/TTT-RL/cohort-closed-loop-structured-state/"
    r"(?P<commit>[0-9a-f]{40})/attempts/(?P<experiment>attempt-[0-9]{3})/"
    r"stages/(?P<stage_kind>[a-z][a-z0-9-]{0,63})/"
    r"(?P<stage_attempt>attempt-[0-9]{3})/private-context\Z"
)
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_STAGE_KIND_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_STAGE_ATTEMPT_RE = _ATTEMPT_RE
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_PRIVATE_RECORD_RE = re.compile(
    r"records/(?P<block>[a-z]+_block_(?P<block_number>[0-9]{2}))/"
    r"(?P<phase>adaptation|held_out)/(?P<item>[1-9][0-9]*)\.json\Z"
)
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_MOUNT_ESCAPE_RE = re.compile(r"\\([0-7]{3})")

for _required_flag in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"):
    if not hasattr(os, _required_flag):
        raise RuntimeError(f"private boundary requires {_required_flag}")

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
_METADATA_FLAGS = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | os.O_CLOEXEC
    | os.O_NOFOLLOW
    | getattr(os, "O_NONBLOCK", 0)
)
_ADAPTER_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_LOCKED_SECUREBITS = 0x3F
_STAGE_SHAPES = {
    "smoke": (1, 5),
    "internal": (3, 20),
    "confirmation": (8, 20),
}

_AUTHORITY_KEYS = frozenset(
    {
        "dgp_calls_authorized",
        "launch_authorized",
        "model_calls_authorized",
        "operational_authorization",
        "scorer_calls_authorized",
    }
)
_ROOT_IDENTITY_KEYS = frozenset(
    {
        "device",
        "group_gid",
        "inode",
        "mode",
        "owner_uid",
        "private_context_root",
    }
)
_MOUNT_KEYS = frozenset(
    {
        "filesystem_type",
        "major_minor",
        "mount_id",
        "mount_options",
        "mount_point",
        "mount_root",
        "mount_source",
        "parent_id",
        "super_options",
    }
)
_NAMESPACE_KEYS = frozenset({"device", "inode", "link_sha256"})
_PROCESS_KEYS = frozenset(
    {
        "active_capabilities_empty",
        "effective_gid",
        "effective_uid",
        "pid",
        "process_start_ticks",
        "real_gid",
        "real_uid",
        "saved_gid",
        "saved_uid",
        "service_identity",
        "supplementary_gids",
    }
)
_SOURCE_KEYS = frozenset({"path", "sha256", "size_bytes"})
_ADAPTER_KEYS = frozenset(
    {
        "adapter_mount",
        "device",
        "extended_attributes_empty",
        "group_gid",
        "inode",
        "link_count",
        "mode",
        "owner_uid",
        "path",
        "sha256",
        "size_bytes",
        "trusted_ancestors",
    }
)
_TRUSTED_ANCESTOR_KEYS = frozenset(
    {"device", "group_gid", "inode", "mode", "owner_uid", "path"}
)
_DIRECTORY_RECORD_KEYS = frozenset(
    {"device", "group_gid", "inode", "mode", "owner_uid", "relative_path"}
)
_FILE_RECORD_KEYS = frozenset(
    {
        "device",
        "group_gid",
        "inode",
        "link_count",
        "mode",
        "owner_uid",
        "relative_path",
        "size_bytes",
    }
)
_INVENTORY_KEYS = frozenset({"directories", "record_count", "records"})
_CONTENT_RECORD_KEYS = frozenset(
    {"device", "hidden_sha256", "inode", "path", "size_bytes"}
)
_PROBE_BINDING_KEYS = frozenset(
    {
        "artifact_device",
        "artifact_inode",
        "artifact_mode",
        "artifact_relative_path",
        "artifact_sha256",
        "artifact_size_bytes",
        "intent_relative_path",
        "intent_sha256",
        "intent_size_bytes",
        "pending_absent",
        "pending_relative_path",
        "probe_id",
    }
)
_ACCESS_PROBE_KEYS = frozenset(
    {
        "access_policy_sha256",
        "adapter_sha256",
        "allowed",
        "content_sha256",
        "credential_transition",
        "invoking_uid_before_transition",
        "pre_transition_effective_gid",
        "pre_transition_effective_uid",
        "pre_transition_real_gid",
        "pre_transition_real_uid",
        "pre_transition_saved_gid",
        "pre_transition_saved_uid",
        "observed_active_capabilities_empty",
        "observed_all_capability_sets_zero",
        "observed_effective_gid",
        "observed_effective_uid",
        "observed_real_gid",
        "observed_real_uid",
        "observed_saved_gid",
        "observed_saved_uid",
        "observed_supplementary_gids",
        "observed_no_new_privs",
        "observed_securebits",
        "self_executable_device",
        "self_executable_inode",
        "self_executable_sha256",
        "self_executable_size_bytes",
        "operation",
        "path",
        "probe_id",
        "protocol",
        "raw_errno",
        "schema_version",
        "stage",
        "target_uid",
        "target_gid",
        "target_supplementary_gids",
    }
)
_ABSENCE_PROBE_KEYS = frozenset(
    {
        "absent",
        "access_policy_sha256",
        "adapter_sha256",
        "credential_transition",
        "invoking_uid_before_transition",
        "pre_transition_effective_gid",
        "pre_transition_effective_uid",
        "pre_transition_real_gid",
        "pre_transition_real_uid",
        "pre_transition_saved_gid",
        "pre_transition_saved_uid",
        "observed_active_capabilities_empty",
        "observed_all_capability_sets_zero",
        "observed_effective_gid",
        "observed_effective_uid",
        "observed_real_gid",
        "observed_real_uid",
        "observed_saved_gid",
        "observed_saved_uid",
        "observed_supplementary_gids",
        "observed_no_new_privs",
        "observed_securebits",
        "self_executable_device",
        "self_executable_inode",
        "self_executable_sha256",
        "self_executable_size_bytes",
        "operation",
        "path",
        "probe_id",
        "protocol",
        "raw_errno",
        "schema_version",
        "stage",
        "target_uid",
        "target_gid",
        "target_supplementary_gids",
    }
)
_REGISTERED_RECORD_KEYS = frozenset(
    {
        "block_id",
        "block_index",
        "hidden_sha256",
        "instance_id",
        "instance_index",
        "item_id",
        "opaque_handle_sha256",
        "relative_path",
        "phase",
        "public_context_identity_sha256",
        "size_bytes",
        "stage_kind",
    }
)
_REGISTRY_UNSIGNED_KEYS = (
    frozenset(
        {
            "experiment_attempt_id",
            "boot_id",
            "completed_at_utc",
            "initial_registration_attestation_sha256",
            "private_context_root",
            "process_identity",
            "protocol",
            "record_set_sha256",
            "registered_record_count",
            "registered_records",
            "registrar_source",
            "schema_version",
            "source_commit",
            "stage_attempt_id",
            "stage_kind",
            "status",
        }
    )
    | _AUTHORITY_KEYS
)
_REGISTRY_KEYS = _REGISTRY_UNSIGNED_KEYS | {"registry_completion_receipt_sha256"}

_COMMON_UNSIGNED_KEYS = (
    frozenset(
        {
            "access_policy",
            "access_policy_sha256",
            "access_probe_receipts",
            "experiment_attempt_id",
            "attester_source",
            "access_probe_source",
            "boot_id",
            "mount_namespace",
            "private_context_root_identity",
            "private_mount",
            "probe_completed_at_utc",
            "probe_started_at_utc",
            "process_identity",
            "protocol",
            "public_durable_root",
            "record_inventory",
            "record_inventory_sha256",
            "record_content_inventory",
            "record_content_inventory_sha256",
            "schema_version",
            "service_identities",
            "setuid_adapter",
            "source_commit",
            "stage_attempt_id",
            "stage_kind",
            "stage",
            "status",
            "transient_probe_relative_path",
        }
    )
    | _AUTHORITY_KEYS
)
_INITIAL_UNSIGNED_KEYS = _COMMON_UNSIGNED_KEYS
_SEALED_UNSIGNED_KEYS = _COMMON_UNSIGNED_KEYS | {
    "fresh_until_utc",
    "initial_registration_attestation_sha256",
    "probe_record_relative_path",
    "registry_completed_at_utc",
    "registry_completion_receipt_sha256",
}
_INITIAL_KEYS = _INITIAL_UNSIGNED_KEYS | {"private_boundary_attestation_sha256"}
_SEALED_KEYS = _SEALED_UNSIGNED_KEYS | {"private_boundary_attestation_sha256"}


@dataclass(frozen=True, slots=True)
class _FileMetadata:
    device: int
    inode: int
    mode: int
    owner_uid: int
    group_gid: int
    size_bytes: int
    link_count: int


@dataclass(frozen=True, slots=True)
class _MountRecord:
    mount_id: int
    parent_id: int
    major_minor: str
    mount_root: str
    mount_point: str
    mount_options: str
    filesystem_type: str
    mount_source: str
    super_options: str


@dataclass(frozen=True, slots=True)
class _NamespaceObservation:
    device: int
    inode: int
    link_text: str


@dataclass(frozen=True, slots=True)
class _ProcessObservation:
    pid: int
    real_uid: int
    effective_uid: int
    saved_uid: int
    real_gid: int
    effective_gid: int
    saved_gid: int
    supplementary_gids: tuple[int, ...]
    active_capabilities_empty: bool
    process_start_ticks: int
    service_identity: str


@dataclass(frozen=True, slots=True)
class _AdapterObservation:
    path: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    group_gid: int
    sha256: str
    size_bytes: int
    link_count: int
    extended_attributes_empty: bool
    trusted_ancestors: tuple[dict[str, object], ...]
    adapter_mount: _MountRecord


@dataclass(frozen=True, slots=True)
class _VerifiedAdapterHandle:
    observation: _AdapterObservation
    descriptor: int
    close_descriptor: bool


@dataclass(frozen=True, slots=True)
class _RegisteredRecord:
    stage_kind: str
    block_id: str
    block_index: int
    phase: str
    item_id: int
    instance_index: int
    instance_id: str
    public_context_identity_sha256: str
    opaque_handle_sha256: str
    relative_path: str
    hidden_sha256: str
    size_bytes: int

    @property
    def sort_key(self) -> tuple[object, ...]:
        return (
            self.stage_kind,
            self.block_id,
            self.block_index,
            self.phase,
            self.item_id,
            self.instance_index,
            self.instance_id,
            self.public_context_identity_sha256,
            self.opaque_handle_sha256,
            self.relative_path,
            self.hidden_sha256,
            self.size_bytes,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "block_id": self.block_id,
            "block_index": self.block_index,
            "hidden_sha256": self.hidden_sha256,
            "instance_id": self.instance_id,
            "instance_index": self.instance_index,
            "item_id": self.item_id,
            "opaque_handle_sha256": self.opaque_handle_sha256,
            "relative_path": self.relative_path,
            "phase": self.phase,
            "public_context_identity_sha256": (self.public_context_identity_sha256),
            "size_bytes": self.size_bytes,
            "stage_kind": self.stage_kind,
        }


@dataclass(frozen=True, slots=True)
class _TreeObservation:
    root_metadata: _FileMetadata
    mount: _MountRecord
    directories: tuple[dict[str, object], ...]
    records: tuple[dict[str, object], ...]


@dataclass(frozen=True, slots=True)
class _PersistedPrerequisiteObservations:
    initial_attestation: PublishedArtifactObservation
    initial_probe_receipts: tuple[tuple[str, PublishedArtifactObservation], ...]
    registry_completion: PublishedArtifactObservation


@dataclass(frozen=True, slots=True)
class _ProbeRequest:
    probe_id: str
    target_uid: int
    target_gid: int
    target_supplementary_gids: tuple[int, ...]
    operation: str
    path: str
    protocol: str
    stage: str
    allowed: bool
    accepted_errnos: tuple[int, ...]
    access_policy_sha256: str
    adapter_sha256: str
    adapter_device: int
    adapter_inode: int
    adapter_size_bytes: int
    expected_content_sha256: str | None = None
    absence_receipt: bool = False
    probe_payload: bytes | None = None


@dataclass(frozen=True, slots=True)
class _PrivateBoundaryRuntime:
    euid: Callable[[], int]
    identity_for_uid: Callable[[int], str]
    now_utc: Callable[[], str]
    boot_id: Callable[[], str]
    process_identity: Callable[[], _ProcessObservation]
    mount_namespace: Callable[[], _NamespaceObservation]
    mountinfo_bytes: Callable[[], bytes]
    uid_translate: Callable[[int], int]
    gid_translate: Callable[[int], int]
    xattrs_for_fd: Callable[[int], tuple[str, ...]]
    open_adapter: Callable[[], _VerifiedAdapterHandle]
    access_probe: Callable[[_ProbeRequest, _VerifiedAdapterHandle], bytes]


@dataclass(frozen=True, slots=True)
class _RegistryCompletionValidation:
    source_commit: str
    experiment_attempt_id: str
    stage_kind: str
    stage_attempt_id: str
    private_context_root: str
    initial_registration_attestation_sha256: str
    registry_completion_receipt_sha256: str
    completed_at_utc: str
    boot_id: str
    registered_records: tuple[_RegisteredRecord, ...]


@dataclass(frozen=True, slots=True)
class PrivateBoundaryArtifacts:
    """Raw public artifact plus separately supplied raw probe receipts."""

    attestation_bytes: bytes
    access_probe_receipts: tuple[tuple[str, bytes], ...]
    probe_publications: tuple[PublishedArtifactObservation, ...]
    publication: PublishedArtifactObservation


@dataclass(frozen=True, slots=True)
class PrivateBoundaryValidation:
    """Pure validation result; every authority field remains false."""

    stage: str
    protocol: str
    source_commit: str
    experiment_attempt_id: str
    stage_kind: str
    stage_attempt_id: str
    private_context_root: str
    private_boundary_attestation_sha256: str
    access_policy_sha256: str
    record_inventory_sha256: str
    initial_registration_attestation_sha256: str | None
    registry_completion_receipt_sha256: str | None
    fresh_until_utc: str | None
    dgp_calls_authorized: bool = False
    model_calls_authorized: bool = False
    scorer_calls_authorized: bool = False
    launch_authorized: bool = False
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
        raise PrivateBoundaryError("canonical JSON encoding failed") from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _probe_receipt_relative_path(stage: str, probe_id: str) -> str:
    if stage == INITIAL_REGISTRATION_STAGE:
        phase = "initial"
    elif stage == SEALED_PRELAUNCH_STAGE:
        phase = "sealed"
    else:
        raise PrivateBoundaryError("probe receipt stage differs")
    return f"control/private_boundary/{phase}/probes/{probe_id}.json"


def _atomic_intent_bytes(relative_path: str, payload: bytes) -> bytes:
    intent_relative, pending_relative = publication_sidecar_relative_paths(
        relative_path
    )
    del intent_relative
    return _canonical(
        {
            "artifact_relative_path": relative_path,
            "artifact_sha256": _sha(payload),
            "artifact_size_bytes": len(payload),
            "pending_name": PurePosixPath(pending_relative).name,
            "protocol": "cohort_structured_atomic_publication_intent_v1",
            "schema_version": 1,
        }
    )


def _probe_publication_binding(
    *,
    stage: str,
    probe_id: str,
    raw: bytes,
    observation: PublishedArtifactObservation,
) -> dict[str, object]:
    expected_relative = _probe_receipt_relative_path(stage, probe_id)
    intent_relative, pending_relative = publication_sidecar_relative_paths(
        expected_relative
    )
    intent_raw = _atomic_intent_bytes(expected_relative, raw)
    if (
        observation.relative_path != expected_relative
        or observation.sha256 != _sha(raw)
        or observation.size_bytes != len(raw)
        or observation.mode != 0o444
        or observation.link_count != 1
    ):
        raise PrivateBoundaryError("probe receipt publication observation differs")
    return {
        "artifact_device": observation.device,
        "artifact_inode": observation.inode,
        "artifact_mode": observation.mode,
        "artifact_relative_path": expected_relative,
        "artifact_sha256": observation.sha256,
        "artifact_size_bytes": observation.size_bytes,
        "intent_relative_path": intent_relative,
        "intent_sha256": _sha(intent_raw),
        "intent_size_bytes": len(intent_raw),
        "pending_absent": True,
        "pending_relative_path": pending_relative,
        "probe_id": probe_id,
    }


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PrivateBoundaryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PrivateBoundaryError(f"non-finite JSON constant: {value}")


def _parse(raw: object, label: str) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise PrivateBoundaryError(f"{label} must be exact bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PrivateBoundaryError(f"{label} is not strict ASCII JSON") from exc
    if type(value) is not dict or _canonical(value) != raw:
        raise PrivateBoundaryError(f"{label} is not exact canonical JSON")
    return value


def _object(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise PrivateBoundaryError(f"{label} exact schema differs")
    return value


def _exact_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PrivateBoundaryError(f"{label} must be exact integer >= {minimum}")
    return value


def _utc(value: object, label: str) -> datetime:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise PrivateBoundaryError(f"{label} must be exact UTC-second text")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalized_absolute(value: object, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise PrivateBoundaryError(f"{label} must be an absolute pathlib.Path")
    normalized = Path(os.path.normpath(os.fspath(value)))
    if normalized != value or normalized == Path("/"):
        raise PrivateBoundaryError(f"{label} must be normalized and non-root")
    return normalized


def _normalized_absolute_text(value: object, label: str) -> str:
    if type(value) is not str or not value.startswith("/") or "\x00" in value:
        raise PrivateBoundaryError(f"{label} must be absolute POSIX text")
    if posixpath.normpath(value) != value or value == "/":
        raise PrivateBoundaryError(f"{label} must be normalized and non-root")
    return value


def _relative(value: object, label: str) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\x00" in value:
        raise PrivateBoundaryError(f"{label} must be relative POSIX text")
    if posixpath.normpath(value) != value or any(
        part in {"", ".", ".."} for part in value.split("/")
    ):
        raise PrivateBoundaryError(f"{label} must be normalized")
    return value


def _private_record_coordinate(
    relative: str, *, stage_kind: str
) -> tuple[int, int, int]:
    match = _PRIVATE_RECORD_RE.fullmatch(relative)
    if match is None or match.group("block") != (
        f"{stage_kind}_block_{match.group('block_number')}"
    ):
        raise PrivateBoundaryError("private record path does not match stage grammar")
    block_index = int(match.group("block_number")) - 1
    phase_index = 0 if match.group("phase") == "adaptation" else 1
    item_id = int(match.group("item"))
    block_count, items_per_phase = _STAGE_SHAPES[stage_kind]
    if (
        block_index < 0
        or block_index >= block_count
        or item_id < 1
        or item_id > items_per_phase
    ):
        raise PrivateBoundaryError("private record path exceeds stage shape")
    return block_index, phase_index, item_id


def _expected_private_directories(
    record_paths: tuple[str, ...],
) -> tuple[str, ...]:
    """Derive the only directories permitted by an exact record-path set."""

    directories: set[str] = set()
    for raw_relative in record_paths:
        relative = _relative(raw_relative, "private record path")
        parts = relative.split("/")
        for end in range(1, len(parts)):
            directories.add("/".join(parts[:end]))
    return tuple(sorted(directories))


def _authority_false() -> dict[str, bool]:
    return {
        "dgp_calls_authorized": False,
        "launch_authorized": False,
        "model_calls_authorized": False,
        "operational_authorization": False,
        "scorer_calls_authorized": False,
    }


def _require_authority_false(value: Mapping[str, object]) -> None:
    if any(value[key] is not False for key in _AUTHORITY_KEYS):
        raise PrivateBoundaryError("private boundary invents operational authority")


def _service_identities() -> dict[str, object]:
    return {
        "attester": {
            "gid": ATTESTER_UID,
            "identity": ATTESTER_SERVICE_IDENTITY,
            "supplementary_gids": [PRIVATE_READ_GID],
            "uid": ATTESTER_UID,
        },
        "launcher": {
            "gid": LAUNCHER_UID,
            "identity": LAUNCHER_SERVICE_IDENTITY,
            "supplementary_gids": [],
            "uid": LAUNCHER_UID,
        },
        "operator": {
            "gid": OPERATOR_UID,
            "identity": OPERATOR_SERVICE_IDENTITY,
            "supplementary_gids": [],
            "uid": OPERATOR_UID,
        },
        "private_validator": {
            "gid": PRIVATE_VALIDATOR_UID,
            "identity": PRIVATE_VALIDATOR_SERVICE_IDENTITY,
            "supplementary_gids": [PRIVATE_READ_GID],
            "uid": PRIVATE_VALIDATOR_UID,
        },
        "pure_scorer": {
            "gid": PURE_SCORER_UID,
            "identity": PURE_SCORER_SERVICE_IDENTITY,
            "supplementary_gids": [PRIVATE_READ_GID],
            "uid": PURE_SCORER_UID,
        },
        "registrar": {
            "gid": PRIVATE_READ_GID,
            "identity": REGISTRAR_SERVICE_IDENTITY,
            "supplementary_gids": [],
            "uid": REGISTRAR_UID,
        },
    }


def _assert_distinct_identities() -> None:
    values = (
        ATTESTER_UID,
        REGISTRAR_UID,
        PURE_SCORER_UID,
        PRIVATE_VALIDATOR_UID,
        LAUNCHER_UID,
        OPERATOR_UID,
    )
    if len(values) != len(set(values)):
        raise PrivateBoundaryError("private-boundary service UIDs must be distinct")


def _access_policy(stage: str) -> dict[str, object]:
    common_denied = {
        "launcher": {
            "operations": ["enumerate_root", "read_probe_or_record"],
            "required_raw_errno": errno.EACCES,
            "gid": LAUNCHER_UID,
            "supplementary_gids": [],
            "uid": LAUNCHER_UID,
        },
        "operator": {
            "operations": ["enumerate_root", "read_probe_or_record"],
            "required_raw_errno": errno.EACCES,
            "gid": OPERATOR_UID,
            "supplementary_gids": [],
            "uid": OPERATOR_UID,
        },
    }
    if stage == INITIAL_REGISTRATION_STAGE:
        return {
            "adapter_credential_transition": (
                "setgroups_then_setresgid_then_setresuid_no_active_capabilities"
            ),
            "adapter_exec_gid": ATTESTER_UID,
            "adapter_invoker_uid": ATTESTER_UID,
            "adapter_mode": 0o4750,
            "attester": {
                "gid": ATTESTER_UID,
                "supplementary_gids": [PRIVATE_READ_GID],
                "uid": ATTESTER_UID,
            },
            "directory_group_gid": PRIVATE_READ_GID,
            "directory_mode": 0o750,
            "mount_mode": "rw",
            "registrar": {
                "operations": [
                    "create_exact_probe",
                    "read_exact_probe",
                    "remove_exact_probe",
                    "verify_probe_absent",
                ],
                "gid": PRIVATE_READ_GID,
                "supplementary_gids": [],
                "uid": REGISTRAR_UID,
            },
            "read_only_consumers": {
                "private_validator": {
                    "denied_operations": ["create_record", "write_exact_probe"],
                    "gid": PRIVATE_VALIDATOR_UID,
                    "required_raw_errno": errno.EACCES,
                    "supplementary_gids": [PRIVATE_READ_GID],
                    "uid": PRIVATE_VALIDATOR_UID,
                },
                "pure_scorer": {
                    "denied_operations": ["create_record", "write_exact_probe"],
                    "gid": PURE_SCORER_UID,
                    "required_raw_errno": errno.EACCES,
                    "supplementary_gids": [PRIVATE_READ_GID],
                    "uid": PURE_SCORER_UID,
                },
            },
            "denied": common_denied,
            "record_group_gid": PRIVATE_READ_GID,
            "record_mode": 0o440,
            "root_owner_uid": REGISTRAR_UID,
            "schema_version": 1,
            "stage": stage,
        }
    if stage == SEALED_PRELAUNCH_STAGE:
        return {
            "adapter_credential_transition": (
                "setgroups_then_setresgid_then_setresuid_no_active_capabilities"
            ),
            "adapter_exec_gid": ATTESTER_UID,
            "adapter_invoker_uid": ATTESTER_UID,
            "adapter_mode": 0o4750,
            "attester": {
                "gid": ATTESTER_UID,
                "supplementary_gids": [PRIVATE_READ_GID],
                "uid": ATTESTER_UID,
            },
            "directory_group_gid": PRIVATE_READ_GID,
            "directory_mode": 0o750,
            "mount_mode": "ro",
            "permitted_readers": {
                "private_validator": {
                    "gid": PRIVATE_VALIDATOR_UID,
                    "supplementary_gids": [PRIVATE_READ_GID],
                    "uid": PRIVATE_VALIDATOR_UID,
                },
                "pure_scorer": {
                    "gid": PURE_SCORER_UID,
                    "supplementary_gids": [PRIVATE_READ_GID],
                    "uid": PURE_SCORER_UID,
                },
                "registrar": {
                    "gid": PRIVATE_READ_GID,
                    "supplementary_gids": [],
                    "uid": REGISTRAR_UID,
                },
            },
            "registrar_mutation_denied": {
                "accepted_raw_errnos": sorted({errno.EACCES, errno.EROFS}),
                "gid": PRIVATE_READ_GID,
                "operations": ["create_probe_record", "write_registered_record"],
                "supplementary_gids": [],
                "uid": REGISTRAR_UID,
            },
            "denied": common_denied,
            "record_group_gid": PRIVATE_READ_GID,
            "record_mode": 0o440,
            "root_owner_uid": REGISTRAR_UID,
            "schema_version": 2,
            "stage": stage,
        }
    raise PrivateBoundaryError("private-boundary stage differs")


def _default_identity(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError as exc:
        raise PrivateBoundaryError(
            "private-boundary service account is missing"
        ) from exc


def _assert_production_service_accounts() -> None:
    specifications = (
        (ATTESTER_UID, ATTESTER_UID, ATTESTER_SERVICE_IDENTITY),
        (REGISTRAR_UID, PRIVATE_READ_GID, REGISTRAR_SERVICE_IDENTITY),
        (PURE_SCORER_UID, PURE_SCORER_UID, PURE_SCORER_SERVICE_IDENTITY),
        (
            PRIVATE_VALIDATOR_UID,
            PRIVATE_VALIDATOR_UID,
            PRIVATE_VALIDATOR_SERVICE_IDENTITY,
        ),
        (LAUNCHER_UID, LAUNCHER_UID, LAUNCHER_SERVICE_IDENTITY),
        (OPERATOR_UID, OPERATOR_UID, OPERATOR_SERVICE_IDENTITY),
    )
    names: dict[int, str] = {}
    try:
        for uid, primary_gid, identity in specifications:
            account = pwd.getpwuid(uid)
            if (
                account.pw_uid != uid
                or account.pw_gid != primary_gid
                or account.pw_name != identity
            ):
                raise PrivateBoundaryError(
                    "private-boundary production service account differs"
                )
            names[uid] = account.pw_name
        private_group = grp.getgrgid(PRIVATE_READ_GID)
        for uid, _primary_gid, _identity in specifications:
            if uid != REGISTRAR_UID:
                grp.getgrgid(uid)
    except KeyError as exc:
        raise PrivateBoundaryError(
            "private-boundary production service account/group is missing"
        ) from exc
    expected_members = {
        names[ATTESTER_UID],
        names[PURE_SCORER_UID],
        names[PRIVATE_VALIDATOR_UID],
    }
    if set(private_group.gr_mem) != expected_members:
        raise PrivateBoundaryError(
            "private-boundary private-read group membership differs"
        )


def _default_now() -> str:
    return _format_utc(datetime.now(timezone.utc))


def _default_boot_id() -> str:
    try:
        value = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        )
    except OSError as exc:
        raise PrivateBoundaryError("cannot read Linux boot id") from exc
    if _BOOT_ID_RE.fullmatch(value) is None:
        raise PrivateBoundaryError("Linux boot id differs")
    return value


def _default_process_identity() -> _ProcessObservation:
    pid = os.getpid()
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        status_raw = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except OSError as exc:
        raise PrivateBoundaryError("cannot read process start identity") from exc
    close = raw.rfind(")")
    fields = raw[close + 2 :].split() if close >= 0 else []
    if len(fields) <= 19 or not fields[19].isdigit():
        raise PrivateBoundaryError("process start identity differs")
    status: dict[str, str] = {}
    for line in status_raw.splitlines():
        key, separator, value = line.partition(":")
        if separator and key not in status:
            status[key] = value.strip()
    try:
        uid_values = tuple(int(value) for value in status["Uid"].split())
        gid_values = tuple(int(value) for value in status["Gid"].split())
        supplementary = tuple(int(value) for value in status["Groups"].split())
        capability_values = tuple(
            int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")
        )
    except (KeyError, ValueError) as exc:
        raise PrivateBoundaryError("process credential identity differs") from exc
    if len(uid_values) != 4 or len(gid_values) != 4:
        raise PrivateBoundaryError("process credential identity differs")
    return _ProcessObservation(
        pid=pid,
        real_uid=uid_values[0],
        effective_uid=uid_values[1],
        saved_uid=uid_values[2],
        real_gid=gid_values[0],
        effective_gid=gid_values[1],
        saved_gid=gid_values[2],
        supplementary_gids=tuple(sorted(supplementary)),
        active_capabilities_empty=all(value == 0 for value in capability_values),
        process_start_ticks=int(fields[19]),
        service_identity=_default_identity(uid_values[1]),
    )


def _default_mount_namespace() -> _NamespaceObservation:
    path = Path("/proc/self/ns/mnt")
    try:
        metadata = path.stat()
        link_text = os.readlink(path)
    except OSError as exc:
        raise PrivateBoundaryError("cannot observe mount namespace") from exc
    return _NamespaceObservation(metadata.st_dev, metadata.st_ino, link_text)


def _default_mountinfo() -> bytes:
    try:
        return Path("/proc/self/mountinfo").read_bytes()
    except OSError as exc:
        raise PrivateBoundaryError("cannot read mountinfo") from exc


def _metadata(value: os.stat_result) -> _FileMetadata:
    return _FileMetadata(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        owner_uid=value.st_uid,
        group_gid=value.st_gid,
        size_bytes=value.st_size,
        link_count=value.st_nlink,
    )


def _open_absolute_directory(path: Path) -> int:
    descriptor = -1
    try:
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        for component in path.parts[1:]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise PrivateBoundaryError(
            f"anchored non-symlink directory traversal failed: {path}"
        ) from exc


def _default_xattrs_for_fd(descriptor: int) -> tuple[str, ...]:
    try:
        names = os.listxattr(descriptor)
    except (OSError, TypeError) as exc:
        raise PrivateBoundaryError("cannot inspect extended attributes") from exc
    if any(type(name) is not str or not name for name in names):
        raise PrivateBoundaryError("extended-attribute inventory differs")
    return tuple(sorted(names))


def _hash_open_descriptor(descriptor: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        try:
            chunk = os.pread(
                descriptor, min(1024 * 1024, expected_size - offset), offset
            )
        except OSError as exc:
            raise PrivateBoundaryError(
                "cannot hash verified adapter descriptor"
            ) from exc
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if offset != expected_size:
        raise PrivateBoundaryError("verified adapter descriptor size differs")
    return digest.hexdigest()


def _trusted_ancestor_object(path: Path, descriptor: int) -> dict[str, object]:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or mode & 0o022
        or metadata.st_nlink < 1
    ):
        raise PrivateBoundaryError("setuid adapter ancestor trust differs")
    if _default_xattrs_for_fd(descriptor):
        raise PrivateBoundaryError("setuid adapter ancestor has extended attributes")
    return {
        "device": metadata.st_dev,
        "group_gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "mode": mode,
        "owner_uid": metadata.st_uid,
        "path": str(path),
    }


def _default_open_adapter() -> _VerifiedAdapterHandle:
    path = _normalized_absolute(SETUID_ADAPTER_PATH, "setuid adapter path")
    descriptor = -1
    current = -1
    ancestors: list[dict[str, object]] = []
    try:
        current = os.open("/", _DIRECTORY_FLAGS)
        ancestors.append(_trusted_ancestor_object(Path("/"), current))
        current_path = Path("/")
        for component in path.parent.parts[1:]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = child
            current_path /= component
            ancestors.append(_trusted_ancestor_object(current_path, current))
        descriptor = os.open(path.name, _ADAPTER_READ_FLAGS, dir_fd=current)
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != ATTESTER_UID
            or mode != 0o4750
            or before.st_nlink != 1
            or before.st_size <= 0
            or _default_xattrs_for_fd(descriptor)
        ):
            raise PrivateBoundaryError("setuid adapter ownership/mode/trust differs")
        adapter_sha = _hash_open_descriptor(descriptor, before.st_size)
        after = os.fstat(descriptor)
        if before != after:
            raise PrivateBoundaryError("setuid adapter changed while verified")
        mount = _mount_for(path, _parse_mountinfo(_default_mountinfo()))
        mount_options = set(mount.mount_options.split(","))
        super_options = set(mount.super_options.split(","))
        if (
            "nosuid" in mount_options
            or "nosuid" in super_options
            or mount.major_minor != _major_minor(before.st_dev)
        ):
            raise PrivateBoundaryError("setuid adapter mount is not suid-enabled")
        observation = _AdapterObservation(
            path=str(path),
            device=before.st_dev,
            inode=before.st_ino,
            mode=mode,
            owner_uid=before.st_uid,
            group_gid=before.st_gid,
            sha256=adapter_sha,
            size_bytes=before.st_size,
            link_count=before.st_nlink,
            extended_attributes_empty=True,
            trusted_ancestors=tuple(ancestors),
            adapter_mount=mount,
        )
        result = _VerifiedAdapterHandle(
            observation=observation,
            descriptor=descriptor,
            close_descriptor=True,
        )
        descriptor = -1
        return result
    except OSError as exc:
        raise PrivateBoundaryError("cannot open fixed setuid adapter") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if current >= 0:
            os.close(current)


def _run_fexecve(
    descriptor: int,
    argv: tuple[str, ...],
    *,
    timeout_seconds: float,
) -> tuple[int, bytes, bytes]:
    if os.name != "posix" or not hasattr(os, "fork"):
        raise PrivateBoundaryError("verified-fd execution requires Linux fork/fexecve")
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - production Linux child
        try:
            devnull = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            os.dup2(devnull, 0)
            os.dup2(stdout_write, 1)
            os.dup2(stderr_write, 2)
            keep = {0, 1, 2, descriptor}
            for name in os.listdir("/proc/self/fd"):
                try:
                    fd = int(name)
                except ValueError:
                    continue
                if fd not in keep:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            os.chdir("/")
            libc = ctypes.CDLL(None, use_errno=True)
            fexecve = libc.fexecve
            fexecve.argtypes = (
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_char_p),
                ctypes.POINTER(ctypes.c_char_p),
            )
            fexecve.restype = ctypes.c_int
            encoded_argv = [value.encode("ascii") for value in argv]
            argv_array = (ctypes.c_char_p * (len(encoded_argv) + 1))(
                *encoded_argv, None
            )
            env_values = (b"PATH=/usr/bin:/bin", b"LANG=C", b"LC_ALL=C")
            env_array = (ctypes.c_char_p * (len(env_values) + 1))(*env_values, None)
            fexecve(descriptor, argv_array, env_array)
            error = ctypes.get_errno()
            os.write(2, f"fexecve failed: {error}\n".encode("ascii"))
        except BaseException:
            pass
        os._exit(127)
    os.close(stdout_write)
    os.close(stderr_write)
    for fd in (stdout_read, stderr_read):
        os.set_blocking(fd, False)
    stdout = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + timeout_seconds
    status: int | None = None
    open_fds = {stdout_read: stdout, stderr_read: stderr}
    try:
        while status is None or open_fds:
            if time.monotonic() >= deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise PrivateBoundaryError("verified-fd access probe timed out")
            ready, _, _ = select.select(tuple(open_fds), (), (), 0.05)
            for fd in ready:
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if chunk:
                    open_fds[fd].extend(chunk)
                    if len(open_fds[fd]) > 1024 * 1024:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                        raise PrivateBoundaryError("access probe output exceeds limit")
                else:
                    os.close(fd)
                    del open_fds[fd]
            if status is None:
                waited, child_status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    status = child_status
        assert status is not None
        exit_code = os.waitstatus_to_exitcode(status)
        return exit_code, bytes(stdout), bytes(stderr)
    finally:
        for fd in tuple(open_fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _default_access_probe(
    request: _ProbeRequest, handle: _VerifiedAdapterHandle
) -> bytes:
    adapter = handle.observation
    command = [
        "/proc/self/exe",
        "--probe-id",
        request.probe_id,
        "--target-uid",
        str(request.target_uid),
        "--target-gid",
        str(request.target_gid),
        "--target-supplementary-gids",
        ",".join(str(value) for value in request.target_supplementary_gids),
        "--credential-transition",
        "setgroups_then_setresgid_then_setresuid_no_active_capabilities",
        "--operation",
        request.operation,
        "--path",
        request.path,
        "--receipt-protocol",
        request.protocol,
        "--stage",
        request.stage,
        "--access-policy-sha256",
        request.access_policy_sha256,
        "--adapter-sha256",
        request.adapter_sha256,
        "--expected-executable-device",
        str(adapter.device),
        "--expected-executable-inode",
        str(adapter.inode),
        "--expected-executable-size-bytes",
        str(adapter.size_bytes),
        "--expected-executable-sha256",
        adapter.sha256,
    ]
    if request.probe_payload is not None:
        command.extend(("--probe-payload-hex", request.probe_payload.hex()))
    exit_code, stdout, stderr = _run_fexecve(
        handle.descriptor, tuple(command), timeout_seconds=10
    )
    if exit_code != 0 or stderr:
        raise PrivateBoundaryError("fixed setuid access probe transport differed")
    return stdout


def _production_runtime() -> _PrivateBoundaryRuntime:
    return _PrivateBoundaryRuntime(
        euid=os.geteuid,
        identity_for_uid=_default_identity,
        now_utc=_default_now,
        boot_id=_default_boot_id,
        process_identity=_default_process_identity,
        mount_namespace=_default_mount_namespace,
        mountinfo_bytes=_default_mountinfo,
        uid_translate=lambda value: value,
        gid_translate=lambda value: value,
        xattrs_for_fd=_default_xattrs_for_fd,
        open_adapter=_default_open_adapter,
        access_probe=_default_access_probe,
    )


def _decode_mount(value: str) -> str:
    return _MOUNT_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _parse_mountinfo(raw: object) -> tuple[_MountRecord, ...]:
    if type(raw) is not bytes or not raw:
        raise PrivateBoundaryError("mountinfo must be nonempty exact bytes")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise PrivateBoundaryError("mountinfo must be ASCII") from exc
    rows: list[_MountRecord] = []
    for line in lines:
        left, separator, right = line.partition(" - ")
        left_fields = left.split()
        right_fields = right.split()
        if (
            not separator
            or len(left_fields) < 6
            or len(right_fields) < 3
            or not left_fields[0].isdigit()
            or not left_fields[1].isdigit()
            or re.fullmatch(r"[0-9]+:[0-9]+", left_fields[2]) is None
        ):
            raise PrivateBoundaryError("mountinfo row is malformed")
        rows.append(
            _MountRecord(
                mount_id=int(left_fields[0]),
                parent_id=int(left_fields[1]),
                major_minor=left_fields[2],
                mount_root=_decode_mount(left_fields[3]),
                mount_point=_decode_mount(left_fields[4]),
                mount_options=left_fields[5],
                filesystem_type=right_fields[0],
                mount_source=_decode_mount(right_fields[1]),
                super_options=right_fields[2],
            )
        )
    if not rows:
        raise PrivateBoundaryError("mountinfo has no records")
    return tuple(rows)


def _path_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _mount_for(path: Path, rows: tuple[_MountRecord, ...]) -> _MountRecord:
    candidates = [row for row in rows if _path_within(str(path), row.mount_point)]
    if not candidates:
        raise PrivateBoundaryError(f"no mount covers private path: {path}")
    longest = max(len(row.mount_point) for row in candidates)
    winners = [row for row in candidates if len(row.mount_point) == longest]
    if len(winners) != 1:
        raise PrivateBoundaryError("private path has a non-unique longest mount")
    return winners[0]


def _major_minor(device: int) -> str:
    return f"{os.major(device)}:{os.minor(device)}"


def _translated_uid(value: int, runtime: _PrivateBoundaryRuntime) -> int:
    result = runtime.uid_translate(value)
    if type(result) is not int:
        raise PrivateBoundaryError("translated uid must be an exact integer")
    return result


def _translated_gid(value: int, runtime: _PrivateBoundaryRuntime) -> int:
    result = runtime.gid_translate(value)
    if type(result) is not int:
        raise PrivateBoundaryError("translated gid must be an exact integer")
    return result


def _validate_mount_mode(mount: _MountRecord, stage: str, root: Path) -> None:
    required = "rw" if stage == INITIAL_REGISTRATION_STAGE else "ro"
    forbidden = "ro" if required == "rw" else "rw"
    mount_options = set(mount.mount_options.split(","))
    super_options = set(mount.super_options.split(","))
    if (
        mount.mount_point != str(root)
        or required not in mount_options
        or required not in super_options
        or forbidden in mount_options
        or forbidden in super_options
    ):
        raise PrivateBoundaryError(
            f"private root is not a dedicated exact {required} mount"
        )


def _directory_record(
    relative: str, metadata: _FileMetadata, runtime: _PrivateBoundaryRuntime
) -> dict[str, object]:
    uid = _translated_uid(metadata.owner_uid, runtime)
    gid = _translated_gid(metadata.group_gid, runtime)
    mode = stat.S_IMODE(metadata.mode)
    if (
        not stat.S_ISDIR(metadata.mode)
        or uid != REGISTRAR_UID
        or gid != PRIVATE_READ_GID
        or mode != 0o750
    ):
        raise PrivateBoundaryError("private directory owner/type/mode differs")
    return {
        "device": metadata.device,
        "group_gid": gid,
        "inode": metadata.inode,
        "mode": mode,
        "owner_uid": uid,
        "relative_path": relative,
    }


def _file_record(
    relative: str, metadata: _FileMetadata, runtime: _PrivateBoundaryRuntime
) -> dict[str, object]:
    uid = _translated_uid(metadata.owner_uid, runtime)
    gid = _translated_gid(metadata.group_gid, runtime)
    mode = stat.S_IMODE(metadata.mode)
    if (
        not stat.S_ISREG(metadata.mode)
        or uid != REGISTRAR_UID
        or gid != PRIVATE_READ_GID
        or mode != 0o440
        or metadata.link_count != 1
    ):
        raise PrivateBoundaryError("private record owner/type/mode/link count differs")
    return {
        "device": metadata.device,
        "group_gid": gid,
        "inode": metadata.inode,
        "link_count": metadata.link_count,
        "mode": mode,
        "owner_uid": uid,
        "relative_path": relative,
        "size_bytes": metadata.size_bytes,
    }


def _reject_fd_xattrs(
    descriptor: int, runtime: _PrivateBoundaryRuntime, label: str
) -> None:
    names = runtime.xattrs_for_fd(descriptor)
    if (
        type(names) is not tuple
        or any(type(name) is not str or not name for name in names)
        or names != tuple(sorted(set(names)))
    ):
        raise PrivateBoundaryError(f"{label} xattr observation differs")
    if names:
        raise PrivateBoundaryError(
            f"{label} has forbidden ACL, file capability, or extended attribute"
        )


def _open_anchored_record(
    root_descriptor: int,
    relative: str,
    runtime: _PrivateBoundaryRuntime,
) -> int:
    components = relative.split("/")
    parent = os.dup(root_descriptor)
    try:
        _reject_fd_xattrs(parent, runtime, "private root")
        for component in components[:-1]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = child
            _reject_fd_xattrs(parent, runtime, f"private parent {relative}")
        descriptor = os.open(components[-1], _ADAPTER_READ_FLAGS, dir_fd=parent)
    except OSError as exc:
        raise PrivateBoundaryError(
            f"anchored private record open failed: {relative}"
        ) from exc
    finally:
        os.close(parent)
    return descriptor


def _read_record_content_inventory(
    root: Path,
    *,
    records: tuple[dict[str, object], ...],
    runtime: _PrivateBoundaryRuntime,
) -> tuple[dict[str, object], ...]:
    root_descriptor = _open_absolute_directory(root)
    observations: list[dict[str, object]] = []
    try:
        root_before = _metadata(os.fstat(root_descriptor))
        _reject_fd_xattrs(root_descriptor, runtime, "private root")
        for record in records:
            relative = _relative(record["relative_path"], "private record path")
            descriptor = _open_anchored_record(root_descriptor, relative, runtime)
            try:
                before = os.fstat(descriptor)
                _reject_fd_xattrs(descriptor, runtime, f"private record {relative}")
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_IMODE(before.st_mode) != 0o440
                    or before.st_nlink != 1
                    or before.st_dev != record["device"]
                    or before.st_ino != record["inode"]
                    or before.st_size != record["size_bytes"]
                ):
                    raise PrivateBoundaryError(
                        f"private record content identity differs: {relative}"
                    )
                digest = hashlib.sha256()
                size_bytes = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size_bytes += len(chunk)
                after = os.fstat(descriptor)
                _reject_fd_xattrs(descriptor, runtime, f"private record {relative}")
                if before != after or size_bytes != before.st_size:
                    raise PrivateBoundaryError(
                        f"private record changed while hashing: {relative}"
                    )
                observations.append(
                    {
                        "device": before.st_dev,
                        "hidden_sha256": digest.hexdigest(),
                        "inode": before.st_ino,
                        "path": relative,
                        "size_bytes": size_bytes,
                    }
                )
            finally:
                os.close(descriptor)
        _reject_fd_xattrs(root_descriptor, runtime, "private root")
        if _metadata(os.fstat(root_descriptor)) != root_before:
            raise PrivateBoundaryError(
                "private root changed during record-content pass"
            )
    finally:
        os.close(root_descriptor)
    if tuple(row["path"] for row in observations) != tuple(
        row["relative_path"] for row in records
    ):
        raise PrivateBoundaryError("private record content inventory differs")
    return tuple(observations)


def _scan_private_tree(
    root: Path,
    *,
    expected_record_paths: tuple[str, ...],
    mountinfo_raw: bytes,
    runtime: _PrivateBoundaryRuntime,
    stage: str,
) -> _TreeObservation:
    mounts = _parse_mountinfo(mountinfo_raw)
    root_descriptor = _open_absolute_directory(root)
    directories: list[dict[str, object]] = []
    records: list[dict[str, object]] = []
    try:
        root_before = _metadata(os.fstat(root_descriptor))
        _reject_fd_xattrs(root_descriptor, runtime, "private root")
        root_uid = _translated_uid(root_before.owner_uid, runtime)
        root_gid = _translated_gid(root_before.group_gid, runtime)
        if (
            not stat.S_ISDIR(root_before.mode)
            or root_uid != REGISTRAR_UID
            or root_gid != PRIVATE_READ_GID
            or stat.S_IMODE(root_before.mode) != 0o750
        ):
            raise PrivateBoundaryError("private root owner/type/mode differs")
        root_mount = _mount_for(root, mounts)
        _validate_mount_mode(root_mount, stage, root)
        if root_mount.major_minor != _major_minor(root_before.device):
            raise PrivateBoundaryError("private root mount/device differs")

        def visit(descriptor: int, parent_relative: str) -> None:
            before = _metadata(os.fstat(descriptor))
            _reject_fd_xattrs(descriptor, runtime, "private directory")
            names = sorted(os.listdir(descriptor))
            if len(names) != len(set(names)):
                raise PrivateBoundaryError("private directory has duplicate entries")
            for name in names:
                if (
                    type(name) is not str
                    or not name
                    or name in {".", ".."}
                    or "/" in name
                    or "\x00" in name
                ):
                    raise PrivateBoundaryError("private directory entry is unsafe")
                relative = f"{parent_relative}/{name}" if parent_relative else name
                path = root / relative
                child_metadata: _FileMetadata
                try:
                    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError as directory_error:
                    if directory_error.errno not in {errno.ELOOP, errno.ENOTDIR}:
                        raise PrivateBoundaryError(
                            f"cannot inspect private entry: {relative}"
                        ) from directory_error
                    try:
                        child = os.open(name, _METADATA_FLAGS, dir_fd=descriptor)
                    except OSError as file_error:
                        raise PrivateBoundaryError(
                            f"private tree contains a symlink or special entry: {relative}"
                        ) from file_error
                    try:
                        child_metadata = _metadata(os.fstat(child))
                        _reject_fd_xattrs(child, runtime, f"private record {relative}")
                        records.append(_file_record(relative, child_metadata, runtime))
                    finally:
                        os.close(child)
                else:
                    try:
                        child_metadata = _metadata(os.fstat(child))
                        _reject_fd_xattrs(
                            child, runtime, f"private directory {relative}"
                        )
                        directories.append(
                            _directory_record(relative, child_metadata, runtime)
                        )
                        visit(child, relative)
                        if _metadata(os.fstat(child)) != child_metadata:
                            raise PrivateBoundaryError(
                                f"private directory identity drifted: {relative}"
                            )
                    finally:
                        os.close(child)
                observed_mount = _mount_for(path, mounts)
                if (
                    observed_mount != root_mount
                    or child_metadata.device != root_before.device
                    or _major_minor(child_metadata.device) != root_mount.major_minor
                ):
                    raise PrivateBoundaryError("private tree crosses a mount or device")
            if _metadata(os.fstat(descriptor)) != before:
                raise PrivateBoundaryError("private directory changed during scan")
            _reject_fd_xattrs(descriptor, runtime, "private directory")

        visit(root_descriptor, "")
        root_after = _metadata(os.fstat(root_descriptor))
        if root_after != root_before:
            raise PrivateBoundaryError("private root changed during scan")
        _reject_fd_xattrs(root_descriptor, runtime, "private root")
        record_rank = {path: index for index, path in enumerate(expected_record_paths)}
        records.sort(
            key=lambda row: (
                record_rank.get(str(row["relative_path"]), len(record_rank)),
                str(row["relative_path"]),
            )
        )
        directories.sort(key=lambda row: str(row["relative_path"]))
        if tuple(row["relative_path"] for row in records) != expected_record_paths:
            raise PrivateBoundaryError("private tree contains an unexpected record set")
        expected_directories = _expected_private_directories(expected_record_paths)
        if tuple(row["relative_path"] for row in directories) != expected_directories:
            raise PrivateBoundaryError(
                "private tree contains an unexpected directory set"
            )
        return _TreeObservation(
            root_metadata=root_before,
            mount=root_mount,
            directories=tuple(directories),
            records=tuple(records),
        )
    finally:
        os.close(root_descriptor)


def _mount_object(value: _MountRecord) -> dict[str, object]:
    return {
        "filesystem_type": value.filesystem_type,
        "major_minor": value.major_minor,
        "mount_id": value.mount_id,
        "mount_options": value.mount_options,
        "mount_point": value.mount_point,
        "mount_root": value.mount_root,
        "mount_source": value.mount_source,
        "parent_id": value.parent_id,
        "super_options": value.super_options,
    }


def _namespace_object(value: _NamespaceObservation) -> dict[str, object]:
    return {
        "device": value.device,
        "inode": value.inode,
        "link_sha256": _sha(value.link_text.encode("ascii")),
    }


def _adapter_object(value: _AdapterObservation) -> dict[str, object]:
    return {
        "adapter_mount": _mount_object(value.adapter_mount),
        "device": value.device,
        "extended_attributes_empty": value.extended_attributes_empty,
        "inode": value.inode,
        "link_count": value.link_count,
        "mode": value.mode,
        "owner_uid": value.owner_uid,
        "group_gid": value.group_gid,
        "path": value.path,
        "sha256": value.sha256,
        "size_bytes": value.size_bytes,
        "trusted_ancestors": list(value.trusted_ancestors),
    }


def _registration_probe_payload(
    *,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
    policy_sha256: str,
) -> bytes:
    return _canonical(
        {
            "experiment_attempt_id": experiment_attempt_id,
            "policy_sha256": policy_sha256,
            "protocol": "cohort_structured_private_registration_synthetic_probe_v1",
            "source_commit": source_commit,
            "stage_attempt_id": stage_attempt_id,
            "stage_kind": stage_kind,
        }
    )


def _credential_groups_for_uid(uid: int) -> tuple[int, tuple[int, ...]]:
    if uid in {ATTESTER_UID, PURE_SCORER_UID, PRIVATE_VALIDATOR_UID}:
        return uid, (PRIVATE_READ_GID,)
    if uid == REGISTRAR_UID:
        return PRIVATE_READ_GID, ()
    if uid in {LAUNCHER_UID, OPERATOR_UID}:
        return uid, ()
    raise PrivateBoundaryError("probe target UID has no exact group identity")


def _request(
    probe_id: str,
    target_uid: int,
    operation: str,
    path: str,
    *,
    protocol: str,
    stage: str,
    allowed: bool,
    accepted_errnos: tuple[int, ...],
    policy_sha256: str,
    adapter_sha256: str,
    adapter_device: int,
    adapter_inode: int,
    adapter_size_bytes: int,
    expected_content_sha256: str | None = None,
    absence_receipt: bool = False,
    probe_payload: bytes | None = None,
) -> _ProbeRequest:
    target_gid, target_supplementary_gids = _credential_groups_for_uid(target_uid)
    return _ProbeRequest(
        probe_id=probe_id,
        target_uid=target_uid,
        target_gid=target_gid,
        target_supplementary_gids=target_supplementary_gids,
        operation=operation,
        path=path,
        protocol=protocol,
        stage=stage,
        allowed=allowed,
        accepted_errnos=accepted_errnos,
        access_policy_sha256=policy_sha256,
        adapter_sha256=adapter_sha256,
        adapter_device=adapter_device,
        adapter_inode=adapter_inode,
        adapter_size_bytes=adapter_size_bytes,
        expected_content_sha256=expected_content_sha256,
        absence_receipt=absence_receipt,
        probe_payload=probe_payload,
    )


def _initial_probe_requests(
    *,
    root: str,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
    policy_sha256: str,
    adapter: _AdapterObservation | Mapping[str, object],
) -> tuple[_ProbeRequest, ...]:
    path = str(PurePosixPath(root, _TRANSIENT_PROBE_RELATIVE_PATH))
    payload = _registration_probe_payload(
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        policy_sha256=policy_sha256,
    )
    payload_sha = _sha(payload)
    validator_create_path = str(
        PurePosixPath(root, ".private-boundary-validator-create-probe")
    )
    scorer_create_path = str(
        PurePosixPath(root, ".private-boundary-scorer-create-probe")
    )
    shared = {
        "protocol": INITIAL_ACCESS_PROBE_PROTOCOL,
        "stage": INITIAL_REGISTRATION_STAGE,
        "policy_sha256": policy_sha256,
        "adapter_sha256": str(
            adapter["sha256"] if isinstance(adapter, Mapping) else adapter.sha256
        ),
        "adapter_device": int(
            adapter["device"] if isinstance(adapter, Mapping) else adapter.device
        ),
        "adapter_inode": int(
            adapter["inode"] if isinstance(adapter, Mapping) else adapter.inode
        ),
        "adapter_size_bytes": int(
            adapter["size_bytes"]
            if isinstance(adapter, Mapping)
            else adapter.size_bytes
        ),
    }
    return (
        _request(
            "01_registrar_create_probe",
            REGISTRAR_UID,
            "create_exact_probe",
            path,
            allowed=True,
            accepted_errnos=(0,),
            expected_content_sha256=payload_sha,
            probe_payload=payload,
            **shared,
        ),
        _request(
            "02_registrar_read_probe",
            REGISTRAR_UID,
            "read_exact_probe",
            path,
            allowed=True,
            accepted_errnos=(0,),
            expected_content_sha256=payload_sha,
            **shared,
        ),
        _request(
            "03_private_validator_read_probe",
            PRIVATE_VALIDATOR_UID,
            "read_exact_probe",
            path,
            allowed=True,
            accepted_errnos=(0,),
            expected_content_sha256=payload_sha,
            **shared,
        ),
        _request(
            "04_private_validator_write_denied",
            PRIVATE_VALIDATOR_UID,
            "write_exact_probe",
            path,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "05_private_validator_create_denied",
            PRIVATE_VALIDATOR_UID,
            "create_record",
            validator_create_path,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "06_scorer_read_probe",
            PURE_SCORER_UID,
            "read_exact_probe",
            path,
            allowed=True,
            accepted_errnos=(0,),
            expected_content_sha256=payload_sha,
            **shared,
        ),
        _request(
            "07_scorer_write_denied",
            PURE_SCORER_UID,
            "write_exact_probe",
            path,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "08_scorer_create_denied",
            PURE_SCORER_UID,
            "create_record",
            scorer_create_path,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "09_launcher_enumerate",
            LAUNCHER_UID,
            "enumerate_root",
            root,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "10_launcher_read_probe",
            LAUNCHER_UID,
            "read_exact_probe",
            path,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "11_operator_enumerate",
            OPERATOR_UID,
            "enumerate_root",
            root,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "12_operator_read_probe",
            OPERATOR_UID,
            "read_exact_probe",
            path,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "13_registrar_remove_probe",
            REGISTRAR_UID,
            "remove_exact_probe",
            path,
            allowed=True,
            accepted_errnos=(0,),
            **shared,
        ),
        _request(
            "14_registrar_verify_no_leftover",
            REGISTRAR_UID,
            "verify_probe_absent",
            path,
            allowed=True,
            accepted_errnos=(errno.ENOENT,),
            absence_receipt=True,
            **shared,
        ),
    )


def _sealed_probe_requests(
    *,
    root: str,
    record_relative: str,
    record_sha256: str,
    policy_sha256: str,
    adapter: _AdapterObservation | Mapping[str, object],
) -> tuple[_ProbeRequest, ...]:
    record_path = str(PurePosixPath(root, record_relative))
    transient_path = str(PurePosixPath(root, _TRANSIENT_PROBE_RELATIVE_PATH))
    shared = {
        "protocol": SEALED_ACCESS_PROBE_PROTOCOL,
        "stage": SEALED_PRELAUNCH_STAGE,
        "policy_sha256": policy_sha256,
        "adapter_sha256": str(
            adapter["sha256"] if isinstance(adapter, Mapping) else adapter.sha256
        ),
        "adapter_device": int(
            adapter["device"] if isinstance(adapter, Mapping) else adapter.device
        ),
        "adapter_inode": int(
            adapter["inode"] if isinstance(adapter, Mapping) else adapter.inode
        ),
        "adapter_size_bytes": int(
            adapter["size_bytes"]
            if isinstance(adapter, Mapping)
            else adapter.size_bytes
        ),
    }
    mutation_errnos = tuple(sorted({errno.EACCES, errno.EROFS}))
    return (
        _request(
            "01_private_validator_read_record",
            PRIVATE_VALIDATOR_UID,
            "read_registered_record",
            record_path,
            allowed=True,
            accepted_errnos=(0,),
            expected_content_sha256=record_sha256,
            **shared,
        ),
        _request(
            "02_scorer_read_record",
            PURE_SCORER_UID,
            "read_registered_record",
            record_path,
            allowed=True,
            accepted_errnos=(0,),
            expected_content_sha256=record_sha256,
            **shared,
        ),
        _request(
            "03_registrar_read_record",
            REGISTRAR_UID,
            "read_registered_record",
            record_path,
            allowed=True,
            accepted_errnos=(0,),
            expected_content_sha256=record_sha256,
            **shared,
        ),
        _request(
            "04_launcher_enumerate",
            LAUNCHER_UID,
            "enumerate_root",
            root,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "05_launcher_read_record",
            LAUNCHER_UID,
            "read_registered_record",
            record_path,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "06_operator_enumerate",
            OPERATOR_UID,
            "enumerate_root",
            root,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "07_operator_read_record",
            OPERATOR_UID,
            "read_registered_record",
            record_path,
            allowed=False,
            accepted_errnos=(errno.EACCES,),
            **shared,
        ),
        _request(
            "08_registrar_create_denied",
            REGISTRAR_UID,
            "create_probe_record",
            transient_path,
            allowed=False,
            accepted_errnos=mutation_errnos,
            **shared,
        ),
        _request(
            "09_registrar_write_denied",
            REGISTRAR_UID,
            "write_registered_record",
            record_path,
            allowed=False,
            accepted_errnos=mutation_errnos,
            **shared,
        ),
    )


def _validate_probe(raw: bytes, expected: _ProbeRequest) -> dict[str, object]:
    keys = _ABSENCE_PROBE_KEYS if expected.absence_receipt else _ACCESS_PROBE_KEYS
    value = _object(_parse(raw, f"probe {expected.probe_id}"), keys, "probe")
    common = {
        "access_policy_sha256": expected.access_policy_sha256,
        "adapter_sha256": expected.adapter_sha256,
        "credential_transition": (
            "setgroups_then_setresgid_then_setresuid_no_active_capabilities"
        ),
        "invoking_uid_before_transition": ATTESTER_UID,
        "pre_transition_effective_gid": ATTESTER_UID,
        "pre_transition_effective_uid": 0,
        "pre_transition_real_gid": ATTESTER_UID,
        "pre_transition_real_uid": ATTESTER_UID,
        "pre_transition_saved_gid": ATTESTER_UID,
        "pre_transition_saved_uid": 0,
        "observed_active_capabilities_empty": True,
        "observed_all_capability_sets_zero": True,
        "observed_effective_gid": expected.target_gid,
        "observed_effective_uid": expected.target_uid,
        "observed_real_gid": expected.target_gid,
        "observed_real_uid": expected.target_uid,
        "observed_saved_gid": expected.target_gid,
        "observed_saved_uid": expected.target_uid,
        "observed_supplementary_gids": list(expected.target_supplementary_gids),
        "observed_no_new_privs": True,
        "observed_securebits": _LOCKED_SECUREBITS,
        "self_executable_device": expected.adapter_device,
        "self_executable_inode": expected.adapter_inode,
        "self_executable_sha256": expected.adapter_sha256,
        "self_executable_size_bytes": expected.adapter_size_bytes,
        "operation": expected.operation,
        "path": expected.path,
        "probe_id": expected.probe_id,
        "protocol": expected.protocol,
        "schema_version": PROBE_SCHEMA_VERSION,
        "stage": expected.stage,
        "target_gid": expected.target_gid,
        "target_supplementary_gids": list(expected.target_supplementary_gids),
        "target_uid": expected.target_uid,
    }
    if any(value[key] != expected_value for key, expected_value in common.items()):
        raise PrivateBoundaryError(f"access probe differs: {expected.probe_id}")
    raw_errno = value["raw_errno"]
    if type(raw_errno) is not int or raw_errno not in expected.accepted_errnos:
        raise PrivateBoundaryError(
            f"access probe raw errno differs: {expected.probe_id}"
        )
    if expected.absence_receipt:
        if value["absent"] is not True or raw_errno != errno.ENOENT:
            raise PrivateBoundaryError("registrar no-leftover receipt differs")
    elif (
        value["allowed"] is not expected.allowed
        or value["content_sha256"] != expected.expected_content_sha256
    ):
        raise PrivateBoundaryError(f"access probe outcome differs: {expected.probe_id}")
    return value


def _validate_trusted_ancestors(value: object) -> tuple[dict[str, object], ...]:
    if type(value) is not list or not value:
        raise PrivateBoundaryError("setuid adapter ancestor inventory differs")
    expected_paths: list[str] = ["/"]
    current = PurePosixPath("/")
    for component in SETUID_ADAPTER_PATH.parent.parts[1:]:
        current /= component
        expected_paths.append(str(current))
    rows: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        row = _object(raw, _TRUSTED_ANCESTOR_KEYS, f"adapter ancestor[{index}]")
        if (
            row["path"] != expected_paths[index]
            if index < len(expected_paths)
            else True
        ):
            raise PrivateBoundaryError("setuid adapter ancestor path differs")
        mode = row["mode"]
        if (
            type(row["device"]) is not int
            or row["device"] < 0
            or type(row["inode"]) is not int
            or row["inode"] <= 0
            or type(mode) is not int
            or mode < 0
            or mode > 0o7777
            or mode & 0o022
            or row["owner_uid"] != 0
            or type(row["group_gid"]) is not int
            or row["group_gid"] < 0
        ):
            raise PrivateBoundaryError("setuid adapter ancestor trust differs")
        rows.append(row)
    if len(rows) != len(expected_paths):
        raise PrivateBoundaryError("setuid adapter ancestor closure differs")
    return tuple(rows)


def _validate_adapter_mount(value: object, *, device: int) -> dict[str, Any]:
    mount = _object(value, _MOUNT_KEYS, "setuid adapter mount")
    if mount["mount_point"] == "/":
        mount_point = "/"
    else:
        mount_point = _normalized_absolute_text(
            mount["mount_point"], "setuid adapter mount point"
        )
    mount_options = (
        set(mount["mount_options"].split(","))
        if type(mount["mount_options"]) is str
        else set()
    )
    super_options = (
        set(mount["super_options"].split(","))
        if type(mount["super_options"]) is str
        else set()
    )
    if (
        not _path_within(str(SETUID_ADAPTER_PATH), mount_point)
        or "nosuid" in mount_options
        or "nosuid" in super_options
        or mount["major_minor"] != _major_minor(device)
        or type(mount["mount_id"]) is not int
        or mount["mount_id"] <= 0
        or type(mount["parent_id"]) is not int
        or mount["parent_id"] < 0
        or any(
            type(mount[key]) is not str or not mount[key]
            for key in (
                "filesystem_type",
                "major_minor",
                "mount_root",
                "mount_source",
                "mount_options",
                "super_options",
            )
        )
    ):
        raise PrivateBoundaryError("setuid adapter mount is not suid-enabled")
    return mount


def _validate_adapter(value: _AdapterObservation) -> None:
    if (
        value.path != str(SETUID_ADAPTER_PATH)
        or type(value.device) is not int
        or value.device < 0
        or type(value.inode) is not int
        or value.inode <= 0
        or value.mode != 0o4750
        or value.owner_uid != 0
        or value.group_gid != ATTESTER_UID
        or value.link_count != 1
        or value.extended_attributes_empty is not True
        or _SHA_RE.fullmatch(value.sha256) is None
        or type(value.size_bytes) is not int
        or value.size_bytes <= 0
    ):
        raise PrivateBoundaryError("fixed setuid adapter binding differs")
    _validate_trusted_ancestors(list(value.trusted_ancestors))
    _validate_adapter_mount(_mount_object(value.adapter_mount), device=value.device)


def _validate_open_adapter_handle(
    handle: _VerifiedAdapterHandle, runtime: _PrivateBoundaryRuntime
) -> _AdapterObservation:
    if type(handle) is not _VerifiedAdapterHandle:
        raise PrivateBoundaryError("verified adapter handle differs")
    observation = handle.observation
    _validate_adapter(observation)
    if handle.close_descriptor:
        if type(handle.descriptor) is not int or handle.descriptor <= 2:
            raise PrivateBoundaryError("verified adapter descriptor differs")
        try:
            metadata = os.fstat(handle.descriptor)
        except OSError as exc:
            raise PrivateBoundaryError("verified adapter descriptor is closed") from exc
        if (
            metadata.st_dev != observation.device
            or metadata.st_ino != observation.inode
            or stat.S_IMODE(metadata.st_mode) != observation.mode
            or metadata.st_uid != observation.owner_uid
            or metadata.st_gid != observation.group_gid
            or metadata.st_size != observation.size_bytes
            or metadata.st_nlink != observation.link_count
            or runtime.xattrs_for_fd(handle.descriptor)
            or _hash_open_descriptor(handle.descriptor, metadata.st_size)
            != observation.sha256
        ):
            raise PrivateBoundaryError("verified adapter descriptor binding drifted")
    return observation


def _validate_runtime_identity(runtime: _PrivateBoundaryRuntime) -> _ProcessObservation:
    _assert_distinct_identities()
    euid = runtime.euid()
    if type(euid) is not int or euid != ATTESTER_UID:
        raise PrivateBoundaryError("private-boundary attester requires exact euid")
    if runtime.identity_for_uid(euid) != ATTESTER_SERVICE_IDENTITY:
        raise PrivateBoundaryError("private-boundary attester identity differs")
    process = runtime.process_identity()
    if (
        process.real_uid != ATTESTER_UID
        or process.effective_uid != ATTESTER_UID
        or process.saved_uid != ATTESTER_UID
        or process.real_gid != ATTESTER_UID
        or process.effective_gid != ATTESTER_UID
        or process.saved_gid != ATTESTER_UID
        or process.supplementary_gids != (PRIVATE_READ_GID,)
        or process.active_capabilities_empty is not True
        or process.service_identity != ATTESTER_SERVICE_IDENTITY
        or process.pid <= 0
        or process.process_start_ticks <= 0
    ):
        raise PrivateBoundaryError(
            "private-boundary attester UID/GID/group identity differs"
        )
    return process


def _validate_root_grammars(
    public_root: Path,
    private_root: Path,
    *,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
    production: bool,
) -> None:
    public_match = _PRODUCTION_PUBLIC_RE.fullmatch(str(public_root))
    private_match = _PRODUCTION_PRIVATE_RE.fullmatch(str(private_root))
    if production:
        if (
            public_match is None
            or private_match is None
            or public_match.group("commit") != source_commit
            or private_match.group("commit") != source_commit
            or public_match.group("experiment") != experiment_attempt_id
            or private_match.group("experiment") != experiment_attempt_id
            or public_match.group("stage_kind") != stage_kind
            or private_match.group("stage_kind") != stage_kind
            or public_match.group("stage_attempt") != stage_attempt_id
            or private_match.group("stage_attempt") != stage_attempt_id
        ):
            raise PrivateBoundaryError("production private/public root grammar differs")
    elif (
        public_match is not None
        or private_match is not None
        or _path_within(str(public_root), _PRODUCTION_PUBLIC_PREFIX)
        or _path_within(str(private_root), _PRODUCTION_PRIVATE_PREFIX)
    ):
        raise PrivateBoundaryError("test helper rejects production root grammar")
    if _path_within(str(private_root), str(public_root)) or _path_within(
        str(public_root), str(private_root)
    ):
        raise PrivateBoundaryError("private and public roots must be external")


def _source_object(path: str, raw: bytes) -> dict[str, object]:
    return {"path": path, "sha256": _sha(raw), "size_bytes": len(raw)}


def _validate_source_binding(
    value: object,
    *,
    raw: object,
    label: str,
    required_suffix: str,
) -> None:
    source = _object(value, _SOURCE_KEYS, label)
    source_raw = raw if type(raw) is bytes else b""
    if (
        type(source["path"]) is not str
        or not source["path"].endswith(required_suffix)
        or source["sha256"] != _sha(source_raw)
        or source["size_bytes"] != len(source_raw)
        or not source_raw
    ):
        raise PrivateBoundaryError(f"{label} raw-byte binding differs")


def _validate_registry_completion_receipt_bytes(
    raw: object,
    *,
    registrar_source_bytes: object,
) -> _RegistryCompletionValidation:
    value = _object(
        _parse(raw, "registry completion receipt"),
        _REGISTRY_KEYS,
        "registry completion receipt",
    )
    _require_authority_false(value)
    if (
        value["protocol"] != REGISTRY_COMPLETION_PROTOCOL
        or value["schema_version"] != REGISTRY_COMPLETION_SCHEMA_VERSION
        or value["status"] != REGISTRY_COMPLETION_STATUS
    ):
        raise PrivateBoundaryError("registry completion protocol differs")
    source_commit = value["source_commit"]
    experiment_attempt_id = value["experiment_attempt_id"]
    stage_kind = value["stage_kind"]
    stage_attempt_id = value["stage_attempt_id"]
    if (
        type(source_commit) is not str
        or _COMMIT_RE.fullmatch(source_commit) is None
        or type(experiment_attempt_id) is not str
        or _ATTEMPT_RE.fullmatch(experiment_attempt_id) is None
        or type(stage_kind) is not str
        or stage_kind not in _STAGE_SHAPES
        or type(stage_attempt_id) is not str
        or _STAGE_ATTEMPT_RE.fullmatch(stage_attempt_id) is None
    ):
        raise PrivateBoundaryError("registry completion source/attempt differs")
    private_root = _normalized_absolute_text(
        value["private_context_root"], "registry private context root"
    )
    initial_sha = value["initial_registration_attestation_sha256"]
    if type(initial_sha) is not str or _SHA_RE.fullmatch(initial_sha) is None:
        raise PrivateBoundaryError("registry completion initial binding differs")
    if (
        type(value["boot_id"]) is not str
        or _BOOT_ID_RE.fullmatch(value["boot_id"]) is None
    ):
        raise PrivateBoundaryError("registry completion boot id differs")
    _validate_process(
        value["process_identity"],
        uid=REGISTRAR_UID,
        gid=PRIVATE_READ_GID,
        supplementary_gids=(),
        identity=REGISTRAR_SERVICE_IDENTITY,
    )
    _utc(value["completed_at_utc"], "registry completed_at_utc")
    _validate_source_binding(
        value["registrar_source"],
        raw=registrar_source_bytes,
        label="registrar source",
        required_suffix="/cohort_closed_loop_structured_context_registrar.py",
    )
    _normalized_absolute_text(
        value["registrar_source"]["path"], "registrar source path"
    )
    rows_value = value["registered_records"]
    if type(rows_value) is not list or not rows_value:
        raise PrivateBoundaryError("registry completion records must be nonempty")
    rows: list[_RegisteredRecord] = []
    canonical_rows: list[dict[str, object]] = []
    for index, raw_row in enumerate(rows_value):
        row = _object(raw_row, _REGISTERED_RECORD_KEYS, f"registered record[{index}]")
        record_stage = row["stage_kind"]
        block_id = row["block_id"]
        block_index = row["block_index"]
        phase = row["phase"]
        item_id = row["item_id"]
        instance_index = row["instance_index"]
        instance_id = row["instance_id"]
        public_identity = row["public_context_identity_sha256"]
        opaque_handle = row["opaque_handle_sha256"]
        relative = _relative(
            row["relative_path"], f"registered record[{index}].relative_path"
        )
        hidden_sha256 = row["hidden_sha256"]
        size_bytes = row["size_bytes"]
        if (
            record_stage != stage_kind
            or type(block_id) is not str
            or _SAFE_ID_RE.fullmatch(block_id) is None
            or type(block_index) is not int
            or block_index < 0
            or block_index > 99
            or block_id != f"{stage_kind}_block_{block_index + 1:02d}"
            or phase not in {"adaptation", "held_out"}
            or type(item_id) is not int
            or item_id < 1
            or type(instance_index) is not int
            or instance_index != item_id - 1
            or type(instance_id) is not str
            or _SAFE_ID_RE.fullmatch(instance_id) is None
            or type(public_identity) is not str
            or _SHA_RE.fullmatch(public_identity) is None
            or type(opaque_handle) is not str
            or _SHA_RE.fullmatch(opaque_handle) is None
            or type(hidden_sha256) is not str
            or _SHA_RE.fullmatch(hidden_sha256) is None
            or type(size_bytes) is not int
            or size_bytes < 0
            or relative != f"records/{block_id}/{phase}/{item_id}.json"
        ):
            raise PrivateBoundaryError(
                "registered record identity/path/digest/size differs"
            )
        registered = _RegisteredRecord(
            stage_kind=record_stage,
            block_id=block_id,
            block_index=block_index,
            phase=phase,
            item_id=item_id,
            instance_index=instance_index,
            instance_id=instance_id,
            public_context_identity_sha256=public_identity,
            opaque_handle_sha256=opaque_handle,
            relative_path=relative,
            hidden_sha256=hidden_sha256,
            size_bytes=size_bytes,
        )
        rows.append(registered)
        canonical_rows.append(registered.to_object())
    relative_paths = [row.relative_path for row in rows]
    semantic_keys = [
        (
            row.stage_kind,
            row.block_id,
            row.block_index,
            row.phase,
            row.item_id,
            row.instance_index,
            row.instance_id,
        )
        for row in rows
    ]
    block_pairs = {(row.block_id, row.block_index) for row in rows}
    block_count, items_per_phase = _STAGE_SHAPES[stage_kind]
    expected_coordinates = [
        (
            stage_kind,
            f"{stage_kind}_block_{block_index + 1:02d}",
            block_index,
            phase,
            item_id,
            item_id - 1,
        )
        for block_index in range(block_count)
        for phase in ("adaptation", "held_out")
        for item_id in range(1, items_per_phase + 1)
    ]
    observed_coordinates = [
        (
            row.stage_kind,
            row.block_id,
            row.block_index,
            row.phase,
            row.item_id,
            row.instance_index,
        )
        for row in rows
    ]
    if (
        tuple(row.sort_key for row in rows)
        != tuple(sorted(row.sort_key for row in rows))
        or len(relative_paths) != len(set(relative_paths))
        or semantic_keys != sorted(set(semantic_keys))
        or len({row.block_id for row in rows}) != len(block_pairs)
        or len({row.block_index for row in rows}) != len(block_pairs)
        or observed_coordinates != expected_coordinates
        or len({row.public_context_identity_sha256 for row in rows}) != len(rows)
        or len({row.opaque_handle_sha256 for row in rows}) != len(rows)
        or type(value["registered_record_count"]) is not int
        or value["registered_record_count"] != len(rows)
    ):
        raise PrivateBoundaryError(
            "registered records must be fully sorted, unique, and count-bound"
        )
    if value["record_set_sha256"] != _sha(_canonical(canonical_rows)):
        raise PrivateBoundaryError("registry completion record-set digest differs")
    expected_self = _sha(
        _canonical({key: value[key] for key in _REGISTRY_UNSIGNED_KEYS})
    )
    if value["registry_completion_receipt_sha256"] != expected_self:
        raise PrivateBoundaryError("registry completion self digest differs")
    return _RegistryCompletionValidation(
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        private_context_root=private_root,
        initial_registration_attestation_sha256=initial_sha,
        registry_completion_receipt_sha256=expected_self,
        completed_at_utc=value["completed_at_utc"],
        boot_id=value["boot_id"],
        registered_records=tuple(rows),
    )


def _validate_identity_inventory(
    value: object,
    *,
    root_device: int,
    allow_empty_records: bool,
    stage_kind: str,
) -> tuple[tuple[str, ...], tuple[tuple[str, int], ...]]:
    inventory = _object(value, _INVENTORY_KEYS, "record inventory")
    directories_value = inventory["directories"]
    records_value = inventory["records"]
    if type(directories_value) is not list or type(records_value) is not list:
        raise PrivateBoundaryError("record inventory rows must be exact lists")
    directories: list[str] = []
    for index, raw in enumerate(directories_value):
        row = _object(raw, _DIRECTORY_RECORD_KEYS, f"directory[{index}]")
        relative = _relative(row["relative_path"], f"directory[{index}].relative_path")
        if (
            _exact_int(row["device"], f"directory[{index}].device") != root_device
            or _exact_int(row["inode"], f"directory[{index}].inode", minimum=1) <= 0
            or row["mode"] != 0o750
            or row["owner_uid"] != REGISTRAR_UID
            or row["group_gid"] != PRIVATE_READ_GID
        ):
            raise PrivateBoundaryError("private directory inventory differs")
        directories.append(relative)
    records: list[tuple[str, int]] = []
    for index, raw in enumerate(records_value):
        row = _object(raw, _FILE_RECORD_KEYS, f"record[{index}]")
        relative = _relative(row["relative_path"], f"record[{index}].relative_path")
        size_bytes = _exact_int(row["size_bytes"], f"record[{index}].size_bytes")
        if (
            _exact_int(row["device"], f"record[{index}].device") != root_device
            or _exact_int(row["inode"], f"record[{index}].inode", minimum=1) <= 0
            or row["mode"] != 0o440
            or row["owner_uid"] != REGISTRAR_UID
            or row["group_gid"] != PRIVATE_READ_GID
            or row["link_count"] != 1
        ):
            raise PrivateBoundaryError("private record inventory differs")
        records.append((relative, size_bytes))
    record_paths = [row[0] for row in records]
    expected_directories = _expected_private_directories(tuple(record_paths))
    if (
        directories != sorted(set(directories))
        or tuple(directories) != expected_directories
        or records
        != sorted(
            records,
            key=lambda row: _private_record_coordinate(row[0], stage_kind=stage_kind),
        )
        or len(record_paths) != len(set(record_paths))
        or inventory["record_count"] != len(records)
        or (not allow_empty_records and not records)
    ):
        raise PrivateBoundaryError("private record inventory closure differs")
    return tuple(directories), tuple(records)


def _validate_content_inventory(
    value: object,
    *,
    identity_inventory: Mapping[str, object],
    root_device: int,
) -> tuple[dict[str, object], ...]:
    if type(value) is not list:
        raise PrivateBoundaryError("record content inventory must be an exact list")
    identity_rows_raw = identity_inventory.get("records")
    if type(identity_rows_raw) is not list:
        raise PrivateBoundaryError("identity inventory records differ")
    identity_by_path: dict[str, dict[str, object]] = {}
    identity_order: list[str] = []
    for index, raw_identity in enumerate(identity_rows_raw):
        identity = _object(raw_identity, _FILE_RECORD_KEYS, f"identity record[{index}]")
        relative = _relative(
            identity["relative_path"], f"identity record[{index}].relative_path"
        )
        identity_by_path[relative] = identity
        identity_order.append(relative)
    rows: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        row = _object(raw, _CONTENT_RECORD_KEYS, f"content record[{index}]")
        relative = _relative(row["path"], f"content record[{index}].path")
        identity = identity_by_path.get(relative)
        if (
            identity is None
            or row["device"] != root_device
            or row["device"] != identity["device"]
            or row["inode"] != identity["inode"]
            or row["size_bytes"] != identity["size_bytes"]
            or type(row["hidden_sha256"]) is not str
            or _SHA_RE.fullmatch(row["hidden_sha256"]) is None
        ):
            raise PrivateBoundaryError("record content inventory identity differs")
        rows.append(row)
    if [row["path"] for row in rows] != identity_order or len(rows) != len(
        identity_by_path
    ):
        raise PrivateBoundaryError("record content inventory closure differs")
    return tuple(rows)


def _validate_mount_object(
    value: object,
    *,
    private_root: str,
    root_device: int,
    stage: str,
) -> dict[str, Any]:
    mount = _object(value, _MOUNT_KEYS, "private mount")
    mount_point = _normalized_absolute_text(mount["mount_point"], "mount point")
    required = "rw" if stage == INITIAL_REGISTRATION_STAGE else "ro"
    forbidden = "ro" if required == "rw" else "rw"
    mount_options = (
        set(mount["mount_options"].split(","))
        if type(mount["mount_options"]) is str
        else set()
    )
    super_options = (
        set(mount["super_options"].split(","))
        if type(mount["super_options"]) is str
        else set()
    )
    if (
        mount_point != private_root
        or mount["major_minor"] != _major_minor(root_device)
        or required not in mount_options
        or required not in super_options
        or forbidden in mount_options
        or forbidden in super_options
        or type(mount["mount_id"]) is not int
        or mount["mount_id"] <= 0
        or type(mount["parent_id"]) is not int
        or mount["parent_id"] < 0
        or any(
            type(mount[key]) is not str or not mount[key]
            for key in (
                "filesystem_type",
                "major_minor",
                "mount_root",
                "mount_source",
                "mount_options",
                "super_options",
            )
        )
    ):
        raise PrivateBoundaryError(
            f"private dedicated {required} mount binding differs"
        )
    return mount


def _validate_namespace(value: object) -> dict[str, Any]:
    namespace = _object(value, _NAMESPACE_KEYS, "mount namespace")
    if (
        type(namespace["device"]) is not int
        or namespace["device"] < 0
        or type(namespace["inode"]) is not int
        or namespace["inode"] <= 0
        or type(namespace["link_sha256"]) is not str
        or _SHA_RE.fullmatch(namespace["link_sha256"]) is None
    ):
        raise PrivateBoundaryError("mount namespace binding differs")
    return namespace


def _validate_process(
    value: object,
    *,
    uid: int,
    gid: int,
    supplementary_gids: tuple[int, ...],
    identity: str,
) -> dict[str, Any]:
    process = _object(value, _PROCESS_KEYS, "process identity")
    if (
        process["real_uid"] != uid
        or process["effective_uid"] != uid
        or process["saved_uid"] != uid
        or process["real_gid"] != gid
        or process["effective_gid"] != gid
        or process["saved_gid"] != gid
        or process["supplementary_gids"] != list(supplementary_gids)
        or process["active_capabilities_empty"] is not True
        or process["service_identity"] != identity
        or type(process["pid"]) is not int
        or process["pid"] <= 0
        or type(process["process_start_ticks"]) is not int
        or process["process_start_ticks"] <= 0
    ):
        raise PrivateBoundaryError("process identity binding differs")
    return process


def _validate_adapter_object(value: object) -> dict[str, Any]:
    adapter = _object(value, _ADAPTER_KEYS, "setuid adapter")
    if (
        adapter["path"] != str(SETUID_ADAPTER_PATH)
        or adapter["mode"] != 0o4750
        or adapter["owner_uid"] != 0
        or adapter["group_gid"] != ATTESTER_UID
        or adapter["link_count"] != 1
        or adapter["extended_attributes_empty"] is not True
        or type(adapter["device"]) is not int
        or adapter["device"] < 0
        or type(adapter["inode"]) is not int
        or adapter["inode"] <= 0
        or type(adapter["sha256"]) is not str
        or _SHA_RE.fullmatch(adapter["sha256"]) is None
        or type(adapter["size_bytes"]) is not int
        or adapter["size_bytes"] <= 0
    ):
        raise PrivateBoundaryError("setuid adapter binding differs")
    _validate_trusted_ancestors(adapter["trusted_ancestors"])
    _validate_adapter_mount(adapter["adapter_mount"], device=adapter["device"])
    return adapter


def _validate_probe_bindings(
    value: object,
    *,
    access_probe_receipts_by_id: Mapping[str, object],
    requests: tuple[_ProbeRequest, ...],
) -> None:
    if not isinstance(access_probe_receipts_by_id, Mapping):
        raise PrivateBoundaryError("access probe receipt map differs")
    if set(access_probe_receipts_by_id) != {row.probe_id for row in requests}:
        raise PrivateBoundaryError("access probe receipt role set differs")
    bindings = value
    if type(bindings) is not list or len(bindings) != len(requests):
        raise PrivateBoundaryError("access probe binding count differs")
    sorted_requests = tuple(sorted(requests, key=lambda row: row.probe_id))
    for index, request in enumerate(sorted_requests):
        probe_raw = access_probe_receipts_by_id[request.probe_id]
        if type(probe_raw) is not bytes:
            raise PrivateBoundaryError("access probe receipt must be exact bytes")
        _validate_probe(probe_raw, request)
        binding = _object(
            bindings[index], _PROBE_BINDING_KEYS, f"probe binding[{index}]"
        )
        relative_path = _probe_receipt_relative_path(request.stage, request.probe_id)
        intent_relative, pending_relative = publication_sidecar_relative_paths(
            relative_path
        )
        intent_raw = _atomic_intent_bytes(relative_path, probe_raw)
        if (
            binding["probe_id"] != request.probe_id
            or binding["artifact_relative_path"] != relative_path
            or binding["artifact_sha256"] != _sha(probe_raw)
            or binding["artifact_size_bytes"] != len(probe_raw)
            or binding["artifact_mode"] != 0o444
            or type(binding["artifact_device"]) is not int
            or binding["artifact_device"] < 0
            or type(binding["artifact_inode"]) is not int
            or binding["artifact_inode"] <= 0
            or binding["intent_relative_path"] != intent_relative
            or binding["intent_sha256"] != _sha(intent_raw)
            or binding["intent_size_bytes"] != len(intent_raw)
            or binding["pending_relative_path"] != pending_relative
            or binding["pending_absent"] is not True
        ):
            raise PrivateBoundaryError(
                "access probe durable publication binding differs"
            )


def _validate_common_attestation(
    value: dict[str, Any],
    *,
    stage: str,
    access_probe_receipts_by_id: Mapping[str, object],
    attester_source_bytes: object,
    access_probe_source_bytes: object,
    validation_time_utc: object,
) -> tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    int,
    dict[str, Any],
    dict[str, Any],
    tuple[tuple[str, int], ...],
    tuple[dict[str, object], ...],
    dict[str, Any],
    datetime,
    datetime,
    datetime,
]:
    _require_authority_false(value)
    expected_protocol = (
        INITIAL_REGISTRATION_PROTOCOL
        if stage == INITIAL_REGISTRATION_STAGE
        else SEALED_PRELAUNCH_PROTOCOL
    )
    expected_schema = (
        INITIAL_SCHEMA_VERSION
        if stage == INITIAL_REGISTRATION_STAGE
        else SEALED_SCHEMA_VERSION
    )
    expected_status = (
        INITIAL_STATUS if stage == INITIAL_REGISTRATION_STAGE else SEALED_STATUS
    )
    if (
        value["protocol"] != expected_protocol
        or value["schema_version"] != expected_schema
        or value["status"] != expected_status
        or value["stage"] != stage
    ):
        raise PrivateBoundaryError("private boundary stage protocol differs")
    source_commit = value["source_commit"]
    experiment_attempt_id = value["experiment_attempt_id"]
    stage_kind = value["stage_kind"]
    stage_attempt_id = value["stage_attempt_id"]
    if (
        type(source_commit) is not str
        or _COMMIT_RE.fullmatch(source_commit) is None
        or type(experiment_attempt_id) is not str
        or _ATTEMPT_RE.fullmatch(experiment_attempt_id) is None
        or type(stage_kind) is not str
        or stage_kind not in _STAGE_SHAPES
        or type(stage_attempt_id) is not str
        or _STAGE_ATTEMPT_RE.fullmatch(stage_attempt_id) is None
    ):
        raise PrivateBoundaryError("private boundary source/stage namespace differs")
    public_root = _normalized_absolute_text(
        value["public_durable_root"], "public durable root"
    )
    root_identity = _object(
        value["private_context_root_identity"],
        _ROOT_IDENTITY_KEYS,
        "private root identity",
    )
    private_root = _normalized_absolute_text(
        root_identity["private_context_root"], "private context root"
    )
    if _path_within(private_root, public_root) or _path_within(
        public_root, private_root
    ):
        raise PrivateBoundaryError("private/public root separation differs")
    root_device = _exact_int(root_identity["device"], "private root device")
    if (
        _exact_int(root_identity["inode"], "private root inode", minimum=1) <= 0
        or root_identity["mode"] != 0o750
        or root_identity["owner_uid"] != REGISTRAR_UID
        or root_identity["group_gid"] != PRIVATE_READ_GID
    ):
        raise PrivateBoundaryError("private root identity differs")
    _assert_distinct_identities()
    if value["service_identities"] != _service_identities():
        raise PrivateBoundaryError("private service identities differ")
    policy = _access_policy(stage)
    policy_sha = _sha(_canonical(policy))
    if value["access_policy"] != policy or value["access_policy_sha256"] != policy_sha:
        raise PrivateBoundaryError("private access policy differs")
    mount = _validate_mount_object(
        value["private_mount"],
        private_root=private_root,
        root_device=root_device,
        stage=stage,
    )
    namespace = _validate_namespace(value["mount_namespace"])
    inventory = _object(value["record_inventory"], _INVENTORY_KEYS, "record inventory")
    _, records = _validate_identity_inventory(
        inventory,
        root_device=root_device,
        allow_empty_records=stage == INITIAL_REGISTRATION_STAGE,
        stage_kind=stage_kind,
    )
    if value["record_inventory_sha256"] != _sha(_canonical(inventory)):
        raise PrivateBoundaryError("record inventory digest differs")
    content_inventory = _validate_content_inventory(
        value["record_content_inventory"],
        identity_inventory=inventory,
        root_device=root_device,
    )
    if value["record_content_inventory_sha256"] != _sha(
        _canonical(list(content_inventory))
    ):
        raise PrivateBoundaryError("record content inventory digest differs")
    if value["transient_probe_relative_path"] != _TRANSIENT_PROBE_RELATIVE_PATH:
        raise PrivateBoundaryError("transient registration probe path differs")
    _validate_source_binding(
        value["attester_source"],
        raw=attester_source_bytes,
        label="attester source",
        required_suffix="/cohort_closed_loop_structured_private_boundary.py",
    )
    _validate_source_binding(
        value["access_probe_source"],
        raw=access_probe_source_bytes,
        label="access probe source",
        required_suffix="/cohort_closed_loop_private_access_probe.c",
    )
    adapter = _validate_adapter_object(value["setuid_adapter"])
    if (
        type(value["boot_id"]) is not str
        or _BOOT_ID_RE.fullmatch(value["boot_id"]) is None
    ):
        raise PrivateBoundaryError("boot id binding differs")
    _validate_process(
        value["process_identity"],
        uid=ATTESTER_UID,
        gid=ATTESTER_UID,
        supplementary_gids=(PRIVATE_READ_GID,),
        identity=ATTESTER_SERVICE_IDENTITY,
    )
    started = _utc(value["probe_started_at_utc"], "probe_started_at_utc")
    completed = _utc(value["probe_completed_at_utc"], "probe_completed_at_utc")
    validation_time = _utc(validation_time_utc, "validation_time_utc")
    if (
        completed < started
        or (completed - started).total_seconds() > MAX_FRESH_SECONDS
        or validation_time < completed
    ):
        raise PrivateBoundaryError("private-boundary timestamp order differs")
    return (
        source_commit,
        experiment_attempt_id,
        stage_kind,
        stage_attempt_id,
        public_root,
        private_root,
        root_device,
        mount,
        namespace,
        records,
        content_inventory,
        adapter,
        started,
        completed,
        validation_time,
    )


def validate_initial_registration_boundary_bytes(
    raw: object,
    *,
    access_probe_receipts_by_id: Mapping[str, object],
    attester_source_bytes: object,
    access_probe_source_bytes: object,
    validation_time_utc: object,
) -> PrivateBoundaryValidation:
    """Purely validate the RW registration boundary; it is not a launch gate."""

    attestation_raw = raw if type(raw) is bytes else b""
    value = _object(
        _parse(attestation_raw, "initial registration boundary"),
        _INITIAL_KEYS,
        "initial registration boundary",
    )
    (
        source_commit,
        experiment_attempt_id,
        stage_kind,
        stage_attempt_id,
        _public_root,
        private_root,
        _root_device,
        _mount,
        _namespace,
        records,
        content_records,
        adapter,
        _started,
        _completed,
        _validation_time,
    ) = _validate_common_attestation(
        value,
        stage=INITIAL_REGISTRATION_STAGE,
        access_probe_receipts_by_id=access_probe_receipts_by_id,
        attester_source_bytes=attester_source_bytes,
        access_probe_source_bytes=access_probe_source_bytes,
        validation_time_utc=validation_time_utc,
    )
    inventory = value["record_inventory"]
    if inventory["directories"] or records or content_records:
        raise PrivateBoundaryError("initial registration root must be exactly empty")
    policy_sha = _sha(_canonical(_access_policy(INITIAL_REGISTRATION_STAGE)))
    requests = _initial_probe_requests(
        root=private_root,
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        policy_sha256=policy_sha,
        adapter=adapter,
    )
    _validate_probe_bindings(
        value["access_probe_receipts"],
        access_probe_receipts_by_id=access_probe_receipts_by_id,
        requests=requests,
    )
    expected_self = _sha(
        _canonical({key: value[key] for key in _INITIAL_UNSIGNED_KEYS})
    )
    if value["private_boundary_attestation_sha256"] != expected_self:
        raise PrivateBoundaryError("initial registration boundary self digest differs")
    return PrivateBoundaryValidation(
        stage=INITIAL_REGISTRATION_STAGE,
        protocol=INITIAL_REGISTRATION_PROTOCOL,
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        private_context_root=private_root,
        private_boundary_attestation_sha256=expected_self,
        access_policy_sha256=policy_sha,
        record_inventory_sha256=value["record_inventory_sha256"],
        initial_registration_attestation_sha256=None,
        registry_completion_receipt_sha256=None,
        fresh_until_utc=None,
    )


def validate_sealed_prelaunch_boundary_bytes(
    raw: object,
    *,
    access_probe_receipts_by_id: Mapping[str, object],
    attester_source_bytes: object,
    access_probe_source_bytes: object,
    validation_time_utc: object,
    initial_registration_attestation_bytes: object,
    initial_access_probe_receipts_by_id: Mapping[str, object],
    registry_completion_receipt_bytes: object,
    registrar_source_bytes: object,
) -> PrivateBoundaryValidation:
    """Purely validate the fresh, RO, state-bound prelaunch boundary."""

    attestation_raw = raw if type(raw) is bytes else b""
    value = _object(
        _parse(attestation_raw, "sealed prelaunch boundary"),
        _SEALED_KEYS,
        "sealed prelaunch boundary",
    )
    (
        source_commit,
        experiment_attempt_id,
        stage_kind,
        stage_attempt_id,
        public_root,
        private_root,
        root_device,
        mount,
        namespace,
        records,
        content_records,
        adapter,
        started,
        completed,
        validation_time,
    ) = _validate_common_attestation(
        value,
        stage=SEALED_PRELAUNCH_STAGE,
        access_probe_receipts_by_id=access_probe_receipts_by_id,
        attester_source_bytes=attester_source_bytes,
        access_probe_source_bytes=access_probe_source_bytes,
        validation_time_utc=validation_time_utc,
    )

    initial = validate_initial_registration_boundary_bytes(
        initial_registration_attestation_bytes,
        access_probe_receipts_by_id=initial_access_probe_receipts_by_id,
        attester_source_bytes=attester_source_bytes,
        access_probe_source_bytes=access_probe_source_bytes,
        validation_time_utc=value["probe_started_at_utc"],
    )
    initial_raw = (
        initial_registration_attestation_bytes
        if type(initial_registration_attestation_bytes) is bytes
        else b""
    )
    initial_value = _object(
        _parse(initial_raw, "bound initial registration boundary"),
        _INITIAL_KEYS,
        "bound initial registration boundary",
    )
    registry = _validate_registry_completion_receipt_bytes(
        registry_completion_receipt_bytes,
        registrar_source_bytes=registrar_source_bytes,
    )
    if (
        initial.source_commit != source_commit
        or initial.experiment_attempt_id != experiment_attempt_id
        or initial.stage_kind != stage_kind
        or initial.stage_attempt_id != stage_attempt_id
        or initial.private_context_root != private_root
        or initial_value["public_durable_root"] != public_root
        or value["initial_registration_attestation_sha256"]
        != initial.private_boundary_attestation_sha256
        or registry.source_commit != source_commit
        or registry.experiment_attempt_id != experiment_attempt_id
        or registry.stage_kind != stage_kind
        or registry.stage_attempt_id != stage_attempt_id
        or registry.private_context_root != private_root
        or registry.initial_registration_attestation_sha256
        != initial.private_boundary_attestation_sha256
        or value["registry_completion_receipt_sha256"]
        != registry.registry_completion_receipt_sha256
        or value["registry_completed_at_utc"] != registry.completed_at_utc
    ):
        raise PrivateBoundaryError("sealed prelaunch state-machine binding differs")

    initial_root = _object(
        initial_value["private_context_root_identity"],
        _ROOT_IDENTITY_KEYS,
        "initial private root identity",
    )
    initial_mount = _object(
        initial_value["private_mount"], _MOUNT_KEYS, "initial private mount"
    )
    initial_namespace = _object(
        initial_value["mount_namespace"], _NAMESPACE_KEYS, "initial mount namespace"
    )
    stable_mount_keys = {
        "filesystem_type",
        "major_minor",
        "mount_id",
        "mount_point",
        "mount_root",
        "mount_source",
        "parent_id",
    }
    if (
        initial_root["device"] != root_device
        or initial_root["inode"] != value["private_context_root_identity"]["inode"]
        or initial_namespace != namespace
        or initial_value["boot_id"] != value["boot_id"]
        or registry.boot_id != value["boot_id"]
        or initial_value["setuid_adapter"] != value["setuid_adapter"]
        or any(initial_mount[key] != mount[key] for key in stable_mount_keys)
    ):
        raise PrivateBoundaryError("RW-to-RO boundary identity transition differs")

    registry_records = {
        row.relative_path: (row.hidden_sha256, row.size_bytes)
        for row in registry.registered_records
    }
    if [(relative, size) for relative, size in records] != [
        (row.relative_path, row.size_bytes) for row in registry.registered_records
    ]:
        raise PrivateBoundaryError("sealed inventory differs from registry completion")
    content_records_by_path = {
        str(row["path"]): (str(row["hidden_sha256"]), int(row["size_bytes"]))
        for row in content_records
    }
    if content_records_by_path != registry_records:
        raise PrivateBoundaryError(
            "sealed content hashes differ from registry completion"
        )
    probe_relative = _relative(
        value["probe_record_relative_path"], "probe record relative path"
    )
    if probe_relative not in registry_records:
        raise PrivateBoundaryError(
            "sealed probe record is absent from registry completion"
        )

    initial_completed = _utc(
        initial_value["probe_completed_at_utc"], "initial probe completed_at_utc"
    )
    registry_completed = _utc(registry.completed_at_utc, "registry completed_at_utc")
    if registry_completed < initial_completed or registry_completed > started:
        raise PrivateBoundaryError("registry completion timestamp order differs")
    fresh_until = _utc(value["fresh_until_utc"], "fresh_until_utc")
    if (
        fresh_until != completed + timedelta(seconds=MAX_FRESH_SECONDS)
        or validation_time > fresh_until
    ):
        raise PrivateBoundaryError("sealed prelaunch boundary is older than 60s")

    policy_sha = _sha(_canonical(_access_policy(SEALED_PRELAUNCH_STAGE)))
    requests = _sealed_probe_requests(
        root=private_root,
        record_relative=probe_relative,
        record_sha256=registry_records[probe_relative][0],
        policy_sha256=policy_sha,
        adapter=adapter,
    )
    _validate_probe_bindings(
        value["access_probe_receipts"],
        access_probe_receipts_by_id=access_probe_receipts_by_id,
        requests=requests,
    )
    expected_self = _sha(_canonical({key: value[key] for key in _SEALED_UNSIGNED_KEYS}))
    if value["private_boundary_attestation_sha256"] != expected_self:
        raise PrivateBoundaryError("sealed prelaunch boundary self digest differs")
    return PrivateBoundaryValidation(
        stage=SEALED_PRELAUNCH_STAGE,
        protocol=SEALED_PRELAUNCH_PROTOCOL,
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        private_context_root=private_root,
        private_boundary_attestation_sha256=expected_self,
        access_policy_sha256=policy_sha,
        record_inventory_sha256=value["record_inventory_sha256"],
        initial_registration_attestation_sha256=initial.private_boundary_attestation_sha256,
        registry_completion_receipt_sha256=registry.registry_completion_receipt_sha256,
        fresh_until_utc=value["fresh_until_utc"],
    )


def _execute_probes(
    requests: tuple[_ProbeRequest, ...],
    *,
    public_root: Path,
    runtime: _PrivateBoundaryRuntime,
    adapter_handle: _VerifiedAdapterHandle,
    cleanup_initial_probe_on_error: bool,
) -> tuple[
    dict[str, bytes],
    tuple[dict[str, object], ...],
    tuple[PublishedArtifactObservation, ...],
]:
    raw_by_id: dict[str, bytes] = {}
    bindings: list[dict[str, object]] = []
    publications: list[PublishedArtifactObservation] = []
    try:
        for request in requests:
            _validate_open_adapter_handle(adapter_handle, runtime)
            raw = runtime.access_probe(request, adapter_handle)
            _validate_open_adapter_handle(adapter_handle, runtime)
            if type(raw) is not bytes:
                raise PrivateBoundaryError(
                    "setuid access probe must return exact bytes"
                )
            _validate_probe(raw, request)
            relative_path = _probe_receipt_relative_path(
                request.stage, request.probe_id
            )
            try:
                publication = publish_readonly_no_overwrite(
                    root=public_root,
                    relative_path=relative_path,
                    payload=raw,
                )
                observed_raw, observation = read_and_validate_readonly_artifact(
                    root=public_root,
                    relative_path=relative_path,
                    expected_payload=raw,
                )
            except (AtomicPublicationError, FileExistsError, OSError) as exc:
                raise PrivateBoundaryError(
                    "private-boundary publication failed; probe evidence namespace poisoned"
                ) from exc
            if observed_raw != raw or observation != publication:
                raise PrivateBoundaryError("probe receipt durable observation differs")
            bindings.append(
                _probe_publication_binding(
                    stage=request.stage,
                    probe_id=request.probe_id,
                    raw=raw,
                    observation=observation,
                )
            )
            publications.append(observation)
            raw_by_id[request.probe_id] = raw
    except BaseException:
        if cleanup_initial_probe_on_error:
            cleanup_requests = requests[-2:]
            for cleanup in cleanup_requests:
                try:
                    runtime.access_probe(cleanup, adapter_handle)
                except BaseException:
                    pass
        raise
    return raw_by_id, tuple(bindings), tuple(publications)


def _revalidate_probe_publications(
    *,
    public_root: Path,
    stage: str,
    raw_by_id: Mapping[str, bytes],
    publications: tuple[PublishedArtifactObservation, ...],
) -> None:
    expected_ids = tuple(sorted(raw_by_id))
    if len(publications) != len(expected_ids):
        raise PrivateBoundaryError("probe publication closure differs")
    for probe_id, expected_observation in zip(expected_ids, publications):
        raw = raw_by_id[probe_id]
        relative = _probe_receipt_relative_path(stage, probe_id)
        try:
            observed_raw, observation = read_and_validate_readonly_artifact(
                root=public_root,
                relative_path=relative,
                expected_payload=raw,
            )
        except (AtomicPublicationError, FileNotFoundError, OSError) as exc:
            raise PrivateBoundaryError(
                "persisted probe receipt closure differs; namespace poisoned"
            ) from exc
        if observed_raw != raw or observation != expected_observation:
            raise PrivateBoundaryError("persisted probe receipt identity differs")


def _observe_persisted_sealed_prerequisites(
    *,
    public_root: Path,
    initial_registration_attestation_bytes: bytes,
    initial_access_probe_receipts_by_id: dict[str, bytes],
    registry_completion_receipt_bytes: bytes,
) -> _PersistedPrerequisiteObservations:
    """Reopen every deterministic sealed prerequisite through atomic paths."""

    initial_value = _object(
        _parse(
            initial_registration_attestation_bytes,
            "persisted initial registration boundary",
        ),
        _INITIAL_KEYS,
        "persisted initial registration boundary",
    )
    bindings_value = initial_value["access_probe_receipts"]
    if type(bindings_value) is not list or len(bindings_value) != len(
        INITIAL_PRIVATE_PROBE_IDS
    ):
        raise PrivateBoundaryError("persisted initial probe binding closure differs")
    bindings_by_id: dict[str, dict[str, Any]] = {}
    for index, raw_binding in enumerate(bindings_value):
        binding = _object(
            raw_binding,
            _PROBE_BINDING_KEYS,
            f"persisted initial probe binding[{index}]",
        )
        probe_id = binding["probe_id"]
        if type(probe_id) is not str or probe_id in bindings_by_id:
            raise PrivateBoundaryError(
                "persisted initial probe binding role set differs"
            )
        bindings_by_id[probe_id] = binding
    expected_probe_ids = tuple(sorted(INITIAL_PRIVATE_PROBE_IDS))
    if (
        tuple(sorted(bindings_by_id)) != expected_probe_ids
        or tuple(sorted(initial_access_probe_receipts_by_id)) != expected_probe_ids
    ):
        raise PrivateBoundaryError("persisted initial probe binding role set differs")

    def observe(
        relative_path: str,
        expected_payload: bytes,
        label: str,
    ) -> PublishedArtifactObservation:
        try:
            observed_raw, observation = read_and_validate_readonly_artifact(
                root=public_root,
                relative_path=relative_path,
                expected_payload=expected_payload,
            )
        except (AtomicPublicationError, FileNotFoundError, OSError) as exc:
            raise PrivateBoundaryError(
                f"persisted {label} closure differs; namespace poisoned"
            ) from exc
        if observed_raw != expected_payload:
            raise PrivateBoundaryError(f"persisted {label} bytes differ")
        return observation

    initial_observation = observe(
        INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH,
        initial_registration_attestation_bytes,
        "initial registration attestation",
    )
    probe_observations: list[tuple[str, PublishedArtifactObservation]] = []
    for probe_id in expected_probe_ids:
        probe_raw = initial_access_probe_receipts_by_id[probe_id]
        relative_path = _probe_receipt_relative_path(
            INITIAL_REGISTRATION_STAGE, probe_id
        )
        observation = observe(
            relative_path,
            probe_raw,
            f"initial probe receipt {probe_id}",
        )
        binding = bindings_by_id[probe_id]
        intent_relative, pending_relative = publication_sidecar_relative_paths(
            relative_path
        )
        intent_raw = _atomic_intent_bytes(relative_path, probe_raw)
        if (
            binding["artifact_relative_path"] != relative_path
            or binding["artifact_sha256"] != observation.sha256
            or binding["artifact_size_bytes"] != observation.size_bytes
            or binding["artifact_device"] != observation.device
            or binding["artifact_inode"] != observation.inode
            or binding["artifact_mode"] != observation.mode
            or observation.link_count != 1
            or observation.path != (public_root / relative_path).as_posix()
            or binding["intent_relative_path"] != intent_relative
            or binding["intent_sha256"] != _sha(intent_raw)
            or binding["intent_size_bytes"] != len(intent_raw)
            or binding["pending_relative_path"] != pending_relative
            or binding["pending_absent"] is not True
            or observation.publication_intent_path
            != (public_root / intent_relative).as_posix()
        ):
            raise PrivateBoundaryError(
                "persisted initial probe publication binding differs"
            )
        probe_observations.append((probe_id, observation))

    registry_observation = observe(
        REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH,
        registry_completion_receipt_bytes,
        "registry completion receipt",
    )
    return _PersistedPrerequisiteObservations(
        initial_attestation=initial_observation,
        initial_probe_receipts=tuple(probe_observations),
        registry_completion=registry_observation,
    )


def _attest_and_publish(
    *,
    stage: str,
    public_root: Path,
    private_root: Path,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
    expected_record_paths: tuple[str, ...],
    probe_record_relative_path: str | None,
    initial_registration_attestation_bytes: bytes | None,
    initial_access_probe_receipts_by_id: Mapping[str, object] | None,
    registry_completion_receipt_bytes: bytes | None,
    registrar_source_bytes: bytes | None,
    runtime: _PrivateBoundaryRuntime,
    production: bool,
) -> PrivateBoundaryArtifacts:
    """Open one trusted adapter fd, retain it for every probe, then close it."""

    if (
        _COMMIT_RE.fullmatch(source_commit) is None
        or _ATTEMPT_RE.fullmatch(experiment_attempt_id) is None
        or stage_kind not in _STAGE_SHAPES
        or _STAGE_ATTEMPT_RE.fullmatch(stage_attempt_id) is None
        or stage not in {INITIAL_REGISTRATION_STAGE, SEALED_PRELAUNCH_STAGE}
    ):
        raise PrivateBoundaryError("private-boundary source/stage identity differs")
    normalized_public = _normalized_absolute(public_root, "public root")
    normalized_private = _normalized_absolute(private_root, "private root")
    _validate_root_grammars(
        normalized_public,
        normalized_private,
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        production=production,
    )
    if production:
        _assert_production_service_accounts()
    handle = runtime.open_adapter()
    try:
        _validate_open_adapter_handle(handle, runtime)
        result = _attest_and_publish_impl(
            stage=stage,
            public_root=normalized_public,
            private_root=normalized_private,
            source_commit=source_commit,
            experiment_attempt_id=experiment_attempt_id,
            stage_kind=stage_kind,
            stage_attempt_id=stage_attempt_id,
            expected_record_paths=expected_record_paths,
            probe_record_relative_path=probe_record_relative_path,
            initial_registration_attestation_bytes=(
                initial_registration_attestation_bytes
            ),
            initial_access_probe_receipts_by_id=(initial_access_probe_receipts_by_id),
            registry_completion_receipt_bytes=registry_completion_receipt_bytes,
            registrar_source_bytes=registrar_source_bytes,
            runtime=runtime,
            adapter_handle=handle,
            production=production,
        )
        _validate_open_adapter_handle(handle, runtime)
        return result
    finally:
        if type(handle) is _VerifiedAdapterHandle and handle.close_descriptor:
            try:
                os.close(handle.descriptor)
            except OSError:
                pass


def _attest_and_publish_impl(
    *,
    stage: str,
    public_root: Path,
    private_root: Path,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
    expected_record_paths: tuple[str, ...],
    probe_record_relative_path: str | None,
    initial_registration_attestation_bytes: bytes | None,
    initial_access_probe_receipts_by_id: Mapping[str, object] | None,
    registry_completion_receipt_bytes: bytes | None,
    registrar_source_bytes: bytes | None,
    runtime: _PrivateBoundaryRuntime,
    adapter_handle: _VerifiedAdapterHandle,
    production: bool,
) -> PrivateBoundaryArtifacts:
    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise PrivateBoundaryError("source_commit must be exact 40-hex")
    if _ATTEMPT_RE.fullmatch(experiment_attempt_id) is None:
        raise PrivateBoundaryError("experiment_attempt_id must match attempt-[0-9]{3}")
    if stage_kind not in _STAGE_SHAPES:
        raise PrivateBoundaryError("stage_kind has unsafe grammar")
    if _STAGE_ATTEMPT_RE.fullmatch(stage_attempt_id) is None:
        raise PrivateBoundaryError("stage_attempt_id must match attempt-[0-9]{3}")
    if stage not in {INITIAL_REGISTRATION_STAGE, SEALED_PRELAUNCH_STAGE}:
        raise PrivateBoundaryError("private-boundary stage differs")
    public_root = _normalized_absolute(public_root, "public root")
    private_root = _normalized_absolute(private_root, "private root")
    _validate_root_grammars(
        public_root,
        private_root,
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        production=production,
    )
    normalized_records = tuple(
        _relative(value, "expected record path") for value in expected_record_paths
    )
    if len(normalized_records) != len(
        set(normalized_records)
    ) or normalized_records != (
        tuple(
            sorted(
                normalized_records,
                key=lambda value: _private_record_coordinate(
                    value, stage_kind=stage_kind
                ),
            )
        )
    ):
        raise PrivateBoundaryError(
            "expected record paths must be numerically sorted and unique"
        )
    if _TRANSIENT_PROBE_RELATIVE_PATH in normalized_records:
        raise PrivateBoundaryError("transient probe cannot be a registered record")
    if stage == INITIAL_REGISTRATION_STAGE:
        if (
            normalized_records
            or probe_record_relative_path is not None
            or initial_registration_attestation_bytes is not None
            or initial_access_probe_receipts_by_id is not None
            or registry_completion_receipt_bytes is not None
            or registrar_source_bytes is not None
        ):
            raise PrivateBoundaryError(
                "initial registration requires an empty root and no sealed-state inputs"
            )
        probe_relative = None
    else:
        if (
            not normalized_records
            or type(probe_record_relative_path) is not str
            or type(initial_registration_attestation_bytes) is not bytes
            or type(initial_access_probe_receipts_by_id) is not dict
            or type(registry_completion_receipt_bytes) is not bytes
            or type(registrar_source_bytes) is not bytes
        ):
            raise PrivateBoundaryError("sealed prelaunch state inputs are incomplete")
        frozen_initial_receipts: dict[str, bytes] = {}
        for probe_id, raw_receipt in initial_access_probe_receipts_by_id.items():
            if type(probe_id) is not str or type(raw_receipt) is not bytes:
                raise PrivateBoundaryError(
                    "sealed initial probe receipts must be an exact raw-byte dict"
                )
            frozen_initial_receipts[probe_id] = raw_receipt
        initial_access_probe_receipts_by_id = frozen_initial_receipts
        probe_relative = _relative(
            probe_record_relative_path, "probe record relative path"
        )
        if probe_relative not in normalized_records:
            raise PrivateBoundaryError(
                "probe record is absent from registered record set"
            )
    process_before = _validate_runtime_identity(runtime)

    source_path = Path(__file__).resolve(strict=True)
    source_raw = source_path.read_bytes()
    access_probe_source_path = source_path.with_name(
        "cohort_closed_loop_private_access_probe.c"
    ).resolve(strict=True)
    access_probe_source_raw = access_probe_source_path.read_bytes()
    adapter = _validate_open_adapter_handle(adapter_handle, runtime)
    policy = _access_policy(stage)
    policy_sha = _sha(_canonical(policy))

    prerequisite_observations: _PersistedPrerequisiteObservations | None = None
    if stage == SEALED_PRELAUNCH_STAGE:
        assert initial_registration_attestation_bytes is not None
        assert type(initial_access_probe_receipts_by_id) is dict
        assert registry_completion_receipt_bytes is not None
        prerequisite_observations = _observe_persisted_sealed_prerequisites(
            public_root=public_root,
            initial_registration_attestation_bytes=(
                initial_registration_attestation_bytes
            ),
            initial_access_probe_receipts_by_id=(initial_access_probe_receipts_by_id),
            registry_completion_receipt_bytes=registry_completion_receipt_bytes,
        )

    boot_before = runtime.boot_id()
    namespace_before = runtime.mount_namespace()
    mountinfo_before = runtime.mountinfo_bytes()
    tree_before = _scan_private_tree(
        private_root,
        expected_record_paths=normalized_records,
        mountinfo_raw=mountinfo_before,
        runtime=runtime,
        stage=stage,
    )
    content_before_first = _read_record_content_inventory(
        private_root, records=tree_before.records, runtime=runtime
    )
    content_before_second = _read_record_content_inventory(
        private_root, records=tree_before.records, runtime=runtime
    )
    if content_before_first != content_before_second:
        raise PrivateBoundaryError(
            "private record content differs across stable passes"
        )
    if stage == INITIAL_REGISTRATION_STAGE and tree_before.directories:
        raise PrivateBoundaryError("initial registration root must be exactly empty")
    started = runtime.now_utc()
    started_dt = _utc(started, "probe_started_at_utc")

    initial_validation: PrivateBoundaryValidation | None = None
    registry_validation: _RegistryCompletionValidation | None = None
    if stage == SEALED_PRELAUNCH_STAGE:
        assert initial_registration_attestation_bytes is not None
        assert initial_access_probe_receipts_by_id is not None
        assert registry_completion_receipt_bytes is not None
        assert registrar_source_bytes is not None
        initial_validation = validate_initial_registration_boundary_bytes(
            initial_registration_attestation_bytes,
            access_probe_receipts_by_id=initial_access_probe_receipts_by_id,
            attester_source_bytes=source_raw,
            access_probe_source_bytes=access_probe_source_raw,
            validation_time_utc=started,
        )
        registry_validation = _validate_registry_completion_receipt_bytes(
            registry_completion_receipt_bytes,
            registrar_source_bytes=registrar_source_bytes,
        )
        registry_paths = tuple(
            row.relative_path for row in registry_validation.registered_records
        )
        if (
            initial_validation.source_commit != source_commit
            or initial_validation.experiment_attempt_id != experiment_attempt_id
            or initial_validation.stage_kind != stage_kind
            or initial_validation.stage_attempt_id != stage_attempt_id
            or initial_validation.private_context_root != str(private_root)
            or registry_validation.source_commit != source_commit
            or registry_validation.experiment_attempt_id != experiment_attempt_id
            or registry_validation.stage_kind != stage_kind
            or registry_validation.stage_attempt_id != stage_attempt_id
            or registry_validation.private_context_root != str(private_root)
            or registry_validation.initial_registration_attestation_sha256
            != initial_validation.private_boundary_attestation_sha256
            or registry_paths != normalized_records
            or registry_validation.boot_id != boot_before
        ):
            raise PrivateBoundaryError("sealed prelaunch prerequisite binding differs")
        registry_sizes = {
            row.relative_path: row.size_bytes
            for row in registry_validation.registered_records
        }
        if any(
            record["size_bytes"] != registry_sizes[record["relative_path"]]
            for record in tree_before.records
        ):
            raise PrivateBoundaryError(
                "registry completion size differs from sealed tree"
            )
        registry_content = {
            row.relative_path: (row.hidden_sha256, row.size_bytes)
            for row in registry_validation.registered_records
        }
        observed_content = {
            str(row["path"]): (str(row["hidden_sha256"]), int(row["size_bytes"]))
            for row in content_before_first
        }
        if observed_content != registry_content:
            raise PrivateBoundaryError(
                "registry completion hidden hash differs from sealed tree"
            )
        requests = _sealed_probe_requests(
            root=str(private_root),
            record_relative=probe_relative,
            record_sha256={
                row.relative_path: row.hidden_sha256
                for row in registry_validation.registered_records
            }[probe_relative],
            policy_sha256=policy_sha,
            adapter=adapter,
        )
    else:
        requests = _initial_probe_requests(
            root=str(private_root),
            source_commit=source_commit,
            experiment_attempt_id=experiment_attempt_id,
            stage_kind=stage_kind,
            stage_attempt_id=stage_attempt_id,
            policy_sha256=policy_sha,
            adapter=adapter,
        )

    probe_raws, probe_bindings, probe_publications = _execute_probes(
        requests,
        public_root=public_root,
        runtime=runtime,
        adapter_handle=adapter_handle,
        cleanup_initial_probe_on_error=stage == INITIAL_REGISTRATION_STAGE,
    )
    completed = runtime.now_utc()
    completed_dt = _utc(completed, "probe_completed_at_utc")
    if (
        completed_dt < started_dt
        or (completed_dt - started_dt).total_seconds() > MAX_FRESH_SECONDS
    ):
        raise PrivateBoundaryError("private-boundary access probe duration exceeds 60s")

    mountinfo_after = runtime.mountinfo_bytes()
    namespace_after = runtime.mount_namespace()
    tree_after = _scan_private_tree(
        private_root,
        expected_record_paths=normalized_records,
        mountinfo_raw=mountinfo_after,
        runtime=runtime,
        stage=stage,
    )
    content_after_first = _read_record_content_inventory(
        private_root, records=tree_after.records, runtime=runtime
    )
    content_after_second = _read_record_content_inventory(
        private_root, records=tree_after.records, runtime=runtime
    )
    boot_after = runtime.boot_id()
    process_after = runtime.process_identity()
    if (
        mountinfo_after != mountinfo_before
        or namespace_after != namespace_before
        or tree_after != tree_before
        or content_after_first != content_before_first
        or content_after_second != content_before_first
        or boot_after != boot_before
        or process_after != process_before
    ):
        raise PrivateBoundaryError("private boundary drifted during attestation")
    if _BOOT_ID_RE.fullmatch(boot_before) is None:
        raise PrivateBoundaryError("boot id differs")
    _revalidate_probe_publications(
        public_root=public_root,
        stage=stage,
        raw_by_id=probe_raws,
        publications=probe_publications,
    )
    inventory = {
        "directories": list(tree_before.directories),
        "record_count": len(tree_before.records),
        "records": list(tree_before.records),
    }
    root_identity = {
        "device": tree_before.root_metadata.device,
        "group_gid": _translated_gid(tree_before.root_metadata.group_gid, runtime),
        "inode": tree_before.root_metadata.inode,
        "mode": stat.S_IMODE(tree_before.root_metadata.mode),
        "owner_uid": _translated_uid(tree_before.root_metadata.owner_uid, runtime),
        "private_context_root": str(private_root),
    }
    unsigned: dict[str, object] = {
        "protocol": (
            INITIAL_REGISTRATION_PROTOCOL
            if stage == INITIAL_REGISTRATION_STAGE
            else SEALED_PRELAUNCH_PROTOCOL
        ),
        "schema_version": (
            INITIAL_SCHEMA_VERSION
            if stage == INITIAL_REGISTRATION_STAGE
            else SEALED_SCHEMA_VERSION
        ),
        "status": INITIAL_STATUS
        if stage == INITIAL_REGISTRATION_STAGE
        else SEALED_STATUS,
        "stage": stage,
        "source_commit": source_commit,
        "experiment_attempt_id": experiment_attempt_id,
        "stage_kind": stage_kind,
        "stage_attempt_id": stage_attempt_id,
        "public_durable_root": str(public_root),
        "private_context_root_identity": root_identity,
        "service_identities": _service_identities(),
        "access_policy": policy,
        "access_policy_sha256": policy_sha,
        "private_mount": _mount_object(tree_before.mount),
        "mount_namespace": _namespace_object(namespace_before),
        "record_inventory": inventory,
        "record_inventory_sha256": _sha(_canonical(inventory)),
        "record_content_inventory": list(content_before_first),
        "record_content_inventory_sha256": _sha(_canonical(list(content_before_first))),
        "transient_probe_relative_path": _TRANSIENT_PROBE_RELATIVE_PATH,
        "access_probe_receipts": list(probe_bindings),
        "boot_id": boot_before,
        "process_identity": {
            "active_capabilities_empty": process_before.active_capabilities_empty,
            "effective_gid": process_before.effective_gid,
            "effective_uid": process_before.effective_uid,
            "pid": process_before.pid,
            "process_start_ticks": process_before.process_start_ticks,
            "real_gid": process_before.real_gid,
            "real_uid": process_before.real_uid,
            "saved_gid": process_before.saved_gid,
            "saved_uid": process_before.saved_uid,
            "service_identity": process_before.service_identity,
            "supplementary_gids": list(process_before.supplementary_gids),
        },
        "probe_started_at_utc": started,
        "probe_completed_at_utc": completed,
        "attester_source": _source_object(str(source_path), source_raw),
        "access_probe_source": _source_object(
            str(access_probe_source_path), access_probe_source_raw
        ),
        "setuid_adapter": _adapter_object(adapter),
        **_authority_false(),
    }
    if stage == SEALED_PRELAUNCH_STAGE:
        assert initial_validation is not None
        assert registry_validation is not None
        unsigned.update(
            {
                "fresh_until_utc": _format_utc(
                    completed_dt + timedelta(seconds=MAX_FRESH_SECONDS)
                ),
                "initial_registration_attestation_sha256": (
                    initial_validation.private_boundary_attestation_sha256
                ),
                "probe_record_relative_path": probe_relative,
                "registry_completed_at_utc": registry_validation.completed_at_utc,
                "registry_completion_receipt_sha256": (
                    registry_validation.registry_completion_receipt_sha256
                ),
            }
        )
        unsigned_keys = _SEALED_UNSIGNED_KEYS
        relative_path = SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH
    else:
        unsigned_keys = _INITIAL_UNSIGNED_KEYS
        relative_path = INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH
    if set(unsigned) != unsigned_keys:
        raise PrivateBoundaryError("private-boundary builder schema differs")
    payload = dict(unsigned)
    payload["private_boundary_attestation_sha256"] = _sha(_canonical(unsigned))
    attestation_raw = _canonical(payload)

    if stage == INITIAL_REGISTRATION_STAGE:
        validate_initial_registration_boundary_bytes(
            attestation_raw,
            access_probe_receipts_by_id=probe_raws,
            attester_source_bytes=source_raw,
            access_probe_source_bytes=access_probe_source_raw,
            validation_time_utc=completed,
        )
    else:
        assert initial_registration_attestation_bytes is not None
        assert initial_access_probe_receipts_by_id is not None
        assert registry_completion_receipt_bytes is not None
        assert registrar_source_bytes is not None
        validate_sealed_prelaunch_boundary_bytes(
            attestation_raw,
            access_probe_receipts_by_id=probe_raws,
            attester_source_bytes=source_raw,
            access_probe_source_bytes=access_probe_source_raw,
            validation_time_utc=completed,
            initial_registration_attestation_bytes=(
                initial_registration_attestation_bytes
            ),
            initial_access_probe_receipts_by_id=(initial_access_probe_receipts_by_id),
            registry_completion_receipt_bytes=registry_completion_receipt_bytes,
            registrar_source_bytes=registrar_source_bytes,
        )
    _validate_open_adapter_handle(adapter_handle, runtime)
    _revalidate_probe_publications(
        public_root=public_root,
        stage=stage,
        raw_by_id=probe_raws,
        publications=probe_publications,
    )
    if stage == SEALED_PRELAUNCH_STAGE:
        assert prerequisite_observations is not None
        assert initial_registration_attestation_bytes is not None
        assert type(initial_access_probe_receipts_by_id) is dict
        assert registry_completion_receipt_bytes is not None
        final_prerequisite_observations = _observe_persisted_sealed_prerequisites(
            public_root=public_root,
            initial_registration_attestation_bytes=(
                initial_registration_attestation_bytes
            ),
            initial_access_probe_receipts_by_id=(initial_access_probe_receipts_by_id),
            registry_completion_receipt_bytes=(registry_completion_receipt_bytes),
        )
        if final_prerequisite_observations != prerequisite_observations:
            raise PrivateBoundaryError(
                "persisted sealed prerequisite identity drifted before final"
            )
    try:
        publication = publish_readonly_no_overwrite(
            root=public_root,
            relative_path=relative_path,
            payload=attestation_raw,
        )
    except (AtomicPublicationError, FileExistsError, OSError) as exc:
        raise PrivateBoundaryError("private-boundary publication failed") from exc
    try:
        observed_raw, observed_publication = read_and_validate_readonly_artifact(
            root=public_root,
            relative_path=relative_path,
            expected_payload=attestation_raw,
        )
    except (AtomicPublicationError, FileNotFoundError, OSError) as exc:
        raise PrivateBoundaryError(
            "private-boundary durable publication differs"
        ) from exc
    if observed_raw != attestation_raw or observed_publication != publication:
        raise PrivateBoundaryError("private-boundary publication identity differs")
    return PrivateBoundaryArtifacts(
        attestation_bytes=attestation_raw,
        access_probe_receipts=tuple(sorted(probe_raws.items())),
        probe_publications=probe_publications,
        publication=publication,
    )


def attest_initial_registration_boundary(
    *,
    public_root: Path,
    private_root: Path,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
) -> PrivateBoundaryArtifacts:
    """Fail closed until the production stage-plan/broker join exists.

    The v2 stage plan prospectively declares ``private_boundary_v2``
    unavailable.  The pure validator and private test seam below are audit
    scaffolding, not permission to mint production evidence.  Enabling this
    entry point requires one new source commit that consumes and reconstructs
    the complete persisted stage-plan/deployment closure and activates the
    separately audited root capability broker.
    """

    del (
        public_root,
        private_root,
        source_commit,
        experiment_attempt_id,
        stage_kind,
        stage_attempt_id,
    )
    raise PrivateBoundaryError(
        "production private-boundary provider is unavailable; "
        "stage-plan runtime join and root capability broker are required"
    )


def attest_sealed_prelaunch_boundary(
    *,
    public_root: Path,
    private_root: Path,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
    expected_record_paths: tuple[str, ...],
    probe_record_relative_path: str,
) -> PrivateBoundaryArtifacts:
    """Fail closed until persisted predecessors and runtime sources are joined.

    Production deliberately accepts no caller-supplied predecessor or source
    bytes.  The future provider must reopen them from their fixed atomic paths
    and fixed deployment descriptors after validating the complete stage plan.
    """

    del (
        public_root,
        private_root,
        source_commit,
        experiment_attempt_id,
        stage_kind,
        stage_attempt_id,
        expected_record_paths,
        probe_record_relative_path,
    )
    raise PrivateBoundaryError(
        "production private-boundary provider is unavailable; "
        "stage-plan runtime join and root capability broker are required"
    )


def _attest_private_boundary_for_test(
    *,
    stage: str,
    public_root: Path,
    private_root: Path,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
    expected_record_paths: tuple[str, ...],
    probe_record_relative_path: str | None,
    initial_registration_attestation_bytes: bytes | None,
    initial_access_probe_receipts_by_id: Mapping[str, object] | None,
    registry_completion_receipt_bytes: bytes | None,
    registrar_source_bytes: bytes | None,
    runtime: _PrivateBoundaryRuntime,
) -> PrivateBoundaryArtifacts:
    """Private test seam; production roots are rejected before runtime use."""

    return _attest_and_publish(
        stage=stage,
        public_root=public_root,
        private_root=private_root,
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage_kind=stage_kind,
        stage_attempt_id=stage_attempt_id,
        expected_record_paths=expected_record_paths,
        probe_record_relative_path=probe_record_relative_path,
        initial_registration_attestation_bytes=(initial_registration_attestation_bytes),
        initial_access_probe_receipts_by_id=initial_access_probe_receipts_by_id,
        registry_completion_receipt_bytes=registry_completion_receipt_bytes,
        registrar_source_bytes=registrar_source_bytes,
        runtime=runtime,
        production=False,
    )
