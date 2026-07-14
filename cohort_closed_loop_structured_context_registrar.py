"""Fail-closed context-registrar and registry-completion-v2 scaffold.

The committed stage plan places context registration at lifecycle ordinals
three and four: write the exact mapped private records, then atomically publish
one registry-completion-v2 receipt.  No production registrar provider exists
yet.  Consequently, the public production entry point below rejects before it
parses caller data, observes a runtime, or touches either filesystem.

The private test seam exercises the prospective contract without granting
authority.  It reconstructs every public scoring-context identity from an
atomically published DGP row, the stage-plan-bound pure-scorer digest, and
digests computed from exact opaque/hidden bytes.  It then writes a complete
no-overwrite private tree, atomically publishes the public digest artifacts,
reopens the entire closure, and publishes the exact receipt schema consumed by
``cohort_closed_loop_structured_private_boundary``.  Hidden bytes are never
placed in any returned or published public object.

This module does not import a model, task, DGP generator, scorer, or launcher.
It cannot make any stage eligible to run.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping

import cohort_closed_loop_structured_private_boundary as private_boundary
import cohort_closed_loop_structured_stage_plan as stage_plan
from cohort_closed_loop_structured_atomic_publish import (
    AtomicPublicationError,
    PublishedArtifactObservation,
    publication_sidecar_relative_paths,
    publish_readonly_no_overwrite,
    read_and_validate_readonly_artifact,
)
from cohort_closed_loop_structured_dgp_context import (
    ContextRegistryRecord,
    DgpContextIntegrityError,
    PhaseKind,
    PublicScoringContextAttestation,
    StageKind,
    STAGE_SHAPES,
    canonical_json_bytes,
    compute_public_context_identity_sha256,
    compute_scoring_context_sha256,
    load_context_registry_record,
    load_dgp_row_identity,
    load_public_scoring_context_attestation,
)

__all__ = (
    "ContextRegistrarArtifacts",
    "ContextRegistrarError",
    "ContextRegistrarValidation",
    "PROVIDER_AVAILABLE",
    "register_structured_contexts_and_publish_completion",
    "validate_registry_completion_bytes",
)


class ContextRegistrarError(RuntimeError):
    """Raised when the prospective registrar closure differs."""


PROVIDER_AVAILABLE = False
REGISTRY_COMPLETION_RELATIVE_PATH = (
    "control/private_boundary/registry/registry_completion.v2.json"
)
REGISTRAR_SOURCE_SUFFIX = "/cohort_closed_loop_structured_context_registrar.py"
_PRODUCTION_PUBLIC_PREFIX = (
    "/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state"
)
_PRODUCTION_PRIVATE_PREFIX = (
    "/sensei-fs/private/zcai/TTT-RL/cohort-closed-loop-structured-state"
)
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_AUTHORITY_KEYS = (
    "dgp_calls_authorized",
    "launch_authorized",
    "model_calls_authorized",
    "operational_authorization",
    "scorer_calls_authorized",
)
_REQUIRED_PLAN_AUTHORITY_KEYS = (
    "dgp_generation_claim_eligible",
    "dgp_generator_import_authorized",
    "dgp_generation_authorized",
    "model_calls_authorized",
    "scorer_calls_authorized",
    "launch_authorized",
    "operational_authorization",
)
_REQUIRED_LIFECYCLE = (
    (1, "create_unique_empty_stage_epoch_rw", "rw"),
    (2, "publish_14_initial_probe_receipts_then_attestation", "rw"),
    (3, "registrar_write_exact_mapped_private_records", "rw"),
    (4, "publish_registry_completion_v2", "rw"),
    (5, "remount_same_epoch_read_only", "ro"),
    (6, "publish_9_sealed_probe_receipts_then_attestation", "ro"),
)
_PLAN_ENTRY_KEYS = frozenset(
    {
        "stage_kind",
        "block_id",
        "block_index",
        "phase",
        "item_id",
        "instance_index",
        "dgp_row_path",
        "public_attestation_path",
        "public_registry_digest_path",
        "private_record_relative_path",
        "private_record_path",
        "completion_values_pending",
    }
)
_COMPLETION_ENTRY_FIELDS = (
    "stage_kind",
    "block_id",
    "block_index",
    "phase",
    "item_id",
    "instance_index",
    "instance_id",
    "public_context_identity_sha256",
    "opaque_handle_sha256",
    "relative_path",
    "hidden_sha256",
    "size_bytes",
)
_PENDING_COMPLETION_VALUES = (
    "hidden_sha256",
    "instance_id",
    "opaque_handle_sha256",
    "public_context_identity_sha256",
    "size_bytes",
)


@dataclass(frozen=True, slots=True)
class _PlanRecord:
    stage_kind: str
    block_id: str
    block_index: int
    phase: str
    item_id: int
    instance_index: int
    dgp_row_relative_path: str
    public_attestation_relative_path: str
    public_registry_relative_path: str
    private_record_relative_path: str

    @property
    def coordinate(self) -> tuple[object, ...]:
        return (
            self.stage_kind,
            self.block_id,
            self.block_index,
            self.phase,
            self.item_id,
            self.instance_index,
        )


@dataclass(frozen=True, slots=True)
class _PreparedRecord:
    plan: _PlanRecord
    private_bytes: bytes
    opaque_handle_sha256: str
    hidden_sha256: str
    public_attestation_bytes: bytes
    public_registry_bytes: bytes
    completion_row: dict[str, object]
    dgp_row_observation: PublishedArtifactObservation


@dataclass(frozen=True, slots=True)
class _PrivateFileObservation:
    relative_path: str
    device: int
    inode: int
    mode: int
    link_count: int
    uid: int
    gid: int
    size_bytes: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _PrivateRootObservation:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class _RetainedPrivateRoot:
    path: Path
    descriptor: int
    observation: _PrivateRootObservation


@dataclass(frozen=True, slots=True)
class _PublicDirectoryObservation:
    relative_path: str
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class _FrozenRegistrarSource:
    path: Path
    raw: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class _InitialBoundaryClosure:
    validation: private_boundary.PrivateBoundaryValidation
    initial_observation: PublishedArtifactObservation
    probe_observations: tuple[tuple[str, PublishedArtifactObservation], ...]


@dataclass(frozen=True, slots=True)
class _RegistrarTestRuntime:
    """Private injected seam; production never accepts this object."""

    completed_at_utc: Callable[[], str]
    boot_id: Callable[[], str]
    process_identity: Callable[[], Mapping[str, object]]
    before_completion_revalidation: Callable[[], None]


@dataclass(frozen=True, slots=True)
class ContextRegistrarArtifacts:
    """Public-only receipt and observations; contains no hidden raw bytes."""

    receipt_bytes: bytes
    receipt_publication: PublishedArtifactObservation
    public_artifact_publications: tuple[PublishedArtifactObservation, ...]
    registered_record_count: int
    record_set_sha256: str
    registry_completion_receipt_sha256: str
    dgp_calls_authorized: bool = False
    model_calls_authorized: bool = False
    scorer_calls_authorized: bool = False
    launch_authorized: bool = False
    operational_authorization: bool = False


@dataclass(frozen=True, slots=True)
class ContextRegistrarValidation:
    """Pure, public receipt validation; never an authorization credential."""

    source_commit: str
    experiment_attempt_id: str
    stage_kind: str
    stage_attempt_id: str
    private_context_root: str
    registered_record_count: int
    registry_completion_receipt_sha256: str
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
        raise ContextRegistrarError("canonical ASCII JSON encoding failed") from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContextRegistrarError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ContextRegistrarError(f"non-finite JSON number is forbidden: {value}")


def _parse_canonical(raw: object, label: str) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ContextRegistrarError(f"{label} must be exact bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContextRegistrarError(f"{label} is not strict ASCII JSON") from exc
    if type(value) is not dict or _canonical(value) != raw:
        raise ContextRegistrarError(f"{label} is not canonical object bytes")
    return value


def _test_root(root: object, *, label: str, production_prefix: str) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise ContextRegistrarError(f"{label} must be an absolute pathlib.Path")
    normalized = Path(os.path.normpath(os.fspath(root)))
    if normalized != root or normalized == Path("/"):
        raise ContextRegistrarError(f"{label} must be normalized and non-root")
    text = root.as_posix()
    if text == production_prefix or text.startswith(production_prefix + "/"):
        raise ContextRegistrarError(
            "private test seam rejects production roots before filesystem access"
        )
    return root


def _freeze_actual_registrar_source(
    *, caller_path: object, caller_bytes: object
) -> _FrozenRegistrarSource:
    """Read the executing source exactly once and join the caller identity."""

    actual_path = Path(__file__).resolve()
    try:
        actual_raw = actual_path.read_bytes()
    except OSError as exc:
        raise ContextRegistrarError(
            "executing registrar source cannot be read"
        ) from exc
    if not isinstance(caller_path, Path) or not caller_path.is_absolute():
        raise ContextRegistrarError(
            "caller registrar source path must be absolute Path"
        )
    normalized_caller = Path(os.path.normpath(os.fspath(caller_path)))
    if normalized_caller != caller_path or caller_path == Path("/"):
        raise ContextRegistrarError("caller registrar source path is not normalized")
    if (
        actual_path.name != REGISTRAR_SOURCE_SUFFIX.removeprefix("/")
        or caller_path != actual_path
        or type(caller_bytes) is not bytes
        or caller_bytes != actual_raw
        or not actual_raw
    ):
        raise ContextRegistrarError(
            "executing, caller, and named registrar source identities differ"
        )
    return _FrozenRegistrarSource(
        path=actual_path,
        raw=actual_raw,
        sha256=_sha(actual_raw),
    )


def _absolute_text(value: object, label: str) -> str:
    if type(value) is not str or not value.startswith("/") or "\x00" in value:
        raise ContextRegistrarError(f"{label} must be absolute POSIX text")
    if posixpath.normpath(value) != value or value == "/":
        raise ContextRegistrarError(f"{label} must be normalized and non-root")
    return value


def _relative_text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\x00" in value:
        raise ContextRegistrarError(f"{label} must be relative POSIX text")
    pure = PurePosixPath(value)
    if pure.as_posix() != value or any(part in {"", ".", ".."} for part in pure.parts):
        raise ContextRegistrarError(f"{label} must be normalized POSIX text")
    return value


def _relative_to_base(path: object, base: object, label: str) -> str:
    path_text = _absolute_text(path, label)
    base_text = _absolute_text(base, f"{label} base")
    prefix = base_text + "/"
    if not path_text.startswith(prefix):
        raise ContextRegistrarError(f"{label} escapes its registered root")
    return _relative_text(path_text[len(prefix) :], f"{label} relative path")


def _authority_false() -> dict[str, bool]:
    return {key: False for key in _AUTHORITY_KEYS}


def _source_binding(payload: Mapping[str, object], *, role: str) -> dict[str, object]:
    rows = payload.get("source_role_bindings")
    if type(rows) is not list:
        raise ContextRegistrarError("stage-plan source-role bindings differ")
    matches = [row for row in rows if type(row) is dict and row.get("role") == role]
    if len(matches) != 1:
        raise ContextRegistrarError(f"stage plan has no unique {role} source binding")
    return matches[0]


def _raw_source_binding(
    payload: Mapping[str, object], *, binding_id: str
) -> dict[str, object]:
    upstream = payload.get("upstream_raw_bindings")
    if type(upstream) is not dict or type(upstream.get("source_files")) is not list:
        raise ContextRegistrarError("stage-plan raw source closure differs")
    matches = [
        row
        for row in upstream["source_files"]
        if type(row) is dict and row.get("binding_id") == binding_id
    ]
    if len(matches) != 1:
        raise ContextRegistrarError(
            f"stage plan has no unique {binding_id} raw source binding"
        )
    return matches[0]


def _require_sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA_RE.fullmatch(value) is None:
        raise ContextRegistrarError(f"{label} must be lowercase SHA256")
    return value


def _validate_plan_lifecycle(payload: Mapping[str, object]) -> None:
    private_plan = payload.get("private_boundary_plan")
    if type(private_plan) is not dict:
        raise ContextRegistrarError("stage-plan private-boundary plan differs")
    lifecycle = private_plan.get("lifecycle")
    if type(lifecycle) is not list:
        raise ContextRegistrarError("stage-plan lifecycle differs")
    observed = tuple(
        (
            row.get("ordinal"),
            row.get("event"),
            row.get("required_mount_mode"),
        )
        for row in lifecycle
        if type(row) is dict
    )
    if observed != _REQUIRED_LIFECYCLE or len(observed) != len(lifecycle):
        raise ContextRegistrarError("stage-plan registrar lifecycle differs")
    if private_plan.get("provider_available") is not False:
        raise ContextRegistrarError("private-boundary provider unexpectedly available")
    protocols = private_plan.get("protocol_schema_bindings")
    expected_protocol = {
        "protocol": private_boundary.REGISTRY_COMPLETION_PROTOCOL,
        "schema_version": private_boundary.REGISTRY_COMPLETION_SCHEMA_VERSION,
    }
    if type(protocols) is not dict or protocols.get("registry_completion") != (
        expected_protocol
    ):
        raise ContextRegistrarError("registry-completion protocol binding differs")


def _plan_records(payload: Mapping[str, object]) -> tuple[_PlanRecord, ...]:
    mapping = payload.get("registry_v2_mapping")
    paths = payload.get("paths")
    inventory = payload.get("dgp_output_inventory")
    if (
        type(mapping) is not dict
        or type(paths) is not dict
        or type(inventory) is not list
    ):
        raise ContextRegistrarError("stage-plan registrar mapping closure differs")
    durable_root = paths.get("durable_root")
    private_root = paths.get("private_context_root")
    if (
        mapping.get("protocol") != "cohort_structured_private_registry_mapping_plan_v2"
        or mapping.get("schema_version") != 2
        or mapping.get("status") != "pre_dgp_completion_values_pending"
        or mapping.get("source_commit") != payload.get("source_commit")
        or mapping.get("experiment_attempt_id") != payload.get("experiment_attempt_id")
        or mapping.get("stage_kind") != payload.get("stage_kind")
        or mapping.get("stage_attempt_id") != payload.get("stage_attempt_id")
        or mapping.get("private_context_root") != private_root
        or mapping.get("completion_receipt_path")
        != paths.get("registry_completion_receipt_path")
        or mapping.get("completion_receipt_protocol")
        != private_boundary.REGISTRY_COMPLETION_PROTOCOL
        or mapping.get("completion_receipt_schema_version")
        != private_boundary.REGISTRY_COMPLETION_SCHEMA_VERSION
        or tuple(mapping.get("completion_entry_fields", ())) != _COMPLETION_ENTRY_FIELDS
    ):
        raise ContextRegistrarError("registry-v2 mapping header differs")
    entries = mapping.get("planned_entries")
    if type(entries) is not list or not entries:
        raise ContextRegistrarError("registry-v2 plan must be nonempty")
    if mapping.get("planned_entry_count") != len(entries):
        raise ContextRegistrarError("registry-v2 planned count differs")

    inventory_by_path: dict[str, dict[str, object]] = {}
    for raw_row in inventory:
        if type(raw_row) is not dict or type(raw_row.get("path")) is not str:
            raise ContextRegistrarError("DGP output inventory row differs")
        path = raw_row["path"]
        if path in inventory_by_path:
            raise ContextRegistrarError("DGP output inventory path is duplicated")
        inventory_by_path[path] = raw_row

    result: list[_PlanRecord] = []
    for index, raw_entry in enumerate(entries):
        if type(raw_entry) is not dict or set(raw_entry) != _PLAN_ENTRY_KEYS:
            raise ContextRegistrarError(f"mapping entry[{index}] exact schema differs")
        if tuple(raw_entry["completion_values_pending"]) != (
            _PENDING_COMPLETION_VALUES
        ):
            raise ContextRegistrarError(
                f"mapping entry[{index}] completion values differ"
            )
        stage_kind = raw_entry["stage_kind"]
        block_id = raw_entry["block_id"]
        block_index = raw_entry["block_index"]
        phase = raw_entry["phase"]
        item_id = raw_entry["item_id"]
        instance_index = raw_entry["instance_index"]
        if (
            stage_kind != payload.get("stage_kind")
            or type(block_id) is not str
            or type(block_index) is not int
            or block_id != f"{stage_kind}_block_{block_index + 1:02d}"
            or phase not in {"adaptation", "held_out"}
            or type(item_id) is not int
            or item_id < 1
            or type(instance_index) is not int
            or instance_index != item_id - 1
        ):
            raise ContextRegistrarError(f"mapping entry[{index}] coordinate differs")
        private_relative = _relative_text(
            raw_entry["private_record_relative_path"],
            f"mapping entry[{index}] private path",
        )
        if private_relative != f"records/{block_id}/{phase}/{item_id}.json":
            raise ContextRegistrarError(f"mapping entry[{index}] private path differs")
        if (
            _relative_to_base(
                raw_entry["private_record_path"], private_root, "private record path"
            )
            != private_relative
        ):
            raise ContextRegistrarError(f"mapping entry[{index}] private path swap")
        dgp_row_relative = _relative_to_base(
            raw_entry["dgp_row_path"], durable_root, "DGP row path"
        )
        attestation_relative = _relative_to_base(
            raw_entry["public_attestation_path"],
            durable_root,
            "public attestation path",
        )
        registry_relative = _relative_to_base(
            raw_entry["public_registry_digest_path"],
            durable_root,
            "public registry path",
        )
        expected_roles = (
            (raw_entry["dgp_row_path"], "dgp_row_identity", "dgp_generator"),
            (
                raw_entry["public_attestation_path"],
                "public_context_attestation",
                "context_registrar",
            ),
            (
                raw_entry["public_registry_digest_path"],
                "context_registry_digest_record",
                "context_registrar",
            ),
        )
        for absolute, role, writer in expected_roles:
            inventory_row = inventory_by_path.get(absolute)
            if (
                inventory_row is None
                or inventory_row.get("role") != role
                or inventory_row.get("writer_service") != writer
            ):
                raise ContextRegistrarError(
                    f"mapping entry[{index}] DGP output role/path differs"
                )
        result.append(
            _PlanRecord(
                stage_kind=stage_kind,
                block_id=block_id,
                block_index=block_index,
                phase=phase,
                item_id=item_id,
                instance_index=instance_index,
                dgp_row_relative_path=dgp_row_relative,
                public_attestation_relative_path=attestation_relative,
                public_registry_relative_path=registry_relative,
                private_record_relative_path=private_relative,
            )
        )

    try:
        stage = StageKind(str(payload.get("stage_kind")))
    except ValueError as exc:
        raise ContextRegistrarError("stage kind is not registered") from exc
    shape = STAGE_SHAPES[stage]
    expected_coordinates = tuple(
        (
            stage.value,
            f"{stage.value}_block_{block_index + 1:02d}",
            block_index,
            phase,
            item_id,
            item_id - 1,
        )
        for block_index in range(shape.blocks)
        for phase in ("adaptation", "held_out")
        for item_id in range(1, shape.items_per_phase + 1)
    )
    coordinates = tuple(row.coordinate for row in result)
    if coordinates != expected_coordinates or len(coordinates) != len(set(coordinates)):
        raise ContextRegistrarError(
            "registry-v2 mapping is not the exact sorted full record closure"
        )
    public_targets = tuple(
        path
        for record in result
        for path in (
            record.public_attestation_relative_path,
            record.public_registry_relative_path,
        )
    )
    if len(public_targets) != len(set(public_targets)):
        raise ContextRegistrarError("registrar public target path is duplicated")
    return tuple(result)


def _validate_stage_plan_for_test(
    raw: bytes,
    *,
    validation_kwargs: Mapping[str, object],
    registrar_source: _FrozenRegistrarSource,
) -> tuple[dict[str, object], tuple[_PlanRecord, ...], str]:
    if type(raw) is not bytes:
        raise ContextRegistrarError("stage plan must be exact bytes")
    try:
        frozen_kwargs = dict(validation_kwargs)
        validation = stage_plan.validate_structured_stage_plan_bytes(
            raw, **frozen_kwargs
        )
    except (stage_plan.StructuredStagePlanError, TypeError, ValueError) as exc:
        raise ContextRegistrarError(
            "stage plan does not pass complete raw-byte reconstruction"
        ) from exc
    payload = _parse_canonical(raw, "stage plan")
    if payload.get("stage_plan_sha256") != validation.stage_plan_sha256:
        raise ContextRegistrarError("stage-plan validation result differs")
    if any(payload.get(key) is not False for key in _REQUIRED_PLAN_AUTHORITY_KEYS):
        raise ContextRegistrarError("stage plan carries forbidden authority")
    provider_status = payload.get("provider_status")
    if (
        type(provider_status) is not dict
        or provider_status.get("all_required_providers_available") is not False
        or provider_status.get("available_provider_ids") != []
    ):
        raise ContextRegistrarError("stage-plan provider status differs")
    _validate_plan_lifecycle(payload)
    source = _source_binding(payload, role="context_registrar")
    if (
        source.get("path") != registrar_source.path.as_posix()
        or source.get("sha256") != registrar_source.sha256
        or source.get("size_bytes") != len(registrar_source.raw)
    ):
        raise ContextRegistrarError(
            "stage-plan, caller, and executing registrar source identities differ"
        )
    scorer = _raw_source_binding(payload, binding_id="pure_scorer")
    scorer_sha = _require_sha(scorer.get("sha256"), "pure scorer source digest")
    records = _plan_records(payload)
    return payload, records, scorer_sha


def _freeze_bytes_map(value: Mapping[str, object], label: str) -> dict[str, bytes]:
    if not isinstance(value, Mapping):
        raise ContextRegistrarError(f"{label} must be a mapping")
    result: dict[str, bytes] = {}
    try:
        items = tuple(value.items())
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise ContextRegistrarError(f"{label} cannot be frozen") from exc
    for key, raw in items:
        relative = _relative_text(key, f"{label} key")
        if relative in result or type(raw) is not bytes:
            raise ContextRegistrarError(f"{label} has duplicate or non-byte entries")
        result[relative] = raw
    return result


def _target_sidecars(relative_path: str) -> tuple[str, str, str]:
    intent, pending = publication_sidecar_relative_paths(relative_path)
    return relative_path, intent, pending


def _assert_targets_absent(root: Path, relative_paths: tuple[str, ...]) -> None:
    for relative in relative_paths:
        for candidate in _target_sidecars(relative):
            if os.path.lexists(root / candidate):
                raise ContextRegistrarError(
                    "registrar found partial or previously committed publication"
                )


def _public_parent_paths(relative_paths: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                PurePosixPath(*PurePosixPath(relative).parts[:-1]).as_posix()
                for relative in relative_paths
            }
        )
    )


def _open_relative_directory(root_descriptor: int, relative: str) -> int:
    current = os.dup(root_descriptor)
    try:
        for component in PurePosixPath(relative).parts:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_descriptor
        return current
    except BaseException:
        os.close(current)
        raise


def _observe_public_parent_closure(
    root: Path, relative_paths: tuple[str, ...]
) -> tuple[_PublicDirectoryObservation, ...]:
    root_descriptor = os.open(
        root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        root_metadata = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
        ):
            raise ContextRegistrarError("public root ownership or mode differs")
        result = [
            _PublicDirectoryObservation(
                relative_path=".",
                device=root_metadata.st_dev,
                inode=root_metadata.st_ino,
                mode=stat.S_IMODE(root_metadata.st_mode),
                uid=root_metadata.st_uid,
                gid=root_metadata.st_gid,
            )
        ]
        for relative in _public_parent_paths(relative_paths):
            descriptor = _open_relative_directory(root_descriptor, relative)
            try:
                metadata = os.fstat(descriptor)
                path_metadata = os.stat(
                    root.joinpath(*PurePosixPath(relative).parts),
                    follow_symlinks=False,
                )
                stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
                if (
                    tuple(getattr(metadata, key) for key in stable)
                    != tuple(getattr(path_metadata, key) for key in stable)
                    or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_dev != root_metadata.st_dev
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    raise ContextRegistrarError(
                        "registered public parent ownership or identity differs"
                    )
                result.append(
                    _PublicDirectoryObservation(
                        relative_path=relative,
                        device=metadata.st_dev,
                        inode=metadata.st_ino,
                        mode=stat.S_IMODE(metadata.st_mode),
                        uid=metadata.st_uid,
                        gid=metadata.st_gid,
                    )
                )
            finally:
                os.close(descriptor)
        return tuple(result)
    except ContextRegistrarError:
        raise
    except OSError as exc:
        raise ContextRegistrarError(
            "registered public parent is missing or cannot be opened"
        ) from exc
    finally:
        os.close(root_descriptor)


def _fsync_directory_closure(root: Path, relative_paths: tuple[str, ...]) -> None:
    root_descriptor = os.open(
        root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        for relative in _public_parent_paths(relative_paths):
            descriptor = _open_relative_directory(root_descriptor, relative)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(root_descriptor)
    finally:
        os.close(root_descriptor)


def _expected_private_directories(
    relative_paths: tuple[str, ...],
) -> tuple[str, ...]:
    directories: set[str] = set()
    for relative in relative_paths:
        parts = PurePosixPath(relative).parts
        for stop in range(1, len(parts)):
            directories.add(PurePosixPath(*parts[:stop]).as_posix())
    return tuple(sorted(directories))


def _private_root_observation(metadata: os.stat_result) -> _PrivateRootObservation:
    return _PrivateRootObservation(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _validate_retained_private_root(
    retained: _RetainedPrivateRoot,
) -> _PrivateRootObservation:
    """Join the retained capability to the unchanged non-symlink path entry."""

    try:
        retained_metadata = os.fstat(retained.descriptor)
        path_metadata = os.stat(retained.path, follow_symlinks=False)
        path_descriptor = os.open(
            retained.path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            reopened_metadata = os.fstat(path_descriptor)
        finally:
            os.close(path_descriptor)
    except OSError as exc:
        raise ContextRegistrarError(
            "private root path no longer resolves to retained directory identity"
        ) from exc
    observations = (
        _private_root_observation(retained_metadata),
        _private_root_observation(path_metadata),
        _private_root_observation(reopened_metadata),
    )
    if (
        not stat.S_ISDIR(retained_metadata.st_mode)
        or not stat.S_ISDIR(path_metadata.st_mode)
        or not stat.S_ISDIR(reopened_metadata.st_mode)
        or any(observation != retained.observation for observation in observations)
        or retained.observation.uid != os.geteuid()
        or retained.observation.mode & 0o022
    ):
        raise ContextRegistrarError(
            "private root path no longer resolves to retained directory identity"
        )
    return retained.observation


def _retain_private_root(private_root: Path) -> _RetainedPrivateRoot:
    try:
        descriptor = os.open(
            private_root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise ContextRegistrarError(
            "private test root must be an existing secure directory"
        ) from exc
    retained = _RetainedPrivateRoot(
        path=private_root,
        descriptor=descriptor,
        observation=_private_root_observation(os.fstat(descriptor)),
    )
    try:
        _validate_retained_private_root(retained)
    except BaseException:
        os.close(descriptor)
        raise
    return retained


def _assert_private_root_empty(retained: _RetainedPrivateRoot) -> None:
    _validate_retained_private_root(retained)
    try:
        entries = os.listdir(retained.descriptor)
    except OSError as exc:
        raise ContextRegistrarError("private registry epoch cannot be listed") from exc
    if entries:
        raise ContextRegistrarError(
            "private registry epoch is not exactly empty before ordinal three"
        )


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    view = memoryview(raw)
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise ContextRegistrarError("private record write made no progress")
        offset += written


def _write_private_records(
    retained: _RetainedPrivateRoot, prepared: tuple[_PreparedRecord, ...]
) -> None:
    relative_paths = tuple(row.plan.private_record_relative_path for row in prepared)
    for relative in _expected_private_directories(relative_paths):
        pure = PurePosixPath(relative)
        parent_relative = pure.parent.as_posix()
        parent_descriptor = (
            os.dup(retained.descriptor)
            if parent_relative == "."
            else _open_relative_directory(retained.descriptor, parent_relative)
        )
        try:
            os.mkdir(pure.name, mode=0o750, dir_fd=parent_descriptor)
            child_descriptor = os.open(
                pure.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
            try:
                os.fchmod(child_descriptor, 0o750)
            finally:
                os.close(child_descriptor)
        finally:
            os.close(parent_descriptor)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    for record in prepared:
        pure = PurePosixPath(record.plan.private_record_relative_path)
        parent_descriptor = _open_relative_directory(
            retained.descriptor, pure.parent.as_posix()
        )
        try:
            descriptor = os.open(pure.name, flags, 0o600, dir_fd=parent_descriptor)
            try:
                _write_all(descriptor, record.private_bytes)
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o440)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_descriptor)
    for relative in reversed(_expected_private_directories(relative_paths)):
        descriptor = _open_relative_directory(retained.descriptor, relative)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    os.fsync(retained.descriptor)


def _observe_private_file(
    retained: _RetainedPrivateRoot, *, relative_path: str
) -> _PrivateFileObservation:
    pure = PurePosixPath(relative_path)
    parent_descriptor = _open_relative_directory(
        retained.descriptor, pure.parent.as_posix()
    )
    try:
        descriptor = os.open(
            pure.name,
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
                pure.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
        finally:
            os.close(descriptor)
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
        or stat.S_IMODE(after.st_mode) != 0o440
        or after.st_nlink != 1
    ):
        raise ContextRegistrarError("private record metadata changed or differs")
    raw = b"".join(chunks)
    return _PrivateFileObservation(
        relative_path=relative_path,
        device=after.st_dev,
        inode=after.st_ino,
        mode=stat.S_IMODE(after.st_mode),
        link_count=after.st_nlink,
        uid=after.st_uid,
        gid=after.st_gid,
        size_bytes=len(raw),
        mtime_ns=after.st_mtime_ns,
        ctime_ns=after.st_ctime_ns,
        sha256=_sha(raw),
    )


def _scan_private_tree(
    descriptor: int, *, parent_relative: str = ""
) -> tuple[list[str], list[str]]:
    observed_directories: list[str] = []
    observed_files: list[str] = []
    for name in sorted(os.listdir(descriptor)):
        relative = f"{parent_relative}/{name}" if parent_relative else name
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o750:
                raise ContextRegistrarError("private registry directory mode differs")
            child_descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                child_metadata = os.fstat(child_descriptor)
                stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
                if tuple(getattr(metadata, key) for key in stable) != tuple(
                    getattr(child_metadata, key) for key in stable
                ):
                    raise ContextRegistrarError(
                        "private registry directory identity changed"
                    )
                observed_directories.append(relative)
                child_directories, child_files = _scan_private_tree(
                    child_descriptor, parent_relative=relative
                )
                observed_directories.extend(child_directories)
                observed_files.extend(child_files)
            finally:
                os.close(child_descriptor)
        elif stat.S_ISREG(metadata.st_mode):
            observed_files.append(relative)
        else:
            raise ContextRegistrarError(
                "private registry contains a symlink or unsupported entry"
            )
    return observed_directories, observed_files


def _observe_private_closure(
    retained: _RetainedPrivateRoot, prepared: tuple[_PreparedRecord, ...]
) -> tuple[_PrivateFileObservation, ...]:
    expected_paths = tuple(row.plan.private_record_relative_path for row in prepared)
    expected_directories = _expected_private_directories(expected_paths)
    _validate_retained_private_root(retained)
    observed_directories, observed_files = _scan_private_tree(retained.descriptor)
    if tuple(sorted(observed_directories)) != expected_directories:
        raise ContextRegistrarError("private registry has missing or extra directories")
    if tuple(sorted(observed_files)) != tuple(sorted(expected_paths)):
        raise ContextRegistrarError("private registry has missing or extra records")
    result = tuple(
        _observe_private_file(
            retained,
            relative_path=relative,
        )
        for relative in expected_paths
    )
    expected_by_path = {
        record.plan.private_record_relative_path: record for record in prepared
    }
    if any(
        observation.sha256 != expected_by_path[observation.relative_path].hidden_sha256
        or observation.size_bytes
        != len(expected_by_path[observation.relative_path].private_bytes)
        for observation in result
    ):
        raise ContextRegistrarError("private registry digest or size differs")
    return result


def _same_public_observation(
    left: PublishedArtifactObservation, right: PublishedArtifactObservation
) -> bool:
    return left == right


def _validate_plan_source_bytes(
    payload: Mapping[str, object], *, role: str, raw: bytes
) -> None:
    source = _source_binding(payload, role=role)
    if (
        source.get("sha256") != _sha(raw)
        or source.get("size_bytes") != len(raw)
        or not raw
    ):
        raise ContextRegistrarError(f"stage-plan {role} source binding differs")


def _observe_initial_boundary_closure(
    *,
    public_root: Path,
    private_root: Path,
    payload: Mapping[str, object],
    initial_attestation_bytes: bytes,
    initial_probe_receipts_by_id: Mapping[str, bytes],
    attester_source_bytes: bytes,
    access_probe_source_bytes: bytes,
    validation_time_utc: str,
) -> _InitialBoundaryClosure:
    paths = payload.get("paths")
    if type(paths) is not dict:
        raise ContextRegistrarError("stage-plan initial-boundary paths differ")
    durable_root = paths.get("durable_root")
    initial_relative = _relative_to_base(
        paths.get("initial_boundary_attestation_path"),
        durable_root,
        "initial boundary attestation path",
    )
    raw_probe_paths = paths.get("initial_probe_receipt_paths")
    if type(raw_probe_paths) is not list:
        raise ContextRegistrarError("stage-plan initial probe paths differ")
    expected_probe_ids = tuple(private_boundary.INITIAL_PRIVATE_PROBE_IDS)
    if tuple(initial_probe_receipts_by_id) != expected_probe_ids:
        raise ContextRegistrarError(
            "initial probe receipt map is not the exact ordered 14-probe closure"
        )
    probe_paths: list[tuple[str, str]] = []
    for index, row in enumerate(raw_probe_paths):
        if type(row) is not dict or set(row) != {"probe_id", "path"}:
            raise ContextRegistrarError(f"initial probe path[{index}] differs")
        probe_id = row["probe_id"]
        if probe_id != expected_probe_ids[index]:
            raise ContextRegistrarError("initial probe path order differs")
        relative = _relative_to_base(
            row["path"], durable_root, f"initial probe path[{index}]"
        )
        expected_suffix = f"control/private_boundary/initial/probes/{probe_id}.json"
        if not relative.endswith("/" + expected_suffix):
            raise ContextRegistrarError("initial probe fixed path differs")
        probe_paths.append((probe_id, relative))
    _validate_plan_source_bytes(
        payload, role="private_context_access_boundary", raw=attester_source_bytes
    )
    _validate_plan_source_bytes(
        payload, role="private_access_probe_source", raw=access_probe_source_bytes
    )
    try:
        persisted_initial, initial_observation = read_and_validate_readonly_artifact(
            root=public_root,
            relative_path=initial_relative,
            expected_payload=initial_attestation_bytes,
        )
        probe_observations: list[tuple[str, PublishedArtifactObservation]] = []
        persisted_probes: dict[str, bytes] = {}
        for probe_id, relative in probe_paths:
            raw, observation = read_and_validate_readonly_artifact(
                root=public_root,
                relative_path=relative,
                expected_payload=initial_probe_receipts_by_id[probe_id],
            )
            persisted_probes[probe_id] = raw
            probe_observations.append((probe_id, observation))
        validation = private_boundary.validate_initial_registration_boundary_bytes(
            persisted_initial,
            access_probe_receipts_by_id=persisted_probes,
            attester_source_bytes=attester_source_bytes,
            access_probe_source_bytes=access_probe_source_bytes,
            validation_time_utc=validation_time_utc,
        )
    except (AtomicPublicationError, private_boundary.PrivateBoundaryError) as exc:
        raise ContextRegistrarError(
            "ordinal-two initial boundary semantic closure differs"
        ) from exc
    initial_value = _parse_canonical(persisted_initial, "initial boundary attestation")
    stage_relative = _relative_to_base(
        paths.get("stage_root"), durable_root, "stage root"
    )
    expected_test_public_root = public_root.joinpath(
        *PurePosixPath(stage_relative).parts
    ).as_posix()
    if (
        validation.source_commit != payload.get("source_commit")
        or validation.experiment_attempt_id != payload.get("experiment_attempt_id")
        or validation.stage_kind != payload.get("stage_kind")
        or validation.stage_attempt_id != payload.get("stage_attempt_id")
        or validation.private_context_root != private_root.as_posix()
        or initial_value.get("public_durable_root") != expected_test_public_root
        or any(getattr(validation, key) is not False for key in _AUTHORITY_KEYS)
    ):
        raise ContextRegistrarError(
            "ordinal-two initial boundary does not bind this test stage epoch"
        )
    return _InitialBoundaryClosure(
        validation=validation,
        initial_observation=initial_observation,
        probe_observations=tuple(probe_observations),
    )


def _prepare_records(
    *,
    public_root: Path,
    plans: tuple[_PlanRecord, ...],
    scorer_source_sha256: str,
    hidden_by_path: Mapping[str, bytes],
    opaque_by_path: Mapping[str, bytes],
) -> tuple[_PreparedRecord, ...]:
    prepared: list[_PreparedRecord] = []
    for plan in plans:
        row_raw, row_observation = read_and_validate_readonly_artifact(
            root=public_root, relative_path=plan.dgp_row_relative_path
        )
        row = load_dgp_row_identity(row_raw)
        if row.item_id != plan.item_id or row.instance_index != plan.instance_index:
            raise ContextRegistrarError("DGP row coordinate differs from stage mapping")
        hidden_raw = hidden_by_path[plan.private_record_relative_path]
        opaque_raw = opaque_by_path[plan.private_record_relative_path]
        hidden_sha = _sha(hidden_raw)
        opaque_sha = _sha(opaque_raw)
        stage = StageKind(plan.stage_kind)
        phase = PhaseKind(plan.phase)
        scoring_sha = compute_scoring_context_sha256(
            scorer_source_sha256=scorer_source_sha256,
            dataset_ground_truth_sha256=row.ground_truth_sha256,
            instance_id=row.instance_id,
            instance_index=row.instance_index,
            reference_survival_sha256=row.reference_survival_sha256,
        )
        identity_sha = compute_public_context_identity_sha256(
            stage_kind=stage,
            block_id=plan.block_id,
            block_index=plan.block_index,
            phase=phase,
            item_id=plan.item_id,
            instance_index=plan.instance_index,
            instance_id=row.instance_id,
            query_sha256=row.query_sha256,
            opaque_handle_sha256=opaque_sha,
            hidden_registry_entry_sha256=hidden_sha,
            scoring_context_sha256=scoring_sha,
        )
        attestation = PublicScoringContextAttestation(
            opaque_handle_sha256=opaque_sha,
            scoring_context_sha256=scoring_sha,
            hidden_registry_entry_sha256=hidden_sha,
        )
        record = ContextRegistryRecord(
            stage_kind=stage,
            block_id=plan.block_id,
            block_index=plan.block_index,
            phase=phase,
            item_id=plan.item_id,
            instance_index=plan.instance_index,
            instance_id=row.instance_id,
            query_sha256=row.query_sha256,
            scorer_source_sha256=scorer_source_sha256,
            dataset_ground_truth_sha256=row.ground_truth_sha256,
            reference_survival_sha256=row.reference_survival_sha256,
            opaque_handle_sha256=opaque_sha,
            hidden_registry_entry_sha256=hidden_sha,
            scoring_context_sha256=scoring_sha,
            public_context_identity_sha256=identity_sha,
        )
        attestation_raw = canonical_json_bytes(attestation.to_payload())
        registry_raw = canonical_json_bytes(record.to_payload())
        load_public_scoring_context_attestation(attestation_raw)
        load_context_registry_record(registry_raw)
        completion_row: dict[str, object] = {
            "block_id": plan.block_id,
            "block_index": plan.block_index,
            "hidden_sha256": hidden_sha,
            "instance_id": row.instance_id,
            "instance_index": plan.instance_index,
            "item_id": plan.item_id,
            "opaque_handle_sha256": opaque_sha,
            "relative_path": plan.private_record_relative_path,
            "phase": plan.phase,
            "public_context_identity_sha256": identity_sha,
            "size_bytes": len(hidden_raw),
            "stage_kind": plan.stage_kind,
        }
        prepared.append(
            _PreparedRecord(
                plan=plan,
                private_bytes=hidden_raw,
                opaque_handle_sha256=opaque_sha,
                hidden_sha256=hidden_sha,
                public_attestation_bytes=attestation_raw,
                public_registry_bytes=registry_raw,
                completion_row=completion_row,
                dgp_row_observation=row_observation,
            )
        )
    if len({row.opaque_handle_sha256 for row in prepared}) != len(prepared):
        raise ContextRegistrarError("registrar reuses an opaque handle digest")
    public_identities = tuple(
        str(row.completion_row["public_context_identity_sha256"]) for row in prepared
    )
    if len(set(public_identities)) != len(public_identities):
        raise ContextRegistrarError("registrar reuses a public context identity")
    completion_rows = tuple(row.completion_row for row in prepared)
    if completion_rows != tuple(
        sorted(
            completion_rows,
            key=lambda row: (
                row["stage_kind"],
                row["block_id"],
                row["block_index"],
                row["phase"],
                row["item_id"],
                row["instance_index"],
                row["instance_id"],
                row["public_context_identity_sha256"],
                row["opaque_handle_sha256"],
                row["relative_path"],
                row["hidden_sha256"],
                row["size_bytes"],
            ),
        )
    ):
        raise ContextRegistrarError("completion rows are not exactly sorted")
    return tuple(prepared)


def _receipt_bytes(
    *,
    payload: Mapping[str, object],
    prepared: tuple[_PreparedRecord, ...],
    initial_attestation_sha256: str,
    private_context_root: Path,
    registrar_source: _FrozenRegistrarSource,
    runtime: _RegistrarTestRuntime,
) -> bytes:
    completed_at = runtime.completed_at_utc()
    boot_id = runtime.boot_id()
    process = dict(runtime.process_identity())
    if type(completed_at) is not str or _UTC_RE.fullmatch(completed_at) is None:
        raise ContextRegistrarError("registrar runtime UTC value differs")
    if type(boot_id) is not str or _BOOT_ID_RE.fullmatch(boot_id) is None:
        raise ContextRegistrarError("registrar runtime boot id differs")
    rows = [dict(record.completion_row) for record in prepared]
    unsigned: dict[str, object] = {
        "boot_id": boot_id,
        "completed_at_utc": completed_at,
        "experiment_attempt_id": payload["experiment_attempt_id"],
        "initial_registration_attestation_sha256": initial_attestation_sha256,
        "private_context_root": private_context_root.as_posix(),
        "process_identity": process,
        "protocol": private_boundary.REGISTRY_COMPLETION_PROTOCOL,
        "record_set_sha256": _sha(_canonical(rows)),
        "registered_record_count": len(rows),
        "registered_records": rows,
        "registrar_source": {
            "path": registrar_source.path.as_posix(),
            "sha256": registrar_source.sha256,
            "size_bytes": len(registrar_source.raw),
        },
        "schema_version": private_boundary.REGISTRY_COMPLETION_SCHEMA_VERSION,
        "source_commit": payload["source_commit"],
        "stage_attempt_id": payload["stage_attempt_id"],
        "stage_kind": payload["stage_kind"],
        "status": private_boundary.REGISTRY_COMPLETION_STATUS,
        **_authority_false(),
    }
    raw = _canonical(
        {
            **unsigned,
            "registry_completion_receipt_sha256": _sha(_canonical(unsigned)),
        }
    )
    try:
        private_boundary._validate_registry_completion_receipt_bytes(  # noqa: SLF001
            raw, registrar_source_bytes=registrar_source.raw
        )
    except private_boundary.PrivateBoundaryError as exc:
        raise ContextRegistrarError(
            "constructed receipt differs from exact private-boundary schema"
        ) from exc
    return raw


def validate_registry_completion_bytes(
    raw: bytes, *, registrar_source_bytes: bytes
) -> ContextRegistrarValidation:
    """Validate public receipt bytes without hidden contents or authority."""

    try:
        validation = private_boundary._validate_registry_completion_receipt_bytes(  # noqa: SLF001
            raw, registrar_source_bytes=registrar_source_bytes
        )
    except private_boundary.PrivateBoundaryError as exc:
        raise ContextRegistrarError("registry-completion-v2 validation failed") from exc
    return ContextRegistrarValidation(
        source_commit=validation.source_commit,
        experiment_attempt_id=validation.experiment_attempt_id,
        stage_kind=validation.stage_kind,
        stage_attempt_id=validation.stage_attempt_id,
        private_context_root=validation.private_context_root,
        registered_record_count=len(validation.registered_records),
        registry_completion_receipt_sha256=(
            validation.registry_completion_receipt_sha256
        ),
    )


def register_structured_contexts_and_publish_completion(
    *,
    stage_root: Path,
    private_context_root: Path,
    source_commit: str,
    experiment_attempt_id: str,
    stage_kind: str,
    stage_attempt_id: str,
) -> ContextRegistrarArtifacts:
    """Fail before runtime, filesystem, stage-plan, or hidden-byte access."""

    del (
        stage_root,
        private_context_root,
        source_commit,
        experiment_attempt_id,
        stage_kind,
        stage_attempt_id,
    )
    raise ContextRegistrarError(
        "production context-registrar provider is unavailable; exact stage-plan "
        "runtime join, private root capability, and registrar identity provider "
        "are required"
    )


def _register_and_publish_for_test(
    *,
    public_root: Path,
    private_root: Path,
    stage_plan_bytes: bytes,
    stage_plan_validation_kwargs: Mapping[str, object],
    initial_registration_attestation_bytes: bytes,
    initial_access_probe_receipts_by_id: Mapping[str, bytes],
    attester_source_bytes: bytes,
    access_probe_source_bytes: bytes,
    initial_validation_time_utc: str,
    registrar_source_path: Path,
    registrar_source_bytes: bytes,
    hidden_record_bytes_by_relative_path: Mapping[str, object],
    opaque_handle_bytes_by_relative_path: Mapping[str, object],
    runtime: _RegistrarTestRuntime,
) -> ContextRegistrarArtifacts:
    """Private prospective seam; production roots are rejected immediately."""

    public_root = _test_root(
        public_root,
        label="public test root",
        production_prefix=_PRODUCTION_PUBLIC_PREFIX,
    )
    private_root = _test_root(
        private_root,
        label="private test root",
        production_prefix=_PRODUCTION_PRIVATE_PREFIX,
    )
    if not isinstance(runtime, _RegistrarTestRuntime):
        raise ContextRegistrarError("runtime must be the private registrar test seam")
    registrar_source = _freeze_actual_registrar_source(
        caller_path=registrar_source_path, caller_bytes=registrar_source_bytes
    )
    payload, plans, scorer_sha = _validate_stage_plan_for_test(
        stage_plan_bytes,
        validation_kwargs=stage_plan_validation_kwargs,
        registrar_source=registrar_source,
    )
    paths = payload.get("paths")
    if type(paths) is not dict:
        raise ContextRegistrarError("stage-plan paths differ")
    completion_relative = _relative_to_base(
        paths.get("registry_completion_receipt_path"),
        paths.get("durable_root"),
        "registry completion path",
    )
    stage_relative = _relative_to_base(
        paths.get("stage_root"), paths.get("durable_root"), "stage root"
    )
    if completion_relative != (f"{stage_relative}/{REGISTRY_COMPLETION_RELATIVE_PATH}"):
        raise ContextRegistrarError("registry completion fixed path differs")
    hidden = _freeze_bytes_map(
        hidden_record_bytes_by_relative_path, "hidden record bytes"
    )
    opaque = _freeze_bytes_map(
        opaque_handle_bytes_by_relative_path, "opaque handle bytes"
    )
    expected_private_paths = tuple(
        record.private_record_relative_path for record in plans
    )
    if set(hidden) != set(expected_private_paths) or set(opaque) != set(
        expected_private_paths
    ):
        raise ContextRegistrarError(
            "hidden and opaque inputs must exactly cover the registry mapping"
        )
    if (
        type(initial_registration_attestation_bytes) is not bytes
        or type(attester_source_bytes) is not bytes
        or type(access_probe_source_bytes) is not bytes
        or type(initial_validation_time_utc) is not str
    ):
        raise ContextRegistrarError(
            "initial semantic-closure inputs must be exact bytes and UTC text"
        )
    try:
        initial_closure = _observe_initial_boundary_closure(
            public_root=public_root,
            private_root=private_root,
            payload=payload,
            initial_attestation_bytes=initial_registration_attestation_bytes,
            initial_probe_receipts_by_id=initial_access_probe_receipts_by_id,
            attester_source_bytes=attester_source_bytes,
            access_probe_source_bytes=access_probe_source_bytes,
            validation_time_utc=initial_validation_time_utc,
        )
        prepared = _prepare_records(
            public_root=public_root,
            plans=plans,
            scorer_source_sha256=scorer_sha,
            hidden_by_path=hidden,
            opaque_by_path=opaque,
        )
    except ContextRegistrarError:
        raise
    except (AtomicPublicationError, DgpContextIntegrityError, OSError) as exc:
        raise ContextRegistrarError(
            "persisted initial boundary or DGP row closure differs"
        ) from exc

    public_targets = tuple(
        path
        for record in plans
        for path in (
            record.public_attestation_relative_path,
            record.public_registry_relative_path,
        )
    )
    _assert_targets_absent(public_root, public_targets + (completion_relative,))
    parent_paths = public_targets + (completion_relative,)
    retained_private_root = _retain_private_root(private_root)
    public_observations: list[PublishedArtifactObservation] = []
    try:
        _assert_private_root_empty(retained_private_root)
        initial_public_parents = _observe_public_parent_closure(
            public_root, parent_paths
        )
        _write_private_records(retained_private_root, prepared)
        first_private = _observe_private_closure(retained_private_root, prepared)
        for record in prepared:
            for relative, raw in (
                (
                    record.plan.public_attestation_relative_path,
                    record.public_attestation_bytes,
                ),
                (
                    record.plan.public_registry_relative_path,
                    record.public_registry_bytes,
                ),
            ):
                public_observations.append(
                    publish_readonly_no_overwrite(
                        root=public_root, relative_path=relative, payload=raw
                    )
                )
        _fsync_directory_closure(public_root, parent_paths)
        parents_before_callback = _observe_public_parent_closure(
            public_root, parent_paths
        )
        if initial_public_parents != parents_before_callback:
            raise ContextRegistrarError(
                "registered public parent identity changed during publication"
            )
        _validate_retained_private_root(retained_private_root)
        runtime.before_completion_revalidation()
        _validate_retained_private_root(retained_private_root)

        second_initial_closure = _observe_initial_boundary_closure(
            public_root=public_root,
            private_root=private_root,
            payload=payload,
            initial_attestation_bytes=initial_registration_attestation_bytes,
            initial_probe_receipts_by_id=initial_access_probe_receipts_by_id,
            attester_source_bytes=attester_source_bytes,
            access_probe_source_bytes=access_probe_source_bytes,
            validation_time_utc=initial_validation_time_utc,
        )
        if second_initial_closure != initial_closure:
            raise ContextRegistrarError(
                "initial boundary semantic closure changed during registration"
            )
        parents_after_callback = _observe_public_parent_closure(
            public_root, parent_paths
        )
        if parents_after_callback != parents_before_callback:
            raise ContextRegistrarError(
                "registered public parent identity changed across callback"
            )
        for record in prepared:
            _, row_observation = read_and_validate_readonly_artifact(
                root=public_root,
                relative_path=record.plan.dgp_row_relative_path,
            )
            if not _same_public_observation(
                record.dgp_row_observation, row_observation
            ):
                raise ContextRegistrarError("DGP row changed during registration")
        reopened_public: list[PublishedArtifactObservation] = []
        for record in prepared:
            for relative, raw in (
                (
                    record.plan.public_attestation_relative_path,
                    record.public_attestation_bytes,
                ),
                (
                    record.plan.public_registry_relative_path,
                    record.public_registry_bytes,
                ),
            ):
                _, observation = read_and_validate_readonly_artifact(
                    root=public_root,
                    relative_path=relative,
                    expected_payload=raw,
                )
                reopened_public.append(observation)
        if tuple(public_observations) != tuple(reopened_public):
            raise ContextRegistrarError(
                "public context artifact changed during registration"
            )
        second_private = _observe_private_closure(retained_private_root, prepared)
        if first_private != second_private:
            raise ContextRegistrarError(
                "private record changed during completion revalidation"
            )
        _validate_retained_private_root(retained_private_root)
        _assert_targets_absent(public_root, (completion_relative,))
        receipt_raw = _receipt_bytes(
            payload=payload,
            prepared=prepared,
            initial_attestation_sha256=(
                initial_closure.validation.private_boundary_attestation_sha256
            ),
            private_context_root=private_root,
            registrar_source=registrar_source,
            runtime=runtime,
        )
        receipt_publication = publish_readonly_no_overwrite(
            root=public_root,
            relative_path=completion_relative,
            payload=receipt_raw,
        )
        _fsync_directory_closure(public_root, (completion_relative,))
        reopened_receipt, reopened_receipt_observation = (
            read_and_validate_readonly_artifact(
                root=public_root,
                relative_path=completion_relative,
                expected_payload=receipt_raw,
            )
        )
        if (
            reopened_receipt != receipt_raw
            or receipt_publication != reopened_receipt_observation
        ):
            raise ContextRegistrarError(
                "registry completion changed after atomic publication"
            )
        _validate_retained_private_root(retained_private_root)
    except ContextRegistrarError:
        raise
    except (AtomicPublicationError, DgpContextIntegrityError, OSError) as exc:
        raise ContextRegistrarError(
            "registrar publication or persisted closure validation failed"
        ) from exc
    finally:
        os.close(retained_private_root.descriptor)

    validation = validate_registry_completion_bytes(
        receipt_raw, registrar_source_bytes=registrar_source.raw
    )
    receipt_value = _parse_canonical(receipt_raw, "registry completion receipt")
    return ContextRegistrarArtifacts(
        receipt_bytes=receipt_raw,
        receipt_publication=receipt_publication,
        public_artifact_publications=tuple(public_observations),
        registered_record_count=validation.registered_record_count,
        record_set_sha256=str(receipt_value["record_set_sha256"]),
        registry_completion_receipt_sha256=(
            validation.registry_completion_receipt_sha256
        ),
    )
