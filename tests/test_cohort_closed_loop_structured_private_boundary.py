from __future__ import annotations

import errno
import importlib.util
import inspect
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pytest

import cohort_closed_loop_structured_private_boundary as boundary


SOURCE_COMMIT = "a" * 40
EXPERIMENT_ATTEMPT_ID = "attempt-001"
STAGE_KIND = "smoke"
STAGE_ATTEMPT_ID = "attempt-001"
BOOT_ID = "12345678-1234-1234-1234-123456789abc"
REGISTRAR_SOURCE = b"registrar source bound by the protocol-plan inventory\n"
SECRET_RECORD_BYTES = b"TOP-SECRET-HIDDEN-CONTEXT-DO-NOT-EXPOSE"
ACCESS_PROBE_SOURCE = (
    Path(boundary.__file__)
    .with_name("cohort_closed_loop_private_access_probe.c")
    .read_bytes()
)
RECORD_RELATIVE = "records/smoke_block_01/adaptation/1.json"


def _stage_plan_fixture_module() -> object:
    name = "_private_boundary_stage_plan_fixture"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).with_name("test_cohort_closed_loop_structured_stage_plan.py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load structured stage-plan fixture")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class _Chain:
    public_root: Path
    private_root: Path
    initial: boundary.PrivateBoundaryArtifacts
    initial_receipts: dict[str, bytes]
    registry_receipt: bytes
    sealed: boundary.PrivateBoundaryArtifacts
    sealed_receipts: dict[str, bytes]
    source_bytes: bytes


def _mountinfo(root: Path, mode: str, *, duplicate: bool = False) -> bytes:
    metadata = root.stat()
    major_minor = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    escaped = str(root).replace("\\", "\\134").replace(" ", "\\040")
    row = (
        f"100 1 {major_minor} / {escaped} {mode},nodev,nosuid "
        f"- ext4 /dev/private {mode},nodev,nosuid\n"
    ).encode("ascii")
    return row + row if duplicate else row


def _probe_receipt(
    request: boundary._ProbeRequest,
    *,
    private_root: Path,
    mutate: Callable[[boundary._ProbeRequest, dict[str, object]], None] | None,
) -> bytes:
    path = Path(request.path)
    raw_errno = request.accepted_errnos[0]
    content_sha256 = request.expected_content_sha256
    if request.operation == "create_exact_probe":
        assert request.probe_payload is not None
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o440,
        )
        try:
            os.write(descriptor, request.probe_payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o440)
        content_sha256 = boundary._sha(path.read_bytes())
    elif request.allowed and request.operation in {
        "read_exact_probe",
        "read_registered_record",
    }:
        content_sha256 = boundary._sha(path.read_bytes())
    elif request.operation == "remove_exact_probe":
        path.unlink()
        content_sha256 = None
    elif request.operation == "verify_probe_absent":
        try:
            path.lstat()
        except FileNotFoundError:
            raw_errno = errno.ENOENT
        else:
            raw_errno = 0
    elif request.operation in {"enumerate_root", "read_exact_probe"}:
        assert path == private_root or path.parent == private_root

    common: dict[str, object] = {
        "access_policy_sha256": request.access_policy_sha256,
        "adapter_sha256": request.adapter_sha256,
        "credential_transition": (
            "setgroups_then_setresgid_then_setresuid_no_active_capabilities"
        ),
        "invoking_uid_before_transition": boundary.ATTESTER_UID,
        "pre_transition_effective_gid": boundary.ATTESTER_UID,
        "pre_transition_effective_uid": 0,
        "pre_transition_real_gid": boundary.ATTESTER_UID,
        "pre_transition_real_uid": boundary.ATTESTER_UID,
        "pre_transition_saved_gid": boundary.ATTESTER_UID,
        "pre_transition_saved_uid": 0,
        "observed_active_capabilities_empty": True,
        "observed_all_capability_sets_zero": True,
        "observed_effective_gid": request.target_gid,
        "observed_effective_uid": request.target_uid,
        "observed_real_gid": request.target_gid,
        "observed_real_uid": request.target_uid,
        "observed_saved_gid": request.target_gid,
        "observed_saved_uid": request.target_uid,
        "observed_supplementary_gids": list(request.target_supplementary_gids),
        "observed_no_new_privs": True,
        "observed_securebits": boundary._LOCKED_SECUREBITS,
        "self_executable_device": request.adapter_device,
        "self_executable_inode": request.adapter_inode,
        "self_executable_sha256": request.adapter_sha256,
        "self_executable_size_bytes": request.adapter_size_bytes,
        "operation": request.operation,
        "path": request.path,
        "probe_id": request.probe_id,
        "protocol": request.protocol,
        "raw_errno": raw_errno,
        "schema_version": boundary.PROBE_SCHEMA_VERSION,
        "stage": request.stage,
        "target_gid": request.target_gid,
        "target_supplementary_gids": list(request.target_supplementary_gids),
        "target_uid": request.target_uid,
    }
    if request.absence_receipt:
        value = {**common, "absent": raw_errno == errno.ENOENT}
    else:
        value = {
            **common,
            "allowed": request.allowed,
            "content_sha256": content_sha256,
        }
    if mutate is not None:
        mutate(request, value)
    return boundary._canonical(value)


def _runtime(
    private_root: Path,
    *,
    mount_mode: str,
    started: str,
    completed: str,
    mutate_probe: Callable[[boundary._ProbeRequest, dict[str, object]], None]
    | None = None,
    duplicate_mount: bool = False,
    mountinfo_bytes: bytes | None = None,
    namespace_values: tuple[boundary._NamespaceObservation, ...] | None = None,
    adapter: boundary._AdapterObservation | None = None,
    process: boundary._ProcessObservation | None = None,
    xattrs_for_fd: Callable[[int], tuple[str, ...]] | None = None,
) -> boundary._PrivateBoundaryRuntime:
    times = iter((started, completed))
    namespaces = iter(
        namespace_values
        or (
            boundary._NamespaceObservation(11, 22, "mnt:[22]"),
            boundary._NamespaceObservation(11, 22, "mnt:[22]"),
        )
    )
    mount_raw = (
        mountinfo_bytes
        if mountinfo_bytes is not None
        else _mountinfo(private_root, mount_mode, duplicate=duplicate_mount)
    )
    adapter_value = adapter or boundary._AdapterObservation(
        path=str(boundary.SETUID_ADAPTER_PATH),
        device=3,
        inode=4,
        mode=0o4750,
        owner_uid=0,
        group_gid=boundary.ATTESTER_UID,
        sha256="f" * 64,
        size_bytes=128,
        link_count=1,
        extended_attributes_empty=True,
        trusted_ancestors=tuple(
            {
                "device": 3,
                "group_gid": 0,
                "inode": index + 10,
                "mode": 0o755,
                "owner_uid": 0,
                "path": path,
            }
            for index, path in enumerate(
                ("/", "/usr", "/usr/local", "/usr/local/libexec")
            )
        ),
        adapter_mount=boundary._MountRecord(
            mount_id=1,
            parent_id=0,
            major_minor=boundary._major_minor(3),
            mount_root="/",
            mount_point="/",
            mount_options="rw,suid",
            filesystem_type="ext4",
            mount_source="/dev/root",
            super_options="rw,suid",
        ),
    )
    process_value = process or boundary._ProcessObservation(
        pid=123,
        real_uid=boundary.ATTESTER_UID,
        effective_uid=boundary.ATTESTER_UID,
        saved_uid=boundary.ATTESTER_UID,
        real_gid=boundary.ATTESTER_UID,
        effective_gid=boundary.ATTESTER_UID,
        saved_gid=boundary.ATTESTER_UID,
        supplementary_gids=(boundary.PRIVATE_READ_GID,),
        active_capabilities_empty=True,
        process_start_ticks=456,
        service_identity=boundary.ATTESTER_SERVICE_IDENTITY,
    )
    return boundary._PrivateBoundaryRuntime(
        euid=lambda: boundary.ATTESTER_UID,
        identity_for_uid=lambda _uid: boundary.ATTESTER_SERVICE_IDENTITY,
        now_utc=lambda: next(times),
        boot_id=lambda: BOOT_ID,
        process_identity=lambda: process_value,
        mount_namespace=lambda: next(namespaces),
        mountinfo_bytes=lambda: mount_raw,
        uid_translate=lambda uid: (
            boundary.REGISTRAR_UID if uid == os.geteuid() else uid
        ),
        gid_translate=lambda gid: (
            boundary.PRIVATE_READ_GID if gid == os.getegid() else gid
        ),
        xattrs_for_fd=xattrs_for_fd or (lambda _descriptor: ()),
        open_adapter=lambda: boundary._VerifiedAdapterHandle(
            observation=adapter_value,
            descriptor=-1,
            close_descriptor=False,
        ),
        access_probe=lambda request, _handle: _probe_receipt(
            request,
            private_root=private_root,
            mutate=mutate_probe,
        ),
    )


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    public_root = tmp_path / "public"
    private_root = tmp_path / "private"
    (public_root / "control").mkdir(parents=True)
    for phase in ("initial", "sealed"):
        (public_root / "control" / "private_boundary" / phase / "probes").mkdir(
            parents=True
        )
    (public_root / "control" / "private_boundary" / "registry").mkdir(parents=True)
    private_root.mkdir()
    public_root.chmod(0o700)
    (public_root / "control").chmod(0o700)
    private_root.chmod(0o750)
    return public_root, private_root


def _write_registered_record(
    private_root: Path,
    *,
    relative_path: str = RECORD_RELATIVE,
    payload: bytes = SECRET_RECORD_BYTES,
    mode: int = 0o440,
) -> Path:
    record = private_root / relative_path
    record.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    current = record.parent
    while current != private_root:
        current.chmod(0o750)
        current = current.parent
    record.write_bytes(payload)
    record.chmod(mode)
    return record


def _write_smoke_records(
    private_root: Path,
    *,
    first_mode: int = 0o440,
) -> tuple[str, ...]:
    records: list[str] = []
    for phase in ("adaptation", "held_out"):
        for item_id in range(1, 6):
            relative = f"records/smoke_block_01/{phase}/{item_id}.json"
            payload = (
                SECRET_RECORD_BYTES
                if relative == RECORD_RELATIVE
                else f"hidden:{phase}:{item_id}".encode("ascii")
            )
            _write_registered_record(
                private_root,
                relative_path=relative,
                payload=payload,
                mode=first_mode if relative == RECORD_RELATIVE else 0o440,
            )
            records.append(relative)
    return tuple(sorted(records))


def _attest_initial(
    public_root: Path,
    private_root: Path,
    *,
    runtime: boundary._PrivateBoundaryRuntime | None = None,
) -> boundary.PrivateBoundaryArtifacts:
    return boundary._attest_private_boundary_for_test(
        stage=boundary.INITIAL_REGISTRATION_STAGE,
        public_root=public_root,
        private_root=private_root,
        source_commit=SOURCE_COMMIT,
        experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
        stage_kind=STAGE_KIND,
        stage_attempt_id=STAGE_ATTEMPT_ID,
        expected_record_paths=(),
        probe_record_relative_path=None,
        initial_registration_attestation_bytes=None,
        initial_access_probe_receipts_by_id=None,
        registry_completion_receipt_bytes=None,
        registrar_source_bytes=None,
        runtime=runtime
        or _runtime(
            private_root,
            mount_mode="rw",
            started="2026-07-14T12:00:00Z",
            completed="2026-07-14T12:00:05Z",
        ),
    )


def _registry_receipt(
    *,
    public_root: Path,
    private_root: Path,
    initial: boundary.PrivateBoundaryArtifacts,
    records: tuple[str, ...],
    completed_at: str = "2026-07-14T12:01:00Z",
    publish: bool = True,
) -> bytes:
    initial_value = json.loads(initial.attestation_bytes)
    registered_records = []
    for relative in records:
        parts = relative.split("/")
        assert len(parts) == 4 and parts[0] == "records"
        block_id, phase = parts[1:3]
        item_id = int(Path(parts[3]).stem)
        registered_records.append(
            {
                "stage_kind": STAGE_KIND,
                "block_id": block_id,
                "block_index": int(block_id.rsplit("_", 1)[1]) - 1,
                "phase": phase,
                "item_id": item_id,
                "instance_index": item_id - 1,
                "instance_id": f"instance-{item_id:03d}",
                "public_context_identity_sha256": boundary._sha(
                    f"public:{relative}".encode("ascii")
                ),
                "opaque_handle_sha256": boundary._sha(
                    f"opaque:{relative}".encode("ascii")
                ),
                "relative_path": relative,
                "hidden_sha256": boundary._sha((private_root / relative).read_bytes()),
                "size_bytes": (private_root / relative).stat().st_size,
            }
        )
    registered_records.sort(
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
        )
    )
    unsigned = {
        "protocol": boundary.REGISTRY_COMPLETION_PROTOCOL,
        "schema_version": boundary.REGISTRY_COMPLETION_SCHEMA_VERSION,
        "status": boundary.REGISTRY_COMPLETION_STATUS,
        "source_commit": SOURCE_COMMIT,
        "experiment_attempt_id": EXPERIMENT_ATTEMPT_ID,
        "stage_kind": STAGE_KIND,
        "stage_attempt_id": STAGE_ATTEMPT_ID,
        "private_context_root": str(private_root),
        "initial_registration_attestation_sha256": initial_value[
            "private_boundary_attestation_sha256"
        ],
        "registered_records": registered_records,
        "registered_record_count": len(registered_records),
        "record_set_sha256": boundary._sha(boundary._canonical(registered_records)),
        "completed_at_utc": completed_at,
        "boot_id": BOOT_ID,
        "process_identity": {
            "active_capabilities_empty": True,
            "effective_gid": boundary.PRIVATE_READ_GID,
            "effective_uid": boundary.REGISTRAR_UID,
            "pid": 200,
            "process_start_ticks": 300,
            "real_gid": boundary.PRIVATE_READ_GID,
            "real_uid": boundary.REGISTRAR_UID,
            "saved_gid": boundary.PRIVATE_READ_GID,
            "saved_uid": boundary.REGISTRAR_UID,
            "service_identity": boundary.REGISTRAR_SERVICE_IDENTITY,
            "supplementary_gids": [],
        },
        "registrar_source": {
            "path": "/srv/cohort_closed_loop_structured_context_registrar.py",
            "sha256": boundary._sha(REGISTRAR_SOURCE),
            "size_bytes": len(REGISTRAR_SOURCE),
        },
        **boundary._authority_false(),
    }
    raw = boundary._canonical(
        {
            **unsigned,
            "registry_completion_receipt_sha256": boundary._sha(
                boundary._canonical(unsigned)
            ),
        }
    )
    if publish:
        boundary.publish_readonly_no_overwrite(
            root=public_root,
            relative_path=boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH,
            payload=raw,
        )
    return raw


def _build_chain(
    tmp_path: Path,
    *,
    sealed_mutator: Callable[[boundary._ProbeRequest, dict[str, object]], None]
    | None = None,
    sealed_mount_mode: str = "ro",
    sealed_duplicate_mount: bool = False,
    sealed_times: tuple[str, str] = (
        "2026-07-14T12:01:01Z",
        "2026-07-14T12:01:05Z",
    ),
) -> _Chain:
    public_root, private_root = _layout(tmp_path)
    initial = _attest_initial(public_root, private_root)
    initial_receipts = dict(initial.access_probe_receipts)
    records = _write_smoke_records(private_root)
    registry = _registry_receipt(
        public_root=public_root,
        private_root=private_root,
        initial=initial,
        records=records,
    )
    sealed = boundary._attest_private_boundary_for_test(
        stage=boundary.SEALED_PRELAUNCH_STAGE,
        public_root=public_root,
        private_root=private_root,
        source_commit=SOURCE_COMMIT,
        experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
        stage_kind=STAGE_KIND,
        stage_attempt_id=STAGE_ATTEMPT_ID,
        expected_record_paths=records,
        probe_record_relative_path=records[0],
        initial_registration_attestation_bytes=initial.attestation_bytes,
        initial_access_probe_receipts_by_id=initial_receipts,
        registry_completion_receipt_bytes=registry,
        registrar_source_bytes=REGISTRAR_SOURCE,
        runtime=_runtime(
            private_root,
            mount_mode=sealed_mount_mode,
            started=sealed_times[0],
            completed=sealed_times[1],
            mutate_probe=sealed_mutator,
            duplicate_mount=sealed_duplicate_mount,
        ),
    )
    return _Chain(
        public_root=public_root,
        private_root=private_root,
        initial=initial,
        initial_receipts=initial_receipts,
        registry_receipt=registry,
        sealed=sealed,
        sealed_receipts=dict(sealed.access_probe_receipts),
        source_bytes=Path(boundary.__file__).read_bytes(),
    )


def _validate_sealed(
    chain: _Chain, *, validation_time: str = "2026-07-14T12:02:05Z"
) -> boundary.PrivateBoundaryValidation:
    return boundary.validate_sealed_prelaunch_boundary_bytes(
        chain.sealed.attestation_bytes,
        access_probe_receipts_by_id=chain.sealed_receipts,
        attester_source_bytes=chain.source_bytes,
        access_probe_source_bytes=ACCESS_PROBE_SOURCE,
        validation_time_utc=validation_time,
        initial_registration_attestation_bytes=chain.initial.attestation_bytes,
        initial_access_probe_receipts_by_id=chain.initial_receipts,
        registry_completion_receipt_bytes=chain.registry_receipt,
        registrar_source_bytes=REGISTRAR_SOURCE,
    )


def test_two_stage_positive_chain_is_distinct_non_authorizing_and_hides_bytes(
    tmp_path: Path,
) -> None:
    chain = _build_chain(tmp_path)
    initial_validation = boundary.validate_initial_registration_boundary_bytes(
        chain.initial.attestation_bytes,
        access_probe_receipts_by_id=chain.initial_receipts,
        attester_source_bytes=chain.source_bytes,
        access_probe_source_bytes=ACCESS_PROBE_SOURCE,
        validation_time_utc="2026-07-14T12:01:01Z",
    )
    sealed_validation = _validate_sealed(chain)

    assert initial_validation.stage == boundary.INITIAL_REGISTRATION_STAGE
    assert sealed_validation.stage == boundary.SEALED_PRELAUNCH_STAGE
    assert initial_validation.protocol != sealed_validation.protocol
    assert initial_validation.fresh_until_utc is None
    assert sealed_validation.fresh_until_utc == "2026-07-14T12:02:05Z"
    assert not any(
        (
            sealed_validation.dgp_calls_authorized,
            sealed_validation.model_calls_authorized,
            sealed_validation.scorer_calls_authorized,
            sealed_validation.launch_authorized,
            sealed_validation.operational_authorization,
        )
    )
    assert stat.S_IMODE(Path(chain.initial.publication.path).stat().st_mode) == 0o444
    assert stat.S_IMODE(Path(chain.sealed.publication.path).stat().st_mode) == 0o444
    assert chain.initial.publication.path != chain.sealed.publication.path
    assert len(chain.initial.probe_publications) == 14
    assert len(chain.sealed.probe_publications) == 9
    initial_value = json.loads(chain.initial.attestation_bytes)
    sealed_value = json.loads(chain.sealed.attestation_bytes)
    assert initial_value["private_context_root_identity"]["mode"] == 0o750
    assert (
        initial_value["private_context_root_identity"]["group_gid"]
        == boundary.PRIVATE_READ_GID
    )
    assert sealed_value["record_inventory"]["records"][0]["mode"] == 0o440
    assert (
        sealed_value["record_inventory"]["records"][0]["group_gid"]
        == boundary.PRIVATE_READ_GID
    )
    assert initial_value["process_identity"]["supplementary_gids"] == [
        boundary.PRIVATE_READ_GID
    ]
    assert not (chain.private_root / boundary._TRANSIENT_PROBE_RELATIVE_PATH).exists()
    all_public_evidence = (
        chain.initial.attestation_bytes
        + chain.sealed.attestation_bytes
        + chain.registry_receipt
        + b"".join(chain.initial_receipts.values())
        + b"".join(chain.sealed_receipts.values())
    )
    assert SECRET_RECORD_BYTES not in all_public_evidence
    assert {
        "01_registrar_create_probe",
        "04_private_validator_write_denied",
        "05_private_validator_create_denied",
        "07_scorer_write_denied",
        "08_scorer_create_denied",
        "13_registrar_remove_probe",
        "14_registrar_verify_no_leftover",
    } <= set(chain.initial_receipts)
    assert {
        "08_registrar_create_denied",
        "09_registrar_write_denied",
    } <= set(chain.sealed_receipts)


def test_initial_artifact_cannot_validate_as_sealed_gate(tmp_path: Path) -> None:
    chain = _build_chain(tmp_path)
    with pytest.raises(boundary.PrivateBoundaryError):
        boundary.validate_sealed_prelaunch_boundary_bytes(
            chain.initial.attestation_bytes,
            access_probe_receipts_by_id=chain.initial_receipts,
            attester_source_bytes=chain.source_bytes,
            access_probe_source_bytes=ACCESS_PROBE_SOURCE,
            validation_time_utc="2026-07-14T12:01:01Z",
            initial_registration_attestation_bytes=chain.initial.attestation_bytes,
            initial_access_probe_receipts_by_id=chain.initial_receipts,
            registry_completion_receipt_bytes=chain.registry_receipt,
            registrar_source_bytes=REGISTRAR_SOURCE,
        )


def test_freshness_is_inclusive_at_60_seconds_then_fails(tmp_path: Path) -> None:
    chain = _build_chain(tmp_path)
    _validate_sealed(chain, validation_time="2026-07-14T12:02:05Z")
    with pytest.raises(boundary.PrivateBoundaryError, match="older than 60s"):
        _validate_sealed(chain, validation_time="2026-07-14T12:02:06Z")


def test_public_entrypoints_have_no_runtime_injection_and_uids_are_distinct() -> None:
    assert (
        "runtime"
        not in inspect.signature(
            boundary.attest_initial_registration_boundary
        ).parameters
    )
    assert (
        "runtime"
        not in inspect.signature(boundary.attest_sealed_prelaunch_boundary).parameters
    )
    sealed_parameters = inspect.signature(
        boundary.attest_sealed_prelaunch_boundary
    ).parameters
    for forbidden in (
        "initial_registration_attestation_bytes",
        "initial_access_probe_receipts_by_id",
        "registry_completion_receipt_bytes",
        "registrar_source_bytes",
    ):
        assert forbidden not in sealed_parameters
    assert (
        len(
            {
                boundary.ATTESTER_UID,
                boundary.REGISTRAR_UID,
                boundary.PURE_SCORER_UID,
                boundary.PRIVATE_VALIDATOR_UID,
                boundary.LAUNCHER_UID,
                boundary.OPERATOR_UID,
            }
        )
        == 6
    )


def test_public_entrypoints_fail_closed_before_any_production_runtime_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        boundary,
        "_production_runtime",
        lambda: (_ for _ in ()).throw(AssertionError("production runtime touched")),
    )
    expected = "production private-boundary provider is unavailable"
    with pytest.raises(boundary.PrivateBoundaryError, match=expected):
        boundary.attest_initial_registration_boundary(
            public_root=Path("/not-opened/public"),
            private_root=Path("/not-opened/private"),
            source_commit=SOURCE_COMMIT,
            experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
            stage_kind=STAGE_KIND,
            stage_attempt_id=STAGE_ATTEMPT_ID,
        )
    with pytest.raises(boundary.PrivateBoundaryError, match=expected):
        boundary.attest_sealed_prelaunch_boundary(
            public_root=Path("/not-opened/public"),
            private_root=Path("/not-opened/private"),
            source_commit=SOURCE_COMMIT,
            experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
            stage_kind=STAGE_KIND,
            stage_attempt_id=STAGE_ATTEMPT_ID,
            expected_record_paths=(RECORD_RELATIVE,),
            probe_record_relative_path=RECORD_RELATIVE,
        )


def test_test_helper_rejects_production_roots_before_runtime(tmp_path: Path) -> None:
    del tmp_path
    public_root = Path(
        f"/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
        f"{SOURCE_COMMIT}/attempts/{EXPERIMENT_ATTEMPT_ID}/stages/"
        f"{STAGE_KIND}/{STAGE_ATTEMPT_ID}"
    )
    private_root = Path(
        f"/sensei-fs/private/zcai/TTT-RL/cohort-closed-loop-structured-state/"
        f"{SOURCE_COMMIT}/attempts/{EXPERIMENT_ATTEMPT_ID}/stages/"
        f"{STAGE_KIND}/{STAGE_ATTEMPT_ID}/private-context"
    )
    runtime = boundary._PrivateBoundaryRuntime(
        euid=lambda: (_ for _ in ()).throw(AssertionError("runtime touched")),
        identity_for_uid=lambda _uid: "",
        now_utc=lambda: "",
        boot_id=lambda: "",
        process_identity=lambda: (_ for _ in ()).throw(AssertionError()),
        mount_namespace=lambda: (_ for _ in ()).throw(AssertionError()),
        mountinfo_bytes=lambda: b"",
        uid_translate=lambda uid: uid,
        gid_translate=lambda gid: gid,
        xattrs_for_fd=lambda _descriptor: (),
        open_adapter=lambda: (_ for _ in ()).throw(AssertionError()),
        access_probe=lambda _request, _handle: b"",
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="rejects production"):
        boundary._attest_private_boundary_for_test(
            stage=boundary.INITIAL_REGISTRATION_STAGE,
            public_root=public_root,
            private_root=private_root,
            source_commit=SOURCE_COMMIT,
            experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
            stage_kind=STAGE_KIND,
            stage_attempt_id=STAGE_ATTEMPT_ID,
            expected_record_paths=(),
            probe_record_relative_path=None,
            initial_registration_attestation_bytes=None,
            initial_access_probe_receipts_by_id=None,
            registry_completion_receipt_bytes=None,
            registrar_source_bytes=None,
            runtime=runtime,
        )


@pytest.mark.parametrize("mode", [0o770, 0o755, 0o700])
def test_initial_writable_or_visible_root_fails(tmp_path: Path, mode: int) -> None:
    public_root, private_root = _layout(tmp_path)
    private_root.chmod(mode)
    with pytest.raises(boundary.PrivateBoundaryError, match="root owner/type/mode"):
        _attest_initial(public_root, private_root)


def test_initial_requires_rw_not_ro_and_unique_dedicated_mount(tmp_path: Path) -> None:
    public_root, private_root = _layout(tmp_path)
    with pytest.raises(boundary.PrivateBoundaryError, match="dedicated exact rw"):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="ro",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
            ),
        )

    public_root_2, private_root_2 = _layout(tmp_path / "duplicate")
    with pytest.raises(boundary.PrivateBoundaryError, match="non-unique"):
        _attest_initial(
            public_root_2,
            private_root_2,
            runtime=_runtime(
                private_root_2,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
                duplicate_mount=True,
            ),
        )


@pytest.mark.parametrize("entry_kind", ["unexpected", "symlink", "directory"])
def test_initial_root_must_be_exactly_empty(tmp_path: Path, entry_kind: str) -> None:
    public_root, private_root = _layout(tmp_path)
    if entry_kind == "unexpected":
        path = private_root / "unexpected.record"
        path.write_bytes(b"x")
        path.chmod(0o440)
    elif entry_kind == "symlink":
        (private_root / "link").symlink_to(tmp_path / "outside")
    else:
        (private_root / "empty-dir").mkdir(mode=0o750)
    with pytest.raises(boundary.PrivateBoundaryError):
        _attest_initial(public_root, private_root)


@pytest.mark.parametrize(
    ("probe_id", "field", "replacement"),
    [
        ("03_private_validator_read_probe", "allowed", False),
        ("10_launcher_read_probe", "raw_errno", errno.EPERM),
        ("14_registrar_verify_no_leftover", "absent", False),
        ("07_scorer_write_denied", "allowed", True),
        ("03_private_validator_read_probe", "observed_supplementary_gids", []),
        (
            "10_launcher_read_probe",
            "observed_supplementary_gids",
            [boundary.PRIVATE_READ_GID],
        ),
        (
            "03_private_validator_read_probe",
            "observed_effective_gid",
            boundary.PRIVATE_READ_GID,
        ),
        (
            "03_private_validator_read_probe",
            "observed_active_capabilities_empty",
            False,
        ),
        (
            "03_private_validator_read_probe",
            "invoking_uid_before_transition",
            boundary.OPERATOR_UID,
        ),
    ],
)
def test_initial_access_or_no_leftover_mismatch_fails(
    tmp_path: Path, probe_id: str, field: str, replacement: object
) -> None:
    public_root, private_root = _layout(tmp_path)

    def mutate(request: boundary._ProbeRequest, value: dict[str, object]) -> None:
        if request.probe_id == probe_id:
            value[field] = replacement

    with pytest.raises(boundary.PrivateBoundaryError):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
                mutate_probe=mutate,
            ),
        )
    assert not (private_root / boundary._TRANSIENT_PROBE_RELATIVE_PATH).exists()


@pytest.mark.parametrize(
    ("probe_id", "field", "replacement"),
    [
        ("01_private_validator_read_record", "content_sha256", "0" * 64),
        ("05_launcher_read_record", "raw_errno", errno.EPERM),
        ("08_registrar_create_denied", "allowed", True),
        ("09_registrar_write_denied", "raw_errno", 0),
    ],
)
def test_sealed_access_mismatch_fails(
    tmp_path: Path, probe_id: str, field: str, replacement: object
) -> None:
    def mutate(request: boundary._ProbeRequest, value: dict[str, object]) -> None:
        if request.probe_id == probe_id:
            value[field] = replacement

    with pytest.raises(boundary.PrivateBoundaryError):
        _build_chain(tmp_path, sealed_mutator=mutate)


def test_sealed_requires_ro_not_rw_and_unique_mount(tmp_path: Path) -> None:
    with pytest.raises(boundary.PrivateBoundaryError, match="dedicated exact ro"):
        _build_chain(tmp_path / "rw", sealed_mount_mode="rw")
    with pytest.raises(boundary.PrivateBoundaryError, match="non-unique"):
        _build_chain(tmp_path / "duplicate", sealed_duplicate_mount=True)


def test_sealed_writable_record_and_unexpected_record_fail(tmp_path: Path) -> None:
    public_root, private_root = _layout(tmp_path / "writable")
    initial = _attest_initial(public_root, private_root)
    records = _write_smoke_records(private_root, first_mode=0o600)
    registry = _registry_receipt(
        public_root=public_root,
        private_root=private_root,
        initial=initial,
        records=records,
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="record owner/type/mode"):
        boundary._attest_private_boundary_for_test(
            stage=boundary.SEALED_PRELAUNCH_STAGE,
            public_root=public_root,
            private_root=private_root,
            source_commit=SOURCE_COMMIT,
            experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
            stage_kind=STAGE_KIND,
            stage_attempt_id=STAGE_ATTEMPT_ID,
            expected_record_paths=records,
            probe_record_relative_path=RECORD_RELATIVE,
            initial_registration_attestation_bytes=initial.attestation_bytes,
            initial_access_probe_receipts_by_id=dict(initial.access_probe_receipts),
            registry_completion_receipt_bytes=registry,
            registrar_source_bytes=REGISTRAR_SOURCE,
            runtime=_runtime(
                private_root,
                mount_mode="ro",
                started="2026-07-14T12:01:01Z",
                completed="2026-07-14T12:01:05Z",
            ),
        )

    public_root_2, private_root_2 = _layout(tmp_path / "unexpected")
    initial_2 = _attest_initial(public_root_2, private_root_2)
    records_2 = _write_smoke_records(private_root_2)
    _write_registered_record(
        private_root_2,
        relative_path="records/smoke_block_01/adaptation/6.json",
    )
    registry_2 = _registry_receipt(
        public_root=public_root_2,
        private_root=private_root_2,
        initial=initial_2,
        records=records_2,
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="unexpected record set"):
        boundary._attest_private_boundary_for_test(
            stage=boundary.SEALED_PRELAUNCH_STAGE,
            public_root=public_root_2,
            private_root=private_root_2,
            source_commit=SOURCE_COMMIT,
            experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
            stage_kind=STAGE_KIND,
            stage_attempt_id=STAGE_ATTEMPT_ID,
            expected_record_paths=records_2,
            probe_record_relative_path=RECORD_RELATIVE,
            initial_registration_attestation_bytes=initial_2.attestation_bytes,
            initial_access_probe_receipts_by_id=dict(initial_2.access_probe_receipts),
            registry_completion_receipt_bytes=registry_2,
            registrar_source_bytes=REGISTRAR_SOURCE,
            runtime=_runtime(
                private_root_2,
                mount_mode="ro",
                started="2026-07-14T12:01:01Z",
                completed="2026-07-14T12:01:05Z",
            ),
        )


def test_impure_sealed_scan_rejects_extra_directory_before_any_probe(
    tmp_path: Path,
) -> None:
    public_root, private_root, initial, registry, records = _two_record_prerequisites(
        tmp_path
    )
    extra = private_root / "records" / "smoke_block_01" / "orphan"
    extra.mkdir(mode=0o750)

    with pytest.raises(boundary.PrivateBoundaryError, match="unexpected directory set"):
        _attest_sealed_from_parts(
            public_root=public_root,
            private_root=private_root,
            initial=initial,
            registry=registry,
            records=records,
        )
    _assert_no_sealed_evidence(public_root)


@pytest.mark.parametrize("defect", ["missing", "extra"])
def test_pure_sealed_validator_requires_exact_derived_directory_set(
    tmp_path: Path, defect: str
) -> None:
    chain = _build_chain(tmp_path)
    value = json.loads(chain.sealed.attestation_bytes)
    inventory = value["record_inventory"]
    directories = list(inventory["directories"])
    if defect == "missing":
        directories.pop()
    else:
        added = dict(directories[0])
        added["relative_path"] = "records/z-orphan"
        added["inode"] = max(row["inode"] for row in directories) + 1
        directories.append(added)
        directories.sort(key=lambda row: row["relative_path"])
    inventory["directories"] = directories
    value["record_inventory_sha256"] = boundary._sha(boundary._canonical(inventory))
    value["private_boundary_attestation_sha256"] = boundary._sha(
        boundary._canonical({key: value[key] for key in boundary._SEALED_UNSIGNED_KEYS})
    )

    with pytest.raises(boundary.PrivateBoundaryError, match="inventory closure"):
        boundary.validate_sealed_prelaunch_boundary_bytes(
            boundary._canonical(value),
            access_probe_receipts_by_id=chain.sealed_receipts,
            attester_source_bytes=chain.source_bytes,
            access_probe_source_bytes=ACCESS_PROBE_SOURCE,
            validation_time_utc="2026-07-14T12:02:05Z",
            initial_registration_attestation_bytes=chain.initial.attestation_bytes,
            initial_access_probe_receipts_by_id=chain.initial_receipts,
            registry_completion_receipt_bytes=chain.registry_receipt,
            registrar_source_bytes=REGISTRAR_SOURCE,
        )


def test_same_uid_configuration_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain = _build_chain(tmp_path)
    monkeypatch.setattr(boundary, "LAUNCHER_UID", boundary.REGISTRAR_UID)
    with pytest.raises(boundary.PrivateBoundaryError, match="must be distinct"):
        boundary.validate_initial_registration_boundary_bytes(
            chain.initial.attestation_bytes,
            access_probe_receipts_by_id=chain.initial_receipts,
            attester_source_bytes=chain.source_bytes,
            access_probe_source_bytes=ACCESS_PROBE_SOURCE,
            validation_time_utc="2026-07-14T12:01:01Z",
        )


@pytest.mark.parametrize(
    "bad_process",
    [
        boundary._ProcessObservation(
            pid=123,
            real_uid=boundary.ATTESTER_UID,
            effective_uid=boundary.ATTESTER_UID,
            saved_uid=boundary.ATTESTER_UID,
            real_gid=boundary.ATTESTER_UID,
            effective_gid=boundary.ATTESTER_UID,
            saved_gid=boundary.ATTESTER_UID,
            supplementary_gids=(),
            active_capabilities_empty=True,
            process_start_ticks=456,
            service_identity=boundary.ATTESTER_SERVICE_IDENTITY,
        ),
        boundary._ProcessObservation(
            pid=123,
            real_uid=boundary.ATTESTER_UID,
            effective_uid=boundary.ATTESTER_UID,
            saved_uid=boundary.ATTESTER_UID,
            real_gid=boundary.PRIVATE_READ_GID,
            effective_gid=boundary.PRIVATE_READ_GID,
            saved_gid=boundary.PRIVATE_READ_GID,
            supplementary_gids=(boundary.PRIVATE_READ_GID,),
            active_capabilities_empty=True,
            process_start_ticks=456,
            service_identity=boundary.ATTESTER_SERVICE_IDENTITY,
        ),
        boundary._ProcessObservation(
            pid=123,
            real_uid=boundary.ATTESTER_UID,
            effective_uid=boundary.ATTESTER_UID,
            saved_uid=boundary.ATTESTER_UID,
            real_gid=boundary.ATTESTER_UID,
            effective_gid=boundary.ATTESTER_UID,
            saved_gid=boundary.ATTESTER_UID,
            supplementary_gids=(boundary.PRIVATE_READ_GID,),
            active_capabilities_empty=False,
            process_start_ticks=456,
            service_identity=boundary.ATTESTER_SERVICE_IDENTITY,
        ),
    ],
)
def test_attester_wrong_gid_membership_or_capabilities_fail_before_scan(
    tmp_path: Path, bad_process: boundary._ProcessObservation
) -> None:
    public_root, private_root = _layout(tmp_path)
    with pytest.raises(boundary.PrivateBoundaryError, match="UID/GID/group"):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
                process=bad_process,
            ),
        )


@pytest.mark.parametrize("target", ["root", "record", "record_mode"])
def test_pure_validator_rejects_wrong_private_group_ownership(
    tmp_path: Path, target: str
) -> None:
    chain = _build_chain(tmp_path)
    value = json.loads(chain.sealed.attestation_bytes)
    if target == "root":
        value["private_context_root_identity"]["group_gid"] = 99999
    elif target == "record":
        value["record_inventory"]["records"][0]["group_gid"] = 99999
        value["record_inventory_sha256"] = boundary._sha(
            boundary._canonical(value["record_inventory"])
        )
    else:
        value["record_inventory"]["records"][0]["mode"] = 0o400
        value["record_inventory_sha256"] = boundary._sha(
            boundary._canonical(value["record_inventory"])
        )
    unsigned = {key: value[key] for key in boundary._SEALED_UNSIGNED_KEYS}
    value["private_boundary_attestation_sha256"] = boundary._sha(
        boundary._canonical(unsigned)
    )
    with pytest.raises(boundary.PrivateBoundaryError):
        boundary.validate_sealed_prelaunch_boundary_bytes(
            boundary._canonical(value),
            access_probe_receipts_by_id=chain.sealed_receipts,
            attester_source_bytes=chain.source_bytes,
            access_probe_source_bytes=ACCESS_PROBE_SOURCE,
            validation_time_utc="2026-07-14T12:02:05Z",
            initial_registration_attestation_bytes=chain.initial.attestation_bytes,
            initial_access_probe_receipts_by_id=chain.initial_receipts,
            registry_completion_receipt_bytes=chain.registry_receipt,
            registrar_source_bytes=REGISTRAR_SOURCE,
        )


def test_source_probe_authority_and_registry_substitution_fail(tmp_path: Path) -> None:
    chain = _build_chain(tmp_path)
    with pytest.raises(boundary.PrivateBoundaryError, match="source raw-byte"):
        boundary.validate_initial_registration_boundary_bytes(
            chain.initial.attestation_bytes,
            access_probe_receipts_by_id=chain.initial_receipts,
            attester_source_bytes=chain.source_bytes + b"substitution",
            access_probe_source_bytes=ACCESS_PROBE_SOURCE,
            validation_time_utc="2026-07-14T12:01:01Z",
        )

    changed_receipts = dict(chain.initial_receipts)
    changed_receipts["10_launcher_read_probe"] += b" "
    with pytest.raises(boundary.PrivateBoundaryError):
        boundary.validate_initial_registration_boundary_bytes(
            chain.initial.attestation_bytes,
            access_probe_receipts_by_id=changed_receipts,
            attester_source_bytes=chain.source_bytes,
            access_probe_source_bytes=ACCESS_PROBE_SOURCE,
            validation_time_utc="2026-07-14T12:01:01Z",
        )

    forged = json.loads(chain.sealed.attestation_bytes)
    forged["launch_authorized"] = True
    unsigned = {key: forged[key] for key in boundary._SEALED_UNSIGNED_KEYS}
    forged["private_boundary_attestation_sha256"] = boundary._sha(
        boundary._canonical(unsigned)
    )
    forged_raw = boundary._canonical(forged)
    with pytest.raises(boundary.PrivateBoundaryError, match="authority"):
        boundary.validate_sealed_prelaunch_boundary_bytes(
            forged_raw,
            access_probe_receipts_by_id=chain.sealed_receipts,
            attester_source_bytes=chain.source_bytes,
            access_probe_source_bytes=ACCESS_PROBE_SOURCE,
            validation_time_utc="2026-07-14T12:02:05Z",
            initial_registration_attestation_bytes=chain.initial.attestation_bytes,
            initial_access_probe_receipts_by_id=chain.initial_receipts,
            registry_completion_receipt_bytes=chain.registry_receipt,
            registrar_source_bytes=REGISTRAR_SOURCE,
        )

    registry = json.loads(chain.registry_receipt)
    registry["initial_registration_attestation_sha256"] = "0" * 64
    registry_unsigned = {key: registry[key] for key in boundary._REGISTRY_UNSIGNED_KEYS}
    registry["registry_completion_receipt_sha256"] = boundary._sha(
        boundary._canonical(registry_unsigned)
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="state-machine"):
        boundary.validate_sealed_prelaunch_boundary_bytes(
            chain.sealed.attestation_bytes,
            access_probe_receipts_by_id=chain.sealed_receipts,
            attester_source_bytes=chain.source_bytes,
            access_probe_source_bytes=ACCESS_PROBE_SOURCE,
            validation_time_utc="2026-07-14T12:02:05Z",
            initial_registration_attestation_bytes=chain.initial.attestation_bytes,
            initial_access_probe_receipts_by_id=chain.initial_receipts,
            registry_completion_receipt_bytes=boundary._canonical(registry),
            registrar_source_bytes=REGISTRAR_SOURCE,
        )


def test_namespace_drift_and_probe_duration_over_60_seconds_fail(
    tmp_path: Path,
) -> None:
    public_root, private_root = _layout(tmp_path / "namespace")
    with pytest.raises(boundary.PrivateBoundaryError, match="drifted"):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
                namespace_values=(
                    boundary._NamespaceObservation(11, 22, "mnt:[22]"),
                    boundary._NamespaceObservation(11, 23, "mnt:[23]"),
                ),
            ),
        )

    public_root_2, private_root_2 = _layout(tmp_path / "duration")
    with pytest.raises(boundary.PrivateBoundaryError, match="exceeds 60s"):
        _attest_initial(
            public_root_2,
            private_root_2,
            runtime=_runtime(
                private_root_2,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:01:01Z",
            ),
        )


def test_atomic_publication_is_no_replace(tmp_path: Path) -> None:
    public_root, private_root = _layout(tmp_path)
    _attest_initial(public_root, private_root)
    with pytest.raises(boundary.PrivateBoundaryError, match="publication failed"):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:03:00Z",
                completed="2026-07-14T12:03:05Z",
            ),
        )


def test_registry_completion_must_follow_initial_and_precede_sealed(
    tmp_path: Path,
) -> None:
    public_root, private_root = _layout(tmp_path)
    initial = _attest_initial(public_root, private_root)
    records = _write_smoke_records(private_root)
    registry = _registry_receipt(
        public_root=public_root,
        private_root=private_root,
        initial=initial,
        records=records,
        completed_at="2026-07-14T12:01:02Z",
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="timestamp order"):
        boundary._attest_private_boundary_for_test(
            stage=boundary.SEALED_PRELAUNCH_STAGE,
            public_root=public_root,
            private_root=private_root,
            source_commit=SOURCE_COMMIT,
            experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
            stage_kind=STAGE_KIND,
            stage_attempt_id=STAGE_ATTEMPT_ID,
            expected_record_paths=records,
            probe_record_relative_path=RECORD_RELATIVE,
            initial_registration_attestation_bytes=initial.attestation_bytes,
            initial_access_probe_receipts_by_id=dict(initial.access_probe_receipts),
            registry_completion_receipt_bytes=registry,
            registrar_source_bytes=REGISTRAR_SOURCE,
            runtime=_runtime(
                private_root,
                mount_mode="ro",
                started="2026-07-14T12:01:01Z",
                completed="2026-07-14T12:01:05Z",
            ),
        )


def test_sealed_rejects_private_root_inode_replacement(tmp_path: Path) -> None:
    public_root, private_root = _layout(tmp_path)
    initial = _attest_initial(public_root, private_root)
    private_root.rename(tmp_path / "replaced-private")
    private_root.mkdir(mode=0o750)
    records = _write_smoke_records(private_root)
    registry = _registry_receipt(
        public_root=public_root,
        private_root=private_root,
        initial=initial,
        records=records,
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="identity transition"):
        boundary._attest_private_boundary_for_test(
            stage=boundary.SEALED_PRELAUNCH_STAGE,
            public_root=public_root,
            private_root=private_root,
            source_commit=SOURCE_COMMIT,
            experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
            stage_kind=STAGE_KIND,
            stage_attempt_id=STAGE_ATTEMPT_ID,
            expected_record_paths=records,
            probe_record_relative_path=RECORD_RELATIVE,
            initial_registration_attestation_bytes=initial.attestation_bytes,
            initial_access_probe_receipts_by_id=dict(initial.access_probe_receipts),
            registry_completion_receipt_bytes=registry,
            registrar_source_bytes=REGISTRAR_SOURCE,
            runtime=_runtime(
                private_root,
                mount_mode="ro",
                started="2026-07-14T12:01:01Z",
                completed="2026-07-14T12:01:05Z",
            ),
        )


def test_adapter_must_be_fixed_root_owned_setuid_binary(tmp_path: Path) -> None:
    public_root, private_root = _layout(tmp_path)
    bad_adapter = boundary._AdapterObservation(
        path=str(boundary.SETUID_ADAPTER_PATH),
        device=3,
        inode=4,
        mode=0o755,
        owner_uid=0,
        group_gid=boundary.ATTESTER_UID,
        sha256="f" * 64,
        size_bytes=128,
        link_count=1,
        extended_attributes_empty=True,
        trusted_ancestors=tuple(
            {
                "device": 3,
                "group_gid": 0,
                "inode": index + 10,
                "mode": 0o755,
                "owner_uid": 0,
                "path": path,
            }
            for index, path in enumerate(
                ("/", "/usr", "/usr/local", "/usr/local/libexec")
            )
        ),
        adapter_mount=boundary._MountRecord(
            mount_id=1,
            parent_id=0,
            major_minor=boundary._major_minor(3),
            mount_root="/",
            mount_point="/",
            mount_options="rw,suid",
            filesystem_type="ext4",
            mount_source="/dev/root",
            super_options="rw,suid",
        ),
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="adapter binding"):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
                adapter=bad_adapter,
            ),
        )


def test_python310_surface_imports_without_newer_syntax() -> None:
    assert boundary.INITIAL_SCHEMA_VERSION == 1
    assert boundary.SEALED_SCHEMA_VERSION == 2
    assert datetime(2026, 7, 14, tzinfo=timezone.utc) + timedelta(seconds=60)


def test_exact_stage_namespace_and_public_evidence_inventory(tmp_path: Path) -> None:
    import cohort_closed_loop_structured_stage_plan as stage_plan

    chain = _build_chain(tmp_path)
    expected_public = (
        f"/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
        f"{SOURCE_COMMIT}/attempts/{EXPERIMENT_ATTEMPT_ID}/stages/"
        f"{STAGE_KIND}/{STAGE_ATTEMPT_ID}"
    )
    expected_private = (
        f"/sensei-fs/private/zcai/TTT-RL/cohort-closed-loop-structured-state/"
        f"{SOURCE_COMMIT}/attempts/{EXPERIMENT_ATTEMPT_ID}/stages/"
        f"{STAGE_KIND}/{STAGE_ATTEMPT_ID}/private-context"
    )
    assert boundary._PRODUCTION_PUBLIC_RE.fullmatch(expected_public)
    assert boundary._PRODUCTION_PRIVATE_RE.fullmatch(expected_private)
    assert not boundary._PRODUCTION_PUBLIC_RE.fullmatch(
        expected_public.replace(
            f"/{STAGE_KIND}/{STAGE_ATTEMPT_ID}",
            f"/{STAGE_KIND}/attempts/{STAGE_ATTEMPT_ID}",
        )
    )
    assert boundary.INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH == (
        "control/private_boundary/initial/attestation.json"
    )
    assert boundary.SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH == (
        "control/private_boundary/sealed/attestation.json"
    )
    assert boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH == (
        "control/private_boundary/registry/registry_completion.v2.json"
    )
    durable_root = (
        f"/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
        f"{SOURCE_COMMIT}/attempts/{EXPERIMENT_ATTEMPT_ID}"
    )
    plan_paths = stage_plan._paths(
        durable_root=durable_root,
        source_commit=SOURCE_COMMIT,
        experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
        stage=stage_plan.StageKind.SMOKE,
        stage_attempt_id=STAGE_ATTEMPT_ID,
    )
    stage_root = str(plan_paths["stage_root"])
    assert stage_root == expected_public
    assert str(plan_paths["private_context_root"]) == expected_private
    assert str(plan_paths["initial_boundary_attestation_path"]) == (
        f"{stage_root}/{boundary.INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH}"
    )
    assert str(plan_paths["sealed_boundary_attestation_path"]) == (
        f"{stage_root}/{boundary.SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH}"
    )
    assert str(plan_paths["registry_completion_receipt_path"]) == (
        f"{stage_root}/{boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH}"
    )
    initial_paths = tuple(row.relative_path for row in chain.initial.probe_publications)
    sealed_paths = tuple(row.relative_path for row in chain.sealed.probe_publications)
    assert initial_paths == tuple(
        f"control/private_boundary/initial/probes/{probe_id}.json"
        for probe_id in sorted(chain.initial_receipts)
    )
    assert sealed_paths == tuple(
        f"control/private_boundary/sealed/probes/{probe_id}.json"
        for probe_id in sorted(chain.sealed_receipts)
    )
    assert tuple(sorted(chain.initial_receipts)) == tuple(
        stage_plan.INITIAL_PRIVATE_PROBE_IDS
    )
    assert tuple(sorted(chain.sealed_receipts)) == tuple(
        stage_plan.SEALED_PRIVATE_PROBE_IDS
    )
    assert (
        tuple(
            str(row["path"]).removeprefix(f"{stage_root}/")
            for row in plan_paths["initial_probe_receipt_paths"]
        )
        == initial_paths
    )
    assert (
        tuple(
            str(row["path"]).removeprefix(f"{stage_root}/")
            for row in plan_paths["sealed_probe_receipt_paths"]
        )
        == sealed_paths
    )
    assert chain.initial.publication.relative_path == (
        boundary.INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH
    )
    assert chain.sealed.publication.relative_path == (
        boundary.SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH
    )
    for relative in (*initial_paths, *sealed_paths):
        intent, pending = boundary.publication_sidecar_relative_paths(relative)
        assert (chain.public_root / intent).is_file()
        assert not (chain.public_root / pending).exists()
    registry_relative = boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH
    registry_intent, registry_pending = boundary.publication_sidecar_relative_paths(
        registry_relative
    )
    assert (
        chain.public_root / registry_relative
    ).read_bytes() == chain.registry_receipt
    assert (chain.public_root / registry_intent).is_file()
    assert not (chain.public_root / registry_pending).exists()
    registry_value = json.loads(chain.registry_receipt)
    assert registry_value["protocol"] == boundary.REGISTRY_COMPLETION_PROTOCOL
    assert registry_value["schema_version"] == 2
    assert registry_value["registered_record_count"] == 10
    assert all(
        set(row) == boundary._REGISTERED_RECORD_KEYS
        for row in registry_value["registered_records"]
    )


def test_stage_plan_and_private_boundary_v2_contract_are_exactly_shared() -> None:
    import cohort_closed_loop_structured_stage_plan as stage_plan

    fixture = _stage_plan_fixture_module()
    raw, _ = fixture._fixture(  # type: ignore[attr-defined]
        stage_kind="smoke", stage_attempt_id=STAGE_ATTEMPT_ID
    )
    payload = json.loads(raw)
    private_plan = payload["private_boundary_plan"]
    paths = payload["paths"]

    for name in (
        "ATTESTER_UID",
        "REGISTRAR_UID",
        "PURE_SCORER_UID",
        "PRIVATE_VALIDATOR_UID",
        "LAUNCHER_UID",
        "OPERATOR_UID",
        "PRIVATE_READ_GID",
        "ATTESTER_SERVICE_IDENTITY",
        "REGISTRAR_SERVICE_IDENTITY",
        "PURE_SCORER_SERVICE_IDENTITY",
        "PRIVATE_VALIDATOR_SERVICE_IDENTITY",
        "LAUNCHER_SERVICE_IDENTITY",
        "OPERATOR_SERVICE_IDENTITY",
    ):
        assert getattr(boundary, name) == getattr(stage_plan, name)

    identities = boundary._service_identities()
    assert identities == stage_plan._private_service_identities()
    assert identities == private_plan["service_identities"]
    assert private_plan["service_identities_sha256"] == boundary._sha(
        boundary._canonical(identities)
    )
    for stage in (
        boundary.INITIAL_REGISTRATION_STAGE,
        boundary.SEALED_PRELAUNCH_STAGE,
    ):
        policy = boundary._access_policy(stage)
        stage_plan_policy = stage_plan._private_access_policy(stage)
        plan_key = (
            "initial" if stage == boundary.INITIAL_REGISTRATION_STAGE else "sealed"
        )
        assert policy == stage_plan_policy == private_plan[f"{plan_key}_access_policy"]
        assert private_plan[f"{plan_key}_access_policy_sha256"] == boundary._sha(
            boundary._canonical(policy)
        )

    assert boundary.INITIAL_PRIVATE_PROBE_IDS == stage_plan.INITIAL_PRIVATE_PROBE_IDS
    assert boundary.SEALED_PRIVATE_PROBE_IDS == stage_plan.SEALED_PRIVATE_PROBE_IDS
    assert (
        tuple(row["probe_id"] for row in paths["initial_probe_receipt_paths"])
        == boundary.INITIAL_PRIVATE_PROBE_IDS
    )
    assert (
        tuple(row["probe_id"] for row in paths["sealed_probe_receipt_paths"])
        == boundary.SEALED_PRIVATE_PROBE_IDS
    )

    assert private_plan["protocol_schema_bindings"] == {
        "initial_attestation": {
            "protocol": boundary.INITIAL_REGISTRATION_PROTOCOL,
            "schema_version": boundary.INITIAL_SCHEMA_VERSION,
        },
        "initial_probe": {
            "protocol": boundary.INITIAL_ACCESS_PROBE_PROTOCOL,
            "schema_version": boundary.PROBE_SCHEMA_VERSION,
        },
        "registry_completion": {
            "protocol": boundary.REGISTRY_COMPLETION_PROTOCOL,
            "schema_version": boundary.REGISTRY_COMPLETION_SCHEMA_VERSION,
        },
        "sealed_attestation": {
            "protocol": boundary.SEALED_PRELAUNCH_PROTOCOL,
            "schema_version": boundary.SEALED_SCHEMA_VERSION,
        },
        "sealed_probe": {
            "protocol": boundary.SEALED_ACCESS_PROBE_PROTOCOL,
            "schema_version": boundary.PROBE_SCHEMA_VERSION,
        },
    }
    assert stage_plan.SETUID_ADAPTER_PATH == str(boundary.SETUID_ADAPTER_PATH)
    assert private_plan["access_probe_binary"]["install_path"] == str(
        boundary.SETUID_ADAPTER_PATH
    )

    stage_root = paths["stage_root"]
    assert paths["initial_boundary_attestation_path"] == (
        f"{stage_root}/{boundary.INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH}"
    )
    assert paths["sealed_boundary_attestation_path"] == (
        f"{stage_root}/{boundary.SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH}"
    )
    assert paths["registry_completion_receipt_path"] == (
        f"{stage_root}/{boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH}"
    )
    registry_mapping = payload["registry_v2_mapping"]
    assert set(registry_mapping["completion_value_derivation"]) == (
        boundary._REGISTERED_RECORD_KEYS
    )
    internal_paths = stage_plan._paths(
        durable_root=f"/durable/{SOURCE_COMMIT}/attempts/{EXPERIMENT_ATTEMPT_ID}",
        source_commit=SOURCE_COMMIT,
        experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
        stage=stage_plan.StageKind.INTERNAL,
        stage_attempt_id=STAGE_ATTEMPT_ID,
    )
    _, internal_mapping = stage_plan._pre_dgp_rows(
        source_commit=SOURCE_COMMIT,
        experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
        stage=stage_plan.StageKind.INTERNAL,
        stage_attempt_id=STAGE_ATTEMPT_ID,
        paths=internal_paths,
    )
    planned = internal_mapping["planned_entries"]
    assert len(planned) == 3 * 2 * 20
    assert [row["item_id"] for row in planned[:20]] == list(range(1, 21))
    assert [row["private_record_relative_path"] for row in planned[:20]][8:11] == [
        "records/internal_block_01/adaptation/9.json",
        "records/internal_block_01/adaptation/10.json",
        "records/internal_block_01/adaptation/11.json",
    ]


def test_partial_probe_publication_poison_is_persistent_and_attestation_absent(
    tmp_path: Path,
) -> None:
    public_root, private_root = _layout(tmp_path)

    def corrupt_fifth(
        request: boundary._ProbeRequest, value: dict[str, object]
    ) -> None:
        if request.probe_id == "05_private_validator_create_denied":
            value["allowed"] = True

    with pytest.raises(boundary.PrivateBoundaryError):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
                mutate_probe=corrupt_fifth,
            ),
        )
    published = sorted(
        path.name
        for path in (
            public_root / "control" / "private_boundary" / "initial" / "probes"
        ).glob("*.json")
        if path.name[0].isdigit()
    )
    assert published == [
        "01_registrar_create_probe.json",
        "02_registrar_read_probe.json",
        "03_private_validator_read_probe.json",
        "04_private_validator_write_denied.json",
    ]
    assert not (
        public_root / boundary.INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH
    ).exists()
    with pytest.raises(boundary.PrivateBoundaryError, match="namespace poisoned"):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:02:00Z",
                completed="2026-07-14T12:02:05Z",
            ),
        )


def _two_record_prerequisites(
    tmp_path: Path,
) -> tuple[Path, Path, boundary.PrivateBoundaryArtifacts, bytes, tuple[str, ...]]:
    public_root, private_root = _layout(tmp_path)
    initial = _attest_initial(public_root, private_root)
    records = _write_smoke_records(private_root)
    registry = _registry_receipt(
        public_root=public_root,
        private_root=private_root,
        initial=initial,
        records=records,
    )
    return public_root, private_root, initial, registry, records


def _attest_sealed_from_parts(
    *,
    public_root: Path,
    private_root: Path,
    initial: boundary.PrivateBoundaryArtifacts,
    registry: bytes,
    records: tuple[str, ...],
) -> boundary.PrivateBoundaryArtifacts:
    return boundary._attest_private_boundary_for_test(
        stage=boundary.SEALED_PRELAUNCH_STAGE,
        public_root=public_root,
        private_root=private_root,
        source_commit=SOURCE_COMMIT,
        experiment_attempt_id=EXPERIMENT_ATTEMPT_ID,
        stage_kind=STAGE_KIND,
        stage_attempt_id=STAGE_ATTEMPT_ID,
        expected_record_paths=records,
        probe_record_relative_path=records[0],
        initial_registration_attestation_bytes=initial.attestation_bytes,
        initial_access_probe_receipts_by_id=dict(initial.access_probe_receipts),
        registry_completion_receipt_bytes=registry,
        registrar_source_bytes=REGISTRAR_SOURCE,
        runtime=_runtime(
            private_root,
            mount_mode="ro",
            started="2026-07-14T12:01:01Z",
            completed="2026-07-14T12:01:05Z",
        ),
    )


def _assert_no_sealed_evidence(public_root: Path) -> None:
    probe_root = public_root / "control" / "private_boundary" / "sealed" / "probes"
    assert not [path for path in probe_root.glob("*.json") if path.name[0].isdigit()]
    assert not (
        public_root / boundary.SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH
    ).exists()


@pytest.mark.parametrize("artifact", ["initial", "probe", "registry"])
@pytest.mark.parametrize("side", ["final", "intent"])
def test_sealed_requires_every_persisted_prerequisite_before_any_probe(
    tmp_path: Path, artifact: str, side: str
) -> None:
    public_root, private_root, initial, registry, records = _two_record_prerequisites(
        tmp_path
    )
    if artifact == "initial":
        relative = boundary.INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH
    elif artifact == "probe":
        relative = boundary._probe_receipt_relative_path(
            boundary.INITIAL_REGISTRATION_STAGE,
            boundary.INITIAL_PRIVATE_PROBE_IDS[0],
        )
    else:
        relative = boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH
    intent_relative, _ = boundary.publication_sidecar_relative_paths(relative)
    target = public_root / (relative if side == "final" else intent_relative)
    target.unlink()

    with pytest.raises(boundary.PrivateBoundaryError, match="persisted"):
        _attest_sealed_from_parts(
            public_root=public_root,
            private_root=private_root,
            initial=initial,
            registry=registry,
            records=records,
        )
    _assert_no_sealed_evidence(public_root)


@pytest.mark.parametrize("artifact", ["initial", "probe", "registry"])
def test_sealed_rejects_any_prerequisite_pending_file_before_any_probe(
    tmp_path: Path, artifact: str
) -> None:
    public_root, private_root, initial, registry, records = _two_record_prerequisites(
        tmp_path
    )
    if artifact == "initial":
        relative = boundary.INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH
    elif artifact == "probe":
        relative = boundary._probe_receipt_relative_path(
            boundary.INITIAL_REGISTRATION_STAGE,
            boundary.INITIAL_PRIVATE_PROBE_IDS[-1],
        )
    else:
        relative = boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH
    _, pending_relative = boundary.publication_sidecar_relative_paths(relative)
    pending = public_root / pending_relative
    pending.write_bytes(b"poison")
    pending.chmod(0o444)

    with pytest.raises(boundary.PrivateBoundaryError, match="persisted"):
        _attest_sealed_from_parts(
            public_root=public_root,
            private_root=private_root,
            initial=initial,
            registry=registry,
            records=records,
        )
    _assert_no_sealed_evidence(public_root)


def test_sealed_rejects_never_published_registry_before_any_probe(
    tmp_path: Path,
) -> None:
    public_root, private_root = _layout(tmp_path)
    initial = _attest_initial(public_root, private_root)
    records = _write_smoke_records(private_root)
    registry = _registry_receipt(
        public_root=public_root,
        private_root=private_root,
        initial=initial,
        records=records,
        publish=False,
    )

    with pytest.raises(boundary.PrivateBoundaryError, match="persisted registry"):
        _attest_sealed_from_parts(
            public_root=public_root,
            private_root=private_root,
            initial=initial,
            registry=registry,
            records=records,
        )
    _assert_no_sealed_evidence(public_root)


@pytest.mark.parametrize("defect", ["delete", "same_bytes_replacement"])
def test_sealed_revalidates_prerequisite_identity_immediately_before_final(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str
) -> None:
    public_root, private_root, initial, registry, records = _two_record_prerequisites(
        tmp_path
    )
    original = boundary._observe_persisted_sealed_prerequisites
    calls = 0

    def mutate_on_final_revalidation(**kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            final = public_root / boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH
            raw = final.read_bytes()
            final.unlink()
            if defect == "same_bytes_replacement":
                final.write_bytes(raw)
                final.chmod(0o444)
        return original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        boundary,
        "_observe_persisted_sealed_prerequisites",
        mutate_on_final_revalidation,
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="persisted"):
        _attest_sealed_from_parts(
            public_root=public_root,
            private_root=private_root,
            initial=initial,
            registry=registry,
            records=records,
        )
    assert calls == 2
    assert len(
        [
            path
            for path in (
                public_root / "control" / "private_boundary" / "sealed" / "probes"
            ).glob("*.json")
            if path.name[0].isdigit()
        ]
    ) == len(boundary.SEALED_PRIVATE_PROBE_IDS)
    assert not (
        public_root / boundary.SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH
    ).exists()


@pytest.mark.parametrize("artifact", ["initial", "probe", "registry"])
@pytest.mark.parametrize("side", ["final", "intent"])
@pytest.mark.parametrize("mutation", ["same_bytes_replacement", "hardlink_round_trip"])
def test_sealed_rejects_any_prerequisite_closure_identity_drift_before_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    side: str,
    mutation: str,
) -> None:
    public_root, private_root, initial, registry, records = _two_record_prerequisites(
        tmp_path
    )
    if artifact == "initial":
        relative = boundary.INITIAL_REGISTRATION_ATTESTATION_RELATIVE_PATH
    elif artifact == "probe":
        relative = boundary._probe_receipt_relative_path(
            boundary.INITIAL_REGISTRATION_STAGE,
            boundary.INITIAL_PRIVATE_PROBE_IDS[0],
        )
    else:
        relative = boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH
    intent_relative, _ = boundary.publication_sidecar_relative_paths(relative)
    target = public_root / (relative if side == "final" else intent_relative)
    original = boundary._observe_persisted_sealed_prerequisites
    calls = 0

    def mutate_on_final_revalidation(**kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            before = target.stat()
            if mutation == "same_bytes_replacement":
                raw = target.read_bytes()
                target.unlink()
                target.write_bytes(raw)
                target.chmod(0o444)
                assert target.stat().st_ino != before.st_ino
            else:
                sibling = target.with_name(f"{target.name}.round-trip")
                os.link(target, sibling)
                target.unlink()
                sibling.replace(target)
                after = target.stat()
                assert after.st_ino == before.st_ino
                assert after.st_ctime_ns != before.st_ctime_ns
        return original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        boundary,
        "_observe_persisted_sealed_prerequisites",
        mutate_on_final_revalidation,
    )
    with pytest.raises(
        boundary.PrivateBoundaryError,
        match="persisted",
    ):
        _attest_sealed_from_parts(
            public_root=public_root,
            private_root=private_root,
            initial=initial,
            registry=registry,
            records=records,
        )
    assert calls == 2
    assert not (
        public_root / boundary.SEALED_PRELAUNCH_ATTESTATION_RELATIVE_PATH
    ).exists()


def test_every_registry_record_hash_is_checked_not_only_probe_record(
    tmp_path: Path,
) -> None:
    public_root, private_root, initial, registry, records = _two_record_prerequisites(
        tmp_path
    )
    second = private_root / records[1]
    original_size = second.stat().st_size
    second.chmod(0o640)
    second.write_bytes(b"Y" * original_size)
    second.chmod(0o440)
    with pytest.raises(boundary.PrivateBoundaryError, match="hidden hash"):
        _attest_sealed_from_parts(
            public_root=public_root,
            private_root=private_root,
            initial=initial,
            registry=registry,
            records=records,
        )


def test_stable_two_pass_detects_same_size_mutation_between_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public_root, private_root, initial, registry, records = _two_record_prerequisites(
        tmp_path
    )
    original = boundary._read_record_content_inventory
    calls = 0

    def mutate_after_first(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            second = private_root / records[1]
            size = second.stat().st_size
            second.chmod(0o640)
            second.write_bytes(b"Z" * size)
            second.chmod(0o440)
        return result

    monkeypatch.setattr(boundary, "_read_record_content_inventory", mutate_after_first)
    with pytest.raises(boundary.PrivateBoundaryError, match="stable passes"):
        _attest_sealed_from_parts(
            public_root=public_root,
            private_root=private_root,
            initial=initial,
            registry=registry,
            records=records,
        )


def test_acl_xattr_is_rejected_before_probe_execution(tmp_path: Path) -> None:
    public_root, private_root = _layout(tmp_path)
    with pytest.raises(boundary.PrivateBoundaryError, match="forbidden ACL"):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
                xattrs_for_fd=lambda _descriptor: ("system.posix_acl_access",),
            ),
        )
    assert not any(
        (public_root / "control" / "private_boundary" / "initial" / "probes").iterdir()
    )


@pytest.mark.parametrize("defect", ["nosuid", "writable_ancestor", "nlink", "xattr"])
def test_adapter_mount_ancestor_link_and_xattr_trust_fail_closed(
    tmp_path: Path, defect: str
) -> None:
    public_root, private_root = _layout(tmp_path)
    runtime = _runtime(
        private_root,
        mount_mode="rw",
        started="2026-07-14T12:00:00Z",
        completed="2026-07-14T12:00:05Z",
    )
    base = runtime.open_adapter().observation
    if defect == "nosuid":
        adapter = replace(
            base,
            adapter_mount=replace(
                base.adapter_mount,
                mount_options="rw,nosuid",
                super_options="rw,nosuid",
            ),
        )
    elif defect == "writable_ancestor":
        ancestors = [dict(row) for row in base.trusted_ancestors]
        ancestors[-1]["mode"] = 0o775
        adapter = replace(base, trusted_ancestors=tuple(ancestors))
    elif defect == "nlink":
        adapter = replace(base, link_count=2)
    else:
        adapter = replace(base, extended_attributes_empty=False)
    with pytest.raises(boundary.PrivateBoundaryError):
        _attest_initial(
            public_root,
            private_root,
            runtime=_runtime(
                private_root,
                mount_mode="rw",
                started="2026-07-14T12:00:00Z",
                completed="2026-07-14T12:00:05Z",
                adapter=adapter,
            ),
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("block_index", 9),
        ("instance_index", 9),
        ("relative_path", "records/smoke_block_01/adaptation/9.json"),
    ],
)
def test_registry_v2_exact_mapping_fields_are_not_compatibility_aliases(
    tmp_path: Path, field: str, replacement: object
) -> None:
    chain = _build_chain(tmp_path)
    registry = json.loads(chain.registry_receipt)
    registry["registered_records"][0][field] = replacement
    registry["record_set_sha256"] = boundary._sha(
        boundary._canonical(registry["registered_records"])
    )
    unsigned = {key: registry[key] for key in boundary._REGISTRY_UNSIGNED_KEYS}
    registry["registry_completion_receipt_sha256"] = boundary._sha(
        boundary._canonical(unsigned)
    )
    with pytest.raises(boundary.PrivateBoundaryError):
        boundary._validate_registry_completion_receipt_bytes(
            boundary._canonical(registry),
            registrar_source_bytes=REGISTRAR_SOURCE,
        )


def test_registry_v2_requires_the_complete_preregistered_stage_shape(
    tmp_path: Path,
) -> None:
    chain = _build_chain(tmp_path)
    registry = json.loads(chain.registry_receipt)
    registry["registered_records"].pop()
    registry["registered_record_count"] = len(registry["registered_records"])
    registry["record_set_sha256"] = boundary._sha(
        boundary._canonical(registry["registered_records"])
    )
    unsigned = {key: registry[key] for key in boundary._REGISTRY_UNSIGNED_KEYS}
    registry["registry_completion_receipt_sha256"] = boundary._sha(
        boundary._canonical(unsigned)
    )
    with pytest.raises(boundary.PrivateBoundaryError, match="fully sorted"):
        boundary._validate_registry_completion_receipt_bytes(
            boundary._canonical(registry),
            registrar_source_bytes=REGISTRAR_SOURCE,
        )


def test_internal_registry_and_inventories_use_numeric_item_order() -> None:
    stage_kind = "internal"
    rows: list[dict[str, object]] = []
    for block_index in range(3):
        block_id = f"internal_block_{block_index + 1:02d}"
        for phase in ("adaptation", "held_out"):
            for item_id in range(1, 21):
                relative = f"records/{block_id}/{phase}/{item_id}.json"
                rows.append(
                    {
                        "block_id": block_id,
                        "block_index": block_index,
                        "hidden_sha256": boundary._sha(
                            f"hidden:{relative}".encode("ascii")
                        ),
                        "instance_id": f"{block_id}-{phase}-{item_id}",
                        "instance_index": item_id - 1,
                        "item_id": item_id,
                        "opaque_handle_sha256": boundary._sha(
                            f"opaque:{relative}".encode("ascii")
                        ),
                        "phase": phase,
                        "public_context_identity_sha256": boundary._sha(
                            f"public:{relative}".encode("ascii")
                        ),
                        "relative_path": relative,
                        "size_bytes": item_id,
                        "stage_kind": stage_kind,
                    }
                )
    unsigned = {
        "boot_id": BOOT_ID,
        "completed_at_utc": "2026-07-14T12:01:00Z",
        "experiment_attempt_id": EXPERIMENT_ATTEMPT_ID,
        "initial_registration_attestation_sha256": "1" * 64,
        "private_context_root": "/private/internal",
        "process_identity": {
            "active_capabilities_empty": True,
            "effective_gid": boundary.PRIVATE_READ_GID,
            "effective_uid": boundary.REGISTRAR_UID,
            "pid": 200,
            "process_start_ticks": 300,
            "real_gid": boundary.PRIVATE_READ_GID,
            "real_uid": boundary.REGISTRAR_UID,
            "saved_gid": boundary.PRIVATE_READ_GID,
            "saved_uid": boundary.REGISTRAR_UID,
            "service_identity": boundary.REGISTRAR_SERVICE_IDENTITY,
            "supplementary_gids": [],
        },
        "protocol": boundary.REGISTRY_COMPLETION_PROTOCOL,
        "record_set_sha256": boundary._sha(boundary._canonical(rows)),
        "registered_record_count": len(rows),
        "registered_records": rows,
        "registrar_source": {
            "path": "/srv/cohort_closed_loop_structured_context_registrar.py",
            "sha256": boundary._sha(REGISTRAR_SOURCE),
            "size_bytes": len(REGISTRAR_SOURCE),
        },
        "schema_version": boundary.REGISTRY_COMPLETION_SCHEMA_VERSION,
        "source_commit": SOURCE_COMMIT,
        "stage_attempt_id": STAGE_ATTEMPT_ID,
        "stage_kind": stage_kind,
        "status": boundary.REGISTRY_COMPLETION_STATUS,
        **boundary._authority_false(),
    }
    raw = boundary._canonical(
        {
            **unsigned,
            "registry_completion_receipt_sha256": boundary._sha(
                boundary._canonical(unsigned)
            ),
        }
    )
    validated = boundary._validate_registry_completion_receipt_bytes(
        raw, registrar_source_bytes=REGISTRAR_SOURCE
    )
    relative_paths = tuple(row.relative_path for row in validated.registered_records)
    assert relative_paths[8:11] == (
        "records/internal_block_01/adaptation/9.json",
        "records/internal_block_01/adaptation/10.json",
        "records/internal_block_01/adaptation/11.json",
    )
    assert relative_paths != tuple(sorted(relative_paths))

    identity_records = [
        {
            "device": 7,
            "group_gid": boundary.PRIVATE_READ_GID,
            "inode": index + 1,
            "link_count": 1,
            "mode": 0o440,
            "owner_uid": boundary.REGISTRAR_UID,
            "relative_path": row["relative_path"],
            "size_bytes": row["size_bytes"],
        }
        for index, row in enumerate(rows)
    ]
    directory_paths = boundary._expected_private_directories(
        tuple(str(row["relative_path"]) for row in rows)
    )
    identity_directories = [
        {
            "device": 7,
            "group_gid": boundary.PRIVATE_READ_GID,
            "inode": len(identity_records) + index + 1,
            "mode": 0o750,
            "owner_uid": boundary.REGISTRAR_UID,
            "relative_path": relative,
        }
        for index, relative in enumerate(directory_paths)
    ]
    identity_inventory = {
        "directories": identity_directories,
        "record_count": len(identity_records),
        "records": identity_records,
    }
    _, observed_identity = boundary._validate_identity_inventory(
        identity_inventory,
        root_device=7,
        allow_empty_records=False,
        stage_kind=stage_kind,
    )
    assert tuple(path for path, _ in observed_identity) == relative_paths
    content_inventory = [
        {
            "device": 7,
            "hidden_sha256": row["hidden_sha256"],
            "inode": index + 1,
            "path": row["relative_path"],
            "size_bytes": row["size_bytes"],
        }
        for index, row in enumerate(rows)
    ]
    assert (
        tuple(
            row["path"]
            for row in boundary._validate_content_inventory(
                content_inventory,
                identity_inventory=identity_inventory,
                root_device=7,
            )
        )
        == relative_paths
    )


def test_access_probe_source_and_privilege_receipt_fields_are_exact(
    tmp_path: Path,
) -> None:
    chain = _build_chain(tmp_path)
    value = json.loads(chain.initial.attestation_bytes)
    assert value["access_probe_source"]["sha256"] == boundary._sha(ACCESS_PROBE_SOURCE)
    receipt = json.loads(chain.initial_receipts["03_private_validator_read_probe"])
    assert receipt["pre_transition_real_uid"] == boundary.ATTESTER_UID
    assert receipt["pre_transition_effective_uid"] == 0
    assert receipt["pre_transition_saved_uid"] == 0
    assert receipt["observed_all_capability_sets_zero"] is True
    assert receipt["observed_no_new_privs"] is True
    assert receipt["observed_securebits"] == boundary._LOCKED_SECUREBITS
    assert receipt["self_executable_sha256"] == value["setuid_adapter"]["sha256"]
    with pytest.raises(boundary.PrivateBoundaryError, match="access probe source"):
        boundary.validate_initial_registration_boundary_bytes(
            chain.initial.attestation_bytes,
            access_probe_receipts_by_id=chain.initial_receipts,
            attester_source_bytes=chain.source_bytes,
            access_probe_source_bytes=ACCESS_PROBE_SOURCE + b"substitution",
            validation_time_utc="2026-07-14T12:01:01Z",
        )


def test_c_adapter_source_requires_verified_fd_self_binding_and_exact_drop_order() -> (
    None
):
    source = ACCESS_PROBE_SOURCE.decode("ascii")
    python_source = Path(boundary.__file__).read_text(encoding="utf-8")
    assert "fexecve(descriptor" in python_source
    assert 'open("/proc/self/exe"' in source
    assert "getresuid" in source and "getresgid" in source
    assert (
        source.index("setgroups(options->target_group_count")
        < source.index("setresgid(options->target_gid")
        < source.index("setresuid(options->target_uid")
    )
    for required in (
        "PR_SET_NO_NEW_PRIVS",
        "PR_SET_SECUREBITS",
        "PR_CAPBSET_DROP",
        '"CapBnd:"',
        "capset zero failed",
        "/proc/self/exe does not match verified descriptor",
    ):
        assert required in source
    assert tuple(re.findall(r'\bSPEC\("([^"]+)"', source)) == (
        boundary.INITIAL_PRIVATE_PROBE_IDS + boundary.SEALED_PRIVATE_PROBE_IDS
    )
    for required in (
        "validate_registered_probe(options);",
        "probe request differs from the compiled allowlist",
        "the private probe allowlist must contain exactly 23 entries",
        "options->target_uid == 0U",
        'strstr(path, "//")',
        'strstr(path, "/./")',
        'strstr(path, "/../")',
        "probe path must be printable ASCII without whitespace",
        "validate_registered_record_path",
        "close_unregistered_fds();",
    ):
        assert required in source
    main_source = source[source.index("int main(int argc") :]
    assert (
        main_source.index("close_unregistered_fds();")
        < main_source.index("verify_self(&options);")
        < main_source.index("transition_credentials(&options);")
    )
