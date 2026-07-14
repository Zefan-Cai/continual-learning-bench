from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable
from unittest import mock

import pytest

import cohort_closed_loop_structured_atomic_publish as atomic_publish
import cohort_closed_loop_structured_context_registrar as registrar
import cohort_closed_loop_structured_deployment_snapshot as deployment_snapshot
import cohort_closed_loop_structured_private_boundary as private_boundary
import cohort_closed_loop_structured_protocol_plan as protocol_plan
import cohort_closed_loop_structured_stage_plan as structured_stage_plan
import cohort_closed_loop_structured_trigger_bridge as trigger_bridge
from cohort_closed_loop_structured_atomic_publish import (
    AtomicPublicationError,
    publication_sidecar_relative_paths,
    publish_readonly_no_overwrite,
    read_and_validate_readonly_artifact,
)
from cohort_closed_loop_structured_dgp_context import (
    canonical_json_bytes,
    make_dgp_row_identity,
)


COMPLETED_AT = "2026-07-14T12:01:00Z"
BOOT_ID = "12345678-1234-1234-1234-123456789abc"


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _stage_plan_fixture_module() -> ModuleType:
    name = "_registrar_stage_plan_fixture"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).with_name("test_cohort_closed_loop_structured_stage_plan.py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load stage-plan fixture module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _private_boundary_fixture_module() -> ModuleType:
    name = "_registrar_private_boundary_fixture"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).with_name(
        "test_cohort_closed_loop_structured_private_boundary.py"
    )
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load private-boundary fixture module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def stage_plan_fixture() -> tuple[bytes, dict[str, Any]]:
    stage_fixture = _stage_plan_fixture_module()
    phase12 = stage_fixture._phase12_fixture_module()  # type: ignore[attr-defined]
    receipt, evidence = phase12._strict_receipt_and_inputs()  # type: ignore[attr-defined]
    trigger = trigger_bridge.revalidate_and_bind_trigger_a_receipt(receipt, **evidence)
    filesystem = phase12._FakeSnapshotFilesystem(  # type: ignore[attr-defined]
        source_commit="b" * 40, attempt_id="attempt-001"
    )
    actual_sources = {
        "context_registrar": (
            Path(registrar.__file__).name,
            Path(registrar.__file__).read_bytes(),
        ),
        "private_context_access_boundary": (
            Path(private_boundary.__file__).name,
            Path(private_boundary.__file__).read_bytes(),
        ),
        "private_access_probe_source": (
            "cohort_closed_loop_private_access_probe.c",
            Path(private_boundary.__file__)
            .with_name("cohort_closed_loop_private_access_probe.c")
            .read_bytes(),
        ),
    }
    source_paths = filesystem.source_paths()
    for role, (basename, raw) in actual_sources.items():
        old_path = PurePosixPath(source_paths[role])
        old_relative = old_path.relative_to(filesystem.checkout).as_posix()
        filesystem.data.pop(str(old_path))
        filesystem.metadata.pop(str(old_path))
        filesystem.committed.pop(old_relative)
        new_path = filesystem.checkout / "sources" / basename
        filesystem._add_file(  # noqa: SLF001
            new_path, raw, device=filesystem.CHECKOUT_DEVICE
        )
        new_relative = new_path.relative_to(filesystem.checkout).as_posix()
        filesystem.committed[new_relative] = raw
        source_paths[role] = str(new_path)
    capture_kwargs = filesystem.capture_kwargs()
    capture_kwargs["source_paths_by_role"] = source_paths
    artifacts = deployment_snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
        **capture_kwargs
    )
    snapshot_kwargs = phase12._snapshot_validation_kwargs(  # type: ignore[attr-defined]
        artifacts
    )
    protocol_kwargs = {
        "strict_trigger_bridge_bytes": trigger.bridge_receipt_bytes,
        "strict_trigger_receipt_bytes": receipt,
        "strict_trigger_evidence_bytes": evidence,
        "deployment_snapshot_bytes": artifacts.deployment_snapshot_bytes,
        **snapshot_kwargs,
    }
    protocol_raw = protocol_plan.seal_structured_protocol_plan_bytes(**protocol_kwargs)
    kwargs = {
        "protocol_plan_seal_bytes": protocol_raw,
        "stage_kind": "smoke",
        "stage_attempt_id": "attempt-007",
        "parent_transition_receipt_bytes": (),
        **protocol_kwargs,
    }
    raw = structured_stage_plan.seal_structured_stage_plan_bytes(**kwargs)
    payload = json.loads(raw)
    source = next(
        row
        for row in payload["source_role_bindings"]
        if row["role"] == "context_registrar"
    )
    assert Path(source["path"]).name == Path(registrar.__file__).name
    assert (
        source["sha256"]
        == hashlib.sha256(actual_sources["context_registrar"][1]).hexdigest()
    )
    return raw, kwargs


@dataclass(slots=True)
class _Setup:
    public_root: Path
    private_root: Path
    plan_raw: bytes
    plan_kwargs: dict[str, Any]
    plan: dict[str, Any]
    registrar_source_path: Path
    registrar_source: bytes
    initial_attestation: bytes
    initial_receipts: dict[str, bytes]
    attester_source: bytes
    access_probe_source: bytes
    initial_validation_time: str
    stage_public_root: Path
    completion_relative: str
    hidden: dict[str, bytes]
    opaque: dict[str, bytes]
    row_raw_by_relative: dict[str, bytes]

    @property
    def entries(self) -> list[dict[str, Any]]:
        return self.plan["registry_v2_mapping"]["planned_entries"]

    def public_relative(self, absolute: str) -> str:
        durable = self.plan["paths"]["durable_root"]
        return absolute.removeprefix(durable + "/")


def _publish(root: Path, relative: str, raw: bytes) -> None:
    root.joinpath(*PurePosixPath(relative).parts[:-1]).mkdir(
        mode=0o700, parents=True, exist_ok=True
    )
    publish_readonly_no_overwrite(root=root, relative_path=relative, payload=raw)


def _publish_alias_intent(root: Path, relative: str, raw: bytes) -> None:
    intent_relative, pending_relative = publication_sidecar_relative_paths(relative)
    intent_raw = atomic_publish._intent_bytes(  # noqa: SLF001
        relative_path=relative,
        pending_name=PurePosixPath(pending_relative).name,
        payload=raw,
    )
    intent_path = root.joinpath(*PurePosixPath(intent_relative).parts)
    descriptor = os.open(
        intent_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, intent_raw)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _row_raw(index: int, item_id: int, *, invalid_hash: bool = False) -> bytes:
    row = make_dgp_row_identity(
        item_id=item_id,
        instance_id=f"instance-{index:02d}",
        query_sha256=_sha_text(f"query:{index}"),
        database_sha256=_sha_text(f"database:{index}"),
        ground_truth_sha256=_sha_text(f"ground-truth:{index}"),
        reference_survival_sha256=_sha_text(f"reference:{index}"),
        schedule_entry_sha256=_sha_text(f"schedule:{index}"),
    )
    payload = row.to_payload()
    if invalid_hash:
        payload["composite_row_identity_sha256"] = "0" * 64
    return canonical_json_bytes(payload)


def _setup(
    tmp_path: Path,
    stage_plan_fixture: tuple[bytes, dict[str, Any]],
    *,
    omit_row_index: int | None = None,
    invalid_row_index: int | None = None,
) -> _Setup:
    plan_raw, plan_kwargs = stage_plan_fixture
    plan = json.loads(plan_raw)
    public_root = (tmp_path / "public").resolve()
    private_root = (tmp_path / "private").resolve()
    public_root.mkdir(mode=0o700, parents=True)
    private_root.mkdir(mode=0o750)
    durable = plan["paths"]["durable_root"]
    stage_relative = plan["paths"]["stage_root"].removeprefix(durable + "/")
    stage_public_root = public_root.joinpath(*PurePosixPath(stage_relative).parts)
    for phase in ("initial", "sealed"):
        (stage_public_root / "control" / "private_boundary" / phase / "probes").mkdir(
            mode=0o700, parents=True
        )
    (stage_public_root / "control" / "private_boundary" / "registry").mkdir(
        mode=0o700, parents=True
    )
    completion_relative = plan["paths"][
        "registry_completion_receipt_path"
    ].removeprefix(durable + "/")

    boundary_fixture = _private_boundary_fixture_module()
    initial = private_boundary._attest_private_boundary_for_test(  # noqa: SLF001
        stage=private_boundary.INITIAL_REGISTRATION_STAGE,
        public_root=stage_public_root,
        private_root=private_root,
        source_commit=plan["source_commit"],
        experiment_attempt_id=plan["experiment_attempt_id"],
        stage_kind=plan["stage_kind"],
        stage_attempt_id=plan["stage_attempt_id"],
        expected_record_paths=(),
        probe_record_relative_path=None,
        initial_registration_attestation_bytes=None,
        initial_access_probe_receipts_by_id=None,
        registry_completion_receipt_bytes=None,
        registrar_source_bytes=None,
        runtime=boundary_fixture._runtime(  # type: ignore[attr-defined]
            private_root,
            mount_mode="rw",
            started="2026-07-14T12:00:00Z",
            completed="2026-07-14T12:00:05Z",
        ),
    )
    initial_raw_by_probe = dict(initial.access_probe_receipts)
    for row in plan["paths"]["initial_probe_receipt_paths"]:
        relative = row["path"].removeprefix(durable + "/")
        _publish_alias_intent(
            public_root,
            relative,
            initial_raw_by_probe[row["probe_id"]],
        )
    initial_relative = plan["paths"]["initial_boundary_attestation_path"].removeprefix(
        durable + "/"
    )
    _publish_alias_intent(public_root, initial_relative, initial.attestation_bytes)

    hidden: dict[str, bytes] = {}
    opaque: dict[str, bytes] = {}
    row_raw_by_relative: dict[str, bytes] = {}
    entries = plan["registry_v2_mapping"]["planned_entries"]
    for index, entry in enumerate(entries):
        private_relative = entry["private_record_relative_path"]
        hidden[private_relative] = (
            f"PRIVATE-GROUND-TRUTH-AND-SCORER-CONTEXT-{index:02d}\n".encode()
        )
        opaque[private_relative] = f"opaque-handle-{index:02d}".encode()
        row_relative = entry["dgp_row_path"].removeprefix(durable + "/")
        row_raw = _row_raw(
            index,
            entry["item_id"],
            invalid_hash=index == invalid_row_index,
        )
        row_raw_by_relative[row_relative] = row_raw
        if index != omit_row_index:
            _publish(public_root, row_relative, row_raw)
        for key in ("public_attestation_path", "public_registry_digest_path"):
            relative = entry[key].removeprefix(durable + "/")
            public_root.joinpath(*PurePosixPath(relative).parts[:-1]).mkdir(
                mode=0o700, parents=True, exist_ok=True
            )

    registrar_source_binding = next(
        row
        for row in plan["source_role_bindings"]
        if row["role"] == "context_registrar"
    )
    attester_source = Path(private_boundary.__file__).read_bytes()
    access_probe_source = (
        Path(private_boundary.__file__)
        .with_name("cohort_closed_loop_private_access_probe.c")
        .read_bytes()
    )

    return _Setup(
        public_root=public_root,
        private_root=private_root,
        plan_raw=plan_raw,
        plan_kwargs=plan_kwargs,
        plan=plan,
        registrar_source_path=Path(registrar_source_binding["path"]),
        registrar_source=plan_kwargs["source_file_bytes_by_role"]["context_registrar"],
        initial_attestation=initial.attestation_bytes,
        initial_receipts=dict(initial.access_probe_receipts),
        attester_source=attester_source,
        access_probe_source=access_probe_source,
        initial_validation_time="2026-07-14T12:00:05Z",
        stage_public_root=stage_public_root,
        completion_relative=completion_relative,
        hidden=hidden,
        opaque=opaque,
        row_raw_by_relative=row_raw_by_relative,
    )


def _process_identity() -> dict[str, object]:
    return {
        "active_capabilities_empty": True,
        "effective_gid": 41016,
        "effective_uid": 41011,
        "pid": 123,
        "process_start_ticks": 456,
        "real_gid": 41016,
        "real_uid": 41011,
        "saved_gid": 41016,
        "saved_uid": 41011,
        "service_identity": "cohort-structured-context-registrar-v1",
        "supplementary_gids": [],
    }


def _runtime(
    callback: Callable[[], None] = lambda: None,
) -> registrar._RegistrarTestRuntime:  # noqa: SLF001
    return registrar._RegistrarTestRuntime(  # noqa: SLF001
        completed_at_utc=lambda: COMPLETED_AT,
        boot_id=lambda: BOOT_ID,
        process_identity=_process_identity,
        before_completion_revalidation=callback,
    )


def _invoke(
    setup: _Setup,
    *,
    hidden: dict[str, bytes] | None = None,
    opaque: dict[str, bytes] | None = None,
    callback: Callable[[], None] = lambda: None,
    plan_raw: bytes | None = None,
    registrar_source: bytes | None = None,
    registrar_source_path: Path | None = None,
    actual_source: bytes | None = None,
    actual_source_path: Path | None = None,
    initial_attestation: bytes | None = None,
    initial_receipts: dict[str, bytes] | None = None,
) -> registrar.ContextRegistrarArtifacts:
    frozen_actual_path = (
        setup.registrar_source_path
        if actual_source_path is None
        else actual_source_path
    )
    frozen_actual_raw = (
        setup.registrar_source if actual_source is None else actual_source
    )
    original_read_bytes = Path.read_bytes

    def read_bytes(path: Path) -> bytes:
        if path.resolve() == frozen_actual_path.resolve():
            return frozen_actual_raw
        return original_read_bytes(path)

    with (
        mock.patch.object(registrar, "__file__", str(frozen_actual_path)),
        mock.patch.object(Path, "read_bytes", read_bytes),
    ):
        return registrar._register_and_publish_for_test(  # noqa: SLF001
            public_root=setup.public_root,
            private_root=setup.private_root,
            stage_plan_bytes=setup.plan_raw if plan_raw is None else plan_raw,
            stage_plan_validation_kwargs=setup.plan_kwargs,
            initial_registration_attestation_bytes=(
                setup.initial_attestation
                if initial_attestation is None
                else initial_attestation
            ),
            initial_access_probe_receipts_by_id=(
                setup.initial_receipts if initial_receipts is None else initial_receipts
            ),
            attester_source_bytes=setup.attester_source,
            access_probe_source_bytes=setup.access_probe_source,
            initial_validation_time_utc=setup.initial_validation_time,
            registrar_source_path=(
                setup.registrar_source_path
                if registrar_source_path is None
                else registrar_source_path
            ),
            registrar_source_bytes=(
                setup.registrar_source if registrar_source is None else registrar_source
            ),
            hidden_record_bytes_by_relative_path=(
                setup.hidden if hidden is None else hidden
            ),
            opaque_handle_bytes_by_relative_path=(
                setup.opaque if opaque is None else opaque
            ),
            runtime=_runtime(callback),
        )


def _receipt_absent(setup: _Setup) -> bool:
    final, intent, pending = (
        setup.completion_relative,
        *publication_sidecar_relative_paths(setup.completion_relative),
    )
    return not any(
        os.path.lexists(setup.public_root / path)
        for path in (
            final,
            intent,
            pending,
        )
    )


def _replace_atomic_same_bytes(root: Path, relative: str, raw: bytes) -> None:
    intent, _ = publication_sidecar_relative_paths(relative)
    (root / relative).unlink()
    (root / intent).unlink()
    publish_readonly_no_overwrite(root=root, relative_path=relative, payload=raw)


def test_public_production_entry_is_provider_unavailable_before_access() -> None:
    class _Bomb:
        def __getattribute__(self, name: str) -> object:
            raise AssertionError(f"production entry accessed {name}")

    assert registrar.PROVIDER_AVAILABLE is False
    signature = inspect.signature(
        registrar.register_structured_contexts_and_publish_completion
    )
    forbidden = {
        "stage_plan_bytes",
        "runtime",
        "hidden_record_bytes_by_relative_path",
        "opaque_handle_bytes_by_relative_path",
        "registrar_source_bytes",
    }
    assert forbidden.isdisjoint(signature.parameters)
    bomb = _Bomb()
    with pytest.raises(
        registrar.ContextRegistrarError, match="provider is unavailable"
    ):
        registrar.register_structured_contexts_and_publish_completion(
            stage_root=bomb,  # type: ignore[arg-type]
            private_context_root=bomb,  # type: ignore[arg-type]
            source_commit=bomb,  # type: ignore[arg-type]
            experiment_attempt_id=bomb,  # type: ignore[arg-type]
            stage_kind=bomb,  # type: ignore[arg-type]
            stage_attempt_id=bomb,  # type: ignore[arg-type]
        )


def test_exact_smoke_closure_publishes_v2_non_authorizing_without_hidden_bytes(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    artifacts = _invoke(setup)
    value = json.loads(artifacts.receipt_bytes)
    validation = registrar.validate_registry_completion_bytes(
        artifacts.receipt_bytes, registrar_source_bytes=setup.registrar_source
    )

    assert artifacts.registered_record_count == validation.registered_record_count == 10
    assert len(artifacts.public_artifact_publications) == 20
    assert value["protocol"] == (
        "cohort_structured_private_context_registry_completion_receipt_v2"
    )
    assert value["schema_version"] == 2
    assert value["status"] == "private_registry_complete_non_authorizing"
    assert value["registered_record_count"] == len(value["registered_records"]) == 10
    assert value["record_set_sha256"] == artifacts.record_set_sha256
    assert value["registry_completion_receipt_sha256"] == (
        artifacts.registry_completion_receipt_sha256
    )
    initial_self_digest = json.loads(setup.initial_attestation)[
        "private_boundary_attestation_sha256"
    ]
    assert value["initial_registration_attestation_sha256"] == initial_self_digest
    assert (
        value["initial_registration_attestation_sha256"]
        != hashlib.sha256(setup.initial_attestation).hexdigest()
    )
    source_binding = next(
        row
        for row in setup.plan["source_role_bindings"]
        if row["role"] == "context_registrar"
    )
    assert source_binding == {
        "path": setup.registrar_source_path.as_posix(),
        "role": "context_registrar",
        "sha256": hashlib.sha256(setup.registrar_source).hexdigest(),
        "size_bytes": len(setup.registrar_source),
    }
    assert all(value[key] is False for key in registrar._AUTHORITY_KEYS)  # noqa: SLF001
    assert not any(
        (
            artifacts.dgp_calls_authorized,
            artifacts.model_calls_authorized,
            artifacts.scorer_calls_authorized,
            artifacts.launch_authorized,
            artifacts.operational_authorization,
        )
    )
    coordinates = [
        (
            row["block_index"],
            row["phase"],
            row["item_id"],
            row["instance_index"],
        )
        for row in value["registered_records"]
    ]
    assert coordinates == [
        (0, phase, item_id, item_id - 1)
        for phase in ("adaptation", "held_out")
        for item_id in range(1, 6)
    ]
    for hidden_raw in setup.hidden.values():
        assert hidden_raw not in artifacts.receipt_bytes
    assert b"PRIVATE-GROUND-TRUTH" not in artifacts.receipt_bytes
    assert (
        stat.S_IMODE(Path(artifacts.receipt_publication.path).stat().st_mode) == 0o444
    )

    expected_directories = {
        "records",
        "records/smoke_block_01",
        "records/smoke_block_01/adaptation",
        "records/smoke_block_01/held_out",
    }
    actual_directories = {
        path.relative_to(setup.private_root).as_posix()
        for path in setup.private_root.rglob("*")
        if path.is_dir()
    }
    assert actual_directories == expected_directories
    private_files = [path for path in setup.private_root.rglob("*") if path.is_file()]
    assert len(private_files) == 10
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o440 for path in private_files)


@pytest.mark.parametrize("mutation", ["missing", "extra", "wrong_path"])
def test_hidden_input_keys_must_be_exact_full_mapping_before_writes(
    tmp_path: Path,
    stage_plan_fixture: tuple[bytes, dict[str, Any]],
    mutation: str,
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    hidden = dict(setup.hidden)
    first = next(iter(hidden))
    if mutation == "missing":
        del hidden[first]
    elif mutation == "extra":
        hidden["records/smoke_block_01/adaptation/99.json"] = b"extra"
    else:
        raw = hidden.pop(first)
        hidden["records/smoke_block_01/held_out/99.json"] = raw
    with pytest.raises(registrar.ContextRegistrarError, match="exactly cover"):
        _invoke(setup, hidden=hidden)
    assert not any(setup.private_root.iterdir())
    assert _receipt_absent(setup)


def test_duplicate_opaque_handle_is_rejected_before_any_ordinal_three_write(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    opaque = dict(setup.opaque)
    keys = tuple(opaque)
    opaque[keys[1]] = opaque[keys[0]]
    with pytest.raises(registrar.ContextRegistrarError, match="reuses an opaque"):
        _invoke(setup, opaque=opaque)
    assert not any(setup.private_root.iterdir())
    assert _receipt_absent(setup)


def test_missing_or_hash_invalid_dgp_row_fails_before_private_write(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    missing = _setup(tmp_path / "missing", stage_plan_fixture, omit_row_index=3)
    with pytest.raises(registrar.ContextRegistrarError, match="DGP row closure"):
        _invoke(missing)
    assert not any(missing.private_root.iterdir())
    assert _receipt_absent(missing)

    invalid = _setup(tmp_path / "invalid", stage_plan_fixture, invalid_row_index=4)
    with pytest.raises(registrar.ContextRegistrarError, match="DGP row closure"):
        _invoke(invalid)
    assert not any(invalid.private_root.iterdir())
    assert _receipt_absent(invalid)


def test_stage_plan_path_tamper_fails_raw_reconstruction_before_filesystem_write(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    tampered = json.loads(setup.plan_raw)
    entry = tampered["registry_v2_mapping"]["planned_entries"][0]
    entry["private_record_relative_path"] = "records/smoke_block_01/adaptation/99.json"
    unsigned = {
        key: value for key, value in tampered.items() if key != "stage_plan_sha256"
    }
    tampered["stage_plan_sha256"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
    with pytest.raises(
        registrar.ContextRegistrarError, match="raw-byte reconstruction"
    ):
        _invoke(setup, plan_raw=_canonical(tampered))
    assert not any(setup.private_root.iterdir())
    assert _receipt_absent(setup)


def test_wrong_registrar_source_binding_fails_before_private_write(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    with pytest.raises(registrar.ContextRegistrarError, match="source identities"):
        _invoke(setup, registrar_source=setup.registrar_source + b"drift")
    assert not any(setup.private_root.iterdir())
    assert _receipt_absent(setup)


def test_actual_source_replacement_and_path_swap_fail_before_private_write(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    with pytest.raises(registrar.ContextRegistrarError, match="source identities"):
        _invoke(setup, actual_source=setup.registrar_source + b"replacement")
    assert not any(setup.private_root.iterdir())
    assert _receipt_absent(setup)

    swapped_path = setup.registrar_source_path.with_name(
        "swapped_cohort_closed_loop_structured_context_registrar.py"
    )
    with pytest.raises(registrar.ContextRegistrarError, match="source identities"):
        _invoke(
            setup,
            actual_source_path=swapped_path,
            registrar_source_path=swapped_path,
        )
    assert not any(setup.private_root.iterdir())
    assert _receipt_absent(setup)


def test_initial_boundary_requires_all_14_receipts_and_valid_self_digest(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    missing = _setup(tmp_path / "missing", stage_plan_fixture)
    receipts = dict(missing.initial_receipts)
    receipts.pop(next(iter(receipts)))
    with pytest.raises(registrar.ContextRegistrarError, match="14-probe"):
        _invoke(missing, initial_receipts=receipts)
    assert not any(missing.private_root.iterdir())
    assert _receipt_absent(missing)

    invalid = _setup(tmp_path / "invalid", stage_plan_fixture)
    value = json.loads(invalid.initial_attestation)
    value["private_boundary_attestation_sha256"] = "0" * 64
    tampered = _canonical(value)
    initial_relative = invalid.public_relative(
        invalid.plan["paths"]["initial_boundary_attestation_path"]
    )
    _replace_atomic_same_bytes(invalid.public_root, initial_relative, tampered)
    with pytest.raises(registrar.ContextRegistrarError, match="semantic closure"):
        _invoke(invalid, initial_attestation=tampered)
    assert not any(invalid.private_root.iterdir())
    assert _receipt_absent(invalid)


def test_partial_publication_or_nonempty_private_epoch_is_poison(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    partial = _setup(tmp_path / "partial", stage_plan_fixture)
    target = partial.public_relative(partial.entries[0]["public_attestation_path"])
    _publish(partial.public_root, target, b"partial-publication")
    with pytest.raises(registrar.ContextRegistrarError, match="partial"):
        _invoke(partial)
    assert not any(partial.private_root.iterdir())
    assert _receipt_absent(partial)

    private_partial = _setup(tmp_path / "private-partial", stage_plan_fixture)
    extra = private_partial.private_root / "unexpected-directory"
    extra.mkdir(mode=0o750)
    with pytest.raises(registrar.ContextRegistrarError, match="not exactly empty"):
        _invoke(private_partial)
    assert _receipt_absent(private_partial)


def test_same_byte_private_record_replacement_is_detected_before_receipt(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    relative = next(iter(setup.hidden))
    target = setup.private_root.joinpath(*PurePosixPath(relative).parts)

    def replace() -> None:
        target.unlink()
        target.write_bytes(setup.hidden[relative])
        target.chmod(0o440)

    with pytest.raises(registrar.ContextRegistrarError, match="private record changed"):
        _invoke(setup, callback=replace)
    assert _receipt_absent(setup)


def test_private_root_rename_and_symlink_to_same_inode_is_rejected(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    renamed = setup.private_root.with_name("private-renamed")

    def replace_with_symlink_to_original_inode() -> None:
        setup.private_root.rename(renamed)
        setup.private_root.symlink_to(renamed, target_is_directory=True)

    with pytest.raises(registrar.ContextRegistrarError, match="retained directory"):
        _invoke(setup, callback=replace_with_symlink_to_original_inode)
    assert renamed.is_dir()
    assert setup.private_root.is_symlink()
    assert _receipt_absent(setup)


def test_private_root_rename_without_replacement_is_rejected(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    renamed = setup.private_root.with_name("private-renamed")

    def rename_root() -> None:
        setup.private_root.rename(renamed)

    with pytest.raises(registrar.ContextRegistrarError, match="retained directory"):
        _invoke(setup, callback=rename_root)
    assert renamed.is_dir()
    assert not setup.private_root.exists()
    assert _receipt_absent(setup)


def test_private_root_rename_and_different_directory_replacement_is_rejected(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    renamed = setup.private_root.with_name("private-renamed")

    def replace_with_different_directory() -> None:
        setup.private_root.rename(renamed)
        setup.private_root.mkdir(mode=0o750)

    with pytest.raises(registrar.ContextRegistrarError, match="retained directory"):
        _invoke(setup, callback=replace_with_different_directory)
    assert renamed.is_dir()
    assert setup.private_root.is_dir()
    assert setup.private_root.stat().st_ino != renamed.stat().st_ino
    assert _receipt_absent(setup)


def test_same_byte_public_identity_artifact_replacement_is_detected(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    relative = setup.public_relative(setup.entries[0]["public_registry_digest_path"])

    def replace() -> None:
        raw, _ = read_and_validate_readonly_artifact(
            root=setup.public_root, relative_path=relative
        )
        intent, _ = publication_sidecar_relative_paths(relative)
        (setup.public_root / relative).unlink()
        (setup.public_root / intent).unlink()
        publish_readonly_no_overwrite(
            root=setup.public_root, relative_path=relative, payload=raw
        )

    with pytest.raises(registrar.ContextRegistrarError, match="artifact changed"):
        _invoke(setup, callback=replace)
    assert _receipt_absent(setup)


def test_same_byte_initial_probe_replacement_is_detected_by_second_semantic_pass(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    first = setup.plan["paths"]["initial_probe_receipt_paths"][0]
    relative = setup.public_relative(first["path"])
    raw = setup.initial_receipts[first["probe_id"]]

    def replace() -> None:
        _replace_atomic_same_bytes(setup.public_root, relative, raw)

    with pytest.raises(
        registrar.ContextRegistrarError, match="semantic closure changed"
    ):
        _invoke(setup, callback=replace)
    assert _receipt_absent(setup)


def test_extra_private_directory_appearing_during_revalidation_is_detected(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)

    def add_extra() -> None:
        (setup.private_root / "records" / "extra").mkdir(mode=0o750)

    with pytest.raises(registrar.ContextRegistrarError, match="extra directories"):
        _invoke(setup, callback=add_extra)
    assert _receipt_absent(setup)


def test_missing_public_parent_fails_before_private_write_and_private_root_is_fsynced(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    missing = _setup(tmp_path / "missing", stage_plan_fixture)
    target_relative = missing.public_relative(
        missing.entries[0]["public_attestation_path"]
    )
    missing.public_root.joinpath(*PurePosixPath(target_relative).parts[:-1]).rmdir()
    with pytest.raises(registrar.ContextRegistrarError, match="parent is missing"):
        _invoke(missing)
    assert not any(missing.private_root.iterdir())
    assert _receipt_absent(missing)

    durable = _setup(tmp_path / "durable", stage_plan_fixture)
    private_identity = (
        durable.private_root.stat().st_dev,
        durable.private_root.stat().st_ino,
    )
    fsynced_directories: list[tuple[int, int]] = []
    original_fsync = registrar.os.fsync

    def recording_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            fsynced_directories.append((metadata.st_dev, metadata.st_ino))
        original_fsync(descriptor)

    with mock.patch.object(registrar.os, "fsync", recording_fsync):
        _invoke(durable)
    assert private_identity in fsynced_directories


def test_public_parent_identity_must_remain_stable_across_callback(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    target_relative = setup.public_relative(setup.entries[0]["public_attestation_path"])
    parent = setup.public_root.joinpath(*PurePosixPath(target_relative).parts[:-1])

    def change_mode() -> None:
        parent.chmod(0o755)

    with pytest.raises(registrar.ContextRegistrarError, match="across callback"):
        _invoke(setup, callback=change_mode)
    assert _receipt_absent(setup)


def test_registry_receipt_is_atomic_readonly_and_no_overwrite(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    artifacts = _invoke(setup)
    before = Path(artifacts.receipt_publication.path).read_bytes()
    with pytest.raises((AtomicPublicationError, FileExistsError)):
        publish_readonly_no_overwrite(
            root=setup.public_root,
            relative_path=setup.completion_relative,
            payload=b"replacement receipt",
        )
    after, observation = read_and_validate_readonly_artifact(
        root=setup.public_root,
        relative_path=setup.completion_relative,
        expected_payload=before,
    )
    assert after == before == artifacts.receipt_bytes
    assert observation == artifacts.receipt_publication


def test_real_initial_registrar_and_sealed_boundary_receipt_binding_join(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    artifacts = _invoke(setup)
    _publish_alias_intent(
        setup.stage_public_root,
        private_boundary.REGISTRY_COMPLETION_RECEIPT_RELATIVE_PATH,
        artifacts.receipt_bytes,
    )

    boundary_fixture = _private_boundary_fixture_module()
    records = tuple(setup.hidden)
    sealed = private_boundary._attest_private_boundary_for_test(  # noqa: SLF001
        stage=private_boundary.SEALED_PRELAUNCH_STAGE,
        public_root=setup.stage_public_root,
        private_root=setup.private_root,
        source_commit=setup.plan["source_commit"],
        experiment_attempt_id=setup.plan["experiment_attempt_id"],
        stage_kind=setup.plan["stage_kind"],
        stage_attempt_id=setup.plan["stage_attempt_id"],
        expected_record_paths=records,
        probe_record_relative_path=records[0],
        initial_registration_attestation_bytes=setup.initial_attestation,
        initial_access_probe_receipts_by_id=setup.initial_receipts,
        registry_completion_receipt_bytes=artifacts.receipt_bytes,
        registrar_source_bytes=setup.registrar_source,
        runtime=boundary_fixture._runtime(  # type: ignore[attr-defined]
            setup.private_root,
            mount_mode="ro",
            started="2026-07-14T12:01:01Z",
            completed="2026-07-14T12:01:05Z",
        ),
    )
    sealed_receipts = dict(sealed.access_probe_receipts)
    validation = private_boundary.validate_sealed_prelaunch_boundary_bytes(
        sealed.attestation_bytes,
        access_probe_receipts_by_id=sealed_receipts,
        attester_source_bytes=setup.attester_source,
        access_probe_source_bytes=setup.access_probe_source,
        validation_time_utc="2026-07-14T12:02:05Z",
        initial_registration_attestation_bytes=setup.initial_attestation,
        initial_access_probe_receipts_by_id=setup.initial_receipts,
        registry_completion_receipt_bytes=artifacts.receipt_bytes,
        registrar_source_bytes=setup.registrar_source,
    )
    sealed_value = json.loads(sealed.attestation_bytes)
    assert validation.registry_completion_receipt_sha256 == (
        artifacts.registry_completion_receipt_sha256
    )
    assert (
        sealed_value["initial_registration_attestation_sha256"]
        == json.loads(setup.initial_attestation)["private_boundary_attestation_sha256"]
    )


def test_public_validator_rejects_forged_authority_even_with_resealed_self_hash(
    tmp_path: Path, stage_plan_fixture: tuple[bytes, dict[str, Any]]
) -> None:
    setup = _setup(tmp_path, stage_plan_fixture)
    artifacts = _invoke(setup)
    forged = json.loads(artifacts.receipt_bytes)
    forged["launch_authorized"] = True
    unsigned = {
        key: value
        for key, value in forged.items()
        if key != "registry_completion_receipt_sha256"
    }
    forged["registry_completion_receipt_sha256"] = hashlib.sha256(
        _canonical(unsigned)
    ).hexdigest()
    with pytest.raises(registrar.ContextRegistrarError, match="validation failed"):
        registrar.validate_registry_completion_bytes(
            _canonical(forged), registrar_source_bytes=setup.registrar_source
        )
