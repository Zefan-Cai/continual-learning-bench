from __future__ import annotations

import ast
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

import cohort_closed_loop_structured_atomic_publish as atomic
import cohort_closed_loop_structured_trigger_absence_adapter as absence
import cohort_closed_loop_structured_trigger_publisher as publisher


SOURCE_COMMIT = "b" * 40
ATTEMPT_ID = "attempt-001"
LOGICAL_ROOT = (
    "/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
    f"{SOURCE_COMMIT}/attempts/{ATTEMPT_ID}"
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mountinfo(root: Path, *, alternate_control: bool = False) -> bytes:
    metadata = root.stat()
    major_minor = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    rows = [f"101 1 {major_minor} / {root} rw,nosuid - testfs /dev/test rw"]
    if alternate_control:
        rows.append(
            f"202 101 {major_minor} / {root / 'control'} rw - testfs /dev/test rw"
        )
    return ("\n".join(rows) + "\n").encode("ascii")


def _absence_runtime(
    root: Path,
    *,
    translated_uid: int = absence.PRETRIGGER_ABSENCE_SERVICE_UID,
    alternate_control_mount: bool = False,
    now: str = "2026-07-14T11:00:05Z",
) -> absence.AbsenceRuntime:
    return absence.AbsenceRuntime(
        euid=lambda: absence.PRETRIGGER_ABSENCE_SERVICE_UID,
        identity_for_uid=lambda uid: absence.PRETRIGGER_ABSENCE_SERVICE_IDENTITY,
        mountinfo_bytes=lambda: _mountinfo(
            root, alternate_control=alternate_control_mount
        ),
        now_utc=lambda: now,
        uid_translate=lambda uid: translated_uid,
        physical_root_override=root,
    )


def _local_source_paths() -> dict[str, Path]:
    return {
        binding_id: publisher._module_source_path(binding_id)
        for binding_id in publisher._LOCAL_MODULE_BY_ID
    }


def _fake_git(repo_root: Path) -> Callable[[Path, tuple[str, ...]], bytes]:
    def run(observed_root: Path, arguments: tuple[str, ...]) -> bytes:
        assert observed_root == repo_root
        if arguments == ("rev-parse", "--show-toplevel"):
            return (repo_root.as_posix() + "\n").encode()
        if arguments == ("rev-parse", "HEAD"):
            return (SOURCE_COMMIT + "\n").encode()
        if arguments == ("status", "--porcelain=v1", "--untracked-files=all"):
            return b""
        if arguments[:3] == ("ls-files", "--error-unmatch", "--"):
            return (arguments[3] + "\n").encode()
        if arguments[:2] == ("cat-file", "blob"):
            _, relative = arguments[2].split(":", 1)
            return (repo_root / relative).read_bytes()
        raise AssertionError(f"unexpected git invocation: {arguments}")

    return run


@dataclass
class _Setup:
    root: Path
    repo_root: Path
    source_paths: dict[str, Path]
    evidence_paths: dict[str, Path]


def _setup(tmp_path: Path) -> _Setup:
    root = tmp_path / "structured-root"
    control = root / "control"
    control.mkdir(parents=True)
    root.chmod(0o700)
    control.chmod(0o700)

    source_dir = tmp_path / "upstream-sources"
    source_dir.mkdir()
    source_paths = _local_source_paths()
    for index, binding_id in enumerate(
        (
            "causal_completion_attester",
            "causal_terminal_revalidator",
            "trigger_execution_seal_builder",
        ),
        1,
    ):
        path = source_dir / f"{binding_id}.py"
        path.write_bytes(f"# frozen upstream source {index}\n".encode())
        source_paths[binding_id] = path

    evidence_dir = tmp_path / "causal-evidence"
    evidence_dir.mkdir()
    evidence_paths: dict[str, Path] = {}
    for index, key in enumerate(sorted(publisher._RAW_EVIDENCE_KEYS), 1):
        path = evidence_dir / f"{key}.bin"
        path.write_bytes(f"synthetic-causal-evidence-{index}\n".encode())
        evidence_paths[key] = path
    return _Setup(
        root=root,
        repo_root=Path(publisher.__file__).resolve().parent,
        source_paths=source_paths,
        evidence_paths=evidence_paths,
    )


def _register(
    setup: _Setup,
    *,
    runtime: absence.AbsenceRuntime | None = None,
    git: Callable[[Path, tuple[str, ...]], bytes] | None = None,
) -> bytes:
    absence_runtime = runtime or _absence_runtime(
        setup.root, now="2026-07-14T09:00:00Z"
    )
    publisher._preregister_validator_inventory_for_test(
        root=setup.root,
        repo_root=setup.repo_root,
        source_commit=SOURCE_COMMIT,
        attempt_id=ATTEMPT_ID,
        source_paths=setup.source_paths,
        runtime=publisher.PublisherRuntime(
            now_utc=lambda: "2026-07-14T09:00:00Z",
            git=git or _fake_git(setup.repo_root),
            absence=absence_runtime,
        ),
    )
    raw, _ = atomic.read_and_validate_readonly_artifact(
        root=setup.root,
        relative_path=publisher.INVENTORY_RELATIVE_PATH,
    )
    return raw


def _absence_bytes(setup: _Setup, inventory_raw: bytes) -> bytes:
    return absence.attest_pretrigger_absence(
        root=setup.root,
        structured_durable_root=LOGICAL_ROOT,
        source_commit=SOURCE_COMMIT,
        attempt_id=ATTEMPT_ID,
        trigger_execution_seal_bytes=setup.evidence_paths[
            "trigger_execution_seal_bytes"
        ].read_bytes(),
        trigger_validator_inventory_bytes=inventory_raw,
        runtime=_absence_runtime(setup.root),
    )


@dataclass(frozen=True)
class _FakeRevalidation:
    attempt_id: str
    trigger_branch: str
    trigger_receipt_sha256: str
    model_calls_authorized: bool = False
    operational_authorization: bool = False


def _fake_receipt_builder(call_log: list[dict[str, object]]) -> Callable[..., bytes]:
    def build(**kwargs: object) -> bytes:
        call_log.append(kwargs)
        expected = (
            set(publisher._RAW_EVIDENCE_KEYS)
            | set(publisher._SOURCE_KWARG_BY_ID.values())
            | {
                "trigger_validator_inventory_bytes",
                "pretrigger_absence_evidence_bytes",
                "structured_attempt_id",
                "created_at_utc",
            }
        )
        assert set(kwargs) == expected
        assert len(kwargs) == 23
        payload = {
            "attempt_id": kwargs["structured_attempt_id"],
            "protocol": publisher.TRIGGER_RECEIPT_PROTOCOL,
            "schema_version": 1,
            "status": "validated_non_authorizing",
            "trigger_branch": publisher.TRIGGER_A,
            "trigger_receipt_sha256": "f" * 64,
        }
        return _canonical(payload)

    return build


def _fake_revalidator(
    call_log: list[tuple[bytes, dict[str, object]]], *, fail: bool
) -> Callable[..., _FakeRevalidation]:
    def validate(raw: bytes, **kwargs: object) -> _FakeRevalidation:
        call_log.append((raw, kwargs))
        assert "structured_attempt_id" not in kwargs
        assert "created_at_utc" not in kwargs
        if fail:
            raise ValueError("independent synthetic failure")
        return _FakeRevalidation(
            attempt_id=ATTEMPT_ID,
            trigger_branch=publisher.TRIGGER_A,
            trigger_receipt_sha256="f" * 64,
        )

    return validate


def _publication_runtime(
    setup: _Setup,
    *,
    builder_calls: list[dict[str, object]],
    revalidator_calls: list[tuple[bytes, dict[str, object]]],
    revalidator_fail: bool = False,
) -> publisher.PublisherRuntime:
    return publisher.PublisherRuntime(
        absence=_absence_runtime(setup.root),
        build_receipt=_fake_receipt_builder(builder_calls),
        revalidate_receipt=_fake_revalidator(revalidator_calls, fail=revalidator_fail),
    )


def _artifact_paths(root: Path, relative_path: str) -> tuple[Path, Path, Path]:
    intent, pending = atomic.publication_sidecar_relative_paths(relative_path)
    return root / relative_path, root / intent, root / pending


def test_prospective_inventory_is_complete_fixed_and_nonrecursive() -> None:
    rows = publisher.prospective_publication_inventory()
    assert len(rows) == 9
    assert tuple(path for role, path in rows if role == "final") == (
        publisher.PROSPECTIVE_FINAL_PATHS
    )
    for index in range(0, len(rows), 3):
        assert rows[index][0] == "final"
        assert rows[index + 1][0] == "atomic_publication_intent"
        assert rows[index + 2][0] == "atomic_publication_pending_absent"
        assert "publish-intent-" not in rows[index][1]


def test_mode_a_binds_clean_exact_sources_and_publishes_only_inventory(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    raw = _register(setup)
    value = json.loads(raw)
    assert value["tooling_source_commit"] == SOURCE_COMMIT
    assert tuple(row["binding_id"] for row in value["bindings"]) == (
        publisher.REQUIRED_BINDING_IDS
    )
    assert len(value["bindings"]) == 8

    control_names = {path.name for path in (setup.root / "control").iterdir()}
    inventory_intent, inventory_pending = atomic.publication_sidecar_relative_paths(
        publisher.INVENTORY_RELATIVE_PATH
    )
    assert control_names == {
        Path(publisher.INVENTORY_RELATIVE_PATH).name,
        Path(inventory_intent).name,
    }
    assert not (setup.root / inventory_pending).exists()
    with pytest.raises(publisher.PublisherError):
        _register(setup)


def test_mode_a_wrong_head_or_dirty_checkout_has_no_publication(tmp_path: Path) -> None:
    setup = _setup(tmp_path)

    def wrong_head(repo: Path, arguments: tuple[str, ...]) -> bytes:
        if arguments == ("rev-parse", "--show-toplevel"):
            return (repo.as_posix() + "\n").encode()
        if arguments == ("rev-parse", "HEAD"):
            return ("a" * 40 + "\n").encode()
        return b""

    with pytest.raises(publisher.PublisherError, match="clean at the exact"):
        _register(setup, git=wrong_head)
    assert not _artifact_paths(setup.root, publisher.INVENTORY_RELATIVE_PATH)[
        0
    ].exists()
    assert not _artifact_paths(setup.root, publisher.INVENTORY_RELATIVE_PATH)[
        1
    ].exists()


def test_mode_a_rejects_0755_root_before_any_publication(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    setup.root.chmod(0o755)

    with pytest.raises(publisher.PublisherError, match="failed closed"):
        _register(setup)

    final, intent, pending = _artifact_paths(
        setup.root, publisher.INVENTORY_RELATIVE_PATH
    )
    assert not final.exists()
    assert not intent.exists()
    assert not pending.exists()


def test_public_apis_reject_runtime_injection_and_private_helpers_reject_production_root(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    runtime = publisher.PublisherRuntime(
        now_utc=lambda: "2026-07-14T09:00:00Z",
        git=_fake_git(setup.repo_root),
        absence=_absence_runtime(setup.root, now="2026-07-14T09:00:00Z"),
    )

    with pytest.raises(publisher.PublisherError, match="forbids runtime injection"):
        publisher.preregister_validator_inventory(
            root=setup.root,
            repo_root=setup.repo_root,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            source_paths=setup.source_paths,
            runtime=runtime,
        )
    with pytest.raises(publisher.PublisherError, match="forbids runtime injection"):
        publisher.publish_trigger_a_chain(
            root=setup.root,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            raw_evidence_paths=setup.evidence_paths,
            runtime=runtime,
        )

    production_root = Path(LOGICAL_ROOT)
    with pytest.raises(
        publisher.PublisherError, match="forbidden for a production root"
    ):
        publisher._preregister_validator_inventory_for_test(
            root=production_root,
            repo_root=setup.repo_root,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            source_paths=setup.source_paths,
            runtime=runtime,
        )
    with pytest.raises(
        publisher.PublisherError, match="forbidden for a production root"
    ):
        publisher._publish_trigger_a_chain_for_test(
            root=production_root,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            raw_evidence_paths=setup.evidence_paths,
            runtime=runtime,
        )

    final, intent, pending = _artifact_paths(
        setup.root, publisher.INVENTORY_RELATIVE_PATH
    )
    assert not final.exists()
    assert not intent.exists()
    assert not pending.exists()


def test_absence_adapter_emits_exact_builder_schema_and_full_bindings(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    inventory_raw = _register(setup)
    raw = _absence_bytes(setup, inventory_raw)
    value = json.loads(raw)
    unsigned = dict(value)
    del unsigned["absence_attestation_sha256"]
    inventory = json.loads(inventory_raw)
    adapter_binding = next(
        row
        for row in inventory["bindings"]
        if row["binding_id"] == "pretrigger_absence_adapter"
    )

    assert raw == _canonical(value)
    assert value["absence_attestation_sha256"] == _sha(_canonical(unsigned))
    assert value["service_identity"] == "cohort-structured-trigger-absence-v1"
    assert value["service_uid"] == 41001
    assert value["filesystem_root_identity"]["owner_uid"] == 41001
    assert value["checked_at_utc"] == value["receipt_created_at_utc"]
    assert value["forbidden_classes"] == list(absence.ABSENCE_FORBIDDEN_CLASSES)
    assert value["forbidden_match_count"] == 0
    assert value["forbidden_matches"] == []
    assert value["adapter_source_path"] == adapter_binding["path"]
    assert value["adapter_source_sha256"] == adapter_binding["sha256"]
    assert value["trigger_execution_seal_sha256"] == _sha(
        setup.evidence_paths["trigger_execution_seal_bytes"].read_bytes()
    )
    assert value["filesystem_root_identity"]["mode"] == 0o700
    assert value["filesystem_root_identity"]["mount_id"].startswith("mountinfo-v1:101:")
    assert value["model_calls_authorized"] is False
    assert value["operational_authorization"] is False


@pytest.mark.parametrize("bad_kind", ["uid", "mode", "mount", "unexpected", "pending"])
def test_absence_adapter_rejects_bad_identity_mode_mount_or_tree(
    tmp_path: Path, bad_kind: str
) -> None:
    setup = _setup(tmp_path)
    inventory_raw = _register(setup)
    runtime = _absence_runtime(setup.root)
    if bad_kind == "uid":
        runtime = _absence_runtime(setup.root, translated_uid=41002)
    elif bad_kind == "mode":
        setup.root.chmod(0o755)
    elif bad_kind == "mount":
        runtime = _absence_runtime(setup.root, alternate_control_mount=True)
    elif bad_kind == "unexpected":
        (setup.root / "control" / "unexpected.json").write_bytes(b"unexpected")
    elif bad_kind == "pending":
        _, pending = atomic.publication_sidecar_relative_paths(
            publisher.INVENTORY_RELATIVE_PATH
        )
        pending_path = setup.root / pending
        pending_path.write_bytes(b"poison")
        pending_path.chmod(0o444)

    with pytest.raises((absence.AbsenceAdapterError, RuntimeError, OSError)):
        absence.attest_pretrigger_absence(
            root=setup.root,
            structured_durable_root=LOGICAL_ROOT,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            trigger_execution_seal_bytes=b"seal",
            trigger_validator_inventory_bytes=inventory_raw,
            runtime=runtime,
        )


def test_absence_adapter_rejects_symlink_and_nonregular_inventory(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    inventory_raw = _register(setup)
    final, _, _ = _artifact_paths(setup.root, publisher.INVENTORY_RELATIVE_PATH)
    final.unlink()
    final.symlink_to(setup.source_paths["causal_completion_attester"])
    with pytest.raises((absence.AbsenceAdapterError, RuntimeError, OSError)):
        absence.attest_pretrigger_absence(
            root=setup.root,
            structured_durable_root=LOGICAL_ROOT,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            trigger_execution_seal_bytes=b"seal",
            trigger_validator_inventory_bytes=inventory_raw,
            runtime=_absence_runtime(setup.root),
        )


def test_mount_lookup_rejects_stacked_same_mountpoint_records(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    metadata = setup.root.stat()
    major_minor = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    mountpoint = setup.root.as_posix()
    records = absence._parse_mountinfo(
        (
            f"101 1 {major_minor} / {mountpoint} rw - testfs /dev/base rw\n"
            f"202 1 {major_minor} / {mountpoint} rw - testfs /dev/stacked rw\n"
        ).encode("ascii")
    )

    with pytest.raises(absence.AbsenceAdapterError, match="non-unique longest"):
        absence._mount_for(setup.root, records)


def test_source_drift_fails_before_absence_or_receipt_publication(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    _register(setup)
    drifted = setup.source_paths["causal_completion_attester"]
    drifted.write_bytes(drifted.read_bytes() + b"# drift\n")
    with pytest.raises(publisher.PublisherError, match="source bytes drifted"):
        publisher._publish_trigger_a_chain_for_test(
            root=setup.root,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            raw_evidence_paths=setup.evidence_paths,
            runtime=_publication_runtime(
                setup,
                builder_calls=[],
                revalidator_calls=[],
            ),
        )
    for relative_path in (
        publisher.ABSENCE_RELATIVE_PATH,
        publisher.RECEIPT_RELATIVE_PATH,
    ):
        final, intent, pending = _artifact_paths(setup.root, relative_path)
        assert not final.exists()
        assert not intent.exists()
        assert not pending.exists()


def test_raw_evidence_drift_after_revalidation_never_reserves_receipt(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    _register(setup)
    builder_calls: list[dict[str, object]] = []
    revalidator_calls: list[tuple[bytes, dict[str, object]]] = []
    target = setup.evidence_paths["causal_exit_file_bytes"]

    def mutate_after_revalidation(raw: bytes, **kwargs: object) -> _FakeRevalidation:
        revalidator_calls.append((raw, kwargs))
        target.write_bytes(b"mutated-after-independent-revalidation\n")
        return _FakeRevalidation(
            attempt_id=ATTEMPT_ID,
            trigger_branch=publisher.TRIGGER_A,
            trigger_receipt_sha256="f" * 64,
        )

    runtime = publisher.PublisherRuntime(
        absence=_absence_runtime(setup.root),
        build_receipt=_fake_receipt_builder(builder_calls),
        revalidate_receipt=mutate_after_revalidation,
    )
    with pytest.raises(publisher.PublisherError, match="raw causal evidence changed"):
        publisher._publish_trigger_a_chain_for_test(
            root=setup.root,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            raw_evidence_paths=setup.evidence_paths,
            runtime=runtime,
        )
    assert len(builder_calls) == 1
    assert len(revalidator_calls) == 1
    atomic.read_and_validate_readonly_artifact(
        root=setup.root,
        relative_path=publisher.ABSENCE_RELATIVE_PATH,
    )
    receipt_final, receipt_intent, receipt_pending = _artifact_paths(
        setup.root, publisher.RECEIPT_RELATIVE_PATH
    )
    assert not receipt_final.exists()
    assert not receipt_intent.exists()
    assert not receipt_pending.exists()


def test_revalidator_failure_leaves_absence_poison_and_never_receipt(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    _register(setup)
    builder_calls: list[dict[str, object]] = []
    revalidator_calls: list[tuple[bytes, dict[str, object]]] = []
    runtime = _publication_runtime(
        setup,
        builder_calls=builder_calls,
        revalidator_calls=revalidator_calls,
        revalidator_fail=True,
    )
    with pytest.raises(publisher.PublisherError):
        publisher._publish_trigger_a_chain_for_test(
            root=setup.root,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            raw_evidence_paths=setup.evidence_paths,
            runtime=runtime,
        )
    assert len(builder_calls) == 1
    assert len(revalidator_calls) == 1
    atomic.read_and_validate_readonly_artifact(
        root=setup.root,
        relative_path=publisher.ABSENCE_RELATIVE_PATH,
    )
    receipt_final, receipt_intent, receipt_pending = _artifact_paths(
        setup.root, publisher.RECEIPT_RELATIVE_PATH
    )
    assert not receipt_final.exists()
    assert not receipt_intent.exists()
    assert not receipt_pending.exists()

    # The durable absence is a poison marker.  A second invocation fails at
    # the pre-absence exact-tree walk and still cannot reserve a receipt.
    with pytest.raises(publisher.PublisherError):
        publisher._publish_trigger_a_chain_for_test(
            root=setup.root,
            source_commit=SOURCE_COMMIT,
            attempt_id=ATTEMPT_ID,
            raw_evidence_paths=setup.evidence_paths,
            runtime=runtime,
        )
    assert len(builder_calls) == 1
    assert len(revalidator_calls) == 1
    assert not receipt_final.exists()
    assert not receipt_intent.exists()
    assert not receipt_pending.exists()


def test_successful_chain_publishes_receipt_only_after_separate_revalidation(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    _register(setup)
    builder_calls: list[dict[str, object]] = []
    revalidator_calls: list[tuple[bytes, dict[str, object]]] = []
    observation = publisher._publish_trigger_a_chain_for_test(
        root=setup.root,
        source_commit=SOURCE_COMMIT,
        attempt_id=ATTEMPT_ID,
        raw_evidence_paths=setup.evidence_paths,
        runtime=_publication_runtime(
            setup,
            builder_calls=builder_calls,
            revalidator_calls=revalidator_calls,
        ),
    )
    assert observation.relative_path == publisher.RECEIPT_RELATIVE_PATH
    assert len(builder_calls) == 1
    assert len(revalidator_calls) == 1
    receipt_raw, receipt_observation = atomic.read_and_validate_readonly_artifact(
        root=setup.root,
        relative_path=publisher.RECEIPT_RELATIVE_PATH,
    )
    assert receipt_observation.mode == 0o444
    assert json.loads(receipt_raw)["status"] == "validated_non_authorizing"
    _, absence_observation = atomic.read_and_validate_readonly_artifact(
        root=setup.root,
        relative_path=publisher.ABSENCE_RELATIVE_PATH,
    )
    assert absence_observation.mode == 0o444


def test_publisher_imports_no_model_scorer_or_scientific_runtime() -> None:
    source = Path(publisher.__file__).read_text()
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    forbidden_fragments = {
        "torch",
        "transformers",
        "model",
        "scorer",
        "cohort_closed_loop_structured_state",
        "cohort_env",
    }
    assert not any(
        fragment in imported_name
        for imported_name in imported
        for fragment in forbidden_fragments
    )
