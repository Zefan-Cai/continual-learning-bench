from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import cohort_closed_loop_structured_atomic_publish as publication


def _root(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "durable"
    (root / "control").mkdir(parents=True)
    return root


def test_publish_is_o_excl_readonly_single_link_and_freshly_revalidated(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    payload = b'{"protocol":"test","schema_version":1}'
    observed = publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/seal.json", payload=payload
    )

    target = root / "control/seal.json"
    metadata = os.lstat(target)
    assert target.read_bytes() == payload
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o444
    assert metadata.st_nlink == 1
    assert observed.path == target.as_posix()
    assert observed.relative_path == "control/seal.json"
    assert Path(observed.publication_intent_path).is_file()
    assert observed.size_bytes == len(payload)
    assert observed.sha256 == hashlib.sha256(payload).hexdigest()
    assert observed.device == metadata.st_dev
    assert observed.inode == metadata.st_ino
    assert observed.mode == 0o444
    assert observed.link_count == 1

    reread, reread_observation = publication.read_and_validate_readonly_artifact(
        root=root,
        relative_path="control/seal.json",
        expected_payload=payload,
    )
    assert reread == payload
    assert reread_observation == observed


def test_sidecar_paths_are_deterministic_closed_inventory_entries(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    relative_path = "receipts/block/adaptation/1/structured/active/h0+.json"
    intent_path, pending_path = publication.publication_sidecar_relative_paths(
        relative_path
    )
    assert intent_path.startswith(
        "receipts/block/adaptation/1/structured/active/publish-intent-"
    )
    assert intent_path.endswith(".json")
    assert pending_path.startswith(
        "receipts/block/adaptation/1/structured/active/publish-pending-"
    )
    assert pending_path.endswith(".bin")
    assert publication.publication_sidecar_relative_paths(relative_path) == (
        intent_path,
        pending_path,
    )

    (root / relative_path).parent.mkdir(parents=True)
    observed = publication.publish_readonly_no_overwrite(
        root=root,
        relative_path=relative_path,
        payload=b"candidate-receipt",
    )
    assert Path(observed.publication_intent_path) == root / intent_path
    assert (root / relative_path).is_file()
    assert not (root / pending_path).exists()


def test_refuses_overwrite_and_preserves_original_bytes(tmp_path: Path) -> None:
    root = _root(tmp_path)
    publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/seal.json", payload=b"first"
    )
    with pytest.raises(FileExistsError, match="refusing to (overwrite|reuse)"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/seal.json", payload=b"second"
        )
    assert (root / "control/seal.json").read_bytes() == b"first"


def test_concurrent_publish_has_exactly_one_winner(tmp_path: Path) -> None:
    root = _root(tmp_path)

    def publish(payload: bytes) -> str:
        try:
            publication.publish_readonly_no_overwrite(
                root=root, relative_path="control/race.json", payload=payload
            )
            return "published"
        except FileExistsError:
            return "exists"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(publish, (b"left", b"right")))
    assert sorted(outcomes) == ["exists", "published"]
    assert (root / "control/race.json").read_bytes() in {b"left", b"right"}


@pytest.mark.parametrize(
    "relative_path",
    (
        "",
        "/absolute.json",
        "../escape.json",
        "control/../escape.json",
        "control//double.json",
        "control/space name.json",
        "control/$shell.json",
    ),
)
def test_rejects_unsafe_relative_paths(tmp_path: Path, relative_path: str) -> None:
    root = _root(tmp_path)
    with pytest.raises(publication.AtomicPublicationError):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path=relative_path, payload=b"payload"
        )


def test_rejects_noncanonical_root_and_nonbytes_or_empty_payload(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    with pytest.raises(publication.AtomicPublicationError, match="normalized"):
        publication.publish_readonly_no_overwrite(
            root=root / ".." / "durable",
            relative_path="control/a.json",
            payload=b"payload",
        )
    with pytest.raises(publication.AtomicPublicationError, match="exact bytes"):
        publication.publish_readonly_no_overwrite(  # type: ignore[arg-type]
            root=root, relative_path="control/a.json", payload=bytearray(b"payload")
        )
    with pytest.raises(publication.AtomicPublicationError, match="nonempty"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/a.json", payload=b""
        )


def test_symlink_parent_and_final_symlink_fail_closed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises((publication.AtomicPublicationError, OSError)):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="linked/escape.json", payload=b"payload"
        )
    assert not (outside / "escape.json").exists()

    (root / "control/symlink.json").symlink_to(outside / "target.json")
    with pytest.raises(FileExistsError):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/symlink.json", payload=b"payload"
        )
    assert not (outside / "target.json").exists()


def test_root_symlink_is_rejected(tmp_path: Path) -> None:
    real_root = _root(tmp_path)
    linked_root = tmp_path.resolve() / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises((publication.AtomicPublicationError, OSError)):
        publication.publish_readonly_no_overwrite(
            root=linked_root,
            relative_path="control/a.json",
            payload=b"payload",
        )


def test_hardlink_and_mutable_mode_are_rejected_on_fresh_read(tmp_path: Path) -> None:
    root = _root(tmp_path)
    publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/a.json", payload=b"payload"
    )
    target = root / "control/a.json"
    os.link(target, root / "control/a-hardlink.json")
    with pytest.raises(publication.AtomicPublicationError, match="link count"):
        publication.read_and_validate_readonly_artifact(
            root=root, relative_path="control/a.json"
        )
    os.unlink(root / "control/a-hardlink.json")
    target.chmod(0o644)
    with pytest.raises(publication.AtomicPublicationError, match="mode"):
        publication.read_and_validate_readonly_artifact(
            root=root, relative_path="control/a.json"
        )


def test_expected_bytes_mismatch_is_rejected(tmp_path: Path) -> None:
    root = _root(tmp_path)
    publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/a.json", payload=b"payload"
    )
    with pytest.raises(publication.AtomicPublicationError, match="expected payload"):
        publication.read_and_validate_readonly_artifact(
            root=root,
            relative_path="control/a.json",
            expected_payload=b"PAYLOAD",
        )


@pytest.mark.parametrize("confused_version", (True, 1.0))
def test_publication_intent_rejects_schema_version_type_confusion(
    tmp_path: Path, confused_version: object
) -> None:
    root = _root(tmp_path)
    observed = publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/a.json", payload=b"payload"
    )
    intent_path = Path(observed.publication_intent_path)
    intent = json.loads(intent_path.read_bytes())
    intent["schema_version"] = confused_version
    confused = json.dumps(
        intent,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    intent_path.chmod(0o644)
    intent_path.write_bytes(confused)
    intent_path.chmod(0o444)

    with pytest.raises(publication.AtomicPublicationError, match="protocol differs"):
        publication.read_and_validate_readonly_artifact(
            root=root, relative_path="control/a.json"
        )


def test_publication_intent_rejects_unregistered_pending_name(tmp_path: Path) -> None:
    root = _root(tmp_path)
    observed = publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/a.json", payload=b"payload"
    )
    intent_path = Path(observed.publication_intent_path)
    intent = json.loads(intent_path.read_bytes())
    intent["pending_name"] = "other-undeclared.bin"
    tampered = json.dumps(
        intent,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    intent_path.chmod(0o644)
    intent_path.write_bytes(tampered)
    intent_path.chmod(0o444)

    with pytest.raises(publication.AtomicPublicationError, match="registered path"):
        publication.read_and_validate_readonly_artifact(
            root=root, relative_path="control/a.json", expected_payload=b"payload"
        )


def test_same_size_tamper_is_rejected_against_supplied_bytes(tmp_path: Path) -> None:
    root = _root(tmp_path)
    target = root / "control/a.json"
    publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/a.json", payload=b"payload"
    )
    target.chmod(0o644)
    target.write_bytes(b"PAYLOAD")
    target.chmod(0o444)
    with pytest.raises(publication.AtomicPublicationError, match="digest differs"):
        publication.read_and_validate_readonly_artifact(
            root=root,
            relative_path="control/a.json",
            expected_payload=b"payload",
        )


def test_partial_write_error_leaves_poison_and_forbids_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    original = publication._write_all
    calls = 0

    def partial_then_fail(descriptor: int, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            original(descriptor, payload)
        else:
            os.write(descriptor, payload[:2])
            raise OSError("injected write failure")

    monkeypatch.setattr(publication, "_write_all", partial_then_fail)
    with pytest.raises(publication.AtomicPublicationError, match="before commit"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/poison.json", payload=b"payload"
        )
    assert not (root / "control/poison.json").exists()
    poison_files = tuple((root / "control").iterdir())
    assert any(path.name.startswith("publish-intent-") for path in poison_files)
    assert any(path.name.startswith("publish-pending-") for path in poison_files)
    with pytest.raises(FileExistsError):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/poison.json", payload=b"payload"
        )


def test_read_retraversal_rejects_parent_swap_during_first_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/a.json", payload=b"good"
    )
    original = publication._read_all
    calls = 0

    def read_then_swap(descriptor: int) -> bytes:
        nonlocal calls
        calls += 1
        payload = original(descriptor)
        if calls == 2:
            (root / "control").rename(root / "moved-control")
            (root / "control").mkdir()
            (root / "control/a.json").write_bytes(b"evil")
        return payload

    monkeypatch.setattr(publication, "_read_all", read_then_swap)
    with pytest.raises(publication.AtomicPublicationError):
        publication.read_and_validate_readonly_artifact(
            root=root,
            relative_path="control/a.json",
            expected_payload=b"good",
        )
    assert (root / "control/a.json").read_bytes() == b"evil"
    assert (root / "moved-control/a.json").read_bytes() == b"good"


def test_publish_rejects_parent_swap_before_commit_and_leaves_two_link_poison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    original = publication._verify_linked_candidate

    def swap_then_verify(**kwargs: object) -> None:
        (root / "control").rename(root / "moved-control")
        (root / "control").mkdir()
        original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(publication, "_verify_linked_candidate", swap_then_verify)
    with pytest.raises(publication.AtomicPublicationError, match="ancestor chain"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/a.json", payload=b"good"
        )
    moved = root / "moved-control"
    final = moved / "a.json"
    pending = next(
        path for path in moved.iterdir() if path.name.startswith("publish-pending-")
    )
    assert final.read_bytes() == b"good"
    assert pending.read_bytes() == b"good"
    assert os.lstat(final).st_nlink == 2
    assert os.lstat(pending).st_ino == os.lstat(final).st_ino
    assert not (root / "control/a.json").exists()


def test_publish_rejects_parent_swap_after_link_verification_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    original = publication._verify_linked_candidate

    def verify_then_swap(**kwargs: object) -> None:
        original(**kwargs)  # type: ignore[arg-type]
        (root / "control").rename(root / "moved-control")
        (root / "control").mkdir()
        (root / "control/a.json").write_bytes(b"evil")

    monkeypatch.setattr(publication, "_verify_linked_candidate", verify_then_swap)
    with pytest.raises(publication.AtomicPublicationError, match="after commit"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/a.json", payload=b"good"
        )
    assert (root / "control/a.json").read_bytes() == b"evil"
    assert (root / "moved-control/a.json").read_bytes() == b"good"
    assert os.lstat(root / "moved-control/a.json").st_nlink == 1


def test_failed_parent_traversal_does_not_leak_file_descriptors(tmp_path: Path) -> None:
    root = _root(tmp_path)
    before = len(tuple(Path("/dev/fd").iterdir()))
    for _ in range(25):
        with pytest.raises(publication.AtomicPublicationError):
            publication.publish_readonly_no_overwrite(
                root=root,
                relative_path="missing/parent/a.json",
                payload=b"payload",
            )
    after = len(tuple(Path("/dev/fd").iterdir()))
    assert after == before


def test_unsafe_parent_does_not_leak_file_descriptors(tmp_path: Path) -> None:
    root = _root(tmp_path)
    unsafe = root / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    before = len(tuple(Path("/dev/fd").iterdir()))
    for _ in range(10):
        with pytest.raises(publication.AtomicPublicationError, match="group/other"):
            publication.publish_readonly_no_overwrite(
                root=root,
                relative_path="unsafe/a.json",
                payload=b"payload",
            )
    after = len(tuple(Path("/dev/fd").iterdir()))
    assert after == before


def test_parent_fsync_failure_leaves_final_as_two_link_poison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    original = os.fsync
    directory_calls = 0

    def fail_third_directory_fsync(descriptor: int) -> None:
        nonlocal directory_calls
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_calls += 1
            if directory_calls == 3:
                raise OSError("injected parent fsync failure")
        original(descriptor)

    monkeypatch.setattr(publication.os, "fsync", fail_third_directory_fsync)
    with pytest.raises(publication.AtomicPublicationError, match="before commit"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/a.json", payload=b"payload"
        )
    final = root / "control/a.json"
    pending = next(
        path
        for path in (root / "control").iterdir()
        if path.name.startswith("publish-pending-")
    )
    assert final.exists() and pending.exists()
    assert os.lstat(final).st_nlink == 2
    with pytest.raises(publication.AtomicPublicationError, match="pending file"):
        publication.read_and_validate_readonly_artifact(
            root=root, relative_path="control/a.json", expected_payload=b"payload"
        )


def test_post_commit_parent_fsync_failure_is_classified_and_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    original = os.fsync
    directory_calls = 0

    def fail_fourth_directory_fsync(descriptor: int) -> None:
        nonlocal directory_calls
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_calls += 1
            if directory_calls == 4:
                raise OSError("injected post-commit parent fsync failure")
        original(descriptor)

    monkeypatch.setattr(publication.os, "fsync", fail_fourth_directory_fsync)
    with pytest.raises(publication.AtomicPublicationError, match="after commit"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/fsync-after.json", payload=b"payload"
        )
    final = root / "control/fsync-after.json"
    assert final.read_bytes() == b"payload"
    assert os.lstat(final).st_nlink == 1
    assert not any(
        path.name.startswith("publish-pending-")
        for path in (root / "control").iterdir()
    )
    with pytest.raises(FileExistsError, match="reuse publication intent"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/fsync-after.json", payload=b"payload"
        )


def test_pending_file_fsync_and_chmod_fail_before_final_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    original_fsync = os.fsync
    file_calls = 0

    def fail_third_file_fsync(descriptor: int) -> None:
        nonlocal file_calls
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            file_calls += 1
            if file_calls == 3:
                raise OSError("injected pending fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(publication.os, "fsync", fail_third_file_fsync)
    with pytest.raises(publication.AtomicPublicationError, match="before commit"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/fsync.json", payload=b"payload"
        )
    assert not (root / "control/fsync.json").exists()

    monkeypatch.setattr(publication.os, "fsync", original_fsync)
    original_chmod = os.fchmod
    chmod_calls = 0

    def fail_second_chmod(descriptor: int, mode: int) -> None:
        nonlocal chmod_calls
        chmod_calls += 1
        if chmod_calls == 2:
            raise OSError("injected pending chmod failure")
        original_chmod(descriptor, mode)

    monkeypatch.setattr(publication.os, "fchmod", fail_second_chmod)
    with pytest.raises(publication.AtomicPublicationError, match="before commit"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/chmod.json", payload=b"payload"
        )
    assert not (root / "control/chmod.json").exists()


def test_fresh_candidate_verification_failure_stays_uncommitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)

    def fail_verification(**_: object) -> None:
        raise publication.AtomicPublicationError("injected fresh verification failure")

    monkeypatch.setattr(publication, "_verify_linked_candidate", fail_verification)
    with pytest.raises(publication.AtomicPublicationError, match="fresh verification"):
        publication.publish_readonly_no_overwrite(
            root=root, relative_path="control/a.json", payload=b"payload"
        )
    final = root / "control/a.json"
    assert final.exists()
    assert os.lstat(final).st_nlink == 2


def test_observation_is_not_mapping_or_bytes_authority(tmp_path: Path) -> None:
    root = _root(tmp_path)
    observed = publication.publish_readonly_no_overwrite(
        root=root, relative_path="control/a.json", payload=b"payload"
    )
    assert not isinstance(observed, dict)
    assert not isinstance(observed, bytes)


def test_module_has_no_scientific_or_process_authorization_surface() -> None:
    source_path = Path(publication.__file__ or "")
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imports.add(node.module)
    assert (
        not {
            "torch",
            "transformers",
            "subprocess",
            "cohort_closed_loop_structured_state",
            "cohort_closed_loop_structured_commitments",
            "cohort_closed_loop_structured_execution_validation",
            "cohort_closed_loop_structured_dgp_context",
        }
        & imports
    )
    assert "model_calls_authorized" not in source
    assert "launch_authorized" not in source
    assert "scorer_reexecution_performed" not in source
