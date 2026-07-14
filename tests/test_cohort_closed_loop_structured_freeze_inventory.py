from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

import pytest

import cohort_closed_loop_structured_freeze_inventory as inventory


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _reseal(value: dict[str, Any]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("freeze_inventory_sha256", None)
    value["freeze_inventory_sha256"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
    return _canonical(value)


@dataclass(frozen=True)
class GitFixture:
    root: Path
    head: str
    documents: tuple[dict[str, object], ...]
    sources: tuple[dict[str, object], ...]
    tests: tuple[dict[str, object], ...]
    joins: tuple[dict[str, object], ...]
    providers: tuple[dict[str, object], ...]
    blockers: tuple[dict[str, object], ...]

    def kwargs(
        self, *, callback: Callable[[], None] = lambda: None
    ) -> dict[str, object]:
        return {
            "git_root": self.root,
            "source_commit": self.head,
            "structured_tip_commit": self.head,
            "documents": self.documents,
            "sources": self.sources,
            "tests": self.tests,
            "joins": self.joins,
            "providers": self.providers,
            "blockers": self.blockers,
            "runtime": inventory._FreezeInventoryTestRuntime(  # noqa: SLF001
                before_final_revalidation=callback
            ),
        }


def _make_repo(root: Path) -> GitFixture:
    root.mkdir(parents=True)
    files = {
        "docs/structured_contract.md": b"structured contract\n",
        "cohort_closed_loop_structured_context_registrar.py": (
            b"PROVIDER_AVAILABLE = False\n"
        ),
        "cohort_closed_loop_structured_freeze_inventory.py": (
            b"PROVIDER_AVAILABLE = False\n"
        ),
        "tests/test_freeze_inventory.py": b"def test_placeholder():\n    pass\n",
    }
    for relative, raw in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Freeze Inventory Test")
    _git(root, "config", "user.email", "freeze-inventory@example.invalid")
    _git(root, "add", "--all")
    _git(root, "commit", "-q", "-m", "freeze fixture")
    head = _git(root, "rev-parse", "HEAD")
    documents = (
        {
            "role": "structured_contract",
            "path": "docs/structured_contract.md",
            "required_before_semantic_open": True,
        },
    )
    sources = (
        {
            "role": "context_registrar",
            "path": "cohort_closed_loop_structured_context_registrar.py",
            "required_before_semantic_open": True,
        },
        {
            "role": "freeze_inventory_validator",
            "path": "cohort_closed_loop_structured_freeze_inventory.py",
            "required_before_semantic_open": True,
        },
    )
    tests = (
        {
            "role": "freeze_inventory_tests",
            "path": "tests/test_freeze_inventory.py",
            "required_before_semantic_open": True,
        },
    )
    joins = (
        {
            "join_id": "registrar_source_join",
            "from_role": "structured_contract",
            "to_role": "context_registrar",
            "validator_role": "freeze_inventory_validator",
            "bound_fields": ["git_blob_sha1", "path", "sha256", "size_bytes"],
            "test_roles": ["freeze_inventory_tests"],
            "status": "committed",
        },
    )
    providers = (
        {
            "provider_id": "production_freeze_inventory_provider",
            "status": "unavailable",
            "implementation_role": None,
            "receipt_protocol": inventory.PROTOCOL,
            "acceptance_test_roles": ["freeze_inventory_tests"],
        },
    )
    blockers = (
        {
            "blocker_id": "production_provider_missing",
            "priority": "P0",
            "reason": "production capture provider remains unavailable",
            "unblocks": ["semantic_open"],
            "acceptance_checks": ["independent_capture", "pinned_clean_head"],
        },
    )
    return GitFixture(
        root=root,
        head=head,
        documents=documents,
        sources=sources,
        tests=tests,
        joins=joins,
        providers=providers,
        blockers=blockers,
    )


def _build(
    fixture: GitFixture, *, callback: Callable[[], None] = lambda: None
) -> bytes:
    return inventory._build_freeze_inventory_for_test(  # noqa: SLF001
        **fixture.kwargs(callback=callback)
    )


def test_public_production_surfaces_are_hard_disabled_before_access(
    tmp_path: Path,
) -> None:
    assert inventory.PROVIDER_AVAILABLE is False
    missing = tmp_path / "must-not-be-opened"
    with pytest.raises(inventory.FreezeInventoryError, match="provider is unavailable"):
        inventory.build_freeze_inventory(
            git_root=missing,
            source_commit="0" * 40,
            structured_tip_commit="1" * 40,
        )
    with pytest.raises(inventory.FreezeInventoryError, match="non-authorizing"):
        inventory.authorize_semantic_open(inventory_bytes=b"not-json")


def test_canonical_roundtrip_has_exact_sections_and_required_registrar(
    tmp_path: Path,
) -> None:
    fixture = _make_repo(tmp_path / "repo")
    raw = _build(fixture)
    assert raw == _canonical(json.loads(raw))
    value = json.loads(raw)
    assert set(value) == inventory._TOP_LEVEL_KEYS  # noqa: SLF001
    assert value["source_commit"] == value["structured_tip_commit"] == fixture.head
    assert value["semantic_open_authorized"] is False
    assert value["model_calls_authorized"] is False
    assert value["scorer_calls_authorized"] is False
    assert set(value["sources"][0]) == inventory._FILE_ROW_KEYS  # noqa: SLF001
    registrar = next(
        row for row in value["sources"] if row["role"] == "context_registrar"
    )
    assert registrar["tracked"] is True
    assert registrar["required_before_semantic_open"] is True
    expected_raw = (fixture.root / registrar["path"]).read_bytes()
    assert registrar["sha256"] == hashlib.sha256(expected_raw).hexdigest()
    assert registrar["size_bytes"] == len(expected_raw)
    validation = inventory.validate_freeze_inventory_bytes(raw)
    assert validation.source_commit == fixture.head
    assert validation.source_count == 2
    assert validation.semantic_open_authorized is False


def test_validator_rejects_duplicate_keys_nan_and_noncanonical_ascii(
    tmp_path: Path,
) -> None:
    fixture = _make_repo(tmp_path / "repo")
    raw = _build(fixture)
    duplicate = raw.replace(
        b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1
    )
    with pytest.raises(inventory.FreezeInventoryError, match="duplicate JSON key"):
        inventory.validate_freeze_inventory_bytes(duplicate)
    with pytest.raises(inventory.FreezeInventoryError, match="non-finite"):
        inventory.validate_freeze_inventory_bytes(b'{"value":NaN}')
    with pytest.raises(inventory.FreezeInventoryError, match="canonical ASCII"):
        inventory.validate_freeze_inventory_bytes(b" " + raw)
    type_confused = json.loads(raw)
    type_confused["schema_version"] = True
    with pytest.raises(inventory.FreezeInventoryError, match="header differs"):
        inventory.validate_freeze_inventory_bytes(_reseal(type_confused))


def test_dirty_and_untracked_worktrees_fail_before_inventory(
    tmp_path: Path,
) -> None:
    dirty = _make_repo(tmp_path / "dirty")
    (dirty.root / dirty.sources[0]["path"]).write_bytes(b"dirty\n")
    with pytest.raises(inventory.FreezeInventoryError, match="dirty or has untracked"):
        _build(dirty)

    untracked = _make_repo(tmp_path / "untracked")
    (untracked.root / "untracked.py").write_bytes(b"untracked\n")
    with pytest.raises(inventory.FreezeInventoryError, match="dirty or has untracked"):
        _build(untracked)


def test_clean_tracked_symlink_source_is_rejected(tmp_path: Path) -> None:
    fixture = _make_repo(tmp_path / "repo")
    registrar = fixture.root / "cohort_closed_loop_structured_context_registrar.py"
    registrar.unlink()
    registrar.symlink_to("cohort_closed_loop_structured_freeze_inventory.py")
    _git(fixture.root, "add", "--all")
    _git(fixture.root, "commit", "-q", "-m", "tracked symlink")
    changed = replace(fixture, head=_git(fixture.root, "rev-parse", "HEAD"))
    with pytest.raises(
        inventory.FreezeInventoryError, match="regular tracked Git blob"
    ):
        _build(changed)


def test_external_hardlink_rejects_required_source_nlink(tmp_path: Path) -> None:
    fixture = _make_repo(tmp_path / "repo")
    registrar = fixture.root / "cohort_closed_loop_structured_context_registrar.py"
    os.link(registrar, tmp_path / "external-hardlink.py")
    assert not _git(fixture.root, "status", "--porcelain=v1", "--untracked-files=all")
    with pytest.raises(inventory.FreezeInventoryError, match="link count"):
        _build(fixture)


def test_same_byte_replacement_is_detected_by_second_capture(tmp_path: Path) -> None:
    fixture = _make_repo(tmp_path / "repo")
    registrar = fixture.root / "cohort_closed_loop_structured_context_registrar.py"
    original = registrar.read_bytes()
    moved = tmp_path / "retained-original.py"

    def replace_same_bytes() -> None:
        registrar.rename(moved)
        registrar.write_bytes(original)

    with pytest.raises(inventory.FreezeInventoryError, match="identity changed"):
        _build(fixture, callback=replace_same_bytes)
    assert not _git(fixture.root, "status", "--porcelain=v1", "--untracked-files=all")


def test_non_file_rows_are_snapshotted_before_mutation_callback(tmp_path: Path) -> None:
    fixture = _make_repo(tmp_path / "repo")
    original_reason = fixture.blockers[0]["reason"]

    def mutate_caller_mapping() -> None:
        fixture.blockers[0]["reason"] = "late caller mutation"

    value = json.loads(_build(fixture, callback=mutate_caller_mapping))
    assert value["blockers"][0]["reason"] == original_reason


def test_forged_authority_and_stale_self_digest_fail_closed(tmp_path: Path) -> None:
    fixture = _make_repo(tmp_path / "repo")
    raw = _build(fixture)
    authority = json.loads(raw)
    authority["semantic_open_authorized"] = True
    with pytest.raises(inventory.FreezeInventoryError, match="exactly false"):
        inventory.validate_freeze_inventory_bytes(_reseal(authority))

    stale = json.loads(raw)
    stale["sources"][0]["sha256"] = "0" * 64
    with pytest.raises(inventory.FreezeInventoryError, match="self-digest"):
        inventory.validate_freeze_inventory_bytes(_canonical(stale))


def test_missing_registrar_fails_in_builder_and_pure_validator(tmp_path: Path) -> None:
    fixture = _make_repo(tmp_path / "repo")
    missing = replace(
        fixture,
        sources=tuple(
            row for row in fixture.sources if row["role"] != "context_registrar"
        ),
    )
    with pytest.raises(
        inventory.FreezeInventoryError, match="registrar source is missing"
    ):
        _build(missing)

    value = json.loads(_build(fixture))
    value["sources"] = [
        row for row in value["sources"] if row["role"] != "context_registrar"
    ]
    with pytest.raises(
        inventory.FreezeInventoryError, match="registrar source is missing"
    ):
        inventory.validate_freeze_inventory_bytes(_reseal(value))


@pytest.mark.parametrize("duplicate_kind", ["role", "path"])
def test_duplicate_file_role_or_path_is_rejected_before_capture(
    tmp_path: Path, duplicate_kind: str
) -> None:
    fixture = _make_repo(tmp_path / "repo")
    extra = dict(fixture.sources[1])
    if duplicate_kind == "role":
        extra["path"] = fixture.documents[0]["path"]
        changed = replace(fixture, documents=fixture.documents + (extra,))
        expected = "roles"
    else:
        extra["role"] = "second_freeze_validator"
        changed = replace(fixture, sources=fixture.sources + (extra,))
        expected = "paths"
    with pytest.raises(inventory.FreezeInventoryError, match=expected):
        _build(changed)


def test_source_commit_and_structured_tip_must_match_real_git_commits(
    tmp_path: Path,
) -> None:
    fixture = _make_repo(tmp_path / "repo")
    wrong_head = fixture.kwargs()
    wrong_head["source_commit"] = "0" * 40
    with pytest.raises(inventory.FreezeInventoryError, match="pinned HEAD differs"):
        inventory._build_freeze_inventory_for_test(**wrong_head)  # noqa: SLF001

    wrong_tip = fixture.kwargs()
    wrong_tip["structured_tip_commit"] = "1" * 40
    with pytest.raises(inventory.FreezeInventoryError, match="committed Git object"):
        inventory._build_freeze_inventory_for_test(**wrong_tip)  # noqa: SLF001


def test_nested_true_authority_is_rejected_even_with_fresh_self_hash(
    tmp_path: Path,
) -> None:
    fixture = _make_repo(tmp_path / "repo")
    value = json.loads(_build(fixture))
    value["blockers"][0]["semantic_open_authorized"] = True
    with pytest.raises(inventory.FreezeInventoryError, match="authority field is true"):
        inventory.validate_freeze_inventory_bytes(_reseal(value))


def test_resealed_document_cannot_claim_validator_source_role(tmp_path: Path) -> None:
    fixture = _make_repo(tmp_path / "repo")
    value = json.loads(_build(fixture))
    value["joins"][0]["validator_role"] = "structured_contract"
    with pytest.raises(inventory.FreezeInventoryError, match="not a source role"):
        inventory.validate_freeze_inventory_bytes(_reseal(value))


def test_resealed_source_cannot_claim_join_test_role(tmp_path: Path) -> None:
    fixture = _make_repo(tmp_path / "repo")
    value = json.loads(_build(fixture))
    value["joins"][0]["test_roles"] = ["context_registrar"]
    with pytest.raises(
        inventory.FreezeInventoryError, match="test role is not in tests"
    ):
        inventory.validate_freeze_inventory_bytes(_reseal(value))


def test_resealed_source_cannot_claim_provider_acceptance_test_role(
    tmp_path: Path,
) -> None:
    fixture = _make_repo(tmp_path / "repo")
    value = json.loads(_build(fixture))
    value["providers"][0]["acceptance_test_roles"] = ["context_registrar"]
    with pytest.raises(
        inventory.FreezeInventoryError, match="acceptance test role is not in tests"
    ):
        inventory.validate_freeze_inventory_bytes(_reseal(value))


def test_resealed_document_cannot_claim_provider_implementation_role(
    tmp_path: Path,
) -> None:
    fixture = _make_repo(tmp_path / "repo")
    value = json.loads(_build(fixture))
    value["providers"][0]["status"] = "implemented_non_authorizing"
    value["providers"][0]["implementation_role"] = "structured_contract"
    with pytest.raises(inventory.FreezeInventoryError, match="not a source role"):
        inventory.validate_freeze_inventory_bytes(_reseal(value))
