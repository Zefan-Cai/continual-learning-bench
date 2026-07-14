from __future__ import annotations

from copy import deepcopy
import hashlib
import subprocess
from pathlib import Path

import pytest

import cohort_shared_causal_parity as parity


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def _write_allowlist(repo: Path, *, marker: str = "base") -> None:
    for index, relative in enumerate(parity.SHARED_CAUSAL_PATHS):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"{marker}:{index}:{relative}\n".encode())


def _repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "Parity Tests")
    _write_allowlist(repo)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base causal")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_allowlist_is_explicit_sorted_and_covers_required_surface() -> None:
    assert parity.SHARED_CAUSAL_PATHS == tuple(sorted(parity.SHARED_CAUSAL_PATHS))
    assert len(parity.SHARED_CAUSAL_PATHS) == len(set(parity.SHARED_CAUSAL_PATHS))
    assert {
        "COHORT_QONLY_CAUSAL_PREREG.md",
        "COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md",
        "assemble_cohort_causal_manifest.py",
        "build_cohort_causal_provenance.py",
        "data/cohort_studies/causal_adapt_2026071411/manifest.json",
        "data/cohort_studies/causal_eval_2026071412/manifest.json",
        "generate_cohort_causal_grid.py",
        "grid_cohort_causal_formal.json",
        "grid_cohort_causal_smoke.json",
        "run_cohort_causal.py",
        "src/tasks/cohort_studies/schedules/causal_adapt_2026071411.json",
        "src/tasks/cohort_studies/schedules/causal_eval_2026071412.json",
        "src/tasks/schedules.py",
        "src/systems/utils/structured_output.py",
        "validate_cohort_causal_results.py",
        "validate_cohort_causal_smoke.py",
    }.issubset(parity.SHARED_CAUSAL_PATHS)


def test_shared_causal_parity_passes_and_returns_canonical_inventory(
    tmp_path: Path,
) -> None:
    repo, base = _repo(tmp_path)

    inventory = parity.verify_shared_causal_parity(
        repo_root=repo,
        base_commit=base,
    )

    assert inventory["base_causal_commit"] == base
    assert inventory["kind"] == parity.INVENTORY_KIND
    assert [entry["path"] for entry in inventory["files"]] == list(
        parity.SHARED_CAUSAL_PATHS
    )
    first_path = repo / parity.SHARED_CAUSAL_PATHS[0]
    assert (
        inventory["files"][0]["sha256"]
        == hashlib.sha256(first_path.read_bytes()).hexdigest()
    )
    without_digest = deepcopy(inventory)
    embedded = without_digest.pop("inventory_sha256")
    assert embedded == parity.canonical_sha256(without_digest)
    assert parity.canonical_json_bytes(inventory) == parity.canonical_json_bytes(
        inventory
    )


def test_shared_causal_parity_rejects_clean_committed_current_drift(
    tmp_path: Path,
) -> None:
    repo, base = _repo(tmp_path)
    target = repo / parity.SHARED_CAUSAL_PATHS[0]
    target.write_bytes(b"committed drift\n")
    _git(repo, "add", str(target.relative_to(repo)))
    _git(repo, "commit", "-m", "drift after causal base")

    with pytest.raises(ValueError, match="byte mismatch against base commit"):
        parity.verify_shared_causal_parity(repo_root=repo, base_commit=base)


def test_shared_causal_parity_rejects_missing_worktree_file(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path)
    (repo / parity.SHARED_CAUSAL_PATHS[0]).unlink()

    with pytest.raises(ValueError, match="not clean|missing"):
        parity.verify_shared_causal_parity(repo_root=repo, base_commit=base)


def test_shared_causal_parity_rejects_untracked_replacement(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path)
    relative = parity.SHARED_CAUSAL_PATHS[0]
    _git(repo, "rm", relative)
    _git(repo, "commit", "-m", "remove tracked causal artifact")
    target = repo / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"untracked replacement\n")

    with pytest.raises(ValueError, match="allowlist|not exactly tracked"):
        parity.verify_shared_causal_parity(repo_root=repo, base_commit=base)


def test_shared_causal_parity_rejects_base_that_is_not_an_ancestor(
    tmp_path: Path,
) -> None:
    repo, base = _repo(tmp_path)
    _git(repo, "checkout", "--orphan", "unrelated")
    _git(repo, "rm", "-rf", ".")
    _write_allowlist(repo, marker="unrelated")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "unrelated checkout")

    with pytest.raises(ValueError, match="not an ancestor"):
        parity.verify_shared_causal_parity(repo_root=repo, base_commit=base)
