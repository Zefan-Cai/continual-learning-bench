#!/usr/bin/env python3
"""Fail-closed byte-parity seal for shared Cohort causal inputs.

The online-ICL checkout is allowed to change its method-specific runtime, but
the shared Cohort data and evaluation surface must remain byte-for-byte equal
to the preregistered causal checkout.  This module verifies that invariant
against Git blobs rather than trusting paths or separately maintained hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Sequence


BASE_CAUSAL_COMMIT = "1caf142f6ce611da8da8691d4c336388a4c3c4b3"
SCHEMA_VERSION = 1
INVENTORY_KIND = "cohort_shared_causal_parity"

# This is intentionally an explicit, sorted allowlist.  In particular, the two
# causal corpus directories include every Git-tracked artifact (including the
# SQLite databases), not just their manifests.
SHARED_CAUSAL_PATHS = (
    "COHORT_QONLY_CAUSAL_PREREG.md",
    "COHORT_QONLY_CAUSAL_STATISTICAL_ADDENDUM_V1.md",
    "assemble_cohort_causal_manifest.py",
    "build_cohort_causal_provenance.py",
    "data/cohort_studies/causal_adapt_2026071411/cohort_definitions.json",
    "data/cohort_studies/causal_adapt_2026071411/dbs/cadence_industrial.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/cadence_industrial_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/cadence_urban.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/cadence_urban_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/forge_industrial.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/forge_industrial_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/forge_urban.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/forge_urban_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/herald_rural.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/herald_rural_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/herald_suburban.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/herald_suburban_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/meridian_rural.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/meridian_rural_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/meridian_suburban.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/meridian_suburban_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/mosaic_suburban.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/mosaic_suburban_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/mosaic_urban.db",
    "data/cohort_studies/causal_adapt_2026071411/dbs/mosaic_urban_s2.db",
    "data/cohort_studies/causal_adapt_2026071411/ground_truth.json",
    "data/cohort_studies/causal_adapt_2026071411/instance_references.json",
    "data/cohort_studies/causal_adapt_2026071411/manifest.json",
    "data/cohort_studies/causal_adapt_2026071411/metadata.json",
    "data/cohort_studies/causal_eval_2026071412/cohort_definitions.json",
    "data/cohort_studies/causal_eval_2026071412/dbs/cadence_industrial.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/cadence_industrial_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/cadence_urban.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/cadence_urban_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/forge_industrial.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/forge_industrial_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/forge_urban.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/forge_urban_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/herald_rural.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/herald_rural_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/herald_suburban.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/herald_suburban_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/meridian_rural.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/meridian_rural_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/meridian_suburban.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/meridian_suburban_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/mosaic_suburban.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/mosaic_suburban_s2.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/mosaic_urban.db",
    "data/cohort_studies/causal_eval_2026071412/dbs/mosaic_urban_s2.db",
    "data/cohort_studies/causal_eval_2026071412/ground_truth.json",
    "data/cohort_studies/causal_eval_2026071412/instance_references.json",
    "data/cohort_studies/causal_eval_2026071412/manifest.json",
    "data/cohort_studies/causal_eval_2026071412/metadata.json",
    "generate_cohort_causal_grid.py",
    "grid_cohort_causal_formal.json",
    "grid_cohort_causal_smoke.json",
    "run_cohort_causal.py",
    "src/systems/utils/structured_output.py",
    "src/tasks/cohort_studies/__init__.py",
    "src/tasks/cohort_studies/dgp.py",
    "src/tasks/cohort_studies/frozen_db.py",
    "src/tasks/cohort_studies/schedules/causal_adapt_2026071411.json",
    "src/tasks/cohort_studies/schedules/causal_eval_2026071412.json",
    "src/tasks/cohort_studies/schedules/default.json",
    "src/tasks/cohort_studies/scorer.py",
    "src/tasks/cohort_studies/scoring_cohorts.py",
    "src/tasks/cohort_studies/study_configs.py",
    "src/tasks/cohort_studies/task.py",
    "src/tasks/cohort_studies/templates/instance_brief.j2",
    "src/tasks/cohort_studies/templates/step_prompt.j2",
    "src/tasks/cohort_studies/tool_schemas.py",
    "src/tasks/cohort_studies/variants/cadence.json",
    "src/tasks/cohort_studies/variants/forge.json",
    "src/tasks/cohort_studies/variants/herald.json",
    "src/tasks/cohort_studies/variants/meridian.json",
    "src/tasks/cohort_studies/variants/mosaic.json",
    "src/tasks/schedules.py",
    "validate_cohort_causal_results.py",
    "validate_cohort_causal_smoke.py",
)

_CORPUS_ROOTS = (
    "data/cohort_studies/causal_adapt_2026071411",
    "data/cohort_studies/causal_eval_2026071412",
)
_COHORT_SOURCE_ROOT = "src/tasks/cohort_studies"
_COHORT_SOURCE_SUFFIXES = (".j2", ".json", ".py")


def canonical_json_bytes(value: Any) -> bytes:
    """Return the sole canonical JSON representation used by the seal."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "shared-causal inventory is not canonical-JSON encodable"
        ) from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _git(
    repo_root: Path,
    args: Sequence[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "--literal-pathspecs", *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(args)} failed: {detail or result.returncode}")
    return result


def _nul_paths(output: bytes) -> tuple[str, ...]:
    if not output:
        return ()
    return tuple(item.decode("utf-8") for item in output.rstrip(b"\0").split(b"\0"))


def _line_paths(output: bytes) -> tuple[str, ...]:
    return tuple(line for line in output.decode("utf-8").splitlines() if line)


def _validate_allowlist() -> None:
    if SHARED_CAUSAL_PATHS != tuple(sorted(SHARED_CAUSAL_PATHS)):
        raise RuntimeError("SHARED_CAUSAL_PATHS must remain explicitly sorted")
    if len(SHARED_CAUSAL_PATHS) != len(set(SHARED_CAUSAL_PATHS)):
        raise RuntimeError("SHARED_CAUSAL_PATHS contains duplicates")
    for path in SHARED_CAUSAL_PATHS:
        candidate = Path(path)
        if (
            candidate.is_absolute()
            or ".." in candidate.parts
            or candidate.as_posix() != path
        ):
            raise RuntimeError(f"unsafe shared-causal path: {path!r}")


def _scope_paths(repo_root: Path, *, treeish: str | None) -> set[str]:
    roots = (*_CORPUS_ROOTS, _COHORT_SOURCE_ROOT)
    if treeish is None:
        output = _git(repo_root, ["ls-files", "-z", "--", *roots]).stdout
        candidates = _nul_paths(output)
    else:
        output = _git(
            repo_root,
            ["ls-tree", "-r", "--name-only", treeish, "--", *roots],
        ).stdout
        candidates = _line_paths(output)
    return {
        path
        for path in candidates
        if path.startswith(_CORPUS_ROOTS)
        or (
            path.startswith(f"{_COHORT_SOURCE_ROOT}/")
            and path.endswith(_COHORT_SOURCE_SUFFIXES)
        )
    }


def _assert_scope_is_fully_allowlisted(repo_root: Path, *, base_commit: str) -> None:
    expected = {
        path
        for path in SHARED_CAUSAL_PATHS
        if path.startswith(_CORPUS_ROOTS) or path.startswith(f"{_COHORT_SOURCE_ROOT}/")
    }
    for label, actual in (
        ("base", _scope_paths(repo_root, treeish=base_commit)),
        ("current index", _scope_paths(repo_root, treeish=None)),
    ):
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise ValueError(
                f"{label} shared-causal scope differs from explicit allowlist: "
                f"missing={missing}, extra={extra}"
            )


def verify_shared_causal_parity(
    *,
    repo_root: Path | str = Path(__file__).resolve().parent,
    base_commit: str = BASE_CAUSAL_COMMIT,
) -> dict[str, Any]:
    """Verify shared causal files and return a canonical, content-bound inventory.

    Any missing commit, non-ancestor base, index/worktree drift, coverage drift,
    untracked replacement, or byte mismatch raises ``ValueError``.
    """

    _validate_allowlist()
    requested_root = Path(repo_root).resolve()
    top_level = _git(requested_root, ["rev-parse", "--show-toplevel"]).stdout
    root = Path(top_level.decode("utf-8").strip()).resolve()

    resolved = _git(
        root,
        ["rev-parse", "--verify", f"{base_commit}^{{commit}}"],
        check=False,
    )
    if resolved.returncode != 0:
        raise ValueError(f"base causal commit does not exist: {base_commit}")
    resolved_base = resolved.stdout.decode("ascii").strip()

    ancestry = _git(
        root,
        ["merge-base", "--is-ancestor", resolved_base, "HEAD"],
        check=False,
    )
    if ancestry.returncode == 1:
        raise ValueError(
            f"base causal commit is not an ancestor of HEAD: {resolved_base}"
        )
    if ancestry.returncode != 0:
        detail = ancestry.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"could not verify base causal ancestry: {detail}")

    _assert_scope_is_fully_allowlisted(root, base_commit=resolved_base)

    tracked = set(
        _nul_paths(_git(root, ["ls-files", "-z", "--", *SHARED_CAUSAL_PATHS]).stdout)
    )
    expected = set(SHARED_CAUSAL_PATHS)
    if tracked != expected:
        missing = sorted(expected - tracked)
        extra = sorted(tracked - expected)
        raise ValueError(
            "current shared-causal files are not exactly tracked: "
            f"missing={missing}, extra={extra}"
        )

    dirty = _git(
        root,
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            *SHARED_CAUSAL_PATHS,
        ],
    ).stdout
    if dirty:
        raise ValueError("current shared-causal files are not clean")

    files: list[dict[str, Any]] = []
    for path in SHARED_CAUSAL_PATHS:
        worktree_path = root / path
        if not worktree_path.is_file():
            raise ValueError(f"shared-causal worktree file is missing: {path}")
        base_bytes = _git(root, ["show", f"{resolved_base}:{path}"]).stdout
        worktree_bytes = worktree_path.read_bytes()
        if base_bytes != worktree_bytes:
            raise ValueError(f"shared-causal byte mismatch against base commit: {path}")
        files.append(
            {
                "path": path,
                "sha256": hashlib.sha256(base_bytes).hexdigest(),
                "size_bytes": len(base_bytes),
            }
        )

    inventory: dict[str, Any] = {
        "base_causal_commit": resolved_base,
        "files": files,
        "kind": INVENTORY_KIND,
        "schema_version": SCHEMA_VERSION,
    }
    inventory["inventory_sha256"] = canonical_sha256(inventory)
    return inventory


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--base-commit", default=BASE_CAUSAL_COMMIT)
    arguments = parser.parse_args(argv)
    inventory = verify_shared_causal_parity(
        repo_root=arguments.repo_root,
        base_commit=arguments.base_commit,
    )
    print(canonical_json_bytes(inventory).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
