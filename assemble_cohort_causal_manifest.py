#!/usr/bin/env python3
"""Assemble the six audited cell artifacts into one formal evidence input."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from run_cohort_causal import (
    ROOT,
    _collector_manifest_path,
    _dataset_projection,
    _resolve,
    _trace_paths,
    load_grid,
    load_provenance,
)
from validate_cohort_causal_results import (
    EXPECTED_PREREGISTRATION_SHA256,
    EXPECTED_STATISTICAL_ADDENDUM_SHA256,
    EXPERIMENT,
    LIMITATION,
    MECHANISM_LABEL,
    PREREGISTRATION_FILENAME,
    SCHEMA_VERSION,
    STATISTICAL_ADDENDUM_FILENAME,
    canonical_sha256,
    tape_item_sha256,
    tape_sha256,
)


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or path.parent.is_symlink():
        raise ValueError("formal manifest parent must be a real directory")
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.tmp.publish."
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _verify_tape(tape: dict[str, Any]) -> dict[str, Any]:
    embedded = tape.get("tape_sha256")
    if embedded != tape_sha256(tape):
        raise ValueError("tape root digest verification failed during assembly")
    items = tape.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError("tape contains no items")
    verification_rows = []
    for position, item in enumerate(items):
        if not isinstance(item, dict) or item.get("sequence_index") != position:
            raise ValueError(f"non-canonical tape item at position {position}")
        if item.get("item_sha256") != tape_item_sha256(item):
            raise ValueError(f"tape item digest failed at position {position}")
        verification_rows.append(
            {
                "sequence_index": position,
                "item_sha256": item["item_sha256"],
                "digest_verified": True,
            }
        )
    return {"digest_verified": True, "items": verification_rows}


def _bind_heldout_trace(
    *, root: Path, cfg: dict[str, Any], cell: dict[str, Any]
) -> dict[str, Any]:
    """Read the registered trace sidecar, verify its digest, and embed it."""

    expected_trace_path, _ = _trace_paths(root, cfg)
    recorded_path = cell.get("trace_path")
    if not isinstance(recorded_path, str) or not recorded_path:
        raise ValueError(f"{cfg['cfg_id']} cell has no trace_path")
    resolved_recorded_path = _resolve(root, recorded_path)
    if resolved_recorded_path.resolve() != expected_trace_path.resolve():
        raise ValueError(f"{cfg['cfg_id']} cell trace_path is not registered")
    trace = _load_json(expected_trace_path)
    trace_digest = canonical_sha256(trace)
    if cell.get("trace_sha256") != trace_digest:
        raise ValueError(f"{cfg['cfg_id']} trace SHA-256 mismatch during assembly")
    bound = dict(cell)
    bound["heldout_trace"] = trace
    return bound


def assemble_manifest(
    *,
    root: Path,
    grid: dict[str, Any],
    provenance: dict[str, Any],
    preregistration_path: Path,
    statistical_addendum_path: Path | None = None,
) -> dict[str, Any]:
    if grid.get("kind") != "formal":
        raise ValueError("the evidence manifest can only be assembled from formal grid")
    collectors = {row["run_seed"]: row for row in grid.get("collectors", [])}
    cells = {
        (row["run_seed"], row["arm"]): row for row in grid.get("evaluation_cells", [])
    }
    if len(collectors) != 3 or len(cells) != 6:
        raise ValueError("formal grid must contain 3 collectors and 6 replay cells")

    pairs: list[dict[str, Any]] = []
    for run_seed in sorted(collectors):
        collector_cfg = collectors[run_seed]
        collector_manifest = _load_json(_collector_manifest_path(root, collector_cfg))
        if (
            collector_manifest.get("status") != "completed"
            or collector_manifest.get("run_seed") != run_seed
            or collector_manifest.get("trainable_param_sha256_initial")
            != collector_manifest.get("trainable_param_sha256_final")
        ):
            raise ValueError(f"collector integrity failure for seed {run_seed}")
        if canonical_sha256(collector_manifest.get("provenance")) != canonical_sha256(
            provenance
        ):
            raise ValueError(f"collector provenance mismatch for seed {run_seed}")
        tape_path = _resolve(root, collector_cfg["tape_path"])
        tape = _load_json(tape_path)
        verification = _verify_tape(tape)
        if tape.get("tape_sha256") != collector_manifest.get("tape_sha256"):
            raise ValueError(f"collector/tape digest mismatch for seed {run_seed}")
        if verification != collector_manifest.get("tape_verification"):
            raise ValueError(f"collector verification mismatch for seed {run_seed}")

        active_cfg = cells[(run_seed, "active")]
        lr0_cfg = cells[(run_seed, "lr0")]
        active = _bind_heldout_trace(
            root=root,
            cfg=active_cfg,
            cell=_load_json(_resolve(root, active_cfg["cell_manifest_path"])),
        )
        lr0 = _bind_heldout_trace(
            root=root,
            cfg=lr0_cfg,
            cell=_load_json(_resolve(root, lr0_cfg["cell_manifest_path"])),
        )
        for arm, cell in (("active", active), ("lr0", lr0)):
            if cell.get("status") != "completed" or cell.get("arm") != arm:
                raise ValueError(f"incomplete {arm} cell for seed {run_seed}")
            if cell.get("tape_sha256") != tape["tape_sha256"]:
                raise ValueError(f"{arm} cell consumed wrong tape for seed {run_seed}")
            if canonical_sha256(cell.get("provenance")) != canonical_sha256(provenance):
                raise ValueError(f"{arm} provenance mismatch for seed {run_seed}")
        if active_cfg["pair_id"] != lr0_cfg["pair_id"]:
            raise ValueError(f"pair ID mismatch for seed {run_seed}")
        pairs.append(
            {
                "pair_id": active_cfg["pair_id"],
                "run_seed": run_seed,
                "tape": tape,
                "tape_verification": verification,
                "active": active,
                "lr0": lr0,
            }
        )

    registered_preregistration = root / PREREGISTRATION_FILENAME
    if preregistration_path.resolve() != registered_preregistration.resolve():
        raise ValueError("preregistration path is not the checked-in repository file")
    preregistration_bytes = registered_preregistration.read_bytes()
    preregistration_sha256 = hashlib.sha256(preregistration_bytes).hexdigest()
    if preregistration_sha256 != EXPECTED_PREREGISTRATION_SHA256:
        raise ValueError(
            "checked-in preregistration bytes differ from validator binding"
        )
    registered_statistical_addendum = root / STATISTICAL_ADDENDUM_FILENAME
    requested_statistical_addendum = (
        registered_statistical_addendum
        if statistical_addendum_path is None
        else statistical_addendum_path
    )
    if (
        requested_statistical_addendum.resolve()
        != registered_statistical_addendum.resolve()
    ):
        raise ValueError(
            "statistical addendum path is not the checked-in repository file"
        )
    statistical_addendum_bytes = registered_statistical_addendum.read_bytes()
    statistical_addendum_sha256 = hashlib.sha256(statistical_addendum_bytes).hexdigest()
    if statistical_addendum_sha256 != EXPECTED_STATISTICAL_ADDENDUM_SHA256:
        raise ValueError(
            "checked-in statistical addendum bytes differ from validator binding"
        )
    if provenance.get("statistical_addendum_sha256") != (statistical_addendum_sha256):
        raise ValueError("provenance statistical addendum SHA-256 mismatch")
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "protocol": grid["protocol"],
        "mechanism_label": MECHANISM_LABEL,
        "limitation": LIMITATION,
        "preregistration_sha256": preregistration_sha256,
        "statistical_addendum_sha256": statistical_addendum_sha256,
        "provenance": provenance,
        "corpora": {
            "adaptation": _dataset_projection(root, grid, "adaptation"),
            "heldout": _dataset_projection(root, grid, "heldout"),
        },
        "pairs": pairs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--preregistration",
        type=Path,
        default=ROOT / "COHORT_QONLY_CAUSAL_PREREG.md",
    )
    parser.add_argument("--statistical-addendum", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite formal manifest: {output}")
    manifest = assemble_manifest(
        root=args.root.resolve(),
        grid=load_grid(args.grid.resolve()),
        provenance=load_provenance(args.provenance.resolve()),
        preregistration_path=args.preregistration.resolve(),
        statistical_addendum_path=(
            args.statistical_addendum.resolve()
            if args.statistical_addendum is not None
            else None
        ),
    )
    _atomic_write_json(output, manifest)
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
