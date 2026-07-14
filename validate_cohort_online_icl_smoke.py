#!/usr/bin/env python3
"""Validate the two-instance online-ICL infrastructure smoke gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from build_cohort_online_icl_protocol_seal import canonical_sha256
from run_cohort_causal import (
    load_grid as load_causal_grid,
    load_provenance as load_causal_provenance,
    verify_runtime_provenance as verify_causal_runtime_provenance,
)
from run_cohort_online_icl import (
    _atomic_write_json_no_overwrite,
    load_grid,
    load_protocol_seal,
    load_provenance,
    verify_runtime_protocol_seal,
    verify_runtime_provenance,
)
from validate_cohort_causal_smoke import validate_smoke as validate_causal_smoke
from validate_cohort_online_icl_results import PROTOCOL, SCHEMA_VERSION, validate_cell


CAUSAL_PREREQUISITE_FIELDS = frozenset(
    {
        "causal_provenance_sha256",
        "causal_smoke_gate_sha256",
        "causal_source_commit",
        "environment_lock_sha256",
        "model_path",
        "model_sha256",
        "tokenizer_sha256",
    }
)

SMOKE_CELL_INTEGRITY_FIELDS = frozenset(
    {
        "adaptation_trace_file_sha256",
        "adaptation_trace_sha256",
        "cell_manifest_file_sha256",
        "cell_manifest_sha256",
        "cfg_id",
        "context_inventory_file_sha256",
        "context_inventory_sha256",
        "heldout_trace_file_sha256",
        "heldout_trace_sha256",
        "restoration_audit_file_sha256",
        "restoration_audit_sha256",
        "run_seed",
        "snapshot_file_sha256",
        "snapshot_artifact_sha256",
        "snapshot_sha256",
        "valid",
    }
)


def _outcome_blind_cell_projection(validated: dict[str, Any]) -> dict[str, Any]:
    """Retain integrity bindings while withholding every efficacy-bearing field."""

    missing = SMOKE_CELL_INTEGRITY_FIELDS - set(validated)
    if missing:
        raise ValueError(f"validated smoke cell is missing integrity fields: {missing}")
    projected = {
        field: validated[field] for field in sorted(SMOKE_CELL_INTEGRITY_FIELDS)
    }
    if projected["valid"] is not True:
        raise ValueError("validated smoke cell did not pass integrity checks")
    return projected


def validate_causal_smoke_prerequisite(
    *,
    causal_root: Path,
    causal_gate: dict[str, Any],
    causal_provenance: dict[str, Any],
) -> dict[str, Any]:
    """Recompute the paired causal smoke gate from its bound raw artifacts."""

    causal_root = causal_root.resolve()
    grid = load_causal_grid(causal_root / "grid_cohort_causal_smoke.json")
    model_path = causal_provenance.get("model_path")
    if not isinstance(model_path, str) or not model_path:
        raise ValueError("causal smoke provenance has no model path")
    verify_causal_runtime_provenance(
        causal_root,
        causal_provenance,
        expected_model_path=Path(model_path),
    )
    recomputed = validate_causal_smoke(
        root=causal_root,
        grid=grid,
        provenance=causal_provenance,
    )
    if canonical_sha256(recomputed) != canonical_sha256(causal_gate):
        raise ValueError("causal smoke gate differs from exact artifact revalidation")
    if (
        recomputed.get("status") != "pass"
        or recomputed.get("decision") != "pass"
        or recomputed.get("errors") != []
    ):
        raise ValueError("paired causal smoke gate did not pass exact revalidation")
    binding = {
        "causal_provenance_sha256": canonical_sha256(causal_provenance),
        "causal_smoke_gate_sha256": canonical_sha256(causal_gate),
        "causal_source_commit": causal_provenance.get("source_commit"),
        "environment_lock_sha256": causal_provenance.get("environment_lock_sha256"),
        "model_path": model_path,
        "model_sha256": causal_provenance.get("model_sha256"),
        "tokenizer_sha256": causal_provenance.get("tokenizer_sha256"),
    }
    for field, value in binding.items():
        if field == "model_path":
            continue
        expected_length = 40 if field == "causal_source_commit" else 64
        if (
            not isinstance(value, str)
            or len(value) != expected_length
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"causal prerequisite binding is invalid: {field}")
    return binding


def validate_smoke(
    *,
    root: Path,
    grid: dict[str, Any],
    provenance: dict[str, Any],
    protocol_seal: dict[str, Any],
    cell: dict[str, Any],
    causal_prerequisite: dict[str, Any],
) -> dict[str, Any]:
    if grid.get("kind") != "smoke" or len(grid.get("cells", [])) != 1:
        raise ValueError("online-ICL smoke requires the one-cell smoke grid")
    protocol_seal_sha256 = verify_runtime_protocol_seal(
        root,
        protocol_seal=protocol_seal,
        provenance=provenance,
    )
    if cell.get("protocol_seal_sha256") != protocol_seal_sha256:
        raise ValueError("online-ICL smoke cell protocol-seal mismatch")
    if set(causal_prerequisite) != CAUSAL_PREREQUISITE_FIELDS:
        raise ValueError("causal smoke prerequisite binding schema mismatch")
    for field in (
        "environment_lock_sha256",
        "model_path",
        "model_sha256",
        "tokenizer_sha256",
    ):
        if causal_prerequisite[field] != provenance[field]:
            raise ValueError(f"causal/online smoke shared provenance differs: {field}")
    if causal_prerequisite["causal_source_commit"] != provenance["base_causal_commit"]:
        raise ValueError("online-ICL base commit differs from causal smoke source")
    validated = validate_cell(
        root=root,
        grid=grid,
        cfg=grid["cells"][0],
        provenance=provenance,
        protocol_seal_sha256=protocol_seal_sha256,
        cell=cell,
    )
    return {
        "cell": _outcome_blind_cell_projection(validated),
        "causal_prerequisite": causal_prerequisite,
        "decision": "pass",
        "decision_scope": "infrastructure_smoke",
        "efficacy_interpretation_allowed": False,
        "protocol": PROTOCOL,
        "protocol_seal_sha256": protocol_seal_sha256,
        "provenance_sha256": canonical_sha256(provenance),
        "publication_grade": False,
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--protocol-seal", type=Path, required=True)
    parser.add_argument("--cell-manifest", type=Path, required=True)
    parser.add_argument("--causal-root", type=Path, required=True)
    parser.add_argument("--causal-smoke-gate", type=Path, required=True)
    parser.add_argument("--causal-provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root = args.root.resolve()
    grid = load_grid(args.grid.resolve())
    registered_manifest = Path(grid["cells"][0]["cell_manifest_path"])
    if not registered_manifest.is_absolute():
        registered_manifest = root / registered_manifest
    if args.cell_manifest.resolve() != registered_manifest.resolve():
        raise SystemExit("smoke cell manifest path differs from registered grid path")
    provenance = load_provenance(args.provenance.resolve())
    verify_runtime_provenance(
        root,
        provenance,
        expected_model_path=Path(grid["cells"][0]["system_params"]["model_path"]),
    )
    causal_gate = json.loads(args.causal_smoke_gate.read_text())
    if not isinstance(causal_gate, dict):
        raise SystemExit("causal smoke gate must be a JSON object")
    causal_provenance = load_causal_provenance(args.causal_provenance.resolve())
    causal_prerequisite = validate_causal_smoke_prerequisite(
        causal_root=args.causal_root,
        causal_gate=causal_gate,
        causal_provenance=causal_provenance,
    )
    payload = validate_smoke(
        root=root,
        grid=grid,
        provenance=provenance,
        protocol_seal=load_protocol_seal(args.protocol_seal.resolve()),
        cell=json.loads(args.cell_manifest.read_text()),
        causal_prerequisite=causal_prerequisite,
    )
    _atomic_write_json_no_overwrite(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
