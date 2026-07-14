from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

import build_cohort_online_icl_protocol_seal as seal_module
import validate_cohort_online_icl_smoke as smoke_validator


def _provenance() -> dict[str, str]:
    return {
        "base_causal_commit": "1" * 40,
        "environment_lock_sha256": "2" * 64,
        "evaluation_code_sha256": "3" * 64,
        "icl_prereg_sha256": "4" * 64,
        "model_path": "/models/Qwen3-4B",
        "model_sha256": "5" * 64,
        "protocol": seal_module.ONLINE_ICL_PROTOCOL,
        "shared_causal_code_sha256": "8" * 64,
        "source_commit": "6" * 40,
        "tokenizer_sha256": "7" * 64,
    }


def _write_grid(path: Path, *, kind: str, marker: str) -> dict:
    payload = {
        "cells": [{"cfg_id": marker}],
        "kind": kind,
        "protocol": seal_module.ONLINE_ICL_PROTOCOL,
    }
    payload["grid_sha256"] = seal_module.canonical_sha256(payload)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload


def _grids(tmp_path: Path) -> tuple[Path, Path, dict, dict]:
    smoke = tmp_path / seal_module.GRID_FILENAMES["smoke"]
    formal = tmp_path / seal_module.GRID_FILENAMES["formal"]
    smoke_payload = _write_grid(smoke, kind="smoke", marker="smoke-cell")
    formal_payload = _write_grid(formal, kind="formal", marker="formal-cell")
    return smoke, formal, smoke_payload, formal_payload


def test_protocol_seal_is_deterministic_and_binds_full_pre_outcome_surface(
    tmp_path: Path,
) -> None:
    smoke, formal, smoke_payload, formal_payload = _grids(tmp_path)
    provenance = _provenance()

    first = seal_module.create_protocol_seal(
        provenance=provenance,
        smoke_grid_path=smoke,
        formal_grid_path=formal,
    )
    second = seal_module.create_protocol_seal(
        provenance=provenance,
        smoke_grid_path=smoke,
        formal_grid_path=formal,
    )

    assert first == second
    assert first["provenance_sha256"] == seal_module.canonical_sha256(provenance)
    assert first["provenance_bindings"] == {
        field: provenance[field] for field in seal_module.PROVENANCE_BINDING_FIELDS
    }
    assert first["shared_parity_bindings"] == {
        field: provenance[field] for field in seal_module.SHARED_PARITY_FIELDS
    }
    assert first["grids"]["smoke"] == {
        "file_sha256": hashlib.sha256(smoke.read_bytes()).hexdigest(),
        "grid_sha256": smoke_payload["grid_sha256"],
        "path": smoke.name,
    }
    assert first["grids"]["formal"] == {
        "file_sha256": hashlib.sha256(formal.read_bytes()).hexdigest(),
        "grid_sha256": formal_payload["grid_sha256"],
        "path": formal.name,
    }
    without_digest = deepcopy(first)
    embedded = without_digest.pop("protocol_seal_sha256")
    assert embedded == seal_module.canonical_sha256(without_digest)


def test_protocol_seal_atomic_publish_is_no_overwrite(tmp_path: Path) -> None:
    smoke, formal, _, _ = _grids(tmp_path)
    seal = seal_module.create_protocol_seal(
        provenance=_provenance(),
        smoke_grid_path=smoke,
        formal_grid_path=formal,
    )
    output = tmp_path / "protocol-seal.json"

    seal_module.write_protocol_seal(output=output, seal=seal)
    original = output.read_bytes()
    assert seal_module.load_protocol_seal(output) == seal
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        seal_module.write_protocol_seal(output=output, seal=seal)
    assert output.read_bytes() == original


def test_protocol_seal_verification_rejects_provenance_or_either_grid_drift(
    tmp_path: Path,
) -> None:
    smoke, formal, _, _ = _grids(tmp_path)
    provenance = _provenance()
    seal = seal_module.create_protocol_seal(
        provenance=provenance,
        smoke_grid_path=smoke,
        formal_grid_path=formal,
    )
    assert (
        seal_module.verify_protocol_seal(
            seal=seal,
            provenance=provenance,
            smoke_grid_path=smoke,
            formal_grid_path=formal,
        )
        == seal["protocol_seal_sha256"]
    )

    changed_provenance = deepcopy(provenance)
    changed_provenance["environment_lock_sha256"] = "8" * 64
    with pytest.raises(ValueError, match="current provenance or grids"):
        seal_module.verify_protocol_seal(
            seal=seal,
            provenance=changed_provenance,
            smoke_grid_path=smoke,
            formal_grid_path=formal,
        )

    _write_grid(formal, kind="formal", marker="changed-formal-cell")
    with pytest.raises(ValueError, match="current provenance or grids"):
        seal_module.verify_protocol_seal(
            seal=seal,
            provenance=provenance,
            smoke_grid_path=smoke,
            formal_grid_path=formal,
        )


def test_load_protocol_seal_rejects_schema_and_digest_tampering(
    tmp_path: Path,
) -> None:
    smoke, formal, _, _ = _grids(tmp_path)
    seal = seal_module.create_protocol_seal(
        provenance=_provenance(),
        smoke_grid_path=smoke,
        formal_grid_path=formal,
    )
    path = tmp_path / "tampered.json"

    tampered = deepcopy(seal)
    tampered["provenance_sha256"] = "0" * 64
    path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="digest mismatch"):
        seal_module.load_protocol_seal(path)

    extra = deepcopy(seal)
    extra["result"] = "favorable"
    without_digest = deepcopy(extra)
    without_digest.pop("protocol_seal_sha256")
    extra["protocol_seal_sha256"] = seal_module.canonical_sha256(without_digest)
    path.write_text(json.dumps(extra))
    with pytest.raises(ValueError, match="field schema mismatch"):
        seal_module.load_protocol_seal(path)


def test_smoke_gate_records_exact_provenance_and_protocol_seal_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provenance = _provenance()
    seal_sha256 = "9" * 64
    cell = {"protocol_seal_sha256": seal_sha256}
    grid = {"kind": "smoke", "cells": [{"cfg_id": "smoke"}]}
    monkeypatch.setattr(
        smoke_validator,
        "verify_runtime_protocol_seal",
        lambda *_args, **_kwargs: seal_sha256,
    )
    monkeypatch.setattr(
        smoke_validator,
        "validate_cell",
        lambda **_kwargs: {
            "adaptation_trace_file_sha256": "8" * 64,
            "adaptation_trace_sha256": "1" * 64,
            "cell_manifest_file_sha256": "9" * 64,
            "cell_manifest_sha256": "2" * 64,
            "cfg_id": "smoke",
            "context_inventory_file_sha256": "a" * 64,
            "context_inventory_sha256": "3" * 64,
            "heldout_trace_file_sha256": "b" * 64,
            "heldout_trace_sha256": "4" * 64,
            "restoration_audit_file_sha256": "c" * 64,
            "restoration_audit_sha256": "5" * 64,
            "run_seed": 2026071498,
            "snapshot_file_sha256": "d" * 64,
            "snapshot_artifact_sha256": "6" * 64,
            "snapshot_sha256": "7" * 64,
            "terminal_actions": [{"reward": 1.0}],
            "valid": True,
        },
    )

    report = smoke_validator.validate_smoke(
        root=tmp_path,
        grid=grid,
        provenance=provenance,
        protocol_seal={"protocol_seal_sha256": seal_sha256},
        cell=cell,
        causal_prerequisite={
            "causal_provenance_sha256": "a" * 64,
            "causal_smoke_gate_sha256": "b" * 64,
            "causal_source_commit": provenance["base_causal_commit"],
            "environment_lock_sha256": provenance["environment_lock_sha256"],
            "model_path": provenance["model_path"],
            "model_sha256": provenance["model_sha256"],
            "tokenizer_sha256": provenance["tokenizer_sha256"],
        },
    )

    assert report["provenance_sha256"] == seal_module.canonical_sha256(provenance)
    assert report["protocol_seal_sha256"] == seal_sha256
    assert report["causal_prerequisite"]["causal_smoke_gate_sha256"] == "b" * 64
    assert report["status"] == "pass"


def test_causal_smoke_prerequisite_is_recomputed_and_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    causal_provenance = {
        "environment_lock_sha256": "1" * 64,
        "model_path": "/models/Qwen3-4B",
        "model_sha256": "2" * 64,
        "source_commit": "3" * 40,
        "tokenizer_sha256": "4" * 64,
    }
    gate = {"decision": "pass", "errors": [], "status": "pass"}
    monkeypatch.setattr(smoke_validator, "load_causal_grid", lambda _path: {})
    monkeypatch.setattr(
        smoke_validator,
        "verify_causal_runtime_provenance",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        smoke_validator, "validate_causal_smoke", lambda **_kwargs: deepcopy(gate)
    )

    binding = smoke_validator.validate_causal_smoke_prerequisite(
        causal_root=tmp_path,
        causal_gate=gate,
        causal_provenance=causal_provenance,
    )
    assert binding["causal_smoke_gate_sha256"] == seal_module.canonical_sha256(gate)
    assert binding["causal_provenance_sha256"] == seal_module.canonical_sha256(
        causal_provenance
    )

    forged = {"decision": "pass", "errors": [], "status": "pass", "fake": True}
    with pytest.raises(ValueError, match="exact artifact revalidation"):
        smoke_validator.validate_causal_smoke_prerequisite(
            causal_root=tmp_path,
            causal_gate=forged,
            causal_provenance=causal_provenance,
        )


def test_launcher_syntax_and_same_seal_smoke_to_formal_gate_contract() -> None:
    launcher = Path(__file__).resolve().parents[1] / "launch_cohort_online_icl.sh"
    subprocess.run(["bash", "-n", str(launcher)], check=True)
    source = launcher.read_text()

    assert "--protocol-seal" in source
    assert "--icl-smoke-gate" in source
    assert "build_cohort_online_icl_protocol_seal.py" in source
    assert "from validate_cohort_causal_results import evaluate" in source
    assert "if evaluate(manifest) != decision:" in source
    assert 'decision.get("decision_scope") != "internal_gate_pass"' in source
    assert 'provenance.get("base_causal_commit") != causal_provenance.get(' in source
    assert "validate_causal_smoke_prerequisite" in source
    assert 'binding["causal_source_commit"] != online_provenance[' in source
    assert "revalidate_registered_formal_smoke_gate(" in source
    assert "causal_smoke_gate=causal_gate" in source
    assert "causal_provenance=causal_provenance" in source
    assert '[[ -e "$REPORT_OUTPUT" || -L "$REPORT_OUTPUT" ]]' in source
    assert "path.exists() or path.is_symlink()" in source
