from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import build_cohort_online_icl_provenance as provenance


@pytest.fixture(autouse=True)
def stub_shared_causal_parity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provenance,
        "verify_shared_causal_parity",
        lambda **_kwargs: {
            "base_causal_commit": provenance.BASE_CAUSAL_COMMIT,
            "files": [],
            "inventory_sha256": "c" * 64,
            "kind": "cohort_shared_causal_parity",
            "schema_version": 1,
        },
    )


def _run(command: list[str], *, cwd: Path) -> str:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _make_checkout(tmp_path: Path, *, omit: str | None = None) -> Path:
    """Materialize future allowlist files without depending on other agents."""

    root = tmp_path / "repo"
    root.mkdir()
    for index, relative in enumerate(provenance.EVALUATION_CODE_ALLOWLIST):
        if relative == omit:
            continue
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"evaluation-file-{index}\n")
    _run(["git", "init", "-q"], cwd=root)
    _run(["git", "config", "user.email", "provenance@example.test"], cwd=root)
    _run(["git", "config", "user.name", "Provenance Test"], cwd=root)
    _run(["git", "add", "."], cwd=root)
    _run(["git", "commit", "-qm", "fixture"], cwd=root)
    provenance.BASE_CAUSAL_COMMIT = _run(["git", "rev-parse", "HEAD"], cwd=root)
    return root


def _make_model(tmp_path: Path) -> Path:
    model = tmp_path / "model"
    model.mkdir()
    (model / "config.json").write_text('{"model_type":"tiny"}\n')
    (model / "generation_config.json").write_text('{"max_new_tokens":8}\n')
    (model / "model-00001-of-00001.safetensors").write_bytes(b"tiny-weights")
    (model / "model.safetensors.index.json").write_text(
        json.dumps(
            {
                "metadata": {},
                "weight_map": {"layer.weight": "model-00001-of-00001.safetensors"},
            }
        )
    )
    (model / "tokenizer.json").write_text('{"version":"1.0"}\n')
    (model / "tokenizer_config.json").write_text('{"model_max_length":32}\n')
    return model


def _environment() -> dict:
    return {
        "pip_freeze_all": ["pip==26.0", "torch==2.9.0"],
        "platform": {
            "machine": "test-machine",
            "platform": "TestOS-1",
            "python_implementation": "CPython",
            "release": "1",
            "system": "TestOS",
            "version": "1.0",
        },
        "python": {
            "compiler": "test-compiler",
            "implementation": "CPython",
            "runtime_version": "3.10.0",
            "version_info": [3, 10, 0, "final", 0],
        },
        "runtime_versions": {
            "nvidia_driver_versions": ["600.1"],
            "torch": {
                "cuda_available": True,
                "cuda_build_version": "13.0",
                "installed": True,
                "torch_version": "2.9.0",
            },
        },
    }


def test_explicit_allowlist_is_sorted_unique_and_binds_future_surface() -> None:
    assert provenance.EVALUATION_CODE_ALLOWLIST == tuple(
        sorted(set(provenance.EVALUATION_CODE_ALLOWLIST))
    )
    required_future = {
        "build_cohort_online_icl_protocol_seal.py",
        "cohort_shared_causal_parity.py",
        "data/cohort_studies/online_icl_smoke_adapt_2026071496/manifest.json",
        "data/cohort_studies/online_icl_smoke_eval_2026071497/manifest.json",
        "generate_cohort_online_icl_grid.py",
        "grid_cohort_online_icl_formal.json",
        "grid_cohort_online_icl_smoke.json",
        "launch_cohort_online_icl.sh",
        "run_cohort_online_icl.py",
        "validate_cohort_online_icl_results.py",
        "validate_cohort_online_icl_smoke.py",
    }
    assert required_future <= set(provenance.EVALUATION_CODE_ALLOWLIST)


def test_bundle_is_deterministic_and_binds_full_contract(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)

    first = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    second = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )

    assert first == second
    consumer, details = first
    assert set(consumer) == provenance.REQUIRED_PROVENANCE_FIELDS
    assert consumer["source_commit"] == _run(["git", "rev-parse", "HEAD"], cwd=root)
    assert consumer["base_causal_commit"] == provenance.BASE_CAUSAL_COMMIT
    assert consumer["protocol"] == provenance.ONLINE_ICL_PROTOCOL
    assert consumer["model_path"] == str(model)
    assert details["provenance"] == consumer
    assert details["environment"]["sha256"] == consumer["environment_lock_sha256"]
    assert (
        details["evaluation_code"]["inventory_sha256"]
        == consumer["evaluation_code_sha256"]
    )
    assert details["model"]["inventory_sha256"] == consumer["model_sha256"]
    assert details["tokenizer"]["inventory_sha256"] == consumer["tokenizer_sha256"]
    assert details["preregistration"]["sha256"] == consumer["icl_prereg_sha256"]
    assert (
        details["shared_causal_code"]["inventory_sha256"]
        == consumer["shared_causal_code_sha256"]
    )


def test_dirty_tracked_checkout_is_refused(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    (root / provenance.EVALUATION_CODE_ALLOWLIST[0]).write_text("dirty\n")

    with pytest.raises(
        RuntimeError, match="dirty tracked checkout|tracked or unregistered"
    ):
        provenance.create_provenance_bundle(
            root=root,
            model_path=model,
            environment_payload=_environment(),
        )


def test_untracked_non_allowlist_file_is_refused(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    (root / "unexpected_runtime_override.py").write_text("raise SystemExit\n")

    with pytest.raises(RuntimeError, match="tracked or unregistered"):
        provenance.create_provenance_bundle(
            root=root,
            model_path=model,
            environment_payload=_environment(),
        )


def test_registered_runtime_artifacts_allow_parallel_verification(
    tmp_path: Path,
) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    artifact = root / "artifacts/cohort_online_icl/formal-cell.live.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"status":"running"}\n')

    consumer, _details = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    assert consumer["source_commit"] == _run(["git", "rev-parse", "HEAD"], cwd=root)


def test_source_commit_must_descend_from_registered_causal_base(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    provenance.BASE_CAUSAL_COMMIT = "0" * 40

    with pytest.raises(RuntimeError, match="does not descend"):
        provenance.create_provenance_bundle(
            root=root,
            model_path=model,
            environment_payload=_environment(),
        )


def test_missing_required_evaluation_file_fails_closed(tmp_path: Path) -> None:
    missing = provenance.EVALUATION_CODE_ALLOWLIST[-1]
    root = _make_checkout(tmp_path, omit=missing)

    with pytest.raises(FileNotFoundError, match="required evaluation code"):
        provenance.hash_evaluation_code(root)


def test_untracked_allowlist_file_fails_closed(tmp_path: Path) -> None:
    missing = "run_cohort_online_icl.py"
    root = _make_checkout(tmp_path, omit=missing)
    path = root / missing
    path.write_text("untracked future runner\n")
    assert _run(["git", "status", "--porcelain=v1"], cwd=root).startswith("?? ")

    with pytest.raises(RuntimeError, match="must be tracked by Git"):
        provenance.hash_evaluation_code(root)


@pytest.mark.parametrize(
    "environment",
    [
        {**_environment(), "api_key": "not-for-artifacts"},
        {**_environment(), "SLACK_BOT_TOKEN": "not-for-artifacts"},
        {**_environment(), "endpoint": "https://user:password@packages.test/x"},
        {**_environment(), "note": "github_" "pat_abcdefghijklmnopqrstuvwxyz1234"},
    ],
)
def test_secret_shaped_environment_fails_closed(
    tmp_path: Path, environment: dict
) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)

    with pytest.raises(ValueError, match="secret|credential"):
        provenance.create_provenance_bundle(
            root=root,
            model_path=model,
            environment_payload=environment,
        )


def test_atomic_outputs_never_overwrite(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, details = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    output = tmp_path / "provenance.json"
    sidecar = tmp_path / "provenance.details.json"

    provenance.write_provenance_bundle(
        output=output,
        details_output=sidecar,
        provenance=consumer,
        details=details,
    )
    original_output = output.read_bytes()
    original_sidecar = sidecar.read_bytes()
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        provenance.write_provenance_bundle(
            output=output,
            details_output=sidecar,
            provenance=consumer,
            details=details,
        )

    assert output.read_bytes() == original_output
    assert sidecar.read_bytes() == original_sidecar
    assert json.loads(output.read_text()) == consumer
    assert json.loads(sidecar.read_text()) == details


def test_runtime_verifier_accepts_exact_bundle_and_rejects_drift(
    tmp_path: Path,
) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    assert (
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=model,
            environment_payload=_environment(),
        )
        == consumer
    )

    tracked = root / "src/systems/qwen_local/system.py"
    tracked.write_text("committed evaluation drift\n")
    _run(["git", "add", str(tracked)], cwd=root)
    _run(["git", "commit", "-qm", "drift"], cwd=root)

    with pytest.raises(RuntimeError) as caught:
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=model,
            environment_payload=_environment(),
        )
    assert "evaluation_code_sha256" in str(caught.value)
    assert "source_commit" in str(caught.value)


@pytest.mark.parametrize(
    "field,tampered",
    [
        ("base_causal_commit", "0" * 40),
        ("environment_lock_sha256", "0" * 64),
        ("icl_prereg_sha256", "0" * 64),
        ("protocol", "different_protocol"),
        ("shared_causal_code_sha256", "0" * 64),
    ],
)
def test_runtime_verifier_recomputes_fixed_and_content_bindings(
    tmp_path: Path, field: str, tampered: str
) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    stale = deepcopy(consumer)
    stale[field] = tampered

    with pytest.raises(RuntimeError, match=field):
        provenance.verify_current_provenance(
            root=root,
            provenance=stale,
            expected_model_path=model,
            environment_payload=_environment(),
        )


def test_runtime_verifier_rejects_model_tokenizer_and_path_drift(
    tmp_path: Path,
) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )

    with pytest.raises(RuntimeError, match="model path"):
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=tmp_path / "other-model",
            environment_payload=_environment(),
        )

    weight = model / "model-00001-of-00001.safetensors"
    weight.write_bytes(weight.read_bytes() + b"-drift")
    with pytest.raises(RuntimeError, match="model_sha256"):
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=model,
            environment_payload=_environment(),
        )

    weight.write_bytes(b"tiny-weights")
    tokenizer = model / "tokenizer.json"
    tokenizer.write_bytes(tokenizer.read_bytes() + b"-drift")
    with pytest.raises(RuntimeError, match="tokenizer_sha256"):
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=model,
            environment_payload=_environment(),
        )
