from __future__ import annotations

import hashlib
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import build_cohort_causal_provenance as provenance
from run_cohort_causal import REQUIRED_PROVENANCE_FIELDS
import validate_cohort_causal_results as validator


@pytest.fixture(autouse=True)
def _fast_publication_fence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validator, "PUBLISHED_STABILITY_SECONDS", 0.0)


def _run(command: list[str], *, cwd: Path) -> str:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _make_checkout(tmp_path: Path, *, omit: str | None = None) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    for index, relative in enumerate(provenance.EVALUATION_CODE_ALLOWLIST):
        if relative == omit:
            continue
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative in {
            "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V1.md",
            "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V2.md",
            "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V3.md",
            "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V4.md",
            "COHORT_QONLY_CAUSAL_SCHEMA_RETRY_AMENDMENT_V5.md",
            provenance.STATISTICAL_ADDENDUM_FILENAME,
        }:
            path.write_bytes((provenance.ROOT / relative).read_bytes())
        else:
            path.write_text(f"evaluation-file-{index}\n")
    _run(["git", "init", "-q"], cwd=root)
    _run(["git", "config", "user.email", "provenance@example.test"], cwd=root)
    _run(["git", "config", "user.name", "Provenance Test"], cwd=root)
    _run(["git", "add", "."], cwd=root)
    _run(["git", "commit", "-qm", "fixture"], cwd=root)
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


def test_bundle_is_deterministic_and_matches_runner_contract(tmp_path: Path) -> None:
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
    assert set(consumer) == REQUIRED_PROVENANCE_FIELDS
    assert consumer["source_commit"] == _run(["git", "rev-parse", "HEAD"], cwd=root)
    assert len(consumer["source_commit"]) == 40
    assert details["provenance"] == consumer
    assert details["model"]["inventory_sha256"] == consumer["model_sha256"]
    assert details["tokenizer"]["inventory_sha256"] == consumer["tokenizer_sha256"]
    assert details["environment"]["sha256"] == consumer["environment_lock_sha256"]
    assert (
        consumer["statistical_addendum_sha256"]
        == provenance.EXPECTED_STATISTICAL_ADDENDUM_SHA256
        == details["statistical_addendum"]["sha256"]
    )


@pytest.mark.parametrize(
    "amendment",
    [
        "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V1.md",
        "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V2.md",
        "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V3.md",
        "COHORT_QONLY_CAUSAL_INFRASTRUCTURE_RETRY_AMENDMENT_V4.md",
        "COHORT_QONLY_CAUSAL_SCHEMA_RETRY_AMENDMENT_V5.md",
    ],
)
def test_evaluation_inventory_binds_infrastructure_retry_amendments(
    tmp_path: Path, amendment: str
) -> None:
    root = _make_checkout(tmp_path)
    inventory = provenance.hash_evaluation_code(root)
    record = next(item for item in inventory["files"] if item["path"] == amendment)

    expected = (provenance.ROOT / amendment).read_bytes()
    assert amendment in inventory["allowlist"]
    assert record["sha256"] == hashlib.sha256(expected).hexdigest()
    assert record["size_bytes"] == len(expected)

    before = inventory["inventory_sha256"]
    (root / amendment).write_bytes(expected + b"\n")
    _run(["git", "add", amendment], cwd=root)
    _run(["git", "commit", "-qm", "change retry amendment"], cwd=root)
    assert provenance.hash_evaluation_code(root)["inventory_sha256"] != before


def test_provenance_disables_bytecode_before_checkout_local_imports() -> None:
    source = (provenance.ROOT / "build_cohort_causal_provenance.py").read_text()
    guard = source.index("sys.dont_write_bytecode = True")
    assert guard < source.index("from generate_cohort_causal_grid import")
    assert guard < source.index("from run_cohort_causal import")
    assert guard < source.index("from validate_cohort_causal_results import")


def test_statistical_addendum_tamper_fails_closed(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    addendum = root / provenance.STATISTICAL_ADDENDUM_FILENAME
    addendum.write_bytes(addendum.read_bytes() + b"\n")

    with pytest.raises(RuntimeError, match="statistical addendum bytes"):
        provenance.hash_statistical_addendum(root)


def test_model_tamper_changes_only_content_bound_digest(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    before, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    weight = model / "model-00001-of-00001.safetensors"
    weight.write_bytes(weight.read_bytes() + b"-tampered")

    after, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )

    assert after["model_sha256"] != before["model_sha256"]
    assert after["tokenizer_sha256"] == before["tokenizer_sha256"]
    assert after["evaluation_code_sha256"] == before["evaluation_code_sha256"]

    tokenizer = model / "tokenizer.json"
    tokenizer.write_bytes(tokenizer.read_bytes() + b"-tampered")
    tokenizer_after, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    assert tokenizer_after["model_sha256"] == after["model_sha256"]
    assert tokenizer_after["tokenizer_sha256"] != after["tokenizer_sha256"]


def test_dirty_tracked_checkout_is_refused(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    tracked = root / provenance.EVALUATION_CODE_ALLOWLIST[0]
    tracked.write_text("dirty\n")

    with pytest.raises(RuntimeError, match="dirty tracked checkout"):
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


def test_untracked_statistical_addendum_fails_closed(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path, omit=provenance.STATISTICAL_ADDENDUM_FILENAME)
    addendum = root / provenance.STATISTICAL_ADDENDUM_FILENAME
    addendum.write_bytes(
        (provenance.ROOT / provenance.STATISTICAL_ADDENDUM_FILENAME).read_bytes()
    )
    assert _run(["git", "status", "--porcelain=v1"], cwd=root).startswith("?? ")

    with pytest.raises(RuntimeError, match="must be tracked by Git"):
        provenance.hash_evaluation_code(root)


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


def test_consumer_collision_preserves_published_provenance_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, details = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    output = tmp_path / "provenance.json"
    sidecar = tmp_path / "provenance.details.json"
    original_publish = provenance._publish_atomic_no_overwrite

    def collide(path: Path, payload: bytes) -> None:
        if path == output:
            path.write_bytes(b"concurrent-authority")
            raise FileExistsError("concurrent authority")
        original_publish(path, payload)

    monkeypatch.setattr(provenance, "_publish_atomic_no_overwrite", collide)

    with pytest.raises(FileExistsError, match="concurrent authority"):
        provenance.write_provenance_bundle(
            output=output,
            details_output=sidecar,
            provenance=consumer,
            details=details,
        )

    assert output.read_bytes() == b"concurrent-authority"
    assert json.loads(sidecar.read_text()) == details


def test_environment_payload_redacts_credentialed_freeze_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "super-secret-token"
    monkeypatch.setattr(
        provenance,
        "_run_text",
        lambda _command, cwd=None: (
            "safe==1.0\n"
            f"private @ https://user:{secret}@packages.test/private.whl"
            f"?token={secret}\n"
            f"-e git+https://oauth:{secret}@git.test/repo#egg=editable\n"
        ),
    )
    monkeypatch.setattr(
        provenance,
        "_torch_runtime",
        lambda: {"installed": True, "torch_version": "test"},
    )
    monkeypatch.setattr(provenance, "_nvidia_driver_versions", lambda: ["test"])

    payload = provenance.collect_environment_payload()
    rendered = json.dumps(payload, sort_keys=True)

    assert "safe==1.0" in payload["pip_freeze_all"]
    assert secret not in rendered
    assert "<url-sha256:" in rendered


def test_runtime_verifier_accepts_exact_current_bundle(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )

    verified = provenance.verify_current_provenance(
        root=root,
        provenance=consumer,
        expected_model_path=model,
        environment_payload=_environment(),
    )

    assert verified == consumer


def test_runtime_verifier_rejects_stale_committed_code(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    tracked = root / provenance.EVALUATION_CODE_ALLOWLIST[0]
    tracked.write_text("new committed evaluation code\n")
    _run(["git", "add", "."], cwd=root)
    _run(["git", "commit", "-qm", "change evaluation"], cwd=root)

    with pytest.raises(RuntimeError) as caught:
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=model,
            environment_payload=_environment(),
        )

    message = str(caught.value)
    assert "evaluation_code_sha256" in message
    assert "source_commit" in message


def test_runtime_verifier_rejects_stale_model(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    weight = model / "model-00001-of-00001.safetensors"
    weight.write_bytes(weight.read_bytes() + b"-stale")

    with pytest.raises(RuntimeError, match="model_sha256"):
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=model,
            environment_payload=_environment(),
        )


def test_runtime_verifier_rejects_stale_tokenizer(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    tokenizer = model / "tokenizer.json"
    tokenizer.write_bytes(tokenizer.read_bytes() + b"-stale")

    with pytest.raises(RuntimeError, match="tokenizer_sha256"):
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=model,
            environment_payload=_environment(),
        )


def test_runtime_verifier_rejects_dirty_tracked_checkout(tmp_path: Path) -> None:
    root = _make_checkout(tmp_path)
    model = _make_model(tmp_path)
    consumer, _ = provenance.create_provenance_bundle(
        root=root,
        model_path=model,
        environment_payload=_environment(),
    )
    (root / provenance.EVALUATION_CODE_ALLOWLIST[1]).write_text("dirty\n")

    with pytest.raises(RuntimeError, match="dirty tracked checkout"):
        provenance.verify_current_provenance(
            root=root,
            provenance=consumer,
            expected_model_path=model,
            environment_payload=_environment(),
        )


@pytest.mark.parametrize(
    "field,tampered",
    [
        ("adapter_init_seed", 0),
        ("environment_lock_sha256", "0" * 64),
        ("preregistered_parent_commit", "0" * 40),
        ("statistical_addendum_sha256", "0" * 64),
    ],
)
def test_runtime_verifier_recomputes_non_file_contract_fields(
    tmp_path: Path, field: str, tampered: object
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
