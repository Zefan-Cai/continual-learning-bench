from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any

import pytest

import build_cohort_online_icl_formal_wrapper_contract_v3_adapter as online
import cohort_closed_loop_structured_trigger_receipt_revalidator_v3_adapter as independent
import cohort_closed_loop_structured_trigger_receipt_v3_adapter as structured


COMMIT = "a" * 40
PRIVATE_RECEIPT = b'{"private":"legacy-v1-receipt"}'
PRIVATE_REVALIDATOR_KWARGS = {"opaque_evidence": b"private-revalidation-evidence"}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _artifact_fixture(
    tmp_path: Path, *, include_seal: bool = True
) -> tuple[Path, dict[str, bytes], dict[str, str]]:
    root = (tmp_path / "attempt-002").resolve()
    names = set(structured.AUTHORITATIVE_RELATIVE_PATHS)
    if not include_seal:
        names.remove("execution_seal")
    payloads: dict[str, dict[str, Any]] = {
        "failure_closure": {
            "protocol": structured.FAILURE_CLOSURE_PROTOCOL,
            "schema_version": 1,
            "status": structured.FAILURE_CLOSURE_STATUS,
        },
        "completion_fence": {
            "protocol": structured.COMPLETION_FENCE_PROTOCOL,
            "schema_version": 3,
            "status": structured.COMPLETION_FENCE_STATUS,
        },
        "execution_plan": {
            "protocol": structured.PLAN_PROTOCOL,
            "schema_version": 3,
            "status": "registered",
        },
    }
    for name in names - set(payloads):
        payloads[name] = {
            "protocol": f"synthetic_{name}_v3",
            "schema_version": 3,
            "status": "synthetic_nonsemantic_fixture",
        }
    raws = {name: structured.canonical_bytes(payloads[name]) for name in sorted(names)}
    paths = {
        name: (root / structured.AUTHORITATIVE_RELATIVE_PATHS[name]).as_posix()
        for name in sorted(names)
    }
    return root, raws, paths


def _write_artifacts(root: Path, raws: dict[str, bytes]) -> None:
    for name, raw in raws.items():
        path = root / structured.AUTHORITATIVE_RELATIVE_PATHS[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def _structured_context(**kwargs: Any) -> dict[str, Any]:
    assert kwargs["require_execution_seal"] is True
    assert kwargs["adapter_kind"] == structured.BRANCH
    return {
        "attempt_id": kwargs["durable_attempt_root"].name,
        "causal_classification": {
            "decision": "valid_no_go",
            "decision_scope": "internal_gate_no_go",
            "status": "valid",
        },
        "private_projection": {
            "builder_kwargs": {"opaque_evidence": b"private-builder-evidence"},
            "revalidator_kwargs": PRIVATE_REVALIDATOR_KWARGS,
        },
        "tooling_source_commit": COMMIT,
        "truth_fields": structured.TRUTH_FIELDS,
    }


def _independent_context(**kwargs: Any) -> dict[str, Any]:
    assert kwargs["require_execution_seal"] is True
    assert kwargs["adapter_kind"] == independent.VALIDATOR_ADAPTER_KIND
    return {
        "attempt_id": kwargs["durable_attempt_root"].name,
        "causal_classification": {
            "decision": "valid_no_go",
            "decision_scope": "internal_gate_no_go",
            "status": "valid",
        },
        "private_projection": {
            "receipt_bytes": PRIVATE_RECEIPT,
            "revalidator_kwargs": PRIVATE_REVALIDATOR_KWARGS,
        },
        "tooling_source_commit": COMMIT,
        "truth_fields": independent.TRUTH_FIELDS,
    }


def _online_context(**kwargs: Any) -> dict[str, Any]:
    assert kwargs["require_execution_seal"] is False
    assert kwargs["adapter_kind"] == online.BRANCH
    return {
        "attempt_id": kwargs["durable_attempt_root"].name,
        "causal_classification": online.EXPECTED_CLASSIFICATION,
        "private_projection": {
            "contract_kwargs": {"opaque_evidence": b"private-online-evidence"}
        },
        "tooling_source_commit": COMMIT,
        "truth_fields": structured.TRUTH_FIELDS,
    }


def _legacy_builder(**kwargs: Any) -> bytes:
    assert kwargs == {"opaque_evidence": b"private-builder-evidence"}
    return PRIVATE_RECEIPT


def _legacy_revalidator(raw: bytes, **kwargs: Any) -> dict[str, Any]:
    assert raw == PRIVATE_RECEIPT
    assert kwargs == PRIVATE_REVALIDATOR_KWARGS
    return {
        "attempt_id": "attempt-002",
        "causal_decision_sha256": "b" * 64,
        "model_calls_authorized": False,
        "operational_authorization": False,
        "tooling_source_commit": COMMIT,
        "trigger_branch": "causal_valid_no_go",
        "trigger_receipt_sha256": _sha(raw),
    }


def _legacy_contract(**kwargs: Any) -> dict[str, Any]:
    assert kwargs == {"opaque_evidence": b"private-online-evidence"}
    return {
        "private_secret": "must-not-be-public",
        "protocol": online.LEGACY_CONTRACT_PROTOCOL,
        "schema_version": 1,
    }


def _structured_receipt(
    root: Path, raws: dict[str, bytes], paths: dict[str, str]
) -> bytes:
    return structured.build_trigger_a_receipt_v3_adapter_bytes(
        durable_attempt_root=root,
        authoritative_artifacts=raws,
        authoritative_paths=paths,
        authoritative_validator=_structured_context,
        legacy_builder=_legacy_builder,
    )


def test_structured_adapter_returns_only_truthful_v3_envelope(tmp_path: Path) -> None:
    root, raws, paths = _artifact_fixture(tmp_path)
    events: list[str] = []

    def validator(**kwargs: Any) -> dict[str, Any]:
        events.append("authoritative-v3")
        return _structured_context(**kwargs)

    def legacy(**kwargs: Any) -> bytes:
        events.append("private-legacy")
        return _legacy_builder(**kwargs)

    raw = structured.build_trigger_a_receipt_v3_adapter_bytes(
        durable_attempt_root=root,
        authoritative_artifacts=raws,
        authoritative_paths=paths,
        authoritative_validator=validator,
        legacy_builder=legacy,
    )
    envelope = structured.validate_adapter_envelope_bytes(raw)
    assert events == ["authoritative-v3", "private-legacy"]
    assert envelope["legacy_strict_mtime_proof"] is False
    assert envelope["mtime_relation"] == (
        "formal_manifest_before_formal_decision_equal_wrapper_exit"
    )
    assert envelope["completion_method"] == ("post-wrapper-death two-snapshot fence")
    assert envelope["historical_exit_order_claimed"] is False
    assert envelope["legacy_publication"] is False
    assert envelope["model_calls_authorized"] is False
    assert envelope["operational_authorization"] is False
    assert PRIVATE_RECEIPT not in raw
    assert b"cohort_structured_trigger_receipt_v1" not in raw


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        (
            "failure_closure",
            {
                "protocol": "cohort_causal_terminal_verifier_v2_failure_closure_v0",
                "schema_version": 1,
                "status": structured.FAILURE_CLOSURE_STATUS,
            },
        ),
        (
            "completion_fence",
            {
                "protocol": structured.COMPLETION_FENCE_PROTOCOL,
                "schema_version": 2,
                "status": structured.COMPLETION_FENCE_STATUS,
            },
        ),
        (
            "execution_plan",
            {
                "protocol": "cohort_causal_terminal_verifier_execution_plan_v2",
                "schema_version": 2,
                "status": "registered",
            },
        ),
    ],
)
def test_authoritative_precheck_blocks_semantic_engine(
    tmp_path: Path, name: str, replacement: dict[str, Any]
) -> None:
    root, raws, paths = _artifact_fixture(tmp_path)
    raws[name] = structured.canonical_bytes(replacement)
    opened = False

    def semantic_sentinel(**_: Any) -> bytes:
        nonlocal opened
        opened = True
        raise AssertionError("semantic engine opened")

    with pytest.raises(structured.V3TriggerAdapterError):
        structured.build_trigger_a_receipt_v3_adapter_bytes(
            durable_attempt_root=root,
            authoritative_artifacts=raws,
            authoritative_paths=paths,
            authoritative_validator=_structured_context,
            legacy_builder=semantic_sentinel,
        )
    assert opened is False


def test_structured_adapter_rejects_wrong_path_missing_seal_and_extra_input(
    tmp_path: Path,
) -> None:
    root, raws, paths = _artifact_fixture(tmp_path)
    wrong_paths = dict(paths)
    wrong_paths["execution_plan"] = (
        root / "control/CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V2.json"
    ).as_posix()
    with pytest.raises(structured.V3TriggerAdapterError, match="path differs"):
        _structured_receipt(root, raws, wrong_paths)

    missing = dict(raws)
    del missing["execution_seal"]
    with pytest.raises(structured.V3TriggerAdapterError, match="names differ"):
        _structured_receipt(root, missing, paths)

    extra = dict(raws)
    extra["v2_poison"] = b"{}"
    with pytest.raises(structured.V3TriggerAdapterError, match="names differ"):
        _structured_receipt(root, extra, paths)


def test_independent_revalidator_never_imports_or_calls_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = Path(independent.__file__).read_text()
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "cohort_closed_loop_structured_trigger_receipt_v3_adapter" not in imported
    assert "cohort_closed_loop_structured_trigger_receipt" not in imported

    root, raws, paths = _artifact_fixture(tmp_path)
    receipt = _structured_receipt(root, raws, paths)
    original_import = independent.importlib.import_module

    def poisoned_import(name: str):
        if name in {
            "cohort_closed_loop_structured_trigger_receipt_v3_adapter",
            "cohort_closed_loop_structured_trigger_receipt",
        }:
            raise AssertionError("builder import attempted")
        return original_import(name)

    monkeypatch.setattr(independent.importlib, "import_module", poisoned_import)
    raw = independent.revalidate_trigger_a_receipt_v3_adapter_bytes(
        receipt,
        durable_attempt_root=root,
        authoritative_artifacts=raws,
        authoritative_paths=paths,
        authoritative_validator=_independent_context,
        legacy_revalidator=_legacy_revalidator,
    )
    envelope = independent.validate_revalidation_envelope_bytes(raw)
    assert envelope["legacy_publication"] is False
    assert envelope["model_calls_authorized"] is False
    assert envelope["outcome_blind_adapter_registration"] is True
    assert PRIVATE_RECEIPT not in raw


def test_independent_revalidator_rejects_drift_before_private_engine(
    tmp_path: Path,
) -> None:
    root, raws, paths = _artifact_fixture(tmp_path)
    receipt = _structured_receipt(root, raws, paths)
    poisoned = dict(raws)
    poisoned["detached_receipt"] += b" "
    called = False

    def sentinel(*_: Any, **__: Any) -> object:
        nonlocal called
        called = True
        raise AssertionError("legacy revalidator opened")

    with pytest.raises(
        independent.V3TriggerRevalidatorAdapterError,
        match="bindings differ",
    ):
        independent.revalidate_trigger_a_receipt_v3_adapter_bytes(
            receipt,
            durable_attempt_root=root,
            authoritative_artifacts=poisoned,
            authoritative_paths=paths,
            authoritative_validator=_independent_context,
            legacy_revalidator=sentinel,
        )
    assert called is False


def test_online_adapter_binds_future_pass_without_authorizing(tmp_path: Path) -> None:
    root, raws, paths = _artifact_fixture(tmp_path, include_seal=False)
    events: list[str] = []

    def validator(**kwargs: Any) -> dict[str, Any]:
        events.append("authoritative-v3")
        return _online_context(**kwargs)

    def legacy(**kwargs: Any) -> dict[str, Any]:
        events.append("private-legacy")
        return _legacy_contract(**kwargs)

    raw = online.build_online_icl_formal_wrapper_contract_v3_adapter_bytes(
        durable_attempt_root=root,
        authoritative_artifacts=raws,
        authoritative_paths=paths,
        authoritative_validator=validator,
        legacy_contract_builder=legacy,
    )
    envelope = online.validate_online_icl_adapter_envelope_bytes(raw)
    assert events == ["authoritative-v3", "private-legacy"]
    assert envelope["causal_classification"] == online.EXPECTED_CLASSIFICATION
    assert envelope["legacy_publication"] is False
    assert envelope["model_calls_authorized"] is False
    assert envelope["operational_authorization"] is False
    assert b"must-not-be-public" not in raw
    assert online.LEGACY_CONTRACT_PROTOCOL.encode() not in raw


def test_wrong_branch_blocks_online_legacy_engine(tmp_path: Path) -> None:
    root, raws, paths = _artifact_fixture(tmp_path, include_seal=False)
    called = False

    def wrong_branch(**kwargs: Any) -> dict[str, Any]:
        context = _online_context(**kwargs)
        context["causal_classification"] = {
            "decision": "valid_no_go",
            "decision_scope": "internal_gate_no_go",
            "status": "valid",
        }
        return context

    def sentinel(**_: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        raise AssertionError("online engine opened")

    with pytest.raises(online.V3OnlineICLAdapterError, match="branch differs"):
        online.build_online_icl_formal_wrapper_contract_v3_adapter_bytes(
            durable_attempt_root=root,
            authoritative_artifacts=raws,
            authoritative_paths=paths,
            authoritative_validator=wrong_branch,
            legacy_contract_builder=sentinel,
        )
    assert called is False


def test_root_loader_rejects_symlink_missing_and_preexisting_output(
    tmp_path: Path,
) -> None:
    root, raws, _ = _artifact_fixture(tmp_path)
    _write_artifacts(root, raws)
    output = tmp_path / "prospective.json"
    output.write_bytes(b"occupied")
    with pytest.raises(FileExistsError):
        structured.build_trigger_a_receipt_v3_adapter_from_root(
            durable_attempt_root=root,
            prospective_output_path=output,
            authoritative_validator=_structured_context,
            legacy_builder=_legacy_builder,
        )

    output.unlink()
    missing = root / structured.AUTHORITATIVE_RELATIVE_PATHS["launch_claim"]
    missing.unlink()
    with pytest.raises(structured.V3TriggerAdapterError, match="missing"):
        structured.build_trigger_a_receipt_v3_adapter_from_root(
            durable_attempt_root=root,
            prospective_output_path=output,
            authoritative_validator=_structured_context,
            legacy_builder=_legacy_builder,
        )

    missing.write_bytes(raws["launch_claim"])
    target = tmp_path / "real-claim.json"
    target.write_bytes(raws["launch_claim"])
    missing.unlink()
    missing.symlink_to(target)
    with pytest.raises(structured.V3TriggerAdapterError, match="symlink"):
        structured.build_trigger_a_receipt_v3_adapter_from_root(
            durable_attempt_root=root,
            prospective_output_path=output,
            authoritative_validator=_structured_context,
            legacy_builder=_legacy_builder,
        )
    assert not output.exists()


def test_root_loader_detects_cross_validation_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, raws, _ = _artifact_fixture(tmp_path)
    _write_artifacts(root, raws)
    output = tmp_path / "prospective.json"
    target = root / structured.AUTHORITATIVE_RELATIVE_PATHS["completion_fence"]
    real_reader = structured._read_stable_no_symlink
    reads = 0

    def drifting_reader(path: Path) -> bytes:
        nonlocal reads
        raw = real_reader(path)
        if path == target:
            reads += 1
            if reads > 1:
                return raw + b" "
        return raw

    monkeypatch.setattr(structured, "_read_stable_no_symlink", drifting_reader)
    with pytest.raises(structured.V3TriggerAdapterError, match="drifted"):
        structured.build_trigger_a_receipt_v3_adapter_from_root(
            durable_attempt_root=root,
            prospective_output_path=output,
            authoritative_validator=_structured_context,
            legacy_builder=_legacy_builder,
        )
    assert not output.exists()


def test_root_loader_rejects_bad_closure_before_semantic_file_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, raws, _ = _artifact_fixture(tmp_path)
    raws["failure_closure"] = structured.canonical_bytes(
        {
            "protocol": "poisoned_v2_closure",
            "schema_version": 1,
            "status": structured.FAILURE_CLOSURE_STATUS,
        }
    )
    _write_artifacts(root, raws)
    output = tmp_path / "prospective.json"
    semantic = root / structured.AUTHORITATIVE_RELATIVE_PATHS["revalidated_decision"]
    real_reader = structured._read_stable_no_symlink
    opened: list[Path] = []

    def sentinel_reader(path: Path) -> bytes:
        opened.append(path)
        if path == semantic:
            raise AssertionError("semantic decision opened before V3 closure")
        return real_reader(path)

    monkeypatch.setattr(structured, "_read_stable_no_symlink", sentinel_reader)
    with pytest.raises(structured.V3TriggerAdapterError, match="failure closure"):
        structured.build_trigger_a_receipt_v3_adapter_from_root(
            durable_attempt_root=root,
            prospective_output_path=output,
            authoritative_validator=_structured_context,
            legacy_builder=_legacy_builder,
        )
    assert semantic not in opened
    assert not output.exists()


def test_root_loader_happy_path_never_publishes(tmp_path: Path) -> None:
    root, raws, _ = _artifact_fixture(tmp_path)
    _write_artifacts(root, raws)
    output = tmp_path / "prospective.json"
    raw = structured.build_trigger_a_receipt_v3_adapter_from_root(
        durable_attempt_root=root,
        prospective_output_path=output,
        authoritative_validator=_structured_context,
        legacy_builder=_legacy_builder,
    )
    structured.validate_adapter_envelope_bytes(raw)
    assert not output.exists()


def test_envelope_tampering_is_fail_closed(tmp_path: Path) -> None:
    root, raws, paths = _artifact_fixture(tmp_path)
    raw = _structured_receipt(root, raws, paths)
    value = structured.strict_json_object(raw, "fixture")
    value["legacy_strict_mtime_proof"] = True
    with pytest.raises(structured.V3TriggerAdapterError):
        structured.validate_adapter_envelope_bytes(structured.canonical_bytes(value))
