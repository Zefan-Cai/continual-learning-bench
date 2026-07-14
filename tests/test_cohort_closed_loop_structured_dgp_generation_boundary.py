from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

import cohort_closed_loop_structured_atomic_publish as atomic_publish
import cohort_closed_loop_structured_dgp_generation_boundary as boundary
import cohort_closed_loop_structured_stage_plan as stage_plan
from cohort_closed_loop_structured_dgp_context import (
    EXPECTED_STAGE_SEEDS,
    STAGE_SHAPES,
    PhaseKind,
    StageKind,
    build_corpus_inventory_bytes,
    canonical_json_bytes,
    load_corpus_inventory,
    make_dgp_row_identity,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _reseal(value: dict[str, Any], digest_key: str) -> bytes:
    unsigned = dict(value)
    unsigned.pop(digest_key, None)
    value[digest_key] = hashlib.sha256(_canonical(unsigned)).hexdigest()
    return _canonical(value)


def _publication_paths(path: str, durable_root: str) -> tuple[str, str]:
    relative = Path(path).relative_to(durable_root).as_posix()
    intent, pending = atomic_publish.publication_sidecar_relative_paths(relative)
    return f"{durable_root}/{intent}", f"{durable_root}/{pending}"


def _stage_plan_bytes(*, root: Path, stage: StageKind, source_bytes: bytes) -> bytes:
    durable_root = root.as_posix()
    source_commit = "1" * 40
    experiment_attempt_id = "attempt-001"
    stage_attempt_id = "attempt-001"
    paths = stage_plan._paths(  # noqa: SLF001
        durable_root=durable_root,
        source_commit=source_commit,
        experiment_attempt_id=experiment_attempt_id,
        stage=stage,
        stage_attempt_id=stage_attempt_id,
    )
    stage_root = str(paths["stage_root"])
    stage_plan_path = str(paths["stage_plan_path"])
    claim_path = str(paths["dgp_generation_claim_path"])
    completion_path = str(paths["dgp_completion_receipt_path"])
    source_path = "/synthetic-checkout/dgp_generator.py"
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    outputs = boundary._expected_output_inventory(  # noqa: SLF001
        durable_root=durable_root,
        stage_root=stage_root,
        stage=stage,
    )
    generator_invocation = {
        "provider_id": "dgp_generator_invocation",
        "provider_available": False,
        "runtime_executable_provider_id": "python_runtime_attester",
        "runtime_executable_provider_available": False,
        "runtime_executable_path": None,
        "generator_source_path": source_path,
        "generator_source_sha256": source_sha,
        "argv_after_runtime": [
            "-I",
            "-B",
            source_path,
            "--protocol-plan-seal",
            f"{durable_root}/control/structured_protocol_plan_seal.json",
            "--stage-plan",
            stage_plan_path,
            "--dgp-generation-claim",
            claim_path,
            "--dgp-completion-receipt",
            completion_path,
            "--stage-kind",
            stage.value,
            "--experiment-attempt-id",
            experiment_attempt_id,
            "--stage-attempt-id",
            stage_attempt_id,
            "--output-root",
            f"{stage_root}/dgp",
        ],
        "cwd": "/synthetic-checkout",
        "stdin": "devnull",
        "stdio_provider_id": "stdio_provider",
        "stdio_provider_available": False,
        "controlled_process_launcher_provider_id": "controlled_process_launcher",
        "controlled_process_launcher_provider_available": False,
        "generator_import_requires_committed_claim": True,
    }
    exact_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    unsigned: dict[str, object] = {
        "protocol": stage_plan.PROTOCOL,
        "schema_version": stage_plan.SCHEMA_VERSION,
        "status": stage_plan.STATUS,
        "source_commit": source_commit,
        "experiment_attempt_id": experiment_attempt_id,
        "stage_kind": stage.value,
        "stage_attempt_id": stage_attempt_id,
        "stage_shape": boundary._stage_shape(stage),  # noqa: SLF001
        "seeds": boundary._stage_seeds(stage),  # noqa: SLF001
        "paths": paths,
        "generator_invocation": generator_invocation,
        "source_role_bindings": [
            {
                "path": source_path,
                "role": "dgp_generator",
                "sha256": source_sha,
                "size_bytes": len(source_bytes),
            }
        ],
        "atomic_claim_protocol": {
            "claim_path": claim_path,
            "publication_intent_path": _publication_paths(claim_path, durable_root)[0],
            "publication_pending_path": _publication_paths(claim_path, durable_root)[1],
            "intent_o_excl_is_concurrency_serialization_point": True,
            "pending_created_with_o_excl": True,
            "pending_full_payload_write_required": True,
            "pending_fsync_before_chmod_required": True,
            "pending_chmod_mode": 0o444,
            "pending_fsync_after_chmod_required": True,
            "final_created_by_no_replace_hardlink": True,
            "precommit_final_and_pending_link_count": 2,
            "parent_fsync_after_final_hardlink_required": True,
            "fresh_precommit_ancestor_retraversal_required": True,
            "fresh_precommit_intent_full_bytes_required": True,
            "fresh_precommit_pending_final_same_inode_required": True,
            "fresh_precommit_final_full_bytes_required": True,
            "final_hardlink_visibility_is_not_commit_or_authorization": True,
            "pending_unlink_is_filesystem_commit_point": True,
            "parent_fsync_after_pending_unlink_required": True,
            "committed_final_link_count": 1,
            "committed_final_mode": 0o444,
            "fresh_committed_intent_present_required": True,
            "fresh_committed_pending_absent_required": True,
            "fresh_committed_final_full_bytes_required": True,
            "fresh_committed_full_path_observation_count": 2,
            "fresh_committed_full_path_observations_must_match": True,
            "direct_final_o_excl_forbidden": True,
            "rename_publication_forbidden": True,
            "fresh_semantically_validated_committed_final_required_before_generator_import": True,
            "generator_import_authorization_boundary": (
                "fresh_semantically_validated_intent_present_pending_absent_"
                "single_link_final"
            ),
            "adapter_source_sha256": _digest("claim-adapter"),
            "atomic_publisher_source_sha256": _digest("atomic-publisher"),
            "provider_id": "dgp_claim_atomic_adapter",
            "provider_available": False,
        },
        "completion_protocol": {
            "receipt_path": completion_path,
            "publication_intent_path": paths["dgp_completion_publication_intent_path"],
            "publication_pending_path": paths[
                "dgp_completion_publication_pending_path"
            ],
            "common_atomic_publication_contract_required": True,
            "committed_final_mode": 0o444,
            "committed_final_link_count": 1,
            "fresh_committed_full_path_observation_count": 2,
            "fresh_committed_full_path_observations_must_match": True,
            "adapter_source_sha256": _digest("completion-adapter"),
            "dgp_output_inventory_sha256": hashlib.sha256(
                _canonical(outputs)
            ).hexdigest(),
            "provider_id": "dgp_completion_adapter",
            "provider_available": False,
        },
        "dgp_output_inventory": outputs,
        "dgp_output_inventory_sha256": hashlib.sha256(_canonical(outputs)).hexdigest(),
        "dgp_generation_claim_eligible": False,
        "dgp_generator_import_authorized": False,
        "dgp_generation_authorized": False,
        "model_calls_authorized": False,
        "scorer_calls_authorized": False,
        "launch_authorized": False,
        "operational_authorization": False,
        "legacy_stage_plan_accepted": False,
        "closed_environment_policy": {
            "exact_environment": exact_environment,
            "allowed_names": sorted(exact_environment),
            "unlisted_names_forbidden": True,
            "secret_environment_forbidden": True,
            "attester_provider_id": "closed_environment_attester",
            "provider_available": False,
        },
        "resource_policy": {
            "job_identity_required": True,
            "job_identity_provider_id": "job_identity_attester",
            "job_identity_provider_available": False,
            "node_identity_required": True,
            "node_identity_provider_id": "node_identity_attester",
            "node_identity_provider_available": False,
            "gpu_inventory_required": True,
            "gpu_inventory_provider_id": "gpu_inventory_attester",
            "gpu_inventory_provider_available": False,
            "registered_job_id": None,
            "registered_node_id": None,
            "registered_gpu_type": None,
            "registered_gpu_count": None,
            "network_access_allowed": False,
            "network_isolation_provider_id": "network_isolation_attester",
            "network_isolation_provider_available": False,
        },
        "provider_status": {
            "required_provider_ids": list(  # noqa: SLF001
                stage_plan._REQUIRED_PROVIDER_IDS
            ),
            "providers": [
                {"available": False, "provider_id": provider_id}
                for provider_id in stage_plan._REQUIRED_PROVIDER_IDS  # noqa: SLF001
            ],
            "available_provider_ids": [],
            "missing_provider_ids": list(  # noqa: SLF001
                stage_plan._REQUIRED_PROVIDER_IDS
            ),
            "all_required_providers_available": False,
        },
    }
    for key in (
        stage_plan._KEYS
        - set(unsigned)
        - {  # noqa: SLF001
            "stage_plan_sha256"
        }
    ):
        unsigned[key] = None
    return _reseal(unsigned, "stage_plan_sha256")


def _make_outputs(
    *,
    stage: StageKind,
    generator_sha256: str,
    first_row_override: object | None = None,
    drift_first_generator: bool = False,
) -> tuple[dict[str, bytes], tuple[bytes, ...]]:
    outputs: dict[str, bytes] = {}
    corpus_raws: list[bytes] = []
    first = True
    for seed in EXPECTED_STAGE_SEEDS[stage]:
        for phase in (PhaseKind.ADAPTATION, PhaseKind.HELD_OUT):
            rows = []
            for item_id in range(1, STAGE_SHAPES[stage].items_per_phase + 1):
                label = f"{stage.value}:{seed.block_id}:{phase.value}:{item_id}"
                if first and item_id == 1 and first_row_override is not None:
                    row = first_row_override
                else:
                    row = make_dgp_row_identity(
                        item_id=item_id,
                        instance_id=f"instance-{label}",
                        query_sha256=_digest(f"query:{label}"),
                        database_sha256=_digest(f"database:{label}"),
                        ground_truth_sha256=_digest(f"truth:{label}"),
                        reference_survival_sha256=_digest(f"reference:{label}"),
                        schedule_entry_sha256=_digest(f"schedule:{label}"),
                    )
                rows.append(row)
            dgp_seed = (
                seed.adaptation_dgp_seed
                if phase is PhaseKind.ADAPTATION
                else seed.held_out_dgp_seed
            )
            corpus_generator = (
                _digest("drifted-generator")
                if first and drift_first_generator
                else generator_sha256
            )
            corpus_raw = build_corpus_inventory_bytes(
                stage_kind=stage,
                block_id=seed.block_id,
                block_index=seed.block_index,
                phase=phase,
                run_seed=seed.run_seed,
                dgp_seed=dgp_seed,
                dgp_generator_sha256=corpus_generator,
                dgp_arguments_sha256=_digest(f"arguments:{stage.value}"),
                cohort_layer_inventory_sha256=_digest(f"cohort-layers:{stage.value}"),
                rows=rows,
            )
            prefix = f"corpora/{seed.block_id}/{phase.value}"
            for row in rows:
                outputs[f"{prefix}/rows/{row.item_id}.json"] = canonical_json_bytes(
                    row.to_payload()
                )
            outputs[f"{prefix}/corpus_inventory.json"] = corpus_raw
            corpus_raws.append(corpus_raw)
            first = False
    return outputs, tuple(corpus_raws)


@dataclass(frozen=True)
class Fixture:
    root: Path
    stage: StageKind
    source: bytes
    plan: bytes
    outputs: dict[str, bytes]
    prior_corpora: tuple[bytes, ...] = ()


def _fixture(
    tmp_path: Path,
    *,
    stage: StageKind = StageKind.SMOKE,
    first_row_override: object | None = None,
    drift_first_generator: bool = False,
    prior_corpora: tuple[bytes, ...] = (),
) -> Fixture:
    root = (tmp_path / f"durable-{stage.value}").resolve()
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    source = b"def synthetic_dgp_generator():\n    raise RuntimeError('never run')\n"
    plan = _stage_plan_bytes(root=root, stage=stage, source_bytes=source)
    outputs, _ = _make_outputs(
        stage=stage,
        generator_sha256=hashlib.sha256(source).hexdigest(),
        first_row_override=first_row_override,
        drift_first_generator=drift_first_generator,
    )
    return Fixture(
        root=root,
        stage=stage,
        source=source,
        plan=plan,
        outputs=outputs,
        prior_corpora=prior_corpora,
    )


def _artifacts(fixture: Fixture) -> boundary._DgpGenerationBoundaryTestArtifacts:  # noqa: SLF001
    claim = boundary._claim_bytes(  # noqa: SLF001
        stage_plan_bytes=fixture.plan,
        generator_source_bytes=fixture.source,
    )
    invocation = boundary._invocation_bytes(  # noqa: SLF001
        stage_plan_bytes=fixture.plan,
        generator_source_bytes=fixture.source,
        claim_bytes=claim,
        generator_output_bytes_by_relative_path=fixture.outputs,
    )
    view = boundary._parse_stage_plan(fixture.plan)  # noqa: SLF001
    corpus_receipts = tuple(
        boundary._corpus_completion_bytes(  # noqa: SLF001
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            claim_bytes=claim,
            invocation_receipt_bytes=invocation,
            generator_output_bytes_by_relative_path=fixture.outputs,
            corpus_inventory_relative_path=(
                f"corpora/{block_id}/{phase.value}/corpus_inventory.json"
            ),
        )
        for block_id, _, phase in boundary._expected_corpus_coordinates(  # noqa: SLF001
            view.stage_kind
        )
    )
    completion = boundary._stage_completion_bytes(  # noqa: SLF001
        stage_plan_bytes=fixture.plan,
        generator_source_bytes=fixture.source,
        claim_bytes=claim,
        invocation_receipt_bytes=invocation,
        corpus_completion_receipt_bytes=corpus_receipts,
        generator_output_bytes_by_relative_path=fixture.outputs,
        prior_stage_corpus_inventory_bytes=fixture.prior_corpora,
    )
    return boundary._DgpGenerationBoundaryTestArtifacts(  # noqa: SLF001
        claim_bytes=claim,
        invocation_receipt_bytes=invocation,
        corpus_completion_receipt_bytes=corpus_receipts,
        stage_completion_receipt_bytes=completion,
    )


def test_public_provider_fails_before_input_filesystem_or_runtime_access() -> None:
    class Explodes:
        def __getattribute__(self, name: str) -> object:
            raise AssertionError(name)

    value = Explodes()
    assert boundary.PROVIDER_AVAILABLE is False
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="unavailable"):
        boundary.produce_dgp_generation_boundary(
            root=value,
            stage_plan_bytes=value,
            generator_source_bytes=value,
            generator_output_bytes_by_relative_path=value,
            prior_stage_corpus_inventory_bytes=value,
            runtime=value,
        )


def test_atomic_synthetic_chain_roundtrips_and_keeps_future_outputs_absent(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    artifacts = boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
        root=fixture.root,
        stage_plan_bytes=fixture.plan,
        generator_source_bytes=fixture.source,
        generator_output_bytes_by_relative_path=fixture.outputs,
    )
    claim_validation = boundary.validate_dgp_generation_claim_bytes(
        artifacts.claim_bytes,
        stage_plan_bytes=fixture.plan,
        generator_source_bytes=fixture.source,
    )
    invocation_validation = boundary.validate_dgp_invocation_receipt_bytes(
        artifacts.invocation_receipt_bytes,
        stage_plan_bytes=fixture.plan,
        generator_source_bytes=fixture.source,
        claim_bytes=artifacts.claim_bytes,
        generator_output_bytes_by_relative_path=fixture.outputs,
    )
    corpus_validations = tuple(
        boundary.validate_dgp_corpus_completion_receipt_bytes(
            raw,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            claim_bytes=artifacts.claim_bytes,
            invocation_receipt_bytes=artifacts.invocation_receipt_bytes,
            generator_output_bytes_by_relative_path=fixture.outputs,
        )
        for raw in artifacts.corpus_completion_receipt_bytes
    )
    stage_validation = boundary.validate_dgp_stage_completion_receipt_bytes(
        artifacts.stage_completion_receipt_bytes,
        stage_plan_bytes=fixture.plan,
        generator_source_bytes=fixture.source,
        claim_bytes=artifacts.claim_bytes,
        invocation_receipt_bytes=artifacts.invocation_receipt_bytes,
        corpus_completion_receipt_bytes=(artifacts.corpus_completion_receipt_bytes),
        generator_output_bytes_by_relative_path=fixture.outputs,
    )
    assert claim_validation.generator_output_count == 12
    assert claim_validation.future_output_count == 21
    assert invocation_validation.generator_execution_performed is False
    assert len(corpus_validations) == stage_validation.corpus_count == 2
    assert stage_validation.row_count == 10
    completion = json.loads(artifacts.stage_completion_receipt_bytes)
    assert completion["registrar_outputs_present"] is False
    assert completion["stage_manifest_present"] is False
    claim = json.loads(artifacts.claim_bytes)
    assert {row["writer_service"] for row in claim["generator_output_inventory"]} == {
        "dgp_generator"
    }
    assert {row["writer_service"] for row in claim["future_output_inventory"]} == {
        "context_registrar",
        "dgp_completion_adapter",
    }
    for row in claim["future_output_inventory"]:
        for key in (
            "path",
            "publication_intent_path",
            "publication_pending_path",
        ):
            assert not Path(row[key]).exists()


def test_claim_rejects_duplicate_nan_noncanonical_and_type_confusion(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    claim = boundary._claim_bytes(  # noqa: SLF001
        stage_plan_bytes=fixture.plan, generator_source_bytes=fixture.source
    )
    duplicate = claim.replace(
        b'"schema_version":2', b'"schema_version":2,"schema_version":2', 1
    )
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="duplicate"):
        boundary.validate_dgp_generation_claim_bytes(
            duplicate,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
        )
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="non-finite"):
        boundary.validate_dgp_generation_claim_bytes(
            b'{"value":NaN}',
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
        )
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="canonical"):
        boundary.validate_dgp_generation_claim_bytes(
            b" " + claim,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
        )
    confused = json.loads(claim)
    confused["schema_version"] = True
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="header"):
        boundary.validate_dgp_generation_claim_bytes(
            _reseal(confused, "dgp_generation_claim_sha256"),
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("protocol", "legacy_claim_v1"),
        ("schema_version", 1),
        ("source_commit", "2" * 40),
        ("experiment_attempt_id", "attempt-002"),
        ("stage_attempt_id", "attempt-002"),
        ("claim_path", "/tmp/wrong-claim.json"),
        ("generator_source_file_sha256", "3" * 64),
    ),
)
def test_claim_rejects_resealed_protocol_coordinate_path_and_source_drift(
    tmp_path: Path, field: str, value: object
) -> None:
    fixture = _fixture(tmp_path)
    claim = json.loads(
        boundary._claim_bytes(  # noqa: SLF001
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
        )
    )
    claim[field] = value
    forged = _reseal(claim, "dgp_generation_claim_sha256")
    with pytest.raises(boundary.DgpGenerationBoundaryError):
        boundary.validate_dgp_generation_claim_bytes(
            forged,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
        )


def test_raw_file_digest_edges_cannot_be_replaced_by_embedded_self_digests(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    artifacts = _artifacts(fixture)

    invocation = json.loads(artifacts.invocation_receipt_bytes)
    claim = json.loads(artifacts.claim_bytes)
    assert (
        hashlib.sha256(artifacts.claim_bytes).hexdigest()
        != claim["dgp_generation_claim_sha256"]
    )
    invocation["dgp_generation_claim_file_sha256"] = claim[
        "dgp_generation_claim_sha256"
    ]
    with pytest.raises(boundary.DgpGenerationBoundaryError):
        boundary.validate_dgp_invocation_receipt_bytes(
            _reseal(invocation, "dgp_invocation_receipt_sha256"),
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            claim_bytes=artifacts.claim_bytes,
            generator_output_bytes_by_relative_path=fixture.outputs,
        )

    corpus = json.loads(artifacts.corpus_completion_receipt_bytes[0])
    corpus["corpus_inventory_binding"]["file_sha256"] = corpus[
        "corpus_inventory_binding"
    ]["corpus_inventory_sha256"]
    with pytest.raises(boundary.DgpGenerationBoundaryError):
        boundary.validate_dgp_corpus_completion_receipt_bytes(
            _reseal(corpus, "dgp_corpus_completion_receipt_sha256"),
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            claim_bytes=artifacts.claim_bytes,
            invocation_receipt_bytes=artifacts.invocation_receipt_bytes,
            generator_output_bytes_by_relative_path=fixture.outputs,
        )

    stage = json.loads(artifacts.stage_completion_receipt_bytes)
    stage["corpus_completion_bindings"][0]["file_sha256"] = stage[
        "corpus_completion_bindings"
    ][0]["dgp_corpus_completion_receipt_sha256"]
    with pytest.raises(boundary.DgpGenerationBoundaryError):
        boundary.validate_dgp_stage_completion_receipt_bytes(
            _reseal(stage, "dgp_completion_receipt_sha256"),
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            claim_bytes=artifacts.claim_bytes,
            invocation_receipt_bytes=artifacts.invocation_receipt_bytes,
            corpus_completion_receipt_bytes=(artifacts.corpus_completion_receipt_bytes),
            generator_output_bytes_by_relative_path=fixture.outputs,
        )


def test_missing_extra_reordered_and_mutated_generator_outputs_fail(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    claim = boundary._claim_bytes(  # noqa: SLF001
        stage_plan_bytes=fixture.plan, generator_source_bytes=fixture.source
    )
    keys = sorted(fixture.outputs)
    row_keys = [key for key in keys if "/rows/" in key]
    cases: list[dict[str, bytes]] = []
    missing = dict(fixture.outputs)
    del missing[keys[0]]
    cases.append(missing)
    extra = dict(fixture.outputs)
    extra["contexts/future.json"] = b"{}"
    cases.append(extra)
    reordered = dict(fixture.outputs)
    reordered[row_keys[0]], reordered[row_keys[1]] = (
        reordered[row_keys[1]],
        reordered[row_keys[0]],
    )
    cases.append(reordered)
    mutated = dict(fixture.outputs)
    mutated[row_keys[0]] += b"\n"
    cases.append(mutated)
    for outputs in cases:
        with pytest.raises(boundary.DgpGenerationBoundaryError):
            boundary._invocation_bytes(  # noqa: SLF001
                stage_plan_bytes=fixture.plan,
                generator_source_bytes=fixture.source,
                claim_bytes=claim,
                generator_output_bytes_by_relative_path=outputs,
            )


def test_stage_completion_rejects_missing_and_reordered_corpus_receipts(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    artifacts = _artifacts(fixture)
    for receipts in (
        artifacts.corpus_completion_receipt_bytes[:-1],
        tuple(reversed(artifacts.corpus_completion_receipt_bytes)),
    ):
        with pytest.raises(boundary.DgpGenerationBoundaryError):
            boundary.validate_dgp_stage_completion_receipt_bytes(
                artifacts.stage_completion_receipt_bytes,
                stage_plan_bytes=fixture.plan,
                generator_source_bytes=fixture.source,
                claim_bytes=artifacts.claim_bytes,
                invocation_receipt_bytes=artifacts.invocation_receipt_bytes,
                corpus_completion_receipt_bytes=receipts,
                generator_output_bytes_by_relative_path=fixture.outputs,
            )


def test_any_resealed_authority_true_fails(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    artifacts = _artifacts(fixture)
    mutations = (
        (
            artifacts.claim_bytes,
            "dgp_generation_claim_sha256",
            boundary._parse_claim,  # noqa: SLF001
        ),
        (
            artifacts.invocation_receipt_bytes,
            "dgp_invocation_receipt_sha256",
            boundary._parse_invocation,  # noqa: SLF001
        ),
        (
            artifacts.corpus_completion_receipt_bytes[0],
            "dgp_corpus_completion_receipt_sha256",
            boundary._parse_corpus_completion,  # noqa: SLF001
        ),
        (
            artifacts.stage_completion_receipt_bytes,
            "dgp_completion_receipt_sha256",
            boundary._parse_stage_completion,  # noqa: SLF001
        ),
    )
    for raw, digest_key, parser in mutations:
        payload = json.loads(raw)
        payload["model_calls_authorized"] = True
        with pytest.raises(boundary.DgpGenerationBoundaryError, match="false"):
            parser(_reseal(payload, digest_key))


def test_future_registrar_output_appearing_before_completion_fails(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    view = boundary._parse_stage_plan(fixture.plan)  # noqa: SLF001
    future = Path(str(view.future_outputs[0]["path"]))

    def appear() -> None:
        future.write_bytes(b"future output must remain absent")
        future.chmod(0o444)

    runtime = boundary._DgpGenerationBoundaryTestRuntime(  # noqa: SLF001
        before_stage_completion=appear
    )
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="future"):
        boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
            root=fixture.root,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            generator_output_bytes_by_relative_path=fixture.outputs,
            runtime=runtime,
        )


@pytest.mark.parametrize("poison", ("replacement", "sidecar", "pending", "hardlink"))
def test_callback_replacement_sidecar_pending_and_linkcount_poison_fail(
    tmp_path: Path, poison: str
) -> None:
    fixture = _fixture(tmp_path)
    view = boundary._parse_stage_plan(fixture.plan)  # noqa: SLF001
    output = next(
        row for row in view.generator_outputs if row["role"] == "dgp_row_identity"
    )
    final = Path(str(output["path"]))
    intent = Path(str(output["publication_intent_path"]))
    pending = Path(str(output["publication_pending_path"]))
    raw = fixture.outputs[str(output["relative_path"])]

    def inject() -> None:
        if poison == "replacement":
            final.unlink()
            final.write_bytes(raw)
            final.chmod(0o444)
        elif poison == "sidecar":
            intent_raw = intent.read_bytes()
            intent.unlink()
            intent.write_bytes(intent_raw)
            intent.chmod(0o444)
        elif poison == "pending":
            pending.write_bytes(raw)
            pending.chmod(0o444)
        else:
            os.link(final, final.with_name("unexpected-hardlink.json"))

    runtime = boundary._DgpGenerationBoundaryTestRuntime(  # noqa: SLF001
        before_stage_completion=inject
    )
    with pytest.raises(boundary.DgpGenerationBoundaryError):
        boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
            root=fixture.root,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            generator_output_bytes_by_relative_path=fixture.outputs,
            runtime=runtime,
        )
    completion_paths = (
        view.stage_completion_receipt_path,
        *_publication_paths(view.stage_completion_receipt_path, view.durable_root),
    )
    assert all(not os.path.lexists(path) for path in completion_paths)


@pytest.mark.parametrize(
    "replacement",
    ("root_directory", "root_symlink", "parent_directory", "parent_symlink"),
)
def test_retained_root_and_parent_replacement_fail(
    tmp_path: Path, replacement: str
) -> None:
    fixture = _fixture(tmp_path)
    view = boundary._parse_stage_plan(fixture.plan)  # noqa: SLF001
    row = next(
        item for item in view.generator_outputs if item["role"] == "dgp_row_identity"
    )

    def replace_boundary() -> None:
        if replacement.startswith("root"):
            old = fixture.root.with_name(f"{fixture.root.name}-old")
            fixture.root.rename(old)
            if replacement == "root_directory":
                fixture.root.mkdir(mode=0o700)
            else:
                os.symlink(old, fixture.root, target_is_directory=True)
            return
        parent = Path(str(row["path"])).parent
        old = parent.with_name(f"{parent.name}-old")
        parent.rename(old)
        if replacement == "parent_directory":
            parent.mkdir(mode=0o755)
        else:
            os.symlink(old, parent, target_is_directory=True)

    runtime = boundary._DgpGenerationBoundaryTestRuntime(  # noqa: SLF001
        before_stage_completion=replace_boundary
    )
    with pytest.raises(
        boundary.DgpGenerationBoundaryError, match="root|parent|linked|identity"
    ):
        boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
            root=fixture.root,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            generator_output_bytes_by_relative_path=fixture.outputs,
            runtime=runtime,
        )


def test_generator_drift_and_prior_stage_collision_fail(tmp_path: Path) -> None:
    drifted = _fixture(tmp_path / "drift", drift_first_generator=True)
    drift_view = boundary._parse_stage_plan(drifted.plan)  # noqa: SLF001
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="generator"):
        boundary._validate_stage_corpora(  # noqa: SLF001
            drift_view, drifted.outputs, ()
        )

    source = b"def synthetic_dgp_generator():\n    raise RuntimeError('never run')\n"
    source_sha = hashlib.sha256(source).hexdigest()
    smoke_outputs, smoke_corpora = _make_outputs(
        stage=StageKind.SMOKE, generator_sha256=source_sha
    )
    first_prior = load_corpus_inventory(smoke_corpora[0]).rows[0]
    internal = _fixture(
        tmp_path / "collision",
        stage=StageKind.INTERNAL,
        first_row_override=first_prior,
        prior_corpora=smoke_corpora,
    )
    assert smoke_outputs
    internal_view = boundary._parse_stage_plan(internal.plan)  # noqa: SLF001
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="collision"):
        boundary._validate_stage_corpora(  # noqa: SLF001
            internal_view,
            internal.outputs,
            internal.prior_corpora,
        )


def test_wrong_stage_plan_path_and_exact_source_bytes_fail(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    plan = json.loads(fixture.plan)
    plan["paths"]["dgp_generation_claim_path"] = (
        f"{plan['paths']['stage_root']}/control/wrong.claim.json"
    )
    forged = _reseal(plan, "stage_plan_sha256")
    with pytest.raises(
        boundary.DgpGenerationBoundaryError, match="fixed|paths|publication"
    ):
        boundary._claim_bytes(  # noqa: SLF001
            stage_plan_bytes=forged,
            generator_source_bytes=fixture.source,
        )
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="source"):
        boundary._claim_bytes(  # noqa: SLF001
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source
            + b"# same semantic source, new bytes\n",
        )


def test_resealed_stage_plan_extra_key_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    plan = json.loads(fixture.plan)
    plan["unexpected_boundary_extension"] = {"all_authority": False}
    forged = _reseal(plan, "stage_plan_sha256")
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="exact top-level"):
        boundary._claim_bytes(  # noqa: SLF001
            stage_plan_bytes=forged,
            generator_source_bytes=fixture.source,
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda plan: plan["generator_invocation"].__setitem__(
            "provider_available", True
        ),
        lambda plan: plan["generator_invocation"].__setitem__(
            "runtime_executable_provider_available", True
        ),
        lambda plan: plan["closed_environment_policy"].__setitem__(
            "provider_available", True
        ),
        lambda plan: plan["resource_policy"].__setitem__(
            "gpu_inventory_provider_available", True
        ),
        lambda plan: plan["provider_status"]["providers"][0].__setitem__(
            "available", True
        ),
    ),
)
def test_resealed_nested_provider_availability_is_rejected(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None]
) -> None:
    fixture = _fixture(tmp_path)
    plan = json.loads(fixture.plan)
    mutate(plan)
    forged = _reseal(plan, "stage_plan_sha256")
    with pytest.raises(boundary.DgpGenerationBoundaryError):
        boundary._claim_bytes(  # noqa: SLF001
            stage_plan_bytes=forged,
            generator_source_bytes=fixture.source,
        )


@pytest.mark.parametrize("drift", ("legacy", "available_ids", "all_required"))
def test_resealed_legacy_or_provider_status_drift_is_rejected(
    tmp_path: Path, drift: str
) -> None:
    fixture = _fixture(tmp_path)
    plan = json.loads(fixture.plan)
    if drift == "legacy":
        plan["legacy_stage_plan_accepted"] = True
    elif drift == "available_ids":
        plan["provider_status"]["available_provider_ids"] = [
            plan["provider_status"]["required_provider_ids"][0]
        ]
    else:
        plan["provider_status"]["all_required_providers_available"] = True
    forged = _reseal(plan, "stage_plan_sha256")
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="legacy|provider"):
        boundary._claim_bytes(  # noqa: SLF001
            stage_plan_bytes=forged,
            generator_source_bytes=fixture.source,
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda plan: plan["provider_status"]["providers"][0].__setitem__(
            "available", 0
        ),
        lambda plan: plan["generator_invocation"].__setitem__("provider_available", 0),
        lambda plan: plan["stage_shape"].__setitem__("blocks", True),
        lambda plan: plan["seeds"][0].__setitem__("block_index", False),
    ),
)
def test_stage_plan_bool_and_integer_fields_have_exact_json_types(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None]
) -> None:
    fixture = _fixture(tmp_path)
    plan = json.loads(fixture.plan)
    mutate(plan)
    with pytest.raises(boundary.DgpGenerationBoundaryError):
        boundary._claim_bytes(  # noqa: SLF001
            stage_plan_bytes=_reseal(plan, "stage_plan_sha256"),
            generator_source_bytes=fixture.source,
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda plan: plan["paths"].__setitem__("unexpected", "/tmp/escape"),
        lambda plan: plan["paths"].pop("dgp_output_root"),
        lambda plan: plan["generator_invocation"].__setitem__("unexpected", False),
        lambda plan: plan["generator_invocation"].pop("stdin"),
        lambda plan: plan["generator_invocation"].__setitem__("cwd", None),
        lambda plan: plan["generator_invocation"].__setitem__(
            "argv_after_runtime", "not-an-argv"
        ),
        lambda plan: plan.__setitem__("closed_environment_policy", None),
        lambda plan: plan["closed_environment_policy"].__setitem__("unexpected", False),
        lambda plan: plan["closed_environment_policy"].__setitem__(
            "provider_available", "false"
        ),
        lambda plan: plan.__setitem__("resource_policy", "not-a-policy"),
        lambda plan: plan["resource_policy"].pop("registered_gpu_count"),
        lambda plan: plan["resource_policy"].__setitem__("network_access_allowed", 0),
        lambda plan: plan["atomic_claim_protocol"].pop("provider_id"),
        lambda plan: plan["atomic_claim_protocol"].__setitem__("unexpected", True),
        lambda plan: plan["completion_protocol"].pop("adapter_source_sha256"),
        lambda plan: plan["completion_protocol"].__setitem__("unexpected", None),
        lambda plan: plan["provider_status"].__setitem__("unexpected", []),
        lambda plan: plan["stage_shape"].__setitem__("phase_count", "2"),
        lambda plan: plan["seeds"][0].__setitem__("unexpected", 0),
    ),
)
def test_stage_plan_boundary_nested_contracts_are_exact(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None]
) -> None:
    fixture = _fixture(tmp_path)
    plan = json.loads(fixture.plan)
    mutate(plan)
    with pytest.raises(boundary.DgpGenerationBoundaryError):
        boundary._claim_bytes(  # noqa: SLF001
            stage_plan_bytes=_reseal(plan, "stage_plan_sha256"),
            generator_source_bytes=fixture.source,
        )


def test_anchored_directory_prepare_rejects_preexisting_stage_symlink(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    outside = tmp_path / "outside-stage-target"
    outside.mkdir(mode=0o700)
    (fixture.root / "stages").symlink_to(outside, target_is_directory=True)

    with pytest.raises(boundary.DgpGenerationBoundaryError, match="anchored|unsafe"):
        boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
            root=fixture.root,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            generator_output_bytes_by_relative_path=fixture.outputs,
        )

    assert list(outside.rglob("*")) == []


def test_preexisting_unexpected_stage_file_fails_before_any_publication(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    view = boundary._parse_stage_plan(fixture.plan)  # noqa: SLF001
    unexpected = Path(view.stage_root) / "control" / "unexpected.txt"
    unexpected.parent.mkdir(parents=True)
    unexpected.write_bytes(b"preexisting poison")
    registered = boundary._all_registered_paths(view)  # noqa: SLF001

    with pytest.raises(
        boundary.DgpGenerationBoundaryError, match="unexpected|exact allowed"
    ):
        boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
            root=fixture.root,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            generator_output_bytes_by_relative_path=fixture.outputs,
        )

    assert all(not os.path.lexists(path) for path in registered)


def test_publish_parent_swap_and_restore_cannot_hide_missing_allowed_file(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    target_relative = (
        Path(
            boundary._parse_stage_plan(fixture.plan).stage_plan_path  # noqa: SLF001
        )
        .relative_to(fixture.root)
        .as_posix()
    )
    saved_parent = tmp_path / "saved-publish-parent"
    alternate_parent = tmp_path / "alternate-published-parent"
    swapped = False

    def publish(*, root: Path, relative_path: str, payload: bytes):
        nonlocal swapped
        if relative_path != target_relative or swapped:
            return atomic_publish.publish_readonly_no_overwrite(
                root=root, relative_path=relative_path, payload=payload
            )
        swapped = True
        parent = root.joinpath(*Path(relative_path).parts[:-1])
        parent.rename(saved_parent)
        parent.mkdir(mode=0o755)
        try:
            observation = atomic_publish.publish_readonly_no_overwrite(
                root=root, relative_path=relative_path, payload=payload
            )
            parent.rename(alternate_parent)
            saved_parent.rename(parent)
            return observation
        finally:
            if saved_parent.exists() and not parent.exists():
                saved_parent.rename(parent)

    runtime = boundary._DgpGenerationBoundaryTestRuntime(  # noqa: SLF001
        publish=publish
    )
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="file set"):
        boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
            root=fixture.root,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            generator_output_bytes_by_relative_path=fixture.outputs,
            runtime=runtime,
        )
    assert swapped is True


def test_injected_read_swap_and_restore_is_followed_by_canonical_read(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    view = boundary._parse_stage_plan(fixture.plan)  # noqa: SLF001
    target_relative = Path(view.stage_plan_path).relative_to(fixture.root).as_posix()
    saved_parent = tmp_path / "saved-read-parent"
    alternate_parent = tmp_path / "alternate-read-parent"
    swapped = False

    def read(*, root: Path, relative_path: str, expected_payload: bytes):
        nonlocal swapped
        result = atomic_publish.read_and_validate_readonly_artifact(
            root=root,
            relative_path=relative_path,
            expected_payload=expected_payload,
        )
        if relative_path != target_relative or swapped:
            return result
        swapped = True
        parent = root.joinpath(*Path(relative_path).parts[:-1])
        parent.rename(saved_parent)
        parent.mkdir(mode=0o755)
        try:
            (saved_parent / Path(relative_path).name).unlink()
            parent.rename(alternate_parent)
            saved_parent.rename(parent)
        finally:
            if saved_parent.exists() and not parent.exists():
                saved_parent.rename(parent)
        return result

    runtime = boundary._DgpGenerationBoundaryTestRuntime(  # noqa: SLF001
        read=read
    )
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="canonical"):
        boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
            root=fixture.root,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            generator_output_bytes_by_relative_path=fixture.outputs,
            runtime=runtime,
        )
    assert swapped is True


def test_final_canonical_sweep_catches_cross_artifact_read_mutation(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    view = boundary._parse_stage_plan(fixture.plan)  # noqa: SLF001
    completion_relative = (
        Path(view.stage_completion_receipt_path).relative_to(fixture.root).as_posix()
    )
    stage_plan_final = Path(view.stage_plan_path)
    mutated = False

    def read(*, root: Path, relative_path: str, expected_payload: bytes):
        nonlocal mutated
        result = atomic_publish.read_and_validate_readonly_artifact(
            root=root,
            relative_path=relative_path,
            expected_payload=expected_payload,
        )
        if relative_path == completion_relative and not mutated:
            mutated = True
            stage_plan_final.unlink()
            stage_plan_final.write_bytes(fixture.plan)
            stage_plan_final.chmod(0o444)
        return result

    runtime = boundary._DgpGenerationBoundaryTestRuntime(  # noqa: SLF001
        read=read
    )
    with pytest.raises(boundary.DgpGenerationBoundaryError, match="canonical"):
        boundary._run_dgp_generation_boundary_for_test(  # noqa: SLF001
            root=fixture.root,
            stage_plan_bytes=fixture.plan,
            generator_source_bytes=fixture.source,
            generator_output_bytes_by_relative_path=fixture.outputs,
            runtime=runtime,
        )
    assert mutated is True
