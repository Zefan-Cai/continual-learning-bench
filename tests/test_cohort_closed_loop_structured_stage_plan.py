from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import cohort_closed_loop_structured_atomic_publish as atomic_publish
import cohort_closed_loop_structured_deployment_snapshot as deployment_snapshot
import cohort_closed_loop_structured_protocol_plan as protocol_plan
import cohort_closed_loop_structured_stage_authorization as legacy_stage_authorization
import cohort_closed_loop_structured_stage_plan as stage_plan
import cohort_closed_loop_structured_trigger_bridge as trigger_bridge


class _FlippingRawMap(Mapping[str, object]):
    """Return different bytes on successive reads of one registered edge."""

    def __init__(self, values: Mapping[str, object]) -> None:
        self._values = dict(values)
        self._reads: dict[str, int] = {}

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __getitem__(self, key: str) -> object:
        self._reads[key] = self._reads.get(key, 0) + 1
        value = self._values[key]
        if self._reads[key] > 1 and type(value) is bytes:
            return value + b"forged-second-read"
        return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _phase12_fixture_module() -> ModuleType:
    name = "_stage_plan_phase12_fixture"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).with_name("test_cohort_closed_loop_structured_phase12.py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load phase-1/2 fixture module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _fixture(
    *, stage_kind: str = "smoke", stage_attempt_id: str = "attempt-007"
) -> tuple[bytes, dict[str, Any]]:
    phase12 = _phase12_fixture_module()
    receipt, evidence = phase12._strict_receipt_and_inputs()  # type: ignore[attr-defined]
    trigger = trigger_bridge.revalidate_and_bind_trigger_a_receipt(receipt, **evidence)
    _, artifacts = phase12._capture_fixture()  # type: ignore[attr-defined]
    snapshot_kwargs = phase12._snapshot_validation_kwargs(  # type: ignore[attr-defined]
        artifacts
    )
    protocol_kwargs = {
        "strict_trigger_bridge_bytes": trigger.bridge_receipt_bytes,
        "strict_trigger_receipt_bytes": receipt,
        "strict_trigger_evidence_bytes": evidence,
        "deployment_snapshot_bytes": artifacts.deployment_snapshot_bytes,
        **snapshot_kwargs,
    }
    protocol_raw = protocol_plan.seal_structured_protocol_plan_bytes(**protocol_kwargs)
    kwargs = {
        "protocol_plan_seal_bytes": protocol_raw,
        "stage_kind": stage_kind,
        "stage_attempt_id": stage_attempt_id,
        "parent_transition_receipt_bytes": (),
        **protocol_kwargs,
    }
    raw = stage_plan.seal_structured_stage_plan_bytes(**kwargs)
    return raw, kwargs


def _reseal_stage_payload(payload: dict[str, Any]) -> bytes:
    payload["stage_plan_sha256"] = _sha(
        _canonical(
            {key: value for key, value in payload.items() if key != "stage_plan_sha256"}
        )
    )
    return _canonical(payload)


def _collect_provider_ids(value: object) -> set[str]:
    result: set[str] = set()
    if type(value) is dict:
        for key, item in value.items():
            if key in {"provider_id", "attester_provider_id"} or key.endswith(
                "_provider_id"
            ):
                assert type(item) is str
                result.add(item)
            result.update(_collect_provider_ids(item))
    elif type(value) is list:
        for item in value:
            result.update(_collect_provider_ids(item))
    return result


def test_contract_pin_and_deployment_role_closures_are_identical() -> None:
    contract_raw = (
        Path(__file__).resolve().parent.parent
        / "COHORT_CLOSED_LOOP_STRUCTURED_EXECUTION_CONTRACT_V1.md"
    ).read_bytes()

    assert _sha(contract_raw) == protocol_plan.EXECUTION_CONTRACT_SHA256
    assert _sha(contract_raw) == legacy_stage_authorization.EXECUTION_CONTRACT_SHA256
    assert deployment_snapshot.SOURCE_ROLE_IDS == (
        legacy_stage_authorization.REQUIRED_SOURCE_BINDING_IDS
    )
    assert deployment_snapshot.ASSET_ROLE_IDS == (
        legacy_stage_authorization.REQUIRED_ASSET_BINDING_IDS
    )
    assert {
        "private_access_probe_source",
        "structured_dgp_claim_adapter",
        "structured_dgp_completion_adapter",
    }.issubset(deployment_snapshot.SOURCE_ROLE_IDS)
    assert "private_access_probe_binary" in deployment_snapshot.ASSET_ROLE_IDS


def test_smoke_stage_plan_reconstructs_full_closure_without_authority() -> None:
    raw, kwargs = _fixture()

    validation = stage_plan.validate_structured_stage_plan_bytes(raw, **kwargs)
    payload = json.loads(raw)

    assert validation.source_commit == "b" * 40
    assert validation.experiment_attempt_id == "attempt-001"
    assert validation.stage_attempt_id == "attempt-007"
    assert validation.stage_kind == "smoke"
    assert validation.stage_root.endswith(
        "/attempts/attempt-001/stages/smoke/attempt-007"
    )
    assert validation.private_context_root == (
        "/sensei-fs/private/zcai/TTT-RL/"
        "cohort-closed-loop-structured-state/"
        f"{'b' * 40}/attempts/attempt-001/stages/smoke/"
        "attempt-007/private-context"
    )
    assert validation.dgp_output_count == 33
    assert validation.private_record_count == 10
    assert payload["parent_transition"] == {
        "receipt_bindings": [],
        "required_stage_kinds": [],
    }
    assert payload["legacy_stage_plan_accepted"] is False
    for key in stage_plan._AUTHORITY_KEYS:  # noqa: SLF001
        assert payload[key] is False
    assert raw == _canonical(payload)


def test_dgp_inventory_is_exactly_rooted_at_stage_dgp_and_binds_sidecars() -> None:
    raw, _ = _fixture()
    payload = json.loads(raw)
    paths = payload["paths"]
    output_root = paths["dgp_output_root"]
    inventory = payload["dgp_output_inventory"]

    assert output_root == paths["stage_root"] + "/dgp"
    assert [row["path"] for row in inventory] == sorted(
        row["path"] for row in inventory
    )
    assert len({row["path"] for row in inventory}) == len(inventory) == 33
    assert {row["role"] for row in inventory} == {
        "context_registry_digest_record",
        "dgp_corpus_inventory",
        "dgp_row_identity",
        "dgp_stage_manifest",
        "public_context_attestation",
    }
    for row in inventory:
        assert row["path"] == output_root + "/" + row["relative_path"]
        assert not row["relative_path"].startswith("dgp/")
        assert row["path"].startswith(output_root + "/")
        durable_relative = row["path"].removeprefix(paths["durable_root"] + "/")
        intent, pending = atomic_publish.publication_sidecar_relative_paths(
            durable_relative
        )
        assert row["publication_intent_path"] == (paths["durable_root"] + "/" + intent)
        assert row["publication_pending_path"] == (
            paths["durable_root"] + "/" + pending
        )


def test_stage_plan_and_completion_bind_atomic_sidecars_without_collisions() -> None:
    raw, _ = _fixture()
    payload = json.loads(raw)
    paths = payload["paths"]
    completion = payload["completion_protocol"]

    stage_relative = paths["stage_plan_path"].removeprefix(
        paths["durable_root"] + "/"
    )
    stage_intent, stage_pending = atomic_publish.publication_sidecar_relative_paths(
        stage_relative
    )
    assert paths["stage_plan_publication_intent_path"] == (
        paths["durable_root"] + "/" + stage_intent
    )
    assert paths["stage_plan_publication_pending_path"] == (
        paths["durable_root"] + "/" + stage_pending
    )

    completion_relative = completion["receipt_path"].removeprefix(
        paths["durable_root"] + "/"
    )
    completion_intent, completion_pending = (
        atomic_publish.publication_sidecar_relative_paths(completion_relative)
    )
    assert completion["publication_intent_path"] == (
        paths["durable_root"] + "/" + completion_intent
    )
    assert completion["publication_pending_path"] == (
        paths["durable_root"] + "/" + completion_pending
    )
    assert completion["common_atomic_publication_contract_required"] is True
    assert completion["committed_final_mode"] == 0o444
    assert completion["committed_final_link_count"] == 1
    assert completion["fresh_committed_full_path_observation_count"] == 2
    assert completion["fresh_committed_full_path_observations_must_match"] is True

    triples = [
        (
            paths["stage_plan_path"],
            paths["stage_plan_publication_intent_path"],
            paths["stage_plan_publication_pending_path"],
        ),
        (
            payload["atomic_claim_protocol"]["claim_path"],
            payload["atomic_claim_protocol"]["publication_intent_path"],
            payload["atomic_claim_protocol"]["publication_pending_path"],
        ),
        (
            completion["receipt_path"],
            completion["publication_intent_path"],
            completion["publication_pending_path"],
        ),
    ]
    for row in (
        payload["dgp_output_inventory"]
        + payload["private_boundary_plan"]["evidence_output_inventory"]
    ):
        triples.append(
            (
                row["path"],
                row["publication_intent_path"],
                row["publication_pending_path"],
            )
        )
    flattened = [path for triple in triples for path in triple]
    assert len(flattened) == len(set(flattened))


def test_registry_mapping_plan_is_not_a_forged_completed_mapping() -> None:
    raw, _ = _fixture()
    payload = json.loads(raw)
    mapping = payload["registry_v2_mapping"]
    entries = mapping["planned_entries"]

    assert mapping["status"] == "pre_dgp_completion_values_pending"
    assert mapping["source_commit"] == payload["source_commit"]
    assert mapping["experiment_attempt_id"] == payload["experiment_attempt_id"]
    assert mapping["stage_kind"] == payload["stage_kind"]
    assert mapping["stage_attempt_id"] == payload["stage_attempt_id"]
    assert mapping["private_context_root"] == payload["paths"]["private_context_root"]
    assert (
        mapping["completion_receipt_path"]
        == payload["paths"]["registry_completion_receipt_path"]
    )
    assert mapping["completion_receipt_protocol"] == (
        "cohort_structured_private_context_registry_completion_receipt_v2"
    )
    assert mapping["completion_receipt_schema_version"] == 2
    assert mapping["planned_entry_count"] == len(entries) == 10
    assert mapping["completion_entry_fields"] == [
        "stage_kind",
        "block_id",
        "block_index",
        "phase",
        "item_id",
        "instance_index",
        "instance_id",
        "public_context_identity_sha256",
        "opaque_handle_sha256",
        "relative_path",
        "hidden_sha256",
        "size_bytes",
    ]
    assert set(entries[0]) == set(mapping["plan_entry_fields"])
    assert entries[0]["completion_values_pending"] == [
        "hidden_sha256",
        "instance_id",
        "opaque_handle_sha256",
        "public_context_identity_sha256",
        "size_bytes",
    ]
    for entry in entries:
        assert "hidden_sha256" not in entry
        assert "instance_id" not in entry
        assert entry["private_record_relative_path"].startswith("records/")
        assert entry["public_attestation_path"].startswith(
            payload["paths"]["dgp_output_root"] + "/contexts/"
        )


def test_private_epoch_and_all_fixed_public_evidence_paths_are_per_stage() -> None:
    raw, _ = _fixture()
    payload = json.loads(raw)
    paths = payload["paths"]
    private_plan = payload["private_boundary_plan"]
    evidence_root = paths["stage_root"] + "/control/private_boundary"

    assert paths["private_evidence_root"] == evidence_root
    assert paths["private_record_root"] == paths["private_context_root"] + "/records"
    assert [row["probe_id"] for row in paths["initial_probe_receipt_paths"]] == list(
        stage_plan.INITIAL_PRIVATE_PROBE_IDS
    )
    assert [row["probe_id"] for row in paths["sealed_probe_receipt_paths"]] == list(
        stage_plan.SEALED_PRIVATE_PROBE_IDS
    )
    for row in paths["initial_probe_receipt_paths"]:
        assert row["path"] == f"{evidence_root}/initial/probes/{row['probe_id']}.json"
    for row in paths["sealed_probe_receipt_paths"]:
        assert row["path"] == f"{evidence_root}/sealed/probes/{row['probe_id']}.json"
    assert paths["initial_boundary_attestation_path"] == (
        evidence_root + "/initial/attestation.json"
    )
    assert paths["sealed_boundary_attestation_path"] == (
        evidence_root + "/sealed/attestation.json"
    )
    assert paths["registry_completion_receipt_path"] == (
        evidence_root + "/registry/registry_completion.v2.json"
    )
    evidence = private_plan["evidence_output_inventory"]
    assert len(evidence) == 14 + 9 + 3
    assert len({row["path"] for row in evidence}) == len(evidence)
    assert (
        private_plan["probe_publication_order"]["initial"]["attestation_last"]
        == paths["initial_boundary_attestation_path"]
    )
    assert (
        private_plan["probe_publication_order"]["sealed"]["attestation_last"]
        == paths["sealed_boundary_attestation_path"]
    )


def test_private_plan_freezes_identities_policies_adapter_and_poison_semantics() -> (
    None
):
    raw, _ = _fixture()
    private_plan = json.loads(raw)["private_boundary_plan"]
    identities = private_plan["service_identities"]

    assert identities == {
        "attester": {
            "gid": 41001,
            "identity": "cohort-structured-private-boundary-v1",
            "supplementary_gids": [41016],
            "uid": 41001,
        },
        "launcher": {
            "gid": 41014,
            "identity": "cohort-structured-launcher-v1",
            "supplementary_gids": [],
            "uid": 41014,
        },
        "operator": {
            "gid": 41015,
            "identity": "cohort-structured-operator-v1",
            "supplementary_gids": [],
            "uid": 41015,
        },
        "private_validator": {
            "gid": 41013,
            "identity": "cohort-structured-private-validator-v1",
            "supplementary_gids": [41016],
            "uid": 41013,
        },
        "pure_scorer": {
            "gid": 41012,
            "identity": "cohort-structured-pure-scorer-v1",
            "supplementary_gids": [41016],
            "uid": 41012,
        },
        "registrar": {
            "gid": 41016,
            "identity": "cohort-structured-context-registrar-v1",
            "supplementary_gids": [],
            "uid": 41011,
        },
    }
    assert private_plan["service_identities_sha256"] == _sha(_canonical(identities))

    initial = private_plan["initial_access_policy"]
    sealed = private_plan["sealed_access_policy"]
    assert initial["stage"] == "initial_registration_boundary"
    assert initial["schema_version"] == 1
    assert initial["mount_mode"] == "rw"
    assert initial["registrar"]["operations"] == [
        "create_exact_probe",
        "read_exact_probe",
        "remove_exact_probe",
        "verify_probe_absent",
    ]
    assert initial["denied"]["launcher"]["required_raw_errno"] == errno.EACCES
    assert private_plan["initial_access_policy_sha256"] == _sha(_canonical(initial))
    assert sealed["stage"] == "sealed_prelaunch_boundary"
    assert sealed["schema_version"] == 2
    assert sealed["mount_mode"] == "ro"
    assert sealed["registrar_mutation_denied"]["accepted_raw_errnos"] == sorted(
        {errno.EACCES, errno.EROFS}
    )
    assert private_plan["sealed_access_policy_sha256"] == _sha(_canonical(sealed))

    protocols = private_plan["protocol_schema_bindings"]
    assert protocols["initial_attestation"]["schema_version"] == 1
    assert protocols["registry_completion"] == {
        "protocol": (
            "cohort_structured_private_context_registry_completion_receipt_v2"
        ),
        "schema_version": 2,
    }
    assert protocols["sealed_attestation"]["schema_version"] == 2

    adapter = private_plan["access_probe_execution_policy"]
    assert adapter["installed_owner_uid"] == 0
    assert adapter["installed_group_gid"] == 41001
    assert adapter["installed_mode"] == 0o4750
    assert adapter["installed_link_count"] == 1
    assert adapter["execution_method"] == "fexecve_or_execveat_at_empty_path"
    assert adapter["pathname_execution_forbidden"] is True
    assert adapter["proc_self_exe_identity_revalidation_required"] is True
    assert adapter["credential_transition"] == (
        "setgroups_then_setresgid_then_setresuid_no_active_capabilities"
    )
    assert adapter["all_capability_sets_zero_required"] is True
    assert adapter["no_new_privs_required"] is True
    assert adapter["locked_securebits_required"] == 63

    poison = private_plan["single_use_poison_policy"]
    assert poison["poison_grants_authority"] is False
    assert poison["missing_registry_completion_receipt_is_poison"] is True
    assert all(value is True for key, value in poison.items() if key != "poison_grants_authority")


def test_every_runtime_provider_is_explicitly_missing_and_every_authority_false() -> (
    None
):
    raw, _ = _fixture()
    payload = json.loads(raw)
    status = payload["provider_status"]
    required = set(status["required_provider_ids"])

    assert required == set(status["missing_provider_ids"])
    assert status["available_provider_ids"] == []
    assert status["all_required_providers_available"] is False
    assert status["providers"] == [
        {"available": False, "provider_id": provider_id}
        for provider_id in status["required_provider_ids"]
    ]
    assert _collect_provider_ids(payload) == required
    assert {
        "closed_environment_attester",
        "controlled_process_launcher",
        "dgp_claim_atomic_adapter",
        "dgp_completion_adapter",
        "dgp_generator_invocation",
        "gpu_inventory_attester",
        "job_identity_attester",
        "network_isolation_attester",
        "node_identity_attester",
        "private_boundary_v2",
        "python_runtime_attester",
        "stdio_provider",
    } == required
    assert payload["generator_invocation"]["runtime_executable_path"] is None
    assert payload["generator_invocation"]["provider_available"] is False
    assert payload["closed_environment_policy"]["provider_available"] is False
    for key in stage_plan._AUTHORITY_KEYS:  # noqa: SLF001
        assert payload[key] is False


def test_claim_protocol_matches_atomic_publisher_commit_boundary() -> None:
    raw, _ = _fixture()
    payload = json.loads(raw)
    claim = payload["atomic_claim_protocol"]
    paths = payload["paths"]
    relative = claim["claim_path"].removeprefix(paths["durable_root"] + "/")
    intent, pending = atomic_publish.publication_sidecar_relative_paths(relative)

    assert claim["publication_intent_path"] == paths["durable_root"] + "/" + intent
    assert claim["publication_pending_path"] == (paths["durable_root"] + "/" + pending)
    assert claim["intent_o_excl_is_concurrency_serialization_point"] is True
    assert claim["pending_created_with_o_excl"] is True
    assert claim["pending_full_payload_write_required"] is True
    assert claim["pending_fsync_before_chmod_required"] is True
    assert claim["pending_chmod_mode"] == 0o444
    assert claim["pending_fsync_after_chmod_required"] is True
    assert claim["final_created_by_no_replace_hardlink"] is True
    assert claim["precommit_final_and_pending_link_count"] == 2
    assert claim["parent_fsync_after_final_hardlink_required"] is True
    assert claim["fresh_precommit_ancestor_retraversal_required"] is True
    assert claim["fresh_precommit_intent_full_bytes_required"] is True
    assert claim["fresh_precommit_pending_final_same_inode_required"] is True
    assert claim["fresh_precommit_final_full_bytes_required"] is True
    assert claim["final_hardlink_visibility_is_not_commit_or_authorization"] is True
    assert claim["pending_unlink_is_filesystem_commit_point"] is True
    assert claim["parent_fsync_after_pending_unlink_required"] is True
    assert claim["committed_final_link_count"] == 1
    assert claim["committed_final_mode"] == 0o444
    assert claim["fresh_committed_intent_present_required"] is True
    assert claim["fresh_committed_pending_absent_required"] is True
    assert claim["fresh_committed_final_full_bytes_required"] is True
    assert claim["fresh_committed_full_path_observation_count"] == 2
    assert claim["fresh_committed_full_path_observations_must_match"] is True
    assert claim["direct_final_o_excl_forbidden"] is True
    assert claim["rename_publication_forbidden"] is True
    assert claim["provider_available"] is False
    assert (
        payload["generator_invocation"]["generator_import_requires_committed_claim"]
        is True
    )


@pytest.mark.parametrize("stage_kind", ["internal", "confirmation"])
def test_non_smoke_stages_fail_closed_without_semantic_parent_validator(
    stage_kind: str,
) -> None:
    with pytest.raises(
        stage_plan.StructuredStagePlanError,
        match="parent semantic validators are unavailable",
    ):
        _fixture(stage_kind=stage_kind)


def test_smoke_rejects_parent_bytes_or_non_tuple_parent() -> None:
    raw, kwargs = _fixture()
    del raw
    with pytest.raises(stage_plan.StructuredStagePlanError, match="must be empty"):
        stage_plan.seal_structured_stage_plan_bytes(
            **{**kwargs, "parent_transition_receipt_bytes": (b"forged",)}
        )
    with pytest.raises(stage_plan.StructuredStagePlanError, match="exact tuple"):
        stage_plan.seal_structured_stage_plan_bytes(
            **{**kwargs, "parent_transition_receipt_bytes": []}
        )


@pytest.mark.parametrize("attempt_id", ["attempt-01", "attempt-0001", "../attempt-007"])
def test_stage_attempt_id_grammar_is_exact(attempt_id: str) -> None:
    raw, kwargs = _fixture()
    del raw
    with pytest.raises(stage_plan.StructuredStagePlanError, match="stage_attempt_id"):
        stage_plan.seal_structured_stage_plan_bytes(
            **{**kwargs, "stage_attempt_id": attempt_id}
        )


@pytest.mark.parametrize(
    "mapping_name",
    [
        "strict_trigger_evidence_bytes",
        "asset_inventory_bytes_by_role",
        "source_file_bytes_by_role",
        "asset_file_bytes_by_role",
    ],
)
def test_caller_owned_raw_maps_are_snapshotted_from_exact_dicts(
    mapping_name: str,
) -> None:
    _, kwargs = _fixture()
    flipping = _FlippingRawMap(kwargs[mapping_name])

    with pytest.raises(
        stage_plan.StructuredStagePlanError, match="must be an exact dict"
    ):
        stage_plan.seal_structured_stage_plan_bytes(
            **{**kwargs, mapping_name: flipping}
        )


def test_nested_asset_file_mapping_cannot_flip_between_consumers() -> None:
    _, kwargs = _fixture()
    nested = {
        role: dict(files)
        for role, files in kwargs["asset_file_bytes_by_role"].items()
    }
    nested["private_access_probe_binary"] = _FlippingRawMap(
        nested["private_access_probe_binary"]
    )

    with pytest.raises(
        stage_plan.StructuredStagePlanError, match="must be an exact dict"
    ):
        stage_plan.seal_structured_stage_plan_bytes(
            **{**kwargs, "asset_file_bytes_by_role": nested}
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda kwargs: kwargs.update(
            strict_trigger_receipt_bytes=kwargs["strict_trigger_receipt_bytes"] + b"\n"
        ),
        lambda kwargs: kwargs["strict_trigger_evidence_bytes"].update(
            causal_original_decision_bytes=(
                kwargs["strict_trigger_evidence_bytes"][
                    "causal_original_decision_bytes"
                ]
                + b"\n"
            )
        ),
        lambda kwargs: kwargs.update(
            deployment_snapshot_bytes=kwargs["deployment_snapshot_bytes"] + b"\n"
        ),
        lambda kwargs: kwargs.update(
            lease_receipt_bytes=kwargs["lease_receipt_bytes"] + b"\n"
        ),
        lambda kwargs: kwargs.update(
            observation_bytes=(
                kwargs["observation_bytes"][0] + b"\n",
                kwargs["observation_bytes"][1],
            )
        ),
        lambda kwargs: kwargs.update(git_index_bytes=kwargs["git_index_bytes"] + b"x"),
        lambda kwargs: kwargs["source_file_bytes_by_role"].update(
            structured_dgp_claim_adapter=(
                kwargs["source_file_bytes_by_role"]["structured_dgp_claim_adapter"]
                + b"x"
            )
        ),
        lambda kwargs: kwargs["asset_file_bytes_by_role"][
            "private_access_probe_binary"
        ].update(
            payload_bin=(
                kwargs["asset_file_bytes_by_role"]["private_access_probe_binary"][
                    "payload.bin"
                ]
                + b"x"
            )
        ),
        lambda kwargs: kwargs.update(
            execution_contract_bytes=kwargs["execution_contract_bytes"] + b"\n"
        ),
    ],
)
def test_stage_plan_rejects_any_upstream_raw_closure_substitution(mutator: Any) -> None:
    raw, kwargs = _fixture()
    mutated = dict(kwargs)
    mutated["strict_trigger_evidence_bytes"] = dict(
        kwargs["strict_trigger_evidence_bytes"]
    )
    mutated["source_file_bytes_by_role"] = dict(kwargs["source_file_bytes_by_role"])
    mutated["asset_file_bytes_by_role"] = {
        role: dict(files) for role, files in kwargs["asset_file_bytes_by_role"].items()
    }
    mutator(mutated)
    with pytest.raises(stage_plan.StructuredStagePlanError):
        stage_plan.validate_structured_stage_plan_bytes(raw, **mutated)


def test_resealed_embedded_authority_or_inventory_substitution_is_rejected() -> None:
    raw, kwargs = _fixture()
    for mutate in (
        lambda payload: payload.__setitem__("launch_authorized", True),
        lambda payload: payload["dgp_output_inventory"][0].__setitem__(
            "path", "/tmp/forged.json"
        ),
        lambda payload: payload["provider_status"].__setitem__(
            "all_required_providers_available", True
        ),
    ):
        payload = json.loads(raw)
        mutate(payload)
        forged = _reseal_stage_payload(payload)
        with pytest.raises(
            stage_plan.StructuredStagePlanError,
            match="complete raw-byte reconstruction",
        ):
            stage_plan.validate_structured_stage_plan_bytes(forged, **kwargs)


def test_duplicate_key_and_noncanonical_json_fail_before_reconstruction() -> None:
    raw, kwargs = _fixture()
    duplicate = raw[:-1] + b',"protocol":"forged"}'
    with pytest.raises(stage_plan.StructuredStagePlanError, match="duplicate JSON key"):
        stage_plan.validate_structured_stage_plan_bytes(duplicate, **kwargs)
    with pytest.raises(stage_plan.StructuredStagePlanError, match="canonical"):
        stage_plan.validate_structured_stage_plan_bytes(raw + b"\n", **kwargs)
