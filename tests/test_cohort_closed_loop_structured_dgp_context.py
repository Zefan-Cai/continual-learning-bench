from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace
from functools import lru_cache

import pytest

import cohort_closed_loop_structured_dgp_context as protocol
import cohort_closed_loop_structured_commitments as commitments
from cohort_closed_loop_structured_commitments import (
    CANDIDATE_ACTION_IDS,
    GENESIS_PRECOMMIT_SHA256,
    PRECOMMIT_PROTOCOL,
    SHARED_RAW_ACTION_PROTOCOL,
    build_precommit_bytes,
    build_scoring_context_attestation,
    canonical_sha256 as commitment_sha256,
    encode_action_bytes,
    numerical_runtime_identity,
)
from cohort_closed_loop_structured_state import (
    ACTION_FIELD_NAMES,
    POSITIVE_ZERO_STATE,
    RHO,
    STATE_SCALE,
    U,
    candidate_probe_states,
    semantic_action_sha256,
    state_payload,
    state_sha256,
    transform_action,
)


def _h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _instance_id(label: str) -> str:
    return "instance-" + hashlib.sha256(label.encode("utf-8")).hexdigest()[:24]


def _row(label: str, item_id: int) -> protocol.DgpRowIdentity:
    return protocol.make_dgp_row_identity(
        item_id=item_id,
        instance_id=_instance_id(label),
        query_sha256=_h(f"query:{label}"),
        database_sha256=_h(f"database:{label}"),
        ground_truth_sha256=_h(f"ground-truth:{label}"),
        reference_survival_sha256=_h(f"reference:{label}"),
        schedule_entry_sha256=_h(f"schedule-entry:{label}"),
    )


def _opaque_handle_bytes(
    stage_kind: protocol.StageKind,
    block_id: str,
    phase: protocol.PhaseKind,
    item_id: int,
) -> bytes:
    return (
        f"opaque:{stage_kind.value}:{block_id}:{phase.value}:{item_id}"
    ).encode("ascii")


def _build_stage(
    stage_kind: protocol.StageKind,
    *,
    prior_stage_manifest_bytes: tuple[bytes, ...],
    first_row_override: protocol.DgpRowIdentity | None = None,
    namespace_suffix: str = "registered",
    generator_sha256: str | None = None,
) -> tuple[bytes, protocol.StageDgpContextManifest]:
    shape = protocol.STAGE_SHAPES[stage_kind]
    corpora: list[protocol.CorpusInventory] = []
    for seed in protocol.EXPECTED_STAGE_SEEDS[stage_kind]:
        for phase in (protocol.PhaseKind.ADAPTATION, protocol.PhaseKind.HELD_OUT):
            dgp_seed = (
                seed.adaptation_dgp_seed
                if phase is protocol.PhaseKind.ADAPTATION
                else seed.held_out_dgp_seed
            )
            rows = [
                _row(
                    f"{namespace_suffix}:{stage_kind.value}:{seed.block_id}:"
                    f"{phase.value}:{item_id}",
                    item_id,
                )
                for item_id in range(1, shape.items_per_phase + 1)
            ]
            if (
                first_row_override is not None
                and seed.block_index == 0
                and phase is protocol.PhaseKind.ADAPTATION
            ):
                rows[0] = first_row_override
            raw = protocol.build_corpus_inventory_bytes(
                stage_kind=stage_kind,
                block_id=seed.block_id,
                block_index=seed.block_index,
                phase=phase,
                run_seed=seed.run_seed,
                dgp_seed=dgp_seed,
                dgp_generator_sha256=(
                    generator_sha256 or _h("fixed-dgp-generator-source")
                ),
                dgp_arguments_sha256=_h(
                    f"args:{namespace_suffix}:{stage_kind.value}:"
                    f"{seed.block_id}:{phase.value}"
                ),
                cohort_layer_inventory_sha256=_h(
                    f"cohort-layers:{namespace_suffix}:{stage_kind.value}:"
                    f"{seed.block_id}:{phase.value}"
                ),
                rows=rows,
            )
            corpora.append(protocol.load_corpus_inventory(raw))
    entries = [
        protocol.build_context_entry(
            corpus=corpus,
            row=row,
            scorer_source_sha256=_h("fixed-scorer-source"),
            opaque_handle_sha256=hashlib.sha256(
                _opaque_handle_bytes(
                    stage_kind,
                    corpus.block_id,
                    corpus.phase,
                    row.item_id,
                )
            ).hexdigest(),
            hidden_registry_entry_sha256=_h(
                f"hidden-entry:{namespace_suffix}:{stage_kind.value}:"
                f"{corpus.block_id}:{corpus.phase.value}:{row.item_id}"
            ),
        )
        for corpus in corpora
        for row in corpus.rows
    ]
    context_raw = protocol.build_context_attestation_inventory_bytes(
        stage_kind=stage_kind,
        records=entries,
    )
    context_inventory = protocol.load_context_attestation_inventory(context_raw)
    stage_raw = protocol.build_stage_manifest_bytes(
        stage_kind=stage_kind,
        corpora=corpora,
        context_attestation_inventory=context_inventory,
        prior_stage_manifest_bytes=prior_stage_manifest_bytes,
    )
    return stage_raw, protocol.load_stage_manifest(stage_raw)


@lru_cache(maxsize=None)
def _cached_stage(
    stage_kind: protocol.StageKind,
) -> tuple[bytes, protocol.StageDgpContextManifest]:
    if stage_kind is protocol.StageKind.SMOKE:
        priors: tuple[bytes, ...] = ()
    elif stage_kind is protocol.StageKind.INTERNAL:
        priors = (_cached_stage(protocol.StageKind.SMOKE)[0],)
    else:
        priors = (
            _cached_stage(protocol.StageKind.SMOKE)[0],
            _cached_stage(protocol.StageKind.INTERNAL)[0],
        )
    return _build_stage(stage_kind, prior_stage_manifest_bytes=priors)


def _resign_corpus(corpus: dict[str, object]) -> None:
    unsigned = {
        key: value
        for key, value in corpus.items()
        if key != "corpus_inventory_sha256"
    }
    corpus["corpus_inventory_sha256"] = protocol.canonical_sha256(unsigned)


def _resign_context_inventory(inventory: dict[str, object]) -> None:
    unsigned = {
        key: value
        for key, value in inventory.items()
        if key != "context_inventory_sha256"
    }
    inventory["context_inventory_sha256"] = protocol.canonical_sha256(unsigned)


def _resign_stage(stage: dict[str, object]) -> bytes:
    unsigned = {
        key: value for key, value in stage.items() if key != "stage_manifest_sha256"
    }
    stage["stage_manifest_sha256"] = protocol.canonical_sha256(unsigned)
    return protocol.canonical_json_bytes(stage)


def _replace_context_inventory(
    manifest: protocol.StageDgpContextManifest,
    inventory: protocol.ContextAttestationInventory,
) -> bytes:
    payload = manifest.to_payload()
    payload["context_attestation_inventory"] = inventory.to_payload()
    return _resign_stage(payload)


def _raw_action(raw_variant: str) -> bytes:
    values = {field: 0.5 for field in ACTION_FIELD_NAMES}
    values[ACTION_FIELD_NAMES[0]] = 0.25 + int(_h(raw_variant)[:2], 16) / 1024.0
    return json.dumps(
        values,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _invocation(
    *,
    branch_id: str,
    action_role: str,
    action_id: str,
    action_bytes: bytes,
) -> dict[str, object]:
    return {
        "branch_id": branch_id,
        "item_id": 1,
        "action_role": action_role,
        "action_id": action_id,
        "semantic_action_sha256": semantic_action_sha256(action_bytes),
        **encode_action_bytes(action_bytes),
    }


def _precommit_bytes(
    manifest: protocol.StageDgpContextManifest,
    family: str,
    *,
    raw_variant: str,
    instance_id_override: str | None = None,
    scoring_context_override: str | None = None,
    inventory_override: tuple[str, str] | None = None,
) -> bytes:
    corpus = manifest.corpora[0]
    row = corpus.rows[0]
    entry = manifest.context_attestation_inventory.records[0]
    record = entry.context_registry_record
    instance_id = instance_id_override or row.instance_id
    scoring_context = scoring_context_override or record.scoring_context_sha256
    raw_trace = _h(f"raw-trace:{raw_variant}")
    raw_action = _raw_action(raw_variant)
    raw_unsigned = {
        "object_protocol": SHARED_RAW_ACTION_PROTOCOL,
        **encode_action_bytes(raw_action),
        "semantic_action_sha256": semantic_action_sha256(raw_action),
    }
    shared_raw = {
        **raw_unsigned,
        "shared_raw_action_object_sha256": commitment_sha256(raw_unsigned),
    }
    opaque_handle = _opaque_handle_bytes(
        manifest.stage_kind,
        corpus.block_id,
        corpus.phase,
        row.item_id,
    )
    assert hashlib.sha256(opaque_handle).hexdigest() == record.opaque_handle_sha256
    attestation = build_scoring_context_attestation(
        opaque_handle_sha256=record.opaque_handle_sha256,
        scoring_context_sha256=scoring_context,
        hidden_registry_entry_sha256=record.hidden_registry_entry_sha256,
    )
    attestation_sha256 = hashlib.sha256(attestation).hexdigest()
    context = {
        "opaque_handle_base64": base64.b64encode(opaque_handle).decode("ascii"),
        "opaque_handle_size": len(opaque_handle),
        "opaque_handle_sha256": record.opaque_handle_sha256,
        "scoring_context_sha256": scoring_context,
        "scoring_context_attestation_sha256": attestation_sha256,
    }
    join = {
        "block_id": corpus.block_id,
        "item_id": row.item_id,
        "instance_id": instance_id,
        "instance_index": row.instance_index,
        "query_sha256": row.query_sha256,
        "raw_trace_sha256": raw_trace,
        "raw_semantic_action_sha256": raw_unsigned["semantic_action_sha256"],
        "raw_action_bytes_sha256": raw_unsigned["action_bytes_sha256"],
        "scoring_context_sha256": scoring_context,
        "scoring_context_attestation_sha256": attestation_sha256,
    }
    if family == "canonical_online_icl":
        branch_ids = ("canonical_online_icl",)
    else:
        branch_ids = (
            "closed_loop_active",
            "closed_loop_lr0",
            "pair_sign_reverse",
        )
    probes = candidate_probe_states(POSITIVE_ZERO_STATE)
    branch_records: list[dict[str, object]] = []
    invocations: list[dict[str, object]] = []
    for branch_id in branch_ids:
        has_candidates = family == "structured"
        candidate_refs = (
            [
                {
                    "branch_id": branch_id,
                    "action_role": "candidate",
                    "action_id": action_id,
                }
                for action_id in CANDIDATE_ACTION_IDS
            ]
            if has_candidates
            else []
        )
        probe_records = (
            [
                {
                    "action_id": action_id,
                    "state": state_payload(probe_state),
                    "state_sha256": state_sha256(probe_state),
                }
                for action_id, (_, probe_state) in zip(
                    CANDIDATE_ACTION_IDS, probes, strict=True
                )
            ]
            if has_candidates
            else []
        )
        branch_records.append(
            {
                "branch_id": branch_id,
                "shared_raw_action_object_sha256": shared_raw[
                    "shared_raw_action_object_sha256"
                ],
                "state_before": (
                    state_payload(POSITIVE_ZERO_STATE) if has_candidates else None
                ),
                "state_before_sha256": (
                    state_sha256(POSITIVE_ZERO_STATE) if has_candidates else None
                ),
                "official_invocation_ref": {
                    "branch_id": branch_id,
                    "action_role": "official",
                    "action_id": "official",
                },
                "candidate_invocation_refs": candidate_refs,
                "probe_states": probe_records,
            }
        )
        invocations.append(
            _invocation(
                branch_id=branch_id,
                action_role="official",
                action_id="official",
                action_bytes=raw_action,
            )
        )
        if has_candidates:
            invocations.extend(
                _invocation(
                    branch_id=branch_id,
                    action_role="candidate",
                    action_id=action_id,
                    action_bytes=transform_action(raw_action, probe_state),
                )
                for action_id, (_, probe_state) in zip(
                    CANDIDATE_ACTION_IDS, probes, strict=True
                )
            )
    inventory = {
        "protocol_sha256": _h(f"protocol:{family}"),
        "source_sha256": _h(f"source:{family}"),
        "model_sha256": _h("shared:model"),
        "tokenizer_sha256": _h("shared:tokenizer"),
        "environment_sha256": _h("shared:environment"),
        "task_sha256": _h("shared:task"),
        "schema_sha256": _h("shared:schema"),
        "dgp_sha256": corpus.dgp_sha256,
        "schedule_sha256": corpus.aggregate_schedule_sha256,
        "condition_order_sha256": corpus.aggregate_order_sha256,
        "cohort_layer_inventory_sha256": corpus.cohort_layer_inventory_sha256,
    }
    if inventory_override is not None:
        inventory[inventory_override[0]] = inventory_override[1]
    unsigned = {
        "precommit_protocol": PRECOMMIT_PROTOCOL,
        "schema_version": commitments.SCHEMA_VERSION,
        "commitment_family": family,
        "commitment_phase": corpus.phase.value,
        "inventory_sha256": inventory,
        "block_id": corpus.block_id,
        "item_id": row.item_id,
        "instance_id": instance_id,
        "instance_index": row.instance_index,
        "query_sha256": row.query_sha256,
        "raw_trace_sha256": raw_trace,
        "shared_join_key": join,
        "shared_raw_action": shared_raw,
        "scoring_context": context,
        "numerical_runtime": numerical_runtime_identity(),
        "probe_design": {
            "d_float_hex": [value.hex() for value in STATE_SCALE],
            "rho_float_hex": RHO.hex(),
            "u": [list(row_values) for row_values in U],
        },
        "branch_records": branch_records,
        "invocations": invocations,
        "previous_item_precommit_sha256": GENESIS_PRECOMMIT_SHA256,
    }
    return build_precommit_bytes(
        unsigned, scoring_context_attestation_bytes=attestation
    )


def test_prereg_seed_table_and_fixed_stage_shapes_are_exact() -> None:
    assert protocol.STAGE_SHAPES == {
        protocol.StageKind.SMOKE: protocol.StageShape(1, 5),
        protocol.StageKind.INTERNAL: protocol.StageShape(3, 20),
        protocol.StageKind.CONFIRMATION: protocol.StageShape(8, 20),
    }
    assert protocol.EXPECTED_STAGE_SEEDS[protocol.StageKind.SMOKE] == (
        protocol.BlockSeedSpec(
            "smoke_block_01", 0, 2026071598, 2026071596, 2026071597
        ),
    )
    assert protocol.EXPECTED_STAGE_SEEDS[protocol.StageKind.INTERNAL] == (
        protocol.BlockSeedSpec(
            "internal_block_01", 0, 2026071501, 2026071511, 2026071512
        ),
        protocol.BlockSeedSpec(
            "internal_block_02", 1, 2026071502, 2026071521, 2026071522
        ),
        protocol.BlockSeedSpec(
            "internal_block_03", 2, 2026071503, 2026071531, 2026071532
        ),
    )
    assert protocol.EXPECTED_STAGE_SEEDS[protocol.StageKind.CONFIRMATION] == tuple(
        protocol.BlockSeedSpec(
            f"confirmation_block_{index + 1:02d}",
            index,
            2026081001 + index,
            2026081101 + index,
            2026081201 + index,
        )
        for index in range(8)
    )


@pytest.mark.parametrize(
    "stage_kind,expected_corpora,expected_rows",
    [
        (protocol.StageKind.SMOKE, 2, 10),
        (protocol.StageKind.INTERNAL, 6, 120),
        (protocol.StageKind.CONFIRMATION, 16, 320),
    ],
)
def test_exact_stage_loaders_accept_registered_shapes(
    stage_kind: protocol.StageKind,
    expected_corpora: int,
    expected_rows: int,
) -> None:
    raw, manifest = _cached_stage(stage_kind)
    assert protocol.load_stage_manifest(raw) == manifest
    assert len(manifest.corpora) == expected_corpora
    assert sum(len(corpus.rows) for corpus in manifest.corpora) == expected_rows
    assert len(manifest.context_attestation_inventory.records) == expected_rows


def test_stage_integrity_requires_exact_prior_stage_chain_and_is_outcome_free() -> None:
    smoke = _cached_stage(protocol.StageKind.SMOKE)[0]
    internal = _cached_stage(protocol.StageKind.INTERNAL)[0]
    confirmation = _cached_stage(protocol.StageKind.CONFIRMATION)[0]

    smoke_record = protocol.validate_stage_integrity(
        current_manifest_bytes=smoke, prior_manifest_bytes=()
    )
    internal_record = protocol.validate_stage_integrity(
        current_manifest_bytes=internal, prior_manifest_bytes=(smoke,)
    )
    confirmation_record = protocol.validate_stage_integrity(
        current_manifest_bytes=confirmation,
        prior_manifest_bytes=(smoke, internal),
    )

    assert smoke_record.disjoint_pair_count == 1
    assert internal_record.disjoint_pair_count == 28
    assert confirmation_record.disjoint_pair_count == 276
    assert confirmation_record.hidden_registry_contents_validated is False
    assert confirmation_record.scorer_reexecution_performed is False
    assert not (
        {"score", "reward", "efficacy", "delta"}
        & set(confirmation_record.__dataclass_fields__)
    )
    with pytest.raises(protocol.DgpContextIntegrityError, match="required prior"):
        protocol.validate_stage_integrity(
            current_manifest_bytes=internal, prior_manifest_bytes=()
        )
    with pytest.raises(protocol.DgpContextIntegrityError, match="required prior"):
        protocol.validate_stage_integrity(
            current_manifest_bytes=confirmation,
            prior_manifest_bytes=(internal, smoke),
        )


def test_stage_manifest_binds_exact_prior_canonical_file_bytes() -> None:
    smoke_raw, _ = _cached_stage(protocol.StageKind.SMOKE)
    internal_raw, internal = _cached_stage(protocol.StageKind.INTERNAL)
    confirmation_raw, confirmation = _cached_stage(protocol.StageKind.CONFIRMATION)
    assert internal.prior_stage_manifest_sha256s == (
        (
            protocol.StageKind.SMOKE,
            hashlib.sha256(smoke_raw).hexdigest(),
        ),
    )
    assert confirmation.prior_stage_manifest_sha256s == (
        (protocol.StageKind.SMOKE, hashlib.sha256(smoke_raw).hexdigest()),
        (protocol.StageKind.INTERNAL, hashlib.sha256(internal_raw).hexdigest()),
    )
    assert protocol.load_stage_manifest(confirmation_raw) == confirmation

    alternate_smoke_raw, _ = _build_stage(
        protocol.StageKind.SMOKE,
        prior_stage_manifest_bytes=(),
        namespace_suffix="alternate-prior",
    )
    with pytest.raises(protocol.DgpContextIntegrityError, match="file-digest binding"):
        protocol.validate_stage_integrity(
            current_manifest_bytes=internal_raw,
            prior_manifest_bytes=(alternate_smoke_raw,),
        )


def test_all_public_validation_entries_are_bytes_first_and_reject_fake_objects() -> None:
    smoke_raw, smoke = _cached_stage(protocol.StageKind.SMOKE)
    precommit_raw = _precommit_bytes(smoke, "structured", raw_variant="bytes-first")
    precommit_view = commitments.validate_precommit_bytes(precommit_raw)

    with pytest.raises(protocol.DgpContextIntegrityError, match="exact canonical bytes"):
        protocol.validate_stage_integrity(
            current_manifest_bytes=smoke,  # type: ignore[arg-type]
            prior_manifest_bytes=(),
        )
    with pytest.raises(protocol.DgpContextIntegrityError, match="exact tuple"):
        protocol.validate_stage_integrity(
            current_manifest_bytes=smoke_raw,
            prior_manifest_bytes=[],  # type: ignore[arg-type]
        )
    with pytest.raises(protocol.DgpContextIntegrityError):
        protocol.validate_stage_integrity(
            current_manifest_bytes=b"{}", prior_manifest_bytes=()
        )
    with pytest.raises(protocol.DgpContextIntegrityError, match="exact canonical bytes"):
        protocol.validate_precommit_to_row_mapping(
            precommit_bytes=precommit_view,  # type: ignore[arg-type]
            stage_manifest_bytes=smoke_raw,
        )
    with pytest.raises(protocol.DgpContextIntegrityError):
        protocol.validate_precommit_to_row_mapping(
            precommit_bytes=b"{}", stage_manifest_bytes=smoke_raw
        )
    with pytest.raises(protocol.DgpContextIntegrityError, match="exact canonical bytes"):
        protocol.validate_cross_family_mapping(
            left_precommit_bytes=precommit_view,  # type: ignore[arg-type]
            right_precommit_bytes=precommit_raw,
            stage_manifest_bytes=smoke_raw,
        )
    with pytest.raises(TypeError, match="left_mapping"):
        protocol.validate_cross_family_mapping(
            left_precommit_bytes=precommit_raw,
            right_precommit_bytes=precommit_raw,
            stage_manifest_bytes=smoke_raw,
            left_mapping=object(),  # type: ignore[call-arg]
        )


def test_stage_loader_and_cross_stage_gate_require_one_frozen_generator() -> None:
    smoke_raw, smoke = _cached_stage(protocol.StageKind.SMOKE)
    payload = copy.deepcopy(smoke.to_payload())
    corpus = smoke.corpora[1]
    mixed_raw = protocol.build_corpus_inventory_bytes(
        stage_kind=corpus.stage_kind,
        block_id=corpus.block_id,
        block_index=corpus.block_index,
        phase=corpus.phase,
        run_seed=corpus.run_seed,
        dgp_seed=corpus.dgp_seed,
        dgp_generator_sha256=_h("different-generator"),
        dgp_arguments_sha256=corpus.dgp_arguments_sha256,
        cohort_layer_inventory_sha256=corpus.cohort_layer_inventory_sha256,
        rows=corpus.rows,
    )
    payload["corpora"][1] = protocol.load_corpus_inventory(mixed_raw).to_payload()
    with pytest.raises(protocol.DgpContextIntegrityError, match="one frozen DGP generator"):
        protocol.load_stage_manifest(_resign_stage(payload))

    with pytest.raises(
        protocol.DgpContextIntegrityError,
        match="current/prior stages do not share one frozen DGP generator",
    ):
        _build_stage(
            protocol.StageKind.INTERNAL,
            prior_stage_manifest_bytes=(smoke_raw,),
            generator_sha256=_h("different-cross-stage-generator"),
        )


def test_strict_loaders_reject_noncanonical_and_duplicate_json_keys() -> None:
    raw, _ = _cached_stage(protocol.StageKind.SMOKE)
    with pytest.raises(protocol.DgpContextIntegrityError, match="not canonical"):
        protocol.load_stage_manifest(raw + b"\n")
    duplicate = (
        b'{"hidden_registry_entry_sha256":"'
        + (b"1" * 64)
        + b'","opaque_handle_sha256":"'
        + (b"2" * 64)
        + b'","opaque_handle_sha256":"'
        + (b"3" * 64)
        + b'","scoring_context_protocol":"cohort_closed_loop_scoring_context_v1",'
        + b'"scoring_context_sha256":"'
        + (b"4" * 64)
        + b'"}'
    )
    with pytest.raises(protocol.DgpContextIntegrityError, match="duplicate JSON key"):
        protocol.load_public_scoring_context_attestation(duplicate)


def test_row_and_context_record_have_standalone_exact_bytes_loaders() -> None:
    manifest = _cached_stage(protocol.StageKind.SMOKE)[1]
    row = manifest.corpora[0].rows[0]
    context = manifest.context_attestation_inventory.records[0]
    assert protocol.load_dgp_row_identity(
        protocol.canonical_json_bytes(row.to_payload())
    ) == row
    assert protocol.load_context_registry_record(
        protocol.canonical_json_bytes(context.context_registry_record.to_payload())
    ) == context.context_registry_record


def test_row_reorder_is_rejected_even_when_outer_self_digests_are_recomputed() -> None:
    payload = copy.deepcopy(_cached_stage(protocol.StageKind.SMOKE)[1].to_payload())
    corpus = payload["corpora"][0]
    corpus["rows"][0], corpus["rows"][1] = corpus["rows"][1], corpus["rows"][0]
    _resign_corpus(corpus)
    with pytest.raises(protocol.DgpContextIntegrityError, match="exact item order"):
        protocol.load_stage_manifest(_resign_stage(payload))


def test_duplicate_component_identity_is_rejected() -> None:
    payload = copy.deepcopy(_cached_stage(protocol.StageKind.SMOKE)[1].to_payload())
    corpus = payload["corpora"][0]
    corpus["rows"][1]["database_sha256"] = corpus["rows"][0]["database_sha256"]
    row = corpus["rows"][1]
    row["composite_row_identity_sha256"] = (
        protocol.compute_composite_row_identity_sha256(
            instance_id=row["instance_id"],
            database_sha256=row["database_sha256"],
            ground_truth_sha256=row["ground_truth_sha256"],
            reference_survival_sha256=row["reference_survival_sha256"],
        )
    )
    _resign_corpus(corpus)
    with pytest.raises(protocol.DgpContextIntegrityError, match="duplicate database"):
        protocol.load_stage_manifest(_resign_stage(payload))


def test_wrong_block_count_item_count_index_and_aggregate_hash_fail_closed() -> None:
    original = _cached_stage(protocol.StageKind.SMOKE)[1].to_payload()

    wrong_blocks = copy.deepcopy(original)
    wrong_blocks["corpora"].pop()
    with pytest.raises(protocol.DgpContextIntegrityError, match="exactly 2 corpora"):
        protocol.load_stage_manifest(_resign_stage(wrong_blocks))

    wrong_n = copy.deepcopy(original)
    corpus = wrong_n["corpora"][0]
    corpus["rows"].pop()
    corpus["item_count"] = 4
    _resign_corpus(corpus)
    with pytest.raises(protocol.DgpContextIntegrityError, match="exactly 5"):
        protocol.load_stage_manifest(_resign_stage(wrong_n))

    wrong_index = copy.deepcopy(original)
    corpus = wrong_index["corpora"][0]
    corpus["rows"][0]["instance_index"] = 1
    _resign_corpus(corpus)
    with pytest.raises(protocol.DgpContextIntegrityError, match="item_id - 1"):
        protocol.load_stage_manifest(_resign_stage(wrong_index))

    wrong_hash = copy.deepcopy(original)
    corpus = wrong_hash["corpora"][0]
    corpus["aggregate_database_sha256"] = _h("wrong aggregate")
    _resign_corpus(corpus)
    with pytest.raises(protocol.DgpContextIntegrityError, match="aggregate_database"):
        protocol.load_stage_manifest(_resign_stage(wrong_hash))


def test_wrong_preregistered_seed_is_rejected_after_valid_corpus_rehash() -> None:
    manifest = _cached_stage(protocol.StageKind.SMOKE)[1]
    corpus = manifest.corpora[0]
    wrong_raw = protocol.build_corpus_inventory_bytes(
        stage_kind=corpus.stage_kind,
        block_id=corpus.block_id,
        block_index=corpus.block_index,
        phase=corpus.phase,
        run_seed=corpus.run_seed + 1,
        dgp_seed=corpus.dgp_seed,
        dgp_generator_sha256=corpus.dgp_generator_sha256,
        dgp_arguments_sha256=corpus.dgp_arguments_sha256,
        cohort_layer_inventory_sha256=corpus.cohort_layer_inventory_sha256,
        rows=corpus.rows,
    )
    wrong_corpus = protocol.load_corpus_inventory(wrong_raw)
    payload = manifest.to_payload()
    payload["corpora"][0] = wrong_corpus.to_payload()
    with pytest.raises(protocol.DgpContextIntegrityError, match="seed table"):
        protocol.load_stage_manifest(_resign_stage(payload))


def test_cross_stage_row_collision_is_rejected_by_required_prior_validation() -> None:
    smoke_raw, smoke = _cached_stage(protocol.StageKind.SMOKE)
    collision = smoke.corpora[0].rows[0]
    with pytest.raises(
        protocol.DgpContextIntegrityError, match="cross-corpus instance_id collision"
    ):
        _build_stage(
            protocol.StageKind.INTERNAL,
            prior_stage_manifest_bytes=(smoke_raw,),
            first_row_override=collision,
        )


def test_context_inventory_rejects_missing_extra_duplicate_and_attestation_swap() -> None:
    manifest = _cached_stage(protocol.StageKind.SMOKE)[1]
    entries = manifest.context_attestation_inventory.records

    missing_raw = protocol.build_context_attestation_inventory_bytes(
        stage_kind=protocol.StageKind.SMOKE, records=entries[:-1]
    )
    missing = protocol.load_context_attestation_inventory(missing_raw)
    with pytest.raises(protocol.DgpContextIntegrityError, match="missing, extra, or swapped"):
        protocol.load_stage_manifest(_replace_context_inventory(manifest, missing))

    with pytest.raises(protocol.DgpContextIntegrityError, match="duplicate public contexts"):
        protocol.build_context_attestation_inventory_bytes(
            stage_kind=protocol.StageKind.SMOKE,
            records=(*entries, entries[0]),
        )

    second_record = entries[1].context_registry_record
    reused_opaque = entries[0].context_registry_record.opaque_handle_sha256
    second_record = replace(
        second_record,
        opaque_handle_sha256=reused_opaque,
        public_context_identity_sha256=(
            protocol.compute_public_context_identity_sha256(
                stage_kind=second_record.stage_kind,
                block_id=second_record.block_id,
                block_index=second_record.block_index,
                phase=second_record.phase,
                item_id=second_record.item_id,
                instance_index=second_record.instance_index,
                instance_id=second_record.instance_id,
                query_sha256=second_record.query_sha256,
                opaque_handle_sha256=reused_opaque,
                hidden_registry_entry_sha256=(
                    second_record.hidden_registry_entry_sha256
                ),
                scoring_context_sha256=second_record.scoring_context_sha256,
            )
        ),
    )
    second_attestation = replace(
        entries[1].public_attestation,
        opaque_handle_sha256=reused_opaque,
    )
    duplicate_handle_entry = replace(
        entries[1],
        context_registry_record=second_record,
        public_attestation=second_attestation,
        scoring_context_attestation_sha256=second_attestation.file_sha256,
    )
    with pytest.raises(protocol.DgpContextIntegrityError, match="opaque handle"):
        protocol.build_context_attestation_inventory_bytes(
            stage_kind=protocol.StageKind.SMOKE,
            records=(entries[0], duplicate_handle_entry, *entries[2:]),
        )

    extra_entry = replace(
        entries[-1],
        context_registry_record=replace(
            entries[-1].context_registry_record,
            instance_id="extra-instance",
            public_context_identity_sha256=_h("syntactically-valid-but-wrong-identity"),
        ),
    )
    with pytest.raises(protocol.DgpContextIntegrityError):
        protocol.build_context_attestation_inventory_bytes(
            stage_kind=protocol.StageKind.SMOKE,
            records=(*entries, extra_entry),
        )

    payload = manifest.to_payload()
    inventory = payload["context_attestation_inventory"]
    first, second = inventory["records"][0], inventory["records"][1]
    first["public_attestation"], second["public_attestation"] = (
        second["public_attestation"],
        first["public_attestation"],
    )
    first["scoring_context_attestation_sha256"] = protocol.canonical_sha256(
        first["public_attestation"]
    )
    second["scoring_context_attestation_sha256"] = protocol.canonical_sha256(
        second["public_attestation"]
    )
    _resign_context_inventory(inventory)
    with pytest.raises(protocol.DgpContextIntegrityError, match="digest swap"):
        protocol.load_stage_manifest(_resign_stage(payload))


def test_public_context_digest_rebuild_does_not_claim_hidden_validation() -> None:
    manifest = _cached_stage(protocol.StageKind.SMOKE)[1]
    entry = manifest.context_attestation_inventory.records[0]
    record = entry.context_registry_record
    assert record.scoring_context_sha256 == protocol.compute_scoring_context_sha256(
        scorer_source_sha256=record.scorer_source_sha256,
        dataset_ground_truth_sha256=record.dataset_ground_truth_sha256,
        instance_id=record.instance_id,
        instance_index=record.instance_index,
        reference_survival_sha256=record.reference_survival_sha256,
    )
    assert entry.public_attestation.to_payload() == {
        "scoring_context_protocol": "cohort_closed_loop_scoring_context_v1",
        "opaque_handle_sha256": record.opaque_handle_sha256,
        "scoring_context_sha256": record.scoring_context_sha256,
        "hidden_registry_entry_sha256": record.hidden_registry_entry_sha256,
    }
    assert all(
        isinstance(value, str) and len(value) == 64
        for key, value in entry.public_attestation.to_payload().items()
        if key.endswith("sha256")
    )


def test_precommit_maps_to_exact_public_row_and_context() -> None:
    stage_raw, manifest = _cached_stage(protocol.StageKind.SMOKE)
    precommit = _precommit_bytes(
        manifest, "structured", raw_variant="structured-raw"
    )
    mapping = protocol.validate_precommit_to_row_mapping(
        precommit_bytes=precommit,
        stage_manifest_bytes=stage_raw,
    )
    assert mapping.item_id == 1
    assert mapping.instance_index == 0
    assert mapping.hidden_registry_contents_validated is False
    assert mapping.scorer_reexecution_performed is False

    with pytest.raises(protocol.DgpContextIntegrityError, match="identity differs"):
        protocol.validate_precommit_to_row_mapping(
            precommit_bytes=_precommit_bytes(
                manifest,
                "structured",
                raw_variant="wrong-instance",
                instance_id_override="wrong-instance",
            ),
            stage_manifest_bytes=stage_raw,
        )
    with pytest.raises(protocol.DgpContextIntegrityError, match="dgp_sha256"):
        protocol.validate_precommit_to_row_mapping(
            precommit_bytes=_precommit_bytes(
                manifest,
                "structured",
                raw_variant="wrong-dgp",
                inventory_override=("dgp_sha256", _h("wrong dgp")),
            ),
            stage_manifest_bytes=stage_raw,
        )


def test_cross_family_allows_raw_protocol_source_difference_but_rejects_context() -> None:
    stage_raw, manifest = _cached_stage(protocol.StageKind.SMOKE)
    structured = _precommit_bytes(
        manifest, "structured", raw_variant="structured-different-raw"
    )
    online = _precommit_bytes(
        manifest, "canonical_online_icl", raw_variant="online-different-raw"
    )
    structured_view = commitments.validate_precommit_bytes(structured)
    online_view = commitments.validate_precommit_bytes(online)
    assert structured_view.raw_trace_sha256 != online_view.raw_trace_sha256
    assert structured_view.shared_raw_action_bytes != online_view.shared_raw_action_bytes
    assert dict(structured_view.inventory_sha256)["protocol_sha256"] != dict(
        online_view.inventory_sha256
    )["protocol_sha256"]
    assert dict(structured_view.inventory_sha256)["source_sha256"] != dict(
        online_view.inventory_sha256
    )["source_sha256"]

    result = protocol.validate_cross_family_mapping(
        left_precommit_bytes=structured,
        right_precommit_bytes=online,
        stage_manifest_bytes=stage_raw,
    )
    assert result.raw_trajectory_or_action_equality_required is False
    assert result.protocol_or_source_equality_required is False
    assert result.hidden_registry_contents_validated is False
    assert result.scorer_reexecution_performed is False

    changed_context = _precommit_bytes(
        manifest,
        "canonical_online_icl",
        raw_variant="online-changed-context",
        scoring_context_override=_h("changed context"),
    )
    with pytest.raises(protocol.DgpContextIntegrityError, match="context"):
        protocol.validate_cross_family_mapping(
            left_precommit_bytes=structured,
            right_precommit_bytes=changed_context,
            stage_manifest_bytes=stage_raw,
        )


def test_cross_family_rejects_shared_environment_or_schedule_mismatch() -> None:
    stage_raw, manifest = _cached_stage(protocol.StageKind.SMOKE)
    structured = _precommit_bytes(manifest, "structured", raw_variant="s")
    for key in ("environment_sha256", "schedule_sha256"):
        changed = _precommit_bytes(
            manifest,
            "canonical_online_icl",
            raw_variant=f"changed-{key}",
            inventory_override=(key, _h(f"changed:{key}")),
        )
        with pytest.raises(protocol.DgpContextIntegrityError, match=key):
            protocol.validate_cross_family_mapping(
                left_precommit_bytes=structured,
                right_precommit_bytes=changed,
                stage_manifest_bytes=stage_raw,
            )
