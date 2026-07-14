from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

from validate_cohort_causal_results import (
    BOOTSTRAP_REPLICATES,
    BOOTSTRAP_SEED,
    EXPECTED_ADAPTER_INIT_SEED,
    EXPECTED_CORPORA,
    EXPECTED_OPERATIONS,
    EXPECTED_RUN_SEEDS,
    EXPECTED_SAMPLING_RNG_BINDING,
    EXPECTED_SYSTEM_CONFIG,
    EXPECTED_TASK_CONFIG,
    EXPERIMENT,
    LIMITATION,
    MECHANISM_LABEL,
    PREREGISTERED_PARENT_COMMIT,
    PROTOCOL,
    canonical_sha256,
    corpus_projection_from_dataset_manifest,
    evaluate,
    masked_pair_config_sha256,
    tape_item_sha256,
    tape_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "validate_cohort_causal_results.py"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _integrity(*, parse_retries: int = 0, repairs: int = 0) -> dict:
    return {
        "fallback": False,
        "hard_schema_failure": False,
        "missing": False,
        "parse_retries": parse_retries,
        "repairs": repairs,
        "schema_valid": True,
        "synthetic": False,
        "timed_out": False,
    }


def _corpus(name: str) -> dict:
    is_adaptation = name == "adaptation"
    prefix = "adapt" if is_adaptation else "eval"
    expected = EXPECTED_CORPORA[name]
    corpus = {
        "aggregate_sha256": expected["aggregate_sha256"],
        "canonical_instance_ids": [
            f"cohort_studies:{expected['schedule_id']}:{prefix}-instance-{index:02d}"
            for index in range(20)
        ],
        "database_sha256": {"cohort.sqlite": _digest(f"{prefix}-database")},
        "dataset_manifest_sha256": _digest(f"{prefix}-manifest"),
        "dgp_seed": expected["dgp_seed"],
        "ground_truth_sha256": {"ground_truth.json": _digest(f"{prefix}-gt")},
        "schedule_id": expected["schedule_id"],
        "schedule_sha256": expected["schedule_sha256"],
        "used_for_evaluation": not is_adaptation,
        "used_for_updates": is_adaptation,
    }
    if not is_adaptation:
        corpus["never_updated"] = True
    return corpus


def _tape(
    run_seed: int, adaptation_ids: list[str], initial_hash: str
) -> tuple[dict, dict]:
    items = []
    for index, instance_id in enumerate(adaptation_ids):
        committed_ids = [run_seed % 10_000, index, 101, 102]
        committed_payload = {"ids": committed_ids, "prompt_tokens": 2}
        committed_reward = 0.2 + index / 1000
        committed = {
            **committed_payload,
            "prompt_token_ids_sha256": canonical_sha256(committed_ids[:2]),
            "reward": committed_reward,
            "reward_sha256": canonical_sha256(committed_reward),
            "target_token_ids_sha256": canonical_sha256(committed_ids[2:]),
            "training_example_sha256": canonical_sha256(committed_payload),
        }
        candidates = [
            {
                "candidate": f"candidate-{run_seed}-{index}-{candidate_index}",
                "candidate_sha256": _digest(
                    f"candidate-{run_seed}-{index}-{candidate_index}"
                ),
                "reward": candidate_index / 10,
                "reward_sha256": canonical_sha256(candidate_index / 10),
            }
            for candidate_index in range(8)
        ]
        selected_batches = []
        for role, candidate_index, signed_weight in (
            ("positive", 7, 1.0),
            ("negative", 0, -0.5),
        ):
            batch = {
                "candidate_index": candidate_index,
                "ids": [index, candidate_index, 201, 202],
                "prompt_tokens": 2,
                "role": role,
                "signed_weight": signed_weight,
            }
            batch["batch_sha256"] = canonical_sha256(batch)
            selected_batches.append(batch)
        sampling = {
            "candidate_count": 8,
            "duplicates": 0,
            "generation_failures": 0,
            "initial_sample_attempts": 7,
            "interaction_step": index + 1,
            "parse_failures": 0,
            "registered_run_seed": run_seed,
            "requested_best_of_n": 8,
            "sampling_prompt_sha256": _digest(f"sampling-prompt-{run_seed}-{index}"),
            "sampling_rng_binding": EXPECTED_SAMPLING_RNG_BINDING,
            "valid_unique": 8,
        }
        sampling["provenance_sha256"] = canonical_sha256(sampling)
        item = {
            "committed_reward_pg": committed,
            "env_bon": {
                "candidate_order_sha256": canonical_sha256(candidates),
                "candidates": candidates,
                "prompt": f"prompt-{run_seed}-{index}",
                "prompt_sha256": _digest(f"prompt-{run_seed}-{index}"),
                "selected_batches": selected_batches,
            },
            "instance_id": instance_id,
            "instance_index": index,
            "integrity": _integrity(),
            "sampling_provenance": sampling,
            "schema_version": 1,
            "sequence_index": index,
        }
        item["item_sha256"] = tape_item_sha256(item)
        items.append(item)
    tape = {
        "collector_lr0_verified": True,
        "collector_trainable_param_sha256_final": initial_hash,
        "collector_trainable_param_sha256_initial": initial_hash,
        "items": items,
        "learning_rate_ablation_fields": ["ttt_lr", "reward_pg_lr"],
        "mechanism_label": f"{MECHANISM_LABEL}; {LIMITATION}",
        "protocol": PROTOCOL,
        "schema_version": 1,
        "update_contract": {
            key: EXPECTED_SYSTEM_CONFIG[key]
            for key in (
                "adapter_init_seed",
                "adaptation_context_policy",
                "best_of_n",
                "bon_critic",
                "bon_env_reward",
                "context_policy",
                "distill_contrastive",
                "history_ttt",
                "method",
                "model_path",
                "num_virtual_tokens",
                "peft_method",
                "reward_negative_weight",
                "reward_pg_steps",
                "reward_positive_weight",
                "reward_update_rule",
                "ttt_max_tokens",
                "ttt_steps",
            )
        },
    }
    tape["tape_sha256"] = tape_sha256(tape)
    verification = {
        "digest_verified": True,
        "items": [
            {
                "digest_verified": True,
                "item_sha256": item["item_sha256"],
                "sequence_index": index,
            }
            for index, item in enumerate(items)
        ],
    }
    return tape, verification


def _replay(tape: dict, *, arm: str, run_seed: int, initial_hash: str) -> dict:
    current = initial_hash
    items = []
    for index, tape_item in enumerate(tape["items"]):
        item_before = current
        operations = []
        for operation_index, operation in enumerate(EXPECTED_OPERATIONS):
            before = current
            after = (
                _digest(f"active-{run_seed}-{index}-{operation_index}")
                if arm == "active"
                else initial_hash
            )
            operations.append(
                {
                    "batch_count": 1 if operation_index == 0 else 2,
                    "input_sha256": (
                        [
                            tape_item["committed_reward_pg"][
                                "training_example_sha256"
                            ],
                            tape_item["committed_reward_pg"]["reward_sha256"],
                        ]
                        if operation_index == 0
                        else [
                            batch["batch_sha256"]
                            for batch in tape_item["env_bon"]["selected_batches"]
                        ]
                    ),
                    "operation": operation,
                    "trainable_param_sha256_after": after,
                    "trainable_param_sha256_before": before,
                }
            )
            current = after
        items.append(
            {
                "best_env_reward": 0.7,
                "instance_id": tape_item["instance_id"],
                "instance_index": tape_item["instance_index"],
                "integrity": deepcopy(tape_item["integrity"]),
                "item_sha256": tape_item["item_sha256"],
                "operation_count": 2,
                "operations": operations,
                "sampling_provenance": deepcopy(
                    tape_item["sampling_provenance"]
                ),
                "sequence_index": index,
                "status": "complete",
                "trainable_param_sha256_after": current,
                "trainable_param_sha256_before": item_before,
            }
        )
    return {
        "digest_verified": True,
        "item_count": 20,
        "items": items,
        "operation_count": 40,
        "operations_per_item": 2,
        "status": "complete",
        "tape_sha256": tape["tape_sha256"],
        "trainable_param_sha256_final": current,
        "trainable_param_sha256_initial": initial_hash,
    }


def _cell(
    *,
    arm: str,
    run_seed: int,
    delta: float,
    tape: dict,
    provenance: dict,
    adaptation: dict,
    heldout: dict,
    initial_hash: str,
) -> dict:
    config = deepcopy(EXPECTED_SYSTEM_CONFIG)
    config["grpo_run_seed"] = run_seed
    if arm == "lr0":
        config["ttt_lr"] = 0.0
        config["reward_pg_lr"] = 0.0
    baseline = 0.1
    reward = baseline + delta if arm == "active" else baseline
    outcomes = [
        {
            "instance_id": instance_id,
            "instance_index": index,
            "integrity": _integrity(),
            "reward": reward,
        }
        for index, instance_id in enumerate(heldout["canonical_instance_ids"])
    ]
    return {
        "adaptation_corpus_sha256": adaptation["aggregate_sha256"],
        "arm": arm,
        "evaluation_order_sha256": canonical_sha256(
            heldout["canonical_instance_ids"]
        ),
        "heldout_corpus_sha256": heldout["aggregate_sha256"],
        "heldout_outcomes": outcomes,
        "heldout_updates_frozen": True,
        "integrity_counters": {
            "fallbacks": 0,
            "hard_schema_failures": 0,
            "missing_outcomes": 0,
            "parse_retries": 0,
            "repairs": 0,
            "synthetic_outcomes": 0,
            "timed_out_outcomes": 0,
        },
        "masked_pair_config_sha256": masked_pair_config_sha256(config),
        "outcome_schema_version": 1,
        "provenance": deepcopy(provenance),
        "replay": _replay(
            tape, arm=arm, run_seed=run_seed, initial_hash=initial_hash
        ),
        "run_seed": run_seed,
        "score": statistics.mean(row["reward"] for row in outcomes),
        "status": "completed",
        "system_config": config,
        "system_config_sha256": canonical_sha256(config),
        "tape_sha256": tape["tape_sha256"],
        "task_config": deepcopy(EXPECTED_TASK_CONFIG),
        "task_config_sha256": canonical_sha256(EXPECTED_TASK_CONFIG),
    }


def _manifest(deltas: tuple[float, float, float] = (0.04, 0.05, 0.03)) -> dict:
    adaptation = _corpus("adaptation")
    heldout = _corpus("heldout")
    provenance = {
        "adapter_init_seed": EXPECTED_ADAPTER_INIT_SEED,
        "environment_lock_sha256": _digest("environment-lock"),
        "evaluation_code_sha256": _digest("evaluation-code"),
        "model_path": EXPECTED_SYSTEM_CONFIG["model_path"],
        "model_sha256": _digest("model"),
        "preregistered_parent_commit": PREREGISTERED_PARENT_COMMIT,
        "source_commit": "a" * 40,
        "tokenizer_sha256": _digest("tokenizer"),
    }
    initial_hash = _digest("shared-adapter-initialization")
    pairs = []
    for run_seed, delta in zip(EXPECTED_RUN_SEEDS, deltas, strict=True):
        tape, verification = _tape(
            run_seed, adaptation["canonical_instance_ids"], initial_hash
        )
        pairs.append(
            {
                "active": _cell(
                    arm="active",
                    run_seed=run_seed,
                    delta=delta,
                    tape=tape,
                    provenance=provenance,
                    adaptation=adaptation,
                    heldout=heldout,
                    initial_hash=initial_hash,
                ),
                "lr0": _cell(
                    arm="lr0",
                    run_seed=run_seed,
                    delta=delta,
                    tape=tape,
                    provenance=provenance,
                    adaptation=adaptation,
                    heldout=heldout,
                    initial_hash=initial_hash,
                ),
                "pair_id": f"cohort-qonly-causal-{run_seed}",
                "run_seed": run_seed,
                "tape": tape,
                "tape_verification": verification,
            }
        )
    return {
        "corpora": {"adaptation": adaptation, "heldout": heldout},
        "experiment": EXPERIMENT,
        "limitation": LIMITATION,
        "mechanism_label": MECHANISM_LABEL,
        "pairs": pairs,
        "preregistration_sha256": _digest("preregistration"),
        "protocol": PROTOCOL,
        "provenance": provenance,
        "schema_version": 1,
    }


def test_passes_only_complete_positive_preregistered_gate() -> None:
    report = evaluate(_manifest())

    assert report["errors"] == []
    assert report["status"] == "valid"
    assert report["decision"] == "pass"
    assert report["aggregate"]["mean_delta"] == 0.04
    assert report["aggregate"]["positive_seeds"] == 3
    assert report["aggregate"]["ci_95_lower"] == 0.03
    assert report["aggregate"]["ci_95_upper"] == 0.05
    assert all(report["threshold_checks"].values())


def test_checked_in_dataset_manifests_project_unambiguously() -> None:
    for role, directory in (
        ("adaptation", "causal_adapt_2026071411"),
        ("heldout", "causal_eval_2026071412"),
    ):
        path = ROOT / "data" / "cohort_studies" / directory / "manifest.json"
        payload = json.loads(path.read_text())
        projection = corpus_projection_from_dataset_manifest(
            payload,
            dataset_manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            role=role,
        )

        assert projection["aggregate_sha256"] == EXPECTED_CORPORA[role][
            "aggregate_sha256"
        ]
        assert projection["schedule_sha256"] == EXPECTED_CORPORA[role][
            "schedule_sha256"
        ]
        assert len(projection["canonical_instance_ids"]) == 20
        assert len(projection["database_sha256"]) == 20
        assert set(projection["ground_truth_sha256"]) == {
            "ground_truth.json",
            "instance_references.json",
        }
        assert projection["never_updated"] is True if role == "heldout" else (
            "never_updated" not in projection
        )


def test_valid_no_go_is_distinct_from_invalid() -> None:
    report = evaluate(_manifest((0.01, 0.02, 0.01)))

    assert report["errors"] == []
    assert report["status"] == "valid"
    assert report["decision"] == "valid_no_go"
    assert report["threshold_checks"]["all_3_seed_deltas_gt_0"] is True
    assert report["threshold_checks"]["mean_delta_gte_0_02"] is False


def test_one_nonpositive_seed_is_valid_no_go_even_if_mean_exceeds_threshold() -> None:
    report = evaluate(_manifest((-0.001, 0.031, 0.031)))

    assert report["errors"] == []
    assert report["decision"] == "valid_no_go"
    assert report["aggregate"]["mean_delta"] > 0.02
    assert report["threshold_checks"]["all_3_seed_deltas_gt_0"] is False


def test_bootstrap_is_deterministic_and_uses_preregistered_parameters() -> None:
    manifest = _manifest((0.03, 0.04, 0.05))

    first = evaluate(manifest)
    second = evaluate(deepcopy(manifest))

    assert first["bootstrap"] == second["bootstrap"]
    assert first["bootstrap"]["seed"] == BOOTSTRAP_SEED
    assert first["bootstrap"]["replicates"] == BOOTSTRAP_REPLICATES
    assert first["bootstrap"]["method"].endswith("percentile_type7")


def test_tampered_tape_item_fails_closed() -> None:
    manifest = _manifest()
    manifest["pairs"][0]["tape"]["items"][3]["committed_reward_pg"][
        "reward_sha256"
    ] = _digest("tampered-reward")

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "item SHA-256 verification failed" in error for error in report["errors"]
    )
    assert any(
        "tape SHA-256 verification failed" in error for error in report["errors"]
    )


def test_tampered_sampling_provenance_fails_closed() -> None:
    manifest = _manifest()
    sampling = manifest["pairs"][1]["tape"]["items"][5][
        "sampling_provenance"
    ]
    sampling["registered_run_seed"] += 1

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any("registered_run_seed mismatch" in error for error in report["errors"])
    assert any("provenance SHA-256 mismatch" in error for error in report["errors"])


def test_valid_short_candidate_groups_and_real_terminal_steps_are_accepted() -> None:
    manifest = _manifest()
    for pair in manifest["pairs"]:
        tape = pair["tape"]
        for position, item in enumerate(tape["items"]):
            env_bon = item["env_bon"]
            env_bon["candidates"] = env_bon["candidates"][:6]
            env_bon["candidate_order_sha256"] = canonical_sha256(
                env_bon["candidates"]
            )
            positive = env_bon["selected_batches"][0]
            positive["candidate_index"] = 5
            positive["ids"][1] = 5
            positive_without_digest = dict(positive)
            positive_without_digest.pop("batch_sha256")
            positive["batch_sha256"] = canonical_sha256(positive_without_digest)

            sampling = item["sampling_provenance"]
            sampling.update(
                {
                    "candidate_count": 6,
                    "duplicates": 1,
                    "interaction_step": 21 * (position + 1),
                    "parse_failures": 1,
                    "valid_unique": 6,
                }
            )
            sampling_without_digest = dict(sampling)
            sampling_without_digest.pop("provenance_sha256")
            sampling["provenance_sha256"] = canonical_sha256(
                sampling_without_digest
            )
            item["item_sha256"] = tape_item_sha256(item)

        tape["tape_sha256"] = tape_sha256(tape)
        pair["tape_verification"] = {
            "digest_verified": True,
            "items": [
                {
                    "digest_verified": True,
                    "item_sha256": item["item_sha256"],
                    "sequence_index": position,
                }
                for position, item in enumerate(tape["items"])
            ],
        }
        for arm in ("active", "lr0"):
            cell = pair[arm]
            cell["tape_sha256"] = tape["tape_sha256"]
            replay = cell["replay"]
            replay["tape_sha256"] = tape["tape_sha256"]
            for tape_item, replay_item in zip(
                tape["items"], replay["items"], strict=True
            ):
                replay_item["item_sha256"] = tape_item["item_sha256"]
                replay_item["sampling_provenance"] = deepcopy(
                    tape_item["sampling_provenance"]
                )
                replay_item["operations"][1]["input_sha256"] = [
                    batch["batch_sha256"]
                    for batch in tape_item["env_bon"]["selected_batches"]
                ]

    report = evaluate(manifest)

    assert report["decision"] == "pass"
    assert report["errors"] == []


def test_tampered_selected_batch_and_replay_input_fail_closed() -> None:
    manifest = _manifest()
    pair = manifest["pairs"][0]
    pair["tape"]["items"][2]["env_bon"]["selected_batches"][0][
        "signed_weight"
    ] = 0.5
    pair["active"]["replay"]["items"][3]["operations"][0][
        "input_sha256"
    ][0] = _digest("wrong-replay-input")

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any("batch SHA-256 mismatch" in error for error in report["errors"])
    assert any("replay input SHA-256 mismatch" in error for error in report["errors"])


def test_recomputed_outer_digests_cannot_hide_invalid_tape_semantics() -> None:
    """Outer item/root hashes must not bless a semantically forged update tape."""

    manifest = _manifest()
    pair = manifest["pairs"][0]
    tape = pair["tape"]
    item = tape["items"][0]
    # Claim the worst candidate is the positive/best target and corrupt a
    # candidate content hash, then recompute every enclosing digest as an
    # attacker or buggy assembler could.
    positive = item["env_bon"]["selected_batches"][0]
    positive["candidate_index"] = 0
    positive_without_digest = dict(positive)
    positive_without_digest.pop("batch_sha256")
    positive["batch_sha256"] = canonical_sha256(positive_without_digest)
    item["env_bon"]["candidates"][3]["candidate_sha256"] = "0" * 64
    item["item_sha256"] = tape_item_sha256(item)
    tape["tape_sha256"] = tape_sha256(tape)
    pair["tape_verification"] = {
        "digest_verified": True,
        "items": [
            {
                "digest_verified": True,
                "item_sha256": row["item_sha256"],
                "sequence_index": index,
            }
            for index, row in enumerate(tape["items"])
        ],
    }
    for arm in ("active", "lr0"):
        cell = pair[arm]
        cell["tape_sha256"] = tape["tape_sha256"]
        cell["replay"]["tape_sha256"] = tape["tape_sha256"]
        replay_item = cell["replay"]["items"][0]
        replay_item["item_sha256"] = item["item_sha256"]
        replay_item["operations"][1]["input_sha256"] = [
            batch["batch_sha256"]
            for batch in item["env_bon"]["selected_batches"]
        ]

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any("candidate_sha256 mismatch" in error for error in report["errors"])
    assert any(
        "selected candidate role/index mismatch" in error for error in report["errors"]
    )


def test_reordered_heldout_outcomes_fail_closed() -> None:
    manifest = _manifest()
    outcomes = manifest["pairs"][1]["active"]["heldout_outcomes"]
    outcomes[4], outcomes[5] = outcomes[5], outcomes[4]

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "held-out instance ID/order mismatch" in error for error in report["errors"]
    )


def test_missing_outcome_fails_closed() -> None:
    manifest = _manifest()
    manifest["pairs"][2]["lr0"]["heldout_outcomes"].pop()

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "heldout_outcomes must contain exactly 20" in error
        for error in report["errors"]
    )


def test_schema_regression_and_fallback_fail_closed() -> None:
    manifest = _manifest()
    row = manifest["pairs"][0]["active"]["heldout_outcomes"][0]["integrity"]
    row["schema_valid"] = False
    row["fallback"] = True
    manifest["pairs"][0]["active"]["integrity_counters"]["fallbacks"] = 1

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any("schema_valid must be true" in error for error in report["errors"])
    assert any("fallback must be false" in error for error in report["errors"])


def test_config_difference_beyond_two_learning_rates_fails_closed() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][0]["lr0"]
    cell["system_config"]["best_of_n"] = 4
    cell["system_config_sha256"] = canonical_sha256(cell["system_config"])
    cell["masked_pair_config_sha256"] = masked_pair_config_sha256(
        cell["system_config"]
    )

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "system config differs from preregistration" in error
        for error in report["errors"]
    )
    assert any("configs differ beyond" in error for error in report["errors"])


def test_lr0_parameter_change_and_active_no_change_fail_closed() -> None:
    lr0_manifest = _manifest()
    lr0_replay = lr0_manifest["pairs"][0]["lr0"]["replay"]
    changed = _digest("illegal-lr0-change")
    lr0_replay["items"][0]["operations"][0][
        "trainable_param_sha256_after"
    ] = changed
    lr0_report = evaluate(lr0_manifest)

    active_manifest = _manifest()
    active = active_manifest["pairs"][0]["active"]
    active["replay"] = _replay(
        active_manifest["pairs"][0]["tape"],
        arm="lr0",
        run_seed=EXPECTED_RUN_SEEDS[0],
        initial_hash=active["replay"]["trainable_param_sha256_initial"],
    )
    active_report = evaluate(active_manifest)

    assert lr0_report["decision"] == "invalid"
    assert any(
        "LR0 replay operation hash changed" in error
        for error in lr0_report["errors"]
    )
    assert active_report["decision"] == "invalid"
    assert any(
        "active final parameter hash did not change" in error
        for error in active_report["errors"]
    )


def test_collector_hash_change_fails_closed() -> None:
    manifest = _manifest()
    manifest["pairs"][0]["tape"][
        "collector_trainable_param_sha256_final"
    ] = _digest("collector-illegally-updated")

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "LR0 collector trainable-parameter hash changed" in error
        for error in report["errors"]
    )


def test_ordered_update_operation_mismatch_fails_closed() -> None:
    manifest = _manifest()
    operations = manifest["pairs"][2]["lr0"]["replay"]["items"][7]["operations"]
    operations[0]["operation"] = "bon_env_best_worst_sft"

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any("wrong ordered operation" in error for error in report["errors"])
    assert any(
        "ordered operation sequence mismatch" in error for error in report["errors"]
    )


def test_same_adaptation_and_heldout_corpus_fails_closed() -> None:
    manifest = _manifest()
    manifest["corpora"]["heldout"]["aggregate_sha256"] = manifest["corpora"][
        "adaptation"
    ]["aggregate_sha256"]
    for pair in manifest["pairs"]:
        for arm in ("active", "lr0"):
            pair[arm]["heldout_corpus_sha256"] = manifest["corpora"]["heldout"][
                "aggregate_sha256"
            ]

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "aggregate corpus SHA-256 must differ" in error for error in report["errors"]
    )


def test_active_parse_repair_regression_fails_closed() -> None:
    manifest = _manifest()
    active = manifest["pairs"][1]["active"]
    active["heldout_outcomes"][0]["integrity"]["parse_retries"] = 1
    active["integrity_counters"]["parse_retries"] = 1

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "active parse retry/repair total exceeds LR0" in error
        for error in report["errors"]
    )


def test_cli_invalid_exits_nonzero_but_valid_no_go_exits_zero(tmp_path: Path) -> None:
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text(json.dumps({}))
    invalid = subprocess.run(
        [sys.executable, str(VALIDATOR), str(invalid_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    no_go_path = tmp_path / "no-go.json"
    no_go_path.write_text(json.dumps(_manifest((0.01, 0.01, 0.01))))
    output_path = tmp_path / "decision.json"
    no_go = subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--manifest",
            str(no_go_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert invalid.returncode == 1
    assert json.loads(invalid.stdout)["decision"] == "invalid"
    assert no_go.returncode == 0
    report = json.loads(no_go.stdout)
    assert report["decision"] == "valid_no_go"
    assert json.loads(output_path.read_text()) == report
