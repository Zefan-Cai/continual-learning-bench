from __future__ import annotations

import hashlib
import json
import shutil
import statistics
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import validate_cohort_causal_results as validator
from validate_cohort_causal_results import (
    BOOTSTRAP_REPLICATES,
    BOOTSTRAP_SEED,
    EXPECTED_ADAPTER_INIT_SEED,
    EXPECTED_CORPORA,
    EXPECTED_OPERATIONS,
    EXPECTED_PREREGISTRATION_SHA256,
    EXPECTED_RUN_SEEDS,
    EXPECTED_SAMPLING_RNG_BINDING,
    EXPECTED_STATISTICAL_ADDENDUM_SHA256,
    EXPECTED_SYSTEM_CONFIG,
    EXPECTED_TASK_CONFIG,
    EXPERIMENT,
    LIMITATION,
    MECHANISM_LABEL,
    PREREGISTERED_PARENT_COMMIT,
    PROTOCOL,
    STATISTICAL_ADDENDUM_FILENAME,
    _TERMINAL_RESPONSE_METADATA_KEYS,
    _exact_zero_value_count,
    _load_checked_in_heldout_scoring_contract,
    _rescore_terminal_action,
    canonical_sha256,
    corpus_projection_from_dataset_manifest,
    evaluate,
    masked_pair_config_sha256,
    tape_item_sha256,
    tape_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "validate_cohort_causal_results.py"
_ARM_ACTION_CACHE: dict[
    float, tuple[dict[str, float], dict[str, float]]
] = {}
_TERMINAL_PROMPT = (
    "Provide your survival estimates for all 36 cohorts. "
    "Each field is named {cohort_id}__s12, {cohort_id}__s24, "
    "{cohort_id}__s36 and takes a float between 0 and 1 "
    "representing P(survival) at that time horizon. "
    "Use all knowledge accumulated from the studies you have seen."
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _copy_checked_in_corpus(tmp_path: Path, role: str) -> Path:
    directory = (
        "causal_adapt_2026071411"
        if role == "adaptation"
        else "causal_eval_2026071412"
    )
    source = ROOT / "data/cohort_studies" / directory
    destination = tmp_path / "data/cohort_studies" / directory
    shutil.copytree(source, destination)
    schedule_source = (
        ROOT / "src/tasks/cohort_studies/schedules" / f"{directory}.json"
    )
    schedule_destination = (
        tmp_path / "src/tasks/cohort_studies/schedules" / f"{directory}.json"
    )
    schedule_destination.parent.mkdir(parents=True)
    shutil.copy2(schedule_source, schedule_destination)
    return destination


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
    directory = (
        "causal_adapt_2026071411"
        if name == "adaptation"
        else "causal_eval_2026071412"
    )
    manifest_path = ROOT / "data/cohort_studies" / directory / "manifest.json"
    raw = manifest_path.read_bytes()
    return corpus_projection_from_dataset_manifest(
        json.loads(raw),
        dataset_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        role=name,
    )


def _scoring_contract(heldout: dict) -> dict:
    errors: list[str] = []
    contract = _load_checked_in_heldout_scoring_contract(
        heldout_corpus=heldout,
        heldout_ids=heldout["canonical_instance_ids"],
        errors=errors,
    )
    assert contract is not None
    assert errors == []
    return contract


def _truth_action(contract: dict) -> dict[str, float]:
    return {
        f"{cohort_id}__s{horizon}": float(truth[f"survival_{horizon}m"])
        for cohort_id, truth in contract["ground_truth"].items()
        for horizon in (12, 24, 36)
    }


def _score_action(contract: dict, instance_id: str, action: dict) -> float:
    errors: list[str] = []
    score = _rescore_terminal_action(
        action,
        instance_id=instance_id,
        scoring_contract=contract,
        label="test",
        errors=errors,
    )
    assert score is not None
    assert errors == []
    return score


def _fixed_arm_actions(
    contract: dict, instance_ids: list[str], delta: float
) -> tuple[dict[str, float], dict[str, float]]:
    """Return one fixed action per arm with an exact fixed paired delta.

    References vary by held-out ID, so absolute rewards vary.  The reference
    term cancels from active-minus-LR0, matching the true greedy qonly contract.
    """

    target = round(abs(float(delta)), 6)
    cache_key = round(float(delta), 6)
    if cache_key in _ARM_ACTION_CACHE:
        active, lr0 = _ARM_ACTION_CACHE[cache_key]
        return deepcopy(active), deepcopy(lr0)
    truth_action = _truth_action(contract)
    if target == 0.0:
        active, lr0 = truth_action, deepcopy(truth_action)
        _ARM_ACTION_CACHE[cache_key] = (deepcopy(active), deepcopy(lr0))
        return active, lr0
    endpoint = {field: 1.0 for field in truth_action}
    lower = 0.0
    upper = 1.0
    degraded: dict[str, float] | None = None
    for _ in range(80):
        weight = (lower + upper) / 2.0
        candidate = {
            field: truth_action[field]
            + weight * (endpoint[field] - truth_action[field])
            for field in truth_action
        }
        degradations = {
            round(
                _score_action(contract, instance_id, truth_action)
                - _score_action(contract, instance_id, candidate),
                6,
            )
            for instance_id in instance_ids
        }
        if degradations == {target}:
            degraded = candidate
            break
        if statistics.mean(degradations) < target:
            lower = weight
        else:
            upper = weight
    assert degraded is not None, (delta, degradations)
    if delta > 0.0:
        active, lr0 = truth_action, degraded
    else:
        active, lr0 = degraded, truth_action
    _ARM_ACTION_CACHE[cache_key] = (deepcopy(active), deepcopy(lr0))
    return active, lr0


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
    pair_id: str,
    run_seed: int,
    delta: float,
    tape: dict,
    provenance: dict,
    adaptation: dict,
    heldout: dict,
    initial_hash: str,
    scoring_contract: dict,
) -> dict:
    config = deepcopy(EXPECTED_SYSTEM_CONFIG)
    config["grpo_run_seed"] = run_seed
    if arm == "lr0":
        config["ttt_lr"] = 0.0
        config["reward_pg_lr"] = 0.0
    active_action, lr0_action = _fixed_arm_actions(
        scoring_contract, heldout["canonical_instance_ids"], delta
    )
    arm_action = active_action if arm == "active" else lr0_action
    outcomes = []
    trace_outcomes = []
    interactions = []
    for index, instance_id in enumerate(heldout["canonical_instance_ids"]):
        action = deepcopy(arm_action)
        reward = _score_action(scoring_contract, instance_id, action)
        integrity = _integrity()
        outcomes.append(
            {
                "instance_id": instance_id,
                "instance_index": index,
                "integrity": integrity,
                "reward": reward,
            }
        )
        trace_outcomes.append(
            {
                "cost_usd": 0.0,
                "instance_id": instance_id,
                "instance_index": index,
                "latency_seconds": 0.0,
                "metadata": {},
                "raw_metric_higher_is_better": True,
                "raw_metric_name": "kl_information_gain_bits",
                "raw_metric_value": reward,
                "reward": reward,
                "success": reward > 0.0,
            }
        )
        for local_step in range(20):
            interaction_index = index * 21 + local_step
            interactions.append(
                {
                    "done": False,
                    "observation": {"instance_complete": False},
                    "query": {
                        "instance_id": instance_id,
                        "instance_index": index,
                    },
                    "response": {},
                    "step_number": interaction_index + 1,
                    "timestamp": "2026-07-14T00:00:00",
                    "timing": {},
                    "usage": {},
                }
            )
        response_metadata = {
            key: None for key in _TERMINAL_RESPONSE_METADATA_KEYS
        }
        response_metadata.update(
            {
                "parse_repair_used": False,
                "parse_retries_used": 0,
            }
        )
        variant = instance_id.rsplit(":", 1)[-1]
        reference = scoring_contract["references"][variant]
        interactions.append(
            {
                "done": index == len(heldout["canonical_instance_ids"]) - 1,
                "observation": {
                    "content": "Report submitted.",
                    "instance_complete": True,
                    "metadata": {
                        "cohort_gt": deepcopy(scoring_contract["cohort_gt"]),
                        "env_feedback_instance_id": instance_id,
                        "env_feedback_instance_index": index,
                        "env_feedback_raw_metric_higher_is_better": True,
                        "env_feedback_raw_metric_name": "kl_information_gain_bits",
                        "env_feedback_raw_metric_value": reward,
                        "env_feedback_reward": reward,
                        "env_feedback_success": reward > 0.0,
                        "ref_survival": [
                            reference[f"survival_{horizon}m"]
                            for horizon in (12, 24, 36)
                        ],
                    },
                },
                "query": {
                    "feedback": None,
                    "instance_id": instance_id,
                    "instance_index": index,
                    "metadata": {
                        "instance_idx": index,
                        "schedule_id": EXPECTED_TASK_CONFIG["schedule"],
                        "step": "submission_extraction",
                        "study_name": variant.split("_", 1)[0].upper(),
                    },
                    "prompt": _TERMINAL_PROMPT,
                    "response_schema": "CohortSubmission",
                },
                "response": {
                    "action": action,
                    "action_type": "structured",
                    "metadata": response_metadata,
                },
                "step_number": (index + 1) * 21,
                "timestamp": "2026-07-14T00:00:00",
                "timing": {},
                "usage": {},
            }
        )
    trace_score = statistics.mean(row["reward"] for row in trace_outcomes)
    trace_task_params = {
        key: EXPECTED_TASK_CONFIG[key]
        for key in (
            "action_budget",
            "dataset_path",
            "num_instances",
            "repeat_instructions",
            "schedule",
            "seed",
        )
    }
    heldout_trace = {
        "artifacts": {},
        "execution": {
            "avg_response_seconds": 0.0,
            "end_time": "2026-07-14T00:00:00",
            "max_response_seconds": 0.0,
            "run_group_id": pair_id,
            "run_index": 0,
            "start_time": "2026-07-14T00:00:00",
            "total_interactions": len(interactions),
            "total_response_seconds": 0.0,
            "usage": {},
            "wall_duration_seconds": 0.0,
        },
        "instance_outcomes": trace_outcomes,
        "interactions": interactions,
        "phase": "baseline",
        "result": {
            "eval_metrics": {},
            "instance_outcomes": deepcopy(trace_outcomes),
            "metrics": {},
            "score": trace_score,
            "summary": "synthetic exact-schema trace",
        },
        "schedule": EXPECTED_TASK_CONFIG["schedule"],
        "status": "completed",
        "system": {
            "continuity": {},
            "name": "qwen_local",
            "params": deepcopy(config),
        },
        "system_artifacts": None,
        "system_memory": None,
        "task": {"name": "cohort_studies", "params": trace_task_params},
        "task_brief": None,
    }
    return {
        "adaptation_corpus_sha256": adaptation["aggregate_sha256"],
        "arm": arm,
        "evaluation_order_sha256": canonical_sha256(
            heldout["canonical_instance_ids"]
        ),
        "heldout_corpus_sha256": heldout["aggregate_sha256"],
        "heldout_outcomes": outcomes,
        "heldout_trace": heldout_trace,
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
        "trace_path": f"artifacts/traces/{arm}-{run_seed}.json",
        "trace_sha256": canonical_sha256(heldout_trace),
    }


def _manifest(deltas: tuple[float, float, float] = (0.04, 0.05, 0.03)) -> dict:
    adaptation = _corpus("adaptation")
    heldout = _corpus("heldout")
    scoring_contract = _scoring_contract(heldout)
    provenance = {
        "adapter_init_seed": EXPECTED_ADAPTER_INIT_SEED,
        "environment_lock_sha256": _digest("environment-lock"),
        "evaluation_code_sha256": _digest("evaluation-code"),
        "model_path": EXPECTED_SYSTEM_CONFIG["model_path"],
        "model_sha256": _digest("model"),
        "preregistered_parent_commit": PREREGISTERED_PARENT_COMMIT,
        "source_commit": "a" * 40,
        "statistical_addendum_sha256": EXPECTED_STATISTICAL_ADDENDUM_SHA256,
        "tokenizer_sha256": _digest("tokenizer"),
    }
    initial_hash = _digest("shared-adapter-initialization")
    pairs = []
    for run_seed, delta in zip(EXPECTED_RUN_SEEDS, deltas, strict=True):
        pair_id = f"cohort-qonly-causal-{run_seed}"
        tape, verification = _tape(
            run_seed, adaptation["canonical_instance_ids"], initial_hash
        )
        pairs.append(
            {
                "active": _cell(
                    arm="active",
                    pair_id=pair_id,
                    run_seed=run_seed,
                    delta=delta,
                    tape=tape,
                    provenance=provenance,
                    adaptation=adaptation,
                    heldout=heldout,
                    initial_hash=initial_hash,
                    scoring_contract=scoring_contract,
                ),
                "lr0": _cell(
                    arm="lr0",
                    pair_id=pair_id,
                    run_seed=run_seed,
                    delta=delta,
                    tape=tape,
                    provenance=provenance,
                    adaptation=adaptation,
                    heldout=heldout,
                    initial_hash=initial_hash,
                    scoring_contract=scoring_contract,
                ),
                "pair_id": pair_id,
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
        "preregistration_sha256": EXPECTED_PREREGISTRATION_SHA256,
        "statistical_addendum_sha256": EXPECTED_STATISTICAL_ADDENDUM_SHA256,
        "protocol": PROTOCOL,
        "provenance": provenance,
        "schema_version": 1,
    }


def test_positive_legacy_gate_is_only_an_internal_screen() -> None:
    report = evaluate(_manifest())

    assert report["errors"] == []
    assert report["status"] == "valid"
    assert report["decision"] == "pass"
    assert report["decision_scope"] == "internal_gate_pass"
    assert report["publication_grade"] is False
    assert report["aggregate"]["mean_delta"] == 0.04
    assert report["aggregate"]["positive_seeds"] == 3
    assert report["aggregate"]["ci_95_lower"] == 0.03
    assert report["aggregate"]["ci_95_upper"] == 0.05
    assert all(report["threshold_checks"].values())
    assert report["bootstrap"]["publication_grade"] is False
    inference = report["publication_inference"]
    assert inference["status"] == "confirmation_required_not_publication_grade"
    assert inference["publication_grade"] is False
    assert inference["internal_screen_status"] == "internal_gate_pass"
    assert inference["raw_seed_deltas"] == [0.04, 0.05, 0.03]
    assert inference["effective_n"] == 3
    assert inference["fixed_scoring_conditions"] == 20
    assert inference["sample_sd"] == 0.01
    assert inference["seed_level_t_interval_95"]["df"] == 2
    assert (
        inference["seed_level_t_interval_95"][
            "normality_dependent_descriptive"
        ]
        is True
    )
    assert inference["exact_sign_test"]["p_value"] == 0.25
    negative = inference["negative_interpretation"]
    assert negative["valid_no_go_establishes_zero_or_harm"] is False
    assert negative["practical_benefit_at_least_0_02_ruled_out"] is False
    assert negative["harm_established"] is False
    confirmation = inference["confirmation_contract"]
    assert confirmation["minimum_new_adaptation_seeds"] == 6
    assert confirmation["minimum_independent_frozen_dgp_populations"] == 2
    assert confirmation["seed_to_population_mapping_preregistered_required"] is True
    for pair in report["pairs"]:
        for arm in ("active", "lr0"):
            terminal_actions = pair["terminal_actions"][arm]
            assert terminal_actions["count"] == 20
            assert terminal_actions["unique_count"] == 1
            assert len(terminal_actions["canonical_sha256"]) == 1
            assert terminal_actions["zero_value_count"] == 0


def test_exact_zero_fields_are_reported_not_treated_as_replicates() -> None:
    assert _exact_zero_value_count({"a": 0.0, "b": -0.0, "c": 0, "d": 0.2}) == 3
    assert _exact_zero_value_count({"bool_is_not_numeric_zero": False}) == 0


def test_fixture_matches_fixed_action_pseudoreplication_contract() -> None:
    manifest = _manifest()
    for pair, expected_delta in zip(
        manifest["pairs"], (0.04, 0.05, 0.03), strict=True
    ):
        arm_hashes = {}
        for arm in ("active", "lr0"):
            trace = pair[arm]["heldout_trace"]
            actions = [
                interaction["response"]["action"]
                for interaction in trace["interactions"]
                if interaction["observation"].get("instance_complete") is True
            ]
            arm_hashes[arm] = {canonical_sha256(action) for action in actions}
            rewards = [row["reward"] for row in pair[arm]["heldout_outcomes"]]
            assert len(arm_hashes[arm]) == 1
            assert len(set(rewards)) > 1
        paired_deltas = {
            round(active["reward"] - lr0["reward"], 6)
            for active, lr0 in zip(
                pair["active"]["heldout_outcomes"],
                pair["lr0"]["heldout_outcomes"],
                strict=True,
            )
        }
        assert paired_deltas == {expected_delta}
        assert arm_hashes["active"] != arm_hashes["lr0"]


def test_early_submission_segments_are_accepted() -> None:
    manifest = _manifest()
    for pair in manifest["pairs"]:
        for arm in ("active", "lr0"):
            cell = pair[arm]
            trace = cell["heldout_trace"]
            shortened = []
            for instance_index in range(len(trace["instance_outcomes"])):
                segment = trace["interactions"][
                    instance_index * 21 : (instance_index + 1) * 21
                ]
                shortened.extend(segment[:1] + segment[-1:])
            for step_number, interaction in enumerate(shortened, start=1):
                interaction["step_number"] = step_number
            trace["interactions"] = shortened
            trace["execution"]["total_interactions"] = len(shortened)
            cell["trace_sha256"] = canonical_sha256(trace)

    report = evaluate(manifest)

    assert report["decision"] == "pass"
    assert report["errors"] == []


def test_single_interaction_terminal_segment_fails_closed() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][0]["active"]
    trace = cell["heldout_trace"]
    trace["interactions"] = trace["interactions"][20:21] + trace[
        "interactions"
    ][21:]
    for step_number, interaction in enumerate(trace["interactions"], start=1):
        interaction["step_number"] = step_number
    trace["execution"]["total_interactions"] = len(trace["interactions"])
    cell["trace_sha256"] = canonical_sha256(trace)

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any("invalid instance segment length" in error for error in report["errors"])


def test_paired_terminal_signature_mismatch_fails_closed() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][0]["active"]
    trace = cell["heldout_trace"]
    trace["interactions"][20]["query"]["metadata"]["study_name"] = "FORGED"
    cell["trace_sha256"] = canonical_sha256(trace)

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "paired terminal prompt/schema/study signatures differ" in error
        for error in report["errors"]
    )


def test_formal_heldout_corpus_must_close_to_checked_in_manifest() -> None:
    manifest = _manifest()
    manifest["corpora"]["heldout"]["dataset_manifest_sha256"] = _digest(
        "wrong-heldout-manifest"
    )

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "checked-in heldout manifest.json SHA-256 mismatch" in error
        for error in report["errors"]
    )


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


def test_checked_in_adaptation_manifest_byte_drift_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    formal_corpus = _corpus("adaptation")
    dataset_dir = _copy_checked_in_corpus(tmp_path, "adaptation")
    manifest_path = dataset_dir / "manifest.json"
    manifest_path.write_bytes(manifest_path.read_bytes() + b"\n")
    monkeypatch.setattr(validator, "ROOT", tmp_path)
    errors: list[str] = []

    verified = validator._load_and_verify_checked_in_corpus(
        role="adaptation",
        formal_corpus=formal_corpus,
        errors=errors,
    )

    assert verified is None
    assert any("registered SHA-256 mismatch" in error for error in errors)


def test_checked_in_heldout_artifact_byte_drift_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    formal_corpus = _corpus("heldout")
    dataset_dir = _copy_checked_in_corpus(tmp_path, "heldout")
    metadata_path = dataset_dir / "metadata.json"
    metadata_path.write_bytes(metadata_path.read_bytes() + b"\n")
    monkeypatch.setattr(validator, "ROOT", tmp_path)
    errors: list[str] = []

    verified = validator._load_and_verify_checked_in_corpus(
        role="heldout",
        formal_corpus=formal_corpus,
        errors=errors,
    )

    assert verified is None
    assert any("artifact size_bytes mismatch" in error for error in errors)
    assert any("artifact raw SHA-256 mismatch" in error for error in errors)


def test_valid_no_go_is_distinct_from_invalid() -> None:
    report = evaluate(_manifest((0.01, 0.02, 0.01)))

    assert report["errors"] == []
    assert report["status"] == "valid"
    assert report["decision"] == "valid_no_go"
    assert report["decision_scope"] == "internal_gate_no_go"
    assert report["publication_grade"] is False
    assert (
        report["publication_inference"]["internal_screen_status"]
        == "internal_gate_no_go"
    )
    assert report["publication_inference"]["publication_grade"] is False
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


def test_reward_and_score_only_tampering_cannot_escape_bound_trace() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][0]["active"]
    cell["heldout_outcomes"][0]["reward"] += 0.5
    cell["score"] = statistics.mean(
        row["reward"] for row in cell["heldout_outcomes"]
    )

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "outcome/reward/integrity differs from bound trace" in error
        for error in report["errors"]
    )


def test_coordinated_outcome_trace_and_hash_laundering_cannot_forge_reward() -> None:
    manifest = _manifest((0.0, 0.0, 0.0))
    for pair in manifest["pairs"]:
        cell = pair["active"]
        forged_reward = 0.1
        for row in cell["heldout_outcomes"]:
            row["reward"] = forged_reward
        cell["score"] = forged_reward
        trace = cell["heldout_trace"]
        for row in trace["instance_outcomes"]:
            row["reward"] = forged_reward
            row["raw_metric_value"] = forged_reward
            row["success"] = True
        trace["result"]["instance_outcomes"] = deepcopy(
            trace["instance_outcomes"]
        )
        trace["result"]["score"] = forged_reward
        cell["trace_sha256"] = canonical_sha256(trace)

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "reward differs from independent score" in error
        for error in report["errors"]
    )


def test_terminal_env_feedback_identity_and_reward_are_bound() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][0]["active"]
    terminal = cell["heldout_trace"]["interactions"][20]
    terminal["observation"]["metadata"]["env_feedback_instance_id"] = (
        "cohort_studies:causal_eval_2026071412:forged"
    )
    terminal["observation"]["metadata"]["env_feedback_reward"] = 0.9
    cell["trace_sha256"] = canonical_sha256(cell["heldout_trace"])

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any("terminal identity chain mismatch" in error for error in report["errors"])
    assert any(
        "env_feedback_reward differs from independent score" in error
        for error in report["errors"]
    )


def test_wrong_trace_task_system_and_unknown_payload_fail_closed() -> None:
    mutations = (
        lambda trace: trace["task"].update(name="not_cohort_studies"),
        lambda trace: trace["system"].update(name="not_qwen_local"),
        lambda trace: trace.update(unknown_payload="x" * 1_000_000),
    )
    expected_errors = (
        "trace task name mismatch",
        "trace system name mismatch",
        "heldout_trace: schema mismatch",
    )
    for mutate, expected_error in zip(mutations, expected_errors, strict=True):
        manifest = _manifest()
        cell = manifest["pairs"][0]["active"]
        mutate(cell["heldout_trace"])
        cell["trace_sha256"] = canonical_sha256(cell["heldout_trace"])

        report = evaluate(manifest)

        assert report["decision"] == "invalid"
        assert any(expected_error in error for error in report["errors"])


def test_terminal_action_schema_is_exact_and_independently_scored() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][0]["active"]
    action = cell["heldout_trace"]["interactions"][20]["response"]["action"]
    action["unregistered_survival"] = 0.5
    cell["trace_sha256"] = canonical_sha256(cell["heldout_trace"])

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any("/action: schema mismatch" in error for error in report["errors"])


def test_second_terminal_action_hash_fails_pseudoreplication_guard() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][0]["active"]
    second_terminal = cell["heldout_trace"]["interactions"][41]
    action = second_terminal["response"]["action"]
    first_field = sorted(action)[0]
    action[first_field] = min(1.0, float(action[first_field]) + 0.001)
    cell["trace_sha256"] = canonical_sha256(cell["heldout_trace"])

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "terminal action canonical SHA-256 unique count=1" in error
        for error in report["errors"]
    )


def test_embedded_trace_only_tampering_fails_digest_verification() -> None:
    manifest = _manifest()
    trace = manifest["pairs"][0]["active"]["heldout_trace"]
    trace["instance_outcomes"][0]["reward"] += 0.5

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "embedded held-out trace SHA-256 mismatch" in error
        for error in report["errors"]
    )


def test_trace_hash_only_tampering_fails_closed() -> None:
    manifest = _manifest()
    manifest["pairs"][1]["lr0"]["trace_sha256"] = _digest("wrong-trace")

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "embedded held-out trace SHA-256 mismatch" in error
        for error in report["errors"]
    )


def test_rehashed_reordered_embedded_trace_fails_canonical_order() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][1]["active"]
    trace = cell["heldout_trace"]
    trace["instance_outcomes"][4], trace["instance_outcomes"][5] = (
        trace["instance_outcomes"][5],
        trace["instance_outcomes"][4],
    )
    trace["result"]["instance_outcomes"] = deepcopy(trace["instance_outcomes"])
    cell["trace_sha256"] = canonical_sha256(trace)

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "held-out instance ID/order mismatch" in error
        for error in report["errors"]
    )


def test_rehashed_missing_embedded_trace_outcome_fails_closed() -> None:
    manifest = _manifest()
    cell = manifest["pairs"][2]["lr0"]
    trace = cell["heldout_trace"]
    trace["instance_outcomes"].pop()
    trace["result"]["instance_outcomes"] = deepcopy(trace["instance_outcomes"])
    trace["result"]["score"] = statistics.mean(
        row["reward"] for row in trace["instance_outcomes"]
    )
    cell["trace_sha256"] = canonical_sha256(trace)

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "trace instance_outcomes must contain exactly 20" in error
        for error in report["errors"]
    )


def test_valid_but_wrong_preregistration_hash_fails_closed() -> None:
    manifest = _manifest()
    manifest["preregistration_sha256"] = _digest("different-preregistration")

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "differs from checked-in preregistration" in error
        for error in report["errors"]
    )


def test_changed_checked_in_preregistration_bytes_fail_closed(
    tmp_path: Path, monkeypatch
) -> None:
    manifest = _manifest()
    preregistration = tmp_path / validator.PREREGISTRATION_FILENAME
    preregistration.write_bytes(
        (ROOT / validator.PREREGISTRATION_FILENAME).read_bytes() + b"\n"
    )
    monkeypatch.setattr(validator, "ROOT", tmp_path)

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "checked-in preregistration file SHA-256 drift" in error
        for error in report["errors"]
    )


def test_valid_but_wrong_statistical_addendum_hash_fails_closed() -> None:
    manifest = _manifest()
    manifest["statistical_addendum_sha256"] = _digest("different-addendum")

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "statistical_addendum_sha256 differs from checked-in addendum" in error
        for error in report["errors"]
    )


def test_changed_checked_in_statistical_addendum_bytes_fail_closed(
    tmp_path: Path, monkeypatch
) -> None:
    manifest = _manifest()
    (tmp_path / validator.PREREGISTRATION_FILENAME).write_bytes(
        (ROOT / validator.PREREGISTRATION_FILENAME).read_bytes()
    )
    (tmp_path / STATISTICAL_ADDENDUM_FILENAME).write_bytes(
        (ROOT / STATISTICAL_ADDENDUM_FILENAME).read_bytes() + b"\n"
    )
    monkeypatch.setattr(validator, "ROOT", tmp_path)

    report = evaluate(manifest)

    assert report["decision"] == "invalid"
    assert any(
        "checked-in statistical addendum file SHA-256 drift" in error
        for error in report["errors"]
    )


def test_unknown_keys_fail_exact_schema_at_all_formal_evidence_levels() -> None:
    mutations = (
        lambda manifest: manifest.update(unregistered_top_level=True),
        lambda manifest: manifest["pairs"][0]["active"].update(
            unregistered_cell_field=True
        ),
        lambda manifest: manifest["pairs"][0]["active"]["replay"].update(
            unregistered_replay_field=True
        ),
        lambda manifest: manifest["pairs"][0]["active"]["heldout_outcomes"][
            0
        ].update(unregistered_outcome_field=True),
    )
    for mutate in mutations:
        manifest = _manifest()
        mutate(manifest)
        report = evaluate(manifest)
        assert report["decision"] == "invalid"
        assert any("schema mismatch" in error for error in report["errors"])


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
