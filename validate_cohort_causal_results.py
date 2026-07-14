#!/usr/bin/env python3
"""Validate the preregistered Cohort frozen-tape causal formal experiment.

This validator is intentionally independent from the training runner.  It
accepts one self-contained formal manifest, verifies the frozen configuration,
corpora, tapes, replay hash chains, provenance, and held-out outcomes, and only
then computes the preregistered endpoint.

``decision=invalid`` is an integrity/schema failure and exits non-zero.
``decision=valid_no_go`` is a valid scientific result that misses at least one
efficacy threshold.  ``decision=pass`` is the only expansion-eligible result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
EXPERIMENT = "cohort_qonly_frozen_tape_causal_formal"
PROTOCOL = "cohort_qonly_frozen_tape_weight_update_ablation_v1"
MECHANISM_LABEL = "frozen-tape weight-update ablation"
LIMITATION = "not exact historical replication"
PREREGISTERED_PARENT_COMMIT = "2d79ec6cd6ce4520ed36e2f68e0afd49fe73d350"

EXPECTED_RUN_SEEDS = (2026071401, 2026071402, 2026071403)
EXPECTED_ADAPTER_INIT_SEED = 2026071400
EXPECTED_OUTCOMES = 20
EXPECTED_OPERATIONS = ("reward_pg_terminal", "bon_env_best_worst_sft")
EXPECTED_SAMPLING_RNG_BINDING = (
    "ambient_runner_rng; grpo_run_seed registered but not locally forked"
)
BOOTSTRAP_SEED = 2026071499
BOOTSTRAP_REPLICATES = 50_000
GO_MEAN_DELTA = 0.02

EXPECTED_SYSTEM_CONFIG: dict[str, Any] = {
    "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
    "method": "ttt_rl",
    "ttt_rl_source": "sft",
    "peft_method": "prefix",
    "num_virtual_tokens": 512,
    "context_policy": "question_only",
    "adaptation_context_policy": "head4k_tail4k",
    "max_context_tokens": 32768,
    "head_tokens": 4096,
    "tail_tokens": 4096,
    "max_new_tokens": 8192,
    "action_max_new_tokens": 4096,
    "temperature": 0.0,
    "top_p": 1.0,
    "parse_retries": 2,
    "system_prompt": "",
    "name": "qwen_local",
    "trust_remote_code": True,
    "ttt_lr": 0.0005,
    "ttt_steps": 1,
    "ttt_max_tokens": 1024,
    "ttt_chunk_tokens": 512,
    "ttt_stride_tokens": 256,
    "ttt_max_chunks": 4,
    "ttt_train_every": 1,
    "lora_rank": 8,
    "lora_alpha": 16,
    "lora_dropout": 0.0,
    "lora_target_modules": "q_proj,v_proj",
    "lora_param_norm_clip": 0.25,
    "reward_pg_lr": 0.0005,
    "reward_pg_steps": 1,
    "reward_positive_weight": 1.0,
    "reward_negative_weight": 0.5,
    "reward_update_rule": "reward_pg",
    "reward_advantage_window": 8,
    "reward_ppo_clip": 0.2,
    "reward_update_terminal": True,
    "reward_judge_provider": "env",
    "reward_judge_model": "gpt-5.4-nano",
    "reward_judge_api_key_env": "OPENAI_API_KEY",
    "reward_judge_base_url": "https://api.openai.com/v1",
    "reward_judge_timeout_seconds": 30.0,
    "inject_env_reward": False,
    "distill_provider": "off",
    "distill_contrastive": True,
    "best_of_n": 8,
    "bon_temperature": 0.8,
    "bon_critic": "env",
    "bon_env_reward": "report",
    "history_ttt": False,
    "adapter_init_seed": EXPECTED_ADAPTER_INIT_SEED,
}

EXPECTED_TASK_CONFIG: dict[str, Any] = {
    "action_budget": 20,
    "dataset_path": "data/cohort_studies/causal_eval_2026071412",
    "num_instances": 20,
    "repeat_instructions": True,
    "schedule": "causal_eval_2026071412",
    "seed": 2026071412,
    "runs": 1,
    "max_workers": 1,
    "run_mode": "replicate",
}

EXPECTED_CORPORA = {
    "adaptation": {
        "aggregate_sha256": (
            "31f94d0130573e347ef8276a44c8d71c7b2159b881334798a7b73cd084ae9d9a"
        ),
        "dgp_seed": 2026071411,
        "schedule_id": "causal_adapt_2026071411",
        "schedule_sha256": (
            "a471a2e1dca55317dda9d6858b2103f3cd51539d9cfa081836a338058eed44f5"
        ),
    },
    "heldout": {
        "aggregate_sha256": (
            "a5c56f2c408b0d909a31cbfad490a95d5facd583eb8d3cbb3190aea4c39e0b80"
        ),
        "dgp_seed": 2026071412,
        "schedule_id": "causal_eval_2026071412",
        "schedule_sha256": (
            "81dde8ec92fe18af6410fbf38ff9cebd52fc298d534d9fb5107df3da5afe09ea"
        ),
    },
}

_ZERO_INTEGRITY_FIELDS = (
    "synthetic",
    "timed_out",
    "fallback",
    "missing",
    "hard_schema_failure",
)
_COUNTER_ZERO_FIELDS = (
    "synthetic_outcomes",
    "timed_out_outcomes",
    "fallbacks",
    "missing_outcomes",
    "hard_schema_failures",
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return the protocol's canonical JSON SHA-256."""

    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def strict_json_equal(left: Any, right: Any) -> bool:
    try:
        return _canonical_bytes(left) == _canonical_bytes(right)
    except (TypeError, ValueError):
        return False


def tape_item_sha256(item: dict[str, Any]) -> str:
    """Recompute a replay-core item digest (excluding its embedded digest)."""

    payload = dict(item)
    payload.pop("item_sha256", None)
    return canonical_sha256(payload)


def tape_sha256(tape: dict[str, Any]) -> str:
    """Recompute a replay-core tape digest (excluding its embedded digest)."""

    payload = dict(tape)
    payload.pop("tape_sha256", None)
    return canonical_sha256(payload)


def masked_pair_config_sha256(config: dict[str, Any]) -> str:
    """Digest a paired config after masking the two allowed arm differences."""

    masked = json.loads(json.dumps(config))
    masked["ttt_lr"] = "<ARM_LR>"
    masked["reward_pg_lr"] = "<ARM_LR>"
    return canonical_sha256(masked)


def corpus_projection_from_dataset_manifest(
    dataset_manifest: dict[str, Any],
    *,
    dataset_manifest_sha256: str,
    role: str,
) -> dict[str, Any]:
    """Project a checked-in frozen-dataset manifest into the formal schema.

    The dataset builder's manifest deliberately uses ``corpus_sha256``, an
    ``artifacts`` list, and ordered ``instances``.  Keeping this conversion in
    the validator package prevents a launcher from inventing a second,
    ambiguous interpretation of database, ground-truth, or canonical-order
    hashes.
    """

    if role not in EXPECTED_CORPORA:
        raise ValueError(f"unknown corpus role: {role}")
    if not isinstance(dataset_manifest, dict):
        raise ValueError("dataset manifest must be an object")
    if not _is_sha256(dataset_manifest_sha256):
        raise ValueError("dataset manifest file SHA-256 is invalid")
    expected = EXPECTED_CORPORA[role]
    if dataset_manifest.get("seed") != expected["dgp_seed"]:
        raise ValueError(f"{role} dataset seed drift")
    if dataset_manifest.get("schedule_id") != expected["schedule_id"]:
        raise ValueError(f"{role} schedule ID drift")
    if dataset_manifest.get("schedule_sha256") != expected["schedule_sha256"]:
        raise ValueError(f"{role} schedule SHA-256 drift")
    if dataset_manifest.get("corpus_sha256") != expected["aggregate_sha256"]:
        raise ValueError(f"{role} aggregate corpus SHA-256 drift")

    raw_instances = dataset_manifest.get("instances")
    if not isinstance(raw_instances, list) or len(raw_instances) != EXPECTED_OUTCOMES:
        raise ValueError(f"{role} dataset must have exactly 20 ordered instances")
    canonical_ids: list[str] = []
    for position, instance in enumerate(raw_instances):
        if not isinstance(instance, dict):
            raise ValueError(f"{role} instance {position} is not an object")
        if instance.get("instance_index") != position:
            raise ValueError(f"{role} instance order drift at {position}")
        variant_id = instance.get("variant_id")
        if not isinstance(variant_id, str) or not variant_id:
            raise ValueError(f"{role} instance {position} has no variant_id")
        if not _is_sha256(instance.get("db_sha256")):
            raise ValueError(f"{role} instance {position} has invalid DB SHA-256")
        canonical_ids.append(
            f"cohort_studies:{dataset_manifest['schedule_id']}:{variant_id}"
        )
    if len(set(canonical_ids)) != EXPECTED_OUTCOMES:
        raise ValueError(f"{role} instance IDs are not unique")

    raw_artifacts = dataset_manifest.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise ValueError(f"{role} artifacts must be a list")
    databases: dict[str, str] = {}
    ground_truth: dict[str, str] = {}
    for artifact in raw_artifacts:
        if not isinstance(artifact, dict):
            raise ValueError(f"{role} artifact is not an object")
        path = artifact.get("path")
        digest = artifact.get("sha256")
        if not isinstance(path, str) or not _is_sha256(digest):
            raise ValueError(f"{role} artifact path/SHA-256 is invalid")
        if path.startswith("dbs/") and path.endswith(".db"):
            databases[path] = digest
        elif path in {"ground_truth.json", "instance_references.json"}:
            ground_truth[path] = digest
    if not databases:
        raise ValueError(f"{role} dataset has no database artifacts")
    if set(ground_truth) != {"ground_truth.json", "instance_references.json"}:
        raise ValueError(f"{role} dataset ground-truth artifacts are incomplete")

    projection = {
        "aggregate_sha256": dataset_manifest["corpus_sha256"],
        "canonical_instance_ids": canonical_ids,
        "database_sha256": databases,
        "dataset_manifest_sha256": dataset_manifest_sha256,
        "dgp_seed": dataset_manifest["seed"],
        "ground_truth_sha256": ground_truth,
        "schedule_id": dataset_manifest["schedule_id"],
        "schedule_sha256": dataset_manifest["schedule_sha256"],
        "used_for_evaluation": role == "heldout",
        "used_for_updates": role == "adaptation",
    }
    if role == "heldout":
        projection["never_updated"] = True
    return projection


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_commit(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _percentile(sorted_values: list[float], quantile: float) -> float:
    """Type-7 linear percentile, stated explicitly for reproducibility."""

    position = quantile * (len(sorted_values) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1.0 - fraction) + sorted_values[upper] * fraction


def hierarchical_paired_bootstrap(
    paired_deltas: list[list[float]],
) -> dict[str, Any]:
    """Run the exact preregistered common-ID hierarchical paired bootstrap."""

    if len(paired_deltas) != len(EXPECTED_RUN_SEEDS) or any(
        len(row) != EXPECTED_OUTCOMES for row in paired_deltas
    ):
        raise ValueError("bootstrap requires exactly 3 seeds x 20 paired deltas")
    if any(not _is_number(value) for row in paired_deltas for value in row):
        raise ValueError("bootstrap deltas must be finite numbers")

    rng = random.Random(BOOTSTRAP_SEED)
    replicates: list[float] = []
    seed_count = len(paired_deltas)
    for _ in range(BOOTSTRAP_REPLICATES):
        sampled_seeds = [rng.randrange(seed_count) for _ in range(seed_count)]
        # The same sampled canonical IDs are applied to every selected seed.
        sampled_ids = [
            rng.randrange(EXPECTED_OUTCOMES) for _ in range(EXPECTED_OUTCOMES)
        ]
        total = 0.0
        for seed_index in sampled_seeds:
            seed_deltas = paired_deltas[seed_index]
            total += sum(seed_deltas[index] for index in sampled_ids)
        replicates.append(total / (seed_count * EXPECTED_OUTCOMES))

    replicates.sort()
    lower = _percentile(replicates, 0.025)
    upper = _percentile(replicates, 0.975)
    return {
        "ci_95": [round(lower, 12), round(upper, 12)],
        "method": "hierarchical_paired_common_instance_ids_percentile_type7",
        "replicates": BOOTSTRAP_REPLICATES,
        "seed": BOOTSTRAP_SEED,
    }


def _validate_integrity_status(
    value: Any, *, label: str, errors: list[str]
) -> tuple[int, int]:
    if not isinstance(value, dict):
        errors.append(f"{label}: integrity must be an object")
        return 0, 0
    if value.get("schema_valid") is not True:
        errors.append(f"{label}: schema_valid must be true")
    for field in _ZERO_INTEGRITY_FIELDS:
        if value.get(field) is not False:
            errors.append(f"{label}: {field} must be false")
    counters: list[int] = []
    for field in ("parse_retries", "repairs"):
        counter = value.get(field)
        if not _is_int(counter) or counter < 0:
            errors.append(f"{label}: {field} must be a nonnegative integer")
            counters.append(0)
        else:
            counters.append(counter)
    return counters[0], counters[1]


def _validate_hash_mapping(value: Any, *, label: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value:
        errors.append(f"{label}: must be a non-empty object")
        return
    for name, digest in value.items():
        if not isinstance(name, str) or not name or not _is_sha256(digest):
            errors.append(f"{label}: contains an invalid name or SHA-256")
            return


def _validate_corpus(
    name: str, corpus: Any, errors: list[str]
) -> tuple[str | None, list[str]]:
    label = f"corpora/{name}"
    if not isinstance(corpus, dict):
        errors.append(f"{label}: must be an object")
        return None, []
    expected = EXPECTED_CORPORA[name]
    if corpus.get("dgp_seed") != expected["dgp_seed"]:
        errors.append(f"{label}: wrong DGP seed")
    if corpus.get("schedule_id") != expected["schedule_id"]:
        errors.append(f"{label}: wrong schedule_id")
    for field in (
        "dataset_manifest_sha256",
        "schedule_sha256",
        "aggregate_sha256",
    ):
        if not _is_sha256(corpus.get(field)):
            errors.append(f"{label}: {field} must be a lowercase SHA-256")
    if corpus.get("schedule_sha256") != expected["schedule_sha256"]:
        errors.append(f"{label}: preregistered schedule SHA-256 mismatch")
    if corpus.get("aggregate_sha256") != expected["aggregate_sha256"]:
        errors.append(f"{label}: preregistered aggregate corpus SHA-256 mismatch")
    _validate_hash_mapping(
        corpus.get("database_sha256"),
        label=f"{label}/database_sha256",
        errors=errors,
    )
    _validate_hash_mapping(
        corpus.get("ground_truth_sha256"),
        label=f"{label}/ground_truth_sha256",
        errors=errors,
    )

    canonical_ids = corpus.get("canonical_instance_ids")
    if not isinstance(canonical_ids, list) or len(canonical_ids) != EXPECTED_OUTCOMES:
        errors.append(f"{label}: canonical_instance_ids must contain exactly 20 IDs")
        ids: list[str] = []
    else:
        ids = canonical_ids
        if any(
            not isinstance(instance_id, str)
            or not instance_id.startswith("cohort_studies:")
            or instance_id.startswith("cohort_studies:__failed")
            for instance_id in ids
        ):
            errors.append(f"{label}: contains a non-real Cohort instance ID")
        if len(set(ids)) != len(ids):
            errors.append(f"{label}: canonical instance IDs are not unique")

    if name == "adaptation":
        if corpus.get("used_for_updates") is not True:
            errors.append(f"{label}: used_for_updates must be true")
        if corpus.get("used_for_evaluation") is not False:
            errors.append(f"{label}: used_for_evaluation must be false")
    else:
        if corpus.get("used_for_updates") is not False:
            errors.append(f"{label}: used_for_updates must be false")
        if corpus.get("used_for_evaluation") is not True:
            errors.append(f"{label}: used_for_evaluation must be true")
        if corpus.get("never_updated") is not True:
            errors.append(f"{label}: never_updated must be true")
    aggregate = corpus.get("aggregate_sha256")
    return aggregate if _is_sha256(aggregate) else None, ids


def _validate_provenance(value: Any, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append("provenance: must be an object")
        return None
    if not _is_git_commit(value.get("source_commit")):
        errors.append("provenance: source_commit must be a full lowercase git SHA")
    if value.get("preregistered_parent_commit") != PREREGISTERED_PARENT_COMMIT:
        errors.append("provenance: preregistered_parent_commit mismatch")
    for field in (
        "environment_lock_sha256",
        "model_sha256",
        "tokenizer_sha256",
        "evaluation_code_sha256",
    ):
        if not _is_sha256(value.get(field)):
            errors.append(f"provenance: {field} must be a lowercase SHA-256")
    if value.get("model_path") != EXPECTED_SYSTEM_CONFIG["model_path"]:
        errors.append("provenance: model_path mismatch")
    if value.get("adapter_init_seed") != EXPECTED_ADAPTER_INIT_SEED:
        errors.append("provenance: adapter_init_seed mismatch")
    return value


_TAPE_KEYS = {
    "schema_version",
    "protocol",
    "mechanism_label",
    "learning_rate_ablation_fields",
    "collector_trainable_param_sha256_initial",
    "collector_trainable_param_sha256_final",
    "collector_lr0_verified",
    "update_contract",
    "items",
    "tape_sha256",
}
_TAPE_ITEM_KEYS = {
    "schema_version",
    "sequence_index",
    "instance_id",
    "instance_index",
    "integrity",
    "sampling_provenance",
    "committed_reward_pg",
    "env_bon",
    "item_sha256",
}
_INTEGRITY_KEYS = {
    "schema_valid",
    "synthetic",
    "timed_out",
    "fallback",
    "missing",
    "hard_schema_failure",
    "parse_retries",
    "repairs",
}
_SAMPLING_KEYS = {
    "candidate_count",
    "duplicates",
    "generation_failures",
    "initial_sample_attempts",
    "interaction_step",
    "parse_failures",
    "provenance_sha256",
    "registered_run_seed",
    "requested_best_of_n",
    "sampling_prompt_sha256",
    "sampling_rng_binding",
    "valid_unique",
}
_COMMITTED_KEYS = {
    "ids",
    "prompt_tokens",
    "prompt_token_ids_sha256",
    "target_token_ids_sha256",
    "training_example_sha256",
    "reward",
    "reward_sha256",
}
_ENV_BON_KEYS = {
    "prompt",
    "prompt_sha256",
    "candidates",
    "candidate_order_sha256",
    "selected_batches",
}
_CANDIDATE_KEYS = {"candidate", "candidate_sha256", "reward", "reward_sha256"}
_BATCH_KEYS = {
    "role",
    "candidate_index",
    "ids",
    "prompt_tokens",
    "signed_weight",
    "batch_sha256",
}
_UPDATE_CONTRACT_KEYS = (
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


def _exact_keys(value: Any, expected: set[str], *, label: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{label}: must be an object")
        return False
    if set(value) != expected:
        errors.append(f"{label}: schema mismatch")
        return False
    return True


def _valid_token_batch(ids: Any, prompt_tokens: Any) -> bool:
    return (
        isinstance(ids, list)
        and bool(ids)
        and all(_is_int(token) and token >= 0 for token in ids)
        and _is_int(prompt_tokens)
        and 0 <= prompt_tokens < len(ids)
    )


def _validate_tape_item_semantics(
    item: Any,
    *,
    position: int,
    run_seed: int,
    label: str,
    errors: list[str],
) -> None:
    """Validate every update-relevant leaf without importing model code."""

    if not _exact_keys(item, _TAPE_ITEM_KEYS, label=label, errors=errors):
        if not isinstance(item, dict):
            return
    if item.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{label}: schema_version mismatch")
    integrity = item.get("integrity")
    _exact_keys(integrity, _INTEGRITY_KEYS, label=f"{label}/integrity", errors=errors)
    _validate_integrity_status(
        integrity, label=f"{label}/integrity", errors=errors
    )

    sampling = item.get("sampling_provenance")
    if _exact_keys(
        sampling, _SAMPLING_KEYS, label=f"{label}/sampling_provenance", errors=errors
    ):
        without_digest = dict(sampling)
        embedded = without_digest.pop("provenance_sha256")
        if not _is_sha256(embedded) or embedded != canonical_sha256(without_digest):
            errors.append(f"{label}: sampling provenance digest mismatch")
        if sampling.get("registered_run_seed") != run_seed:
            errors.append(f"{label}: registered_run_seed mismatch")
        for field in (
            "candidate_count",
            "duplicates",
            "generation_failures",
            "initial_sample_attempts",
            "interaction_step",
            "parse_failures",
            "registered_run_seed",
            "requested_best_of_n",
            "valid_unique",
        ):
            if not _is_int(sampling.get(field)) or sampling[field] < 0:
                errors.append(f"{label}: sampling {field} must be nonnegative integer")
        if sampling.get("requested_best_of_n") != 8:
            errors.append(f"{label}: requested_best_of_n must be 8")
        if sampling.get("initial_sample_attempts") != 7:
            errors.append(f"{label}: initial_sample_attempts must be 7")
        if not _is_int(sampling.get("interaction_step")) or sampling[
            "interaction_step"
        ] < 1:
            errors.append(f"{label}: interaction_step must be positive")
        if not _is_sha256(sampling.get("sampling_prompt_sha256")):
            errors.append(f"{label}: sampling_prompt_sha256 is invalid")
        if sampling.get("sampling_rng_binding") != EXPECTED_SAMPLING_RNG_BINDING:
            errors.append(f"{label}: sampling_rng_binding mismatch")

    committed = item.get("committed_reward_pg")
    if _exact_keys(
        committed, _COMMITTED_KEYS, label=f"{label}/committed_reward_pg", errors=errors
    ):
        ids = committed.get("ids")
        prompt_tokens = committed.get("prompt_tokens")
        if not _valid_token_batch(ids, prompt_tokens):
            errors.append(f"{label}: committed reward-PG token batch is malformed")
        else:
            payload = {"ids": ids, "prompt_tokens": prompt_tokens}
            expected_hashes = {
                "prompt_token_ids_sha256": canonical_sha256(ids[:prompt_tokens]),
                "target_token_ids_sha256": canonical_sha256(ids[prompt_tokens:]),
                "training_example_sha256": canonical_sha256(payload),
            }
            for field, expected in expected_hashes.items():
                if committed.get(field) != expected:
                    errors.append(f"{label}: committed {field} mismatch")
        reward = committed.get("reward")
        if not _is_number(reward) or float(reward) == 0.0:
            errors.append(f"{label}: committed reward must be finite and nonzero")
        elif committed.get("reward_sha256") != canonical_sha256(float(reward)):
            errors.append(f"{label}: committed reward_sha256 mismatch")

    env_bon = item.get("env_bon")
    if not _exact_keys(env_bon, _ENV_BON_KEYS, label=f"{label}/env_bon", errors=errors):
        return
    prompt = env_bon.get("prompt")
    if not isinstance(prompt, str) or not prompt:
        errors.append(f"{label}: env-BoN prompt must be non-empty")
    elif env_bon.get("prompt_sha256") != hashlib.sha256(prompt.encode()).hexdigest():
        errors.append(f"{label}: env-BoN prompt_sha256 mismatch")

    candidates = env_bon.get("candidates")
    if not isinstance(candidates, list) or len(candidates) < 2:
        errors.append(f"{label}: env-BoN needs at least two candidates")
        return
    candidate_values: list[str] = []
    candidate_rewards: list[float] = []
    candidate_objects: list[dict[str, Any]] = []
    for candidate_index, record in enumerate(candidates):
        candidate_label = f"{label}/env_bon/candidates[{candidate_index}]"
        if not _exact_keys(record, _CANDIDATE_KEYS, label=candidate_label, errors=errors):
            continue
        candidate = record.get("candidate")
        reward = record.get("reward")
        if not isinstance(candidate, str) or not candidate:
            errors.append(f"{candidate_label}: candidate must be non-empty")
            continue
        if record.get("candidate_sha256") != hashlib.sha256(candidate.encode()).hexdigest():
            errors.append(f"{candidate_label}: candidate_sha256 mismatch")
        if not _is_number(reward):
            errors.append(f"{candidate_label}: reward must be finite numeric")
            continue
        numeric_reward = float(reward)
        if record.get("reward_sha256") != canonical_sha256(numeric_reward):
            errors.append(f"{candidate_label}: reward_sha256 mismatch")
        candidate_values.append(candidate)
        candidate_rewards.append(numeric_reward)
        candidate_objects.append(record)
    if len(candidate_objects) != len(candidates):
        return
    if len(set(candidate_values)) != len(candidate_values):
        errors.append(f"{label}: stored env-BoN candidates must be unique")
    if env_bon.get("candidate_order_sha256") != canonical_sha256(candidates):
        errors.append(f"{label}: candidate_order_sha256 mismatch")
    if isinstance(sampling, dict):
        if sampling.get("candidate_count") != len(candidates):
            errors.append(f"{label}: candidate_count mismatch")
        if sampling.get("valid_unique") != len(set(candidate_values)):
            errors.append(f"{label}: valid_unique mismatch")
        accounted = sum(
            sampling.get(field, -1)
            for field in (
                "candidate_count",
                "duplicates",
                "generation_failures",
                "parse_failures",
            )
        )
        if accounted != sampling.get("requested_best_of_n"):
            errors.append(f"{label}: candidate draw accounting mismatch")

    ranked_indices = sorted(
        range(len(candidates)), key=lambda index: candidate_rewards[index], reverse=True
    )
    expected_specs = [
        ("positive", ranked_indices[0], float(EXPECTED_SYSTEM_CONFIG["reward_positive_weight"])),
        ("negative", ranked_indices[-1], -float(EXPECTED_SYSTEM_CONFIG["reward_negative_weight"])),
    ]
    batches = env_bon.get("selected_batches")
    if not isinstance(batches, list) or len(batches) != len(expected_specs):
        errors.append(f"{label}: selected_batches must contain exact best/worst pair")
        return
    for batch_index, (batch, expected) in enumerate(zip(batches, expected_specs, strict=True)):
        batch_label = f"{label}/env_bon/selected_batches[{batch_index}]"
        if not _exact_keys(batch, _BATCH_KEYS, label=batch_label, errors=errors):
            continue
        role, candidate_index, signed_weight = expected
        if batch.get("role") != role or batch.get("candidate_index") != candidate_index:
            errors.append(f"{batch_label}: selected candidate role/index mismatch")
        if not _is_number(batch.get("signed_weight")) or float(
            batch["signed_weight"]
        ) != signed_weight:
            errors.append(f"{batch_label}: signed_weight mismatch")
        if not _valid_token_batch(batch.get("ids"), batch.get("prompt_tokens")):
            errors.append(f"{batch_label}: token batch is malformed")
        without_digest = dict(batch)
        embedded = without_digest.pop("batch_sha256")
        if not _is_sha256(embedded) or embedded != canonical_sha256(without_digest):
            errors.append(f"{batch_label}: batch SHA-256 mismatch")


def validate_tape_nested_semantics(
    tape: Any,
    *,
    run_seed: int,
    expected_items: int,
    expected_instance_ids: list[str] | None,
    label: str,
    errors: list[str],
) -> None:
    """Pure-JSON full tape validation shared by formal and smoke gates."""

    if not _exact_keys(tape, _TAPE_KEYS, label=label, errors=errors):
        if not isinstance(tape, dict):
            return
    if tape.get("schema_version") != SCHEMA_VERSION or tape.get("protocol") != PROTOCOL:
        errors.append(f"{label}: tape protocol/schema mismatch")
    if tape.get("mechanism_label") != f"{MECHANISM_LABEL}; {LIMITATION}":
        errors.append(f"{label}: mechanism label mismatch")
    if tape.get("learning_rate_ablation_fields") != ["ttt_lr", "reward_pg_lr"]:
        errors.append(f"{label}: learning-rate ablation fields mismatch")
    initial = tape.get("collector_trainable_param_sha256_initial")
    final = tape.get("collector_trainable_param_sha256_final")
    if not _is_sha256(initial) or not _is_sha256(final) or initial != final:
        errors.append(f"{label}: invalid/changing LR0 collector parameter hash")
    if tape.get("collector_lr0_verified") is not True:
        errors.append(f"{label}: collector_lr0_verified must be true")
    expected_contract = {
        key: EXPECTED_SYSTEM_CONFIG[key] for key in _UPDATE_CONTRACT_KEYS
    }
    if not strict_json_equal(tape.get("update_contract"), expected_contract):
        errors.append(f"{label}: update contract differs from preregistration")
    embedded = tape.get("tape_sha256")
    if not _is_sha256(embedded) or embedded != tape_sha256(tape):
        errors.append(f"{label}: tape SHA-256 verification failed")
    items = tape.get("items")
    if not isinstance(items, list) or len(items) != expected_items:
        errors.append(f"{label}: wrong tape item count")
        return
    observed_ids: list[Any] = []
    interaction_steps: list[int] = []
    for position, item in enumerate(items):
        item_label = f"{label}/items[{position}]"
        _validate_tape_item_semantics(
            item,
            position=position,
            run_seed=run_seed,
            label=item_label,
            errors=errors,
        )
        if isinstance(item, dict):
            observed_ids.append(item.get("instance_id"))
            if item.get("sequence_index") != position or item.get("instance_index") != position:
                errors.append(f"{item_label}: non-canonical item order")
            if expected_instance_ids is not None and position < len(expected_instance_ids):
                if item.get("instance_id") != expected_instance_ids[position]:
                    errors.append(f"{item_label}: adaptation instance ID/order mismatch")
            digest = item.get("item_sha256")
            if not _is_sha256(digest) or digest != tape_item_sha256(item):
                errors.append(f"{item_label}: item SHA-256 verification failed")
            sampling = item.get("sampling_provenance")
            step = sampling.get("interaction_step") if isinstance(sampling, dict) else None
            if _is_int(step) and step > 0:
                interaction_steps.append(step)
    if len(set(observed_ids)) != len(observed_ids):
        errors.append(f"{label}: duplicate tape instance IDs")
    if len(interaction_steps) == len(items) and any(
        later <= earlier
        for earlier, later in zip(interaction_steps, interaction_steps[1:])
    ):
        errors.append(f"{label}: terminal interaction steps must be strictly increasing")


def _validate_tape(
    pair_label: str,
    run_seed: int,
    tape: Any,
    verification: Any,
    adaptation_ids: list[str],
    errors: list[str],
) -> tuple[str | None, list[str], str | None, list[dict[str, Any]]]:
    label = f"{pair_label}/tape"
    if not isinstance(tape, dict):
        errors.append(f"{label}: must be an object")
        return None, [], None, []
    validate_tape_nested_semantics(
        tape,
        run_seed=run_seed,
        expected_items=EXPECTED_OUTCOMES,
        expected_instance_ids=adaptation_ids,
        label=label,
        errors=errors,
    )
    if tape.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{label}: schema_version mismatch")
    if tape.get("protocol") != PROTOCOL:
        errors.append(f"{label}: protocol mismatch")
    if tape.get("mechanism_label") != f"{MECHANISM_LABEL}; {LIMITATION}":
        errors.append(f"{label}: source mechanism label mismatch")
    if tape.get("learning_rate_ablation_fields") != ["ttt_lr", "reward_pg_lr"]:
        errors.append(f"{label}: learning-rate ablation fields mismatch")
    collector_initial = tape.get("collector_trainable_param_sha256_initial")
    collector_final = tape.get("collector_trainable_param_sha256_final")
    if not _is_sha256(collector_initial) or not _is_sha256(collector_final):
        errors.append(f"{label}: invalid collector trainable-parameter hash")
        collector_initial = None
    elif collector_initial != collector_final:
        errors.append(f"{label}: LR0 collector trainable-parameter hash changed")
    if tape.get("collector_lr0_verified") is not True:
        errors.append(f"{label}: collector_lr0_verified must be true")
    contract_keys = (
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
    expected_update_contract = {
        key: EXPECTED_SYSTEM_CONFIG[key] for key in contract_keys
    }
    if not strict_json_equal(tape.get("update_contract"), expected_update_contract):
        errors.append(f"{label}: update contract differs from preregistration")
    embedded_digest = tape.get("tape_sha256")
    if not _is_sha256(embedded_digest):
        errors.append(f"{label}: tape_sha256 must be a lowercase SHA-256")
        embedded_digest = None
    else:
        try:
            recomputed = tape_sha256(tape)
        except (TypeError, ValueError) as exc:
            errors.append(f"{label}: cannot canonicalize tape: {exc}")
        else:
            if embedded_digest != recomputed:
                errors.append(f"{label}: tape SHA-256 verification failed")

    items = tape.get("items")
    if not isinstance(items, list) or len(items) != EXPECTED_OUTCOMES:
        errors.append(f"{label}: must contain exactly 20 items")
        items = []
    item_digests: list[str] = []
    identities: list[tuple[Any, Any, Any]] = []
    terminal_interaction_steps: list[int] = []
    for position, item in enumerate(items):
        item_label = f"{label}/items[{position}]"
        if not isinstance(item, dict):
            errors.append(f"{item_label}: must be an object")
            continue
        sequence_index = item.get("sequence_index")
        instance_index = item.get("instance_index")
        instance_id = item.get("instance_id")
        identities.append((sequence_index, instance_index, instance_id))
        if sequence_index != position:
            errors.append(f"{item_label}: non-canonical sequence_index")
        if not _is_int(instance_index) or instance_index < 0:
            errors.append(f"{item_label}: invalid instance_index")
        elif instance_index != position:
            errors.append(f"{item_label}: non-canonical instance_index")
        if (
            not isinstance(instance_id, str)
            or not instance_id.startswith("cohort_studies:")
            or instance_id.startswith("cohort_studies:__failed")
        ):
            errors.append(f"{item_label}: invalid/non-real Cohort instance_id")
        if position < len(adaptation_ids) and instance_id != adaptation_ids[position]:
            errors.append(f"{item_label}: adaptation instance ID/order mismatch")
        digest = item.get("item_sha256")
        if not _is_sha256(digest):
            errors.append(f"{item_label}: item_sha256 must be a lowercase SHA-256")
        else:
            item_digests.append(digest)
            try:
                recomputed = tape_item_sha256(item)
            except (TypeError, ValueError) as exc:
                errors.append(f"{item_label}: cannot canonicalize item: {exc}")
            else:
                if digest != recomputed:
                    errors.append(f"{item_label}: item SHA-256 verification failed")
        _validate_integrity_status(
            item.get("integrity"), label=f"{item_label}/collector", errors=errors
        )
        sampling = item.get("sampling_provenance")
        if not isinstance(sampling, dict):
            errors.append(f"{item_label}: sampling_provenance must be an object")
        else:
            expected_sampling_fields = {
                "candidate_count",
                "duplicates",
                "generation_failures",
                "initial_sample_attempts",
                "interaction_step",
                "parse_failures",
                "provenance_sha256",
                "registered_run_seed",
                "requested_best_of_n",
                "sampling_prompt_sha256",
                "sampling_rng_binding",
                "valid_unique",
            }
            if set(sampling) != expected_sampling_fields:
                errors.append(f"{item_label}: sampling provenance schema mismatch")
            if sampling.get("registered_run_seed") != run_seed:
                errors.append(f"{item_label}: registered_run_seed mismatch")
            if sampling.get("requested_best_of_n") != 8:
                errors.append(f"{item_label}: requested_best_of_n must be 8")
            if sampling.get("initial_sample_attempts") != 7:
                errors.append(f"{item_label}: initial_sample_attempts must be 7")
            for field in (
                "candidate_count",
                "duplicates",
                "generation_failures",
                "initial_sample_attempts",
                "interaction_step",
                "parse_failures",
                "registered_run_seed",
                "requested_best_of_n",
                "valid_unique",
            ):
                if not _is_int(sampling.get(field)) or sampling.get(field) < 0:
                    errors.append(
                        f"{item_label}: sampling {field} must be nonnegative integer"
                    )
            interaction_step = sampling.get("interaction_step")
            if _is_int(interaction_step) and interaction_step > 0:
                terminal_interaction_steps.append(interaction_step)
            else:
                errors.append(f"{item_label}: interaction_step must be positive")
            sampling_digest = sampling.get("provenance_sha256")
            if not _is_sha256(sampling_digest):
                errors.append(f"{item_label}: invalid provenance_sha256")
            else:
                sampling_without_digest = dict(sampling)
                sampling_without_digest.pop("provenance_sha256")
                if sampling_digest != canonical_sha256(sampling_without_digest):
                    errors.append(f"{item_label}: provenance SHA-256 mismatch")
            if not _is_sha256(sampling.get("sampling_prompt_sha256")):
                errors.append(f"{item_label}: invalid sampling_prompt_sha256")
            if (
                sampling.get("sampling_rng_binding")
                != EXPECTED_SAMPLING_RNG_BINDING
            ):
                errors.append(f"{item_label}: sampling_rng_binding mismatch")
            env_bon = item.get("env_bon")
            candidates = (
                env_bon.get("candidates", []) if isinstance(env_bon, dict) else []
            )
            candidate_values = [
                record.get("candidate")
                for record in candidates
                if isinstance(record, dict)
            ]
            if len(candidate_values) != len(candidates) or any(
                not isinstance(candidate, str) or not candidate
                for candidate in candidate_values
            ):
                errors.append(f"{item_label}: malformed candidate records")
            if sampling.get("candidate_count") != len(candidates):
                errors.append(f"{item_label}: candidate_count mismatch")
            candidate_count = sampling.get("candidate_count")
            valid_unique = sampling.get("valid_unique")
            if _is_int(candidate_count) and candidate_count < 2:
                errors.append(f"{item_label}: candidate_count must be at least 2")
            if valid_unique != len(set(candidate_values)):
                errors.append(f"{item_label}: valid_unique mismatch")
            if len(set(candidate_values)) != len(candidate_values):
                errors.append(f"{item_label}: stored candidates must be deduplicated")
            accounted_draws = sum(
                sampling.get(field, -1)
                for field in (
                    "candidate_count",
                    "duplicates",
                    "generation_failures",
                    "parse_failures",
                )
            )
            if accounted_draws != sampling.get("requested_best_of_n"):
                errors.append(f"{item_label}: candidate draw accounting mismatch")

        env_bon = item.get("env_bon")
        selected_batches = (
            env_bon.get("selected_batches", []) if isinstance(env_bon, dict) else []
        )
        if not isinstance(selected_batches, list) or len(selected_batches) not in {
            1,
            2,
        }:
            errors.append(
                f"{item_label}: selected_batches must contain one or two rows"
            )
            selected_batches = []
        expected_roles = ["positive"] + (
            ["negative"] if len(selected_batches) == 2 else []
        )
        for batch_index, batch in enumerate(selected_batches):
            batch_label = f"{item_label}/selected_batches[{batch_index}]"
            if not isinstance(batch, dict):
                errors.append(f"{batch_label}: must be an object")
                continue
            if batch.get("role") != expected_roles[batch_index]:
                errors.append(f"{batch_label}: role/order mismatch")
            batch_digest = batch.get("batch_sha256")
            if not _is_sha256(batch_digest):
                errors.append(f"{batch_label}: invalid batch_sha256")
            else:
                batch_without_digest = dict(batch)
                batch_without_digest.pop("batch_sha256")
                if batch_digest != canonical_sha256(batch_without_digest):
                    errors.append(f"{batch_label}: batch SHA-256 mismatch")

    if len(set(identities)) != len(identities):
        errors.append(f"{label}: duplicate item identity")
    if len(terminal_interaction_steps) == len(items) and any(
        later <= earlier
        for earlier, later in zip(
            terminal_interaction_steps,
            terminal_interaction_steps[1:],
        )
    ):
        errors.append(f"{label}: terminal interaction steps must be strictly increasing")

    verification_items: Any = None
    if not isinstance(verification, dict):
        errors.append(f"{pair_label}/tape_verification: must be an object")
    else:
        if verification.get("digest_verified") is not True:
            errors.append(
                f"{pair_label}/tape_verification: digest_verified must be true"
            )
        verification_items = verification.get("items")
    if not isinstance(verification_items, list) or len(verification_items) != len(
        items
    ):
        errors.append(
            f"{pair_label}/tape_verification: items must cover all tape items"
        )
    else:
        for position, row in enumerate(verification_items):
            row_label = f"{pair_label}/tape_verification/items[{position}]"
            if not isinstance(row, dict):
                errors.append(f"{row_label}: must be an object")
                continue
            if row.get("sequence_index") != position:
                errors.append(f"{row_label}: sequence_index mismatch")
            expected_digest = items[position].get("item_sha256")
            if row.get("item_sha256") != expected_digest:
                errors.append(f"{row_label}: item_sha256 mismatch")
            if row.get("digest_verified") is not True:
                errors.append(f"{row_label}: digest_verified must be true")
    object_items = [item for item in items if isinstance(item, dict)]
    return embedded_digest, item_digests, collector_initial, object_items


def _expected_arm_config(arm: str, run_seed: int) -> dict[str, Any]:
    expected = dict(EXPECTED_SYSTEM_CONFIG)
    expected["grpo_run_seed"] = run_seed
    if arm == "lr0":
        expected["ttt_lr"] = 0.0
        expected["reward_pg_lr"] = 0.0
    return expected


def _validate_cell(
    *,
    pair_label: str,
    run_seed: int,
    arm: str,
    cell: Any,
    tape_digest: str | None,
    tape_item_digests: list[str],
    tape_items: list[dict[str, Any]],
    global_provenance: dict[str, Any] | None,
    adaptation_digest: str | None,
    heldout_digest: str | None,
    heldout_ids: list[str],
    errors: list[str],
) -> dict[str, Any] | None:
    label = f"{pair_label}/{arm}"
    if not isinstance(cell, dict):
        errors.append(f"{label}: cell must be an object")
        return None
    if cell.get("arm") != arm:
        errors.append(f"{label}: arm label mismatch")
    if cell.get("run_seed") != run_seed:
        errors.append(f"{label}: run_seed mismatch")
    if cell.get("status") != "completed":
        errors.append(f"{label}: status must be completed")
    if cell.get("outcome_schema_version") != SCHEMA_VERSION:
        errors.append(f"{label}: outcome_schema_version mismatch")
    if cell.get("heldout_updates_frozen") is not True:
        errors.append(f"{label}: heldout_updates_frozen must be true")
    if cell.get("tape_sha256") != tape_digest:
        errors.append(f"{label}: tape SHA-256 mismatch")
    if cell.get("adaptation_corpus_sha256") != adaptation_digest:
        errors.append(f"{label}: adaptation corpus SHA-256 mismatch")
    if cell.get("heldout_corpus_sha256") != heldout_digest:
        errors.append(f"{label}: held-out corpus SHA-256 mismatch")
    if global_provenance is None or not strict_json_equal(
        cell.get("provenance"), global_provenance
    ):
        errors.append(f"{label}: provenance mismatch")

    system_config = cell.get("system_config")
    expected_config = _expected_arm_config(arm, run_seed)
    if not strict_json_equal(system_config, expected_config):
        errors.append(f"{label}: system config differs from preregistration")
    if not isinstance(system_config, dict):
        system_config = {}
    expected_config_digest = canonical_sha256(system_config)
    if cell.get("system_config_sha256") != expected_config_digest:
        errors.append(f"{label}: system_config_sha256 mismatch")
    expected_masked_digest = masked_pair_config_sha256(system_config)
    if cell.get("masked_pair_config_sha256") != expected_masked_digest:
        errors.append(f"{label}: masked_pair_config_sha256 mismatch")

    task_config = cell.get("task_config")
    if not strict_json_equal(task_config, EXPECTED_TASK_CONFIG):
        errors.append(f"{label}: task config differs from preregistration")
    task_digest = canonical_sha256(task_config)
    if cell.get("task_config_sha256") != task_digest:
        errors.append(f"{label}: task_config_sha256 mismatch")
    expected_order_digest = canonical_sha256(heldout_ids)
    if cell.get("evaluation_order_sha256") != expected_order_digest:
        errors.append(f"{label}: evaluation_order_sha256 mismatch")

    replay = cell.get("replay")
    replay_summary: dict[str, Any] | None = None
    if not isinstance(replay, dict):
        errors.append(f"{label}: replay must be an object")
    else:
        if replay.get("tape_sha256") != tape_digest:
            errors.append(f"{label}: replay tape SHA-256 mismatch")
        if replay.get("status") != "complete":
            errors.append(f"{label}: replay status must be complete")
        if replay.get("digest_verified") is not True:
            errors.append(f"{label}: replay digest_verified must be true")
        if replay.get("item_count") != EXPECTED_OUTCOMES:
            errors.append(f"{label}: replay item_count must be 20")
        if replay.get("operations_per_item") != len(EXPECTED_OPERATIONS):
            errors.append(f"{label}: replay operations_per_item must be 2")
        if replay.get("operation_count") != EXPECTED_OUTCOMES * len(
            EXPECTED_OPERATIONS
        ):
            errors.append(f"{label}: replay operation_count must be 40")
        initial = replay.get("trainable_param_sha256_initial")
        final = replay.get("trainable_param_sha256_final")
        if not _is_sha256(initial):
            errors.append(f"{label}: invalid initial trainable-parameter hash")
        if not _is_sha256(final):
            errors.append(f"{label}: invalid final trainable-parameter hash")
        replay_items = replay.get("items")
        if not isinstance(replay_items, list) or len(replay_items) != EXPECTED_OUTCOMES:
            errors.append(f"{label}: replay must contain exactly 20 items")
            replay_items = []
        previous_hash = initial
        operation_signature: list[list[tuple[str, int]]] = []
        changed_operations = 0
        for position, item in enumerate(replay_items):
            item_label = f"{label}/replay/items[{position}]"
            if not isinstance(item, dict):
                errors.append(f"{item_label}: must be an object")
                continue
            if item.get("sequence_index") != position:
                errors.append(f"{item_label}: non-canonical sequence_index")
            if position >= len(tape_item_digests) or item.get(
                "item_sha256"
            ) != tape_item_digests[position]:
                errors.append(f"{item_label}: tape item SHA-256 mismatch")
            tape_item = tape_items[position] if position < len(tape_items) else {}
            for field in (
                "instance_id",
                "instance_index",
                "integrity",
                "sampling_provenance",
            ):
                if not strict_json_equal(item.get(field), tape_item.get(field)):
                    errors.append(f"{item_label}: replay {field} differs from tape")
            if item.get("status") != "complete":
                errors.append(f"{item_label}: status must be complete")
            if item.get("operation_count") != len(EXPECTED_OPERATIONS):
                errors.append(f"{item_label}: operation_count must be 2")
            item_before = item.get("trainable_param_sha256_before")
            item_after = item.get("trainable_param_sha256_after")
            if item_before != previous_hash:
                errors.append(f"{item_label}: broken cross-item parameter hash chain")
            operations = item.get("operations")
            if not isinstance(operations, list) or len(operations) != len(
                EXPECTED_OPERATIONS
            ):
                errors.append(f"{item_label}: must contain exactly two operations")
                operations = []
            signature: list[tuple[str, int, tuple[str, ...]]] = []
            operation_previous = item_before
            for operation_index, operation in enumerate(operations):
                operation_label = f"{item_label}/operations[{operation_index}]"
                if not isinstance(operation, dict):
                    errors.append(f"{operation_label}: must be an object")
                    continue
                operation_name = operation.get("operation")
                if (
                    operation_index >= len(EXPECTED_OPERATIONS)
                    or operation_name != EXPECTED_OPERATIONS[operation_index]
                ):
                    errors.append(f"{operation_label}: wrong ordered operation")
                batch_count = operation.get("batch_count")
                if not _is_int(batch_count) or batch_count <= 0:
                    errors.append(f"{operation_label}: batch_count must be positive")
                    batch_count = -1
                if operation_name == "reward_pg_terminal" and batch_count != 1:
                    errors.append(f"{operation_label}: reward-PG batch_count must be 1")
                input_digests = operation.get("input_sha256")
                if not isinstance(input_digests, list) or not input_digests or any(
                    not _is_sha256(digest) for digest in input_digests
                ):
                    errors.append(
                        f"{operation_label}: input_sha256 must contain SHA-256 values"
                    )
                    input_digests = []
                if operation_name == "reward_pg_terminal":
                    committed = tape_item.get("committed_reward_pg", {})
                    expected_inputs = [
                        committed.get("training_example_sha256"),
                        committed.get("reward_sha256"),
                    ]
                else:
                    env_bon = tape_item.get("env_bon", {})
                    batches = env_bon.get("selected_batches", [])
                    expected_inputs = [
                        batch.get("batch_sha256")
                        for batch in batches
                        if isinstance(batch, dict)
                    ]
                if input_digests != expected_inputs:
                    errors.append(f"{operation_label}: replay input SHA-256 mismatch")
                if operation_name == "bon_env_best_worst_sft" and batch_count != len(
                    expected_inputs
                ):
                    errors.append(
                        f"{operation_label}: env-BoN batch_count differs from tape"
                    )
                before = operation.get("trainable_param_sha256_before")
                after = operation.get("trainable_param_sha256_after")
                if not _is_sha256(before) or not _is_sha256(after):
                    errors.append(f"{operation_label}: invalid parameter hash")
                if before != operation_previous:
                    errors.append(f"{operation_label}: broken parameter hash chain")
                if before != after:
                    changed_operations += 1
                operation_previous = after
                signature.append(
                    (str(operation_name), batch_count, tuple(input_digests))
                )
            if operations:
                if item_before != operations[0].get("trainable_param_sha256_before"):
                    errors.append(
                        f"{item_label}: item/first-operation before hash mismatch"
                    )
                if item_after != operations[-1].get("trainable_param_sha256_after"):
                    errors.append(
                        f"{item_label}: item/last-operation after hash mismatch"
                    )
            previous_hash = item_after
            operation_signature.append(signature)
        if replay_items and final != replay_items[-1].get(
            "trainable_param_sha256_after"
        ):
            errors.append(f"{label}: final parameter hash does not close replay chain")
        if arm == "lr0" and _is_sha256(initial):
            if final != initial:
                errors.append(f"{label}: LR0 final parameter hash changed")
            for position, item in enumerate(replay_items):
                if not isinstance(item, dict):
                    continue
                for operation in item.get("operations", []):
                    if not isinstance(operation, dict):
                        continue
                    if (
                        operation.get("trainable_param_sha256_before") != initial
                        or operation.get("trainable_param_sha256_after") != initial
                    ):
                        errors.append(
                            f"{label}: LR0 replay operation hash changed at item "
                            f"{position}"
                        )
        if arm == "active" and _is_sha256(initial):
            if final == initial:
                errors.append(f"{label}: active final parameter hash did not change")
            if changed_operations < 1:
                errors.append(
                    f"{label}: no audited active replay update changed parameters"
                )
        replay_summary = {
            "initial_hash": initial,
            "final_hash": final,
            "operation_signature": operation_signature,
            "changed_operations": changed_operations,
        }

    outcomes = cell.get("heldout_outcomes")
    outcome_summary: dict[str, Any] | None = None
    if not isinstance(outcomes, list) or len(outcomes) != EXPECTED_OUTCOMES:
        errors.append(f"{label}: heldout_outcomes must contain exactly 20 rows")
        outcomes = []
    identities: list[tuple[Any, Any]] = []
    rewards: list[float] = []
    parse_retries = 0
    repairs = 0
    for position, outcome in enumerate(outcomes):
        outcome_label = f"{label}/heldout_outcomes[{position}]"
        if not isinstance(outcome, dict):
            errors.append(f"{outcome_label}: must be an object")
            continue
        instance_id = outcome.get("instance_id")
        instance_index = outcome.get("instance_index")
        identities.append((instance_id, instance_index))
        if position < len(heldout_ids) and instance_id != heldout_ids[position]:
            errors.append(f"{outcome_label}: held-out instance ID/order mismatch")
        if instance_index != position:
            errors.append(f"{outcome_label}: non-canonical instance_index")
        reward = outcome.get("reward")
        if not _is_number(reward):
            errors.append(f"{outcome_label}: reward must be finite numeric")
        else:
            rewards.append(float(reward))
        retries, row_repairs = _validate_integrity_status(
            outcome.get("integrity"), label=outcome_label, errors=errors
        )
        parse_retries += retries
        repairs += row_repairs
    if len(set(identities)) != len(identities):
        errors.append(f"{label}: duplicate held-out outcome identity")

    counters = cell.get("integrity_counters")
    if not isinstance(counters, dict):
        errors.append(f"{label}: integrity_counters must be an object")
    else:
        for field in _COUNTER_ZERO_FIELDS:
            if counters.get(field) != 0:
                errors.append(f"{label}: integrity counter {field} must be zero")
        if counters.get("parse_retries") != parse_retries:
            errors.append(f"{label}: parse_retries counter mismatch")
        if counters.get("repairs") != repairs:
            errors.append(f"{label}: repairs counter mismatch")

    if len(rewards) == EXPECTED_OUTCOMES:
        score = statistics.mean(rewards)
        recorded_score = cell.get("score")
        if not _is_number(recorded_score) or not math.isclose(
            float(recorded_score), score, rel_tol=0.0, abs_tol=1e-12
        ):
            errors.append(f"{label}: score is not the held-out reward mean")
        outcome_summary = {
            "identities": identities,
            "rewards": rewards,
            "score": score,
            "parse_retries": parse_retries,
            "repairs": repairs,
        }

    return {
        "masked_config_sha256": expected_masked_digest,
        "outcomes": outcome_summary,
        "replay": replay_summary,
    }


def _invalid_report(errors: list[str]) -> dict[str, Any]:
    return {
        "aggregate": None,
        "bootstrap": None,
        "decision": "invalid",
        "errors": sorted(set(errors)),
        "experiment": EXPERIMENT,
        "limitation": LIMITATION,
        "mechanism_label": MECHANISM_LABEL,
        "pairs": [],
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": "invalid",
        "threshold_checks": None,
    }


def evaluate(manifest: Any) -> dict[str, Any]:
    """Validate one formal manifest and return the preregistered decision."""

    errors: list[str] = []
    if not isinstance(manifest, dict):
        return _invalid_report(["formal manifest must be a JSON object"])
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version mismatch")
    if manifest.get("experiment") != EXPERIMENT:
        errors.append("experiment label mismatch")
    if manifest.get("protocol") != PROTOCOL:
        errors.append("protocol mismatch")
    if manifest.get("mechanism_label") != MECHANISM_LABEL:
        errors.append(
            "mechanism_label must be exactly frozen-tape weight-update ablation"
        )
    if manifest.get("limitation") != LIMITATION:
        errors.append("limitation must retain not exact historical replication")
    if not _is_sha256(manifest.get("preregistration_sha256")):
        errors.append("preregistration_sha256 must be a lowercase SHA-256")

    provenance = _validate_provenance(manifest.get("provenance"), errors)
    corpora = manifest.get("corpora")
    if not isinstance(corpora, dict):
        errors.append("corpora: must be an object")
        corpora = {}
    adaptation_digest, adaptation_ids = _validate_corpus(
        "adaptation", corpora.get("adaptation"), errors
    )
    heldout_digest, heldout_ids = _validate_corpus(
        "heldout", corpora.get("heldout"), errors
    )
    if (
        adaptation_digest is not None
        and heldout_digest is not None
        and adaptation_digest == heldout_digest
    ):
        errors.append("adaptation and held-out aggregate corpus SHA-256 must differ")
    if adaptation_ids and heldout_ids and adaptation_ids == heldout_ids:
        errors.append("adaptation and held-out canonical instance IDs must differ")
    pairs = manifest.get("pairs")
    if not isinstance(pairs, list) or len(pairs) != len(EXPECTED_RUN_SEEDS):
        errors.append("pairs must contain exactly three seed pairs")
        pairs = []
    pair_ids = [pair.get("pair_id") for pair in pairs if isinstance(pair, dict)]
    if len(pair_ids) != len(set(pair_ids)):
        errors.append("pair_id values must be unique")
    observed_seeds = [
        pair.get("run_seed") for pair in pairs if isinstance(pair, dict)
    ]
    if Counter(observed_seeds) != Counter(EXPECTED_RUN_SEEDS):
        errors.append("run seeds must be exactly 2026071401, 2026071402, 2026071403")

    pair_reports: list[dict[str, Any]] = []
    paired_deltas_by_seed: list[list[float]] = []
    initial_hashes: list[str] = []
    for pair in sorted(
        (row for row in pairs if isinstance(row, dict)),
        key=lambda row: row.get("run_seed") if _is_int(row.get("run_seed")) else -1,
    ):
        pair_id = pair.get("pair_id")
        run_seed = pair.get("run_seed")
        pair_label = (
            f"pair[{pair_id}]"
            if isinstance(pair_id, str) and pair_id
            else f"pair[seed={run_seed}]"
        )
        if not isinstance(pair_id, str) or not pair_id:
            errors.append(f"{pair_label}: pair_id must be a non-empty string")
        if run_seed not in EXPECTED_RUN_SEEDS:
            errors.append(f"{pair_label}: invalid run_seed")
            continue
        (
            tape_digest,
            tape_item_digests,
            collector_initial_hash,
            tape_items,
        ) = _validate_tape(
            pair_label,
            run_seed,
            pair.get("tape"),
            pair.get("tape_verification"),
            adaptation_ids,
            errors,
        )
        active = _validate_cell(
            pair_label=pair_label,
            run_seed=run_seed,
            arm="active",
            cell=pair.get("active"),
            tape_digest=tape_digest,
            tape_item_digests=tape_item_digests,
            tape_items=tape_items,
            global_provenance=provenance,
            adaptation_digest=adaptation_digest,
            heldout_digest=heldout_digest,
            heldout_ids=heldout_ids,
            errors=errors,
        )
        lr0 = _validate_cell(
            pair_label=pair_label,
            run_seed=run_seed,
            arm="lr0",
            cell=pair.get("lr0"),
            tape_digest=tape_digest,
            tape_item_digests=tape_item_digests,
            tape_items=tape_items,
            global_provenance=provenance,
            adaptation_digest=adaptation_digest,
            heldout_digest=heldout_digest,
            heldout_ids=heldout_ids,
            errors=errors,
        )
        if active is None or lr0 is None:
            continue
        if active["masked_config_sha256"] != lr0["masked_config_sha256"]:
            errors.append(f"{pair_label}: configs differ beyond the two learning rates")
        active_replay = active.get("replay")
        lr0_replay = lr0.get("replay")
        if isinstance(active_replay, dict) and isinstance(lr0_replay, dict):
            if active_replay["operation_signature"] != lr0_replay[
                "operation_signature"
            ]:
                errors.append(
                    f"{pair_label}: active/LR0 ordered operation sequence mismatch"
                )
            for replay in (active_replay, lr0_replay):
                initial_hash = replay.get("initial_hash")
                if _is_sha256(initial_hash):
                    initial_hashes.append(initial_hash)
            if active_replay.get("initial_hash") != lr0_replay.get("initial_hash"):
                errors.append(f"{pair_label}: paired initial parameter hashes differ")
            if (
                collector_initial_hash is not None
                and (
                    active_replay.get("initial_hash") != collector_initial_hash
                    or lr0_replay.get("initial_hash") != collector_initial_hash
                )
            ):
                errors.append(
                    f"{pair_label}: collector/evaluation initial parameter hashes "
                    "differ"
                )
        active_outcomes = active.get("outcomes")
        lr0_outcomes = lr0.get("outcomes")
        if isinstance(active_outcomes, dict) and isinstance(lr0_outcomes, dict):
            if active_outcomes["identities"] != lr0_outcomes["identities"]:
                errors.append(f"{pair_label}: paired held-out outcome order mismatch")
            active_repair_total = (
                active_outcomes["parse_retries"] + active_outcomes["repairs"]
            )
            lr0_repair_total = lr0_outcomes["parse_retries"] + lr0_outcomes["repairs"]
            if active_repair_total > lr0_repair_total:
                errors.append(
                    f"{pair_label}: active parse retry/repair total exceeds LR0"
                )
            deltas = [
                active_reward - lr0_reward
                for active_reward, lr0_reward in zip(
                    active_outcomes["rewards"],
                    lr0_outcomes["rewards"],
                    strict=True,
                )
            ]
            delta_seed = statistics.mean(deltas)
            paired_deltas_by_seed.append(deltas)
            pair_reports.append(
                {
                    "active_score": round(active_outcomes["score"], 12),
                    "delta_seed": round(delta_seed, 12),
                    "lr0_score": round(lr0_outcomes["score"], 12),
                    "pair_id": pair_id,
                    "run_seed": run_seed,
                    "tape_sha256": tape_digest,
                }
            )

    if len(initial_hashes) == 2 * len(EXPECTED_RUN_SEEDS):
        if len(set(initial_hashes)) != 1:
            errors.append("all six cells must share one initial parameter SHA-256")
    else:
        errors.append("all six initial parameter SHA-256 values are required")

    if errors:
        report = _invalid_report(errors)
        report["pairs"] = pair_reports
        return report

    if len(pair_reports) != len(EXPECTED_RUN_SEEDS) or len(
        paired_deltas_by_seed
    ) != len(EXPECTED_RUN_SEEDS):
        report = _invalid_report(["three complete paired endpoints are required"])
        report["pairs"] = pair_reports
        return report

    bootstrap = hierarchical_paired_bootstrap(paired_deltas_by_seed)
    raw_seed_deltas = [statistics.mean(row) for row in paired_deltas_by_seed]
    raw_mean_delta = statistics.mean(raw_seed_deltas)
    ci_lower, ci_upper = bootstrap["ci_95"]
    threshold_checks = {
        "all_3_seed_deltas_gt_0": all(delta > 0.0 for delta in raw_seed_deltas),
        "mean_delta_gte_0_02": raw_mean_delta >= GO_MEAN_DELTA,
        "ci_95_lower_gt_0": ci_lower > 0.0,
        "integrity_gate_passed": True,
        "no_schema_format_regression": True,
    }
    passed = all(threshold_checks.values())
    return {
        "aggregate": {
            "ci_95_lower": ci_lower,
            "ci_95_upper": ci_upper,
            "mean_delta": round(raw_mean_delta, 12),
            "positive_seeds": sum(delta > 0.0 for delta in raw_seed_deltas),
        },
        "bootstrap": bootstrap,
        "decision": "pass" if passed else "valid_no_go",
        "errors": [],
        "experiment": EXPERIMENT,
        "limitation": LIMITATION,
        "mechanism_label": MECHANISM_LABEL,
        "pairs": pair_reports,
        "preregistered_thresholds": {
            "all_seed_deltas_gt": 0.0,
            "bootstrap_ci_lower_gt": 0.0,
            "mean_delta_gte": GO_MEAN_DELTA,
        },
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": "valid",
        "threshold_checks": threshold_checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a Cohort qonly frozen-tape causal formal manifest."
    )
    parser.add_argument("manifest_positional", type=Path, nargs="?")
    parser.add_argument("--manifest", dest="manifest_flag", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.manifest_positional is not None and args.manifest_flag is not None:
        parser.error("manifest may be provided either positionally or with --manifest")
    manifest_path = args.manifest_flag or args.manifest_positional
    if manifest_path is None:
        parser.error("formal manifest is required")

    load_errors: list[str] = []
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        manifest = {}
        load_errors.append(f"cannot load formal manifest: {exc}")
    report = evaluate(manifest)
    if load_errors:
        report = _invalid_report([*report.get("errors", []), *load_errors])
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    if report["decision"] == "invalid":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
