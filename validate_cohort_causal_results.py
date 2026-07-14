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
ROOT = Path(__file__).resolve().parent
PREREGISTRATION_FILENAME = "COHORT_QONLY_CAUSAL_PREREG.md"
EXPECTED_PREREGISTRATION_SHA256 = (
    "f9bb24bee51eabf155f5fac74a215304053f5156dd567ed9c19aa027aa88c94b"
)

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

_CHECKED_IN_DATASETS = {
    "adaptation": {
        "directory": "causal_adapt_2026071411",
        "manifest_sha256": (
            "16e5cd0f020c6a7e28d4f97b7cee2c5df683e56f133de4f5f9b46c3928890c5f"
        ),
    },
    "heldout": {
        "directory": "causal_eval_2026071412",
        "manifest_sha256": (
            "76259361e5d80da024f93803ce1e59e7c66be5f529aacb94e3125db9fc26e83d"
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

_MANIFEST_KEYS = {
    "schema_version",
    "experiment",
    "protocol",
    "mechanism_label",
    "limitation",
    "preregistration_sha256",
    "provenance",
    "corpora",
    "pairs",
}
_PROVENANCE_KEYS = {
    "source_commit",
    "preregistered_parent_commit",
    "environment_lock_sha256",
    "model_sha256",
    "tokenizer_sha256",
    "evaluation_code_sha256",
    "model_path",
    "adapter_init_seed",
}
_CORPORA_KEYS = {"adaptation", "heldout"}
_ADAPTATION_CORPUS_KEYS = {
    "aggregate_sha256",
    "canonical_instance_ids",
    "database_sha256",
    "dataset_manifest_sha256",
    "dgp_seed",
    "ground_truth_sha256",
    "schedule_id",
    "schedule_sha256",
    "used_for_evaluation",
    "used_for_updates",
}
_HELDOUT_CORPUS_KEYS = _ADAPTATION_CORPUS_KEYS | {"never_updated"}
_PAIR_KEYS = {
    "pair_id",
    "run_seed",
    "tape",
    "tape_verification",
    "active",
    "lr0",
}
_TAPE_VERIFICATION_KEYS = {"digest_verified", "items"}
_TAPE_VERIFICATION_ITEM_KEYS = {
    "digest_verified",
    "item_sha256",
    "sequence_index",
}
_CELL_KEYS = {
    "adaptation_corpus_sha256",
    "arm",
    "evaluation_order_sha256",
    "heldout_corpus_sha256",
    "heldout_outcomes",
    "heldout_trace",
    "heldout_updates_frozen",
    "integrity_counters",
    "masked_pair_config_sha256",
    "outcome_schema_version",
    "provenance",
    "replay",
    "run_seed",
    "score",
    "status",
    "system_config",
    "system_config_sha256",
    "tape_sha256",
    "task_config",
    "task_config_sha256",
    "trace_path",
    "trace_sha256",
}
_REPLAY_KEYS = {
    "digest_verified",
    "item_count",
    "items",
    "operation_count",
    "operations_per_item",
    "status",
    "tape_sha256",
    "trainable_param_sha256_final",
    "trainable_param_sha256_initial",
}
_REPLAY_ITEM_KEYS = {
    "best_env_reward",
    "instance_id",
    "instance_index",
    "integrity",
    "item_sha256",
    "operation_count",
    "operations",
    "sampling_provenance",
    "sequence_index",
    "status",
    "trainable_param_sha256_after",
    "trainable_param_sha256_before",
}
_REPLAY_OPERATION_KEYS = {
    "batch_count",
    "input_sha256",
    "operation",
    "trainable_param_sha256_after",
    "trainable_param_sha256_before",
}
_HELDOUT_OUTCOME_KEYS = {
    "instance_id",
    "instance_index",
    "integrity",
    "reward",
}
_INTEGRITY_COUNTER_KEYS = set(_COUNTER_ZERO_FIELDS) | {
    "parse_retries",
    "repairs",
}
_TRACE_KEYS = {
    "artifacts",
    "execution",
    "instance_outcomes",
    "interactions",
    "phase",
    "result",
    "schedule",
    "status",
    "system",
    "system_artifacts",
    "system_memory",
    "task",
    "task_brief",
}
_TRACE_SYSTEM_KEYS = {"continuity", "name", "params"}
_TRACE_TASK_KEYS = {"name", "params"}
_TRACE_EXECUTION_KEYS = {
    "avg_response_seconds",
    "end_time",
    "max_response_seconds",
    "run_group_id",
    "run_index",
    "start_time",
    "total_interactions",
    "total_response_seconds",
    "usage",
    "wall_duration_seconds",
}
_TRACE_INTERACTION_KEYS = {
    "done",
    "observation",
    "query",
    "response",
    "step_number",
    "timestamp",
    "timing",
    "usage",
}
_TERMINAL_QUERY_KEYS = {
    "feedback",
    "instance_id",
    "instance_index",
    "metadata",
    "prompt",
    "response_schema",
}
_TERMINAL_QUERY_METADATA_KEYS = {
    "instance_idx",
    "schedule_id",
    "step",
    "study_name",
}
_TERMINAL_RESPONSE_KEYS = {"action", "action_type", "metadata"}
_TERMINAL_RESPONSE_METADATA_KEYS = {
    "adaptation_context_policy",
    "adaptation_count",
    "context_policy",
    "generation_max_new_tokens",
    "has_truncated",
    "interaction_count",
    "last_adaptation_loss",
    "last_feedback_reward",
    "last_reward_advantage",
    "last_reward_clipped_advantage",
    "last_reward_judge_usage",
    "last_reward_pg_loss",
    "lora_param_norm_clip",
    "method",
    "model_path",
    "output_tokens",
    "parse_repair_used",
    "parse_retries_used",
    "prompt_tokens",
    "reward_feedback_source",
    "reward_judge_model",
    "reward_judge_provider",
    "reward_pg_negative_updates",
    "reward_pg_positive_updates",
    "reward_pg_updates",
    "reward_ppo_clip",
    "reward_update_rule",
    "reward_update_terminal",
    "system_type",
    "truncation_count",
    "ttt_history_truncation_count",
    "ttt_rl_source",
    "usage",
}
_TERMINAL_OBSERVATION_KEYS = {"content", "instance_complete", "metadata"}
_TERMINAL_OBSERVATION_METADATA_KEYS = {
    "cohort_gt",
    "env_feedback_instance_id",
    "env_feedback_instance_index",
    "env_feedback_raw_metric_higher_is_better",
    "env_feedback_raw_metric_name",
    "env_feedback_raw_metric_value",
    "env_feedback_reward",
    "env_feedback_success",
    "ref_survival",
}
_TRACE_OUTCOME_KEYS = {
    "cost_usd",
    "instance_id",
    "instance_index",
    "latency_seconds",
    "metadata",
    "raw_metric_higher_is_better",
    "raw_metric_name",
    "raw_metric_value",
    "reward",
    "success",
}
_TRACE_RESULT_KEYS = {
    "eval_metrics",
    "instance_outcomes",
    "metrics",
    "score",
    "summary",
}
_GROUND_TRUTH_ENTRY_KEYS = {
    "cohort_id",
    "survival_12m",
    "survival_24m",
    "survival_36m",
    "n_patients",
}
_REFERENCE_KEYS = {"survival_12m", "survival_24m", "survival_36m"}
_TRACE_TASK_CONFIG_KEYS = {
    "action_budget",
    "dataset_path",
    "num_instances",
    "repeat_instructions",
    "schedule",
    "seed",
}
_TIME_HORIZONS = (12, 24, 36)
_TERMINAL_PROMPT_SHA256 = (
    "6ba5b389db30d6d7e9fd7b2b54c826e8bef971cb4616fd013655aeaed0fc7d4e"
)
_TERMINAL_RESPONSE_SCHEMA = "CohortSubmission"


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


def _load_and_verify_checked_in_corpus(
    *, role: str, formal_corpus: Any, errors: list[str]
) -> dict[str, Any] | None:
    """Close a formal corpus projection over every checked-in source byte."""

    error_count = len(errors)
    contract = _CHECKED_IN_DATASETS.get(role)
    if contract is None:
        errors.append(f"unknown checked-in corpus role: {role}")
        return None
    if not isinstance(formal_corpus, dict):
        errors.append(f"formal {role} corpus must be an object")
        return None

    dataset_dir = ROOT / "data/cohort_studies" / contract["directory"]
    manifest_path = dataset_dir / "manifest.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
        dataset_manifest = json.loads(manifest_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load checked-in {role} manifest.json: {exc}")
        return None
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_digest != contract["manifest_sha256"]:
        errors.append(f"checked-in {role} manifest.json registered SHA-256 mismatch")
    if formal_corpus.get("dataset_manifest_sha256") != manifest_digest:
        errors.append(f"checked-in {role} manifest.json SHA-256 mismatch")

    artifacts = dataset_manifest.get("artifacts")
    artifact_bytes: dict[str, bytes] = {}
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(f"checked-in {role} manifest has no artifact inventory")
        artifacts = []
    dataset_root = dataset_dir.resolve()
    seen_paths: set[str] = set()
    for position, artifact in enumerate(artifacts):
        label = f"checked-in {role} manifest/artifacts[{position}]"
        if not _exact_keys(
            artifact,
            {"path", "sha256", "size_bytes"},
            label=label,
            errors=errors,
        ):
            if not isinstance(artifact, dict):
                continue
        relative_path = artifact.get("path")
        if not isinstance(relative_path, str) or not relative_path:
            errors.append(f"{label}: invalid artifact path")
            continue
        relative = Path(relative_path)
        if relative.is_absolute():
            errors.append(f"{label}: artifact path escapes dataset directory")
            continue
        try:
            artifact_path = (dataset_dir / relative).resolve()
            artifact_path.relative_to(dataset_root)
        except (OSError, ValueError):
            errors.append(f"{label}: artifact path escapes dataset directory")
            continue
        if relative_path in seen_paths:
            errors.append(f"{label}: duplicate artifact path")
            continue
        seen_paths.add(relative_path)
        expected_size = artifact.get("size_bytes")
        expected_digest = artifact.get("sha256")
        if not _is_int(expected_size) or expected_size < 0:
            errors.append(f"{label}: invalid size_bytes")
        if not _is_sha256(expected_digest):
            errors.append(f"{label}: invalid SHA-256")
        try:
            raw = artifact_path.read_bytes()
        except OSError as exc:
            errors.append(f"{label}: cannot read artifact: {exc}")
            continue
        artifact_bytes[relative_path] = raw
        if len(raw) != expected_size:
            errors.append(f"{label}: artifact size_bytes mismatch")
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            errors.append(f"{label}: artifact raw SHA-256 mismatch")

    try:
        artifacts_digest = canonical_sha256(artifacts)
    except (TypeError, ValueError) as exc:
        errors.append(f"cannot canonicalize checked-in {role} artifacts: {exc}")
    else:
        if artifacts_digest != dataset_manifest.get("corpus_sha256"):
            errors.append(f"checked-in {role} artifacts corpus SHA-256 mismatch")

    schedule_path = (
        ROOT
        / "src/tasks/cohort_studies/schedules"
        / f"{EXPECTED_CORPORA[role]['schedule_id']}.json"
    )
    try:
        schedule_bytes = schedule_path.read_bytes()
    except OSError as exc:
        errors.append(f"cannot read checked-in {role} schedule: {exc}")
    else:
        if (
            hashlib.sha256(schedule_bytes).hexdigest()
            != dataset_manifest.get("schedule_sha256")
        ):
            errors.append(f"checked-in {role} schedule raw SHA-256 mismatch")

    try:
        projection = corpus_projection_from_dataset_manifest(
            dataset_manifest,
            dataset_manifest_sha256=manifest_digest,
            role=role,
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"cannot project checked-in {role} manifest.json: {exc}")
        return None
    if not strict_json_equal(projection, formal_corpus):
        errors.append(f"formal {role} corpus differs from checked-in manifest projection")
    if len(errors) != error_count:
        return None
    return {
        "artifact_bytes": artifact_bytes,
        "manifest": dataset_manifest,
        "manifest_sha256": manifest_digest,
        "projection": projection,
    }


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


def _validate_formal_exact_schema(manifest: dict[str, Any]) -> list[str]:
    """Validate the publication evidence envelope with no ignored fields.

    The semantic validators below remain responsible for values.  This pass is
    deliberately separate so the preregistered ``no_schema_format_regression``
    threshold is computed from an actual gate rather than asserted as a literal.
    """

    errors: list[str] = []

    def exact(value: Any, expected: set[str], label: str) -> bool:
        return _exact_keys(value, expected, label=label, errors=errors)

    exact(manifest, _MANIFEST_KEYS, "manifest")
    exact(manifest.get("provenance"), _PROVENANCE_KEYS, "provenance")
    corpora = manifest.get("corpora")
    if exact(corpora, _CORPORA_KEYS, "corpora"):
        exact(
            corpora.get("adaptation"),
            _ADAPTATION_CORPUS_KEYS,
            "corpora/adaptation",
        )
        exact(
            corpora.get("heldout"),
            _HELDOUT_CORPUS_KEYS,
            "corpora/heldout",
        )

    pairs = manifest.get("pairs")
    if not isinstance(pairs, list):
        errors.append("pairs: must be a list")
        return errors
    for pair_index, pair in enumerate(pairs):
        pair_label = f"pairs[{pair_index}]"
        if not exact(pair, _PAIR_KEYS, pair_label):
            if not isinstance(pair, dict):
                continue
        tape_verification = pair.get("tape_verification")
        if exact(
            tape_verification,
            _TAPE_VERIFICATION_KEYS,
            f"{pair_label}/tape_verification",
        ):
            verification_items = tape_verification.get("items")
            if not isinstance(verification_items, list):
                errors.append(f"{pair_label}/tape_verification/items: must be a list")
            else:
                for item_index, item in enumerate(verification_items):
                    exact(
                        item,
                        _TAPE_VERIFICATION_ITEM_KEYS,
                        f"{pair_label}/tape_verification/items[{item_index}]",
                    )
        for arm in ("active", "lr0"):
            cell = pair.get(arm)
            cell_label = f"{pair_label}/{arm}"
            if not exact(cell, _CELL_KEYS, cell_label):
                if not isinstance(cell, dict):
                    continue
            replay = cell.get("replay")
            if exact(replay, _REPLAY_KEYS, f"{cell_label}/replay"):
                replay_items = replay.get("items")
                if not isinstance(replay_items, list):
                    errors.append(f"{cell_label}/replay/items: must be a list")
                else:
                    for item_index, item in enumerate(replay_items):
                        item_label = (
                            f"{cell_label}/replay/items[{item_index}]"
                        )
                        if not exact(item, _REPLAY_ITEM_KEYS, item_label):
                            if not isinstance(item, dict):
                                continue
                        exact(
                            item.get("integrity"),
                            _INTEGRITY_KEYS,
                            f"{item_label}/integrity",
                        )
                        operations = item.get("operations")
                        if not isinstance(operations, list):
                            errors.append(f"{item_label}/operations: must be a list")
                        else:
                            for operation_index, operation in enumerate(operations):
                                exact(
                                    operation,
                                    _REPLAY_OPERATION_KEYS,
                                    f"{item_label}/operations[{operation_index}]",
                                )
            outcomes = cell.get("heldout_outcomes")
            if not isinstance(outcomes, list):
                errors.append(f"{cell_label}/heldout_outcomes: must be a list")
            else:
                for outcome_index, outcome in enumerate(outcomes):
                    outcome_label = (
                        f"{cell_label}/heldout_outcomes[{outcome_index}]"
                    )
                    if exact(outcome, _HELDOUT_OUTCOME_KEYS, outcome_label):
                        exact(
                            outcome.get("integrity"),
                            _INTEGRITY_KEYS,
                            f"{outcome_label}/integrity",
                        )
            exact(
                cell.get("integrity_counters"),
                _INTEGRITY_COUNTER_KEYS,
                f"{cell_label}/integrity_counters",
            )
    return errors


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


def _load_checked_in_heldout_scoring_contract(
    *,
    heldout_corpus: Any,
    heldout_ids: list[str],
    errors: list[str],
    checked_in_corpus: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Load and verify the immutable files needed to rescore terminal actions."""

    if not isinstance(heldout_corpus, dict):
        return None
    if checked_in_corpus is None:
        checked_in_corpus = _load_and_verify_checked_in_corpus(
            role="heldout",
            formal_corpus=heldout_corpus,
            errors=errors,
        )
    if checked_in_corpus is None:
        return None
    verified_artifacts = checked_in_corpus.get("artifact_bytes")
    if not isinstance(verified_artifacts, dict):
        errors.append("checked-in held-out artifact bytes were not verified")
        return None
    loaded: dict[str, Any] = {}
    for filename in ("ground_truth.json", "instance_references.json"):
        raw = verified_artifacts.get(filename)
        if not isinstance(raw, bytes):
            errors.append(f"checked-in held-out {filename} bytes were not verified")
            return None
        try:
            loaded[filename] = json.loads(raw)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
            errors.append(f"cannot parse checked-in held-out {filename}: {exc}")
            return None

    ground_truth_rows = loaded["ground_truth.json"]
    if not isinstance(ground_truth_rows, list) or len(ground_truth_rows) != 36:
        errors.append("checked-in held-out ground truth must contain 36 cohorts")
        return None
    ground_truth: dict[str, dict[str, Any]] = {}
    for position, row in enumerate(ground_truth_rows):
        label = f"checked-in ground_truth[{position}]"
        if not _exact_keys(row, _GROUND_TRUTH_ENTRY_KEYS, label=label, errors=errors):
            continue
        cohort_id = row.get("cohort_id")
        if not isinstance(cohort_id, str) or not cohort_id:
            errors.append(f"{label}: invalid cohort_id")
            continue
        if cohort_id in ground_truth:
            errors.append(f"{label}: duplicate cohort_id")
        for field in ("survival_12m", "survival_24m", "survival_36m"):
            value = row.get(field)
            if not _is_number(value) or not 0.0 <= float(value) <= 1.0:
                errors.append(f"{label}: {field} must be a probability")
        if not _is_int(row.get("n_patients")) or row["n_patients"] < 0:
            errors.append(f"{label}: n_patients must be nonnegative integer")
        ground_truth[cohort_id] = row
    if len(ground_truth) != 36:
        return None

    references = loaded["instance_references.json"]
    if not isinstance(references, dict):
        errors.append("checked-in held-out instance references must be an object")
        return None
    expected_variants = [instance_id.rsplit(":", 1)[-1] for instance_id in heldout_ids]
    if set(references) != set(expected_variants):
        errors.append("checked-in held-out instance reference IDs mismatch")
    for variant, reference in references.items():
        label = f"checked-in instance_references[{variant}]"
        if not _exact_keys(reference, _REFERENCE_KEYS, label=label, errors=errors):
            continue
        for field in _REFERENCE_KEYS:
            value = reference.get(field)
            if not _is_number(value) or not 0.0 <= float(value) <= 1.0:
                errors.append(f"{label}: {field} must be a probability")

    cohort_gt = {
        cohort_id: {
            "cohort_id": row["cohort_id"],
            "survival_12m": row["survival_12m"],
            "survival_24m": row["survival_24m"],
            "survival_36m": row["survival_36m"],
            "n_patients": row["n_patients"],
            "type_mixture": {},
        }
        for cohort_id, row in ground_truth.items()
    }
    action_keys = {
        f"{cohort_id}__s{horizon}"
        for cohort_id in ground_truth
        for horizon in _TIME_HORIZONS
    }
    return {
        "action_keys": action_keys,
        "cohort_gt": cohort_gt,
        "ground_truth": ground_truth,
        "references": references,
    }


def _binary_kl_from_survival(true_survival: float, predicted_survival: float) -> float:
    """Mirror the frozen Cohort scorer's smoothed binary KL in bits."""

    true_value = min(1.0, max(0.0, float(true_survival)))
    predicted_value = min(1.0, max(0.0, float(predicted_survival)))
    true_dist = (
        0.99 * true_value + 0.005,
        0.99 * (1.0 - true_value) + 0.005,
    )
    predicted_dist = (
        0.99 * predicted_value + 0.005,
        0.99 * (1.0 - predicted_value) + 0.005,
    )
    value = sum(
        probability * math.log2(probability / prediction)
        for probability, prediction in zip(true_dist, predicted_dist, strict=True)
        if probability > 0.0
    )
    return max(0.0, value)


def _rescore_terminal_action(
    action: Any,
    *,
    instance_id: str,
    scoring_contract: dict[str, Any] | None,
    label: str,
    errors: list[str],
) -> float | None:
    """Independently score one exact 108-field terminal report."""

    if scoring_contract is None:
        errors.append(f"{label}: checked-in scoring contract is unavailable")
        return None
    expected_keys = scoring_contract["action_keys"]
    if not _exact_keys(action, expected_keys, label=f"{label}/action", errors=errors):
        return None
    numeric_action: dict[str, float] = {}
    for field, value in action.items():
        if not _is_number(value) or not 0.0 <= float(value) <= 1.0:
            errors.append(f"{label}/action: {field} must be a probability")
        else:
            numeric_action[field] = float(value)
    if len(numeric_action) != len(expected_keys):
        return None
    variant = instance_id.rsplit(":", 1)[-1]
    reference = scoring_contract["references"].get(variant)
    if not isinstance(reference, dict):
        errors.append(f"{label}: no checked-in reference for {variant}")
        return None
    ref_survival = tuple(
        float(reference[f"survival_{horizon}m"])
        for horizon in _TIME_HORIZONS
    )
    cohort_kls: list[float] = []
    reference_kls: list[float] = []
    for cohort_id, truth in scoring_contract["ground_truth"].items():
        cohort_time_kls: list[float] = []
        cohort_reference_kls: list[float] = []
        for horizon, ref_value in zip(
            _TIME_HORIZONS, ref_survival, strict=True
        ):
            predicted = numeric_action[f"{cohort_id}__s{horizon}"] or ref_value
            truth_value = float(truth[f"survival_{horizon}m"])
            cohort_time_kls.append(
                _binary_kl_from_survival(truth_value, predicted)
            )
            cohort_reference_kls.append(
                _binary_kl_from_survival(truth_value, ref_value)
            )
        cohort_kls.append(statistics.mean(cohort_time_kls))
        reference_kls.append(statistics.mean(cohort_reference_kls))
    return round(statistics.mean(reference_kls) - statistics.mean(cohort_kls), 6)


def _trace_response_integrity(metadata: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the runner's terminal response-integrity projection."""

    llm_error = metadata.get("llm_error")
    return {
        "schema_valid": llm_error is None,
        "synthetic": llm_error is not None,
        "timed_out": bool(
            isinstance(llm_error, dict)
            and llm_error.get("error_type") == "_InstanceTimeout"
        ),
        "fallback": llm_error is not None,
        "missing": False,
        "hard_schema_failure": bool(
            isinstance(llm_error, dict)
            and "did not parse as the required JSON"
            in str(llm_error.get("error_message", ""))
        ),
        "parse_retries": int(metadata.get("parse_retries_used", 0)),
        "repairs": int(bool(metadata.get("parse_repair_used", False))),
    }


def _validate_bound_heldout_trace(
    *,
    cell: dict[str, Any],
    pair_id: str,
    label: str,
    heldout_ids: list[str],
    scoring_contract: dict[str, Any] | None,
    errors: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Verify, independently rescore, and reconstruct held-out trace outcomes."""

    trace = cell.get("heldout_trace")
    if not isinstance(trace, dict):
        errors.append(f"{label}: heldout_trace must be an object")
        return [], []
    _exact_keys(trace, _TRACE_KEYS, label=f"{label}/heldout_trace", errors=errors)
    embedded_digest = cell.get("trace_sha256")
    if not _is_sha256(embedded_digest):
        errors.append(f"{label}: trace_sha256 must be a lowercase SHA-256")
    else:
        try:
            recomputed = canonical_sha256(trace)
        except (TypeError, ValueError) as exc:
            errors.append(f"{label}: cannot canonicalize heldout_trace: {exc}")
        else:
            if recomputed != embedded_digest:
                errors.append(f"{label}: embedded held-out trace SHA-256 mismatch")
    if not isinstance(cell.get("trace_path"), str) or not cell["trace_path"]:
        errors.append(f"{label}: trace_path must be a non-empty string")
    if trace.get("status") != "completed":
        errors.append(f"{label}: held-out trace status must be completed")
    if trace.get("phase") != "baseline":
        errors.append(f"{label}: held-out trace phase must be baseline")
    if trace.get("schedule") != EXPECTED_TASK_CONFIG["schedule"]:
        errors.append(f"{label}: held-out trace schedule mismatch")

    trace_system = trace.get("system")
    if _exact_keys(
        trace_system,
        _TRACE_SYSTEM_KEYS,
        label=f"{label}/heldout_trace/system",
        errors=errors,
    ):
        if trace_system.get("name") != "qwen_local":
            errors.append(f"{label}: held-out trace system name mismatch")
        if not strict_json_equal(trace_system.get("params"), cell.get("system_config")):
            errors.append(f"{label}: held-out trace system params mismatch")

    trace_task = trace.get("task")
    if _exact_keys(
        trace_task,
        _TRACE_TASK_KEYS,
        label=f"{label}/heldout_trace/task",
        errors=errors,
    ):
        if trace_task.get("name") != "cohort_studies":
            errors.append(f"{label}: held-out trace task name mismatch")
        cell_task_config = cell.get("task_config")
        expected_trace_task = (
            {
                key: cell_task_config.get(key)
                for key in _TRACE_TASK_CONFIG_KEYS
            }
            if isinstance(cell_task_config, dict)
            else None
        )
        if not strict_json_equal(trace_task.get("params"), expected_trace_task):
            errors.append(f"{label}: held-out trace task params mismatch")

    interactions = trace.get("interactions")
    if not isinstance(interactions, list):
        errors.append(f"{label}: held-out trace interactions must be a list")
        interactions = []
    max_interactions = EXPECTED_OUTCOMES * (
        int(EXPECTED_TASK_CONFIG["action_budget"]) + 1
    )
    if not EXPECTED_OUTCOMES * 2 <= len(interactions) <= max_interactions:
        errors.append(
            f"{label}: held-out trace interaction count is outside the "
            "preregistered per-instance bounds"
        )
    execution = trace.get("execution")
    if _exact_keys(
        execution,
        _TRACE_EXECUTION_KEYS,
        label=f"{label}/heldout_trace/execution",
        errors=errors,
    ):
        if execution.get("total_interactions") != len(interactions):
            errors.append(f"{label}: trace execution interaction count mismatch")
        if execution.get("run_group_id") != pair_id:
            errors.append(f"{label}: held-out trace run_group_id mismatch")
        if execution.get("run_index") != 0:
            errors.append(f"{label}: held-out trace run_index must be zero")

    terminal_by_identity: dict[tuple[Any, Any], dict[str, Any]] = {}
    terminal_signatures: list[dict[str, Any]] = []
    terminal_count = 0
    segment_length = 0
    for interaction_index, interaction in enumerate(interactions):
        interaction_label = (
            f"{label}/heldout_trace/interactions[{interaction_index}]"
        )
        if not _exact_keys(
            interaction,
            _TRACE_INTERACTION_KEYS,
            label=interaction_label,
            errors=errors,
        ):
            if not isinstance(interaction, dict):
                continue
        if interaction.get("step_number") != interaction_index + 1:
            errors.append(f"{interaction_label}: non-canonical step_number")
        expected_segment_id = (
            heldout_ids[terminal_count]
            if terminal_count < len(heldout_ids)
            else None
        )
        query_for_segment = interaction.get("query")
        if not isinstance(query_for_segment, dict) or (
            query_for_segment.get("instance_id"),
            query_for_segment.get("instance_index"),
        ) != (expected_segment_id, terminal_count):
            errors.append(f"{interaction_label}: interaction left canonical instance segment")
        segment_length += 1
        if segment_length > int(EXPECTED_TASK_CONFIG["action_budget"]) + 1:
            errors.append(f"{interaction_label}: instance segment exceeds action budget")
        observation = interaction.get("observation")
        if not isinstance(observation, dict):
            continue
        if observation.get("instance_complete") is not True:
            if interaction.get("done") is not False:
                errors.append(f"{interaction_label}: nonterminal done must be false")
            continue
        terminal_position = terminal_count
        terminal_count += 1
        if not 2 <= segment_length <= int(EXPECTED_TASK_CONFIG["action_budget"]) + 1:
            errors.append(f"{interaction_label}: invalid instance segment length")
        segment_length = 0
        if interaction.get("done") is not (
            terminal_position == EXPECTED_OUTCOMES - 1
        ):
            errors.append(f"{interaction_label}: terminal done flag mismatch")
        _exact_keys(
            observation,
            _TERMINAL_OBSERVATION_KEYS,
            label=f"{interaction_label}/observation",
            errors=errors,
        )
        query = interaction.get("query")
        response = interaction.get("response")
        if not isinstance(query, dict) or not isinstance(response, dict):
            errors.append(
                f"{label}/heldout_trace/interactions[{interaction_index}]: "
                "terminal query/response must be objects"
            )
            continue
        _exact_keys(
            query,
            _TERMINAL_QUERY_KEYS,
            label=f"{interaction_label}/query",
            errors=errors,
        )
        _exact_keys(
            response,
            _TERMINAL_RESPONSE_KEYS,
            label=f"{interaction_label}/response",
            errors=errors,
        )
        query_metadata = query.get("metadata")
        response_metadata = response.get("metadata")
        observation_metadata = observation.get("metadata")
        if not _exact_keys(
            query_metadata,
            _TERMINAL_QUERY_METADATA_KEYS,
            label=f"{interaction_label}/query/metadata",
            errors=errors,
        ):
            continue
        if not _exact_keys(
            response_metadata,
            _TERMINAL_RESPONSE_METADATA_KEYS,
            label=f"{interaction_label}/response/metadata",
            errors=errors,
        ):
            continue
        if not _exact_keys(
            observation_metadata,
            _TERMINAL_OBSERVATION_METADATA_KEYS,
            label=f"{interaction_label}/observation/metadata",
            errors=errors,
        ):
            continue
        expected_instance_id = (
            heldout_ids[terminal_position]
            if terminal_position < len(heldout_ids)
            else None
        )
        identity = (query.get("instance_id"), query.get("instance_index"))
        expected_identity = (expected_instance_id, terminal_position)
        observation_identity = (
            observation_metadata.get("env_feedback_instance_id"),
            observation_metadata.get("env_feedback_instance_index"),
        )
        if identity != expected_identity or observation_identity != expected_identity:
            errors.append(f"{interaction_label}: terminal identity chain mismatch")
        if query_metadata.get("instance_idx") != terminal_position:
            errors.append(f"{interaction_label}: query instance_idx mismatch")
        if query_metadata.get("schedule_id") != EXPECTED_TASK_CONFIG["schedule"]:
            errors.append(f"{interaction_label}: query schedule_id mismatch")
        if query_metadata.get("step") != "submission_extraction":
            errors.append(f"{interaction_label}: query terminal step mismatch")
        prompt = query.get("prompt")
        if not isinstance(prompt, str) or hashlib.sha256(
            prompt.encode()
        ).hexdigest() != _TERMINAL_PROMPT_SHA256:
            errors.append(f"{interaction_label}: terminal prompt SHA-256 mismatch")
        if query.get("response_schema") != _TERMINAL_RESPONSE_SCHEMA:
            errors.append(f"{interaction_label}: response_schema mismatch")
        variant = (
            expected_instance_id.rsplit(":", 1)[-1]
            if isinstance(expected_instance_id, str)
            else ""
        )
        if not isinstance(query_metadata.get("study_name"), str) or not query_metadata[
            "study_name"
        ]:
            errors.append(f"{interaction_label}: terminal study_name must be non-empty")
        terminal_signatures.append(
            {
                "instance_id": expected_instance_id,
                "prompt_sha256": (
                    hashlib.sha256(prompt.encode()).hexdigest()
                    if isinstance(prompt, str)
                    else None
                ),
                "response_schema": query.get("response_schema"),
                "study_name": query_metadata.get("study_name"),
            }
        )
        if response.get("action_type") != "structured":
            errors.append(f"{interaction_label}: terminal action_type mismatch")
        rescored_reward = _rescore_terminal_action(
            response.get("action"),
            instance_id=str(expected_instance_id),
            scoring_contract=scoring_contract,
            label=interaction_label,
            errors=errors,
        )
        reference = (
            scoring_contract["references"].get(variant)
            if scoring_contract is not None
            else None
        )
        expected_reference = (
            [reference[f"survival_{horizon}m"] for horizon in _TIME_HORIZONS]
            if isinstance(reference, dict)
            else None
        )
        if not strict_json_equal(
            observation_metadata.get("ref_survival"), expected_reference
        ):
            errors.append(f"{interaction_label}: checked-in ref_survival mismatch")
        if scoring_contract is None or not strict_json_equal(
            observation_metadata.get("cohort_gt"), scoring_contract["cohort_gt"]
        ):
            errors.append(f"{interaction_label}: checked-in cohort_gt mismatch")
        if rescored_reward is not None:
            for field in ("env_feedback_reward", "env_feedback_raw_metric_value"):
                value = observation_metadata.get(field)
                if not _is_number(value) or not math.isclose(
                    float(value), rescored_reward, rel_tol=0.0, abs_tol=1e-12
                ):
                    errors.append(
                        f"{interaction_label}: {field} differs from independent score"
                    )
            if observation_metadata.get("env_feedback_success") is not (
                rescored_reward > 0.0
            ):
                errors.append(f"{interaction_label}: env_feedback_success mismatch")
        if (
            observation_metadata.get("env_feedback_raw_metric_name")
            != "kl_information_gain_bits"
        ):
            errors.append(f"{interaction_label}: env feedback metric name mismatch")
        if observation_metadata.get(
            "env_feedback_raw_metric_higher_is_better"
        ) is not True:
            errors.append(f"{interaction_label}: env feedback metric direction mismatch")
        if identity in terminal_by_identity:
            errors.append(f"{label}: duplicate terminal identities in held-out trace")
        terminal_by_identity[identity] = {
            "integrity": _trace_response_integrity(response_metadata),
            "reward": rescored_reward,
        }
    if terminal_count != EXPECTED_OUTCOMES:
        errors.append(f"{label}: held-out trace must contain exactly 20 terminals")
    if segment_length != 0:
        errors.append(f"{label}: held-out trace ends inside an instance segment")

    trace_outcomes = trace.get("instance_outcomes")
    if not isinstance(trace_outcomes, list) or len(trace_outcomes) != EXPECTED_OUTCOMES:
        errors.append(
            f"{label}: held-out trace instance_outcomes must contain exactly 20 rows"
        )
        return [], terminal_signatures
    result = trace.get("result")
    if not _exact_keys(
        result,
        _TRACE_RESULT_KEYS,
        label=f"{label}/heldout_trace/result",
        errors=errors,
    ):
        result = {}
    result_outcomes = result.get("instance_outcomes")
    if not strict_json_equal(result_outcomes, trace_outcomes):
        errors.append(f"{label}: trace/result instance_outcomes mismatch")

    reconstructed: list[dict[str, Any]] = []
    rewards: list[float] = []
    for position, trace_outcome in enumerate(trace_outcomes):
        row_label = f"{label}/heldout_trace/instance_outcomes[{position}]"
        if not _exact_keys(
            trace_outcome,
            _TRACE_OUTCOME_KEYS,
            label=row_label,
            errors=errors,
        ):
            continue
        instance_id = trace_outcome.get("instance_id")
        instance_index = trace_outcome.get("instance_index")
        reward = trace_outcome.get("reward")
        if position < len(heldout_ids) and instance_id != heldout_ids[position]:
            errors.append(f"{row_label}: held-out instance ID/order mismatch")
        if instance_index != position:
            errors.append(f"{row_label}: non-canonical instance_index")
        if not _is_number(reward):
            errors.append(f"{row_label}: reward must be finite numeric")
            continue
        identity = (instance_id, instance_index)
        terminal = terminal_by_identity.get(identity)
        if terminal is None or terminal.get("reward") is None:
            errors.append(f"{row_label}: missing independently scored terminal")
            continue
        independent_reward = float(terminal["reward"])
        if not math.isclose(
            float(reward), independent_reward, rel_tol=0.0, abs_tol=1e-12
        ):
            errors.append(f"{row_label}: reward differs from independent score")
        raw_value = trace_outcome.get("raw_metric_value")
        if not _is_number(raw_value) or not math.isclose(
            float(raw_value), independent_reward, rel_tol=0.0, abs_tol=1e-12
        ):
            errors.append(f"{row_label}: raw_metric_value differs from score")
        if trace_outcome.get("raw_metric_name") != "kl_information_gain_bits":
            errors.append(f"{row_label}: raw_metric_name mismatch")
        if trace_outcome.get("raw_metric_higher_is_better") is not True:
            errors.append(f"{row_label}: raw metric direction mismatch")
        if trace_outcome.get("success") is not (independent_reward > 0.0):
            errors.append(f"{row_label}: success differs from score sign")
        numeric_reward = independent_reward
        rewards.append(numeric_reward)
        reconstructed.append(
            {
                "instance_id": instance_id,
                "instance_index": instance_index,
                "integrity": terminal["integrity"],
                "reward": numeric_reward,
            }
        )
    if len(rewards) == EXPECTED_OUTCOMES:
        trace_score = statistics.mean(rewards)
        result_score = result.get("score")
        if not _is_number(result_score) or not math.isclose(
            float(result_score), trace_score, rel_tol=0.0, abs_tol=1e-12
        ):
            errors.append(f"{label}: trace result score is not the trace reward mean")
    return reconstructed, terminal_signatures


def _validate_cell(
    *,
    pair_label: str,
    pair_id: str,
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
    scoring_contract: dict[str, Any] | None,
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

    trace_outcomes, terminal_signatures = _validate_bound_heldout_trace(
        cell=cell,
        pair_id=pair_id,
        label=label,
        heldout_ids=heldout_ids,
        scoring_contract=scoring_contract,
        errors=errors,
    )

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
        if position >= len(trace_outcomes) or not strict_json_equal(
            outcome, trace_outcomes[position]
        ):
            errors.append(
                f"{outcome_label}: outcome/reward/integrity differs from bound trace"
            )
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
            "terminal_signatures": terminal_signatures,
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
    schema_errors = _validate_formal_exact_schema(manifest)
    schema_gate_passed = not schema_errors
    errors.extend(schema_errors)
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
    preregistration_sha256 = manifest.get("preregistration_sha256")
    try:
        checked_in_preregistration_sha256 = hashlib.sha256(
            (ROOT / PREREGISTRATION_FILENAME).read_bytes()
        ).hexdigest()
    except OSError as exc:
        errors.append(f"cannot read checked-in preregistration file: {exc}")
    else:
        if checked_in_preregistration_sha256 != EXPECTED_PREREGISTRATION_SHA256:
            errors.append("checked-in preregistration file SHA-256 drift")
    if not _is_sha256(preregistration_sha256):
        errors.append("preregistration_sha256 must be a lowercase SHA-256")
    elif preregistration_sha256 != EXPECTED_PREREGISTRATION_SHA256:
        errors.append(
            "preregistration_sha256 differs from checked-in preregistration"
        )

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
    _load_and_verify_checked_in_corpus(
        role="adaptation",
        formal_corpus=corpora.get("adaptation"),
        errors=errors,
    )
    checked_in_heldout = _load_and_verify_checked_in_corpus(
        role="heldout",
        formal_corpus=corpora.get("heldout"),
        errors=errors,
    )
    scoring_contract = _load_checked_in_heldout_scoring_contract(
        heldout_corpus=corpora.get("heldout"),
        heldout_ids=heldout_ids,
        errors=errors,
        checked_in_corpus=checked_in_heldout,
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
            pair_id=pair_id,
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
            scoring_contract=scoring_contract,
            errors=errors,
        )
        lr0 = _validate_cell(
            pair_label=pair_label,
            pair_id=pair_id,
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
            scoring_contract=scoring_contract,
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
            if active_outcomes["terminal_signatures"] != lr0_outcomes[
                "terminal_signatures"
            ]:
                errors.append(
                    f"{pair_label}: paired terminal prompt/schema/study signatures differ"
                )
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
        "no_schema_format_regression": schema_gate_passed,
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
