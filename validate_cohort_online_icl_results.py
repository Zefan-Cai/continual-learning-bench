#!/usr/bin/env python3
"""Validate Cohort online-ICL cells and assemble the internal three-arm screen."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import math
import statistics
from pathlib import Path
from typing import Any, Callable

from run_cohort_causal import (
    _canonical_bytes,
    _response_integrity,
)
from run_cohort_online_icl import _json_no_duplicates, _load_verified_dataset_bundle
from validate_cohort_causal_results import (
    _load_checked_in_heldout_scoring_contract,
    _rescore_terminal_action,
    _exact_zero_value_count,
    canonical_sha256,
    evaluate as evaluate_causal_manifest,
)


SCHEMA_VERSION = 1
PROTOCOL = "cohort_reward_aware_online_icl_v1"
ARM = "online_icl"
INTERNAL_SCREEN_SEEDS = (2026071401, 2026071402, 2026071403)
NO_UPDATE_AUDIT = {
    "adaptation_count": 0,
    "adapter_enabled": False,
    "bon_updates": 0,
    "distill_updates": 0,
    "grpo_optimizer_steps": 0,
    "grpo_updates": 0,
    "peft_config_present": False,
    "reward_pg_updates": 0,
}
INTEGRITY_ZERO_FIELDS = (
    "fallbacks",
    "hard_schema_failures",
    "missing_outcomes",
    "synthetic_outcomes",
    "timed_out_outcomes",
)
CAUSAL_PREREQUISITE_FIELDS = frozenset(
    {
        "causal_provenance_sha256",
        "causal_smoke_gate_sha256",
        "causal_source_commit",
        "environment_lock_sha256",
        "model_path",
        "model_sha256",
        "tokenizer_sha256",
    }
)
FORMAL_SMOKE_GATE_FIELDS = frozenset(
    {
        "causal_prerequisite",
        "cell",
        "decision",
        "decision_scope",
        "efficacy_interpretation_allowed",
        "protocol",
        "protocol_seal_sha256",
        "provenance_sha256",
        "publication_grade",
        "schema_version",
        "status",
    }
)
SMOKE_CELL_INTEGRITY_FIELDS = frozenset(
    {
        "adaptation_trace_file_sha256",
        "adaptation_trace_sha256",
        "cell_manifest_file_sha256",
        "cell_manifest_sha256",
        "cfg_id",
        "context_inventory_file_sha256",
        "context_inventory_sha256",
        "heldout_trace_file_sha256",
        "heldout_trace_sha256",
        "restoration_audit_file_sha256",
        "restoration_audit_sha256",
        "run_seed",
        "snapshot_file_sha256",
        "snapshot_artifact_sha256",
        "snapshot_sha256",
        "valid",
    }
)

TokenizerLoader = Callable[[dict[str, Any]], Any]


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _load_with_file_sha256(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink():
        raise ValueError(f"refusing final-component artifact symlink: {path}")
    raw = path.read_bytes()
    value = _json_no_duplicates(raw, where=f"online-ICL artifact {path}")
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    if raw != _canonical_bytes(value) + b"\n":
        raise ValueError(f"online-ICL artifact is not canonical JSON: {path}")
    return value, hashlib.sha256(raw).hexdigest()


def _artifact_payload_sha(artifact: dict[str, Any]) -> str:
    embedded = artifact.get("artifact_sha256")
    payload = {
        key: value for key, value in artifact.items() if key != "artifact_sha256"
    }
    calculated = canonical_sha256(payload)
    if embedded != calculated:
        raise ValueError("online-ICL artifact SHA-256 mismatch")
    return calculated


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _assert_exact_keys(value: Any, expected: set[str], *, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{where} schema mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _assert_integrity_zero(counters: Any, *, where: str) -> None:
    if not isinstance(counters, dict):
        raise ValueError(f"{where} integrity counters must be an object")
    nonzero = {
        key: counters.get(key)
        for key in INTEGRITY_ZERO_FIELDS
        if counters.get(key) != 0
    }
    if nonzero:
        raise ValueError(f"{where} integrity failure: {nonzero}")


def _assert_outcomes(
    outcomes: Any, *, expected: int, expected_ids: list[str], where: str
) -> list[dict[str, Any]]:
    if not isinstance(outcomes, list) or len(outcomes) != expected:
        raise ValueError(f"{where} must contain exactly {expected} outcomes")
    observed_ids = [row.get("instance_id") for row in outcomes if isinstance(row, dict)]
    observed_indices = [
        row.get("instance_index") for row in outcomes if isinstance(row, dict)
    ]
    if observed_ids != expected_ids[:expected]:
        raise ValueError(f"{where} instance IDs/order differ from corpus")
    if observed_indices != list(range(expected)):
        raise ValueError(f"{where} instance indexes/order differ from corpus")
    if len(set(zip(observed_ids, observed_indices, strict=True))) != expected:
        raise ValueError(f"{where} contains duplicate identities")
    for row in outcomes:
        if not isinstance(row, dict):
            raise ValueError(f"{where} row must be an object")
        reward = row.get("reward")
        if (
            isinstance(reward, bool)
            or not isinstance(reward, (int, float))
            or not math.isfinite(float(reward))
        ):
            raise ValueError(f"{where} contains a non-finite reward")
        integrity = row.get("integrity")
        if not isinstance(integrity, dict) or any(
            integrity.get(key) is not expected_value
            for key, expected_value in {
                "fallback": False,
                "hard_schema_failure": False,
                "missing": False,
                "schema_valid": True,
                "synthetic": False,
                "timed_out": False,
            }.items()
        ):
            raise ValueError(f"{where} response integrity failed")
    return outcomes


def _assert_compute(compute: Any) -> None:
    if not isinstance(compute, dict) or set(compute) != {
        "adaptation",
        "heldout",
        "model_initialization",
        "snapshot",
    }:
        raise ValueError("online-ICL compute phase inventory mismatch")
    for phase, values in compute.items():
        if not isinstance(values, dict):
            raise ValueError(f"compute.{phase} must be an object")
        for key in (
            "candidate_samples",
            "failures",
            "generation_calls",
            "gpu_count",
            "gpu_seconds",
            "input_tokens",
            "optimizer_backward_calls",
            "optimizer_forward_calls",
            "optimizer_steps",
            "output_tokens",
            "parse_repairs",
            "parse_retries",
            "peak_allocated_bytes",
            "peak_reserved_bytes",
            "prompt_hard_truncations",
            "total_tokens",
            "wall_seconds",
        ):
            value = values.get(key)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0
            ):
                raise ValueError(f"compute.{phase}.{key} is invalid")
        if values["candidate_samples"] != 0:
            raise ValueError("online ICL may not sample adaptation candidates")
        if values["failures"] != 0:
            raise ValueError("valid online ICL may not contain generation failures")
        if any(
            values[key] != 0
            for key in (
                "optimizer_backward_calls",
                "optimizer_forward_calls",
                "optimizer_steps",
            )
        ):
            raise ValueError("online ICL compute reports an optimizer operation")
        if values["total_tokens"] != values["input_tokens"] + values["output_tokens"]:
            raise ValueError(f"compute.{phase} token accounting mismatch")
        if phase in {"model_initialization", "snapshot"} and any(
            values[key] != 0
            for key in (
                "generation_calls",
                "input_tokens",
                "output_tokens",
                "parse_repairs",
                "parse_retries",
                "prompt_hard_truncations",
                "total_tokens",
            )
        ):
            raise ValueError(f"compute.{phase} reports an impossible model call")


def _trace_compute_counts(trace: dict[str, Any]) -> dict[str, int]:
    interactions = trace.get("interactions")
    if not isinstance(interactions, list):
        raise ValueError("trace interactions are missing for compute accounting")
    metadata_rows = []
    for interaction in interactions:
        if not isinstance(interaction, dict):
            raise ValueError("trace interaction is malformed for compute accounting")
        metadata = interaction.get("response", {}).get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError(
                "trace response metadata is missing for compute accounting"
            )
        for key in (
            "generation_calls",
            "generation_input_tokens_total",
            "generation_output_tokens_total",
            "generation_prompt_hard_truncations",
            "parse_retries_used",
        ):
            value = metadata.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"trace response compute metadata {key} is incomplete")
        if not isinstance(metadata.get("parse_repair_used"), bool):
            raise ValueError(
                "trace response compute metadata parse_repair_used is incomplete"
            )
        if "llm_error" in metadata and not isinstance(metadata["llm_error"], dict):
            raise ValueError("trace response llm_error metadata is malformed")
        metadata_rows.append(metadata)
    projection = {
        "failures": sum(
            int(isinstance(row.get("llm_error"), dict)) for row in metadata_rows
        ),
        "generation_calls": sum(row["generation_calls"] for row in metadata_rows),
        "input_tokens": sum(
            row["generation_input_tokens_total"] for row in metadata_rows
        ),
        "output_tokens": sum(
            row["generation_output_tokens_total"] for row in metadata_rows
        ),
        "parse_repairs": sum(
            int(bool(row.get("parse_repair_used"))) for row in metadata_rows
        ),
        "parse_retries": sum(row["parse_retries_used"] for row in metadata_rows),
        "prompt_hard_truncations": sum(
            row["generation_prompt_hard_truncations"] for row in metadata_rows
        ),
    }
    projection["total_tokens"] = (
        projection["input_tokens"] + projection["output_tokens"]
    )
    if (
        projection["generation_calls"]
        != len(interactions) + projection["parse_retries"]
    ):
        raise ValueError("trace generation-call accounting differs from retries")
    return projection


def _scoring_contract(
    *, root: Path, grid: dict[str, Any], role: str, corpus: dict[str, Any]
) -> dict[str, Any]:
    checked_in = _load_verified_dataset_bundle(root, grid, role)
    projection = checked_in["projection"]
    if _canonical_bytes(projection) != _canonical_bytes(corpus):
        raise ValueError(f"{role} corpus differs from registered checked-in bytes")
    errors: list[str] = []
    canonical_ids = projection["canonical_instance_ids"]
    contract = _load_checked_in_heldout_scoring_contract(
        heldout_corpus=corpus,
        heldout_ids=canonical_ids,
        errors=errors,
        checked_in_corpus=checked_in,
    )
    if errors or contract is None:
        raise ValueError(
            f"{role} checked-in scoring contract validation failed: "
            + "; ".join(sorted(set(errors)))
        )
    return contract


def _independent_reward(
    action: Any,
    *,
    instance_id: str,
    scoring_contract: dict[str, Any],
    where: str,
) -> float:
    errors: list[str] = []
    value = _rescore_terminal_action(
        action,
        instance_id=instance_id,
        scoring_contract=scoring_contract,
        label=where,
        errors=errors,
    )
    if errors or value is None:
        raise ValueError(
            f"{where} independent Cohort rescore failed: "
            + "; ".join(sorted(set(errors)))
        )
    return float(value)


def _load_registered_tokenizer(system_params: dict[str, Any]) -> Any:
    """Load only the provenance-bound tokenizer used by the registered cell."""

    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(
        system_params["model_path"],
        trust_remote_code=bool(system_params.get("trust_remote_code", False)),
    )


def _render_messages(
    tokenizer: Any,
    *,
    system_prompt: str,
    messages: list[dict[str, str]],
) -> str:
    rendered_messages = list(messages)
    if system_prompt:
        rendered_messages = [
            {"role": "system", "content": system_prompt},
            *rendered_messages,
        ]
    try:
        rendered = tokenizer.apply_chat_template(
            rendered_messages,
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=False,
        )
    except TypeError:
        rendered = tokenizer.apply_chat_template(
            rendered_messages,
            tokenize=False,
            add_generation_prompt=True,
        )
    if not isinstance(rendered, str):
        raise ValueError("registered tokenizer returned a non-string chat template")
    return rendered


def _token_ids(tokenizer: Any, rendered: str) -> list[int]:
    encoded = tokenizer.encode(rendered, add_special_tokens=False)
    if not isinstance(encoded, list) or any(
        isinstance(token, bool) or not isinstance(token, int) or token < 0
        for token in encoded
    ):
        raise ValueError("registered tokenizer returned malformed token IDs")
    return encoded


def _expected_snapshot_system_contract(
    system_params: dict[str, Any],
) -> dict[str, Any]:
    system_prompt = system_params["system_prompt"]
    return {
        "action_max_new_tokens": system_params["action_max_new_tokens"],
        "adaptation_context_policy": system_params["adaptation_context_policy"],
        "best_of_n": system_params["best_of_n"],
        "bon_critic": system_params.get("bon_critic", "llm"),
        "context_policy": system_params["context_policy"],
        "distill_provider": system_params["distill_provider"],
        "head_tokens": system_params["head_tokens"],
        "inject_env_reward": system_params["inject_env_reward"],
        "max_context_tokens": system_params["max_context_tokens"],
        "max_new_tokens": system_params["max_new_tokens"],
        "method": system_params["method"],
        "model_path": system_params["model_path"],
        "parse_retries": system_params["parse_retries"],
        "sealed_eval": True,
        "system_prompt_chars": len(system_prompt),
        "system_prompt_sha256": hashlib.sha256(
            system_prompt.encode("utf-8")
        ).hexdigest(),
        "tail_tokens": system_params["tail_tokens"],
        "temperature": system_params["temperature"],
        "top_p": system_params["top_p"],
    }


def _registered_cohort_response_schema(response_schema_name: Any) -> type[Any]:
    """Resolve only the two response schemas registered by CohortStudyTask."""

    from src.tasks.cohort_studies.tool_schemas import (
        ToolCallResponse,
        build_submission_schema,
    )

    schemas = (ToolCallResponse, build_submission_schema())
    by_name = {schema.__name__: schema for schema in schemas}
    if len(by_name) != len(schemas):
        raise RuntimeError("registered Cohort response-schema names are ambiguous")
    if not isinstance(response_schema_name, str) or response_schema_name not in by_name:
        raise ValueError(
            "adaptation trace carries an unregistered response schema: "
            f"{response_schema_name!r}"
        )
    return by_name[response_schema_name]


def _assistant_record(action: Any, *, response_schema_name: Any) -> str:
    """Reproduce the exact Pydantic JSON appended by QwenLocalSystem.

    Trace artifacts are canonical JSON and therefore sort object keys.  The
    live system instead appends ``parsed_action.model_dump_json()`` to its
    prompt-bearing state, which uses the registered Pydantic field order.  A
    schema revalidation is required to recover those exact bytes.
    """

    if not isinstance(action, dict):
        raise ValueError("adaptation trace action must be a structured object")
    schema = _registered_cohort_response_schema(response_schema_name)
    try:
        parsed_action = schema.model_validate(deepcopy(action))
        if _canonical_bytes(parsed_action.model_dump()) != _canonical_bytes(action):
            raise ValueError("recorded action changes under schema validation")
        return parsed_action.model_dump_json()
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "adaptation trace action does not validate against its recorded "
            f"response schema {response_schema_name!r}"
        ) from exc


def _reconstruct_adaptation_snapshot_state(
    *,
    trace: dict[str, Any],
    system_params: dict[str, Any],
    tokenizer: Any,
) -> dict[str, Any]:
    """Rebuild the exact prompt-bearing state from adaptation trace events."""

    if system_params.get("context_policy") != "full":
        raise ValueError("online-ICL snapshot reconstruction requires full context")
    max_context_tokens = system_params.get("max_context_tokens")
    if (
        isinstance(max_context_tokens, bool)
        or not isinstance(max_context_tokens, int)
        or max_context_tokens <= 0
    ):
        raise ValueError("registered max_context_tokens is invalid")
    system_prompt = system_params.get("system_prompt")
    if not isinstance(system_prompt, str):
        raise ValueError("registered system_prompt is invalid")

    interactions = trace.get("interactions")
    if not isinstance(interactions, list):
        raise ValueError("adaptation trace interactions are missing")
    messages: list[dict[str, str]] = []
    truncation_count = 0
    injections = 0
    for position, interaction in enumerate(interactions):
        if not isinstance(interaction, dict):
            raise ValueError(f"adaptation trace interaction {position} is malformed")
        query = interaction.get("query")
        response = interaction.get("response")
        observation = interaction.get("observation")
        if not all(isinstance(value, dict) for value in (query, response, observation)):
            raise ValueError(f"adaptation trace interaction {position} schema mismatch")
        if query.get("feedback") is not None:
            raise ValueError("adaptation trace unexpectedly carries Query.feedback")
        prompt = query.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError(f"adaptation trace query {position} has no prompt")
        messages.append({"role": "user", "content": prompt or "(no content)"})
        while len(messages) > 1:
            rendered = _render_messages(
                tokenizer,
                system_prompt=system_prompt,
                messages=messages,
            )
            if len(_token_ids(tokenizer, rendered)) <= max_context_tokens:
                break
            messages.pop(0)
            truncation_count += 1

        messages.append(
            {
                "role": "assistant",
                "content": _assistant_record(
                    response.get("action"),
                    response_schema_name=query.get("response_schema"),
                ),
            }
        )
        content = observation.get("content")
        if not isinstance(content, str):
            raise ValueError(f"adaptation observation {position} content is invalid")
        parts: list[str] = []
        if content.strip():
            parts.append(f"FEEDBACK: {content.strip()}")
        metadata = observation.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError(f"adaptation observation {position} metadata is invalid")
        reward = metadata.get("env_feedback_reward")
        if (
            system_params.get("inject_env_reward")
            and isinstance(reward, (int, float))
            and not isinstance(reward, bool)
        ):
            if not math.isfinite(float(reward)):
                raise ValueError("adaptation environment reward is non-finite")
            parts.append(
                "ENV_REWARD (score of your previous answer, higher is better): "
                f"{float(reward):.4f}"
            )
            injections += 1
        if parts:
            messages.append({"role": "user", "content": "\n".join(parts)})
    return {
        "has_truncated_flag": truncation_count > 0,
        "icl_env_reward_injections": injections,
        "interaction_count": len(interactions),
        "messages": messages,
        "truncation_count": truncation_count,
    }


def _message_inventory(messages: list[dict[str, str]]) -> dict[str, Any]:
    rows = [
        {
            "content_sha256": hashlib.sha256(
                message["content"].encode("utf-8")
            ).hexdigest(),
            "index": index,
            "role": message["role"],
            "utf8_bytes": len(message["content"].encode("utf-8")),
        }
        for index, message in enumerate(messages)
    ]
    return {
        "count": len(rows),
        "inventory_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def _token_inventory(
    *,
    tokenizer: Any,
    system_prompt: str,
    messages: list[dict[str, str]],
    snapshot_sha256: str,
) -> dict[str, Any]:
    rendered = _render_messages(
        tokenizer,
        system_prompt=system_prompt,
        messages=messages,
    )
    token_ids = _token_ids(tokenizer, rendered)
    return {
        "rendered_prompt_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "snapshot_sha256": snapshot_sha256,
        "token_count": len(token_ids),
        "token_ids": token_ids,
        "token_ids_sha256": canonical_sha256(token_ids),
    }


def _reconstruct_trace_phase(
    *,
    trace: dict[str, Any],
    cfg: dict[str, Any],
    role: str,
    expected: int,
    expected_ids: list[str],
    scoring_contract: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    expected_phase = "rollout" if role == "adaptation" else "baseline"
    if trace.get("status") != "completed" or trace.get("phase") != expected_phase:
        raise ValueError(f"{role} trace status or phase mismatch")
    system = trace.get("system")
    if (
        not isinstance(system, dict)
        or system.get("name") != "qwen_local"
        or system.get("params") != cfg["system_params"]
    ):
        raise ValueError(f"{role} trace system configuration mismatch")
    task = trace.get("task")
    expected_task_params = cfg[f"{role}_task_params"]
    if (
        not isinstance(task, dict)
        or task.get("name") != "cohort_studies"
        or task.get("params") != expected_task_params
    ):
        raise ValueError(f"{role} trace task configuration mismatch")

    trace_outcomes = trace.get("instance_outcomes")
    result = trace.get("result")
    result_outcomes = (
        result.get("instance_outcomes") if isinstance(result, dict) else None
    )
    if (
        not isinstance(trace_outcomes, list)
        or len(trace_outcomes) != expected
        or _canonical_bytes(trace_outcomes) != _canonical_bytes(result_outcomes)
    ):
        raise ValueError(f"{role} trace outcome inventory mismatch")

    terminal_by_identity: dict[tuple[str, int], dict[str, Any]] = {}
    terminal_order: list[tuple[str, int]] = []
    expected_sealed = role == "heldout"
    expected_order = [
        (instance_id, index)
        for index, instance_id in enumerate(expected_ids[:expected])
    ]
    adaptation_instance_cursor = 0
    interactions = trace.get("interactions")
    if not isinstance(interactions, list) or not interactions:
        raise ValueError(f"{role} trace interaction inventory is missing")
    for position, interaction in enumerate(interactions):
        if not isinstance(interaction, dict):
            raise ValueError(f"{role} trace interaction {position} is malformed")
        query = interaction.get("query")
        response = interaction.get("response")
        observation = interaction.get("observation")
        if not all(isinstance(value, dict) for value in (query, response, observation)):
            raise ValueError(f"{role} trace interaction {position} schema mismatch")
        if query.get("feedback") is not None:
            raise ValueError(f"{role} trace unexpectedly carries Query.feedback")
        metadata = response.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError(f"{role} trace response metadata is missing")
        if metadata.get("icl_context_sealed_eval") is not expected_sealed:
            raise ValueError(f"{role} trace sealed-evaluation flag mismatch")
        instance_complete = observation.get("instance_complete")
        if not isinstance(instance_complete, bool):
            raise ValueError(f"{role} observation completion flag is invalid")
        if role == "adaptation":
            instance_id = query.get("instance_id")
            instance_index = query.get("instance_index")
            if (
                adaptation_instance_cursor >= len(expected_order)
                or (
                    instance_id,
                    instance_index,
                )
                != expected_order[adaptation_instance_cursor]
            ):
                raise ValueError(
                    "adaptation interaction identity/order differs from corpus"
                )
            observation_metadata = observation.get("metadata")
            if not isinstance(observation_metadata, dict):
                raise ValueError("adaptation observation metadata is missing")
            env_feedback_fields = {
                key for key in observation_metadata if key.startswith("env_feedback_")
            }
            if not instance_complete:
                if env_feedback_fields:
                    raise ValueError(
                        "adaptation nonterminal observation exposes environment reward"
                    )
            else:
                env_reward = observation_metadata.get("env_feedback_reward")
                if (
                    isinstance(env_reward, bool)
                    or not isinstance(env_reward, (int, float))
                    or not math.isfinite(float(env_reward))
                ):
                    raise ValueError(
                        "adaptation terminal observation lacks a finite post-score reward"
                    )
                identity_fields = {
                    "env_feedback_instance_id": instance_id,
                    "env_feedback_instance_index": instance_index,
                }
                present_identity_fields = {
                    key for key in identity_fields if key in observation_metadata
                }
                if present_identity_fields != set(identity_fields) or any(
                    observation_metadata[key] != expected_value
                    for key, expected_value in identity_fields.items()
                ):
                    raise ValueError(
                        "adaptation terminal reward identity differs from query/order"
                    )
        if not instance_complete:
            continue
        instance_id = query.get("instance_id")
        instance_index = query.get("instance_index")
        if (
            not isinstance(instance_id, str)
            or isinstance(instance_index, bool)
            or not isinstance(instance_index, int)
        ):
            raise ValueError(f"{role} terminal interaction identity is invalid")
        identity = (instance_id, instance_index)
        if identity in terminal_by_identity:
            raise ValueError(f"{role} trace has duplicate terminal interactions")
        terminal_by_identity[identity] = interaction
        terminal_order.append(identity)
        if role == "adaptation":
            adaptation_instance_cursor += 1

    if terminal_order != expected_order:
        raise ValueError(f"{role} terminal interaction IDs/order differ from corpus")

    rows: list[dict[str, Any]] = []
    action_hashes: list[dict[str, Any]] = []
    for position, outcome in enumerate(trace_outcomes):
        if not isinstance(outcome, dict):
            raise ValueError(f"{role} trace outcome {position} is malformed")
        instance_id = outcome.get("instance_id")
        instance_index = outcome.get("instance_index")
        identity = (instance_id, instance_index)
        if identity != expected_order[position]:
            raise ValueError(f"{role} trace outcome IDs/order differ from corpus")
        reward = outcome.get("reward")
        if (
            isinstance(reward, bool)
            or not isinstance(reward, (int, float))
            or not math.isfinite(float(reward))
        ):
            raise ValueError(f"{role} trace outcome reward is invalid")
        interaction = terminal_by_identity[identity]
        response = interaction["response"]
        action = response.get("action")
        rescored = _independent_reward(
            action,
            instance_id=instance_id,
            scoring_contract=scoring_contract,
            where=f"{role} terminal action {position}",
        )
        if not math.isclose(float(reward), rescored, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError(f"{role} trace reward differs from independent rescore")
        if role == "adaptation":
            terminal_metadata = interaction["observation"]["metadata"]
            env_reward = float(terminal_metadata["env_feedback_reward"])
            if not math.isclose(env_reward, rescored, rel_tol=0.0, abs_tol=1e-12):
                raise ValueError(
                    "adaptation terminal environment reward differs from independently "
                    "rescored submitted report"
                )
            if not math.isclose(env_reward, float(reward), rel_tol=0.0, abs_tol=1e-12):
                raise ValueError(
                    "adaptation terminal environment reward differs from bound outcome"
                )
        rows.append(
            {
                "instance_id": instance_id,
                "instance_index": instance_index,
                "integrity": _response_integrity(response["metadata"]),
                "reward": float(reward),
            }
        )
        action_hashes.append(
            {
                "action_sha256": canonical_sha256(action),
                "exact_zero_value_count": _exact_zero_value_count(action),
                "instance_id": instance_id,
                "instance_index": instance_index,
            }
        )

    counters = {
        "fallbacks": sum(row["integrity"]["fallback"] for row in rows),
        "hard_schema_failures": sum(
            row["integrity"]["hard_schema_failure"] for row in rows
        ),
        "missing_outcomes": sum(row["integrity"]["missing"] for row in rows),
        "parse_retries": sum(row["integrity"]["parse_retries"] for row in rows),
        "repairs": sum(row["integrity"]["repairs"] for row in rows),
        "synthetic_outcomes": sum(row["integrity"]["synthetic"] for row in rows),
        "timed_out_outcomes": sum(row["integrity"]["timed_out"] for row in rows),
    }
    return rows, counters, action_hashes


def validate_cell(
    *,
    root: Path,
    grid: dict[str, Any],
    cfg: dict[str, Any],
    provenance: dict[str, Any],
    protocol_seal_sha256: str,
    cell: dict[str, Any],
    tokenizer_loader: TokenizerLoader | None = None,
) -> dict[str, Any]:
    expected = int(cfg["expected_num_instances"])
    if cell.get("protocol") != PROTOCOL or cell.get("arm") != ARM:
        raise ValueError("online-ICL cell identity mismatch")
    if (
        cell.get("status") != "completed"
        or cell.get("schema_version") != SCHEMA_VERSION
    ):
        raise ValueError("online-ICL cell is not a completed schema-v1 artifact")
    if cell.get("run_seed") != cfg["run_seed"]:
        raise ValueError("online-ICL cell seed mismatch")
    if cell.get("expected_num_instances") != expected:
        raise ValueError("online-ICL expected instance count mismatch")
    if _canonical_bytes(cell.get("provenance")) != _canonical_bytes(provenance):
        raise ValueError("online-ICL cell provenance mismatch")
    if (
        not _is_sha256(protocol_seal_sha256)
        or cell.get("protocol_seal_sha256") != protocol_seal_sha256
    ):
        raise ValueError("online-ICL cell protocol-seal mismatch")
    if cell.get("system_config") != cfg["system_params"]:
        raise ValueError("online-ICL system config mismatch")
    if cell.get("system_config_sha256") != canonical_sha256(cfg["system_params"]):
        raise ValueError("online-ICL system config digest mismatch")
    for key in (
        "cell_manifest_path",
        "context_inventory_path",
        "restoration_audit_path",
        "snapshot_path",
    ):
        if cell.get(key) != cfg[key]:
            raise ValueError(f"online-ICL registered artifact path mismatch: {key}")
    if cell.get("no_update_audit") != NO_UPDATE_AUDIT:
        raise ValueError("online-ICL no-update audit mismatch")
    model_hashes = cell.get("model_param_sha256")
    if (
        not isinstance(model_hashes, dict)
        or set(model_hashes) != {"initial", "after_adaptation", "final"}
        or any(not _is_sha256(value) for value in model_hashes.values())
        or len(set(model_hashes.values())) != 1
    ):
        raise ValueError("online-ICL runtime model hashes changed")

    adaptation = cell.get("adaptation")
    heldout = cell.get("heldout")
    if not isinstance(adaptation, dict) or not isinstance(heldout, dict):
        raise ValueError("online-ICL phase payload missing")
    for role, phase in (("adaptation", adaptation), ("heldout", heldout)):
        corpus = phase.get("corpus")
        if not isinstance(corpus, dict):
            raise ValueError(f"{role} corpus projection missing")
        registered = grid["datasets"][role]
        if corpus.get("aggregate_sha256") != registered["corpus_sha256"]:
            raise ValueError(f"{role} corpus aggregate hash mismatch")
        _assert_integrity_zero(phase.get("integrity_counters"), where=role)

    adaptation_rows = _assert_outcomes(
        adaptation.get("outcomes"),
        expected=expected,
        expected_ids=adaptation["corpus"]["canonical_instance_ids"],
        where="adaptation outcomes",
    )
    heldout_rows = _assert_outcomes(
        heldout.get("outcomes"),
        expected=expected,
        expected_ids=heldout["corpus"]["canonical_instance_ids"],
        where="heldout outcomes",
    )
    score = statistics.mean(float(row["reward"]) for row in heldout_rows)
    if not math.isclose(float(cell.get("score")), score, rel_tol=0.0, abs_tol=1e-15):
        raise ValueError("online-ICL score does not equal held-out mean")

    trace_by_phase: dict[str, dict[str, Any]] = {}
    trace_file_sha256: dict[str, str] = {}
    for phase_name, phase in (("adaptation", adaptation), ("heldout", heldout)):
        registered_trace = cfg[f"{phase_name}_trace_path"]
        if phase.get("trace_path") != registered_trace:
            raise ValueError(f"{phase_name} trace path differs from grid")
        trace_path = Path(phase["trace_path"])
        if not trace_path.is_absolute():
            trace_path = root / trace_path
        trace, trace_file_sha256[phase_name] = _load_with_file_sha256(trace_path)
        if canonical_sha256(trace) != phase["trace_sha256"]:
            raise ValueError(f"{phase_name} trace digest mismatch")
        trace_by_phase[phase_name] = trace

    adaptation_contract = _scoring_contract(
        root=root,
        grid=grid,
        role="adaptation",
        corpus=adaptation["corpus"],
    )
    heldout_contract = _scoring_contract(
        root=root,
        grid=grid,
        role="heldout",
        corpus=heldout["corpus"],
    )
    bound_adaptation, bound_adaptation_counters, _adaptation_action_hashes = (
        _reconstruct_trace_phase(
            trace=trace_by_phase["adaptation"],
            cfg=cfg,
            role="adaptation",
            expected=expected,
            expected_ids=adaptation["corpus"]["canonical_instance_ids"],
            scoring_contract=adaptation_contract,
        )
    )
    bound_heldout, bound_heldout_counters, bound_heldout_action_hashes = (
        _reconstruct_trace_phase(
            trace=trace_by_phase["heldout"],
            cfg=cfg,
            role="heldout",
            expected=expected,
            expected_ids=heldout["corpus"]["canonical_instance_ids"],
            scoring_contract=heldout_contract,
        )
    )
    if _canonical_bytes(adaptation_rows) != _canonical_bytes(bound_adaptation):
        raise ValueError("adaptation cell outcomes differ from bound trace")
    if _canonical_bytes(heldout_rows) != _canonical_bytes(bound_heldout):
        raise ValueError("heldout cell outcomes differ from bound trace")
    if adaptation.get("integrity_counters") != bound_adaptation_counters:
        raise ValueError("adaptation integrity counters differ from bound trace")
    if heldout.get("integrity_counters") != bound_heldout_counters:
        raise ValueError("heldout integrity counters differ from bound trace")
    compute = cell.get("compute")
    _assert_compute(compute)
    for phase_name in ("adaptation", "heldout"):
        trace_counts = _trace_compute_counts(trace_by_phase[phase_name])
        recorded_counts = compute[phase_name]
        mismatched_counts = [
            key
            for key, value in trace_counts.items()
            if recorded_counts.get(key) != value
        ]
        if mismatched_counts:
            raise ValueError(
                f"{phase_name} compute accounting differs from bound trace: "
                + ", ".join(mismatched_counts)
            )

    snapshot_path = Path(cell["snapshot_path"])
    inventory_path = Path(cell["context_inventory_path"])
    restoration_path = Path(cell["restoration_audit_path"])
    if not snapshot_path.is_absolute():
        snapshot_path = root / snapshot_path
    if not inventory_path.is_absolute():
        inventory_path = root / inventory_path
    if not restoration_path.is_absolute():
        restoration_path = root / restoration_path
    snapshot, snapshot_file_sha256 = _load_with_file_sha256(snapshot_path)
    inventory, context_inventory_file_sha256 = _load_with_file_sha256(inventory_path)
    restoration, restoration_audit_file_sha256 = _load_with_file_sha256(
        restoration_path
    )
    _assert_exact_keys(
        snapshot,
        {
            "artifact_sha256",
            "protocol",
            "run_seed",
            "schema_version",
            "snapshot",
        },
        where="snapshot artifact",
    )
    _assert_exact_keys(
        inventory,
        {
            "artifact_sha256",
            "message_inventory",
            "protocol",
            "run_seed",
            "schema_version",
            "snapshot_sha256",
            "token_inventory",
        },
        where="context inventory artifact",
    )
    _assert_exact_keys(
        restoration,
        {
            "artifact_sha256",
            "initial_snapshot_audit",
            "protocol",
            "restoration_audit",
            "run_seed",
            "schema_version",
            "sensitive_feedback_drops",
            "snapshot_sha256",
        },
        where="restoration artifact",
    )
    for artifact_name, artifact in (
        ("snapshot", snapshot),
        ("context inventory", inventory),
        ("restoration", restoration),
    ):
        if (
            artifact.get("protocol") != PROTOCOL
            or artifact.get("schema_version") != SCHEMA_VERSION
            or artifact.get("run_seed") != cfg["run_seed"]
        ):
            raise ValueError(f"{artifact_name} artifact identity mismatch")
    if _artifact_payload_sha(snapshot) != cell["snapshot_artifact_sha256"]:
        raise ValueError("snapshot artifact binding mismatch")
    if _artifact_payload_sha(inventory) != cell["context_inventory_sha256"]:
        raise ValueError("context inventory binding mismatch")
    if _artifact_payload_sha(restoration) != cell["restoration_audit_sha256"]:
        raise ValueError("restoration artifact binding mismatch")
    snapshot_payload = _assert_exact_keys(
        snapshot.get("snapshot"),
        {
            "protocol",
            "schema_version",
            "snapshot_sha256",
            "state",
            "system_contract",
        },
        where="sealed snapshot",
    )
    if (
        snapshot_payload.get("protocol") != "qwen_local_icl_context_snapshot_v1"
        or snapshot_payload.get("schema_version") != SCHEMA_VERSION
    ):
        raise ValueError("sealed snapshot identity mismatch")
    snapshot_without_digest = {
        key: snapshot_payload[key]
        for key in ("protocol", "schema_version", "state", "system_contract")
    }
    recomputed_snapshot_digest = canonical_sha256(snapshot_without_digest)
    snapshot_digest = cell.get("snapshot_sha256")
    if (
        not _is_sha256(snapshot_digest)
        or snapshot_payload.get("snapshot_sha256") != snapshot_digest
        or recomputed_snapshot_digest != snapshot_digest
        or inventory.get("snapshot_sha256") != snapshot_digest
        or restoration.get("snapshot_sha256") != snapshot_digest
    ):
        raise ValueError("sealed snapshot digest binding mismatch")
    expected_system_contract = _expected_snapshot_system_contract(cfg["system_params"])
    if snapshot_payload.get("system_contract") != expected_system_contract:
        raise ValueError("sealed snapshot system contract differs from grid")

    loader = (
        _load_registered_tokenizer if tokenizer_loader is None else tokenizer_loader
    )
    tokenizer = loader(cfg["system_params"])
    expected_state = _reconstruct_adaptation_snapshot_state(
        trace=trace_by_phase["adaptation"],
        system_params=cfg["system_params"],
        tokenizer=tokenizer,
    )
    _assert_exact_keys(
        snapshot_payload.get("state"),
        {
            "has_truncated_flag",
            "icl_env_reward_injections",
            "interaction_count",
            "messages",
            "truncation_count",
        },
        where="sealed snapshot state",
    )
    if expected_state["icl_env_reward_injections"] != expected:
        raise ValueError(
            "adaptation trace does not contain exactly one terminal reward injection "
            "per registered instance"
        )
    if snapshot_payload["state"] != expected_state:
        raise ValueError(
            "sealed snapshot state differs from adaptation prompt-bearing trajectory"
        )
    messages = expected_state["messages"]
    expected_message_inventory = _message_inventory(messages)
    if inventory.get("message_inventory") != expected_message_inventory:
        raise ValueError("message inventory differs from sealed snapshot messages")
    expected_token_inventory = _token_inventory(
        tokenizer=tokenizer,
        system_prompt=cfg["system_params"]["system_prompt"],
        messages=messages,
        snapshot_sha256=snapshot_digest,
    )
    if inventory.get("token_inventory") != expected_token_inventory:
        raise ValueError(
            "token inventory differs from registered tokenizer and sealed snapshot"
        )

    initial = restoration.get("initial_snapshot_audit")
    restored = restoration.get("restoration_audit")
    if initial != heldout.get("initial_snapshot_audit") or restored != heldout.get(
        "restoration_audit"
    ):
        raise ValueError("restoration audit differs between artifacts")
    if not isinstance(initial, list) or len(initial) != expected:
        raise ValueError("initial snapshot audit cardinality mismatch")
    if not isinstance(restored, list) or len(restored) != expected:
        raise ValueError("restoration audit cardinality mismatch")
    if any(row.get("snapshot_sha256") != snapshot_digest for row in initial):
        raise ValueError("held-out instance did not start from sealed snapshot")
    if any(row.get("restored_snapshot_sha256") != snapshot_digest for row in restored):
        raise ValueError("held-out instance restoration digest mismatch")
    if (
        restoration.get("sensitive_feedback_drops") != expected
        or heldout.get("sensitive_feedback_drops") != expected
    ):
        raise ValueError("sealed held-out feedback-drop count mismatch")
    action_hashes = heldout.get("terminal_action_hashes")
    bound_manifest_action_hashes = [
        {key: value for key, value in row.items() if key != "exact_zero_value_count"}
        for row in bound_heldout_action_hashes
    ]
    if _canonical_bytes(action_hashes) != _canonical_bytes(
        bound_manifest_action_hashes
    ):
        raise ValueError("terminal action hashes differ from bound trace")
    cell_manifest_path = Path(cfg["cell_manifest_path"])
    if not cell_manifest_path.is_absolute():
        cell_manifest_path = root / cell_manifest_path
    registered_cell, cell_manifest_file_sha256 = _load_with_file_sha256(
        cell_manifest_path
    )
    if _canonical_bytes(registered_cell) != _canonical_bytes(cell):
        raise ValueError("validated cell differs from registered manifest bytes")
    return {
        "adaptation_score": statistics.mean(
            float(row["reward"]) for row in adaptation_rows
        ),
        "adaptation_trace_file_sha256": trace_file_sha256["adaptation"],
        "adaptation_trace_sha256": adaptation["trace_sha256"],
        "cell_manifest_file_sha256": cell_manifest_file_sha256,
        "cell_manifest_sha256": canonical_sha256(cell),
        "cfg_id": cfg["cfg_id"],
        "context_inventory_file_sha256": context_inventory_file_sha256,
        "context_inventory_sha256": cell["context_inventory_sha256"],
        "heldout_score": score,
        "heldout_trace_file_sha256": trace_file_sha256["heldout"],
        "heldout_trace_sha256": heldout["trace_sha256"],
        "restoration_audit_file_sha256": restoration_audit_file_sha256,
        "restoration_audit_sha256": cell["restoration_audit_sha256"],
        "run_seed": cfg["run_seed"],
        "snapshot_file_sha256": snapshot_file_sha256,
        "snapshot_artifact_sha256": cell["snapshot_artifact_sha256"],
        "snapshot_sha256": snapshot_digest,
        "terminal_actions": bound_heldout_action_hashes,
        "valid": True,
    }


def _student_t_interval_df2(values: list[float]) -> list[float]:
    if len(values) != 3:
        raise ValueError("internal online-ICL screen requires exactly three deltas")
    mean = statistics.mean(values)
    standard_error = statistics.stdev(values) / math.sqrt(3)
    critical = 4.302652729911275
    return [mean - critical * standard_error, mean + critical * standard_error]


def _sign_test_two_sided(values: list[float]) -> float:
    nonzero = [value for value in values if value != 0.0]
    n = len(nonzero)
    if n == 0:
        return 1.0
    positive = sum(value > 0 for value in nonzero)
    tail = min(positive, n - positive)
    numerator = 2 * sum(math.comb(n, k) for k in range(tail + 1))
    return min(1.0, numerator / (2**n))


def validate_formal_smoke_gate_binding(
    *,
    smoke_gate: dict[str, Any],
    provenance: dict[str, Any],
    protocol_seal_sha256: str,
) -> str:
    _assert_exact_keys(
        smoke_gate,
        set(FORMAL_SMOKE_GATE_FIELDS),
        where="formal online-ICL smoke gate",
    )
    smoke_cell = _assert_exact_keys(
        smoke_gate.get("cell"),
        set(SMOKE_CELL_INTEGRITY_FIELDS),
        where="formal online-ICL smoke gate cell",
    )
    for field in SMOKE_CELL_INTEGRITY_FIELDS - {"cfg_id", "run_seed", "valid"}:
        if not _is_sha256(smoke_cell.get(field)):
            raise ValueError(f"formal smoke gate cell digest is invalid: {field}")
    if not isinstance(smoke_cell.get("cfg_id"), str) or not smoke_cell["cfg_id"]:
        raise ValueError("formal smoke gate cell cfg_id is invalid")
    if (
        isinstance(smoke_cell.get("run_seed"), bool)
        or not isinstance(smoke_cell.get("run_seed"), int)
        or smoke_cell.get("valid") is not True
    ):
        raise ValueError("formal smoke gate cell identity or validity is invalid")
    causal_prerequisite = smoke_gate.get("causal_prerequisite")
    if (
        smoke_gate.get("status") != "pass"
        or smoke_gate.get("decision") != "pass"
        or smoke_gate.get("decision_scope") != "infrastructure_smoke"
        or smoke_gate.get("efficacy_interpretation_allowed") is not False
        or smoke_gate.get("protocol") != PROTOCOL
        or smoke_gate.get("protocol_seal_sha256") != protocol_seal_sha256
        or smoke_gate.get("provenance_sha256") != canonical_sha256(provenance)
        or smoke_gate.get("publication_grade") is not False
        or smoke_gate.get("schema_version") != SCHEMA_VERSION
        or not isinstance(smoke_gate.get("cell"), dict)
    ):
        raise ValueError(
            "formal validation requires the passing smoke gate from this exact seal"
        )
    if (
        not isinstance(causal_prerequisite, dict)
        or set(causal_prerequisite) != CAUSAL_PREREQUISITE_FIELDS
    ):
        raise ValueError("formal smoke gate causal prerequisite schema mismatch")
    for field in (
        "causal_provenance_sha256",
        "causal_smoke_gate_sha256",
        "environment_lock_sha256",
        "model_sha256",
        "tokenizer_sha256",
    ):
        if not _is_sha256(causal_prerequisite.get(field)):
            raise ValueError(
                f"formal smoke gate causal prerequisite digest is invalid: {field}"
            )
    causal_source_commit = causal_prerequisite.get("causal_source_commit")
    if (
        not isinstance(causal_source_commit, str)
        or len(causal_source_commit) != 40
        or any(
            character not in "0123456789abcdef" for character in causal_source_commit
        )
    ):
        raise ValueError("formal smoke gate causal source commit is invalid")
    model_path = causal_prerequisite.get("model_path")
    if not isinstance(model_path, str) or not model_path:
        raise ValueError("formal smoke gate causal model path is invalid")
    for field in (
        "environment_lock_sha256",
        "model_path",
        "model_sha256",
        "tokenizer_sha256",
    ):
        if causal_prerequisite[field] != provenance.get(field):
            raise ValueError(
                f"formal smoke gate causal/online provenance differs: {field}"
            )
    if causal_source_commit != provenance.get("base_causal_commit"):
        raise ValueError("formal smoke gate causal source differs from online base")
    return canonical_sha256(smoke_gate)


def revalidate_registered_formal_smoke_gate(
    *,
    root: Path,
    smoke_gate: dict[str, Any],
    provenance: dict[str, Any],
    protocol_seal: dict[str, Any],
    protocol_seal_sha256: str,
    causal_root: Path,
    causal_smoke_gate: dict[str, Any],
    causal_provenance: dict[str, Any],
) -> str:
    """Recompute the formal prerequisite from its registered raw smoke artifacts."""

    expected_gate_sha256 = validate_formal_smoke_gate_binding(
        smoke_gate=smoke_gate,
        provenance=provenance,
        protocol_seal_sha256=protocol_seal_sha256,
    )
    grids = protocol_seal.get("grids")
    if not isinstance(grids, dict):
        raise ValueError("protocol seal has no registered smoke grid")
    smoke_binding = _assert_exact_keys(
        grids.get("smoke"),
        {"file_sha256", "grid_sha256", "path"},
        where="protocol-seal smoke-grid binding",
    )
    smoke_grid_name = smoke_binding.get("path")
    if not isinstance(smoke_grid_name, str) or not smoke_grid_name:
        raise ValueError("protocol seal has an invalid smoke-grid path")
    root = root.resolve()
    smoke_grid_path = (root / smoke_grid_name).resolve()
    if smoke_grid_path.parent != root:
        raise ValueError("protocol-seal smoke-grid path escapes the registered root")

    # Local imports avoid the results <-> smoke-validator import cycle.
    from run_cohort_online_icl import load_grid
    from validate_cohort_online_icl_smoke import (
        validate_causal_smoke_prerequisite,
        validate_smoke,
    )

    try:
        smoke_grid_bytes = smoke_grid_path.read_bytes()
        smoke_grid = load_grid(smoke_grid_path)
        if (
            hashlib.sha256(smoke_grid_bytes).hexdigest() != smoke_binding["file_sha256"]
            or smoke_grid.get("grid_sha256") != smoke_binding["grid_sha256"]
        ):
            raise ValueError("registered smoke grid differs from protocol seal")
        smoke_cells = smoke_grid.get("cells")
        if (
            smoke_grid.get("kind") != "smoke"
            or not isinstance(smoke_cells, list)
            or len(smoke_cells) != 1
            or not isinstance(smoke_cells[0], dict)
        ):
            raise ValueError("registered online-ICL smoke grid is malformed")
        recomputed_causal_prerequisite = validate_causal_smoke_prerequisite(
            causal_root=causal_root,
            causal_gate=causal_smoke_gate,
            causal_provenance=causal_provenance,
        )
        if _canonical_bytes(recomputed_causal_prerequisite) != _canonical_bytes(
            smoke_gate["causal_prerequisite"]
        ):
            raise ValueError(
                "formal smoke gate causal prerequisite differs from exact "
                "causal raw-artifact revalidation"
            )
        cell_path = Path(smoke_cells[0].get("cell_manifest_path", ""))
        if not cell_path.is_absolute():
            cell_path = root / cell_path
        smoke_cell = _load(cell_path.resolve())
        recomputed_gate = validate_smoke(
            root=root,
            grid=smoke_grid,
            provenance=provenance,
            protocol_seal=protocol_seal,
            cell=smoke_cell,
            causal_prerequisite=recomputed_causal_prerequisite,
        )
    except FileNotFoundError as exc:
        raise ValueError(
            f"registered online-ICL smoke raw artifact is missing: {exc.filename}"
        ) from exc
    if _canonical_bytes(recomputed_gate) != _canonical_bytes(smoke_gate):
        raise ValueError(
            "formal smoke gate differs from exact registered raw-artifact revalidation"
        )
    if canonical_sha256(recomputed_gate) != expected_gate_sha256:
        raise ValueError("formal smoke gate digest changed during exact revalidation")
    return expected_gate_sha256


def _integrity_retry_repair_total(cell: Any, *, where: str) -> dict[str, int]:
    if not isinstance(cell, dict):
        raise ValueError(f"{where} cell must be an object")
    counters = cell.get("integrity_counters")
    if not isinstance(counters, dict):
        raise ValueError(f"{where} integrity counters are missing")
    for field in INTEGRITY_ZERO_FIELDS:
        if counters.get(field) != 0:
            raise ValueError(f"{where} integrity counter {field} must be zero")
    values: dict[str, int] = {}
    for field in ("parse_retries", "repairs"):
        value = counters.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{where} integrity counter {field} is invalid")
        values[field] = value
    values["total"] = values["parse_retries"] + values["repairs"]
    return values


def _score(cell: Any, *, where: str) -> float:
    if not isinstance(cell, dict):
        raise ValueError(f"{where} cell must be an object")
    value = cell.get("score")
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ValueError(f"{where} score is invalid")
    return float(value)


def assemble_internal_screen(
    *,
    causal_manifest: dict[str, Any],
    causal_decision: dict[str, Any],
    online_cells: list[dict[str, Any]],
) -> dict[str, Any]:
    recomputed_causal_decision = evaluate_causal_manifest(causal_manifest)
    if _canonical_bytes(recomputed_causal_decision) != _canonical_bytes(
        causal_decision
    ):
        raise ValueError("causal decision is not the exact evaluation of its manifest")
    if (
        causal_decision.get("status") != "valid"
        or causal_decision.get("decision") != "pass"
        or causal_decision.get("decision_scope") != "internal_gate_pass"
        or causal_decision.get("errors") not in (None, [])
    ):
        raise ValueError("competitive screen requires causal internal gate pass")
    causal_pairs = causal_manifest.get("pairs")
    decision_pairs = causal_decision.get("pairs")
    if not isinstance(causal_pairs, list) or not isinstance(decision_pairs, list):
        raise ValueError("causal formal manifest pairs missing")
    if len(causal_pairs) != 3 or len(decision_pairs) != 3 or len(online_cells) != 3:
        raise ValueError("three-arm internal seed inventory mismatch")
    if any(
        not isinstance(row, dict)
        for row in [*causal_pairs, *decision_pairs, *online_cells]
    ):
        raise ValueError("three-arm screen rows must be objects")

    raw_by_seed = {row.get("run_seed"): row for row in causal_pairs}
    decision_by_seed = {row.get("run_seed"): row for row in decision_pairs}
    icl_by_seed = {row.get("run_seed"): row for row in online_cells}
    seeds = sorted(raw_by_seed)
    if (
        seeds != list(INTERNAL_SCREEN_SEEDS)
        or seeds != sorted(decision_by_seed)
        or seeds != sorted(icl_by_seed)
        or len(raw_by_seed) != 3
        or len(decision_by_seed) != 3
        or len(icl_by_seed) != 3
    ):
        raise ValueError("three-arm internal seed inventory mismatch")

    causal_provenance = causal_manifest.get("provenance")
    if not isinstance(causal_provenance, dict):
        raise ValueError("causal manifest provenance is missing")
    shared_provenance_fields = (
        "environment_lock_sha256",
        "model_path",
        "model_sha256",
        "tokenizer_sha256",
    )
    for seed in seeds:
        online_provenance = icl_by_seed[seed].get("provenance")
        if not isinstance(online_provenance, dict):
            raise ValueError(f"seed {seed} online-ICL provenance is missing")
        mismatched = [
            field
            for field in shared_provenance_fields
            if online_provenance.get(field) != causal_provenance.get(field)
        ]
        if online_provenance.get("base_causal_commit") != causal_provenance.get(
            "source_commit"
        ):
            mismatched.append("base_causal_commit")
        if mismatched:
            raise ValueError(
                f"seed {seed} three-arm shared provenance mismatch: "
                + ", ".join(mismatched)
            )
    online_provenance_values = [icl_by_seed[seed]["provenance"] for seed in seeds]
    if any(
        _canonical_bytes(value) != _canonical_bytes(online_provenance_values[0])
        for value in online_provenance_values[1:]
    ):
        raise ValueError("online-ICL formal cells do not share one provenance seal")

    active_by_seed: dict[int, float] = {}
    lr0_by_seed: dict[int, float] = {}
    online_by_seed: dict[int, float] = {}
    integrity_rows: list[dict[str, Any]] = []
    for seed in seeds:
        raw_pair = raw_by_seed[seed]
        decision_pair = decision_by_seed[seed]
        active = _score(raw_pair.get("active"), where=f"seed {seed} active")
        lr0 = _score(raw_pair.get("lr0"), where=f"seed {seed} LR0")
        online = _score(icl_by_seed[seed], where=f"seed {seed} online ICL")
        for field, expected in (
            ("active_score", active),
            ("lr0_score", lr0),
            ("delta_seed", active - lr0),
        ):
            observed = decision_pair.get(field)
            if (
                isinstance(observed, bool)
                or not isinstance(observed, (int, float))
                or not math.isclose(
                    float(observed), expected, rel_tol=0.0, abs_tol=1e-12
                )
            ):
                raise ValueError(
                    f"seed {seed} causal decision is not bound to raw manifest"
                )
        active_integrity = _integrity_retry_repair_total(
            raw_pair.get("active"), where=f"seed {seed} active"
        )
        lr0_integrity = _integrity_retry_repair_total(
            raw_pair.get("lr0"), where=f"seed {seed} LR0"
        )
        online_integrity = _integrity_retry_repair_total(
            icl_by_seed[seed].get("heldout"), where=f"seed {seed} online ICL"
        )
        integrity_rows.append(
            {
                "active": active_integrity,
                "active_not_worse_than_both_controls": (
                    active_integrity["total"] <= lr0_integrity["total"]
                    and active_integrity["total"] <= online_integrity["total"]
                ),
                "lr0": lr0_integrity,
                "online_icl": online_integrity,
                "run_seed": seed,
            }
        )
        active_by_seed[seed] = active
        lr0_by_seed[seed] = lr0
        online_by_seed[seed] = online

    causal_deltas = [active_by_seed[seed] - lr0_by_seed[seed] for seed in seeds]
    competitive = [active_by_seed[seed] - online_by_seed[seed] for seed in seeds]
    mean_competitive = statistics.mean(competitive)
    checks = {
        "all_competitive_deltas_positive": all(value > 0 for value in competitive),
        "causal_internal_gate_pass": True,
        "mean_competitive_delta_gte_0_02": mean_competitive >= 0.02,
        "no_schema_format_regression": all(
            row["active_not_worse_than_both_controls"] for row in integrity_rows
        ),
    }
    return {
        "causal_decision_sha256": canonical_sha256(causal_decision),
        "causal_deltas": causal_deltas,
        "causal_manifest_sha256": canonical_sha256(causal_manifest),
        "competitive_deltas": competitive,
        "decision": "pass" if all(checks.values()) else "valid_no_go",
        "decision_scope": "internal_screen",
        "effective_n": 3,
        "integrity_comparison": integrity_rows,
        "mean_competitive_delta": mean_competitive,
        "protocol": PROTOCOL,
        "publication_grade": False,
        "sample_standard_deviation": statistics.stdev(competitive),
        "schema_version": SCHEMA_VERSION,
        "seeds": seeds,
        "sign_test_two_sided_p": _sign_test_two_sided(competitive),
        "student_t_95_interval_df2": _student_t_interval_df2(competitive),
        "threshold_checks": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--protocol-seal", type=Path, required=True)
    parser.add_argument("--cell-manifest", type=Path, action="append", required=True)
    parser.add_argument("--causal-manifest", type=Path)
    parser.add_argument("--causal-decision", type=Path)
    parser.add_argument("--causal-root", type=Path)
    parser.add_argument("--causal-smoke-gate", type=Path)
    parser.add_argument("--causal-provenance", type=Path)
    parser.add_argument("--icl-smoke-gate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()

    from run_cohort_online_icl import (
        _atomic_write_json_no_overwrite,
        load_grid,
        load_protocol_seal,
        load_provenance,
        verify_runtime_provenance,
        verify_runtime_protocol_seal,
    )

    root = args.root.resolve()
    grid = load_grid(args.grid.resolve())
    if grid.get("kind") != "formal":
        raise SystemExit(
            "online-ICL results validator accepts only the formal grid; "
            "smoke must use validate_cohort_online_icl_smoke.py"
        )
    provenance = load_provenance(args.provenance.resolve())
    registered_model_paths = {
        row["system_params"]["model_path"] for row in grid["cells"]
    }
    if len(registered_model_paths) != 1:
        raise SystemExit("online-ICL grid must register exactly one model path")
    verify_runtime_provenance(
        root,
        provenance,
        expected_model_path=Path(next(iter(registered_model_paths))),
    )
    protocol_seal = load_protocol_seal(args.protocol_seal.resolve())
    protocol_seal_sha256 = verify_runtime_protocol_seal(
        root,
        protocol_seal=protocol_seal,
        provenance=provenance,
    )
    smoke_gate: dict[str, Any] | None = None
    smoke_gate_sha256: str | None = None
    if grid["kind"] == "formal":
        if any(
            value is None
            for value in (
                args.icl_smoke_gate,
                args.causal_root,
                args.causal_smoke_gate,
                args.causal_provenance,
            )
        ):
            raise SystemExit(
                "formal validation requires --icl-smoke-gate, --causal-root, "
                "--causal-smoke-gate, and --causal-provenance"
            )
        assert (
            args.icl_smoke_gate is not None
            and args.causal_root is not None
            and args.causal_smoke_gate is not None
            and args.causal_provenance is not None
        )
        smoke_gate = _load(args.icl_smoke_gate.resolve())
        from run_cohort_causal import load_provenance as load_causal_provenance

        try:
            smoke_gate_sha256 = revalidate_registered_formal_smoke_gate(
                root=root,
                smoke_gate=smoke_gate,
                provenance=provenance,
                protocol_seal=protocol_seal,
                protocol_seal_sha256=protocol_seal_sha256,
                causal_root=args.causal_root,
                causal_smoke_gate=_load(args.causal_smoke_gate.resolve()),
                causal_provenance=load_causal_provenance(
                    args.causal_provenance.resolve()
                ),
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    cfg_by_id = {row["cfg_id"]: row for row in grid["cells"]}
    validated = []
    raw_cells = []
    for path in args.cell_manifest:
        manifest_path = path.resolve()
        cell = _load(manifest_path)
        matches = [
            cfg for cfg in cfg_by_id.values() if cfg["run_seed"] == cell.get("run_seed")
        ]
        if len(matches) != 1:
            raise SystemExit("cell manifest does not map to exactly one grid row")
        registered_path = Path(matches[0]["cell_manifest_path"])
        if not registered_path.is_absolute():
            registered_path = root / registered_path
        if manifest_path != registered_path.resolve():
            raise SystemExit("cell manifest path differs from registered grid path")
        validated.append(
            validate_cell(
                root=root,
                grid=grid,
                cfg=matches[0],
                provenance=provenance,
                protocol_seal_sha256=protocol_seal_sha256,
                cell=cell,
            )
        )
        raw_cells.append(cell)
    if len(validated) != len(grid["cells"]) or {row["cfg_id"] for row in validated} != {
        row["cfg_id"] for row in grid["cells"]
    }:
        raise SystemExit("cell manifests must cover every grid row exactly once")
    payload: dict[str, Any] = {
        "cells": validated,
        "decision_scope": grid["decision_scope"],
        "grid_sha256": grid["grid_sha256"],
        "protocol": PROTOCOL,
        "protocol_seal_sha256": protocol_seal_sha256,
        "provenance_sha256": canonical_sha256(provenance),
        "schema_version": SCHEMA_VERSION,
        "status": "valid",
    }
    if grid["kind"] == "formal":
        if args.causal_manifest is None or args.causal_decision is None:
            raise SystemExit("formal validation requires causal manifest and decision")
        payload["internal_screen"] = assemble_internal_screen(
            causal_manifest=_load(args.causal_manifest.resolve()),
            causal_decision=_load(args.causal_decision.resolve()),
            online_cells=raw_cells,
        )
        assert (
            args.icl_smoke_gate is not None
            and smoke_gate is not None
            and smoke_gate_sha256 is not None
        )
        payload["icl_smoke_gate_sha256"] = smoke_gate_sha256
    _atomic_write_json_no_overwrite(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
