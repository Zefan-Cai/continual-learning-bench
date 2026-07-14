"""Local Hugging Face Qwen system for official CLBench runs."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import signal
import threading
import time
from typing import Any, Literal
import urllib.error
import urllib.request

from pydantic import BaseModel

from ...interface import ContinualLearningSystem, Observation, Query, Response
from ...registry import register_system
from ...usage import UsageEvent, build_usage_event_from_response
from ..utils.structured_output import (
    extract_json,
    schema_to_prompt_instruction,
    validate_with_coercion,
)

ContextPolicy = Literal[
    "full",
    "tail",
    "tail4k",
    "head_tail",
    "head4k_tail4k",
    "question_only",
]

_THINK_BLOCK_RE = re.compile(r"(?is)<think>.*?</think>")
TTTBatch = list[int] | dict[str, Any]
_REWARD_JUDGE_RETRYABLE_HTTP_CODES = {408, 409, 429, 500, 502, 503, 504}
_REWARD_JUDGE_MAX_ATTEMPTS = 3
_LORA_TARGET_MODULE_PRESETS = {
    "attn_only": ("q_proj", "v_proj"),
    "qv_only": ("q_proj", "v_proj"),
    "ffn_only": ("gate_proj", "up_proj", "down_proj"),
    "locas_glu": ("gate_proj", "up_proj", "down_proj"),
    "qv_ffn": ("q_proj", "v_proj", "gate_proj", "up_proj", "down_proj"),
}
_INSTANCE_GROUP_PG_RULES = {"grpo_instance", "group_pg_instance"}
_INSTANCE_CANDIDATE_DISTILL_RULE = "candidate_distill_instance"
_INSTANCE_GROUP_UPDATE_RULES = {
    *_INSTANCE_GROUP_PG_RULES,
    _INSTANCE_CANDIDATE_DISTILL_RULE,
}
_INSTANCE_GROUP_PG_OBJECTIVE = "group_normalized_policy_gradient"
_INSTANCE_STRUCTURED_PROPOSAL_OBJECTIVE = "group_normalized_candidate_distillation"
_GROUP_PG_CANDIDATE_PROPOSERS = {"policy_sample", "unit_interval_jitter"}
_GROUP_PG_PROPOSAL_JITTER_SCALE = 0.35
_GROUP_PG_LOGIT_CHUNK_TOKENS = 128
_GROUP_PG_LOGIT_STRATEGY = "decoder_hidden_hook+chunked_target_ce"
_FROZEN_TAPE_SCHEMA_VERSION = 1
_FROZEN_TAPE_PROTOCOL = "cohort_qonly_frozen_tape_weight_update_ablation_v1"
_FROZEN_TAPE_MECHANISM_LABEL = (
    "frozen-tape weight-update ablation; not exact historical replication"
)
_FROZEN_TAPE_SAMPLING_RNG_BINDING = (
    "ambient_runner_rng; grpo_run_seed registered but not locally forked"
)
_ICL_CONTEXT_SNAPSHOT_SCHEMA_VERSION = 1
_ICL_CONTEXT_SNAPSHOT_PROTOCOL = "qwen_local_icl_context_snapshot_v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


@register_system("qwen_local")
class QwenLocalSystem(ContinualLearningSystem):
    """Run CLBench systems against a local Qwen-style causal LM."""

    parallel_safe = False
    reuse_across_baseline_instances = True

    def __init__(
        self,
        model_path: str = "/data/zefan/models/Qwen3-4B",
        method: str = "icl",
        context_policy: ContextPolicy = "full",
        adaptation_context_policy: ContextPolicy | None = None,
        max_context_tokens: int = 28672,
        head_tokens: int = 4096,
        tail_tokens: int = 4096,
        max_new_tokens: int = 1536,
        action_max_new_tokens: int = 1024,
        temperature: float = 0.0,
        top_p: float = 1.0,
        parse_retries: int = 2,
        system_prompt: str = "",
        name: str = "qwen_local",
        trust_remote_code: bool = True,
        attn_implementation: str | None = None,
        ttt_lr: float = 2e-5,
        ttt_steps: int = 1,
        ttt_max_tokens: int = 1024,
        ttt_chunk_tokens: int = 512,
        ttt_stride_tokens: int = 256,
        ttt_max_chunks: int = 2,
        ttt_train_every: int = 1,
        lora_rank: int = 8,
        lora_alpha: int = 16,
        lora_dropout: float = 0.0,
        lora_target_modules: str = "q_proj,v_proj",
        lora_param_norm_clip: float = 0.0,
        peft_method: str = "lora",
        num_virtual_tokens: int = 32,
        ttt_rl_source: str = "qttt",
        reward_pg_lr: float | None = None,
        reward_pg_steps: int = 1,
        reward_positive_weight: float = 1.0,
        reward_negative_weight: float = 0.25,
        reward_update_rule: str = "reward_pg",
        reward_advantage_window: int = 8,
        reward_ppo_clip: float = 0.2,
        reward_update_terminal: bool = True,
        reward_judge_provider: str = "heuristic",
        reward_judge_model: str = "gpt-5.4-nano",
        reward_judge_api_key_env: str = "OPENAI_API_KEY",
        reward_judge_base_url: str = "https://api.openai.com/v1",
        reward_judge_timeout_seconds: float = 30.0,
        inject_env_reward: bool | None = None,
        distill_provider: str = "off",
        distill_contrastive: bool = False,
        best_of_n: int = 1,
        bon_temperature: float = 0.8,
        bon_critic: str = "llm",
        bon_env_reward: str = "near",
        history_ttt: bool = True,
        grpo_adv_clip: float = 2.0,
        grpo_std_floor: float = 1e-4,
        grpo_run_seed: int = 0,
        grpo_adapter_init_seed: int | None = None,
        adapter_init_seed: int | None = None,
        grpo_candidate_proposer: str | None = None,
        freeze_parameter_updates: bool = False,
        grpo_frozen_stream: bool = False,
    ):
        method = method.lower().strip()
        if method == "hybrid":
            method = "both"
        supported_methods = {"icl", "chunk", "sft", "both", "qttt", "ttt_rl"}
        if method not in supported_methods:
            raise ValueError(
                f"qwen_local method={method!r} is not implemented. Supported: "
                f"{sorted(supported_methods)}."
            )
        ttt_rl_source = ttt_rl_source.lower().strip()
        if ttt_rl_source == "hybrid":
            ttt_rl_source = "both"
        supported_rl_sources = {"none", "chunk", "sft", "both", "qttt"}
        if ttt_rl_source not in supported_rl_sources:
            raise ValueError(
                f"ttt_rl_source={ttt_rl_source!r} must be one of "
                f"{sorted(supported_rl_sources)}"
            )
        if max_context_tokens <= 0:
            raise ValueError("max_context_tokens must be positive")
        if head_tokens < 0 or tail_tokens <= 0:
            raise ValueError("head_tokens must be >= 0 and tail_tokens must be > 0")
        if parse_retries < 0:
            raise ValueError("parse_retries must be >= 0")
        if action_max_new_tokens <= 0:
            raise ValueError("action_max_new_tokens must be positive")
        if ttt_steps < 0:
            raise ValueError("ttt_steps must be >= 0")
        if ttt_max_tokens <= 0 or ttt_chunk_tokens <= 0 or ttt_stride_tokens <= 0:
            raise ValueError("TTT token limits must be positive")
        if ttt_max_chunks <= 0:
            raise ValueError("ttt_max_chunks must be positive")
        if ttt_train_every <= 0:
            raise ValueError("ttt_train_every must be positive")
        if reward_pg_steps < 0:
            raise ValueError("reward_pg_steps must be >= 0")
        if reward_positive_weight < 0 or reward_negative_weight < 0:
            raise ValueError("reward PG weights must be non-negative")
        reward_update_rule = reward_update_rule.lower().strip()
        supported_reward_update_rules = {
            "reward_pg",
            "grpo",
            "dapo",
            "ppo_clip",
            "grpo_norm",
            "grpo_instance",
            "group_pg_instance",
            "candidate_distill_instance",
        }
        if reward_update_rule not in supported_reward_update_rules:
            raise ValueError(
                f"reward_update_rule={reward_update_rule!r} must be one of "
                f"{sorted(supported_reward_update_rules)}"
            )
        if reward_advantage_window <= 0:
            raise ValueError("reward_advantage_window must be positive")
        if reward_ppo_clip <= 0:
            raise ValueError("reward_ppo_clip must be positive")
        reward_judge_provider = reward_judge_provider.lower().strip()
        supported_distill_providers = {"off", "self", "gpt"}
        distill_provider = distill_provider.lower().strip()
        if distill_provider not in supported_distill_providers:
            raise ValueError(
                f"distill_provider={distill_provider!r} must be one of "
                f"{sorted(supported_distill_providers)}"
            )
        if best_of_n < 1:
            raise ValueError("best_of_n must be >= 1")
        bon_critic = bon_critic.lower().strip()
        if bon_critic not in {"llm", "env"}:
            raise ValueError("bon_critic must be 'llm' or 'env'")
        if reward_update_rule in _INSTANCE_GROUP_UPDATE_RULES and (
            best_of_n < 2 or bon_critic != "env"
        ):
            raise ValueError(
                "instance group reward updates require best_of_n >= 2 and "
                "bon_critic='env' (the post-commit objective scores the "
                "stashed env-BoN candidate group post-hoc at completion)"
            )
        if grpo_adv_clip <= 0:
            raise ValueError("grpo_adv_clip must be positive")
        if grpo_std_floor <= 0:
            raise ValueError("grpo_std_floor must be positive")
        if isinstance(grpo_run_seed, bool) or not isinstance(grpo_run_seed, int):
            raise ValueError("grpo_run_seed must be an integer")
        if grpo_run_seed < 0:
            raise ValueError("grpo_run_seed must be non-negative")
        for seed_name, seed_value in (
            ("grpo_adapter_init_seed", grpo_adapter_init_seed),
            ("adapter_init_seed", adapter_init_seed),
        ):
            if seed_value is not None and (
                isinstance(seed_value, bool) or not isinstance(seed_value, int)
            ):
                raise ValueError(f"{seed_name} must be an integer or null")
            if seed_value is not None and seed_value < 0:
                raise ValueError(f"{seed_name} must be non-negative")
        if (
            grpo_adapter_init_seed is not None
            and adapter_init_seed is not None
            and grpo_adapter_init_seed != adapter_init_seed
        ):
            raise ValueError(
                "adapter_init_seed and legacy grpo_adapter_init_seed must match "
                "when both are supplied"
            )
        adapter_init_seed = (
            grpo_adapter_init_seed if adapter_init_seed is None else adapter_init_seed
        )
        if grpo_candidate_proposer is None:
            grpo_candidate_proposer = "policy_sample"
        elif not isinstance(grpo_candidate_proposer, str):
            raise ValueError("grpo_candidate_proposer must be a string or null")
        else:
            grpo_candidate_proposer = grpo_candidate_proposer.lower().strip()
        if grpo_candidate_proposer not in _GROUP_PG_CANDIDATE_PROPOSERS:
            raise ValueError(
                f"grpo_candidate_proposer={grpo_candidate_proposer!r} must be one of "
                f"{sorted(_GROUP_PG_CANDIDATE_PROPOSERS)}"
            )
        if reward_update_rule in _INSTANCE_GROUP_PG_RULES and (
            grpo_candidate_proposer != "policy_sample"
        ):
            raise ValueError(
                "reward_update_rule='group_pg_instance' (or legacy alias "
                "'grpo_instance') requires grpo_candidate_proposer='policy_sample'"
            )
        if reward_update_rule == _INSTANCE_CANDIDATE_DISTILL_RULE and (
            grpo_candidate_proposer != "unit_interval_jitter"
        ):
            raise ValueError(
                "reward_update_rule='candidate_distill_instance' requires "
                "grpo_candidate_proposer='unit_interval_jitter'"
            )
        if (
            grpo_candidate_proposer != "policy_sample"
            and reward_update_rule != _INSTANCE_CANDIDATE_DISTILL_RULE
        ):
            raise ValueError(
                "grpo_candidate_proposer='unit_interval_jitter' is only supported "
                "by reward_update_rule='candidate_distill_instance'"
            )
        if (
            freeze_parameter_updates or grpo_frozen_stream
        ) and reward_update_rule not in _INSTANCE_GROUP_UPDATE_RULES:
            raise ValueError(
                "freeze_parameter_updates is only supported by "
                "reward_update_rule='group_pg_instance' (or legacy alias "
                "'grpo_instance')"
            )
        supported_reward_judge_providers = {
            "env",
            "heuristic",
            "openai",
            "openrouter",
            "self",
        }
        if reward_judge_provider not in supported_reward_judge_providers:
            raise ValueError(
                f"reward_judge_provider={reward_judge_provider!r} must be one of "
                f"{sorted(supported_reward_judge_providers)}"
            )
        if reward_judge_timeout_seconds <= 0:
            raise ValueError("reward_judge_timeout_seconds must be positive")
        if lora_param_norm_clip < 0:
            raise ValueError("lora_param_norm_clip must be non-negative")
        peft_method = peft_method.lower().strip()
        if peft_method not in {"lora", "prefix"}:
            raise ValueError(
                f"peft_method={peft_method!r} must be one of ['lora', 'prefix']"
            )
        if peft_method == "prefix" and num_virtual_tokens <= 0:
            raise ValueError("num_virtual_tokens must be positive for prefix tuning")
        self.peft_method = peft_method
        self.num_virtual_tokens = num_virtual_tokens

        self._name = name
        self.model_path = model_path
        self.method = method
        self.context_policy = context_policy
        self.adaptation_context_policy = adaptation_context_policy
        self.max_context_tokens = max_context_tokens
        self.head_tokens = head_tokens
        self.tail_tokens = tail_tokens
        self.max_new_tokens = max_new_tokens
        self.action_max_new_tokens = action_max_new_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.parse_retries = parse_retries
        self.system_prompt = system_prompt
        self.trust_remote_code = trust_remote_code
        self.attn_implementation = attn_implementation
        self.ttt_lr = ttt_lr
        self.ttt_steps = ttt_steps
        self.ttt_max_tokens = ttt_max_tokens
        self.ttt_chunk_tokens = ttt_chunk_tokens
        self.ttt_stride_tokens = ttt_stride_tokens
        self.ttt_max_chunks = ttt_max_chunks
        self.ttt_train_every = ttt_train_every
        self.lora_rank = lora_rank
        self.lora_alpha = lora_alpha
        self.lora_dropout = lora_dropout
        self.lora_target_modules = self._resolve_lora_target_modules(
            lora_target_modules
        )
        self.lora_param_norm_clip = lora_param_norm_clip
        # Default: ICL injects the env reward in-context (its only learning path);
        # everything else does not. An explicit True/False overrides — including
        # turning injection OFF for ICL to get a true no-feedback ICL baseline.
        self.inject_env_reward = (
            (method == "icl") if inject_env_reward is None else inject_env_reward
        )
        self.distill_provider = distill_provider
        self.distill_contrastive = distill_contrastive
        self.best_of_n = best_of_n
        self.bon_temperature = bon_temperature
        self.bon_critic = bon_critic
        self.bon_env_reward = (bon_env_reward or "near").lower().strip()
        self.history_ttt = history_ttt
        self.ttt_rl_source = ttt_rl_source
        self.reward_pg_lr = reward_pg_lr if reward_pg_lr is not None else ttt_lr
        self.reward_pg_steps = reward_pg_steps
        self.reward_positive_weight = reward_positive_weight
        self.reward_negative_weight = reward_negative_weight
        self.reward_update_rule = reward_update_rule
        self.reward_advantage_window = reward_advantage_window
        self.reward_ppo_clip = reward_ppo_clip
        self.reward_update_terminal = reward_update_terminal
        self.grpo_adv_clip = grpo_adv_clip
        self.grpo_std_floor = grpo_std_floor
        self.grpo_run_seed = grpo_run_seed
        # ``grpo_adapter_init_seed`` is retained as a config/provenance alias.
        # Adapter initialization is useful outside group-PG too, most importantly
        # for paired reward_pg/prefix frozen-tape ablations.
        self.adapter_init_seed = adapter_init_seed
        self.grpo_adapter_init_seed = adapter_init_seed
        self.grpo_candidate_proposer = grpo_candidate_proposer
        # ``grpo_frozen_stream`` is kept as a compatibility alias for the first
        # local D2 draft.  New configs should use the mechanism-neutral name.
        self.freeze_parameter_updates = bool(
            freeze_parameter_updates or grpo_frozen_stream
        )
        self.grpo_frozen_stream = self.freeze_parameter_updates
        if reward_judge_provider == "openrouter":
            if reward_judge_api_key_env == "OPENAI_API_KEY":
                reward_judge_api_key_env = "OPENROUTER_API_KEY"
            if reward_judge_base_url.rstrip("/") == "https://api.openai.com/v1":
                reward_judge_base_url = "https://openrouter.ai/api/v1"
            if reward_judge_model == "gpt-5.4-nano":
                reward_judge_model = "openai/gpt-5.4-nano"

        self.reward_judge_provider = reward_judge_provider
        self.reward_judge_model = reward_judge_model
        self.reward_judge_api_key_env = reward_judge_api_key_env
        self.reward_judge_base_url = reward_judge_base_url.rstrip("/")
        self.reward_judge_timeout_seconds = reward_judge_timeout_seconds

        self.messages: list[dict[str, str]] = []
        self.interaction_count = 0
        self.truncation_count = 0
        self.has_truncated_flag = False
        self.adaptation_count = 0
        self.last_adaptation_loss: float | None = None
        self.ttt_history_truncation_count = 0
        self.reward_pg_updates = 0
        self.reward_pg_positive_updates = 0
        self.reward_pg_negative_updates = 0
        self.last_feedback_reward: float | None = None
        self.icl_env_reward_injections = 0
        self.last_reward_pg_loss: float | None = None
        self.last_reward_advantage: float | None = None
        self.last_reward_clipped_advantage: float | None = None
        self.last_reward_judge_raw: str | None = None
        self.last_reward_judge_usage: dict[str, Any] | None = None
        self.grpo_updates = 0
        self.grpo_optimizer_steps = 0
        self.grpo_skipped_low_std = 0
        self.grpo_skipped_no_group = 0
        self.last_grpo_loss: float | None = None
        self.last_grpo_group_size: int | None = None
        self.last_grpo_reward_mean: float | None = None
        self.last_grpo_reward_std: float | None = None
        self.last_grpo_committed_reward: float | None = None
        self.grpo_trainable_param_sha256_initial: str | None = None
        self.grpo_trainable_param_sha256_current: str | None = None
        self._grpo_instance_log: list[dict[str, Any]] = []
        self._reward_history: list[float] = []
        self._last_action_training_ids: list[int] | None = None
        self._last_action_prompt_tokens: int | None = None
        self._last_response_integrity: dict[str, Any] | None = None
        self._icl_context_observation_pending = False
        self._icl_context_lifecycle_invalid = False
        # One-way gate used by reward-aware online ICL after adaptation.  Once
        # sealed, held-out harness rewards may never enter the prompt-bearing
        # state, even transiently through Query.feedback or observe().
        self._icl_context_sealed_eval = False
        self._icl_context_sensitive_feedback_drops = 0
        self._tokenizer = None
        self._model = None
        self._lora_enabled = False
        self._frozen_tape_initial_trainable_state: dict[str, Any] | None = None
        self._frozen_tape_initial_hash: str | None = None
        self._frozen_tape_last_digest: str | None = None
        self._frozen_tape_replay_log: list[dict[str, Any]] = []
        self._frozen_tape_heldout_eval = False
        # Make the explicit streaming control frozen even before run_task() calls
        # set_parameter_updates_enabled().  The runner may request updates for a
        # normal rollout later; set_parameter_updates_enabled keeps this hard gate.
        super().set_parameter_updates_enabled(
            not (self._uses_instance_group_pg() and self.freeze_parameter_updates)
        )

    def _resolve_lora_target_modules(self, value: str) -> tuple[str, ...]:
        key = value.lower().strip()
        if key in _LORA_TARGET_MODULE_PRESETS:
            return _LORA_TARGET_MODULE_PRESETS[key]
        return tuple(module.strip() for module in value.split(",") if module.strip())

    @property
    def name(self) -> str:
        return self._name

    def _uses_instance_group_pg(self) -> bool:
        """Whether an opt-in post-commit instance-group update is selected."""
        return self.reward_update_rule in _INSTANCE_GROUP_UPDATE_RULES

    def _grpo_objective_name(self) -> str:
        if self.grpo_candidate_proposer == "policy_sample":
            return _INSTANCE_GROUP_PG_OBJECTIVE
        return _INSTANCE_STRUCTURED_PROPOSAL_OBJECTIVE

    def set_parameter_updates_enabled(self, enabled: bool) -> None:
        """Freeze every update path only for the opt-in instance group-PG rule.

        Existing reward-update rules retain their historical per-instance
        baseline behavior.  D2 additionally exposes
        ``freeze_parameter_updates`` so a normal continual rollout can retain its
        history while never updating.
        """
        if self._frozen_tape_heldout_eval or self._icl_context_sealed_eval:
            enabled = False
        elif self._uses_instance_group_pg():
            enabled = bool(enabled) and not self.freeze_parameter_updates
        else:
            # Preserve historical behavior of all old reward rules.
            enabled = True
        super().set_parameter_updates_enabled(enabled)

    def reset(self) -> None:
        self.messages = []
        self.interaction_count = 0
        self.truncation_count = 0
        self.has_truncated_flag = False
        self.adaptation_count = 0
        self.last_adaptation_loss = None
        self.ttt_history_truncation_count = 0
        self.reward_pg_updates = 0
        self.reward_pg_positive_updates = 0
        self.reward_pg_negative_updates = 0
        self.last_feedback_reward = None
        self.last_reward_pg_loss = None
        self.last_reward_advantage = None
        self.last_reward_clipped_advantage = None
        self.last_reward_judge_raw = None
        self.last_reward_judge_usage = None
        self.grpo_updates = 0
        self.grpo_optimizer_steps = 0
        self.grpo_skipped_low_std = 0
        self.grpo_skipped_no_group = 0
        self.last_grpo_loss = None
        self.last_grpo_group_size = None
        self.last_grpo_reward_mean = None
        self.last_grpo_reward_std = None
        self.last_grpo_committed_reward = None
        self.grpo_trainable_param_sha256_initial = None
        self.grpo_trainable_param_sha256_current = None
        self._grpo_instance_log = []
        self._reward_history = []
        self.distill_updates = 0
        self.bon_updates = 0
        self._pending_env_bon = None
        self._last_action_training_ids = None
        self._last_action_prompt_tokens = None
        self._last_response_integrity = None
        self._icl_context_observation_pending = False
        self._icl_context_lifecycle_invalid = False
        self._icl_context_sensitive_feedback_drops = 0

    # ------------------------------------------------------------------
    # Matched-ICL context isolation
    # ------------------------------------------------------------------

    @staticmethod
    def _icl_context_canonical_bytes(value: Any) -> bytes:
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "ICL context snapshot is not canonical-JSON encodable"
            ) from exc

    @classmethod
    def _icl_context_digest(cls, value: Any) -> str:
        return hashlib.sha256(cls._icl_context_canonical_bytes(value)).hexdigest()

    @staticmethod
    def _icl_context_exact_keys(
        value: Any, expected: set[str], *, where: str
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError(f"{where} must be an object")
        actual = set(value)
        if actual != expected:
            raise ValueError(
                f"{where} schema mismatch: missing={sorted(expected - actual)}, "
                f"extra={sorted(actual - expected)}"
            )
        return value

    def _icl_context_system_contract(self) -> dict[str, Any]:
        return {
            "action_max_new_tokens": self.action_max_new_tokens,
            "adaptation_context_policy": self.adaptation_context_policy,
            "best_of_n": self.best_of_n,
            "bon_critic": self.bon_critic,
            "context_policy": self.context_policy,
            "distill_provider": self.distill_provider,
            "head_tokens": self.head_tokens,
            "inject_env_reward": self.inject_env_reward,
            "sealed_eval": self._icl_context_sealed_eval,
            "max_context_tokens": self.max_context_tokens,
            "max_new_tokens": self.max_new_tokens,
            "method": self.method,
            "model_path": self.model_path,
            "parse_retries": self.parse_retries,
            "system_prompt_chars": len(self.system_prompt),
            "system_prompt_sha256": hashlib.sha256(
                self.system_prompt.encode("utf-8")
            ).hexdigest(),
            "tail_tokens": self.tail_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }

    def _assert_icl_context_snapshot_supported(self) -> None:
        problems = []
        if self.method != "icl":
            problems.append("method must be 'icl'")
        # With best_of_n > 1, qwen_local can train an adapter even when method is
        # named ICL. A context-only restore cannot roll those parameters back.
        if self.best_of_n != 1:
            problems.append("best_of_n must equal 1")
        if self._lora_enabled:
            problems.append("a trainable adapter is already enabled")
        update_counters = {
            "adaptation_count": self.adaptation_count,
            "bon_updates": getattr(self, "bon_updates", 0),
            "distill_updates": getattr(self, "distill_updates", 0),
            "grpo_optimizer_steps": self.grpo_optimizer_steps,
            "grpo_updates": self.grpo_updates,
            "reward_pg_updates": self.reward_pg_updates,
        }
        nonzero_updates = {
            key: value for key, value in update_counters.items() if value != 0
        }
        if nonzero_updates:
            problems.append(f"parameter-update counters are nonzero: {nonzero_updates}")
        if self._reward_history:
            problems.append("reward-update history is non-empty")
        if problems:
            raise RuntimeError(
                "ICL context snapshot contract violation: " + "; ".join(problems)
            )

    def _assert_icl_context_quiescent(self, *, where: str) -> None:
        pending = []
        if self._icl_context_observation_pending:
            pending.append("observation")
        if self._icl_context_lifecycle_invalid:
            pending.append("invalid response/observation lifecycle")
        if getattr(self, "_pending_env_bon", None) is not None:
            pending.append("env-BoN update")
        if self._last_action_training_ids is not None:
            pending.append("action training ids")
        if self._last_action_prompt_tokens is not None:
            pending.append("action prompt boundary")
        if self._last_response_integrity is not None:
            pending.append("response integrity record")
        if pending:
            raise RuntimeError(
                f"ICL context {where} is not quiescent; pending=" + ", ".join(pending)
            )

    def seal_icl_context_for_evaluation(self) -> None:
        """Irreversibly disable held-out reward ingestion for this ICL system.

        Reward-aware ICL uses environment rewards during the adaptation
        rollout.  The terminal adaptation context is then sealed and cloned for
        held-out conditions.  The gate intentionally survives ``reset()`` so a
        later runner call cannot accidentally re-enable reward leakage.
        """
        self._assert_icl_context_snapshot_supported()
        self._assert_icl_context_quiescent(where="seal source")
        self._icl_context_sealed_eval = True
        super().set_parameter_updates_enabled(False)

    def _icl_context_state_payload(self) -> dict[str, Any]:
        return {
            "has_truncated_flag": self.has_truncated_flag,
            "icl_env_reward_injections": self.icl_env_reward_injections,
            "interaction_count": self.interaction_count,
            "messages": [dict(message) for message in self.messages],
            "truncation_count": self.truncation_count,
        }

    def _icl_context_snapshot_payload(self) -> dict[str, Any]:
        return {
            "protocol": _ICL_CONTEXT_SNAPSHOT_PROTOCOL,
            "schema_version": _ICL_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
            "state": self._icl_context_state_payload(),
            "system_contract": self._icl_context_system_contract(),
        }

    @staticmethod
    def _icl_context_nonnegative_int(value: Any, *, where: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{where} must be a non-negative integer")
        return value

    def _validate_icl_context_state(self, state: Any) -> dict[str, Any]:
        state = self._icl_context_exact_keys(
            state,
            {
                "has_truncated_flag",
                "icl_env_reward_injections",
                "interaction_count",
                "messages",
                "truncation_count",
            },
            where="ICL context snapshot state",
        )
        messages = state["messages"]
        if not isinstance(messages, list):
            raise ValueError("ICL context snapshot messages must be a list")
        normalized_messages: list[dict[str, str]] = []
        for index, message in enumerate(messages):
            message = self._icl_context_exact_keys(
                message,
                {"content", "role"},
                where=f"ICL context snapshot messages[{index}]",
            )
            role = message["role"]
            content = message["content"]
            if role not in {"assistant", "user"}:
                raise ValueError(
                    f"ICL context snapshot messages[{index}].role is invalid"
                )
            if not isinstance(content, str):
                raise ValueError(
                    f"ICL context snapshot messages[{index}].content must be a string"
                )
            normalized_messages.append({"role": role, "content": content})
        if not isinstance(state["has_truncated_flag"], bool):
            raise ValueError("ICL context has_truncated_flag must be boolean")
        normalized = {
            "has_truncated_flag": state["has_truncated_flag"],
            "icl_env_reward_injections": self._icl_context_nonnegative_int(
                state["icl_env_reward_injections"],
                where="ICL context icl_env_reward_injections",
            ),
            "interaction_count": self._icl_context_nonnegative_int(
                state["interaction_count"],
                where="ICL context interaction_count",
            ),
            "messages": normalized_messages,
            "truncation_count": self._icl_context_nonnegative_int(
                state["truncation_count"],
                where="ICL context truncation_count",
            ),
        }
        assistant_count = sum(
            message["role"] == "assistant" for message in normalized_messages
        )
        if assistant_count > normalized["interaction_count"]:
            raise ValueError(
                "ICL context has more assistant messages than interactions"
            )
        return normalized

    def _validate_icl_context_snapshot(
        self, snapshot: Any
    ) -> tuple[dict[str, Any], str]:
        snapshot = self._icl_context_exact_keys(
            snapshot,
            {
                "protocol",
                "schema_version",
                "snapshot_sha256",
                "state",
                "system_contract",
            },
            where="ICL context snapshot",
        )
        snapshot_sha256 = snapshot["snapshot_sha256"]
        if (
            not isinstance(snapshot_sha256, str)
            or _SHA256_RE.fullmatch(snapshot_sha256) is None
        ):
            raise ValueError("ICL context snapshot SHA256 is malformed")
        payload = {
            key: snapshot[key]
            for key in ("protocol", "schema_version", "state", "system_contract")
        }
        if self._icl_context_digest(payload) != snapshot_sha256:
            raise ValueError("ICL context snapshot SHA256 mismatch")
        if snapshot["protocol"] != _ICL_CONTEXT_SNAPSHOT_PROTOCOL:
            raise ValueError("ICL context snapshot protocol mismatch")
        if snapshot["schema_version"] != _ICL_CONTEXT_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("ICL context snapshot schema_version mismatch")
        if self._icl_context_canonical_bytes(snapshot["system_contract"]) != (
            self._icl_context_canonical_bytes(self._icl_context_system_contract())
        ):
            raise ValueError("ICL context snapshot system contract mismatch")
        return self._validate_icl_context_state(snapshot["state"]), snapshot_sha256

    def snapshot_icl_context(self) -> dict[str, Any]:
        """Freeze a canonical, integrity-bound pure-ICL prompt state.

        The snapshot intentionally excludes model/tokenizer caches, usage events,
        and unfinished response/update state. It is safe to reuse before every
        matched held-out instance because restore rejects any non-quiescent
        boundary and clears all per-action transients.
        """
        self._assert_icl_context_snapshot_supported()
        self._assert_icl_context_quiescent(where="snapshot source")
        payload = self._icl_context_snapshot_payload()
        snapshot = {
            **payload,
            "snapshot_sha256": self._icl_context_digest(payload),
        }
        # JSON round-trip returns a detached tree and proves serializability.
        return json.loads(self._icl_context_canonical_bytes(snapshot))

    def tokenize_icl_context_snapshot(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        """Render and tokenize a validated snapshot without mutating live state."""
        state, snapshot_sha256 = self._validate_icl_context_snapshot(snapshot)
        rendered = self._render_messages([*self._system_messages(), *state["messages"]])
        token_ids = self._load_tokenizer().encode(rendered, add_special_tokens=False)
        inventory = {
            "rendered_prompt_sha256": hashlib.sha256(
                rendered.encode("utf-8")
            ).hexdigest(),
            "snapshot_sha256": snapshot_sha256,
            "token_count": len(token_ids),
            "token_ids": list(token_ids),
        }
        inventory["token_ids_sha256"] = self._icl_context_digest(token_ids)
        return inventory

    def _apply_icl_context_state(self, state: dict[str, Any]) -> None:
        self.messages = [dict(message) for message in state["messages"]]
        self.interaction_count = state["interaction_count"]
        self.truncation_count = state["truncation_count"]
        self.has_truncated_flag = state["has_truncated_flag"]
        self.icl_env_reward_injections = state["icl_env_reward_injections"]
        self._pending_env_bon = None
        self._last_action_training_ids = None
        self._last_action_prompt_tokens = None
        self._last_response_integrity = None
        self._icl_context_observation_pending = False
        self._icl_context_lifecycle_invalid = False

    def restore_icl_context(self, snapshot: dict[str, Any]) -> None:
        """Restore one frozen ICL context transactionally and verify it again."""
        self._assert_icl_context_snapshot_supported()
        self._assert_icl_context_quiescent(where="restore target")
        state, expected_sha256 = self._validate_icl_context_snapshot(snapshot)
        previous_state = self._icl_context_state_payload()
        try:
            self._apply_icl_context_state(state)
            restored_payload = self._icl_context_snapshot_payload()
            if self._icl_context_digest(restored_payload) != expected_sha256:
                raise RuntimeError(
                    "ICL context restore post-restore integrity verification failed"
                )
        except Exception:
            self._apply_icl_context_state(previous_state)
            raise

    def respond(self, query: Query) -> Response:
        if self.method == "icl":
            if self._icl_context_observation_pending:
                self._icl_context_lifecycle_invalid = True
            self._icl_context_observation_pending = True
        self.interaction_count += 1
        query_content = self._query_content(query)
        if self._uses_instance_group_pg():
            # A failed response must not leave the previous step's recipe armed
            # for a later terminal observation.
            self._pending_env_bon = None
        self.messages.append({"role": "user", "content": query_content})
        if self.parameter_updates_enabled:
            self._adapt_before_response(query_content)

        base_messages = self._select_messages()
        prompt_messages = self._with_schema_instruction(
            base_messages, query.response_schema
        )
        rendered_prompt = self._render_messages(prompt_messages)
        windowed_prompt = self._window_prompt(rendered_prompt)

        raw_text = ""
        sampled_continuation = ""
        parsed_action: BaseModel | None = None
        parse_errors: list[str] = []
        attempt_debugs: list[dict[str, Any]] = []
        parse_repair_used = False
        prompt_for_attempt = windowed_prompt
        input_tokens = self._count_tokens(prompt_for_attempt)
        output_tokens = 0
        generation_max_new_tokens = self._max_new_tokens_for_schema(
            query.response_schema
        )
        generation_prefix = self._generation_prefix_for_schema(query.response_schema)
        start = time.perf_counter()

        for attempt in range(self.parse_retries + 1):
            generated_continuation, generation_debug = self._generate_text(
                prompt_for_attempt + generation_prefix,
                max_new_tokens=generation_max_new_tokens,
            )
            raw_text = self._merge_generation_prefix(
                generation_prefix, generated_continuation
            )
            attempt_debugs.append({"attempt": attempt, **generation_debug})
            input_tokens = int(generation_debug.get("prompt_tokens", input_tokens))
            output_tokens = self._count_tokens(raw_text)
            cleaned_text = self._strip_think(raw_text).strip()
            try:
                parsed_action, repaired = self._parse_action(
                    cleaned_text, query.response_schema
                )
                parsed_action, action_normalized = self._normalize_zero_cost_poker_call(
                    parsed_action, query
                )
                parse_repair_used = parse_repair_used or repaired
                parse_repair_used = parse_repair_used or action_normalized
                # Preserve the exact tokens sampled after the generation prefix.
                # ``assistant_record`` below is a normalized Pydantic rendering and
                # is suitable for scoring, but it is not necessarily the policy
                # continuation that produced the action.
                sampled_continuation = generated_continuation
                break
            except Exception as exc:
                parse_errors.append(f"{type(exc).__name__}: {exc}")
                if attempt >= self.parse_retries:
                    raise RuntimeError(
                        "Local Qwen response did not parse as the required JSON; "
                        f"raw output prefix={raw_text[:500]!r}; "
                        f"errors={parse_errors}; "
                        f"generation_debug={json.dumps(attempt_debugs, ensure_ascii=True)[:3000]}"
                    ) from exc
                retry_messages = [*prompt_messages]
                failed_response_message = self._failed_response_retry_message(
                    raw_text, query.response_schema
                )
                if failed_response_message is not None:
                    retry_messages.append(failed_response_message)
                retry_messages.append(
                    {
                        "role": "user",
                        "content": self._retry_instruction(query.response_schema),
                    }
                )
                prompt_for_attempt = self._window_prompt(
                    self._render_messages(retry_messages)
                )

        assert parsed_action is not None
        final_generation_debug = attempt_debugs[-1]
        generation_calls = len(attempt_debugs)
        generation_input_tokens_total = sum(
            int(debug.get("prompt_tokens", 0)) for debug in attempt_debugs
        )
        generation_output_tokens_total = sum(
            int(debug.get("new_token_count", 0)) for debug in attempt_debugs
        )
        generation_prompt_hard_truncations = sum(
            bool(debug.get("prompt_hard_truncated", False)) for debug in attempt_debugs
        )
        assistant_record = parsed_action.model_dump_json()
        self._remember_last_action_training_example(
            prompt_for_attempt, assistant_record
        )
        self._last_response_integrity = {
            "schema_valid": True,
            "synthetic": False,
            "timed_out": False,
            "fallback": False,
            "missing": False,
            "hard_schema_failure": False,
            "parse_retries": len(parse_errors),
            "repairs": int(parse_repair_used),
        }
        self.messages.append({"role": "assistant", "content": assistant_record})

        # Best-of-N + judge: sample N candidates for THIS query, score each with a
        # critic, and SFT the adapter toward the best (the relative-comparison
        # learning signal a single sample cannot provide). distill_provider picks
        # the critic backend (self|gpt).
        if (
            self.parameter_updates_enabled
            and self.best_of_n > 1
            and self.bon_critic == "llm"
            and self.distill_provider != "off"
        ):
            # LLM critic scores quality (no ground truth) -> train immediately.
            self._best_of_n_update(
                prompt_for_attempt,
                generation_prefix,
                assistant_record,
                query_content,
                query.response_schema,
                generation_max_new_tokens,
            )
        elif (
            self.parameter_updates_enabled
            and self.best_of_n > 1
            and self.bon_critic == "env"
        ):
            # Env (near-year) reward is only revealed AFTER the instance is graded.
            # Sample+store candidates now; score+train post-commit in observe().
            self._stash_env_bon_candidates(
                prompt_for_attempt,
                generation_prefix,
                assistant_record,
                query_content,
                query.response_schema,
                generation_max_new_tokens,
                primary_continuation=sampled_continuation,
                instance_index=query.instance_index,
                instance_id=query.instance_id,
                interaction_step=self.interaction_count,
            )

        elapsed = time.perf_counter() - start
        self.record_usage_event(
            UsageEvent(
                call_type="local_generation",
                model=self.model_path,
                provider="local_hf",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                metadata={
                    "elapsed_seconds": round(elapsed, 6),
                    "method": self.method,
                    "context_policy": self.context_policy,
                    "adaptation_context_policy": self.adaptation_context_policy,
                    "adaptation_count": self.adaptation_count,
                    "last_adaptation_loss": self.last_adaptation_loss,
                    "ttt_history_truncation_count": self.ttt_history_truncation_count,
                    "ttt_rl_source": self.ttt_rl_source,
                    "reward_update_rule": self.reward_update_rule,
                    "lora_param_norm_clip": self.lora_param_norm_clip,
                    "reward_update_terminal": self.reward_update_terminal,
                    "reward_ppo_clip": self.reward_ppo_clip,
                    "reward_judge_provider": self.reward_judge_provider,
                    "reward_judge_model": self.reward_judge_model,
                    "reward_feedback_source": self.reward_judge_provider,
                    "reward_pg_updates": self.reward_pg_updates,
                    "reward_pg_positive_updates": self.reward_pg_positive_updates,
                    "reward_pg_negative_updates": self.reward_pg_negative_updates,
                    "last_feedback_reward": self.last_feedback_reward,
                    "last_reward_pg_loss": self.last_reward_pg_loss,
                    "last_reward_advantage": self.last_reward_advantage,
                    "last_reward_clipped_advantage": self.last_reward_clipped_advantage,
                    "last_reward_judge_usage": self.last_reward_judge_usage,
                    **self._grpo_usage_metadata(),
                },
            )
        )

        return Response(
            action=parsed_action,
            metadata={
                "system_type": "qwen_local",
                "model_path": self.model_path,
                "method": self.method,
                "context_policy": self.context_policy,
                "adaptation_context_policy": self.adaptation_context_policy,
                "interaction_count": self.interaction_count,
                "prompt_tokens": input_tokens,
                "prompt_tokens_before_hard_cap": final_generation_debug.get(
                    "prompt_tokens_before_hard_cap", input_tokens
                ),
                "prompt_token_budget": final_generation_debug.get(
                    "prompt_token_budget"
                ),
                "prompt_hard_truncated": bool(
                    final_generation_debug.get("prompt_hard_truncated", False)
                ),
                "generation_calls": generation_calls,
                "generation_input_tokens_total": generation_input_tokens_total,
                "generation_output_tokens_total": generation_output_tokens_total,
                "generation_prompt_hard_truncations": (
                    generation_prompt_hard_truncations
                ),
                "output_tokens": output_tokens,
                "generation_max_new_tokens": generation_max_new_tokens,
                "parse_retries_used": len(parse_errors),
                "parse_repair_used": parse_repair_used,
                "icl_context_sealed_eval": self._icl_context_sealed_eval,
                "has_truncated": self.has_truncated_flag,
                "truncation_count": self.truncation_count,
                "adaptation_count": self.adaptation_count,
                "last_adaptation_loss": self.last_adaptation_loss,
                "ttt_history_truncation_count": self.ttt_history_truncation_count,
                "ttt_rl_source": self.ttt_rl_source,
                "reward_update_rule": self.reward_update_rule,
                "lora_param_norm_clip": self.lora_param_norm_clip,
                "reward_update_terminal": self.reward_update_terminal,
                "reward_ppo_clip": self.reward_ppo_clip,
                "reward_judge_provider": self.reward_judge_provider,
                "reward_judge_model": self.reward_judge_model,
                "reward_feedback_source": self.reward_judge_provider,
                "reward_pg_updates": self.reward_pg_updates,
                "reward_pg_positive_updates": self.reward_pg_positive_updates,
                "reward_pg_negative_updates": self.reward_pg_negative_updates,
                "last_feedback_reward": self.last_feedback_reward,
                "last_reward_pg_loss": self.last_reward_pg_loss,
                "last_reward_advantage": self.last_reward_advantage,
                "last_reward_clipped_advantage": self.last_reward_clipped_advantage,
                "last_reward_judge_usage": self.last_reward_judge_usage,
                **self._grpo_usage_metadata(),
            },
        )

    def _grpo_usage_metadata(self) -> dict[str, Any]:
        # Only emitted for the opt-in instance group-PG rules so that requeued
        # old-grid cells keep byte-identical usage/metadata output.
        if not self._uses_instance_group_pg():
            return {}
        metadata = {
            "parameter_updates_enabled": self.parameter_updates_enabled,
            "freeze_parameter_updates": self.freeze_parameter_updates,
            "grpo_frozen_stream": self.grpo_frozen_stream,
            "grpo_objective": self._grpo_objective_name(),
            "grpo_candidate_proposer": self.grpo_candidate_proposer,
            "grpo_run_seed": self.grpo_run_seed,
            "grpo_updates": self.grpo_updates,
            "grpo_optimizer_steps": self.grpo_optimizer_steps,
            "grpo_skipped_low_std": self.grpo_skipped_low_std,
            "grpo_skipped_no_group": self.grpo_skipped_no_group,
            "last_grpo_loss": self.last_grpo_loss,
            "last_grpo_group_size": self.last_grpo_group_size,
            "last_grpo_reward_mean": self.last_grpo_reward_mean,
            "last_grpo_reward_std": self.last_grpo_reward_std,
            "last_grpo_committed_reward": self.last_grpo_committed_reward,
            "grpo_trainable_param_sha256_initial": (
                self.grpo_trainable_param_sha256_initial
            ),
            "grpo_trainable_param_sha256_current": (
                self.grpo_trainable_param_sha256_current
            ),
        }
        if self.grpo_adapter_init_seed is not None:
            metadata["grpo_adapter_init_seed"] = self.grpo_adapter_init_seed
        return metadata

    def observe(
        self, observation: Observation, next_query: Query | None = None
    ) -> None:
        icl_action_committed = True
        if self.method == "icl":
            integrity = self._last_response_integrity
            icl_action_committed = (
                self._icl_context_observation_pending
                and self._last_action_training_ids is not None
                and self._last_action_prompt_tokens is not None
                and isinstance(integrity, dict)
                and integrity.get("schema_valid") is True
                and integrity.get("hard_schema_failure") is False
            )
        content = observation.content.strip()
        meta = observation.metadata or {}
        env_reward = meta.get("env_feedback_reward")
        has_env_reward = isinstance(env_reward, (int, float)) and not isinstance(
            env_reward, bool
        )
        # The reward_pg policy gradient must fire whenever a usable reward exists,
        # not only when there is textual feedback. Env-reward tasks (sales/cohort/
        # db/poker) deliver the reward via observation.metadata with EMPTY content,
        # so gating the update on `content` alone silently disabled the RL half of
        # TTT-RL on exactly those tasks. A non-env reward judge (self/openai/
        # openrouter/heuristic) scores each action, so it should fire on every step
        # that followed an action to give a dense reward.
        judge_dense = (
            self.method == "ttt_rl"
            and self.reward_judge_provider != "env"
            and self._last_action_training_ids is not None
        )
        # D2 defers counterfactual candidate generation until it knows this was
        # the terminal action. Materialize from the prompt saved pre-commit,
        # before any reward update, distillation, or feedback is made visible.
        if (
            self.parameter_updates_enabled
            and self._uses_instance_group_pg()
            and observation.instance_complete
        ):
            if self._pending_env_bon is None:
                self.grpo_skipped_no_group += 1
                self._append_grpo_log(
                    {
                        "group_size": 0,
                        "skipped": "no_pending",
                        "objective": self._grpo_objective_name(),
                    }
                )
            else:
                self._materialize_pending_env_bon_candidates()
        if self.parameter_updates_enabled and (
            content or has_env_reward or judge_dense
        ):
            self._adapt_from_feedback(observation)
        # TextGrad-style critique->SFT distillation: at instance completion, ask a
        # critic for an improved answer and SFT the adapter toward it. Fires only at
        # instance boundaries to bound cost (one critic call per instance).
        if (
            self.parameter_updates_enabled
            and self.distill_provider != "off"
            and self.method == "ttt_rl"
            and observation.instance_complete
        ):
            self._distill_from_critic(observation)
        # Env best-of-N: now the near-year reward is revealed, score the stashed
        # candidates and SFT toward the best (post-commit -> no leakage).
        if (
            self.parameter_updates_enabled
            and self.best_of_n > 1
            and self.bon_critic == "env"
            and observation.instance_complete
            and self._pending_env_bon is not None
        ):
            self._env_best_of_n_train(observation)
        parts: list[str] = []
        sealed_terminal = (
            self._icl_context_sealed_eval and observation.instance_complete
        )
        if sealed_terminal:
            self._icl_context_sensitive_feedback_drops += 1
        if content and not sealed_terminal:
            parts.append(f"FEEDBACK: {content}")
        # ICL has no parameter-update path, so it can only consume the harness
        # reward in-context. Surface env_feedback_reward (present in observation
        # metadata even when content is empty, e.g. sales/forecasting tasks) so
        # ICL learns across instances; LoRA/prefix use reward_pg by default.
        # When inject_env_reward is set, TTT-RL also surfaces the reward in-context
        # (in addition to its reward_pg gradient) so it becomes a strict superset
        # of ICL: same in-context reward signal plus a parameter update.
        if self.inject_env_reward and not self._icl_context_sealed_eval:
            meta = observation.metadata or {}
            reward = meta.get("env_feedback_reward")
            if isinstance(reward, (int, float)) and not isinstance(reward, bool):
                parts.append(
                    "ENV_REWARD (score of your previous answer, higher is better): "
                    f"{float(reward):.4f}"
                )
                self.icl_env_reward_injections += 1
        if parts:
            self.messages.append({"role": "user", "content": "\n".join(parts)})
        if self.method == "icl":
            if not icl_action_committed:
                self._icl_context_lifecycle_invalid = True
            self._last_action_training_ids = None
            self._last_action_prompt_tokens = None
            self._last_response_integrity = None
            self._icl_context_observation_pending = False

    def get_run_artifacts(self) -> dict[str, Any]:
        artifacts = {
            "artifact_type": "qwen_local",
            "method": self.method,
            "icl_env_reward_injections": self.icl_env_reward_injections,
            "inject_env_reward": self.inject_env_reward,
            "icl_context_sealed_eval": self._icl_context_sealed_eval,
            "icl_context_sensitive_feedback_drops": (
                self._icl_context_sensitive_feedback_drops
            ),
            "distill_provider": self.distill_provider,
            "distill_contrastive": self.distill_contrastive,
            "distill_updates": getattr(self, "distill_updates", 0),
            "best_of_n": self.best_of_n,
            "bon_critic": self.bon_critic,
            "bon_updates": getattr(self, "bon_updates", 0),
            "context_policy": self.context_policy,
            "adaptation_context_policy": self.adaptation_context_policy,
            "model_path": self.model_path,
            "messages": list(self.messages),
            "interaction_count": self.interaction_count,
            "has_truncated": self.has_truncated_flag,
            "truncation_count": self.truncation_count,
            "adaptation_count": self.adaptation_count,
            "last_adaptation_loss": self.last_adaptation_loss,
            "ttt_history_truncation_count": self.ttt_history_truncation_count,
            "ttt_rl_source": self.ttt_rl_source,
            "reward_update_rule": self.reward_update_rule,
            "lora_param_norm_clip": self.lora_param_norm_clip,
            "reward_update_terminal": self.reward_update_terminal,
            "reward_ppo_clip": self.reward_ppo_clip,
            "reward_judge_provider": self.reward_judge_provider,
            "reward_judge_model": self.reward_judge_model,
            "reward_feedback_source": self.reward_judge_provider,
            "reward_pg_updates": self.reward_pg_updates,
            "reward_pg_positive_updates": self.reward_pg_positive_updates,
            "reward_pg_negative_updates": self.reward_pg_negative_updates,
            "last_feedback_reward": self.last_feedback_reward,
            "last_reward_pg_loss": self.last_reward_pg_loss,
            "last_reward_advantage": self.last_reward_advantage,
            "last_reward_clipped_advantage": self.last_reward_clipped_advantage,
            "last_reward_judge_raw": self.last_reward_judge_raw,
            "last_reward_judge_usage": self.last_reward_judge_usage,
        }
        # Instance group-PG is opt-in: keep old-rule artifacts byte-identical.
        if self._uses_instance_group_pg():
            artifacts.update(self._grpo_usage_metadata())
            artifacts["grpo_adv_clip"] = self.grpo_adv_clip
            artifacts["grpo_std_floor"] = self.grpo_std_floor
            artifacts["grpo_candidate_proposer"] = self.grpo_candidate_proposer
            artifacts["grpo_instance_log"] = list(self._grpo_instance_log)
        if self._frozen_tape_last_digest is not None:
            artifacts["frozen_tape_weight_update_ablation"] = {
                "protocol": _FROZEN_TAPE_PROTOCOL,
                "mechanism_label": _FROZEN_TAPE_MECHANISM_LABEL,
                "tape_sha256": self._frozen_tape_last_digest,
                "adapter_init_seed": self.adapter_init_seed,
                "initial_trainable_param_sha256": self._frozen_tape_initial_hash,
                "final_trainable_param_sha256": (
                    self._frozen_tape_replay_log[-1]["trainable_param_sha256_final"]
                    if self._frozen_tape_replay_log
                    else None
                ),
                "heldout_updates_frozen": self._frozen_tape_heldout_eval,
                "replays": list(self._frozen_tape_replay_log),
            }
        return artifacts

    # ------------------------------------------------------------------
    # Cohort qonly frozen-tape weight-update ablation
    # ------------------------------------------------------------------
    # This API deliberately replays the *updates* produced by the historical
    # reward_pg + env-BoN path against a shared immutable tape.  It is not an
    # exact historical rollout replication: proposals during held-out evaluation
    # are generated after replay, while the adaptation examples are frozen.

    @staticmethod
    def _frozen_tape_canonical_bytes(value: Any) -> bytes:
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Frozen update tape is not canonical-JSON encodable"
            ) from exc

    @classmethod
    def _frozen_tape_digest(cls, value: Any) -> str:
        return hashlib.sha256(cls._frozen_tape_canonical_bytes(value)).hexdigest()

    @staticmethod
    def _frozen_tape_exact_keys(
        value: Any, expected: set[str], *, where: str
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError(f"{where} must be an object")
        actual = set(value)
        if actual != expected:
            raise ValueError(
                f"{where} schema mismatch: missing={sorted(expected - actual)} "
                f"extra={sorted(actual - expected)}"
            )
        return value

    @staticmethod
    def _frozen_tape_finite_number(value: Any, *, where: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{where} must be a finite number")
        result = float(value)
        if not math.isfinite(result):
            raise ValueError(f"{where} must be a finite number")
        return result

    @staticmethod
    def _frozen_tape_parse_json(payload: bytes | str) -> Any:
        if isinstance(payload, bytes):
            try:
                payload = payload.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ValueError("Frozen update tape must be strict UTF-8") from exc
        if not isinstance(payload, str):
            raise TypeError("Frozen update tape payload must be bytes, str, or dict")

        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"Frozen update tape has duplicate key {key!r}")
                result[key] = value
            return result

        try:
            return json.loads(payload, object_pairs_hook=reject_duplicate_keys)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ValueError("Frozen update tape is not valid strict JSON") from exc

    def _frozen_tape_update_contract(self) -> dict[str, Any]:
        return {
            "adapter_init_seed": self.adapter_init_seed,
            "adaptation_context_policy": self.adaptation_context_policy,
            "best_of_n": self.best_of_n,
            "bon_critic": self.bon_critic,
            "bon_env_reward": self.bon_env_reward,
            "context_policy": self.context_policy,
            "distill_contrastive": self.distill_contrastive,
            "history_ttt": self.history_ttt,
            "method": self.method,
            "model_path": self.model_path,
            "num_virtual_tokens": self.num_virtual_tokens,
            "peft_method": self.peft_method,
            "reward_negative_weight": self.reward_negative_weight,
            "reward_pg_steps": self.reward_pg_steps,
            "reward_positive_weight": self.reward_positive_weight,
            "reward_update_rule": self.reward_update_rule,
            "ttt_max_tokens": self.ttt_max_tokens,
            "ttt_steps": self.ttt_steps,
        }

    def _assert_frozen_tape_system_contract(self) -> None:
        problems = []
        if self.method != "ttt_rl":
            problems.append("method must be 'ttt_rl'")
        if self.reward_update_rule != "reward_pg":
            problems.append("reward_update_rule must be 'reward_pg'")
        if self.context_policy != "question_only":
            problems.append("context_policy must be 'question_only'")
        if self.bon_critic != "env" or self.best_of_n < 2:
            problems.append("env BoN requires bon_critic='env' and best_of_n>=2")
        if self.reward_pg_steps < 1:
            problems.append("reward_pg_steps must be >=1")
        if problems:
            raise RuntimeError(
                "Frozen-tape weight-update ablation contract violation: "
                + "; ".join(problems)
            )

    def _normalize_frozen_tape_sampling_provenance(
        self, provenance: Any
    ) -> dict[str, Any]:
        base_keys = {
            "registered_run_seed",
            "interaction_step",
            "requested_best_of_n",
            "initial_sample_attempts",
            "generation_failures",
            "parse_failures",
            "duplicates",
            "valid_unique",
            "candidate_count",
            "sampling_prompt_sha256",
            "sampling_rng_binding",
        }
        if not isinstance(provenance, dict):
            raise ValueError("Frozen tape sampling provenance must be an object")
        has_digest = "provenance_sha256" in provenance
        expected_keys = base_keys | ({"provenance_sha256"} if has_digest else set())
        provenance = self._frozen_tape_exact_keys(
            provenance, expected_keys, where="frozen tape sampling provenance"
        )
        for key in (
            "registered_run_seed",
            "interaction_step",
            "requested_best_of_n",
            "initial_sample_attempts",
            "generation_failures",
            "parse_failures",
            "duplicates",
            "valid_unique",
            "candidate_count",
        ):
            if (
                isinstance(provenance[key], bool)
                or not isinstance(provenance[key], int)
                or provenance[key] < 0
            ):
                raise ValueError(f"Frozen tape sampling {key} must be non-negative int")
        if provenance["interaction_step"] < 1:
            raise ValueError("Frozen tape sampling interaction_step must be positive")
        if provenance["requested_best_of_n"] < 2:
            raise ValueError("Frozen tape sampling requested_best_of_n must be >=2")
        prompt_hash = provenance["sampling_prompt_sha256"]
        if (
            not isinstance(prompt_hash, str)
            or _SHA256_RE.fullmatch(prompt_hash) is None
        ):
            raise ValueError("Frozen tape sampling prompt hash is malformed")
        if provenance["sampling_rng_binding"] != _FROZEN_TAPE_SAMPLING_RNG_BINDING:
            raise ValueError("Frozen tape sampling RNG binding mismatch")
        if provenance["candidate_count"] < 2:
            raise ValueError("Frozen tape sampling candidate_count must be >=2")
        if provenance["valid_unique"] > provenance["candidate_count"]:
            raise ValueError(
                "Frozen tape sampling valid_unique exceeds candidate_count"
            )
        normalized = {key: provenance[key] for key in base_keys}
        digest = self._frozen_tape_digest(normalized)
        if has_digest and provenance["provenance_sha256"] != digest:
            raise ValueError("Frozen tape sampling provenance digest mismatch")
        normalized["provenance_sha256"] = digest
        return normalized

    def record_frozen_tape_item(
        self,
        *,
        sequence_index: int,
        instance_id: str,
        instance_index: int,
        committed_training_ids: list[int],
        committed_prompt_tokens: int,
        committed_reward: float,
        env_bon_prompt: str,
        env_bon_candidates: list[str],
        env_bon_rewards: list[float],
        integrity: dict[str, Any],
        sampling_provenance: dict[str, Any],
    ) -> dict[str, Any]:
        """Build one immutable adaptation item with content-level hashes.

        Callers may use :meth:`capture_frozen_tape_item` for the normal runner
        path.  This lower-level constructor exists for offline collectors that
        already persisted the exact committed token IDs and env-scored group.
        """
        self._assert_frozen_tape_system_contract()
        if isinstance(sequence_index, bool) or not isinstance(sequence_index, int):
            raise ValueError("sequence_index must be an integer")
        if sequence_index < 0:
            raise ValueError("sequence_index must be non-negative")
        if not isinstance(instance_id, str) or not instance_id:
            raise ValueError("instance_id must be a non-empty string")
        if isinstance(instance_index, bool) or not isinstance(instance_index, int):
            raise ValueError("instance_index must be an integer")
        if instance_index < 0:
            raise ValueError("instance_index must be non-negative")
        if not isinstance(committed_training_ids, list) or not committed_training_ids:
            raise ValueError("committed_training_ids must be a non-empty list")
        if any(
            isinstance(token, bool) or not isinstance(token, int) or token < 0
            for token in committed_training_ids
        ):
            raise ValueError("committed_training_ids must contain non-negative ints")
        if (
            isinstance(committed_prompt_tokens, bool)
            or not isinstance(committed_prompt_tokens, int)
            or not 0 <= committed_prompt_tokens < len(committed_training_ids)
        ):
            raise ValueError(
                "committed_prompt_tokens must retain at least one target token"
            )
        committed_reward = self._frozen_tape_finite_number(
            committed_reward, where="committed_reward"
        )
        # The formal contract intentionally has exactly two optimizer calls per
        # item. A zero reward would make the historical reward-PG call a no-op and
        # therefore belongs in a different preregistered protocol.
        if committed_reward == 0.0:
            raise ValueError("committed_reward must be non-zero for two-call replay")
        if not isinstance(env_bon_prompt, str) or not env_bon_prompt:
            raise ValueError("env_bon_prompt must be a non-empty string")
        if not isinstance(env_bon_candidates, list) or len(env_bon_candidates) < 2:
            raise ValueError("env_bon_candidates must contain at least two candidates")
        if any(
            not isinstance(candidate, str) or not candidate
            for candidate in env_bon_candidates
        ):
            raise ValueError("env_bon_candidates must contain non-empty strings")
        if not isinstance(env_bon_rewards, list) or len(env_bon_rewards) != len(
            env_bon_candidates
        ):
            raise ValueError("env_bon_rewards must align one-to-one with candidates")
        rewards = [
            self._frozen_tape_finite_number(value, where="env_bon_reward")
            for value in env_bon_rewards
        ]
        integrity = self._validate_frozen_tape_integrity(integrity)
        sampling_provenance = self._normalize_frozen_tape_sampling_provenance(
            sampling_provenance
        )
        if sampling_provenance["requested_best_of_n"] != self.best_of_n:
            raise ValueError("Frozen tape requested best_of_n differs from system")
        if sampling_provenance["valid_unique"] != len(set(env_bon_candidates)):
            raise ValueError("Frozen tape sampling valid_unique mismatch")

        prompt_ids = committed_training_ids[:committed_prompt_tokens]
        target_ids = committed_training_ids[committed_prompt_tokens:]
        training_payload = {
            "ids": list(committed_training_ids),
            "prompt_tokens": committed_prompt_tokens,
        }
        candidate_records = [
            {
                "candidate": candidate,
                "candidate_sha256": hashlib.sha256(
                    candidate.encode("utf-8")
                ).hexdigest(),
                "reward": reward,
                "reward_sha256": self._frozen_tape_digest(reward),
            }
            for candidate, reward in zip(env_bon_candidates, rewards, strict=True)
        ]
        if sampling_provenance["candidate_count"] != len(candidate_records):
            raise ValueError("Frozen tape sampling candidate_count mismatch")
        ranked = sorted(
            (
                (record["reward"], record["candidate"], candidate_index)
                for candidate_index, record in enumerate(candidate_records)
            ),
            key=lambda row: row[0],
            reverse=True,
        )
        _best_reward, best_candidate, best_index = ranked[0]
        _worst_reward, worst_candidate, worst_index = ranked[-1]
        batch_specs = [
            ("positive", best_index, best_candidate, self.reward_positive_weight)
        ]
        if (
            self.distill_contrastive
            and self.reward_negative_weight > 0
            and worst_candidate != best_candidate
        ):
            batch_specs.append(
                ("negative", worst_index, worst_candidate, -self.reward_negative_weight)
            )
        selected_batches: list[dict[str, Any]] = []
        for role, candidate_index, candidate, signed_weight in batch_specs:
            batch = self._build_distill_batch(env_bon_prompt, candidate, signed_weight)
            if batch is None:
                raise ValueError(f"env-BoN {role} selected batch is empty")
            batch_payload = {
                "role": role,
                "candidate_index": candidate_index,
                "ids": list(batch["ids"]),
                "prompt_tokens": int(batch["prompt_tokens"]),
                "signed_weight": float(batch["signed_weight"]),
            }
            batch_payload["batch_sha256"] = self._frozen_tape_digest(batch_payload)
            selected_batches.append(batch_payload)
        item: dict[str, Any] = {
            "schema_version": _FROZEN_TAPE_SCHEMA_VERSION,
            "sequence_index": sequence_index,
            "instance_id": instance_id,
            "instance_index": instance_index,
            "integrity": dict(integrity),
            "sampling_provenance": sampling_provenance,
            "committed_reward_pg": {
                **training_payload,
                "prompt_token_ids_sha256": self._frozen_tape_digest(prompt_ids),
                "target_token_ids_sha256": self._frozen_tape_digest(target_ids),
                "training_example_sha256": self._frozen_tape_digest(training_payload),
                "reward": committed_reward,
                "reward_sha256": self._frozen_tape_digest(committed_reward),
            },
            "env_bon": {
                "prompt": env_bon_prompt,
                "prompt_sha256": hashlib.sha256(
                    env_bon_prompt.encode("utf-8")
                ).hexdigest(),
                "candidates": candidate_records,
                "candidate_order_sha256": self._frozen_tape_digest(candidate_records),
                "selected_batches": selected_batches,
            },
        }
        item["item_sha256"] = self._frozen_tape_digest(item)
        self._validate_frozen_tape_item(item, expected_sequence_index=sequence_index)
        return item

    def capture_frozen_tape_item(
        self,
        observation: Observation,
        *,
        sequence_index: int,
        instance_id: str | None = None,
        instance_index: int | None = None,
        integrity: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Capture the exact terminal update inputs before ``observe()`` consumes them."""
        self._assert_frozen_tape_system_contract()
        pending = self._pending_env_bon
        if not isinstance(pending, dict):
            raise RuntimeError("No pending env-BoN group to capture")
        if pending.get("lazy_generation") is not None:
            raise RuntimeError(
                "Frozen-tape collector requires eager historical env-BoN"
            )
        if (
            self._last_action_training_ids is None
            or self._last_action_prompt_tokens is None
        ):
            raise RuntimeError("No committed reward-PG training example to capture")
        candidates = pending.get("candidates")
        if not isinstance(candidates, list):
            raise RuntimeError("Pending env-BoN candidates are malformed")
        scored: list[float] = []
        metadata = observation.metadata or {}
        for candidate in candidates:
            reward = self._score_env_candidate(
                candidate, pending.get("schema"), metadata
            )
            if reward is None:
                raise RuntimeError("Every frozen-tape env-BoN candidate must score")
            scored.append(float(reward))
        resolved_instance_id = (
            pending.get("instance_id") if instance_id is None else instance_id
        )
        resolved_instance_index = (
            pending.get("instance_index") if instance_index is None else instance_index
        )
        if resolved_instance_id is None:
            resolved_instance_id = f"instance-{resolved_instance_index}"
        prompt = self._render_generation_prompt(
            [{"role": "user", "content": str(pending["query_text"])}]
        )
        resolved_integrity = (
            dict(self._last_response_integrity)
            if integrity is None and self._last_response_integrity is not None
            else integrity
        )
        if resolved_integrity is None:
            raise RuntimeError("No response integrity evidence to capture")
        candidate_sampling = pending.get("candidate_sampling")
        if not isinstance(candidate_sampling, dict):
            raise RuntimeError("No eager env-BoN sampling provenance to capture")
        sampling_provenance = {
            "registered_run_seed": pending.get("registered_run_seed"),
            "interaction_step": pending.get("interaction_step"),
            "requested_best_of_n": candidate_sampling.get("requested_group_size"),
            "initial_sample_attempts": candidate_sampling.get(
                "initial_sample_attempts"
            ),
            "generation_failures": candidate_sampling.get("generation_failures"),
            "parse_failures": candidate_sampling.get("parse_failures"),
            "duplicates": candidate_sampling.get("duplicates"),
            "valid_unique": candidate_sampling.get("valid_unique"),
            "candidate_count": candidate_sampling.get("candidate_count"),
            "sampling_prompt_sha256": pending.get("sampling_prompt_sha256"),
            "sampling_rng_binding": _FROZEN_TAPE_SAMPLING_RNG_BINDING,
        }
        return self.record_frozen_tape_item(
            sequence_index=sequence_index,
            instance_id=resolved_instance_id,
            instance_index=resolved_instance_index,
            committed_training_ids=list(self._last_action_training_ids),
            committed_prompt_tokens=int(self._last_action_prompt_tokens),
            committed_reward=self._infer_feedback_reward(observation),
            env_bon_prompt=prompt,
            env_bon_candidates=list(candidates),
            env_bon_rewards=scored,
            integrity=resolved_integrity,
            sampling_provenance=sampling_provenance,
        )

    def _validate_frozen_tape_integrity(self, integrity: Any) -> dict[str, Any]:
        integrity = self._frozen_tape_exact_keys(
            integrity,
            {
                "schema_valid",
                "synthetic",
                "timed_out",
                "fallback",
                "missing",
                "hard_schema_failure",
                "parse_retries",
                "repairs",
            },
            where="frozen tape item integrity",
        )
        for key in (
            "schema_valid",
            "synthetic",
            "timed_out",
            "fallback",
            "missing",
            "hard_schema_failure",
        ):
            if not isinstance(integrity[key], bool):
                raise ValueError(f"Frozen tape integrity {key} must be boolean")
        for key in ("parse_retries", "repairs"):
            if (
                isinstance(integrity[key], bool)
                or not isinstance(integrity[key], int)
                or integrity[key] < 0
            ):
                raise ValueError(
                    f"Frozen tape integrity {key} must be non-negative int"
                )
        if (
            not integrity["schema_valid"]
            or integrity["synthetic"]
            or integrity["timed_out"]
            or integrity["fallback"]
            or integrity["missing"]
            or integrity["hard_schema_failure"]
        ):
            raise ValueError("Frozen tape item failed the no-fallback/schema gate")
        return integrity

    def _validate_frozen_tape_item(
        self, item: Any, *, expected_sequence_index: int
    ) -> dict[str, Any]:
        item = self._frozen_tape_exact_keys(
            item,
            {
                "schema_version",
                "sequence_index",
                "instance_id",
                "instance_index",
                "integrity",
                "sampling_provenance",
                "committed_reward_pg",
                "env_bon",
                "item_sha256",
            },
            where=f"items[{expected_sequence_index}]",
        )
        if item["schema_version"] != _FROZEN_TAPE_SCHEMA_VERSION:
            raise ValueError("Frozen tape item schema_version mismatch")
        if item["sequence_index"] != expected_sequence_index:
            raise ValueError("Frozen tape item order/sequence_index mismatch")
        if not isinstance(item["instance_id"], str) or not item["instance_id"]:
            raise ValueError("Frozen tape instance_id must be non-empty")
        if (
            isinstance(item["instance_index"], bool)
            or not isinstance(item["instance_index"], int)
            or item["instance_index"] < 0
        ):
            raise ValueError("Frozen tape instance_index must be non-negative int")
        self._validate_frozen_tape_integrity(item["integrity"])
        sampling_provenance = self._normalize_frozen_tape_sampling_provenance(
            item["sampling_provenance"]
        )
        committed = self._frozen_tape_exact_keys(
            item["committed_reward_pg"],
            {
                "ids",
                "prompt_tokens",
                "prompt_token_ids_sha256",
                "target_token_ids_sha256",
                "training_example_sha256",
                "reward",
                "reward_sha256",
            },
            where=f"items[{expected_sequence_index}].committed_reward_pg",
        )
        ids = committed["ids"]
        prompt_tokens = committed["prompt_tokens"]
        if (
            not isinstance(ids, list)
            or not ids
            or any(
                isinstance(token, bool) or not isinstance(token, int) or token < 0
                for token in ids
            )
        ):
            raise ValueError("Frozen tape committed ids are malformed")
        if (
            isinstance(prompt_tokens, bool)
            or not isinstance(prompt_tokens, int)
            or not 0 <= prompt_tokens < len(ids)
        ):
            raise ValueError("Frozen tape committed prompt_tokens are malformed")
        reward = self._frozen_tape_finite_number(
            committed["reward"], where="committed reward"
        )
        if reward == 0.0:
            raise ValueError("Frozen tape committed reward must be non-zero")
        expected_hashes = {
            "prompt_token_ids_sha256": self._frozen_tape_digest(ids[:prompt_tokens]),
            "target_token_ids_sha256": self._frozen_tape_digest(ids[prompt_tokens:]),
            "training_example_sha256": self._frozen_tape_digest(
                {"ids": ids, "prompt_tokens": prompt_tokens}
            ),
            "reward_sha256": self._frozen_tape_digest(reward),
        }
        for key, expected in expected_hashes.items():
            if committed[key] != expected:
                raise ValueError(f"Frozen tape committed {key} mismatch")

        env_bon = self._frozen_tape_exact_keys(
            item["env_bon"],
            {
                "prompt",
                "prompt_sha256",
                "candidates",
                "candidate_order_sha256",
                "selected_batches",
            },
            where=f"items[{expected_sequence_index}].env_bon",
        )
        prompt = env_bon["prompt"]
        if not isinstance(prompt, str) or not prompt:
            raise ValueError("Frozen tape env-BoN prompt must be non-empty")
        if (
            env_bon["prompt_sha256"]
            != hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        ):
            raise ValueError("Frozen tape env-BoN prompt hash mismatch")
        candidate_records = env_bon["candidates"]
        if not isinstance(candidate_records, list) or len(candidate_records) < 2:
            raise ValueError(
                "Frozen tape env-BoN group must have at least two candidates"
            )
        if sampling_provenance["requested_best_of_n"] != self.best_of_n:
            raise ValueError("Frozen tape requested best_of_n differs from system")
        if sampling_provenance["candidate_count"] != len(candidate_records):
            raise ValueError("Frozen tape sampling candidate_count mismatch")
        for candidate_index, record in enumerate(candidate_records):
            record = self._frozen_tape_exact_keys(
                record,
                {"candidate", "candidate_sha256", "reward", "reward_sha256"},
                where=(
                    f"items[{expected_sequence_index}].env_bon.candidates"
                    f"[{candidate_index}]"
                ),
            )
            candidate = record["candidate"]
            if not isinstance(candidate, str) or not candidate:
                raise ValueError("Frozen tape candidates must be non-empty strings")
            if (
                record["candidate_sha256"]
                != hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            ):
                raise ValueError("Frozen tape candidate hash mismatch")
            candidate_reward = self._frozen_tape_finite_number(
                record["reward"], where="candidate reward"
            )
            if record["reward_sha256"] != self._frozen_tape_digest(candidate_reward):
                raise ValueError("Frozen tape candidate reward hash mismatch")
        if sampling_provenance["valid_unique"] != len(
            {record["candidate"] for record in candidate_records}
        ):
            raise ValueError("Frozen tape sampling valid_unique mismatch")
        if env_bon["candidate_order_sha256"] != self._frozen_tape_digest(
            candidate_records
        ):
            raise ValueError("Frozen tape candidate order hash mismatch")
        ranked = sorted(
            (
                (float(record["reward"]), record["candidate"], candidate_index)
                for candidate_index, record in enumerate(candidate_records)
            ),
            key=lambda row: row[0],
            reverse=True,
        )
        _best_reward, best_candidate, best_index = ranked[0]
        _worst_reward, worst_candidate, worst_index = ranked[-1]
        expected_specs = [("positive", best_index, float(self.reward_positive_weight))]
        if (
            self.distill_contrastive
            and self.reward_negative_weight > 0
            and worst_candidate != best_candidate
        ):
            expected_specs.append(
                ("negative", worst_index, -float(self.reward_negative_weight))
            )
        selected_batches = env_bon["selected_batches"]
        if not isinstance(selected_batches, list) or len(selected_batches) != len(
            expected_specs
        ):
            raise ValueError("Frozen tape selected env-BoN batch count mismatch")
        for batch_index, (batch, expected_spec) in enumerate(
            zip(selected_batches, expected_specs, strict=True)
        ):
            batch = self._frozen_tape_exact_keys(
                batch,
                {
                    "role",
                    "candidate_index",
                    "ids",
                    "prompt_tokens",
                    "signed_weight",
                    "batch_sha256",
                },
                where=(
                    f"items[{expected_sequence_index}].env_bon.selected_batches"
                    f"[{batch_index}]"
                ),
            )
            expected_role, expected_candidate_index, expected_weight = expected_spec
            if batch["role"] != expected_role:
                raise ValueError("Frozen tape selected batch role/order mismatch")
            if batch["candidate_index"] != expected_candidate_index:
                raise ValueError("Frozen tape selected batch candidate index mismatch")
            ids = batch["ids"]
            prompt_tokens = batch["prompt_tokens"]
            if (
                not isinstance(ids, list)
                or not ids
                or any(
                    isinstance(token, bool) or not isinstance(token, int) or token < 0
                    for token in ids
                )
            ):
                raise ValueError("Frozen tape selected batch ids are malformed")
            if (
                isinstance(prompt_tokens, bool)
                or not isinstance(prompt_tokens, int)
                or not 0 <= prompt_tokens < len(ids)
            ):
                raise ValueError(
                    "Frozen tape selected batch prompt_tokens are malformed"
                )
            signed_weight = self._frozen_tape_finite_number(
                batch["signed_weight"], where="selected batch signed_weight"
            )
            if signed_weight != expected_weight:
                raise ValueError("Frozen tape selected batch signed weight mismatch")
            batch_without_digest = {
                key: value for key, value in batch.items() if key != "batch_sha256"
            }
            if (
                not isinstance(batch["batch_sha256"], str)
                or _SHA256_RE.fullmatch(batch["batch_sha256"]) is None
                or batch["batch_sha256"]
                != self._frozen_tape_digest(batch_without_digest)
            ):
                raise ValueError("Frozen tape selected batch digest mismatch")
        item_without_digest = {
            key: value for key, value in item.items() if key != "item_sha256"
        }
        if (
            not isinstance(item["item_sha256"], str)
            or _SHA256_RE.fullmatch(item["item_sha256"]) is None
            or item["item_sha256"] != self._frozen_tape_digest(item_without_digest)
        ):
            raise ValueError("Frozen tape item digest mismatch")
        return item

    def assemble_frozen_update_tape(
        self, items: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Assemble ordered items and bind every update-relevant config except LR."""
        self._assert_frozen_tape_system_contract()
        if float(self.ttt_lr) != 0.0 or float(self.reward_pg_lr) != 0.0:
            raise RuntimeError(
                "Frozen update tape must be assembled by an LR0 collector"
            )
        if (
            self._frozen_tape_initial_trainable_state is None
            or self._frozen_tape_initial_hash is None
        ):
            raise RuntimeError(
                "Call initialize_and_snapshot_adapter_state() before collection"
            )
        collector_final_hash = self._trainable_param_sha256()
        if collector_final_hash != self._frozen_tape_initial_hash:
            raise RuntimeError("LR0 collector changed trainable parameters")
        if not isinstance(items, list) or not items:
            raise ValueError("Frozen update tape requires at least one item")
        validated = [
            self._validate_frozen_tape_item(item, expected_sequence_index=index)
            for index, item in enumerate(items)
        ]
        instance_ids = [item["instance_id"] for item in validated]
        instance_indices = [item["instance_index"] for item in validated]
        if len(set(instance_ids)) != len(instance_ids):
            raise ValueError("Frozen update tape instance_id values must be unique")
        if len(set(instance_indices)) != len(instance_indices):
            raise ValueError("Frozen update tape instance_index values must be unique")
        tape: dict[str, Any] = {
            "schema_version": _FROZEN_TAPE_SCHEMA_VERSION,
            "protocol": _FROZEN_TAPE_PROTOCOL,
            "mechanism_label": _FROZEN_TAPE_MECHANISM_LABEL,
            "learning_rate_ablation_fields": ["ttt_lr", "reward_pg_lr"],
            "collector_trainable_param_sha256_initial": self._frozen_tape_initial_hash,
            "collector_trainable_param_sha256_final": collector_final_hash,
            "collector_lr0_verified": True,
            "update_contract": self._frozen_tape_update_contract(),
            # Canonical round-trip prevents the caller mutating nested input lists
            # after the digest is computed.
            "items": json.loads(self._frozen_tape_canonical_bytes(validated)),
        }
        tape["tape_sha256"] = self._frozen_tape_digest(tape)
        return tape

    def validate_frozen_update_tape(
        self,
        tape: dict[str, Any] | bytes | str,
        *,
        expected_tape_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Strictly validate schema, every nested hash, order, and root digest."""
        self._assert_frozen_tape_system_contract()
        if isinstance(tape, (bytes, str)):
            tape = self._frozen_tape_parse_json(tape)
        tape = self._frozen_tape_exact_keys(
            tape,
            {
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
            },
            where="frozen_update_tape",
        )
        if tape["schema_version"] != _FROZEN_TAPE_SCHEMA_VERSION:
            raise ValueError("Frozen update tape schema_version mismatch")
        if tape["protocol"] != _FROZEN_TAPE_PROTOCOL:
            raise ValueError("Frozen update tape protocol mismatch")
        if tape["mechanism_label"] != _FROZEN_TAPE_MECHANISM_LABEL:
            raise ValueError("Frozen update tape mechanism label mismatch")
        if tape["learning_rate_ablation_fields"] != ["ttt_lr", "reward_pg_lr"]:
            raise ValueError("Frozen update tape LR-ablation fields mismatch")
        collector_initial = tape["collector_trainable_param_sha256_initial"]
        collector_final = tape["collector_trainable_param_sha256_final"]
        if (
            not isinstance(collector_initial, str)
            or _SHA256_RE.fullmatch(collector_initial) is None
            or not isinstance(collector_final, str)
            or _SHA256_RE.fullmatch(collector_final) is None
            or collector_initial != collector_final
            or tape["collector_lr0_verified"] is not True
        ):
            raise ValueError("Frozen update tape LR0 collector hash gate failed")
        if tape["update_contract"] != self._frozen_tape_update_contract():
            raise ValueError("Frozen update tape updater config differs from this arm")
        items = tape["items"]
        if not isinstance(items, list) or not items:
            raise ValueError("Frozen update tape items must be a non-empty list")
        validated = [
            self._validate_frozen_tape_item(item, expected_sequence_index=index)
            for index, item in enumerate(items)
        ]
        if len({item["instance_id"] for item in validated}) != len(validated):
            raise ValueError("Frozen update tape instance_id values must be unique")
        if len({item["instance_index"] for item in validated}) != len(validated):
            raise ValueError("Frozen update tape instance_index values must be unique")
        embedded = tape["tape_sha256"]
        if not isinstance(embedded, str) or _SHA256_RE.fullmatch(embedded) is None:
            raise ValueError("Frozen update tape root digest is malformed")
        without_digest = {
            key: value for key, value in tape.items() if key != "tape_sha256"
        }
        if embedded != self._frozen_tape_digest(without_digest):
            raise ValueError("Frozen update tape root digest mismatch")
        if expected_tape_sha256 is not None:
            if (
                not isinstance(expected_tape_sha256, str)
                or _SHA256_RE.fullmatch(expected_tape_sha256) is None
            ):
                raise ValueError("Expected frozen update tape digest is malformed")
            if embedded != expected_tape_sha256:
                raise ValueError("Frozen update tape differs from preregistered digest")
        return json.loads(self._frozen_tape_canonical_bytes(tape))

    def serialize_frozen_update_tape(self, tape: dict[str, Any]) -> bytes:
        validated = self.validate_frozen_update_tape(tape)
        return self._frozen_tape_canonical_bytes(validated)

    def capture_initial_adapter_state(self) -> str:
        """Snapshot the exact initial trainable adapter for later restoration."""
        self._ensure_lora_model()

        assert self._model is not None
        if self._frozen_tape_initial_trainable_state is not None:
            current_hash = self._trainable_param_sha256()
            if current_hash != self._frozen_tape_initial_hash:
                raise RuntimeError(
                    "Initial adapter state was already captured and weights changed"
                )
            return current_hash
        state = {
            name: parameter.detach().cpu().clone()
            for name, parameter in self._model.named_parameters()
            if parameter.requires_grad
        }
        if not state:
            raise RuntimeError(
                "Frozen-tape ablation found no trainable adapter parameters"
            )
        current_hash = self._trainable_param_sha256()
        self._frozen_tape_initial_trainable_state = state
        self._frozen_tape_initial_hash = current_hash
        return current_hash

    def initialize_and_snapshot_adapter_state(self) -> str:
        """Install the adapter before collection and snapshot its frozen policy."""
        return self.capture_initial_adapter_state()

    def current_trainable_param_sha256(self) -> str:
        """Return an audit hash after ensuring the configured adapter is installed."""
        self._ensure_lora_model()
        return self._trainable_param_sha256()

    def current_model_param_sha256(self) -> str:
        """Hash the complete loaded model state for no-update ICL auditing.

        The historical method name is retained for compatibility, but the
        digest covers every tensor in ``state_dict()``: parameters and persistent
        buffers.  This is intentionally more expensive than the adapter-only
        hash.  The canonical online-ICL arm calls it only at cell boundaries to
        prove that no hidden optimizer or in-place model-state mutation occurred.
        """
        import torch

        _tokenizer, model = self._load_model()
        digest = hashlib.sha256()
        state = sorted(model.state_dict().items(), key=lambda item: item[0])
        if not state:
            raise RuntimeError("Cannot hash an empty model-state inventory")
        for name, tensor in state:
            if not isinstance(tensor, torch.Tensor):
                raise RuntimeError(
                    f"Model state entry {name!r} is not a tensor: "
                    f"{type(tensor).__name__}"
                )
            detached = tensor.detach().contiguous()
            digest.update(name.encode("utf-8"))
            digest.update(str(detached.dtype).encode("ascii"))
            digest.update(self._icl_context_canonical_bytes(list(detached.shape)))
            digest.update(
                detached.reshape(-1).view(torch.uint8).cpu().numpy().tobytes()
            )
        return digest.hexdigest()

    def icl_no_update_audit(self) -> dict[str, Any]:
        """Return the fail-closed counters used by canonical online ICL."""
        model = self._model
        peft_config = getattr(model, "peft_config", None) if model is not None else None
        return {
            "adaptation_count": self.adaptation_count,
            "adapter_enabled": self._lora_enabled,
            "bon_updates": getattr(self, "bon_updates", 0),
            "distill_updates": getattr(self, "distill_updates", 0),
            "grpo_optimizer_steps": self.grpo_optimizer_steps,
            "grpo_updates": self.grpo_updates,
            "peft_config_present": bool(peft_config),
            "reward_pg_updates": self.reward_pg_updates,
        }

    def restore_initial_adapter_state(self) -> str:
        """Restore the captured pre-replay adapter and verify its exact hash."""
        if self._frozen_tape_initial_trainable_state is None:
            raise RuntimeError("No frozen-tape initial adapter state has been captured")
        self._ensure_lora_model()
        import torch

        assert self._model is not None
        trainable = {
            name: parameter
            for name, parameter in self._model.named_parameters()
            if parameter.requires_grad
        }
        expected_names = set(self._frozen_tape_initial_trainable_state)
        if set(trainable) != expected_names:
            raise RuntimeError("Trainable adapter parameter set changed before restore")
        with torch.no_grad():
            for name, saved in self._frozen_tape_initial_trainable_state.items():
                parameter = trainable[name]
                if tuple(parameter.shape) != tuple(saved.shape):
                    raise RuntimeError(f"Trainable adapter shape changed for {name}")
                parameter.copy_(
                    saved.to(device=parameter.device, dtype=parameter.dtype)
                )
        restored_hash = self._trainable_param_sha256()
        if restored_hash != self._frozen_tape_initial_hash:
            raise RuntimeError("Initial adapter restore hash mismatch")
        return restored_hash

    def replay_frozen_update_tape(
        self,
        tape: dict[str, Any] | bytes | str,
        *,
        expected_tape_sha256: str,
    ) -> dict[str, Any]:
        """Replay identical update calls; only configured learning rates may differ."""
        if self._frozen_tape_heldout_eval:
            raise RuntimeError(
                "Cannot replay after held-out evaluation updates are frozen"
            )
        validated = self.validate_frozen_update_tape(
            tape, expected_tape_sha256=expected_tape_sha256
        )
        self.set_parameter_updates_enabled(True)
        self._ensure_lora_model()
        if self._frozen_tape_initial_trainable_state is None:
            initial_hash = self.capture_initial_adapter_state()
        else:
            initial_hash = self._trainable_param_sha256()
            if initial_hash != self._frozen_tape_initial_hash:
                raise RuntimeError(
                    "Adapter is not at captured initial state; call "
                    "restore_initial_adapter_state() before replay"
                )
        replay_items: list[dict[str, Any]] = []
        for item in validated["items"]:
            item_before = self._trainable_param_sha256()
            operations: list[dict[str, Any]] = []

            committed = item["committed_reward_pg"]
            reward = float(committed["reward"])
            signed_weight = self._signed_weight_from_reward(reward)
            if signed_weight == 0.0:
                raise RuntimeError(
                    "Frozen-tape reward-PG signed weight unexpectedly zero"
                )
            reward_before = self._trainable_param_sha256()
            previous_steps = self.ttt_steps
            try:
                self.ttt_steps = self.reward_pg_steps
                self.last_reward_pg_loss = self._train_lora_token_batches(
                    [
                        {
                            "ids": list(committed["ids"]),
                            "prompt_tokens": int(committed["prompt_tokens"]),
                            "signed_weight": signed_weight,
                        }
                    ],
                    lr=self.reward_pg_lr,
                )
            finally:
                self.ttt_steps = previous_steps
            reward_after = self._trainable_param_sha256()
            self.reward_pg_updates += 1
            if signed_weight > 0:
                self.reward_pg_positive_updates += 1
            else:
                self.reward_pg_negative_updates += 1
            operations.append(
                {
                    "operation": "reward_pg_terminal",
                    "batch_count": 1,
                    "input_sha256": [
                        committed["training_example_sha256"],
                        committed["reward_sha256"],
                    ],
                    "trainable_param_sha256_before": reward_before,
                    "trainable_param_sha256_after": reward_after,
                }
            )

            env_bon = item["env_bon"]
            scored = [
                (float(record["reward"]), record["candidate"])
                for record in env_bon["candidates"]
            ]
            scored.sort(key=lambda pair: pair[0], reverse=True)
            best_score, _best = scored[0]
            batches = [
                {
                    "ids": list(batch["ids"]),
                    "prompt_tokens": int(batch["prompt_tokens"]),
                    "signed_weight": float(batch["signed_weight"]),
                }
                for batch in env_bon["selected_batches"]
            ]
            bon_before = self._trainable_param_sha256()
            self.last_adaptation_loss = self._train_lora_token_batches(
                batches, lr=self.reward_pg_lr
            )
            bon_after = self._trainable_param_sha256()
            self.bon_updates = getattr(self, "bon_updates", 0) + 1
            operations.append(
                {
                    "operation": "bon_env_best_worst_sft",
                    "batch_count": len(batches),
                    "input_sha256": [
                        batch["batch_sha256"] for batch in env_bon["selected_batches"]
                    ],
                    "trainable_param_sha256_before": bon_before,
                    "trainable_param_sha256_after": bon_after,
                }
            )
            replay_items.append(
                {
                    "sequence_index": item["sequence_index"],
                    "instance_id": item["instance_id"],
                    "instance_index": item["instance_index"],
                    "integrity": dict(item["integrity"]),
                    "sampling_provenance": dict(item["sampling_provenance"]),
                    "item_sha256": item["item_sha256"],
                    "best_env_reward": best_score,
                    "status": "complete",
                    "operation_count": 2,
                    "operations": operations,
                    "trainable_param_sha256_before": item_before,
                    "trainable_param_sha256_after": bon_after,
                }
            )

        final_hash = self._trainable_param_sha256()
        replay_log = {
            "status": "complete",
            "digest_verified": True,
            "tape_sha256": validated["tape_sha256"],
            "item_count": len(replay_items),
            "operations_per_item": 2,
            "operation_count": 2 * len(replay_items),
            "trainable_param_sha256_initial": initial_hash,
            "trainable_param_sha256_final": final_hash,
            "items": replay_items,
        }
        self._frozen_tape_last_digest = validated["tape_sha256"]
        self._frozen_tape_replay_log.append(replay_log)
        if float(self.reward_pg_lr) == 0.0:
            if final_hash != initial_hash:
                raise RuntimeError(
                    "LR0 frozen-tape replay changed trainable parameters"
                )
        elif final_hash == initial_hash:
            raise RuntimeError("Active frozen-tape replay produced no parameter change")
        return replay_log

    def freeze_updates_for_heldout_eval(self) -> str:
        """Hard-freeze every update path after replay for held-out evaluation."""
        if self._frozen_tape_last_digest is None:
            raise RuntimeError(
                "Replay a validated frozen update tape before held-out eval"
            )
        self._frozen_tape_heldout_eval = True
        self._pending_env_bon = None
        super().set_parameter_updates_enabled(False)
        return self._trainable_param_sha256()

    def _adapt_before_response(self, query_content: str) -> None:
        # history_ttt=False disables the self-supervised history pass independently
        # of ttt_steps, so best-of-N methods can take N SFT steps (ttt_steps>0) on
        # the selected candidate WITHOUT also doing chunk/sft history-TTT.
        if self.method == "icl" or self.ttt_steps == 0 or not self.history_ttt:
            return
        if self.interaction_count % self.ttt_train_every != 0:
            return

        history = self.messages[:-1]
        if not history:
            return

        sequences = self._select_ttt_sequences(history, query_content)
        if not sequences:
            return

        self._ensure_lora_model()
        self.last_adaptation_loss = self._train_lora_sequences(sequences)
        self.adaptation_count += 1

    def _select_ttt_sequences(
        self, history: list[dict[str, str]], query_content: str
    ) -> list[TTTBatch]:
        method = self.method
        if method == "ttt_rl":
            method = self.ttt_rl_source
        if method == "none":
            return []
        if method == "chunk":
            return self._chunk_ttt_sequences(history, query_content, query_aware=False)
        if method == "qttt":
            return self._chunk_ttt_sequences(history, query_content, query_aware=True)
        if method == "sft":
            return self._sft_ttt_sequences(history)
        if method == "both":
            return self._interleave_ttt_sequences(
                self._chunk_ttt_sequences(history, query_content, query_aware=True),
                self._sft_ttt_sequences(history),
            )
        raise ValueError(f"Unsupported TTT method={method!r}")

    def _interleave_ttt_sequences(
        self, chunk_sequences: list[TTTBatch], sft_sequences: list[TTTBatch]
    ) -> list[TTTBatch]:
        """Keep hybrid/both updates from collapsing into pure chunk updates."""
        selected: list[TTTBatch] = []
        cap = self.ttt_max_chunks
        if chunk_sequences and sft_sequences:
            cap = max(cap, 2)
        max_len = max(len(chunk_sequences), len(sft_sequences))
        for idx in range(max_len):
            if idx < len(chunk_sequences):
                selected.append(chunk_sequences[idx])
            if len(selected) >= cap:
                break
            if idx < len(sft_sequences):
                selected.append(sft_sequences[idx])
            if len(selected) >= cap:
                break
        return selected

    def _chunk_ttt_sequences(
        self,
        history: list[dict[str, str]],
        query_content: str,
        *,
        query_aware: bool,
    ) -> list[list[int]]:
        text = self._render_ttt_history_window(history)
        tokenizer = self._load_tokenizer()
        ids = tokenizer.encode(text, add_special_tokens=False)
        if len(ids) < 16:
            return []

        chunks: list[list[int]] = []
        limit = min(self.ttt_chunk_tokens, self.ttt_max_tokens)
        for start in range(0, len(ids), self.ttt_stride_tokens):
            chunk = ids[start : start + limit]
            if len(chunk) >= 16:
                chunks.append(chunk)
            if start + limit >= len(ids):
                break
        if not chunks:
            return []

        if not query_aware:
            return chunks[-self.ttt_max_chunks :]

        query_terms = self._lexical_terms(query_content)
        if not query_terms:
            return chunks[-self.ttt_max_chunks :]

        scored: list[tuple[int, int, list[int]]] = []
        for idx, chunk in enumerate(chunks):
            chunk_text = tokenizer.decode(chunk, skip_special_tokens=True).lower()
            score = sum(chunk_text.count(term) for term in query_terms)
            scored.append((score, idx, chunk))
        selected = sorted(scored, key=lambda item: (item[0], item[1]), reverse=True)
        top = [
            chunk for score, _, chunk in selected[: self.ttt_max_chunks] if score > 0
        ]
        return top or chunks[-self.ttt_max_chunks :]

    def _render_ttt_history_window(self, history: list[dict[str, str]]) -> str:
        """Render only a bounded recent history window for chunk/qTTT updates."""
        tokenizer = self._load_tokenizer()
        token_budget = max(self.ttt_max_tokens, self.max_context_tokens)
        selected: list[dict[str, str]] = []
        for message in reversed(history):
            candidate = [message, *selected]
            rendered = self._render_training_messages(candidate)
            ids = tokenizer.encode(rendered, add_special_tokens=False)
            if len(ids) <= token_budget:
                selected = candidate
                continue
            self.ttt_history_truncation_count += 1
            self.has_truncated_flag = True
            if selected:
                break
            if self.adaptation_context_policy is not None:
                return self._window_text_for_policy(
                    rendered,
                    self.adaptation_context_policy,
                    full_token_limit=token_budget,
                    count_as_generation=False,
                )
            kept = ids[-token_budget:]
            return tokenizer.decode(kept, skip_special_tokens=False)
        if selected:
            rendered = self._render_training_messages(selected)
            if self.adaptation_context_policy is not None:
                return self._window_text_for_policy(
                    rendered,
                    self.adaptation_context_policy,
                    full_token_limit=token_budget,
                    count_as_generation=False,
                )
            return rendered
        return ""

    def _sft_ttt_sequences(self, history: list[dict[str, str]]) -> list[TTTBatch]:
        tokenizer = self._load_tokenizer()
        sequences: list[TTTBatch] = []
        for idx, message in enumerate(history):
            if message["role"] != "assistant":
                continue
            if idx == 0:
                # No preceding turn to pair as prompt->target. This happens under
                # context_policy="full" once _truncate_full_messages drops the
                # leading user turn, leaving an assistant message at index 0.
                # Rendering an empty conversation crashes apply_chat_template.
                continue
            start = idx - 1
            prompt_text = self._render_generation_prompt(history[start:idx])
            target_text = message["content"] + (tokenizer.eos_token or "")
            prompt_ids = tokenizer.encode(prompt_text, add_special_tokens=False)
            target_ids = tokenizer.encode(target_text, add_special_tokens=False)
            if not target_ids:
                continue
            ids = prompt_ids + target_ids
            if len(ids) < 16:
                continue
            prompt_tokens = len(prompt_ids)
            if len(ids) > self.ttt_max_tokens:
                offset = len(ids) - self.ttt_max_tokens
                ids = ids[-self.ttt_max_tokens :]
                prompt_tokens = max(0, prompt_tokens - offset)
            sequences.append(
                {
                    "ids": ids,
                    "prompt_tokens": prompt_tokens,
                    "signed_weight": 1.0,
                    "source": "sft",
                }
            )
        return sequences[-self.ttt_max_chunks :]

    def _render_generation_prompt(self, messages: list[dict[str, str]]) -> str:
        tokenizer = self._load_tokenizer()
        try:
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
        except TypeError:
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

    def _render_training_messages(self, messages: list[dict[str, str]]) -> str:
        tokenizer = self._load_tokenizer()
        try:
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
                enable_thinking=False,
            )
        except TypeError:
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
            )

    def _lexical_terms(self, text: str) -> set[str]:
        return {
            term
            for term in re.findall(r"[a-zA-Z0-9_]{3,}", text.lower())
            if term
            not in {
                "the",
                "and",
                "for",
                "with",
                "that",
                "this",
                "you",
                "are",
                "from",
                "json",
            }
        }

    def _ensure_lora_model(self) -> None:
        if self._lora_enabled:
            return
        self._load_model()
        try:
            from peft import LoraConfig, TaskType, get_peft_model
        except ImportError as exc:
            raise RuntimeError(
                "qwen_local TTT methods require peft. Install peft on this node "
                "instead of silently running a non-updating baseline."
            ) from exc

        if self.peft_method == "prefix":
            # Compress history into a trainable KV prefix (prefix-tuning) instead of
            # LoRA weights. The TTT/reward updates train the prefix key-values; at
            # answer time the prefix is prepended so history is carried via attention.
            from peft import PrefixTuningConfig

            config = PrefixTuningConfig(
                task_type=TaskType.CAUSAL_LM,
                num_virtual_tokens=self.num_virtual_tokens,
            )
        else:
            config = LoraConfig(
                r=self.lora_rank,
                lora_alpha=self.lora_alpha,
                lora_dropout=self.lora_dropout,
                target_modules=list(self.lora_target_modules),
                bias="none",
                task_type=TaskType.CAUSAL_LM,
            )
        self._model = self._install_peft_adapter(config, get_peft_model)
        if self.peft_method == "prefix":
            # PEFT initializes the prefix RANDOMLY, which corrupts the base model's
            # generation before any training (unlike LoRA's zero-init no-op start).
            # Zero the prefix params so it starts as a near no-op and TTT grows it.
            import torch

            with torch.no_grad():
                for param in self._model.parameters():
                    if param.requires_grad:
                        param.zero_()
        self._model.train()
        # Prefix-tuning carries the learned KV-prefix via past_key_values, which
        # generation needs; only disable the cache for the LoRA path.
        if hasattr(self._model.config, "use_cache") and self.peft_method != "prefix":
            self._model.config.use_cache = False
        self._lora_enabled = True

    def _install_peft_adapter(self, config: Any, get_peft_model: Any) -> Any:
        """Install PEFT with an optional isolated, auditable adapter seed.

        The seed is deliberately independent from rollout/proposer seeds: formal
        active/LR0 pairs must begin from the exact same adapter.  It applies to
        both LoRA and prefix adapters, including the legacy ``reward_pg`` rule;
        ``fork_rng`` restores caller CPU and model-device RNG streams.
        """
        if self.adapter_init_seed is None:
            return get_peft_model(self._model, config)

        import torch

        cuda_devices: list[int] = []
        if torch.cuda.is_available() and self._model is not None:
            device = next(self._model.parameters()).device
            if device.type == "cuda":
                cuda_devices = [
                    torch.cuda.current_device()
                    if device.index is None
                    else device.index
                ]
        with torch.random.fork_rng(devices=cuda_devices):
            torch.random.default_generator.manual_seed(self.adapter_init_seed)
            for cuda_device in cuda_devices:
                with torch.cuda.device(cuda_device):
                    torch.cuda.manual_seed(self.adapter_init_seed)
            return get_peft_model(self._model, config)

    def _train_lora_sequences(self, sequences: list[TTTBatch]) -> float:
        batches = []
        for sequence in sequences:
            if isinstance(sequence, dict):
                batches.append(sequence)
            else:
                batches.append(
                    {
                        "ids": sequence,
                        "prompt_tokens": None,
                        "signed_weight": 1.0,
                    }
                )
        return self._train_lora_token_batches(batches, lr=self.ttt_lr)

    def _train_lora_token_batches(
        self, batches: list[dict[str, Any]], *, lr: float
    ) -> float:
        import torch

        if not self.parameter_updates_enabled:
            raise RuntimeError(
                "Parameter update attempted while runtime updates are frozen"
            )
        assert self._model is not None
        model = self._model
        model.train()
        params = [p for p in model.parameters() if p.requires_grad]
        if not params:
            raise RuntimeError("No trainable LoRA parameters found for TTT update")
        optimizer = torch.optim.AdamW(params, lr=lr)

        total_loss = 0.0
        updates = 0
        device = next(model.parameters()).device
        # Always take at least one gradient step when the trainer is invoked.
        # ttt_steps=0 is used elsewhere to DISABLE the history-TTT pass (guarded by
        # an early return in _adapt_before_response), but the SFT-based learners
        # (reward_pg / distill / best-of-N) reach this trainer intentionally and
        # must not be silently turned into a no-op by ttt_steps=0.
        n_steps = max(1, self.ttt_steps)
        for _ in range(n_steps):
            for batch in batches:
                ids = batch["ids"]
                if len(ids) < 2:
                    continue
                offset = max(0, len(ids) - self.ttt_max_tokens)
                trimmed = ids[-self.ttt_max_tokens :]
                input_ids = torch.tensor([trimmed], device=device)
                labels = input_ids.clone()
                prompt_tokens = batch.get("prompt_tokens")
                if prompt_tokens is not None:
                    ignored = max(0, min(len(trimmed), int(prompt_tokens) - offset))
                    if ignored:
                        labels[:, :ignored] = -100
                    if bool(torch.all(labels == -100)):
                        continue
                optimizer.zero_grad(set_to_none=True)
                outputs = model(input_ids=input_ids, labels=labels)
                loss = outputs.loss * float(batch.get("signed_weight", 1.0))
                loss.backward()
                torch.nn.utils.clip_grad_norm_(params, 1.0)
                optimizer.step()
                self._clip_trainable_param_norms(params)
                total_loss += abs(float(loss.detach().cpu()))
                updates += 1
        model.eval()
        return total_loss / max(1, updates)

    def _train_lora_group_objective(
        self, batches: list[dict[str, Any]], *, lr: float
    ) -> float:
        """Apply one group-normalized policy-gradient optimizer step.

        Every candidate loss is evaluated under the same pre-update policy.  We
        accumulate the mean signed objective's gradients and call optimizer.step
        exactly once, so candidate iteration order cannot change which policy
        evaluates later candidates.  This is REINFORCE-style group-normalized PG;
        it intentionally does not claim canonical GRPO's old-policy ratio/KL.
        """
        import torch

        if not self.parameter_updates_enabled:
            raise RuntimeError(
                "Parameter update attempted while runtime updates are frozen"
            )
        assert self._model is not None
        model = self._model
        model.train()
        params = [p for p in model.parameters() if p.requires_grad]
        if not params:
            raise RuntimeError("No trainable LoRA parameters found for TTT update")

        prepared: list[tuple[list[int], int | None, float]] = []
        for batch in batches:
            ids = batch["ids"]
            if len(ids) < 2:
                continue
            offset = max(0, len(ids) - self.ttt_max_tokens)
            trimmed = ids[-self.ttt_max_tokens :]
            prompt_tokens = batch.get("prompt_tokens")
            ignored: int | None = None
            if prompt_tokens is not None:
                ignored = max(0, min(len(trimmed), int(prompt_tokens) - offset))
                if ignored >= len(trimmed):
                    continue
            prepared.append((trimmed, ignored, float(batch.get("signed_weight", 1.0))))
        if not prepared:
            model.eval()
            raise RuntimeError("No valid candidate batches for group objective")

        # Emit the bounded-memory execution plan before the first model forward.
        # This deliberately contains only token counts, never prompt/candidate text,
        # so an OOM or other forward failure still leaves useful audit evidence.
        candidate_token_stats = []
        for trimmed, ignored, _signed_weight in prepared:
            prompt_tokens_retained = max(0, int(ignored or 0))
            target_start = max(1, prompt_tokens_retained)
            candidate_token_stats.append(
                {
                    "trimmed_tokens": len(trimmed),
                    "prompt_tokens_retained": prompt_tokens_retained,
                    "target_tokens": len(trimmed) - target_start,
                }
            )
        print(
            "GROUP_PG_TRAINER "
            + json.dumps(
                {
                    "candidate_token_stats": candidate_token_stats,
                    "group_size": len(prepared),
                    "logit_chunk_tokens": _GROUP_PG_LOGIT_CHUNK_TOKENS,
                    "logits_to_keep": 1,
                    "strategy": _GROUP_PG_LOGIT_STRATEGY,
                },
                sort_keys=True,
            ),
            flush=True,
        )

        # Resolve the decoder and frozen output projection through the PEFT wrapper.
        # Qwen's native `logits_to_keep` avoids the full [sequence, vocab] tensor,
        # while the decoder hook gives us the complete hidden sequence needed for
        # exact prompt-masked causal CE.
        get_base_model = getattr(model, "get_base_model", None)
        base_lm = get_base_model() if callable(get_base_model) else model
        decoder = getattr(base_lm, "model", None)
        if decoder is None or not hasattr(decoder, "register_forward_hook"):
            raise RuntimeError(
                "Group objective requires a causal LM with a hookable decoder"
            )
        get_output_embeddings = getattr(model, "get_output_embeddings", None)
        if callable(get_output_embeddings):
            output_embeddings = get_output_embeddings()
        else:
            base_get_output_embeddings = getattr(base_lm, "get_output_embeddings", None)
            output_embeddings = (
                base_get_output_embeddings()
                if callable(base_get_output_embeddings)
                else None
            )
        if output_embeddings is None:
            raise RuntimeError(
                "Group objective requires a causal LM output embedding projection"
            )
        if any(param.requires_grad for param in output_embeddings.parameters()):
            raise RuntimeError(
                "Chunked group objective requires frozen output embeddings"
            )

        # Non-reentrant checkpointing supports LoRA parameters even though the base
        # embeddings are frozen, and only affects this explicitly selected trainer.
        gradient_checkpointing_enable = getattr(
            model, "gradient_checkpointing_enable", None
        )
        if callable(gradient_checkpointing_enable):
            try:
                gradient_checkpointing_enable(
                    gradient_checkpointing_kwargs={"use_reentrant": False}
                )
            except TypeError:
                gradient_checkpointing_enable()

        optimizer = torch.optim.AdamW(params, lr=lr)
        optimizer.zero_grad(set_to_none=True)
        device = next(model.parameters()).device
        objective_value = 0.0
        group_size = len(prepared)
        try:
            for trimmed, ignored, signed_weight in prepared:
                input_ids = torch.tensor([trimmed], device=device)
                captured_hidden: list[Any] = []

                def capture_decoder_hidden(
                    _module: Any, _inputs: Any, output: Any
                ) -> None:
                    hidden = getattr(output, "last_hidden_state", None)
                    if hidden is None and isinstance(output, (tuple, list)):
                        hidden = output[0]
                    if hidden is None:
                        raise RuntimeError(
                            "Decoder hook did not receive last_hidden_state"
                        )
                    captured_hidden.append(hidden)

                hook = decoder.register_forward_hook(capture_decoder_hidden)
                try:
                    # PEFT remains in the forward path (LoRA/prefix semantics are
                    # preserved), but Qwen only projects the final hidden token here.
                    forward_outputs = model(
                        input_ids=input_ids,
                        labels=None,
                        use_cache=False,
                        logits_to_keep=1,
                        return_dict=True,
                    )
                finally:
                    hook.remove()
                if len(captured_hidden) != 1:
                    raise RuntimeError(
                        "Expected exactly one decoder hidden-state capture, got "
                        f"{len(captured_hidden)}"
                    )
                hidden_states = captured_hidden.pop()
                del forward_outputs

                prompt_tokens_retained = max(0, int(ignored or 0))
                target_start = max(1, prompt_tokens_retained)
                target_count = len(trimmed) - target_start
                if target_count <= 0:
                    raise RuntimeError(
                        "Prepared group candidate has no causal target tokens"
                    )

                # Build d(objective)/d(decoder_hidden) without ever retaining more
                # than one small [chunk, vocab] projection. The output projection is
                # frozen, so this is exactly equivalent to a full-logits CE backward.
                hidden_gradient = torch.zeros_like(hidden_states)
                candidate_loss_sum = 0.0
                for chunk_start in range(0, target_count, _GROUP_PG_LOGIT_CHUNK_TOKENS):
                    chunk_end = min(
                        target_count,
                        chunk_start + _GROUP_PG_LOGIT_CHUNK_TOKENS,
                    )
                    prediction_start = target_start - 1 + chunk_start
                    prediction_end = target_start - 1 + chunk_end
                    prediction_hidden = hidden_states[
                        :, prediction_start:prediction_end, :
                    ]
                    targets = input_ids[
                        :, target_start + chunk_start : target_start + chunk_end
                    ]
                    chunk_logits = output_embeddings(prediction_hidden)
                    chunk_loss_sum = torch.nn.functional.cross_entropy(
                        chunk_logits.float().reshape(-1, chunk_logits.shape[-1]),
                        targets.reshape(-1),
                        reduction="sum",
                    )
                    (chunk_hidden_gradient,) = torch.autograd.grad(
                        chunk_loss_sum, prediction_hidden
                    )
                    hidden_gradient[:, prediction_start:prediction_end, :].add_(
                        chunk_hidden_gradient,
                        alpha=signed_weight / (group_size * target_count),
                    )
                    candidate_loss_sum += float(chunk_loss_sum.detach().cpu())
                    del (
                        chunk_hidden_gradient,
                        chunk_logits,
                        chunk_loss_sum,
                        prediction_hidden,
                        targets,
                    )

                hidden_states.backward(hidden_gradient)
                objective_value += (
                    signed_weight * candidate_loss_sum / target_count / group_size
                )
                del hidden_gradient, hidden_states, input_ids
            torch.nn.utils.clip_grad_norm_(params, 1.0)
            optimizer.step()
            self.grpo_optimizer_steps += 1
            self._clip_trainable_param_norms(params)
        finally:
            model.eval()
        return objective_value

    def _clip_trainable_param_norms(self, params: list[Any]) -> None:
        if self.lora_param_norm_clip <= 0:
            return
        import torch

        max_norm = float(self.lora_param_norm_clip)
        with torch.no_grad():
            for param in params:
                norm = param.data.norm()
                if norm > max_norm:
                    param.data.mul_(max_norm / (norm + 1e-12))

    def _remember_last_action_training_example(
        self, prompt: str, assistant_record: str
    ) -> None:
        tokenizer = self._load_tokenizer()
        prompt_ids = tokenizer.encode(prompt, add_special_tokens=False)
        assistant_ids = tokenizer.encode(
            assistant_record + (tokenizer.eos_token or ""),
            add_special_tokens=False,
        )
        self._last_action_training_ids = prompt_ids + assistant_ids
        self._last_action_prompt_tokens = len(prompt_ids)

    def _adapt_from_feedback(self, observation: Observation) -> None:
        if self.method != "ttt_rl" or self.reward_pg_steps == 0:
            return
        if self._uses_instance_group_pg():
            # D2: instance group-normalized PG replaces per-step moving-average PG
            # (which conflates instance difficulty with policy quality). The
            # update fires in _env_best_of_n_train over the candidate group.
            return
        if self._last_action_training_ids is None:
            return
        if observation.instance_complete and not self.reward_update_terminal:
            return
        reward = self._infer_feedback_reward(observation)
        self.last_feedback_reward = reward
        if reward == 0:
            return

        signed_weight = self._signed_weight_from_reward(reward)
        if signed_weight == 0:
            return

        self._ensure_lora_model()
        previous_steps = self.ttt_steps
        try:
            self.ttt_steps = self.reward_pg_steps
            self.last_reward_pg_loss = self._train_lora_token_batches(
                [
                    {
                        "ids": self._last_action_training_ids,
                        "prompt_tokens": self._last_action_prompt_tokens,
                        "signed_weight": signed_weight,
                    }
                ],
                lr=self.reward_pg_lr,
            )
        finally:
            self.ttt_steps = previous_steps

        self.reward_pg_updates += 1
        if signed_weight > 0:
            self.reward_pg_positive_updates += 1
        else:
            self.reward_pg_negative_updates += 1

    def _signed_weight_from_reward(self, reward: float) -> float:
        if self.reward_update_rule == "reward_pg":
            self.last_reward_advantage = reward
            self.last_reward_clipped_advantage = None
            self._append_reward_history(reward)
            return (
                self.reward_positive_weight
                if reward > 0
                else -self.reward_negative_weight
            )

        baseline_window = self._reward_history[-self.reward_advantage_window :]
        baseline = (
            sum(baseline_window) / len(baseline_window) if baseline_window else 0.0
        )
        advantage = reward - baseline
        self.last_reward_advantage = advantage
        self.last_reward_clipped_advantage = None
        self._append_reward_history(reward)

        if self.reward_update_rule == "grpo":
            if advantage > 0:
                return advantage * self.reward_positive_weight
            if advantage < 0:
                return advantage * self.reward_negative_weight
            return 0.0

        if self.reward_update_rule == "grpo_norm":
            # GRPO-style normalized advantage: (reward - mean) / std.
            # Raw advantages on env rewards are tiny (~0.05) so the sign-only /
            # unnormalized rules barely learn at low lr; normalizing makes the
            # update scale-invariant and reinforces only above-average actions.
            if len(baseline_window) >= 2:
                mean_w = baseline
                var = sum((r - mean_w) ** 2 for r in baseline_window) / len(
                    baseline_window
                )
                std = var**0.5
            else:
                std = 0.0
            norm_adv = advantage / (std + 1e-6) if std > 1e-6 else advantage
            norm_adv = max(min(norm_adv, 2.0), -2.0)
            self.last_reward_clipped_advantage = norm_adv
            if norm_adv > 0:
                return norm_adv * self.reward_positive_weight
            if norm_adv < 0:
                return norm_adv * self.reward_negative_weight
            return 0.0

        if self.reward_update_rule == "dapo":
            if advantage <= 0:
                return 0.0
            return min(advantage, 1.0) * self.reward_positive_weight

        if self.reward_update_rule == "ppo_clip":
            clipped_advantage = max(
                min(advantage, self.reward_ppo_clip), -self.reward_ppo_clip
            )
            self.last_reward_clipped_advantage = clipped_advantage
            if clipped_advantage > 0:
                return clipped_advantage * self.reward_positive_weight
            if clipped_advantage < 0:
                return clipped_advantage * self.reward_negative_weight
            return 0.0

        raise ValueError(f"Unsupported reward_update_rule={self.reward_update_rule!r}")

    def _append_reward_history(self, reward: float) -> None:
        self._reward_history.append(float(reward))
        keep = max(self.reward_advantage_window * 2, self.reward_advantage_window)
        if len(self._reward_history) > keep:
            self._reward_history = self._reward_history[-keep:]

    def _infer_feedback_reward(self, observation: Observation) -> float:
        if self.reward_judge_provider == "env":
            return self._infer_feedback_reward_env(observation)
        if self.reward_judge_provider == "openai":
            return self._infer_feedback_reward_openai(observation)
        if self.reward_judge_provider == "openrouter":
            return self._infer_feedback_reward_openrouter(observation)
        if self.reward_judge_provider == "self":
            return self._infer_feedback_reward_self(observation)

        metadata = observation.metadata or {}
        for key in ("reward", "score", "raw_metric_value"):
            value = metadata.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if value > 0:
                    return 1.0
                if value < 0:
                    return -1.0
                if observation.instance_complete:
                    return -1.0
                return 0.0
        success = metadata.get("success")
        if isinstance(success, bool):
            return 1.0 if success else -1.0

        text = observation.content.lower()
        numeric_reward = self._numeric_feedback_value(text)
        if numeric_reward is not None:
            if numeric_reward > 0:
                return 1.0
            if numeric_reward < 0:
                return -1.0
            return -1.0 if observation.instance_complete else 0.0

        negative_patterns = (
            "incorrect",
            "not correct",
            "wrong",
            "invalid",
            "failed",
            "failure",
            "error",
            "exception",
            "traceback",
            "sql error",
            "timed out",
            "not valid",
            "lost",
        )
        if any(pattern in text for pattern in negative_patterns):
            return -1.0

        positive_patterns = (
            "correct",
            "success",
            "passed",
            "accepted",
            "valid",
            "won",
        )
        if any(pattern in text for pattern in positive_patterns):
            return 1.0
        return 0.0

    def _infer_feedback_reward_env(self, observation: Observation) -> float:
        metadata = observation.metadata or {}
        value = metadata.get("env_feedback_reward")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            if not observation.instance_complete:
                return 0.0
            raise RuntimeError(
                "reward_judge_provider='env' requires runner-provided "
                "env_feedback_reward metadata"
            )
        return float(value)

    def _infer_feedback_reward_self(self, observation: Observation) -> float:
        # Dense process reward: ask the locally loaded model to rate the quality
        # of its own most-recent action, giving a reward at every step instead of
        # only at instance completion (which is all env reward provides on
        # sales/cohort). Caveat: the same adapter is both trained and judging, so
        # this is a self-evaluation with possible bias/circularity.
        if self._last_action_training_ids is None:
            return 0.0
        action = ""
        for message in reversed(self.messages):
            if message["role"] == "assistant":
                action = message["content"]
                break
        if not action.strip():
            return 0.0
        meta = observation.metadata or {}
        public_meta = {
            key: meta[key]
            for key in ("success", "format_valid", "timed_out", "raw_metric_value")
            if key in meta
        }
        feedback = observation.content.strip()
        judge_prompt = (
            "You are a strict evaluator. Rate how good the assistant's most recent "
            "action was for making progress on the task, using any feedback. Reply "
            'with ONLY a JSON object {"score": x} where x is a number from -1 '
            "(harmful) to 1 (excellent); 0 means mediocre.\n"
            f"action={action[:1500]!r}\n"
            f"feedback={feedback[:800]!r}\n"
            f"public_metadata={json.dumps(public_meta, ensure_ascii=False)}"
        )
        try:
            raw_text, _ = self._generate_text(judge_prompt, max_new_tokens=24)
        except Exception:
            return 0.0
        self.last_reward_judge_raw = raw_text[:1000]
        return self._parse_self_judge_score(raw_text)

    def _parse_self_judge_score(self, raw_text: str) -> float:
        text = self._strip_think(raw_text).strip()
        score: float | None = None
        try:
            start = text.index("{")
            end = text.index("}", start) + 1
            parsed = json.loads(text[start:end])
            value = parsed.get("score")
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                score = float(value)
        except (ValueError, json.JSONDecodeError):
            score = None
        if score is None:
            match = re.search(r"-?\d+(?:\.\d+)?", text)
            if match:
                score = float(match.group())
        if score is None:
            return 0.0
        return max(-1.0, min(1.0, score))

    def _distill_from_critic(self, observation: Observation) -> None:
        # Find the most recent (user query, assistant answer) pair.
        query_text = ""
        answer_text = ""
        for idx in range(len(self.messages) - 1, -1, -1):
            if self.messages[idx]["role"] == "assistant" and not answer_text:
                answer_text = self.messages[idx]["content"]
                if idx > 0 and self.messages[idx - 1]["role"] == "user":
                    query_text = self.messages[idx - 1]["content"]
                break
        if not answer_text.strip() or not query_text.strip():
            return
        improved = self._critic_improved_answer(query_text, answer_text, observation)
        if (
            not improved
            or not improved.strip()
            or improved.strip() == answer_text.strip()
        ):
            return

        prompt_text = self._render_generation_prompt(
            [{"role": "user", "content": query_text}]
        )
        # Positive: pull the adapter toward the critic-improved answer.
        batches = []
        pos = self._build_distill_batch(
            prompt_text, improved, self.reward_positive_weight
        )
        if pos is None:
            return
        batches.append(pos)
        # Contrastive: also push the adapter AWAY from the original (worse) answer,
        # so the textual gradient (worse -> better) becomes a directional parameter
        # update (a simplified preference/DPO-style step), not one-sided SFT.
        if self.distill_contrastive and self.reward_negative_weight > 0:
            neg = self._build_distill_batch(
                prompt_text, answer_text, -self.reward_negative_weight
            )
            if neg is not None:
                batches.append(neg)
        self._ensure_lora_model()
        self.last_adaptation_loss = self._train_lora_token_batches(
            batches, lr=self.reward_pg_lr
        )
        self.distill_updates = getattr(self, "distill_updates", 0) + 1
        print(
            f"[distill] provider={self.distill_provider} "
            f"contrastive={self.distill_contrastive} batches={len(batches)} "
            f"update#{self.distill_updates} loss={self.last_adaptation_loss}",
            flush=True,
        )

    def _build_distill_batch(
        self, prompt_text: str, answer_text: str, signed_weight: float
    ) -> dict[str, Any] | None:
        tokenizer = self._load_tokenizer()
        target_text = answer_text.strip() + (tokenizer.eos_token or "")
        prompt_ids = tokenizer.encode(prompt_text, add_special_tokens=False)
        target_ids = tokenizer.encode(target_text, add_special_tokens=False)
        if not target_ids:
            return None
        ids = prompt_ids + target_ids
        prompt_tokens = len(prompt_ids)
        if len(ids) > self.ttt_max_tokens:
            offset = len(ids) - self.ttt_max_tokens
            ids = ids[-self.ttt_max_tokens :]
            prompt_tokens = max(0, prompt_tokens - offset)
        if len(ids) < 8:
            return None
        return {
            "ids": ids,
            "prompt_tokens": prompt_tokens,
            "signed_weight": signed_weight,
        }

    def _critic_improved_answer(
        self, query_text: str, answer_text: str, observation: Observation
    ) -> str | None:
        meta = observation.metadata or {}
        # Exclude raw_metric_value to avoid leaking the held-out target.
        public_meta = {
            key: meta[key]
            for key in ("success", "format_valid", "timed_out")
            if key in meta
        }
        prompt = (
            "You are an expert assistant improving a previous answer to a task. "
            "Given the task and the prior answer (with only its public outcome "
            "flags, NOT the ground truth), produce a better answer in the SAME "
            "format. Do not invent facts. Reply with ONLY a JSON object "
            '{"improved_answer": "..."}.\n'
            f"task={query_text[:2000]!r}\n"
            f"prior_answer={answer_text[:1500]!r}\n"
            f"public_outcome={json.dumps(public_meta, ensure_ascii=False)}"
        )
        if self.distill_provider == "self":
            try:
                raw, _ = self._generate_text(
                    prompt, max_new_tokens=self.action_max_new_tokens
                )
            except Exception:
                return None
            return self._extract_improved_answer(self._strip_think(raw))
        if self.distill_provider == "gpt":
            return self._critic_improved_answer_gpt(prompt)
        return None

    def _critic_improved_answer_gpt(self, prompt: str) -> str | None:
        raw_text = self._gpt_responses_text(prompt, max_output_tokens=1024)
        if raw_text is None:
            return None
        return self._extract_improved_answer(raw_text)

    def _gpt_responses_text(self, prompt: str, max_output_tokens: int) -> str | None:
        api_key = os.environ.get(self.reward_judge_api_key_env)
        if not api_key:
            return None
        try:
            payload = {
                "model": self.reward_judge_model,
                "input": prompt,
                "max_output_tokens": max_output_tokens,
                "text": {"format": {"type": "json_object"}},
            }
            response_payload = self._reward_judge_request_json(
                f"{self.reward_judge_base_url}/responses",
                payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                provider_label="OpenAI",
            )
            return self._extract_responses_text(response_payload)
        except Exception:
            return None

    def _score_text(self, query_text: str, candidate_text: str) -> float:
        prompt = (
            "Rate how good this candidate answer is for the task. Reply with ONLY "
            'a JSON object {"score": x} where x is a number from -1 (bad) to 1 '
            "(excellent).\n"
            f"task={query_text[:1500]!r}\n"
            f"candidate={candidate_text[:1500]!r}"
        )
        if self.distill_provider == "gpt":
            raw = self._gpt_responses_text(prompt, max_output_tokens=24)
            return self._parse_self_judge_score(raw) if raw else 0.0
        try:
            raw, _ = self._generate_text(prompt, max_new_tokens=24)
        except Exception:
            return 0.0
        return self._parse_self_judge_score(raw)

    def _best_of_n_update(
        self,
        prompt_for_attempt: str,
        generation_prefix: str,
        primary_answer: str,
        query_text: str,
        schema: type[BaseModel],
        max_new_tokens: int,
    ) -> None:
        candidates = [primary_answer]
        saved_temp = self.temperature
        try:
            self.temperature = self.bon_temperature if self.bon_temperature > 0 else 0.8
            for _ in range(self.best_of_n - 1):
                try:
                    raw, _ = self._generate_text(
                        prompt_for_attempt + generation_prefix,
                        max_new_tokens=max_new_tokens,
                    )
                except Exception:
                    continue
                raw = self._merge_generation_prefix(generation_prefix, raw)
                cleaned = self._strip_think(raw).strip()
                try:
                    parsed, _ = self._parse_action(cleaned, schema)
                    candidates.append(parsed.model_dump_json())
                except Exception:
                    continue
        finally:
            self.temperature = saved_temp

        uniq: list[str] = []
        for cand in candidates:
            if cand not in uniq:
                uniq.append(cand)
        if len(uniq) < 2:
            return
        scored = sorted(
            ((self._score_text(query_text, cand), cand) for cand in uniq),
            key=lambda item: item[0],
            reverse=True,
        )
        best_score, best = scored[0]
        worst_score, worst = scored[-1]
        prompt_text = self._render_generation_prompt(
            [{"role": "user", "content": query_text}]
        )
        batches = []
        pos = self._build_distill_batch(prompt_text, best, self.reward_positive_weight)
        if pos is None:
            return
        batches.append(pos)
        if (
            self.distill_contrastive
            and self.reward_negative_weight > 0
            and worst != best
        ):
            neg = self._build_distill_batch(
                prompt_text, worst, -self.reward_negative_weight
            )
            if neg is not None:
                batches.append(neg)
        self._ensure_lora_model()
        self.last_adaptation_loss = self._train_lora_token_batches(
            batches, lr=self.reward_pg_lr
        )
        self.bon_updates = getattr(self, "bon_updates", 0) + 1
        print(
            f"[bon] n={self.best_of_n} cands={len(uniq)} best={best_score:.3f} "
            f"worst={worst_score:.3f} batches={len(batches)} update#{self.bon_updates}",
            flush=True,
        )

    def _stash_env_bon_candidates(
        self,
        prompt_for_attempt: str,
        generation_prefix: str,
        primary_answer: str,
        query_text: str,
        schema: type[BaseModel],
        max_new_tokens: int,
        *,
        force_sample: bool = False,
        primary_continuation: str | None = None,
        instance_index: int | None = None,
        instance_id: str | None = None,
        interaction_step: int | None = None,
        sampling_seed: int | None = None,
    ) -> None:
        if self._uses_instance_group_pg() and not force_sample:
            # Tool-using tasks may take dozens of nonterminal command steps. The
            # old eager path generated K-1 candidates at every step even though
            # each pending group was overwritten by the next response and only
            # the terminal group could ever be scored. Save the pre-commit prompt
            # now and generate that one useful group at terminal observe().
            seed_step = (
                self.interaction_count
                if interaction_step is None
                else int(interaction_step)
            )
            sampling_seed = self._derive_grpo_candidate_seed(
                instance_index=instance_index,
                instance_id=instance_id,
                interaction_step=seed_step,
            )
            sampling_prompt = prompt_for_attempt + generation_prefix
            self._pending_env_bon = {
                "query_text": query_text,
                "candidates": [primary_answer],
                "schema": schema,
                "grpo_run_seed": self.grpo_run_seed,
                "grpo_adapter_init_seed": self.grpo_adapter_init_seed,
                "seed_instance_index": instance_index,
                "seed_instance_id": instance_id,
                "seed_interaction_step": seed_step,
                "sampling_seed": sampling_seed,
                "candidate_proposer": self.grpo_candidate_proposer,
                "objective": self._grpo_objective_name(),
                "sampling_prompt_sha256": hashlib.sha256(
                    sampling_prompt.encode("utf-8")
                ).hexdigest(),
                "lazy_generation": {
                    "prompt_for_attempt": prompt_for_attempt,
                    "generation_prefix": generation_prefix,
                    "primary_continuation": (
                        primary_answer
                        if primary_continuation is None
                        else primary_continuation
                    ),
                    "max_new_tokens": max_new_tokens,
                    "sampling_seed": sampling_seed,
                    "candidate_proposer": self.grpo_candidate_proposer,
                    "objective": self._grpo_objective_name(),
                    "update_signature": self._grpo_update_signature(),
                },
            }
            return
        if (
            self._uses_instance_group_pg()
            and self.grpo_candidate_proposer == "unit_interval_jitter"
        ):
            self._stash_unit_interval_jitter_candidates(
                prompt_for_attempt,
                generation_prefix,
                primary_answer,
                query_text,
                schema,
                primary_continuation=primary_continuation,
                sampling_seed=(
                    self.grpo_run_seed if sampling_seed is None else sampling_seed
                ),
            )
            return
        candidate_records = [
            {
                "answer": primary_answer,
                "continuation": (
                    primary_answer
                    if primary_continuation is None
                    else primary_continuation
                ),
            }
        ]
        generation_failures = 0
        parse_failures = 0
        initial_sample_attempts = 0
        rescue_sample_attempts = 0

        def sample_candidate() -> None:
            nonlocal generation_failures, parse_failures
            try:
                continuation, _ = self._generate_text(
                    prompt_for_attempt + generation_prefix,
                    max_new_tokens=max_new_tokens,
                )
            except Exception:
                generation_failures += 1
                return
            raw = self._merge_generation_prefix(generation_prefix, continuation)
            cleaned = self._strip_think(raw).strip()
            try:
                parsed, _ = self._parse_action(cleaned, schema)
            except Exception:
                parse_failures += 1
                return
            candidate_records.append(
                {
                    "answer": parsed.model_dump_json(),
                    "continuation": continuation,
                }
            )

        def valid_unique_count() -> int:
            return len({record["answer"] for record in candidate_records})

        saved_temp = self.temperature
        try:
            self.temperature = self.bon_temperature if self.bon_temperature > 0 else 0.8
            for _ in range(self.best_of_n - 1):
                initial_sample_attempts += 1
                sample_candidate()

            # A degenerate group cannot produce a normalized group-PG update. Keep
            # the original K-1 draws intact, then (only for instance group-PG) use
            # at most one more bounded K-1 segment of the same deterministic RNG
            # stream. Stop as soon as a second unique parsed action exists. The
            # primary action plus that rescue action still fits within best_of_n.
            if self._uses_instance_group_pg() and valid_unique_count() < 2:
                for _ in range(self.best_of_n - 1):
                    rescue_sample_attempts += 1
                    sample_candidate()
                    if valid_unique_count() >= 2:
                        break
        finally:
            self.temperature = saved_temp
        unique_records: list[dict[str, str]] = []
        seen_answers: set[str] = set()
        for record in candidate_records:
            answer = record["answer"]
            if answer not in seen_answers:
                seen_answers.add(answer)
                unique_records.append(record)
        uniq = [record["answer"] for record in unique_records]
        self._pending_env_bon = {
            "query_text": query_text,
            "candidates": uniq,
            "schema": schema,
            "instance_index": instance_index,
            "instance_id": instance_id,
            "interaction_step": interaction_step,
            "registered_run_seed": self.grpo_run_seed,
            "sampling_prompt_sha256": hashlib.sha256(
                (prompt_for_attempt + generation_prefix).encode("utf-8")
            ).hexdigest(),
            "candidate_sampling": {
                "requested_group_size": self.best_of_n,
                "initial_sample_attempts": initial_sample_attempts,
                "rescue_sample_attempts": rescue_sample_attempts,
                "generation_failures": generation_failures,
                "parse_failures": parse_failures,
                "duplicates": len(candidate_records) - len(unique_records),
                "valid_unique": len(unique_records),
                "candidate_count": len(uniq),
            },
        }
        if self._uses_instance_group_pg():
            self._pending_env_bon.update(
                {
                    "prompt_for_attempt": prompt_for_attempt,
                    "generation_prefix": generation_prefix,
                    "candidate_records": unique_records,
                    "sampling_prompt_sha256": hashlib.sha256(
                        (prompt_for_attempt + generation_prefix).encode("utf-8")
                    ).hexdigest(),
                    "candidate_proposer": self.grpo_candidate_proposer,
                    "objective": self._grpo_objective_name(),
                    "candidate_sampling": {
                        "requested_group_size": self.best_of_n,
                        "initial_sample_attempts": initial_sample_attempts,
                        "rescue_sample_attempts": rescue_sample_attempts,
                        "sample_attempts": (
                            initial_sample_attempts + rescue_sample_attempts
                        ),
                        "generation_failures": generation_failures,
                        "parse_failures": parse_failures,
                        "duplicates": len(candidate_records) - len(unique_records),
                        "valid_unique": len(unique_records),
                    },
                }
            )

    def _stash_unit_interval_jitter_candidates(
        self,
        prompt_for_attempt: str,
        generation_prefix: str,
        primary_answer: str,
        query_text: str,
        schema: type[BaseModel],
        *,
        primary_continuation: str | None,
        sampling_seed: int,
    ) -> None:
        """Build a bounded, pre-reward local proposal group for flat survival data.

        These candidates are deliberately not described as policy samples.  They
        form an opt-in candidate-distillation objective around the committed
        report, with deterministic candidate-local RNG streams and no model calls.
        """
        primary_model = schema.model_validate_json(primary_answer)
        primary_data = primary_model.model_dump(mode="json")
        self._validate_unit_interval_triplet_payload(primary_data)

        primary_identity = self._canonical_candidate_identity(primary_answer, schema)
        candidate_records: list[dict[str, Any]] = [
            {
                "answer": primary_answer,
                "continuation": (
                    self._continuation_after_generation_prefix(
                        primary_answer, generation_prefix
                    )
                    if primary_continuation is None
                    else primary_continuation
                ),
                "source": "primary_policy",
            }
        ]
        seen_identities = {primary_identity}
        initial_sample_attempts = 0
        rescue_sample_attempts = 0
        parse_failures = 0
        duplicates = 0
        proposal_seed_digests: list[str] = []

        def propose(attempt_index: int) -> None:
            nonlocal parse_failures, duplicates
            proposal_seed = self._derive_grpo_proposal_seed(
                sampling_seed=sampling_seed,
                attempt_index=attempt_index,
            )
            proposal_seed_digests.append(
                hashlib.sha256(str(proposal_seed).encode("ascii")).hexdigest()
            )
            try:
                answer = self._unit_interval_jitter_candidate(
                    primary_data,
                    schema,
                    proposal_seed=proposal_seed,
                )
                identity = self._canonical_candidate_identity(answer, schema)
            except Exception:
                parse_failures += 1
                return
            if identity in seen_identities:
                duplicates += 1
                return
            continuation = self._continuation_after_generation_prefix(
                answer, generation_prefix
            )
            roundtrip = generation_prefix + continuation
            if self._canonical_candidate_identity(roundtrip, schema) != identity:
                raise RuntimeError(
                    "Structured candidate prefix/continuation round-trip mismatch"
                )
            seen_identities.add(identity)
            candidate_records.append(
                {
                    "answer": answer,
                    "continuation": continuation,
                    "source": "unit_interval_jitter",
                    "attempt_index": attempt_index,
                    "proposal_seed": proposal_seed,
                }
            )

        attempt_index = 0
        for _ in range(self.best_of_n - 1):
            initial_sample_attempts += 1
            propose(attempt_index)
            attempt_index += 1
        if len(candidate_records) < self.best_of_n:
            for _ in range(self.best_of_n - 1):
                rescue_sample_attempts += 1
                propose(attempt_index)
                attempt_index += 1
                if len(candidate_records) >= self.best_of_n:
                    break

        sample_attempts = initial_sample_attempts + rescue_sample_attempts
        if len(proposal_seed_digests) != sample_attempts or len(
            set(proposal_seed_digests)
        ) != len(proposal_seed_digests):
            raise RuntimeError("Structured proposal seeds must be unique per attempt")
        self._pending_env_bon = {
            "query_text": query_text,
            "candidates": [record["answer"] for record in candidate_records],
            "schema": schema,
            "prompt_for_attempt": prompt_for_attempt,
            "generation_prefix": generation_prefix,
            "candidate_records": candidate_records,
            "sampling_prompt_sha256": hashlib.sha256(
                (prompt_for_attempt + generation_prefix).encode("utf-8")
            ).hexdigest(),
            "candidate_proposer": self.grpo_candidate_proposer,
            "objective": self._grpo_objective_name(),
            "candidate_sampling": {
                "candidate_proposer": self.grpo_candidate_proposer,
                "proposal_seed_scheme": "blake2b(base_sampling_seed,attempt_index)",
                "proposal_jitter_scale": _GROUP_PG_PROPOSAL_JITTER_SCALE,
                "proposal_seed_digests": proposal_seed_digests,
                "model_generation_attempts": 0,
                "structured_proposal_attempts": sample_attempts,
                "requested_group_size": self.best_of_n,
                "target_valid_unique": self.best_of_n,
                "max_sample_attempts": 2 * (self.best_of_n - 1),
                "initial_sample_attempts": initial_sample_attempts,
                "rescue_sample_attempts": rescue_sample_attempts,
                "sample_attempts": sample_attempts,
                "generation_failures": 0,
                "parse_failures": parse_failures,
                "duplicates": duplicates,
                "valid_unique": len(candidate_records),
                "proposal_mode_counts": {
                    "primary_policy": 1,
                    "unit_interval_jitter": len(candidate_records) - 1,
                },
            },
        }

    @staticmethod
    def _derive_grpo_proposal_seed(*, sampling_seed: int, attempt_index: int) -> int:
        payload = json.dumps(
            {
                "sampling_seed": int(sampling_seed),
                "attempt_index": int(attempt_index),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.blake2b(payload, digest_size=8, person=b"clb-gpprop").digest()
        return int.from_bytes(digest, "big") & ((1 << 63) - 1)

    @staticmethod
    def _validate_unit_interval_triplet_payload(data: Any) -> None:
        if not isinstance(data, dict) or not data:
            raise ValueError(
                "unit_interval_jitter requires a non-empty flat JSON object"
            )
        grouped: dict[str, set[str]] = {}
        for key, value in data.items():
            if not isinstance(key, str):
                raise ValueError("unit_interval_jitter requires string field names")
            match = re.fullmatch(r"(.+)__s(12|24|36)", key)
            if match is None:
                raise ValueError(
                    "unit_interval_jitter requires complete __s12/__s24/__s36 "
                    f"triplets; unsupported field={key!r}"
                )
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    "unit_interval_jitter requires numeric unit-interval fields"
                )
            numeric = float(value)
            if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
                raise ValueError(
                    "unit_interval_jitter requires finite values in [0, 1]"
                )
            grouped.setdefault(match.group(1), set()).add(match.group(2))
        incomplete = sorted(
            prefix
            for prefix, horizons in grouped.items()
            if horizons != {"12", "24", "36"}
        )
        if incomplete:
            raise ValueError(
                "unit_interval_jitter requires complete survival triplets; "
                f"incomplete={incomplete[:5]}"
            )

    @staticmethod
    def _canonical_candidate_identity(answer: str, schema: type[BaseModel]) -> str:
        parsed = schema.model_validate_json(answer)
        return json.dumps(
            parsed.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _continuation_after_generation_prefix(answer: str, prefix: str) -> str:
        stripped = answer.lstrip()
        if prefix and stripped.startswith(prefix):
            return stripped[len(prefix) :]
        return answer

    def _unit_interval_jitter_candidate(
        self,
        primary_data: dict[str, Any],
        schema: type[BaseModel],
        *,
        proposal_seed: int,
    ) -> str:
        self._validate_unit_interval_triplet_payload(primary_data)
        rng = random.Random(proposal_seed)
        proposed = dict(primary_data)
        prefixes = sorted({key.rsplit("__s", 1)[0] for key in primary_data})

        def logit(value: float) -> float:
            clipped = min(max(value, 1e-6), 1.0 - 1e-6)
            return math.log(clipped / (1.0 - clipped))

        def sigmoid(value: float) -> float:
            if value >= 0:
                z = math.exp(-value)
                return 1.0 / (1.0 + z)
            z = math.exp(value)
            return z / (1.0 + z)

        for prefix in prefixes:
            level_noise = rng.gauss(0.0, _GROUP_PG_PROPOSAL_JITTER_SCALE)
            slope_noise = rng.gauss(0.0, _GROUP_PG_PROPOSAL_JITTER_SCALE / 3.0)
            values = []
            for horizon, slope_sign in (("12", 1.0), ("24", 0.0), ("36", -1.0)):
                key = f"{prefix}__s{horizon}"
                shifted = logit(float(primary_data[key])) + level_noise
                shifted += slope_sign * slope_noise
                values.append(sigmoid(shifted))
            s12, s24, s36 = sorted(values, reverse=True)
            proposed[f"{prefix}__s12"] = round(s12, 6)
            proposed[f"{prefix}__s24"] = round(s24, 6)
            proposed[f"{prefix}__s36"] = round(s36, 6)

        parsed = schema.model_validate(proposed)
        answer = parsed.model_dump_json()
        self._validate_unit_interval_triplet_payload(parsed.model_dump(mode="json"))
        return answer

    def _derive_grpo_candidate_seed(
        self,
        *,
        instance_index: int | None,
        instance_id: str | None,
        interaction_step: int,
    ) -> int:
        """Derive an auditable candidate seed without Python's salted hash()."""
        payload = json.dumps(
            {
                "run_seed": self.grpo_run_seed,
                "instance_index": instance_index,
                "instance_id": "" if instance_id is None else str(instance_id),
                "interaction_step": int(interaction_step),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.blake2b(
            payload, digest_size=8, person=b"clbench-grppg"
        ).digest()
        return int.from_bytes(digest, "big") & ((1 << 63) - 1)

    def _materialize_pending_env_bon_candidates(self) -> None:
        pending = self._pending_env_bon
        if not pending:
            return
        lazy = pending.get("lazy_generation")
        candidates = pending.get("candidates")
        if (
            not isinstance(lazy, dict)
            or not isinstance(candidates, list)
            or not candidates
        ):
            return
        expected_signature = tuple(lazy.get("update_signature") or ())
        if expected_signature != self._grpo_update_signature():
            raise RuntimeError(
                "Group-PG policy changed between pre-commit recipe and terminal sampling"
            )
        if lazy.get("candidate_proposer") != self.grpo_candidate_proposer:
            raise RuntimeError(
                "Candidate proposer changed between pre-commit recipe and terminal "
                "materialization"
            )
        if lazy.get("objective") != self._grpo_objective_name():
            raise RuntimeError(
                "Instance-group objective changed between pre-commit recipe and "
                "terminal materialization"
            )

        import torch

        cuda_devices: list[int] = []
        if torch.cuda.is_available() and self._model is not None:
            device = next(self._model.parameters()).device
            if device.type == "cuda":
                cuda_devices = [
                    torch.cuda.current_device()
                    if device.index is None
                    else device.index
                ]

        timeout_s = int(os.environ.get("CLBENCH_INSTANCE_TIMEOUT", "0") or 0)
        use_alarm = (
            timeout_s > 0 and threading.current_thread() is threading.main_thread()
        )
        previous_handler = None
        if use_alarm:

            def _on_alarm(signum, frame):
                raise TimeoutError(
                    "deferred GRPO candidate generation exceeded "
                    f"CLBENCH_INSTANCE_TIMEOUT={timeout_s}s"
                )

            previous_handler = signal.signal(signal.SIGALRM, _on_alarm)
            signal.alarm(timeout_s)

        sampling_seed = int(lazy["sampling_seed"])
        seed_provenance = {
            key: pending.get(key)
            for key in (
                "grpo_run_seed",
                "grpo_adapter_init_seed",
                "seed_instance_index",
                "seed_instance_id",
                "seed_interaction_step",
                "sampling_prompt_sha256",
            )
        }
        start = time.perf_counter()
        try:
            # The seed is committed in respond(), before reward reveal. fork_rng
            # keeps deferred sampling auditable without perturbing later global
            # RNG state; the saved prompt contains no observation or ground truth.
            with torch.random.fork_rng(devices=cuda_devices):
                torch.random.default_generator.manual_seed(sampling_seed)
                if cuda_devices:
                    torch.cuda.manual_seed_all(sampling_seed)
                self._stash_env_bon_candidates(
                    str(lazy["prompt_for_attempt"]),
                    str(lazy["generation_prefix"]),
                    str(candidates[0]),
                    str(pending["query_text"]),
                    pending["schema"],
                    int(lazy["max_new_tokens"]),
                    force_sample=True,
                    primary_continuation=str(lazy["primary_continuation"]),
                    sampling_seed=sampling_seed,
                )
        finally:
            if use_alarm:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous_handler)

        elapsed = time.perf_counter() - start
        if self._pending_env_bon is not None:
            self._pending_env_bon.update(seed_provenance)
            self._pending_env_bon["sampling_seed"] = sampling_seed
            self._pending_env_bon["candidate_generation_seconds"] = round(elapsed, 6)

    def _grpo_update_signature(self) -> tuple[int, ...]:
        return (
            int(self.adaptation_count),
            int(self.reward_pg_updates),
            int(self.distill_updates),
            int(self.bon_updates),
            int(self.grpo_updates),
            int(self.grpo_optimizer_steps),
        )

    def _score_env_candidate(self, cand: str, schema, meta: dict) -> float | None:
        """Score a candidate answer on the post-commit, officially-revealed reward.
        Dispatches by which ground truth the task exposed (no held-out leakage)."""
        # sales: near-year and/or full-horizon forecast accuracy (per bon_env_reward)
        if meta.get("nearyear_gt") is not None:
            try:
                from src.tasks.sales_prediction.evaluator import (
                    score_structured_predictions,
                    score_structured_predictions_for_year,
                )

                preds = schema.model_validate_json(cand).predictions
                rf = self.bon_env_reward

                def near() -> float:
                    return score_structured_predictions_for_year(
                        preds, meta["nearyear_gt"], year=int(meta["nearyear"])
                    ).score

                def final() -> float:
                    return score_structured_predictions(preds, meta["final_gt"]).score

                if rf == "final" and meta.get("final_gt") is not None:
                    return final()
                if rf == "both" and meta.get("final_gt") is not None:
                    return 0.5 * (near() + final())
                return near()
            except Exception:
                return None
        # cohort: report vs revealed survival ground truth
        if meta.get("cohort_gt") is not None:
            try:
                from src.tasks.cohort_studies.tool_schemas import parse_flat_submission
                from src.tasks.cohort_studies.scorer import (
                    CohortGroundTruth,
                    score_cohort_report,
                )

                estimates = parse_flat_submission(schema.model_validate_json(cand))
                gt = {
                    cid: CohortGroundTruth(**g) for cid, g in meta["cohort_gt"].items()
                }
                ref = meta.get("ref_survival")
                ref = tuple(ref) if ref else None
                return score_cohort_report(estimates, gt, ref_survival=ref).score
            except Exception:
                return None
        # bsm: IoU of reported-available vs revealed long-run available spectrum
        if meta.get("bsm_gt_available") is not None:
            try:
                from src.tasks.blind_spectrum_monitoring.task import (
                    _normalize_intervals,
                    _complement_intervals,
                    _intersect_intervals,
                    _interval_set_measure,
                    _interval_bounds,
                )

                rep = schema.model_validate_json(cand)
                bw = float(meta["bsm_band_width"])
                rep_occ = _normalize_intervals(
                    [
                        _interval_bounds(t.center_freq, t.bandwidth)
                        for t in rep.transmitters
                    ],
                    band_end=bw,
                )
                rep_avail = _complement_intervals(rep_occ, band_end=bw)
                gt_avail = [tuple(iv) for iv in meta["bsm_gt_available"]]
                ov = _interval_set_measure(_intersect_intervals(gt_avail, rep_avail))
                union = (
                    _interval_set_measure(gt_avail)
                    + _interval_set_measure(rep_avail)
                    - ov
                )
                return 1.0 if union == 0.0 else ov / union
            except Exception:
                return None
        return None

    def _env_best_of_n_train(self, observation: Observation) -> None:
        pending = self._pending_env_bon
        self._pending_env_bon = None
        meta = observation.metadata or {}
        if not pending:
            return
        if len(pending["candidates"]) < 2:
            if self._uses_instance_group_pg():
                self.grpo_skipped_no_group += 1
                entry = {
                    "group_size": len(pending["candidates"]),
                    "skipped": "no_group",
                }
                self._add_grpo_sampling_provenance(entry, pending)
                self._append_grpo_log(entry)
            return
        schema = pending["schema"]
        scored = []
        for cand in pending["candidates"]:
            sc = self._score_env_candidate(cand, schema, meta)
            if sc is not None:
                scored.append((sc, cand))
        if len(scored) < 2:
            if self._uses_instance_group_pg():
                self.grpo_skipped_no_group += 1
                entry = {"group_size": len(scored), "skipped": "no_group"}
                self._add_grpo_sampling_provenance(entry, pending)
                self._append_grpo_log(entry)
            return
        if self._uses_instance_group_pg():
            self._grpo_instance_update(pending, scored)
            return
        scored.sort(key=lambda x: x[0], reverse=True)
        best_score, best = scored[0]
        worst_score, worst = scored[-1]
        prompt_text = self._render_generation_prompt(
            [{"role": "user", "content": pending["query_text"]}]
        )
        batches = []
        pos = self._build_distill_batch(prompt_text, best, self.reward_positive_weight)
        if pos is None:
            return
        batches.append(pos)
        if (
            self.distill_contrastive
            and self.reward_negative_weight > 0
            and worst != best
        ):
            neg = self._build_distill_batch(
                prompt_text, worst, -self.reward_negative_weight
            )
            if neg is not None:
                batches.append(neg)
        self._ensure_lora_model()
        self.last_adaptation_loss = self._train_lora_token_batches(
            batches, lr=self.reward_pg_lr
        )
        self.bon_updates = getattr(self, "bon_updates", 0) + 1
        print(
            f"[bon-env] n={self.best_of_n} cands={len(scored)} best={best_score:.3f} "
            f"worst={worst_score:.3f} batches={len(batches)} update#{self.bon_updates}",
            flush=True,
        )

    def _grpo_instance_update(
        self, pending: dict[str, Any], scored: list[tuple[float, str]]
    ) -> None:
        """D2: instance-level group-normalized update over an env-scored group.

        At instance completion the revealed ground truth counterfactually scores
        every stashed candidate (legal only on pure-function tasks — the extra
        candidates never touched the environment; same post-commit compliance as
        the bonenv SFT path). Policy-sampled groups use exact sampling prompts and
        continuations for a REINFORCE-style objective. Structured proposal groups
        are explicitly labelled candidate distillation, because their signed CE
        terms are off-policy and are not a policy-gradient estimator.
        """
        rewards = [reward for reward, _ in scored]
        k = len(rewards)
        mean_r = sum(rewards) / k
        var = sum((reward - mean_r) ** 2 for reward in rewards) / k
        std = var**0.5
        committed = pending["candidates"][0]
        committed_reward = next(
            (reward for reward, cand in scored if cand == committed), None
        )
        self.last_grpo_group_size = k
        self.last_grpo_reward_mean = mean_r
        self.last_grpo_reward_std = std
        self.last_grpo_committed_reward = committed_reward
        log_entry: dict[str, Any] = {
            "group_size": k,
            "reward_mean": round(mean_r, 6),
            "reward_std": round(std, 6),
            "objective": pending.get("objective", self._grpo_objective_name()),
        }
        self._add_grpo_sampling_provenance(log_entry, pending)
        if committed_reward is not None:
            log_entry["committed_reward"] = round(committed_reward, 6)
        if std <= self.grpo_std_floor:
            self.grpo_skipped_low_std += 1
            log_entry["skipped"] = "low_std"
            self._append_grpo_log(log_entry)
            print(
                f"[group-pg-inst] k={k} mean={mean_r:.4f} std={std:.6f} SKIP low_std "
                f"(floor={self.grpo_std_floor})",
                flush=True,
            )
            return
        prompt_for_attempt = pending.get("prompt_for_attempt")
        generation_prefix = pending.get("generation_prefix")
        if isinstance(prompt_for_attempt, str) and isinstance(generation_prefix, str):
            prompt_text = prompt_for_attempt + generation_prefix
        else:
            # Compatibility only for hand-built legacy unit fixtures. Actual D2
            # respond()->materialize always records the exact sampled prompt.
            prompt_text = self._render_generation_prompt(
                [{"role": "user", "content": pending["query_text"]}]
            )
            log_entry["legacy_prompt_fallback"] = True
        prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
        expected_prompt_hash = pending.get("sampling_prompt_sha256")
        if expected_prompt_hash is not None and expected_prompt_hash != prompt_hash:
            raise RuntimeError(
                "Group-PG training prompt differs from the pre-commit sampling prompt"
            )
        log_entry["sampling_prompt_sha256"] = prompt_hash
        continuation_by_answer = {
            record.get("answer"): record.get("continuation")
            for record in pending.get("candidate_records", [])
            if isinstance(record, dict)
            and isinstance(record.get("answer"), str)
            and isinstance(record.get("continuation"), str)
        }
        clip = float(self.grpo_adv_clip)
        batches = []
        for reward, cand in scored:
            advantage = (reward - mean_r) / std
            advantage = max(min(advantage, clip), -clip)
            continuation = continuation_by_answer.get(cand, cand)
            batch = self._build_distill_batch(prompt_text, continuation, advantage)
            if batch is not None:
                batches.append(batch)
        if not batches:
            self.grpo_skipped_no_group += 1
            log_entry["skipped"] = "no_batches"
            self._append_grpo_log(log_entry)
            return
        retained_prompt_tokens = [
            int(batch.get("prompt_tokens") or 0) for batch in batches
        ]
        candidate_tokens = [
            max(0, len(batch["ids"]) - retained_prompt_tokens[index])
            for index, batch in enumerate(batches)
        ]
        log_entry.update(
            {
                "candidate_tokens_min": min(candidate_tokens),
                "candidate_tokens_max": max(candidate_tokens),
                "target_tokens_min": min(candidate_tokens),
                "target_tokens_max": max(candidate_tokens),
                "prompt_tokens_retained_min": min(retained_prompt_tokens),
                "prompt_tokens_retained_max": max(retained_prompt_tokens),
                "retained_prompt_tokens_min": min(retained_prompt_tokens),
                "retained_prompt_tokens_max": max(retained_prompt_tokens),
            }
        )
        if min(retained_prompt_tokens) < 1:
            # A target-only update is not the policy gradient of the sampled
            # conditional action. Refuse to train instead of silently claiming
            # exact-prompt parity after ttt_max_tokens truncated the whole prompt.
            self.grpo_skipped_no_group += 1
            log_entry["skipped"] = "prompt_truncated"
            self._append_grpo_log(log_entry)
            print(
                "[group-pg-inst] SKIP prompt_truncated "
                f"ttt_max_tokens={self.ttt_max_tokens}",
                flush=True,
            )
            return
        self._ensure_lora_model()
        track_candidate_weights = self.grpo_candidate_proposer == "unit_interval_jitter"
        verify_frozen_weights = (
            track_candidate_weights and float(self.reward_pg_lr) == 0.0
        )
        trainable_hash_before = None
        if track_candidate_weights:
            trainable_hash_before = self._trainable_param_sha256()
            if self.grpo_trainable_param_sha256_initial is None:
                self.grpo_trainable_param_sha256_initial = trainable_hash_before
            elif (
                self.grpo_trainable_param_sha256_current is not None
                and trainable_hash_before != self.grpo_trainable_param_sha256_current
            ):
                raise RuntimeError(
                    "Candidate-distillation trainable parameters changed between "
                    "audited updates"
                )
        optimizer_steps_before = self.grpo_optimizer_steps
        self.last_grpo_loss = self._train_lora_group_objective(
            batches, lr=self.reward_pg_lr
        )
        optimizer_steps = self.grpo_optimizer_steps - optimizer_steps_before
        if optimizer_steps != 1:
            raise RuntimeError(
                "Group-PG update must perform exactly one optimizer step; "
                f"observed {optimizer_steps}"
            )
        if track_candidate_weights:
            trainable_hash_after = self._trainable_param_sha256()
            self.grpo_trainable_param_sha256_current = trainable_hash_after
            log_entry["trainable_param_sha256_before"] = trainable_hash_before
            log_entry["trainable_param_sha256_after"] = trainable_hash_after
            if verify_frozen_weights and trainable_hash_before != trainable_hash_after:
                raise RuntimeError(
                    "LR0 candidate-distillation gate changed trainable parameters"
                )
        self.grpo_updates += 1
        log_entry["loss"] = round(self.last_grpo_loss, 8)
        log_entry["n_batches"] = len(batches)
        log_entry["optimizer_steps"] = optimizer_steps
        self._append_grpo_log(log_entry)
        label = (
            "group-pg-inst"
            if self.grpo_candidate_proposer == "policy_sample"
            else "candidate-distill-inst"
        )
        print(
            f"[{label}] k={k} mean={mean_r:.4f} std={std:.4f} "
            f"committed={committed_reward if committed_reward is None else round(committed_reward, 4)} "
            f"batches={len(batches)} loss={self.last_grpo_loss:.6f} "
            f"update#{self.grpo_updates}",
            flush=True,
        )

    def _trainable_param_sha256(self) -> str:
        import torch

        if self._model is None:
            raise RuntimeError("Cannot hash trainable parameters before model setup")
        digest = hashlib.sha256()
        trainable = [
            (name, parameter)
            for name, parameter in self._model.named_parameters()
            if parameter.requires_grad
        ]
        if not trainable:
            raise RuntimeError(
                "Candidate-distillation gate found no trainable parameters"
            )
        for name, parameter in sorted(trainable, key=lambda item: item[0]):
            digest.update(name.encode("utf-8"))
            raw = parameter.detach().contiguous().view(torch.uint8)
            digest.update(raw.cpu().numpy().tobytes())
        return digest.hexdigest()

    def _append_grpo_log(self, entry: dict[str, Any]) -> None:
        self._grpo_instance_log.append(entry)
        if len(self._grpo_instance_log) > 512:
            self._grpo_instance_log = self._grpo_instance_log[-512:]

    @staticmethod
    def _add_grpo_sampling_provenance(
        entry: dict[str, Any], pending: dict[str, Any]
    ) -> None:
        objective = pending.get("objective")
        entry.setdefault(
            "objective",
            objective if isinstance(objective, str) else _INSTANCE_GROUP_PG_OBJECTIVE,
        )
        proposer = pending.get("candidate_proposer")
        if isinstance(proposer, str):
            entry["candidate_proposer"] = proposer
        for key in (
            "grpo_run_seed",
            "grpo_adapter_init_seed",
            "sampling_seed",
            "seed_instance_index",
            "seed_interaction_step",
        ):
            if isinstance(pending.get(key), int) and not isinstance(
                pending.get(key), bool
            ):
                entry[key] = pending[key]
        if isinstance(pending.get("seed_instance_id"), str):
            entry["seed_instance_id"] = pending["seed_instance_id"]
        if isinstance(pending.get("sampling_prompt_sha256"), str):
            entry["sampling_prompt_sha256"] = pending["sampling_prompt_sha256"]
        if isinstance(pending.get("candidate_sampling"), dict):
            entry["candidate_sampling"] = dict(pending["candidate_sampling"])
        elapsed = pending.get("candidate_generation_seconds")
        if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool):
            entry["candidate_generation_seconds"] = float(elapsed)

    def _extract_improved_answer(self, text: str) -> str | None:
        text = text.strip()
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            parsed = json.loads(text[start:end])
        except (ValueError, json.JSONDecodeError):
            return None
        value = parsed.get("improved_answer")
        return value if isinstance(value, str) and value.strip() else None

    def _infer_feedback_reward_openai(self, observation: Observation) -> float:
        api_key = os.environ.get(self.reward_judge_api_key_env)
        if not api_key:
            raise RuntimeError(
                f"reward_judge_provider='openai' requires "
                f"{self.reward_judge_api_key_env} to be set"
            )

        payload = {
            "model": self.reward_judge_model,
            "input": self._reward_judge_prompt(observation),
            "max_output_tokens": 128,
            "text": {"format": {"type": "json_object"}},
        }
        response_payload = self._reward_judge_request_json(
            f"{self.reward_judge_base_url}/responses",
            payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            provider_label="OpenAI",
        )

        raw_text = self._extract_responses_text(response_payload).strip()
        self.last_reward_judge_raw = raw_text[:1000]
        usage = response_payload.get("usage")
        self.last_reward_judge_usage = usage if isinstance(usage, dict) else None
        if self.last_reward_judge_usage is not None:
            self.record_usage_event(
                build_usage_event_from_response(
                    model=self.reward_judge_model,
                    response=response_payload,
                    call_type="reward_judge",
                    provider="openai",
                    metadata={"reward_judge_provider": "openai"},
                )
            )
        return self._parse_reward_judge_json(raw_text, provider_label="OpenAI")

    def _infer_feedback_reward_openrouter(self, observation: Observation) -> float:
        api_key = os.environ.get(self.reward_judge_api_key_env)
        if not api_key:
            raise RuntimeError(
                f"reward_judge_provider='openrouter' requires "
                f"{self.reward_judge_api_key_env} to be set"
            )

        prompt = self._reward_judge_prompt(observation)
        payload = {
            "model": self.reward_judge_model,
            "messages": [
                {
                    "role": "system",
                    "content": "Return only one JSON object with reward and reason.",
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 128,
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        response_payload = self._reward_judge_request_json(
            f"{self.reward_judge_base_url}/chat/completions",
            payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            provider_label="OpenRouter",
        )

        raw_text = self._extract_chat_completion_text(response_payload).strip()
        self.last_reward_judge_raw = raw_text[:1000]
        usage = response_payload.get("usage")
        self.last_reward_judge_usage = usage if isinstance(usage, dict) else None
        if self.last_reward_judge_usage is not None:
            self.record_usage_event(
                build_usage_event_from_response(
                    model=self.reward_judge_model,
                    response=response_payload,
                    call_type="reward_judge",
                    provider="openrouter",
                    metadata={"reward_judge_provider": "openrouter"},
                )
            )
        return self._parse_reward_judge_json(raw_text, provider_label="OpenRouter")

    def _reward_judge_request_json(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str],
        provider_label: str,
    ) -> dict[str, Any]:
        encoded_payload = json.dumps(payload).encode("utf-8")
        for attempt in range(_REWARD_JUDGE_MAX_ATTEMPTS):
            request = urllib.request.Request(
                url,
                data=encoded_payload,
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(
                    request, timeout=self.reward_judge_timeout_seconds
                ) as response:
                    response_payload = json.loads(response.read().decode("utf-8"))
                if not isinstance(response_payload, dict):
                    raise RuntimeError(
                        f"{provider_label} reward judge returned non-object JSON"
                    )
                return response_payload
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")[:500]
                if (
                    exc.code in _REWARD_JUDGE_RETRYABLE_HTTP_CODES
                    and attempt + 1 < _REWARD_JUDGE_MAX_ATTEMPTS
                ):
                    time.sleep(0.5 * (2**attempt))
                    continue
                raise RuntimeError(
                    f"{provider_label} reward judge failed with HTTP {exc.code} "
                    f"after {attempt + 1} attempt(s): {body}"
                ) from exc
            except (TimeoutError, urllib.error.URLError) as exc:
                if attempt + 1 < _REWARD_JUDGE_MAX_ATTEMPTS:
                    time.sleep(0.5 * (2**attempt))
                    continue
                raise RuntimeError(
                    f"{provider_label} reward judge request failed after "
                    f"{attempt + 1} attempt(s): {exc}"
                ) from exc
            except Exception as exc:
                raise RuntimeError(
                    f"{provider_label} reward judge request failed: {exc}"
                ) from exc

        raise RuntimeError(f"{provider_label} reward judge request failed")

    def _parse_reward_judge_json(self, raw_text: str, *, provider_label: str) -> float:
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"{provider_label} reward judge returned non-JSON text: "
                f"{raw_text[:200]!r}"
            ) from exc
        reward = parsed.get("reward")
        if reward not in (-1, 0, 1):
            raise RuntimeError(
                f"{provider_label} reward judge returned invalid reward={reward!r}; "
                "expected -1, 0, or 1"
            )
        return float(reward)

    def _reward_judge_prompt(self, observation: Observation) -> str:
        metadata = observation.metadata or {}
        public_metadata = {
            key: value
            for key, value in metadata.items()
            if key
            in {
                "reward",
                "score",
                "raw_metric_value",
                "success",
                "format_valid",
                "timed_out",
                "steps",
                "target_year",
                "variant_id",
            }
        }
        content = observation.content.strip()
        if len(content) > 3000:
            content = content[-3000:]
        return (
            "You judge only public benchmark feedback for a previous action. "
            "Do not solve the benchmark task. Return exactly one JSON object "
            'like {"reward":0,"reason":"short note"}. reward must be 1 for '
            "clearly positive feedback, -1 for clearly negative feedback, and "
            "0 for neutral or insufficient feedback. The reason must be 8 words "
            "or fewer.\n"
            f"instance_complete={observation.instance_complete}\n"
            f"public_metadata={json.dumps(public_metadata, ensure_ascii=False)}\n"
            f"feedback={content!r}"
        )

    def _extract_responses_text(self, payload: dict[str, Any]) -> str:
        texts: list[str] = []
        for item in payload.get("output") or []:
            for content in item.get("content") or []:
                text = content.get("text")
                if isinstance(text, str):
                    texts.append(text)
        if texts:
            return "\n".join(texts)
        output_text = payload.get("output_text")
        if isinstance(output_text, str):
            return output_text
        return ""

    def _extract_chat_completion_text(self, payload: dict[str, Any]) -> str:
        choices = payload.get("choices")
        if not isinstance(choices, list):
            return ""
        texts: list[str] = []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    texts.append(content)
        return "\n".join(texts)

    def _numeric_feedback_value(self, text: str) -> float | None:
        for name in ("reward", "score", "profit", "gain", "utility"):
            match = re.search(rf"{name}[^-+0-9]*([-+]?\d+(?:\.\d+)?)", text)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    continue
        return None

    def _max_new_tokens_for_schema(self, schema: type[BaseModel]) -> int:
        fields = set(schema.model_fields.keys())
        if "predictions" in fields or len(fields) > 20:
            return self.max_new_tokens
        if "command" in fields:
            return min(self.max_new_tokens, self.action_max_new_tokens, 1536)
        if "tool_call" in fields:
            return min(self.max_new_tokens, self.action_max_new_tokens, 768)
        if "action" in fields:
            return min(self.max_new_tokens, self.action_max_new_tokens, 768)
        return min(self.max_new_tokens, self.action_max_new_tokens)

    def _generation_prefix_for_schema(self, schema: type[BaseModel]) -> str:
        if "predictions" in schema.model_fields:
            return '{"predictions": ['
        if {"thought", "command"} <= set(schema.model_fields.keys()):
            return '{"thought":"'
        if len(schema.model_fields) > 20:
            return "{"
        return ""

    def _merge_generation_prefix(self, prefix: str, generated: str) -> str:
        if not prefix:
            return generated
        stripped = generated.lstrip()
        if prefix == "{":
            if stripped.startswith("{"):
                return generated
            return prefix + generated
        if (
            stripped.startswith(prefix)
            or stripped.startswith('{"predictions"')
            or stripped.startswith('{"thought"')
        ):
            return generated
        return prefix + generated

    def _include_failed_response_in_retry(self, schema: type[BaseModel]) -> bool:
        fields = set(schema.model_fields.keys())
        if "predictions" in fields:
            return False
        if "tool_call" in fields:
            return False
        if {"action", "content"} <= fields:
            return False
        return True

    def _failed_response_retry_message(
        self, raw_text: str, schema: type[BaseModel]
    ) -> dict[str, str] | None:
        fields = set(schema.model_fields.keys())
        if self._include_failed_response_in_retry(schema):
            if "command" in fields:
                snippet = raw_text.strip()
                excerpt = ""
                if snippet.startswith("{"):
                    excerpt = f"\nPrevious invalid JSON excerpt:\n{snippet[:1200]}"
                return {
                    "role": "user",
                    "content": (
                        "The previous command response was invalid. Replace it "
                        'with one fresh JSON object containing both "thought" '
                        'and "command". Do not copy, continue, or paraphrase '
                        f"the previous response.{excerpt}"
                    ),
                }
            return {"role": "assistant", "content": raw_text[:2000]}
        if not ("predictions" in fields or {"action", "content"} <= fields):
            return None
        snippet = raw_text.strip()
        if not snippet:
            return None
        return {
            "role": "user",
            "content": (
                "The invalid previous response began with this excerpt. "
                "Do not copy or continue it; use it only to avoid repeating "
                "the same failure:\n"
                f"{snippet[:1200]}"
            ),
        }

    def _retry_instruction(self, schema: type[BaseModel]) -> str:
        keys = list(schema.model_fields.keys())
        instruction = (
            "The previous assistant response was not valid for the required "
            "JSON schema. Retry now with only one JSON object whose top-level "
            f"keys are exactly compatible with {json.dumps(keys)}."
        )
        if "predictions" in schema.model_fields:
            instruction += (
                " You are in FINAL FORECAST SUBMISSION mode. Output exactly one "
                'JSON object with top-level key "predictions". Do not include '
                "thought, command, or tool_call. A response with a command key, "
                "including echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT, is invalid "
                "because the shell step is already over. Start the retry exactly "
                'with {"predictions": [ and include one object per requested '
                "entry."
            )
        elif {"action", "content"} <= set(schema.model_fields.keys()):
            instruction += (
                " For QUERY actions, retry with one complete JSON object whose "
                "content is a single short SQL statement under 500 characters. "
                "Do not repeat equivalent LIKE predicates, nested IN subqueries, "
                "or long OR chains. If the previous SQL was too long or was "
                "cut off, do not continue that query. Replace it with a short "
                "SELECT ... LIMIT 10 / GROUP BY query, or output an ANSWER "
                "object with the best concise answer from evidence already seen. "
                "Never enumerate product titles with ttl !=, title !=, name !=, "
                "or many string-literal exclusions; quote-heavy product titles "
                "make invalid JSON. Use COUNT, GROUP BY, MIN/MAX/AVG, or LIMIT "
                "instead."
            )
        elif "tool_call" in schema.model_fields:
            instruction += (
                " Keep the retry short and complete. If the failed tool_call "
                "used a long thought, replace it with one short sentence under "
                "30 words and then provide the tool_call immediately. Do not "
                "enumerate cohorts, bins, genotypes, or future plans in the "
                "thought. For query_sql, use one short exploratory SELECT under "
                "300 characters; do not use many SUM(CASE ...) columns, long OR "
                "chains, or broad patient-distribution inventories. If the "
                "previous response was cut off while writing query_sql, do not "
                "retry query_sql; choose get_database_metadata or "
                "get_data_summary instead. If the retry used group_expression, "
                "make it one compact SQL CASE expression "
                "under 500 characters with at most 3 WHEN branches. Do not try "
                "to enumerate all 36 cohorts, every latent group, or every "
                "unobservable group in one tool call; use a coarse exploratory "
                "grouping or submit if enough evidence has been collected. "
                "Never retry by counting patients in each of the 36 target "
                "cohorts or by writing a long WHERE clause with many OR "
                "alternatives. If you were about to count all target cohorts, "
                "output get_database_metadata or get_data_summary instead."
            )
        elif not ({"command", "tool_call"} & set(schema.model_fields.keys())):
            instruction += " Do not include thought, command, or tool_call."
        if len(keys) > 20:
            instruction += (
                " The previous object omitted required fields. Retry with every "
                "required top-level key exactly once; if a value is uncertain, "
                "use your best bounded numeric estimate rather than omitting it."
            )
        if self._has_unit_interval_fields(schema):
            instruction += (
                " Every numeric field in this schema is a probability bounded "
                "from 0 to 1 inclusive. Do not output counts, class labels, "
                "percent values, or any value greater than 1."
            )
        return instruction

    def _query_content(self, query: Query) -> str:
        pieces: list[str] = []
        feedback_metadata = (
            query.feedback.metadata or {} if query.feedback is not None else {}
        )
        # Once held-out evaluation is sealed, Query.feedback is never a legal
        # prompt input.  Do not key this gate on a short sensitive-field list:
        # terminal content with empty or newly named metadata is sensitive too.
        sealed_feedback = self._icl_context_sealed_eval and query.feedback is not None
        if sealed_feedback:
            self._icl_context_sensitive_feedback_drops += 1
        if (
            query.feedback is not None
            and query.feedback.content.strip()
            and not sealed_feedback
        ):
            pieces.append(f"FEEDBACK: {query.feedback.content.strip()}")
        # ICL has no parameter-update path, so it can only consume the harness
        # reward in-context: surface the env_feedback_reward explicitly in the
        # prompt for the ICL method (LoRA/prefix get it via reward_pg instead).
        if (
            self.method == "icl"
            and not self._icl_context_sealed_eval
            and query.feedback is not None
        ):
            meta = feedback_metadata
            reward = meta.get("env_feedback_reward")
            if isinstance(reward, (int, float)) and not isinstance(reward, bool):
                pieces.append(
                    "ENV_REWARD (score of your previous answer, higher is better): "
                    f"{float(reward):.4f}"
                )
        pieces.append(query.prompt if query.prompt else "(no content)")
        return "\n\n".join(pieces)

    def _system_messages(self) -> list[dict[str, str]]:
        if not self.system_prompt:
            return []
        return [{"role": "system", "content": self.system_prompt}]

    def _select_messages(self) -> list[dict[str, str]]:
        if self.context_policy == "question_only":
            return [self.messages[-1]]
        if self.context_policy == "full":
            return self._truncate_full_messages()
        return list(self.messages)

    def _truncate_full_messages(self) -> list[dict[str, str]]:
        selected = list(self.messages)
        while len(selected) > 1:
            rendered = self._render_messages([*self._system_messages(), *selected])
            if self._count_tokens(rendered) <= self.max_context_tokens:
                break
            selected.pop(0)
            self.truncation_count += 1
            self.has_truncated_flag = True
        if len(selected) != len(self.messages):
            self.messages = selected
        return selected

    def _with_schema_instruction(
        self, messages: list[dict[str, str]], schema: type[BaseModel]
    ) -> list[dict[str, str]]:
        selected = [m.copy() for m in [*self._system_messages(), *messages]]
        instruction = schema_to_prompt_instruction(schema)
        top_level_keys = list(schema.model_fields.keys())
        if top_level_keys:
            instruction += (
                "\nThe response JSON's top-level object MUST contain these keys: "
                f"{json.dumps(top_level_keys)}."
            )
        if "command" in schema.model_fields:
            instruction += (
                '\nFormat example: {"thought": "brief reason", '
                '"command": "python -c \'print(1)\'"}'
                "\nDo not output forecasts, patches, or final answers directly "
                "while this schema asks for a command. If you are ready to "
                "finish, issue the benchmark's explicit submit command."
                "\nThe command JSON string must be complete and parseable. "
                "Do not put raw double quote characters inside the command "
                'string; escape them as \\" or use single quotes inside the '
                "shell/Python code. Prefer short commands whose Python string "
                "literals use single quotes."
                "\nFor code search, keep the command short. If you need "
                "multiple terms, use one pattern such as "
                "grep -R -E 'term1|term2' . | head -50; do not repeat nested "
                "grep fragments or long path strings."
            )
        if "tool_call" in schema.model_fields:
            instruction += (
                "\nDo not output tool arguments or a final report directly at the "
                "top level. Always wrap the selected tool invocation inside the "
                '"tool_call" field and include a "thought" string.'
                '\nFormat example: {"thought": "brief reason", '
                '"tool_call": {"tool": "get_database_metadata"}}'
                "\nThe thought must be one short sentence under 30 words. Put "
                "the tool_call immediately after thought; do not spend the "
                "response planning many cohorts, bins, genotypes, or future "
                "actions."
                "\nIf your next action is to submit, output only the submit "
                "tool call wrapper. Do not include final estimates until the "
                "benchmark later asks for the flat submission schema."
                "\nKeep the thought concise so the JSON tool_call object is not "
                "truncated."
                "\nDo not try to create all 36 final cohorts inside a tool call. "
                "The final flat submission schema is where the 36 estimates are "
                "reported; tool calls should be short exploratory steps."
                "\nFor cohort group tools, keep group_expression compact: use a "
                "single SQL CASE expression under 500 characters and at most 3 "
                "WHEN branches. Do not attempt to encode all cohorts, all latent "
                "profiles, or all unobservable groups in one CASE expression. "
                "Prefer broad observable groupings such as age/risk/biomarker "
                "bins, then refine with another short tool call if needed."
                "\nFor query_sql tool calls, keep sql under 300 characters and "
                "target one question at a time. Avoid many SUM(CASE ...) "
                "columns, long OR chains, repeated equivalent predicates, or "
                "broad patient-distribution inventories."
                "\nNever use query_sql to count patients in each of the 36 "
                "target cohorts, verify all cohort definitions, or encode many "
                "age/risk/biomarker alternatives in one WHERE clause. That "
                "failure mode creates truncated invalid JSON. If you need "
                "cohort evidence, ask one small metadata/summary/query question "
                "or use one compact estimator/grouping tool call."
                "\nIf you are about to write the sentence 'I will query the "
                "database to count patients in each of the 36 target cohorts', "
                "stop and instead output "
                '{"thought": "I will inspect cohort metadata.", '
                '"tool_call": {"tool": "get_database_metadata"}}.'
            )
        if {"thinking", "action"} <= set(schema.model_fields.keys()):
            instruction += (
                "\nFor poker action responses, output the action fields first "
                "and keep reasoning short: "
                '{"action": "CALL", "amount": null, "thinking": "one short sentence"}. '
                "The action must be one of FOLD, CALL, CHECK, or RAISE and must "
                "also be legal in the current prompt's legal_actions list. If "
                "CHECK is legal and CALL is not legal, choose CHECK instead of "
                "CALL. Only include a numeric amount for RAISE, within the "
                "prompt's min/max raise bounds. If the prompt gives a fixed "
                "all-in RAISE amount, use exactly that amount and not a larger "
                "standard minimum raise. Do not write a long analysis before "
                "the action. The thinking field must be a short string, not "
                "null. Never output an error report, hand_info, your_state, "
                "opponent_state, or message object; even if the state looks "
                "inconsistent, submit one legal PokerAction object."
            )
        if not ({"command", "tool_call"} & set(schema.model_fields.keys())):
            instruction += (
                "\nYou are now in structured submission mode, not action mode. "
                "Do not include thought, command, or tool_call fields unless "
                "they are listed in the required top-level keys."
            )
        if "predictions" in schema.model_fields:
            instruction += (
                "\nFINAL FORECAST SUBMISSION MODE: the shell step is already "
                "over. The next response will be parsed only as a "
                "PredictionResponse. The top-level object must be "
                '{"predictions": [...]} with one entry for every requested '
                "locality, furniture_name, and year. Do not output thought, "
                "command, or tool_call fields. Do not output "
                "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT again. Do not output a "
                "command that prints or loads predictions; output the predictions "
                "array directly in this response. Your first non-whitespace "
                'characters must be {"predictions": [. Never start with '
                '{"thought": or any explanation. If an item is uncertain, '
                "still include that required entry and set items_sold to your "
                "best numeric estimate or null."
            )
        if {"action", "content"} <= set(schema.model_fields.keys()):
            instruction += (
                "\nDATABASE ACTION MODE: output exactly one object such as "
                '{"action": "QUERY", "content": "SELECT ... LIMIT 20"} or '
                '{"action": "ANSWER", "content": "..."}. For SQL exploration, '
                "the content must be a single complete SQL statement under 800 "
                "characters. Do not repeat equivalent LIKE predicates, do not "
                "write long OR chains, and do not enumerate many similar search "
                "terms. Prefer IN, GROUP BY, LIMIT, or one targeted predicate. "
                "If a broad search is needed, issue several short queries across "
                "turns instead of one oversized query."
                "\nNever enumerate or exclude many literal item titles. In "
                "particular, do not write chains of ttl !=, title !=, name !=, "
                "or product-title string literals. Product titles often contain "
                "quotes and will break JSON if copied into the SQL string. Use "
                "GROUP BY, COUNT, DISTINCT, aggregate functions, or LIMIT 10."
            )
        if len(top_level_keys) > 20:
            instruction += (
                "\nThis is a large final submission schema. The JSON object must "
                "include every required top-level key exactly once. Do not omit "
                "unknown fields; provide your best numeric estimate within the "
                "field bounds for every key."
            )
        if self._has_unit_interval_fields(schema):
            instruction += (
                "\nAll numeric fields in this final submission are probabilities "
                "bounded from 0 to 1 inclusive. Output decimals such as 0.42, not "
                "counts, class labels, percentages, or values greater than 1."
            )
        for idx in range(len(selected) - 1, -1, -1):
            if selected[idx]["role"] == "user":
                selected[idx]["content"] += instruction
                return selected
        selected.append({"role": "user", "content": instruction})
        return selected

    def _has_unit_interval_fields(self, schema: type[BaseModel]) -> bool:
        bounded = 0
        for field in schema.model_fields.values():
            has_ge_zero = any(getattr(meta, "ge", None) == 0 for meta in field.metadata)
            has_le_one = any(getattr(meta, "le", None) == 1 for meta in field.metadata)
            if has_ge_zero and has_le_one:
                bounded += 1
        return bounded > 20

    def _parse_action(
        self, text: str, schema: type[BaseModel]
    ) -> tuple[BaseModel, bool]:
        candidates: list[tuple[str, bool]] = []

        def add_candidate(candidate: str | None, repair_used: bool) -> None:
            if candidate is None:
                return
            if candidate not in {existing for existing, _ in candidates}:
                candidates.append((candidate, repair_used))

        for candidate in self._extract_balanced_json_candidates(text):
            add_candidate(candidate, False)
        add_candidate(extract_json(text), False)

        for candidate, _ in list(candidates):
            repaired = self._repair_truncated_json_object(candidate)
            if repaired is not None and repaired != candidate:
                add_candidate(repaired, True)
            stray_paren_repair = self._repair_terminal_stray_paren_json_object(
                candidate
            )
            if stray_paren_repair is not None and stray_paren_repair != candidate:
                add_candidate(stray_paren_repair, True)
            null_thinking_repair = self._repair_null_thinking_string(candidate, schema)
            add_candidate(null_thinking_repair, True)
            description_thinking_repair = self._repair_description_alias_for_thinking(
                candidate, schema
            )
            add_candidate(description_thinking_repair, True)
            numeric_quote_repair = self._repair_numeric_value_trailing_quote(candidate)
            add_candidate(numeric_quote_repair, True)
            duplicate_bracket_repair = (
                self._repair_duplicate_closing_bracket_before_object_end(candidate)
            )
            add_candidate(duplicate_bracket_repair, True)
            unquoted_key_repair = self._repair_unquoted_tool_call_key(candidate, schema)
            add_candidate(unquoted_key_repair, True)
            missing_thought_repair = self._repair_missing_command_thought(
                candidate, schema
            )
            add_candidate(missing_thought_repair, True)
            command_thought_quote_repair = self._repair_missing_command_thought_quote(
                candidate, schema
            )
            add_candidate(command_thought_quote_repair, True)
            command_repair = self._repair_command_json_with_raw_quotes(
                candidate, schema
            )
            add_candidate(command_repair, True)

        last_error: Exception | None = None
        for candidate, repair_used in candidates:
            try:
                return validate_with_coercion(candidate, schema), repair_used
            except Exception as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def _normalize_zero_cost_poker_call(
        self, action: BaseModel, query: Query
    ) -> tuple[BaseModel, bool]:
        """Treat a zero-cost poker CALL as CHECK when the prompt offers CHECK."""
        fields = set(action.__class__.model_fields.keys())
        if not {"thinking", "action", "amount"} <= fields:
            return action, False
        action_value = getattr(action, "action", None)
        if not isinstance(action_value, str) or action_value.upper() != "CALL":
            return action, False
        prompt = query.prompt
        if "costs 0 chips" not in prompt or "CHECK - check" not in prompt:
            return action, False
        data = action.model_dump()
        data["action"] = "CHECK"
        data["amount"] = None
        return action.__class__.model_validate(data), True

    def _extract_balanced_json_candidates(self, text: str) -> list[str]:
        """Return balanced JSON object/array substrings in output order.

        Some Qwen generations emit a valid JSON object, then continue by
        echoing the next prompt. A greedy first-brace/last-brace extraction can
        then grab schema examples with placeholders such as ``<float>``. Trying
        balanced substrings first lets schema validation select the actual
        answer without inventing or falling back to a different response.
        """
        candidates: list[str] = []
        starts = {"{": "}", "[": "]"}
        pos = 0
        while pos < len(text):
            if text[pos] not in starts:
                pos += 1
                continue
            stack = [starts[text[pos]]]
            start = pos
            pos += 1
            in_string = False
            escaped = False
            while pos < len(text):
                ch = text[pos]
                if in_string:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == '"':
                        in_string = False
                    pos += 1
                    continue
                if ch == '"':
                    in_string = True
                elif ch in starts:
                    stack.append(starts[ch])
                elif ch in "}]":
                    if not stack or stack[-1] != ch:
                        break
                    stack.pop()
                    if not stack:
                        candidates.append(text[start : pos + 1])
                        break
                pos += 1
            pos = start + 1
        return candidates

    def _repair_truncated_json_object(self, text: str) -> str | None:
        """Close a JSON object/array cut off after valid completed tokens.

        This intentionally only balances braces/brackets when the stream is not
        inside a string. It does not invent missing values or schema fields.
        """
        candidate = text.strip()
        if not candidate or candidate[0] not in "{[":
            return None

        stack: list[str] = []
        in_string = False
        escaped = False
        for ch in candidate:
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
            elif ch == "{":
                stack.append("}")
            elif ch == "[":
                stack.append("]")
            elif ch in "}]":
                if not stack or stack[-1] != ch:
                    return None
                stack.pop()

        if in_string or not stack:
            return None
        return candidate + "".join(reversed(stack))

    def _repair_terminal_stray_paren_json_object(self, text: str) -> str | None:
        """Remove a terminal ``)`` that Qwen sometimes emits instead of ``}``.

        The repair is intentionally syntax-only: it only removes a parenthesis
        that is outside strings and followed only by closing JSON delimiters or
        whitespace. Schema validation still decides whether the repaired object
        is usable.
        """
        candidate = text.strip()
        if not candidate or candidate[0] not in "{[":
            return None

        in_string = False
        escaped = False
        for idx, ch in enumerate(candidate):
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
                continue
            if ch != ")":
                continue
            suffix = candidate[idx + 1 :]
            if all(c.isspace() or c in "}]" for c in suffix):
                repaired = (candidate[:idx] + suffix).strip()
                return self._repair_truncated_json_object(repaired) or repaired
        return None

    def _repair_null_thinking_string(
        self, text: str, schema: type[BaseModel]
    ) -> str | None:
        """Coerce non-semantic poker ``thinking: null`` to an empty string."""
        if "thinking" not in schema.model_fields:
            return None
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(data, dict) or data.get("thinking", ...) is not None:
            return None
        data["thinking"] = ""
        return json.dumps(data, ensure_ascii=False)

    def _repair_description_alias_for_thinking(
        self, text: str, schema: type[BaseModel]
    ) -> str | None:
        """Map a generated ``description`` field into required ``thinking``.

        Some action schemas require a short ``thinking`` string, but Qwen
        occasionally emits the same content under ``description``. This is a
        key rename only; schema validation still decides whether the repaired
        object is acceptable.
        """
        if (
            "thinking" not in schema.model_fields
            or "description" in schema.model_fields
        ):
            return None
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        if data.get("thinking", ...) is not ...:
            return None
        description = data.get("description")
        if not isinstance(description, str):
            return None
        repaired = dict(data)
        repaired["thinking"] = repaired.pop("description")
        return json.dumps(repaired, ensure_ascii=False)

    def _repair_numeric_value_trailing_quote(self, text: str) -> str | None:
        """Remove a stray quote immediately after a JSON numeric value.

        Qwen occasionally emits large flat numeric submissions with a single
        value like ``"field": 0.60"``. This is a syntax-only repair: it never
        changes quoted string values and schema validation still decides
        whether the candidate is acceptable.
        """
        candidate = text.strip()
        if not candidate or candidate[0] not in "{[":
            return None
        repaired = re.sub(
            r'(:\s*[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)"(?=\s*(?:[,}\]]|$))',
            r"\1",
            candidate,
        )
        if repaired == candidate:
            return None
        return self._repair_truncated_json_object(repaired) or repaired

    def _repair_duplicate_closing_bracket_before_object_end(
        self, text: str
    ) -> str | None:
        """Remove one extra closing bracket near the end of a JSON object.

        Qwen sometimes emits ``... ] ] }`` for object fields that are already
        fully closed lists. This is a syntax-only repair that drops a single
        redundant ``]`` right before the object terminator.
        """
        candidate = text.strip()
        if not candidate.startswith("{"):
            return None
        repaired = re.sub(r"\]\s*\]\s*}$", "]}", candidate)
        if repaired == candidate:
            return None
        return repaired

    def _repair_unquoted_tool_call_key(
        self, text: str, schema: type[BaseModel]
    ) -> str | None:
        """Quote a generated top-level ``tool_call`` key when only quotes are missing."""
        if "tool_call" not in schema.model_fields:
            return None
        candidate = text.strip()
        if not candidate.startswith("{"):
            return None
        repaired = re.sub(r"([,{]\s*)tool_call\s*:", r'\1"tool_call":', candidate)
        if repaired == candidate:
            return None
        return self._repair_truncated_json_object(repaired) or repaired

    def _repair_command_json_with_raw_quotes(
        self, text: str, schema: type[BaseModel]
    ) -> str | None:
        """Recover command schemas when the command string contains raw quotes.

        Qwen often emits the right top-level object but places shell/Python code
        like ``open("file")`` directly inside the JSON string. Standard JSON
        parsing then fails even though the intended command field is present.
        This repair extracts existing top-level string fields and re-encodes
        them without altering commands. If the schema requires a short thought
        and the model emitted only the command, fill thought with an empty
        string so the valid action can be executed.
        """
        expected = set(schema.model_fields.keys())
        if "command" not in expected:
            return None
        candidate = text.strip()
        if not candidate.startswith("{"):
            return None
        for field in expected:
            candidate = re.sub(
                rf'([{{,]\s*){re.escape(field)}"\s*:',
                rf'\1"{field}":',
                candidate,
            )

        recovered: dict[str, str] = {}
        for field in ("thought", "command"):
            if field not in expected:
                continue
            value = self._extract_loose_top_level_string(candidate, field, expected)
            if value is None and field == "command":
                value = self._extract_unclosed_command_string(candidate)
            if value is not None:
                recovered[field] = value

        if "command" not in recovered:
            return None
        if "thought" in expected and "thought" not in recovered:
            recovered["thought"] = ""
        return json.dumps(recovered, ensure_ascii=False)

    def _repair_missing_command_thought(
        self, text: str, schema: type[BaseModel]
    ) -> str | None:
        """Allow command-only JSON for command schemas by adding empty thought."""
        expected = set(schema.model_fields.keys())
        if not {"command", "thought"} <= expected:
            return None
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        if "thought" in data or "command" not in data:
            return None
        if not isinstance(data["command"], str):
            return None
        repaired = dict(data)
        repaired["thought"] = ""
        return json.dumps(repaired, ensure_ascii=False)

    def _repair_missing_command_thought_quote(
        self, text: str, schema: type[BaseModel]
    ) -> str | None:
        """Close a leaked thought string before the command key.

        Qwen sometimes emits:
        {"thought":"... 'code patch','command":"grep ..."}
        where the thought string is missing its closing quote before the comma.
        This repair only applies to command schemas and only when the structure
        clearly matches that failure mode.
        """
        expected = set(schema.model_fields.keys())
        if not {"command", "thought"} <= expected:
            return None
        candidate = text.strip()
        if not candidate.startswith("{"):
            return None
        repaired = candidate
        for pattern in (
            r"'\s*,\s*'command\"\s*:",
            r",\s*'command\"\s*:",
            r"'\s*,\s*\"command\"\s*:",
        ):
            updated = re.sub(pattern, '","command":', repaired, count=1)
            if updated != repaired:
                repaired = updated
                break
        if repaired == candidate:
            return None
        return self._repair_truncated_json_object(repaired) or repaired

    def _extract_unclosed_command_string(self, text: str) -> str | None:
        match = re.search(r'"command"\s*:\s*"', text)
        if match is None:
            return None
        value = text[match.end() :].strip()
        if not value:
            return None
        # Preserve generated content only. If the model hit max_new_tokens
        # before closing JSON, the environment can still give feedback on the
        # exact partial shell command instead of aborting the benchmark.
        value = value.removesuffix("}").rstrip()
        return value or None

    def _extract_loose_top_level_string(
        self, text: str, field: str, expected_fields: set[str]
    ) -> str | None:
        match = re.search(rf'"{re.escape(field)}"\s*:\s*"', text)
        if match is None:
            return None
        start = match.end()

        next_positions: list[int] = []
        for other in expected_fields - {field}:
            next_match = re.search(
                rf'",\s*"{re.escape(other)}"\s*:',
                text[start:],
            )
            if next_match is not None:
                next_positions.append(start + next_match.start())

        if next_positions:
            end = min(next_positions)
        else:
            stripped_end = len(text.rstrip())
            if stripped_end > 0 and text.rstrip().endswith("}"):
                closing_quote = text.rfind('"', start, stripped_end - 1)
            else:
                closing_quote = text.rfind('"', start)
            if closing_quote <= start:
                return None
            end = closing_quote

        return text[start:end]

    def _render_messages(self, messages: list[dict[str, str]]) -> str:
        tokenizer = self._load_tokenizer()
        try:
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
        except TypeError:
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

    def _window_prompt(self, prompt: str) -> str:
        return self._window_text_for_policy(
            prompt,
            self.context_policy,
            full_token_limit=self.max_context_tokens,
            count_as_generation=True,
        )

    def _window_text_for_policy(
        self,
        text: str,
        policy: ContextPolicy,
        *,
        full_token_limit: int,
        count_as_generation: bool,
    ) -> str:
        if policy == "full":
            return self._truncate_token_text_for_counter(
                text, full_token_limit, "tail", count_as_generation=count_as_generation
            )
        if policy in {"tail", "tail4k"}:
            return self._truncate_token_text_for_counter(
                text, self.tail_tokens, "tail", count_as_generation=count_as_generation
            )
        if policy in {"head_tail", "head4k_tail4k"}:
            tokenizer = self._load_tokenizer()
            ids = tokenizer.encode(text, add_special_tokens=False)
            budget = min(full_token_limit, self.head_tokens + self.tail_tokens)
            if len(ids) <= budget:
                return text
            head_count = min(self.head_tokens, budget)
            tail_count = max(1, budget - head_count)
            head = tokenizer.decode(ids[:head_count], skip_special_tokens=False)
            tail = tokenizer.decode(ids[-tail_count:], skip_special_tokens=False)
            self._record_policy_truncation(count_as_generation)
            return (
                head
                + "\n\n[... middle context omitted by qwen_local head_tail window ...]\n\n"
                + tail
            )
        if policy == "question_only":
            return self._truncate_token_text_for_counter(
                text, full_token_limit, "tail", count_as_generation=count_as_generation
            )
        raise ValueError(f"Unknown context_policy={policy!r}")

    def _truncate_token_text(self, text: str, token_limit: int, side: str) -> str:
        return self._truncate_token_text_for_counter(
            text, token_limit, side, count_as_generation=True
        )

    def _truncate_token_text_for_counter(
        self,
        text: str,
        token_limit: int,
        side: str,
        *,
        count_as_generation: bool,
    ) -> str:
        tokenizer = self._load_tokenizer()
        ids = tokenizer.encode(text, add_special_tokens=False)
        if len(ids) <= token_limit:
            return text
        self._record_policy_truncation(count_as_generation)
        kept = ids[-token_limit:] if side == "tail" else ids[:token_limit]
        return tokenizer.decode(kept, skip_special_tokens=False)

    def _record_policy_truncation(self, count_as_generation: bool) -> None:
        self.has_truncated_flag = True
        if count_as_generation:
            self.truncation_count += 1
        else:
            self.ttt_history_truncation_count += 1

    def _generate_text(
        self, prompt: str, *, max_new_tokens: int
    ) -> tuple[str, dict[str, Any]]:
        tokenizer, model = self._load_model()
        import torch

        inputs = tokenizer(prompt, return_tensors="pt")
        prompt_tokens_before_hard_cap = int(inputs["input_ids"].shape[-1])
        prompt_token_budget = self._generation_input_token_budget(
            model, tokenizer, max_new_tokens
        )
        prompt_hard_truncated = False
        if (
            prompt_token_budget is not None
            and prompt_tokens_before_hard_cap > prompt_token_budget
        ):
            for key, value in list(inputs.items()):
                if (
                    hasattr(value, "shape")
                    and len(value.shape) >= 2
                    and int(value.shape[-1]) == prompt_tokens_before_hard_cap
                ):
                    inputs[key] = value[..., -prompt_token_budget:]
            prompt_hard_truncated = True
            self.has_truncated_flag = True
            self.truncation_count += 1

        device = next(model.parameters()).device
        inputs = {key: value.to(device) for key, value in inputs.items()}
        do_sample = self.temperature > 0
        generation_kwargs: dict[str, Any] = {
            "max_new_tokens": max_new_tokens,
            "do_sample": do_sample,
            # LoRA training disables config.use_cache for gradient forwards.
            # Generation must override it back on; otherwise every response
            # after the first update becomes uncached autoregressive decoding.
            "use_cache": True,
            "pad_token_id": tokenizer.pad_token_id or tokenizer.eos_token_id,
            "eos_token_id": tokenizer.eos_token_id,
        }
        if do_sample:
            generation_kwargs["temperature"] = self.temperature
            generation_kwargs["top_p"] = self.top_p
        with torch.inference_mode():
            generated = model.generate(
                **inputs,
                **generation_kwargs,
            )
        prompt_len = int(inputs["input_ids"].shape[-1])
        output_ids = generated[0][prompt_len:]
        output_id_list = output_ids.tolist()
        raw_with_special = tokenizer.decode(output_ids, skip_special_tokens=False)
        raw_without_special = tokenizer.decode(output_ids, skip_special_tokens=True)
        return raw_without_special, {
            "prompt_tokens_before_hard_cap": prompt_tokens_before_hard_cap,
            "prompt_tokens": prompt_len,
            "prompt_token_budget": prompt_token_budget,
            "prompt_hard_truncated": prompt_hard_truncated,
            "new_token_count": len(output_id_list),
            "new_token_ids_prefix": output_id_list[:80],
            "decoded_with_special_prefix": raw_with_special[:500],
            "decoded_without_special_prefix": raw_without_special[:500],
        }

    def _generation_input_token_budget(
        self, model: Any, tokenizer: Any, max_new_tokens: int
    ) -> int | None:
        candidates: list[int] = []
        config = getattr(model, "config", None)
        for attr in ("max_position_embeddings", "n_positions", "seq_length"):
            value = getattr(config, attr, None)
            if isinstance(value, int) and 0 < value < 10_000_000:
                candidates.append(value)
        tokenizer_limit = getattr(tokenizer, "model_max_length", None)
        if isinstance(tokenizer_limit, int) and 0 < tokenizer_limit < 10_000_000:
            candidates.append(tokenizer_limit)
        if not candidates:
            return None
        return max(1, min(candidates) - max(0, int(max_new_tokens)))

    def _strip_think(self, text: str) -> str:
        return _THINK_BLOCK_RE.sub("", text)

    def _count_tokens(self, text: str) -> int:
        return len(self._load_tokenizer().encode(text, add_special_tokens=False))

    def _load_tokenizer(self):
        if self._tokenizer is None:
            from transformers import AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_path, trust_remote_code=self.trust_remote_code
            )
            if self._tokenizer.pad_token_id is None:
                self._tokenizer.pad_token = self._tokenizer.eos_token
        return self._tokenizer

    def _load_model(self):
        tokenizer = self._load_tokenizer()
        if self._model is None:
            import importlib.util

            import torch
            from transformers import AutoModelForCausalLM

            has_accelerate = importlib.util.find_spec("accelerate") is not None
            kwargs: dict[str, Any] = {
                "torch_dtype": torch.bfloat16,
                "trust_remote_code": self.trust_remote_code,
            }
            if has_accelerate:
                kwargs["device_map"] = "auto"
            if self.attn_implementation:
                kwargs["attn_implementation"] = self.attn_implementation
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_path, **kwargs
            )
            self._validate_model_assets(self._model)
            if not has_accelerate:
                device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self._model.to(device)
            self._model.eval()
        return tokenizer, self._model

    def _validate_model_assets(self, model: Any) -> None:
        config = getattr(model, "config", None)
        if config is None:
            return
        model_type = getattr(config, "model_type", None)
        bos_token_id = getattr(config, "bos_token_id", None)
        eos_token_id = getattr(config, "eos_token_id", None)
        if (
            model_type == "qwen3"
            and isinstance(eos_token_id, int)
            and eos_token_id == bos_token_id
        ):
            raise RuntimeError(
                "Invalid Qwen3 model assets: config.eos_token_id equals "
                "bos_token_id. This checkpoint/tokenizer variant enters an "
                "`assistant` role-token loop under the Qwen chat template. "
                "Sync a correct Qwen3 instruct model directory instead of "
                "running or bypassing the benchmark."
            )
        if model_type == "qwen3":
            bad_weight_sources = self._bad_qwen3_weight_sources()
            if bad_weight_sources:
                preview = ", ".join(bad_weight_sources[:2])
                raise RuntimeError(
                    "Invalid Qwen3 model assets: this chat/instruct model "
                    "directory points at base Qwen3 weights that enter an "
                    "`assistant` role-token loop under the Qwen chat template. "
                    f"Bad weight source(s): {preview}. Sync a correct Qwen3 "
                    "instruct model directory instead of running or bypassing "
                    "the benchmark."
                )

    def _bad_qwen3_weight_sources(self) -> list[str]:
        model_dir = Path(self.model_path)
        if not model_dir.exists() or not model_dir.is_dir():
            return []
        bad_sources: list[str] = []
        for weight_path in sorted(model_dir.glob("*.safetensors")):
            if not weight_path.is_symlink():
                continue
            resolved = weight_path.resolve(strict=False)
            source = str(resolved)
            if "qwen3-4b-base" in source.lower():
                bad_sources.append(source)
        return bad_sources
