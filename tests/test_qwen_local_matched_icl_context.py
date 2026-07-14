"""CPU-only tests for matched-ICL context snapshot isolation."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import sys
from types import ModuleType
from types import SimpleNamespace

import pytest

try:
    import litellm  # noqa: F401
except ImportError:  # Minimal CPU-test environment; production declares it.
    litellm_stub = ModuleType("litellm")
    for exception_name in (
        "InternalServerError",
        "APIConnectionError",
        "Timeout",
        "ServiceUnavailableError",
        "RateLimitError",
        "APIError",
        "BadRequestError",
    ):
        setattr(litellm_stub, exception_name, type(exception_name, (Exception,), {}))
    litellm_stub.model_cost = {}
    sys.modules["litellm"] = litellm_stub

from src.interface import Observation, Query
from pydantic import BaseModel
from src.systems.qwen_local.system import QwenLocalSystem


def make_system(**overrides) -> QwenLocalSystem:
    params = {
        "model_path": "unused-qwen",
        "method": "icl",
        "context_policy": "full",
        "max_context_tokens": 4096,
        "system_prompt": "matched ICL",
        "best_of_n": 1,
    }
    params.update(overrides)
    system = QwenLocalSystem(**params)
    system.reset()
    return system


def install_adaptation_context(system: QwenLocalSystem) -> None:
    system.messages = [
        {"role": "user", "content": "adaptation instance 0"},
        {"role": "assistant", "content": '{"forecast": 0.25}'},
        {"role": "user", "content": "ENV_REWARD: 0.75"},
        {"role": "user", "content": "adaptation instance 1"},
        {"role": "assistant", "content": '{"forecast": 0.50}'},
        {"role": "user", "content": "ENV_REWARD: 0.90"},
    ]
    system.interaction_count = 2
    system.truncation_count = 1
    system.has_truncated_flag = True
    system.icl_env_reward_injections = 2


def resign(snapshot: dict) -> None:
    payload = {
        key: snapshot[key]
        for key in ("protocol", "schema_version", "state", "system_contract")
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    snapshot["snapshot_sha256"] = hashlib.sha256(canonical).hexdigest()


def test_snapshot_is_canonical_detached_and_reusable_for_each_heldout() -> None:
    system = make_system()
    install_adaptation_context(system)

    snapshot = system.snapshot_icl_context()
    canonical = json.dumps(
        {
            key: snapshot[key]
            for key in ("protocol", "schema_version", "state", "system_contract")
        },
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert snapshot["snapshot_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert json.loads(json.dumps(snapshot, allow_nan=False)) == snapshot

    # Held-out 0 mutates prompt-bearing state. Restoring must erase it without
    # aliasing either the live system or the caller-owned frozen snapshot.
    system.messages.append({"role": "user", "content": "heldout-0 feedback"})
    system.interaction_count += 1
    system.truncation_count += 3
    system.icl_env_reward_injections += 1
    system.restore_icl_context(snapshot)
    assert system.messages == snapshot["state"]["messages"]
    assert system.interaction_count == 2
    assert system.truncation_count == 1
    assert system.icl_env_reward_injections == 2
    assert "heldout-0" not in json.dumps(system.messages)

    system.messages[0]["content"] = "heldout-1 mutated live context"
    assert snapshot["state"]["messages"][0]["content"] == "adaptation instance 0"
    system.restore_icl_context(snapshot)
    assert system.snapshot_icl_context() == snapshot


def test_snapshot_token_inventory_is_bound_and_non_mutating() -> None:
    system = make_system()
    install_adaptation_context(system)
    snapshot = system.snapshot_icl_context()
    before = deepcopy(system._icl_context_state_payload())

    class _Tokenizer:
        @staticmethod
        def encode(text: str, add_special_tokens: bool) -> list[int]:
            assert add_special_tokens is False
            return list(text.encode("utf-8"))

    system._render_messages = lambda messages: json.dumps(  # type: ignore[method-assign]
        messages, sort_keys=True, separators=(",", ":")
    )
    system._load_tokenizer = lambda: _Tokenizer()  # type: ignore[method-assign]
    inventory = system.tokenize_icl_context_snapshot(snapshot)

    assert inventory["snapshot_sha256"] == snapshot["snapshot_sha256"]
    assert inventory["token_count"] == len(inventory["token_ids"])
    assert inventory["token_ids_sha256"] == system._icl_context_digest(
        inventory["token_ids"]
    )
    assert system._icl_context_state_payload() == before


def test_observe_settles_action_transients_before_snapshot_boundary() -> None:
    system = make_system()
    system.messages = [
        {"role": "user", "content": "adaptation"},
        {"role": "assistant", "content": '{"forecast": 0.25}'},
    ]
    system.interaction_count = 1
    system._icl_context_observation_pending = True
    system._last_action_training_ids = [1, 2]
    system._last_action_prompt_tokens = 1
    system._last_response_integrity = {
        "schema_valid": True,
        "hard_schema_failure": False,
    }

    system.observe(
        Observation(
            content="",
            instance_complete=True,
            metadata={"env_feedback_reward": 0.5},
        )
    )

    assert system._icl_context_observation_pending is False
    assert system._last_action_training_ids is None
    assert system._last_action_prompt_tokens is None
    assert system._last_response_integrity is None
    snapshot = system.snapshot_icl_context()
    assert snapshot["state"]["messages"][-1]["content"].startswith("ENV_REWARD")


class _Action(BaseModel):
    value: int


def test_sealed_eval_blocks_terminal_reward_and_sensitive_feedback() -> None:
    system = make_system()
    install_adaptation_context(system)
    injections_before = system.icl_env_reward_injections
    system.seal_icl_context_for_evaluation()
    assert system.parameter_updates_enabled is False
    system.set_parameter_updates_enabled(True)
    assert system.parameter_updates_enabled is False
    sealed = system.snapshot_icl_context()
    assert sealed["system_contract"]["sealed_eval"] is True

    # Settle a synthetic valid action exactly as respond() would, then expose
    # every Cohort terminal secret through observation metadata.  None of it may
    # enter the prompt-bearing state once the context is sealed.
    system._icl_context_observation_pending = True
    system._last_action_training_ids = [1, 2]
    system._last_action_prompt_tokens = 1
    system._last_response_integrity = {
        "schema_valid": True,
        "hard_schema_failure": False,
    }
    system.observe(
        Observation(
            content="Report submitted for heldout-secret.",
            instance_complete=True,
            metadata={
                "env_feedback_reward": 0.99,
                "env_feedback_instance_id": "heldout-secret",
                "cohort_gt": {"secret": 1},
                "ref_survival": [0.1, 0.2, 0.3],
            },
        )
    )
    assert system.icl_env_reward_injections == injections_before
    assert system.snapshot_icl_context() == sealed
    assert system._icl_context_sensitive_feedback_drops == 1

    query = Query(
        prompt="new held-out query",
        response_schema=_Action,
        instance_id="new-heldout",
        instance_index=1,
        feedback=Observation(
            content="terminal secret content",
            instance_complete=True,
            metadata={
                "env_feedback_reward": 0.75,
                "cohort_gt": {"secret": 1},
                "ref_survival": [0.1, 0.2, 0.3],
            },
        ),
    )
    content = system._query_content(query)
    assert content == "new held-out query"
    assert "0.75" not in content
    assert "secret" not in content
    assert system._icl_context_sensitive_feedback_drops == 2

    metadata_free_feedback = Query(
        prompt="another held-out query",
        response_schema=_Action,
        instance_id="another-heldout",
        instance_index=2,
        feedback=Observation(
            content="terminal content without recognized metadata",
            instance_complete=True,
            metadata={},
        ),
    )
    content = system._query_content(metadata_free_feedback)
    assert content == "another held-out query"
    assert "terminal content" not in content
    assert system._icl_context_sensitive_feedback_drops == 3


def test_seal_is_one_way_and_preseal_snapshot_cannot_be_restored() -> None:
    system = make_system()
    before = system.snapshot_icl_context()
    system.seal_icl_context_for_evaluation()
    with pytest.raises(ValueError, match="system contract mismatch"):
        system.restore_icl_context(before)
    sealed = system.snapshot_icl_context()
    system.reset()
    assert system._icl_context_sealed_eval is True
    system.restore_icl_context(sealed)


@pytest.mark.parametrize(
    "transient,value,match",
    [
        ("_icl_context_observation_pending", True, "observation"),
        ("_pending_env_bon", {}, "env-BoN"),
        ("_last_action_training_ids", [1], "action training ids"),
        ("_last_action_prompt_tokens", 0, "action prompt boundary"),
        ("_last_response_integrity", {}, "response integrity"),
    ],
)
def test_snapshot_rejects_every_uncommitted_transient(
    transient: str, value: object, match: str
) -> None:
    system = make_system()
    setattr(system, transient, value)
    with pytest.raises(RuntimeError, match=match):
        system.snapshot_icl_context()


def test_snapshot_rejects_invalid_response_observation_lifecycle() -> None:
    system = make_system()
    system.observe(Observation(content="", instance_complete=True))
    with pytest.raises(RuntimeError, match="invalid response/observation lifecycle"):
        system.snapshot_icl_context()


def test_restore_rejects_tampering_and_is_transactional() -> None:
    system = make_system()
    install_adaptation_context(system)
    snapshot = system.snapshot_icl_context()
    system.messages = [{"role": "user", "content": "current safe state"}]
    system.interaction_count = 0
    state_before = deepcopy(system._icl_context_state_payload())

    tampered = deepcopy(snapshot)
    tampered["state"]["messages"][0]["content"] = "tampered"
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        system.restore_icl_context(tampered)
    assert system._icl_context_state_payload() == state_before

    malformed = deepcopy(snapshot)
    malformed["state"]["interaction_count"] = True
    resign(malformed)
    with pytest.raises(ValueError, match="non-negative integer"):
        system.restore_icl_context(malformed)
    assert system._icl_context_state_payload() == state_before

    extra_key = deepcopy(snapshot)
    extra_key["state"]["unexpected"] = 1
    resign(extra_key)
    with pytest.raises(ValueError, match="schema mismatch"):
        system.restore_icl_context(extra_key)
    assert system._icl_context_state_payload() == state_before


def test_restore_rejects_cross_contract_and_pending_target() -> None:
    source = make_system(max_context_tokens=4096)
    install_adaptation_context(source)
    snapshot = source.snapshot_icl_context()

    incompatible = make_system(max_context_tokens=2048)
    with pytest.raises(ValueError, match="system contract mismatch"):
        incompatible.restore_icl_context(snapshot)

    target = make_system(max_context_tokens=4096)
    target._icl_context_observation_pending = True
    with pytest.raises(RuntimeError, match="restore target is not quiescent"):
        target.restore_icl_context(snapshot)


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"method": "qttt"}, "method must be 'icl'"),
        ({"best_of_n": 2, "bon_critic": "env"}, "best_of_n must equal 1"),
    ],
)
def test_snapshot_rejects_non_context_only_systems(overrides: dict, match: str) -> None:
    system = make_system(**overrides)
    with pytest.raises(RuntimeError, match=match):
        system.snapshot_icl_context()

    # Restore applies the same contract gate before reading attacker-controlled
    # snapshot data.
    with pytest.raises(RuntimeError, match=match):
        system.restore_icl_context({})


def test_snapshot_rejects_hidden_adapter_or_update_state() -> None:
    system = make_system()
    system._lora_enabled = True
    with pytest.raises(RuntimeError, match="trainable adapter"):
        system.snapshot_icl_context()

    system._lora_enabled = False
    system.reward_pg_updates = 1
    with pytest.raises(RuntimeError, match="parameter-update counters"):
        system.snapshot_icl_context()


def test_icl_no_update_audit_exposes_every_forbidden_counter() -> None:
    system = make_system()
    assert system.icl_no_update_audit() == {
        "adaptation_count": 0,
        "adapter_enabled": False,
        "bon_updates": 0,
        "distill_updates": 0,
        "grpo_optimizer_steps": 0,
        "grpo_updates": 0,
        "peft_config_present": False,
        "reward_pg_updates": 0,
    }


def test_complete_model_state_hash_includes_persistent_buffers() -> None:
    torch = pytest.importorskip("torch")
    system = make_system()

    class TinyState(torch.nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.weight = torch.nn.Parameter(torch.tensor([1.0, 2.0]))
            self.register_buffer("running", torch.tensor([3.0]))

    model = TinyState()
    system._load_model = lambda: (SimpleNamespace(), model)  # type: ignore[method-assign]
    initial = system.current_model_param_sha256()
    with torch.no_grad():
        model.running.add_(1.0)
    after_buffer_change = system.current_model_param_sha256()
    assert after_buffer_change != initial
