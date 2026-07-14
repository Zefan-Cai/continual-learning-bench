"""CPU tests for the Cohort qonly frozen-tape weight-update ablation."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import sys
from types import ModuleType, SimpleNamespace

import pytest
import torch

try:
    import litellm  # noqa: F401
except ImportError:  # Minimal local CPU-test environment; production declares it.
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

from src.systems.qwen_local.system import QwenLocalSystem


INTEGRITY = {
    "schema_valid": True,
    "synthetic": False,
    "timed_out": False,
    "fallback": False,
    "missing": False,
    "hard_schema_failure": False,
    "parse_retries": 0,
    "repairs": 0,
}


def sampling_provenance(
    *,
    candidate_count: int = 2,
    valid_unique: int = 2,
    duplicates: int = 0,
    interaction_step: int = 1,
) -> dict:
    return {
        "registered_run_seed": 0,
        "interaction_step": interaction_step,
        "requested_best_of_n": 2,
        "initial_sample_attempts": 1,
        "generation_failures": 0,
        "parse_failures": 0,
        "duplicates": duplicates,
        "valid_unique": valid_unique,
        "candidate_count": candidate_count,
        "sampling_prompt_sha256": hashlib.sha256(b"sampling prompt").hexdigest(),
        "sampling_rng_binding": (
            "ambient_runner_rng; grpo_run_seed registered but not locally forked"
        ),
    }


class ToyAdapter(torch.nn.Module):
    def __init__(self, values: list[float] | None = None) -> None:
        super().__init__()
        self.adapter = torch.nn.Parameter(
            torch.tensor([0.25, -0.5] if values is None else values)
        )


def make_system(*, lr: float, adapter_seed: int = 2026071401) -> QwenLocalSystem:
    system = QwenLocalSystem(
        model_path="unused",
        method="ttt_rl",
        ttt_rl_source="sft",
        context_policy="question_only",
        adaptation_context_policy="head4k_tail4k",
        history_ttt=False,
        reward_update_rule="reward_pg",
        reward_judge_provider="env",
        reward_pg_steps=1,
        ttt_steps=1,
        ttt_max_tokens=64,
        ttt_lr=lr,
        reward_pg_lr=lr,
        peft_method="prefix",
        num_virtual_tokens=8,
        best_of_n=2,
        bon_critic="env",
        bon_env_reward="report",
        distill_provider="off",
        distill_contrastive=False,
        adapter_init_seed=adapter_seed,
    )
    system._model = ToyAdapter()
    system._lora_enabled = True

    def fake_train(batches, *, lr):
        # Deterministic CPU stand-in for AdamW: LR0 is bitwise frozen and active
        # performs a nonzero update for both historical calls.
        magnitude = sum(float(batch.get("signed_weight", 1.0)) for batch in batches)
        with torch.no_grad():
            system._model.adapter.add_(float(lr) * magnitude)
        return abs(magnitude)

    system._train_lora_token_batches = fake_train
    system._build_distill_batch = lambda prompt, candidate, weight: {
        "ids": [11, 12, 21 if candidate == "A" else 22],
        "prompt_tokens": 2,
        "signed_weight": weight,
    }
    return system


def make_tape(system: QwenLocalSystem, *, count: int = 2) -> dict:
    if system._frozen_tape_initial_trainable_state is None:
        system.initialize_and_snapshot_adapter_state()
    items = []
    for index in range(count):
        items.append(
            system.record_frozen_tape_item(
                sequence_index=index,
                instance_id=f"cohort-{index}",
                instance_index=100 + index,
                committed_training_ids=[1, 2, 3 + index, 4 + index],
                committed_prompt_tokens=2,
                committed_reward=-0.2 - 0.1 * index,
                env_bon_prompt=f"exact prompt {index}",
                env_bon_candidates=["A", "B"],
                env_bon_rewards=[0.7 + 0.01 * index, 0.2],
                integrity=dict(INTEGRITY),
                sampling_provenance=sampling_provenance(
                    interaction_step=index + 1
                ),
            )
        )
    return system.assemble_frozen_update_tape(items)


def test_prefix_reward_pg_adapter_seed_is_generic_and_rng_isolated() -> None:
    def install_random_adapter(_base, _config):
        return ToyAdapter(torch.rand(2).tolist())

    first = make_system(lr=0.0, adapter_seed=91)
    second = make_system(lr=0.0, adapter_seed=91)
    first._model = ToyAdapter()
    second._model = ToyAdapter()

    torch.manual_seed(12345)
    state_before = torch.random.get_rng_state().clone()
    installed_first = first._install_peft_adapter(object(), install_random_adapter)
    assert torch.equal(torch.random.get_rng_state(), state_before)
    installed_second = second._install_peft_adapter(object(), install_random_adapter)
    assert torch.equal(installed_first.adapter, installed_second.adapter)
    assert first.reward_update_rule == "reward_pg"
    assert first.peft_method == "prefix"

    with pytest.raises(ValueError, match="must match"):
        QwenLocalSystem(adapter_init_seed=1, grpo_adapter_init_seed=2)


def test_record_serialize_replay_lr0_active_restore_and_freeze() -> None:
    collector = make_system(lr=0.0)
    collector_initial = collector.initialize_and_snapshot_adapter_state()
    tape = make_tape(collector)
    payload = collector.serialize_frozen_update_tape(tape)
    assert collector.validate_frozen_update_tape(payload) == tape
    assert collector.current_trainable_param_sha256() == collector_initial

    lr0 = make_system(lr=0.0)
    lr0_log = lr0.replay_frozen_update_tape(
        payload, expected_tape_sha256=tape["tape_sha256"]
    )
    assert lr0_log["digest_verified"] is True
    assert lr0_log["trainable_param_sha256_initial"] == lr0_log[
        "trainable_param_sha256_final"
    ]
    assert [
        operation["operation"]
        for item in lr0_log["items"]
        for operation in item["operations"]
    ] == [
        "reward_pg_terminal",
        "bon_env_best_worst_sft",
        "reward_pg_terminal",
        "bon_env_best_worst_sft",
    ]
    assert all(
        operation["trainable_param_sha256_before"]
        == operation["trainable_param_sha256_after"]
        for item in lr0_log["items"]
        for operation in item["operations"]
    )

    active = make_system(lr=0.1)
    active._build_distill_batch = lambda *_args, **_kwargs: pytest.fail(
        "replay must consume recorded selected_batches without retokenizing"
    )
    active_log = active.replay_frozen_update_tape(
        tape, expected_tape_sha256=tape["tape_sha256"]
    )
    assert active_log["trainable_param_sha256_initial"] != active_log[
        "trainable_param_sha256_final"
    ]
    assert [item["item_sha256"] for item in active_log["items"]] == [
        item["item_sha256"] for item in lr0_log["items"]
    ]
    restored = active.restore_initial_adapter_state()
    assert restored == active_log["trainable_param_sha256_initial"]

    # Replaying from the restored state works; held-out freeze then becomes a
    # hard gate that a later runner enable request cannot undo.
    active.replay_frozen_update_tape(
        tape, expected_tape_sha256=tape["tape_sha256"]
    )
    frozen_hash = active.freeze_updates_for_heldout_eval()
    active.set_parameter_updates_enabled(True)
    assert active.parameter_updates_enabled is False
    assert active.current_trainable_param_sha256() == frozen_hash
    artifact = active.get_run_artifacts()["frozen_tape_weight_update_ablation"]
    assert artifact["mechanism_label"].endswith("not exact historical replication")
    assert artifact["heldout_updates_frozen"] is True


def test_capture_uses_exact_pending_training_inputs_without_consuming() -> None:
    system = make_system(lr=0.0)
    system._last_action_training_ids = [7, 8, 9]
    system._last_action_prompt_tokens = 2
    system._last_response_integrity = dict(INTEGRITY)
    system._pending_env_bon = {
        "query_text": "cohort query",
        "candidates": ["A", "B"],
        "schema": object(),
        "instance_id": "heldout-7",
        "instance_index": 7,
        "interaction_step": 8,
        "registered_run_seed": 0,
        "sampling_prompt_sha256": hashlib.sha256(b"sample prompt").hexdigest(),
        "candidate_sampling": {
            "requested_group_size": 2,
            "initial_sample_attempts": 1,
            "generation_failures": 0,
            "parse_failures": 0,
            "duplicates": 0,
            "valid_unique": 2,
            "candidate_count": 2,
        },
    }
    system._render_generation_prompt = lambda messages: "EXACT:" + messages[0][
        "content"
    ]
    system._score_env_candidate = lambda candidate, schema, meta: {
        "A": 0.8,
        "B": 0.1,
    }[candidate]
    observation = SimpleNamespace(
        content="", metadata={"env_feedback_reward": -0.4}, instance_complete=True
    )
    item = system.capture_frozen_tape_item(observation, sequence_index=0)
    assert item["instance_id"] == "heldout-7"
    assert item["committed_reward_pg"]["ids"] == [7, 8, 9]
    assert item["env_bon"]["prompt"] == "EXACT:cohort query"
    assert system._pending_env_bon["candidates"] == ["A", "B"]
    assert system.current_trainable_param_sha256() == system.current_trainable_param_sha256()


@pytest.mark.parametrize(
    "mutate, error",
    [
        (
            lambda tape: tape["items"][0]["env_bon"]["candidates"][0].__setitem__(
                "candidate", "tampered"
            ),
            "candidate hash mismatch",
        ),
        (
            lambda tape: tape["items"].reverse(),
            "order/sequence_index mismatch",
        ),
        (
            lambda tape: tape["items"][0].__setitem__("unexpected", True),
            "schema mismatch",
        ),
        (
            lambda tape: tape["items"][0]["env_bon"]["selected_batches"][
                0
            ]["ids"].__setitem__(0, 999),
            "selected batch digest mismatch",
        ),
        (
            lambda tape: tape["items"][0]["sampling_provenance"].__setitem__(
                "registered_run_seed", 999
            ),
            "sampling provenance digest mismatch",
        ),
        (
            lambda tape: tape.__setitem__("tape_sha256", "0" * 64),
            "root digest mismatch",
        ),
    ],
)
def test_tape_tampering_fails_before_any_update(mutate, error: str) -> None:
    system = make_system(lr=0.1)
    tape = make_tape(make_system(lr=0.0))
    tampered = deepcopy(tape)
    mutate(tampered)
    before = system.current_trainable_param_sha256()
    with pytest.raises(ValueError, match=error):
        system.replay_frozen_update_tape(
            tampered, expected_tape_sha256=tape["tape_sha256"]
        )
    assert system.current_trainable_param_sha256() == before


def test_recomputed_tampered_tape_still_fails_preregistered_digest() -> None:
    system = make_system(lr=0.1)
    tape = make_tape(make_system(lr=0.0), count=1)
    expected = tape["tape_sha256"]
    tampered = deepcopy(tape)
    record = tampered["items"][0]["env_bon"]["candidates"][0]
    record["candidate"] = "tampered"
    record["candidate_sha256"] = system._frozen_tape_digest(
        "tampered"
    )  # sha256(canonical JSON string), deliberately corrected below
    # Candidate hashes are raw UTF-8 hashes, while aggregate hashes are canonical.
    import hashlib

    record["candidate_sha256"] = hashlib.sha256(b"tampered").hexdigest()
    env_bon = tampered["items"][0]["env_bon"]
    env_bon["candidate_order_sha256"] = system._frozen_tape_digest(
        env_bon["candidates"]
    )
    item = tampered["items"][0]
    item["item_sha256"] = system._frozen_tape_digest(
        {key: value for key, value in item.items() if key != "item_sha256"}
    )
    tampered["tape_sha256"] = system._frozen_tape_digest(
        {key: value for key, value in tampered.items() if key != "tape_sha256"}
    )
    with pytest.raises(ValueError, match="preregistered digest"):
        system.replay_frozen_update_tape(tampered, expected_tape_sha256=expected)


def test_integrity_gate_and_duplicate_json_keys_fail_closed() -> None:
    system = make_system(lr=0.0)
    bad_integrity = dict(INTEGRITY, fallback=True)
    with pytest.raises(ValueError, match="no-fallback/schema gate"):
        system.record_frozen_tape_item(
            sequence_index=0,
            instance_id="x",
            instance_index=0,
            committed_training_ids=[1, 2],
            committed_prompt_tokens=1,
            committed_reward=-0.1,
            env_bon_prompt="p",
            env_bon_candidates=["A", "B"],
            env_bon_rewards=[0.2, 0.1],
            integrity=bad_integrity,
            sampling_provenance=sampling_provenance(),
        )
    with pytest.raises(ValueError, match="duplicate key"):
        system.validate_frozen_update_tape('{"schema_version":1,"schema_version":1}')


def test_historical_bon_candidate_duplicates_are_preserved_in_order() -> None:
    system = make_system(lr=0.0)
    system.initialize_and_snapshot_adapter_state()
    item = system.record_frozen_tape_item(
        sequence_index=0,
        instance_id="duplicate-candidates",
        instance_index=0,
        committed_training_ids=[1, 2, 3],
        committed_prompt_tokens=2,
        committed_reward=-0.1,
        env_bon_prompt="prompt",
        env_bon_candidates=["A", "A", "B"],
        env_bon_rewards=[0.7, 0.6, 0.1],
        integrity=dict(INTEGRITY),
        sampling_provenance=sampling_provenance(
            candidate_count=3, valid_unique=2, duplicates=1
        ),
    )
    tape = system.assemble_frozen_update_tape([item])
    assert [
        record["candidate"] for record in tape["items"][0]["env_bon"]["candidates"]
    ] == ["A", "A", "B"]
