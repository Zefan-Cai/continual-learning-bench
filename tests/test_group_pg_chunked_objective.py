"""CPU tests for the bounded-memory D2 group-PG objective."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import torch

from src.systems.qwen_local.system import QwenLocalSystem


class RecordingOutputHead(torch.nn.Linear):
    def __init__(self, hidden_size: int, vocab_size: int) -> None:
        super().__init__(hidden_size, vocab_size, bias=False)
        self.projected_token_counts: list[int] = []

    def forward(self, hidden_states: torch.Tensor) -> torch.Tensor:
        self.projected_token_counts.append(hidden_states.shape[-2])
        return super().forward(hidden_states)


class TinyDecoder(torch.nn.Module):
    def __init__(self, vocab_size: int, hidden_size: int) -> None:
        super().__init__()
        self.embed_tokens = torch.nn.Embedding(vocab_size, hidden_size)
        self.embed_tokens.requires_grad_(False)
        self.adapter_scale = torch.nn.Parameter(torch.tensor(0.25))

    def forward(self, input_ids: torch.Tensor, **_kwargs: object) -> object:
        embedded = self.embed_tokens(input_ids)
        hidden_states = embedded + self.adapter_scale * torch.tanh(embedded)
        return SimpleNamespace(last_hidden_state=hidden_states)


class TinyCausalLM(torch.nn.Module):
    """Small Qwen-shaped model whose output projection records its token axis."""

    def __init__(self, vocab_size: int = 23, hidden_size: int = 7) -> None:
        super().__init__()
        self.model = TinyDecoder(vocab_size, hidden_size)
        self.lm_head = RecordingOutputHead(hidden_size, vocab_size)
        self.lm_head.requires_grad_(False)
        self.forward_adapter_values: list[float] = []
        self.forward_logits_to_keep: list[int] = []
        self.gradient_checkpointing_kwargs: dict[str, object] | None = None

    def get_base_model(self) -> TinyCausalLM:
        return self

    def get_output_embeddings(self) -> RecordingOutputHead:
        return self.lm_head

    def gradient_checkpointing_enable(self, **kwargs: object) -> None:
        self.gradient_checkpointing_kwargs = kwargs

    def forward(
        self,
        input_ids: torch.Tensor,
        *,
        labels: None,
        use_cache: bool,
        logits_to_keep: int,
        return_dict: bool,
    ) -> object:
        assert labels is None
        assert use_cache is False
        assert return_dict is True
        self.forward_adapter_values.append(float(self.model.adapter_scale.detach()))
        self.forward_logits_to_keep.append(logits_to_keep)
        hidden_states = self.model(input_ids).last_hidden_state
        kept_hidden = hidden_states[:, -logits_to_keep:, :]
        return SimpleNamespace(logits=self.lm_head(kept_hidden))


class SpyOptimizer:
    def __init__(self, params: object, lr: float) -> None:
        del lr
        self.params = list(params)
        self.step_calls = 0

    def zero_grad(self, set_to_none: bool = True) -> None:
        del set_to_none
        for param in self.params:
            param.grad = None

    def step(self) -> None:
        self.step_calls += 1


def build_system(model: TinyCausalLM, *, ttt_max_tokens: int = 4096) -> QwenLocalSystem:
    system = QwenLocalSystem(
        method="ttt_rl",
        ttt_rl_source="sft",
        peft_method="lora",
        best_of_n=3,
        bon_critic="env",
        reward_update_rule="group_pg_instance",
        history_ttt=False,
        ttt_max_tokens=ttt_max_tokens,
    )
    system._model = model
    system.set_parameter_updates_enabled(True)
    system._clip_trainable_param_norms = lambda params: None
    return system


def reference_objective(
    model: TinyCausalLM,
    batches: list[dict[str, object]],
    *,
    max_tokens: int,
) -> torch.Tensor:
    valid_batches = [batch for batch in batches if len(batch["ids"]) >= 2]
    objective = torch.zeros(())
    for batch in valid_batches:
        ids = batch["ids"]
        offset = max(0, len(ids) - max_tokens)
        trimmed = ids[-max_tokens:]
        prompt_tokens = batch.get("prompt_tokens")
        ignored = (
            max(0, min(len(trimmed), int(prompt_tokens) - offset))
            if prompt_tokens is not None
            else 0
        )
        target_start = max(1, ignored)
        input_ids = torch.tensor([trimmed])
        hidden_states = model.model(input_ids).last_hidden_state
        prediction_hidden = hidden_states[:, target_start - 1 : -1, :]
        targets = input_ids[:, target_start:]
        logits = model.lm_head(prediction_hidden)
        candidate_loss = torch.nn.functional.cross_entropy(
            logits.float().reshape(-1, logits.shape[-1]),
            targets.reshape(-1),
        )
        objective = objective + (
            candidate_loss * float(batch.get("signed_weight", 1.0)) / len(valid_batches)
        )
    return objective


def install_optimizer_spy(
    monkeypatch: pytest.MonkeyPatch,
) -> list[SpyOptimizer]:
    optimizers: list[SpyOptimizer] = []

    def make_optimizer(params: object, lr: float) -> SpyOptimizer:
        optimizer = SpyOptimizer(params, lr)
        optimizers.append(optimizer)
        return optimizer

    monkeypatch.setattr(torch.optim, "AdamW", make_optimizer)
    monkeypatch.setattr(
        torch.nn.utils,
        "clip_grad_norm_",
        lambda params, max_norm: None,
    )
    return optimizers


def test_chunked_objective_matches_full_logits_value_and_gradient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    torch.manual_seed(17)
    chunked_model = TinyCausalLM()
    reference_model = TinyCausalLM()
    reference_model.load_state_dict(chunked_model.state_dict())
    system = build_system(chunked_model, ttt_max_tokens=12)
    optimizers = install_optimizer_spy(monkeypatch)
    batches: list[dict[str, object]] = [
        {
            "ids": [2, 3, 4, 5, 6, 7, 8, 9],
            "prompt_tokens": 3,
            "signed_weight": 1.25,
        },
        {
            "ids": [1, 5, 9, 2, 6, 10, 3],
            "prompt_tokens": 2,
            "signed_weight": -0.75,
        },
        {
            "ids": [4, 2, 8, 3, 7, 1],
            "prompt_tokens": 4,
            "signed_weight": 0.0,
        },
    ]

    chunked_value = system._train_lora_group_objective(batches, lr=1e-4)
    chunked_gradient = chunked_model.model.adapter_scale.grad.detach().clone()

    full_objective = reference_objective(
        reference_model, batches, max_tokens=system.ttt_max_tokens
    )
    full_objective.backward()
    full_gradient = reference_model.model.adapter_scale.grad

    assert chunked_value == pytest.approx(float(full_objective.detach()), abs=1e-6)
    torch.testing.assert_close(chunked_gradient, full_gradient, atol=1e-6, rtol=1e-6)
    assert len(optimizers) == 1
    assert optimizers[0].step_calls == 1
    assert system.grpo_optimizer_steps == 1
    assert chunked_model.forward_adapter_values == [0.25, 0.25, 0.25]


def test_group_trainer_never_materializes_full_sequence_logits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    torch.manual_seed(23)
    model = TinyCausalLM()
    system = build_system(model)
    optimizers = install_optimizer_spy(monkeypatch)
    # 4,300 input tokens exercise the production 4,096-token truncation budget:
    # 204 leading prompt tokens are dropped, leaving 3,696 prompt + 400 targets.
    long_ids = [index % 23 for index in range(4300)]
    batches: list[dict[str, object]] = [
        {
            "ids": long_ids,
            "prompt_tokens": 3900,
            "signed_weight": weight,
        }
        for weight in (1.0, -1.0, 0.0)
    ]

    system._train_lora_group_objective(batches, lr=1e-4)

    assert model.forward_logits_to_keep == [1, 1, 1]
    assert max(model.lm_head.projected_token_counts) == 128
    assert 4096 not in model.lm_head.projected_token_counts
    assert optimizers[0].step_calls == 1
    assert model.gradient_checkpointing_kwargs == {
        "gradient_checkpointing_kwargs": {"use_reentrant": False}
    }

    telemetry_line = next(
        line
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("GROUP_PG_TRAINER ")
    )
    telemetry = json.loads(telemetry_line.removeprefix("GROUP_PG_TRAINER "))
    assert telemetry == {
        "candidate_token_stats": [
            {
                "prompt_tokens_retained": 3696,
                "target_tokens": 400,
                "trimmed_tokens": 4096,
            }
        ]
        * 3,
        "group_size": 3,
        "logit_chunk_tokens": 128,
        "logits_to_keep": 1,
        "strategy": "decoder_hidden_hook+chunked_target_ce",
    }
