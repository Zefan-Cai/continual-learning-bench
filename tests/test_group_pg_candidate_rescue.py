"""Bounded deterministic rescue tests for instance group-PG sampling."""

from __future__ import annotations

from types import SimpleNamespace

from pydantic import BaseModel, Field
import pytest
import torch

from src.systems.qwen_local.system import QwenLocalSystem


def _system(best_of_n: int = 4, *, run_seed: int = 20260712) -> QwenLocalSystem:
    system = QwenLocalSystem(
        best_of_n=best_of_n,
        bon_critic="env",
        reward_update_rule="group_pg_instance",
        grpo_run_seed=run_seed,
    )
    system.reset()
    system._merge_generation_prefix = lambda _prefix, continuation: continuation
    system._strip_think = lambda raw: raw

    def parse(cleaned, _schema):
        if cleaned == "PARSE_FAIL":
            raise ValueError("intentional parse failure")
        return SimpleNamespace(model_dump_json=lambda: cleaned), False

    system._parse_action = parse
    return system


def _install_sequence(system: QwenLocalSystem, sequence: list[object]) -> list[str]:
    remaining = iter(sequence)
    calls: list[str] = []

    def generate(prompt, *, max_new_tokens):
        calls.append(f"{prompt}:{max_new_tokens}")
        item = next(remaining)
        if isinstance(item, Exception):
            raise item
        return str(item), {}

    system._generate_text = generate
    return calls


def _force_sample(system: QwenLocalSystem) -> None:
    system._stash_env_bon_candidates(
        "PROMPT",
        "PREFIX",
        "PRIMARY",
        "query",
        object,
        32,
        force_sample=True,
        primary_continuation="raw-primary",
    )


def test_degenerate_initial_group_rescues_until_second_unique() -> None:
    system = _system(best_of_n=4)
    calls = _install_sequence(
        system,
        ["PRIMARY", "PRIMARY", "PRIMARY", "RESCUED"],
    )

    _force_sample(system)

    sampling = system._pending_env_bon["candidate_sampling"]
    assert len(calls) == 4
    assert system._pending_env_bon["candidates"] == ["PRIMARY", "RESCUED"]
    assert sampling == {
        "requested_group_size": 4,
        "initial_sample_attempts": 3,
        "rescue_sample_attempts": 1,
        "sample_attempts": 4,
        "generation_failures": 0,
        "parse_failures": 0,
        "duplicates": 3,
        "valid_unique": 2,
    }
    assert len(system._pending_env_bon["candidates"]) <= system.best_of_n


def test_exhausted_rescue_remains_auditable_no_group_skip() -> None:
    system = _system(best_of_n=3)
    calls = _install_sequence(system, ["PRIMARY"] * 4)

    _force_sample(system)
    sampling = dict(system._pending_env_bon["candidate_sampling"])
    system._env_best_of_n_train(
        SimpleNamespace(content="", metadata={}, instance_complete=True)
    )

    assert len(calls) == 4
    assert sampling["initial_sample_attempts"] == 2
    assert sampling["rescue_sample_attempts"] == 2
    assert sampling["sample_attempts"] == 4
    assert sampling["duplicates"] == 4
    assert sampling["valid_unique"] == 1
    assert system.grpo_skipped_no_group == 1
    assert system.grpo_updates == 0
    assert system._grpo_instance_log[-1]["skipped"] == "no_group"
    assert system._grpo_instance_log[-1]["candidate_sampling"] == sampling


def test_non_degenerate_initial_group_does_not_rescue() -> None:
    system = _system(best_of_n=4)
    calls = _install_sequence(system, ["SECOND", "THIRD", "FOURTH"])

    _force_sample(system)

    sampling = system._pending_env_bon["candidate_sampling"]
    assert len(calls) == system.best_of_n - 1
    assert sampling["initial_sample_attempts"] == system.best_of_n - 1
    assert sampling["rescue_sample_attempts"] == 0
    assert sampling["sample_attempts"] == system.best_of_n - 1
    assert sampling["valid_unique"] == system.best_of_n


def test_rescue_accounting_distinguishes_failures_and_duplicates() -> None:
    system = _system(best_of_n=3)
    _install_sequence(
        system,
        [RuntimeError("generation failed"), "PARSE_FAIL", "PRIMARY", "RESCUED"],
    )

    _force_sample(system)

    sampling = system._pending_env_bon["candidate_sampling"]
    assert sampling == {
        "requested_group_size": 3,
        "initial_sample_attempts": 2,
        "rescue_sample_attempts": 2,
        "sample_attempts": 4,
        "generation_failures": 1,
        "parse_failures": 1,
        "duplicates": 1,
        "valid_unique": 2,
    }
    assert sampling["sample_attempts"] == (
        sampling["initial_sample_attempts"] + sampling["rescue_sample_attempts"]
    )
    assert system._pending_env_bon["candidate_records"] == [
        {"answer": "PRIMARY", "continuation": "raw-primary"},
        {"answer": "RESCUED", "continuation": "RESCUED"},
    ]


def test_lazy_rescue_replays_same_seeded_rng_stream() -> None:
    def materialize() -> dict:
        system = _system(best_of_n=3, run_seed=77)
        calls = 0

        def generate(_prompt, *, max_new_tokens):
            nonlocal calls
            assert max_new_tokens == 32
            calls += 1
            random_value = int(torch.randint(0, 2**31, (1,)).item())
            if calls <= system.best_of_n - 1:
                return "PRIMARY", {"random_value": random_value}
            return f"RESCUED-{random_value}", {"random_value": random_value}

        system._generate_text = generate
        system._stash_env_bon_candidates(
            "PROMPT",
            "PREFIX",
            "PRIMARY",
            "query",
            object,
            32,
            primary_continuation="raw-primary",
            instance_index=5,
            instance_id="cohort-five",
            interaction_step=11,
        )
        system._materialize_pending_env_bon_candidates()
        return system._pending_env_bon

    first = materialize()
    second = materialize()

    assert first["sampling_seed"] == second["sampling_seed"]
    assert first["candidates"] == second["candidates"]
    assert first["candidate_records"] == second["candidate_records"]
    assert first["candidate_sampling"] == second["candidate_sampling"]
    assert first["candidate_sampling"]["initial_sample_attempts"] == 2
    assert first["candidate_sampling"]["rescue_sample_attempts"] == 1
    assert first["candidate_sampling"]["sample_attempts"] == 3


class _UnitIntervalSubmission(BaseModel):
    alpha__s12: float = Field(ge=0, le=1)
    alpha__s24: float = Field(ge=0, le=1)
    alpha__s36: float = Field(ge=0, le=1)
    beta__s12: float = Field(ge=0, le=1)
    beta__s24: float = Field(ge=0, le=1)
    beta__s36: float = Field(ge=0, le=1)


def _structured_system(
    *, run_seed: int = 77, adapter_seed: int | None = None
) -> QwenLocalSystem:
    system = QwenLocalSystem(
        best_of_n=4,
        bon_critic="env",
        reward_update_rule="candidate_distill_instance",
        grpo_run_seed=run_seed,
        grpo_adapter_init_seed=adapter_seed,
        grpo_candidate_proposer="unit_interval_jitter",
    )
    system.reset()
    system._generate_text = lambda *_args, **_kwargs: pytest.fail(
        "structured proposer must not call model.generate"
    )
    return system


def _structured_materialize(
    *, run_seed: int = 77, adapter_seed: int | None = None
) -> dict:
    system = _structured_system(run_seed=run_seed, adapter_seed=adapter_seed)
    primary = _UnitIntervalSubmission(
        alpha__s12=0.8,
        alpha__s24=0.5,
        alpha__s36=0.2,
        beta__s12=0.7,
        beta__s24=0.4,
        beta__s36=0.1,
    ).model_dump_json()
    system._stash_env_bon_candidates(
        "PROMPT",
        "{",
        primary,
        "query",
        _UnitIntervalSubmission,
        32,
        primary_continuation=primary[1:],
        instance_index=5,
        instance_id="cohort-five",
        interaction_step=11,
    )
    system._materialize_pending_env_bon_candidates()
    return system._pending_env_bon


def test_unit_interval_proposer_is_deterministic_diverse_and_schema_valid() -> None:
    first = _structured_materialize()
    second = _structured_materialize()

    assert first["candidates"] == second["candidates"]
    assert first["candidate_records"] == second["candidate_records"]
    assert len(first["candidates"]) == 4
    assert len(set(first["candidates"])) == 4
    for answer in first["candidates"]:
        parsed = _UnitIntervalSubmission.model_validate_json(answer)
        assert parsed.alpha__s12 >= parsed.alpha__s24 >= parsed.alpha__s36
        assert parsed.beta__s12 >= parsed.beta__s24 >= parsed.beta__s36

    sampling = first["candidate_sampling"]
    assert sampling["candidate_proposer"] == "unit_interval_jitter"
    assert sampling["proposal_seed_scheme"] == (
        "blake2b(base_sampling_seed,attempt_index)"
    )
    assert sampling["proposal_jitter_scale"] == 0.35
    assert sampling["requested_group_size"] == 4
    assert sampling["target_valid_unique"] == 4
    assert sampling["max_sample_attempts"] == 6
    assert sampling["initial_sample_attempts"] == 3
    assert sampling["rescue_sample_attempts"] == 0
    assert sampling["sample_attempts"] == 3
    assert sampling["model_generation_attempts"] == 0
    assert sampling["structured_proposal_attempts"] == 3
    assert sampling["generation_failures"] == 0
    assert sampling["parse_failures"] == 0
    assert sampling["duplicates"] == 0
    assert sampling["valid_unique"] == 4
    assert sampling["proposal_mode_counts"] == {
        "primary_policy": 1,
        "unit_interval_jitter": 3,
    }
    assert len(sampling["proposal_seed_digests"]) == 3
    assert len(set(sampling["proposal_seed_digests"])) == 3
    assert first["candidate_proposer"] == "unit_interval_jitter"
    assert first["objective"] == "group_normalized_candidate_distillation"
    assert all(
        record["continuation"] == record["answer"][1:]
        for record in first["candidate_records"][1:]
    )
    assert all(
        record["source"] == "unit_interval_jitter"
        for record in first["candidate_records"][1:]
    )


def test_structured_materialization_preserves_adapter_seed_provenance() -> None:
    pending = _structured_materialize(adapter_seed=2026071200)

    assert pending["grpo_adapter_init_seed"] == 2026071200


def test_unit_interval_proposer_uses_independent_run_seed_streams() -> None:
    assert (
        _structured_materialize(run_seed=77)["candidates"]
        != (_structured_materialize(run_seed=78)["candidates"])
    )


def test_attempt_streams_are_candidate_local() -> None:
    seeds = [
        QwenLocalSystem._derive_grpo_proposal_seed(
            sampling_seed=1234, attempt_index=index
        )
        for index in range(6)
    ]
    assert seeds == [
        QwenLocalSystem._derive_grpo_proposal_seed(
            sampling_seed=1234, attempt_index=index
        )
        for index in range(6)
    ]
    assert len(set(seeds)) == len(seeds)

    system = _structured_system()
    primary = _UnitIntervalSubmission(
        alpha__s12=0.8,
        alpha__s24=0.5,
        alpha__s36=0.2,
        beta__s12=0.7,
        beta__s24=0.4,
        beta__s36=0.1,
    ).model_dump(mode="json")
    expected = system._unit_interval_jitter_candidate(
        primary, _UnitIntervalSubmission, proposal_seed=seeds[1]
    )
    for _ in range(20):
        system._unit_interval_jitter_candidate(
            primary, _UnitIntervalSubmission, proposal_seed=seeds[0]
        )
    assert (
        system._unit_interval_jitter_candidate(
            primary, _UnitIntervalSubmission, proposal_seed=seeds[1]
        )
        == expected
    )


def test_canonical_candidate_identity_ignores_json_formatting() -> None:
    canonical = QwenLocalSystem._canonical_candidate_identity(
        '{"alpha__s12":0.8,"alpha__s24":0.5,"alpha__s36":0.2,'
        '"beta__s12":0.7,"beta__s24":0.4,"beta__s36":0.1}',
        _UnitIntervalSubmission,
    )
    reordered = QwenLocalSystem._canonical_candidate_identity(
        '{ "beta__s36": 0.1, "beta__s24": 0.4, "beta__s12": 0.7,'
        ' "alpha__s36": 0.2, "alpha__s24": 0.5, "alpha__s12": 0.8 }',
        _UnitIntervalSubmission,
    )
    assert canonical == reordered
    assert " " not in canonical
    assert canonical.startswith('{"alpha__s12":')


def test_structured_refill_stops_at_target_and_cap() -> None:
    system = _structured_system()
    primary_model = _UnitIntervalSubmission(
        alpha__s12=0.8,
        alpha__s24=0.5,
        alpha__s36=0.2,
        beta__s12=0.7,
        beta__s24=0.4,
        beta__s36=0.1,
    )
    primary = primary_model.model_dump_json()

    def candidate(alpha: float) -> str:
        data = primary_model.model_dump()
        data["alpha__s12"] = alpha
        return _UnitIntervalSubmission.model_validate(data).model_dump_json()

    proposals = iter(
        [primary, primary, candidate(0.81), primary, candidate(0.82), candidate(0.83)]
    )
    calls = 0

    def propose(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return next(proposals)

    system._unit_interval_jitter_candidate = propose
    system._stash_env_bon_candidates(
        "PROMPT",
        "{",
        primary,
        "query",
        _UnitIntervalSubmission,
        32,
        force_sample=True,
        primary_continuation=primary[1:],
        sampling_seed=99,
    )
    sampling = system._pending_env_bon["candidate_sampling"]
    assert calls == 6
    assert sampling["sample_attempts"] == sampling["max_sample_attempts"] == 6
    assert sampling["valid_unique"] == sampling["target_valid_unique"] == 4
    assert sampling["duplicates"] == 3


class _IncompleteSubmission(BaseModel):
    alpha__s12: float = Field(ge=0, le=1)
    alpha__s24: float = Field(ge=0, le=1)


def test_structured_schema_requires_complete_triplets() -> None:
    system = _structured_system()
    primary = _IncompleteSubmission(alpha__s12=0.8, alpha__s24=0.5).model_dump_json()
    with pytest.raises(ValueError, match="complete survival triplets"):
        system._stash_env_bon_candidates(
            "PROMPT",
            "{",
            primary,
            "query",
            _IncompleteSubmission,
            32,
            force_sample=True,
            sampling_seed=99,
        )


def test_candidate_distillation_objective_propagates_to_metadata_and_update_log() -> (
    None
):
    system = _structured_system()
    primary = _UnitIntervalSubmission(
        alpha__s12=0.8,
        alpha__s24=0.5,
        alpha__s36=0.2,
        beta__s12=0.7,
        beta__s24=0.4,
        beta__s36=0.1,
    ).model_dump_json()
    system._stash_env_bon_candidates(
        "PROMPT",
        "{",
        primary,
        "query",
        _UnitIntervalSubmission,
        32,
        force_sample=True,
        primary_continuation=primary[1:],
        sampling_seed=99,
    )
    pending = system._pending_env_bon
    captured_targets: list[tuple[str, str]] = []
    system._build_distill_batch = lambda prompt, target, weight: (
        captured_targets.append((prompt, target))
        or {"ids": [1] * 16, "prompt_tokens": 8, "signed_weight": weight}
    )
    system._ensure_lora_model = lambda: None

    def train(batches, *, lr):
        assert len(batches) == 4
        system.grpo_optimizer_steps += 1
        return 0.125

    system._train_lora_group_objective = train
    parameter_hashes = iter(("a" * 64, "b" * 64))
    system._trainable_param_sha256 = lambda: next(parameter_hashes)
    scored = [
        (float(index), candidate)
        for index, candidate in enumerate(pending["candidates"])
    ]
    system._grpo_instance_update(pending, scored)

    metadata = system._grpo_usage_metadata()
    assert metadata["grpo_objective"] == "group_normalized_candidate_distillation"
    assert metadata["grpo_candidate_proposer"] == "unit_interval_jitter"
    assert metadata["grpo_trainable_param_sha256_initial"] == "a" * 64
    assert metadata["grpo_trainable_param_sha256_current"] == "b" * 64
    log = system._grpo_instance_log[-1]
    assert log["objective"] == "group_normalized_candidate_distillation"
    assert log["candidate_proposer"] == "unit_interval_jitter"
    assert log["trainable_param_sha256_before"] == "a" * 64
    assert log["trainable_param_sha256_after"] == "b" * 64
    assert captured_targets == [
        ("PROMPT{", record["continuation"]) for record in pending["candidate_records"]
    ]


@pytest.mark.parametrize(
    ("params", "message"),
    [
        ({"grpo_candidate_proposer": "bogus"}, "grpo_candidate_proposer"),
        (
            {"grpo_candidate_proposer": "unit_interval_jitter"},
            "only supported by reward_update_rule='candidate_distill_instance'",
        ),
    ],
)
def test_candidate_proposer_configuration_is_fail_closed(
    params: dict, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        QwenLocalSystem(**params)


@pytest.mark.parametrize(
    "adapter_seed",
    [True, -1, 1.5, "2026071200"],
)
def test_adapter_init_seed_configuration_is_fail_closed(adapter_seed: object) -> None:
    with pytest.raises(ValueError, match="grpo_adapter_init_seed"):
        QwenLocalSystem(grpo_adapter_init_seed=adapter_seed)


def test_adapter_init_seed_is_deterministic_and_restores_cpu_rng() -> None:
    def draw(*, adapter_seed: int, ambient_seed: int) -> tuple[float, float]:
        system = QwenLocalSystem(
            best_of_n=2,
            bon_critic="env",
            reward_update_rule="candidate_distill_instance",
            grpo_candidate_proposer="unit_interval_jitter",
            grpo_adapter_init_seed=adapter_seed,
        )
        system._model = torch.nn.Linear(1, 1)
        torch.manual_seed(ambient_seed)
        expected_after = torch.rand(())
        torch.manual_seed(ambient_seed)
        adapter_draw = system._install_peft_adapter(
            object(), lambda _model, _config: torch.rand(())
        )
        observed_after = torch.rand(())
        assert torch.equal(observed_after, expected_after)
        return float(adapter_draw), float(observed_after)

    first, _ = draw(adapter_seed=2026071200, ambient_seed=11)
    second, _ = draw(adapter_seed=2026071200, ambient_seed=999)
    different, _ = draw(adapter_seed=2026071201, ambient_seed=11)

    assert first == second
    assert first != different


def test_default_adapter_seed_does_not_change_instance_metadata_shape() -> None:
    system = QwenLocalSystem(
        best_of_n=2,
        bon_critic="env",
        reward_update_rule="candidate_distill_instance",
        grpo_candidate_proposer="unit_interval_jitter",
    )

    assert "grpo_adapter_init_seed" not in system._grpo_usage_metadata()
