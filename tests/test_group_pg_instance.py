"""CPU unit smoke for D2 grpo_instance (no GPU needed). Run from repo root."""
import json
import sys
from types import SimpleNamespace

import torch

sys.path.insert(0, ".")
from src.systems.qwen_local.system import QwenLocalSystem

MODEL = "/sensei-fs/users/zcai/models/Qwen3-4B"
FAILED = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name, flush=True)
    if not cond:
        FAILED.append(name)


OLD_KW = dict(
    model_path=MODEL,
    method="ttt_rl",
    ttt_rl_source="sft",
    peft_method="lora",
    lora_rank=64,
    lora_alpha=128,
    lora_target_modules="q_proj,v_proj,gate_proj,up_proj,down_proj",
    history_ttt=False,
    best_of_n=8,
    bon_temperature=0.8,
    bon_critic="env",
    distill_provider="off",
    distill_contrastive=True,
    reward_judge_provider="env",
    ttt_lr=1e-4,
    reward_pg_lr=1e-4,
    ttt_steps=1,
    context_policy="question_only",
    bon_env_reward="near",
)

# 1. old-cell param set (no new params) -> default-off everywhere
old = QwenLocalSystem(**OLD_KW)
old.reset()
check("old rule default reward_pg", old.reward_update_rule == "reward_pg")
check("old usage-metadata empty", old._grpo_usage_metadata() == {})
arts = old.get_run_artifacts()
check("old artifacts no grpo keys", not any("grpo" in k for k in arts))
old.set_parameter_updates_enabled(False)
check("old rule baseline semantics unchanged", old.parameter_updates_enabled is True)

# 2. honest rule name and legacy alias both construct; metadata is explicit.
g = QwenLocalSystem(**{**OLD_KW, "reward_update_rule": "group_pg_instance"})
g.reset()
check("group-PG rule set", g.reward_update_rule == "group_pg_instance")
check(
    "grpo defaults",
    g.grpo_adv_clip == 2.0
    and g.grpo_std_floor == 1e-4
    and g.parameter_updates_enabled is True,
)
meta = g._grpo_usage_metadata()
check("grpo usage-metadata populated", meta.get("grpo_updates") == 0 and "last_grpo_loss" in meta)
check(
    "honest objective label",
    meta.get("grpo_objective") == "group_normalized_policy_gradient",
)
arts = g.get_run_artifacts()
check("grpo artifacts populated", "grpo_instance_log" in arts and arts["grpo_updates"] == 0)
check("grpo artifacts json-serializable", json.dumps(arts.get("grpo_instance_log")) == "[]")

# 3. invalid combos raise
for kw, name in [
    ({"reward_update_rule": "grpo_instance", "best_of_n": 1}, "reject best_of_n=1"),
    ({"reward_update_rule": "grpo_instance", "bon_critic": "llm"}, "reject bon_critic=llm"),
    ({"reward_update_rule": "grpo_instance", "grpo_adv_clip": 0.0}, "reject clip=0"),
    ({"reward_update_rule": "group_pg_instance", "grpo_run_seed": -1}, "reject seed<0"),
    ({"freeze_parameter_updates": True}, "reject frozen switch on old rule"),
    ({"reward_update_rule": "bogus_rule"}, "reject unknown rule"),
]:
    try:
        QwenLocalSystem(**{**OLD_KW, **kw})
        check(name, False)
    except ValueError:
        check(name, True)

# 4. _adapt_from_feedback bypass under grpo_instance
g2 = QwenLocalSystem(**{**OLD_KW, "reward_update_rule": "grpo_instance"})
g2.reset()
g2._last_action_training_ids = [1, 2, 3]
g2._last_action_prompt_tokens = 1
called = []
g2._infer_feedback_reward = lambda obs: called.append("reward") or 1.0
obs = SimpleNamespace(content="", metadata={"env_feedback_reward": 0.7}, instance_complete=True)
g2._adapt_from_feedback(obs)
check("per-step PG bypassed", called == [] and g2.reward_pg_updates == 0)

# 5. advantage math + update path with stubbed trainer/tokenizer-free batches
g3 = QwenLocalSystem(**{**OLD_KW, "reward_update_rule": "grpo_instance"})
g3.reset()
captured = {}
g3._ensure_lora_model = lambda: None
def fake_train(batches, *, lr):
    captured["batches"] = batches
    captured["lr"] = lr
    return 0.123
def attach_fake_group_trainer(system):
    def fake_group_train(batches, *, lr):
        captured["batches"] = batches
        captured["lr"] = lr
        system.grpo_optimizer_steps += 1
        return 0.123
    system._train_lora_group_objective = fake_group_train

attach_fake_group_trainer(g3)
g3._render_generation_prompt = lambda msgs: "PROMPT: " + msgs[0]["content"]
def fake_build(prompt_text, cand, weight):
    captured.setdefault("prompt_targets", []).append((prompt_text, cand))
    return {"ids": [1] * 16, "prompt_tokens": 8, "signed_weight": weight}
g3._build_distill_batch = fake_build
pending = {
    "query_text": "q",
    "candidates": ["A", "B", "C"],
    "schema": None,
    "prompt_for_attempt": "EXACT_PROMPT",
    "generation_prefix": "PREFIX",
    "sampling_prompt_sha256": __import__("hashlib").sha256(
        b"EXACT_PROMPTPREFIX"
    ).hexdigest(),
    "candidate_records": [
        {"answer": "A", "continuation": "raw-A"},
        {"answer": "B", "continuation": "raw-B"},
        {"answer": "C", "continuation": "raw-C"},
    ],
}
scored = [(0.9, "A"), (0.1, "B"), (0.5, "C")]
g3._grpo_instance_update(pending, scored)
ws = [round(b["signed_weight"], 4) for b in captured["batches"]]
check("grpo update fired", g3.grpo_updates == 1 and g3.last_grpo_loss == 0.123)
check("grpo lr = reward_pg_lr", captured["lr"] == 1e-4)
check("group advantages include zero-weight member", ws == [1.2247, -1.2247, 0.0])
check(
    "training uses exact sampled prompt and continuations",
    captured["prompt_targets"] == [
        ("EXACT_PROMPTPREFIX", "raw-A"),
        ("EXACT_PROMPTPREFIX", "raw-B"),
        ("EXACT_PROMPTPREFIX", "raw-C"),
    ],
)
check("grpo committed reward logged", g3.last_grpo_committed_reward == 0.9)
check(
    "grpo group stats",
    g3.last_grpo_group_size == 3
    and round(g3.last_grpo_reward_std, 4) == 0.3266,
)
check(
    "one optimizer step per group",
    g3._grpo_instance_log[-1]["n_batches"] == 3
    and g3._grpo_instance_log[-1]["optimizer_steps"] == 1
    and g3._grpo_instance_log[-1]["candidate_tokens_min"] == 8
    and g3._grpo_instance_log[-1]["prompt_tokens_retained_min"] == 8
    and g3.grpo_optimizer_steps == 1,
)

# 6. zero-diversity group -> low_std skip, no trainer call
captured.clear()
g3._grpo_instance_update(pending, [(0.5, "A"), (0.5, "B"), (0.5, "C")])
check(
    "low-std skip",
    g3.grpo_skipped_low_std == 1
    and "batches" not in captured
    and g3.grpo_updates == 1,
)

# 6b. Never claim exact-prompt PG when truncation retained zero prompt tokens.
captured.clear()
g_trunc = QwenLocalSystem(
    **{**OLD_KW, "reward_update_rule": "group_pg_instance"}
)
g_trunc.reset()
g_trunc._ensure_lora_model = lambda: None
attach_fake_group_trainer(g_trunc)
g_trunc._build_distill_batch = lambda prompt, cand, weight: {
    "ids": [1] * 16,
    "prompt_tokens": 0,
    "signed_weight": weight,
}
g_trunc._grpo_instance_update(pending, scored)
check(
    "zero retained prompt is rejected",
    g_trunc.grpo_updates == 0
    and g_trunc.grpo_optimizer_steps == 0
    and g_trunc._grpo_instance_log[-1]["skipped"] == "prompt_truncated",
)

# 7. adv clip honored
captured.clear()
g4 = QwenLocalSystem(**{**OLD_KW, "reward_update_rule": "grpo_instance", "grpo_adv_clip": 1.0})
g4.reset()
g4._ensure_lora_model = lambda: None
attach_fake_group_trainer(g4)
g4._render_generation_prompt = lambda msgs: "P"
g4._build_distill_batch = fake_build
g4._grpo_instance_update(pending, scored)
ws = [round(b["signed_weight"], 4) for b in captured["batches"]]
check("adv clip=1.0", ws == [1.0, -1.0, 0.0])

# 8. observe()-path branch: _env_best_of_n_train dispatches to GRPO / old path intact
g5 = QwenLocalSystem(**{**OLD_KW, "reward_update_rule": "grpo_instance"})
g5.reset()
g5._ensure_lora_model = lambda: None
attach_fake_group_trainer(g5)
g5._render_generation_prompt = lambda msgs: "P"
g5._build_distill_batch = fake_build
score_map = {"A": 0.9, "B": 0.1, "C": 0.5}
g5._score_env_candidate = lambda cand, schema, meta: score_map.get(cand)
g5._pending_env_bon = dict(pending)
captured.clear()
g5._env_best_of_n_train(SimpleNamespace(content="", metadata={}, instance_complete=True))
check(
    "observe-path group-PG dispatch",
    g5.grpo_updates == 1
    and g5.bon_updates == 0
    and len(captured["batches"]) == 3,
)

# 8b. Baseline/frozen execution must skip the post-instance GRPO update.
g5_frozen = QwenLocalSystem(
    **{
        **OLD_KW,
        "reward_update_rule": "group_pg_instance",
        "freeze_parameter_updates": True,
    }
)
g5_frozen.reset()
g5_frozen.set_parameter_updates_enabled(True)
g5_frozen._ensure_lora_model = lambda: None
attach_fake_group_trainer(g5_frozen)
norm_clip_calls = []
g5_frozen._clip_trainable_param_norms = lambda params: norm_clip_calls.append(params)
g5_frozen._render_generation_prompt = lambda msgs: "P"
g5_frozen._build_distill_batch = fake_build
g5_frozen._score_env_candidate = lambda cand, schema, meta: score_map.get(cand)
g5_frozen._pending_env_bon = dict(pending)
captured.clear()
g5_frozen.observe(
    SimpleNamespace(content="", metadata={}, instance_complete=True)
)
check(
    "training-disabled GRPO is frozen",
    g5_frozen.grpo_updates == 0
    and g5_frozen.grpo_optimizer_steps == 0
    and norm_clip_calls == []
    and "batches" not in captured,
)
check(
    "training-disabled metadata is explicit",
    g5_frozen._grpo_usage_metadata().get("parameter_updates_enabled") is False,
)
check(
    "frozen-stream hard gate is explicit",
    g5_frozen._grpo_usage_metadata().get("freeze_parameter_updates") is True,
)
try:
    fail_closed = QwenLocalSystem(
        **{**OLD_KW, "reward_update_rule": "grpo_instance"}
    )
    fail_closed.set_parameter_updates_enabled(False)
    fail_closed._train_lora_token_batches([], lr=1e-4)
    check("frozen trainer fails closed", False)
except RuntimeError as exc:
    check("frozen trainer fails closed", "updates are frozen" in str(exc))
try:
    fail_closed._train_lora_group_objective([], lr=1e-4)
    check("frozen group trainer fails closed", False)
except RuntimeError as exc:
    check("frozen group trainer fails closed", "updates are frozen" in str(exc))

o2 = QwenLocalSystem(**OLD_KW)  # old rule: best/worst SFT path unchanged
o2.reset()
o2._ensure_lora_model = lambda: None
o2._train_lora_token_batches = fake_train
o2._render_generation_prompt = lambda msgs: "P"
o2._build_distill_batch = fake_build
o2._score_env_candidate = lambda cand, schema, meta: score_map.get(cand)
o2._pending_env_bon = dict(pending)
captured.clear()
o2._env_best_of_n_train(SimpleNamespace(content="", metadata={}, instance_complete=True))
ws = [round(b["signed_weight"], 4) for b in captured["batches"]]
check(
    "old bonenv path unchanged (best +1.0, worst -0.25=default)",
    o2.bon_updates == 1
    and o2.grpo_updates == 0
    and ws == [1.0, -0.25],
)

# 9. single-candidate group -> no_group skip counter
g6 = QwenLocalSystem(**{**OLD_KW, "reward_update_rule": "grpo_instance"})
g6.reset()
g6._score_env_candidate = lambda cand, schema, meta: 0.9 if cand == "A" else None
g6._pending_env_bon = {"query_text": "q", "candidates": ["A", "B"], "schema": None}
g6._env_best_of_n_train(SimpleNamespace(content="", metadata={}, instance_complete=True))
check("no-group skip", g6.grpo_skipped_no_group == 1 and g6.grpo_updates == 0)

# 10. D2 lazily samples only the terminal candidate group; old bonenv stays eager.
def stub_candidate_generation(system):
    calls = []

    def fake_generate(prompt, *, max_new_tokens):
        calls.append((prompt, max_new_tokens))
        return f'{{"candidate":{len(calls)}}}', {}

    system._generate_text = fake_generate
    system._merge_generation_prefix = lambda prefix, raw: raw
    system._strip_think = lambda raw: raw
    system._parse_action = lambda cleaned, schema: (
        SimpleNamespace(model_dump_json=lambda: cleaned),
        False,
    )
    return calls


lazy = QwenLocalSystem(
    **{
        **OLD_KW,
        "best_of_n": 3,
        "reward_update_rule": "group_pg_instance",
        "grpo_run_seed": 20260712,
    }
)
lazy.reset()
lazy_calls = stub_candidate_generation(lazy)
lazy._stash_env_bon_candidates(
    "PROMPT",
    "PREFIX",
    "PRIMARY",
    "query",
    object,
    32,
    primary_continuation="raw-primary",
    instance_index=4,
    instance_id="instance-four",
    interaction_step=9,
)
check(
    "grpo candidate sampling deferred",
    lazy_calls == []
    and lazy._pending_env_bon["candidates"] == ["PRIMARY"]
    and "lazy_generation" in lazy._pending_env_bon,
)
precommitted_seed = lazy._pending_env_bon["lazy_generation"]["sampling_seed"]
same_seed = lazy._derive_grpo_candidate_seed(
    instance_index=4, instance_id="instance-four", interaction_step=9
)
different_seed = lazy._derive_grpo_candidate_seed(
    instance_index=4, instance_id="instance-four", interaction_step=10
)
check(
    "candidate seed is deterministic from run/instance/step",
    precommitted_seed == same_seed and precommitted_seed != different_seed,
)
lazy._materialize_pending_env_bon_candidates()
check(
    "grpo terminal group materialized",
    len(lazy_calls) == 2
    and lazy_calls == [("PROMPTPREFIX", 32), ("PROMPTPREFIX", 32)]
    and lazy._pending_env_bon["candidates"][0] == "PRIMARY"
    and len(lazy._pending_env_bon["candidates"]) == 3
    and "lazy_generation" not in lazy._pending_env_bon,
)
check(
    "grpo sampling provenance retained",
    lazy._pending_env_bon["sampling_seed"] == precommitted_seed
    and lazy._pending_env_bon["candidate_generation_seconds"] >= 0
    and lazy._pending_env_bon["grpo_run_seed"] == 20260712
    and lazy._pending_env_bon["seed_instance_index"] == 4
    and lazy._pending_env_bon["seed_interaction_step"] == 9,
)
check(
    "exact sampling prompt/continuations retained",
    lazy._pending_env_bon["prompt_for_attempt"] == "PROMPT"
    and lazy._pending_env_bon["generation_prefix"] == "PREFIX"
    and lazy._pending_env_bon["candidate_records"][0]
    == {"answer": "PRIMARY", "continuation": "raw-primary"},
)

eager = QwenLocalSystem(**{**OLD_KW, "best_of_n": 3})
eager.reset()
eager_calls = stub_candidate_generation(eager)
eager._stash_env_bon_candidates("PROMPT", "PREFIX", "PRIMARY", "query", object, 32)
check(
    "old bonenv sampling remains eager",
    len(eager_calls) == 2 and "lazy_generation" not in eager._pending_env_bon,
)

no_pending = QwenLocalSystem(
    **{**OLD_KW, "reward_update_rule": "grpo_instance"}
)
no_pending.reset()
no_pending.observe(
    SimpleNamespace(content="", metadata={}, instance_complete=True)
)
check(
    "terminal response failure is accounted",
    no_pending.grpo_skipped_no_group == 1
    and no_pending._grpo_instance_log == [
        {
            "group_size": 0,
            "skipped": "no_pending",
            "objective": "group_normalized_policy_gradient",
        }
    ],
)

# 11. Generation explicitly restores KV cache after LoRA training disabled it.


class FakeTokenizer:
    pad_token_id = 0
    eos_token_id = 2
    model_max_length = 128

    def __call__(self, prompt, return_tensors):
        return {"input_ids": torch.tensor([[1, 2]], dtype=torch.long)}

    def decode(self, token_ids, skip_special_tokens):
        return "ok"


class FakeConfig:
    max_position_embeddings = 128
    use_cache = False


class FakeModel:
    config = FakeConfig()

    def __init__(self):
        self.weight = torch.nn.Parameter(torch.zeros(1))
        self.kwargs = None

    def parameters(self):
        return iter([self.weight])

    def generate(self, **kwargs):
        self.kwargs = kwargs
        return torch.tensor([[1, 2, 3]], dtype=torch.long)


cache_test = QwenLocalSystem()
fake_model = FakeModel()
cache_test._load_model = lambda: (FakeTokenizer(), fake_model)
cache_test._generate_text("prompt", max_new_tokens=4)
check(
    "generation re-enables KV cache",
    fake_model.kwargs.get("use_cache") is True,
)

# 12. The real group trainer evaluates all members under one policy and steps once.
class TinyGroupModel(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.weight = torch.nn.Parameter(torch.tensor(0.25))
        self.forward_weights = []

    def forward(self, input_ids, labels):
        self.forward_weights.append(float(self.weight.detach()))
        target = input_ids.float().mean() / 10.0
        return SimpleNamespace(loss=(self.weight - target) ** 2)


class SpyOptimizer:
    def __init__(self, params, lr):
        self.params = list(params)
        self.step_calls = 0

    def zero_grad(self, set_to_none=True):
        for param in self.params:
            param.grad = None

    def step(self):
        self.step_calls += 1


group_real = QwenLocalSystem(
    **{**OLD_KW, "reward_update_rule": "group_pg_instance"}
)
group_real._model = TinyGroupModel()
group_real.set_parameter_updates_enabled(True)
group_real._clip_trainable_param_norms = lambda params: None
real_adamw = torch.optim.AdamW
optimizer_spy = None
try:
    def make_spy_optimizer(params, lr):
        global optimizer_spy
        optimizer_spy = SpyOptimizer(params, lr)
        return optimizer_spy

    torch.optim.AdamW = make_spy_optimizer
    group_real._train_lora_group_objective(
        [
            {"ids": [1, 2, 3], "prompt_tokens": 1, "signed_weight": 1.0},
            {"ids": [1, 2, 4], "prompt_tokens": 1, "signed_weight": -1.0},
            {"ids": [1, 2, 5], "prompt_tokens": 1, "signed_weight": 0.0},
        ],
        lr=1e-4,
    )
finally:
    torch.optim.AdamW = real_adamw
check(
    "real group trainer makes exactly one optimizer step",
    optimizer_spy is not None
    and optimizer_spy.step_calls == 1
    and group_real.grpo_optimizer_steps == 1,
)
check(
    "all candidates evaluated under identical pre-update policy",
    group_real._model.forward_weights == [0.25, 0.25, 0.25],
)

print("=" * 40)
if FAILED:
    print("UNIT_SMOKE_FAILED:", FAILED)
    sys.exit(1)
print("UNIT_SMOKE_ALL_PASS")
