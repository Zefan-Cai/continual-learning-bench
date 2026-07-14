# Preregistration: Cohort qonly frozen-tape causal gate

Status: **preregistered before any run on the new corpora**  
Date: 2026-07-13 America/Los_Angeles  
Branch: `codex/cohort-qonly-causal`  
Parent commit: `2d79ec6cd6ce4520ed36e2f68e0afd49fe73d350`

## Question and scope

The historical Cohort signal (`+0.0609273` against a reset-per-instance
baseline) used `question_only`, prefix tuning with 512 virtual tokens,
environment-scored best-of-8 reports, one update step, and learning rate
`5e-4`. It did not use a sequential LR0 control, did not preserve candidate
tapes, and did not record parameter hashes. It is therefore a hypothesis, not
evidence that reward-driven parameter updates caused the gain.

This experiment asks a narrower causal question:

> When active and LR0 systems consume byte-identical Cohort update examples,
> candidate reports, rewards, ordering, and budgets, does the resulting prefix
> update improve performance on independently generated held-out Cohort
> instances?

The experiment is named **frozen-tape weight-update ablation**. It is not an
exact replication of the historical online mechanism, because later online
candidates would normally be sampled from already-updated parameters. This
name and limitation must be retained in every report.

The failed candidate-distillation formal and the group-PG smoke that failed its
candidate-diversity gate will not be expanded. This frozen-tape test is the
confirmatory parameter-adaptation mechanism family. A structured latent-state
learner is the only permitted later pivot if this family fails.

## Frozen configuration

The following historical settings are fixed for all tape collectors and both
evaluation arms:

```json
{
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
  "trust_remote_code": true,
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
  "reward_update_terminal": true,
  "reward_judge_provider": "env",
  "inject_env_reward": false,
  "distill_provider": "off",
  "distill_contrastive": true,
  "best_of_n": 8,
  "bon_temperature": 0.8,
  "bon_critic": "env",
  "bon_env_reward": "report",
  "history_ttt": false
}
```

Task settings are `action_budget=20`, `num_instances=20`,
`repeat_instructions=true`, `runs=1`, `max_workers=1`, and
`run_mode=replicate`.

The adapter initialization seed is `2026071400`. Tape/run seeds are exactly
`2026071401`, `2026071402`, and `2026071403`. The active and LR0 member of a
pair share the same adapter initialization, tape, held-out corpus, task order,
and evaluation code. The only allowed arm difference is:

```text
active: ttt_lr=5e-4 and reward_pg_lr=5e-4
LR0:    ttt_lr=0     and reward_pg_lr=0
```

No hyperparameter, prompt, token limit, failure policy, or threshold may be
changed after observing formal results.

## Data split

Two new deterministic frozen corpora were built from the released Cohort DGP
before GPU execution:

- adaptation corpus: DGP seed `2026071411`, schedule id
  `causal_adapt_2026071411`, corpus SHA-256
  `31f94d0130573e347ef8276a44c8d71c7b2159b881334798a7b73cd084ae9d9a`,
  schedule SHA-256
  `a471a2e1dca55317dda9d6858b2103f3cd51539d9cfa081836a338058eed44f5`;
- held-out evaluation corpus: DGP seed `2026071412`, schedule id
  `causal_eval_2026071412`, corpus SHA-256
  `a5c56f2c408b0d909a31cbfad490a95d5facd583eb8d3cbb3190aea4c39e0b80`,
  schedule SHA-256
  `81dde8ec92fe18af6410fbf38ff9cebd52fc298d534d9fb5107df3da5afe09ea`.

Each corpus contains the same preregistered 5-stage/20-instance structure as
the default schedule but uses an independently generated population and
independent study draws. Dataset manifests, database hashes, ground-truth
hashes, schedule hash, and aggregate corpus hash are frozen in each checked-in
`manifest.json` and must be copied into the launch artifact. The evaluation
corpus is never used for candidate scoring or a parameter update.

## Tape collection and replay

For each run seed, a frozen initial policy collects one 20-instance adaptation
tape. A tape item records, in order:

1. the committed terminal reward-PG training example and reward;
2. all valid environment-BoN candidate reports and their scores;
3. the exact positive/negative SFT batches selected by the historical rule;
4. prompt, candidate, reward, task-instance, and combined item digests;
5. schema/parse/fallback status and sampling provenance.

The zero-initialized prefix adapter is installed and hashed before the first
collector query, and the collector executes both historical update calls at
learning rate zero. Candidate sampling uses the registered global run seed and
the historical eager env-BoN path; only the terminal pending group is retained
in the tape. The collector's trainable hash must remain byte-identical from
start to finish.

The collector must never change trainable parameters. Each pair then replays
the same tape through the same two historical update paths in the same order.
The LR0 arm executes the optimizer calls with zero learning rates; it may not
skip the calls. After replay, all update paths are frozen and the system is
evaluated once on the held-out corpus. Evaluation responses may differ as a
consequence of learned parameters; the frozen initial instance prompts,
dataset, order, action budget, decoding settings, and scorer remain matched.

## Integrity gate

A seed pair is invalid and must be repaired or rerun, rather than counted as a
negative result, if any of these conditions fails:

- the tape has exactly 20 unique real Cohort instances in canonical order;
- no collector or evaluation outcome is synthetic, timed out, recovered by a
  fallback, or missing;
- every tape digest verifies before replay, and both arms report the identical
  tape SHA-256;
- the six evaluation cells share one initial trainable-parameter SHA-256;
- every LR0 before/after/final parameter hash equals its initial hash;
- every active final parameter hash differs from its initial hash and at least
  one audited replay update changes the hash;
- active and LR0 execute the same ordered update-operation count per tape item;
- model, tokenizer, source commit, environment lock, task, dataset, order,
  budget, adapter initialization, and evaluation settings match within pair;
- each evaluation cell has exactly 20 unique held-out outcomes;
- neither arm has a hard schema failure, and the active arm's total parse
  retry/repair count is no greater than its paired LR0 arm.

Tampered, reordered, truncated, or schema-incompatible tapes must fail closed.

## Confirmatory endpoint and decision rule

For each run seed, compute the paired mean over the 20 held-out instance
rewards:

```text
delta_seed = mean_i(reward_active[seed, i] - reward_lr0[seed, i])
```

The overall effect is the unweighted mean of the three `delta_seed` values.
The clustered 95% confidence interval is estimated with 50,000 deterministic
hierarchical paired bootstrap replicates using seed `2026071499`: sample the
three run seeds with replacement, sample the 20 canonical instance IDs with
replacement once per replicate, apply the same sampled IDs to both arms and
all selected seeds, and average the paired deltas. The percentile 2.5% and
97.5% quantiles form the interval.

The gate passes only if all of the following hold:

1. all three valid seed-level deltas are strictly positive;
2. mean paired delta is at least `+0.02` bits/cohort;
3. the clustered 95% interval lower bound is strictly above zero;
4. the integrity gate passes;
5. there is no schema/format regression.

If the valid experiment misses any efficacy threshold, the frozen-tape
parameter-adaptation test is a no-go. No broad sweep follows. If it passes,
the next preregistered work is a mechanism check (restore/rollback and
reward-shuffle) followed by one transfer setting; those results are not part
of this initial gate.

## Compute and launch policy

Use an existing safely idle A100-40G Pluto node when available. New placement
prefers P1 and then P2, but a formal run may not be launched from unpushed code
or an unverified deployment. CPU unit/tamper tests and a two-instance GPU
record/replay smoke must pass before the three collectors and six evaluation
cells are started.
