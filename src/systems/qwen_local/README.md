# Local Qwen system

`qwen_local` runs a local Hugging Face causal language model and exposes the
TTT, reward-update, and environment-scored best-of-N paths used by the
TTT-RL experiments.

The corrected D2 rule is `group_pg_instance`. It uses an exact sampled prompt,
group-normalized advantages, and one optimizer step per candidate group. The
legacy `grpo_instance` spelling remains a compatibility alias, but this method
does not implement canonical GRPO importance ratios or KL regularization.

The opt-in `candidate_distill_instance` rule is a separate off-policy probe for
flat survival submissions. With
`grpo_candidate_proposer=unit_interval_jitter`, it constructs deterministic,
schema-valid local proposals around the committed report before reward reveal,
then applies a signed group-normalized candidate-distillation update. It is
reported as `group_normalized_candidate_distillation`, never as policy
gradient. The proposer uses independent candidate-local seeds, canonical JSON
deduplication, complete `s12/s24/s36` triplets, and a hard attempt cap of
`2 * (best_of_n - 1)`.

For a diversity-only gate, use `ttt_lr=0`, `reward_pg_lr=0`, and
`lora_param_norm_clip=0`. The run artifacts include before/after hashes of all
trainable parameters so the validator can prove that this LR0 path left the
weights bit-identical.

Set `freeze_parameter_updates=true` for a full-history streaming control that
keeps the normal rollout context while rejecting every parameter update.
