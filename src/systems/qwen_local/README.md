# Local Qwen system

`qwen_local` runs a local Hugging Face causal language model and exposes the
TTT, reward-update, and environment-scored best-of-N paths used by the
TTT-RL experiments.

The corrected D2 rule is `group_pg_instance`. It uses an exact sampled prompt,
group-normalized advantages, and one optimizer step per candidate group. The
legacy `grpo_instance` spelling remains a compatibility alias, but this method
does not implement canonical GRPO importance ratios or KL regularization.

Set `freeze_parameter_updates=true` for a full-history streaming control that
keeps the normal rollout context while rejecting every parameter update.
