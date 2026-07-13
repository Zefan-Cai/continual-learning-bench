#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [GPU=0]" >&2
  exit 2
fi

GPU=${1:-0}
REPO=${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
VENV=${VENV:-/mnt/localssd/ttt-rl/cl-venv}
GRID=$REPO/grid_candidate_distill_smoke.json
CFG=gpgfix_cohort_full_candidate_distill_v2_lr0_seed2026071299_n5
LOG_ROOT=${LOG_ROOT:-/mnt/localssd/ttt-rl-proposer-v2/logs}
LOG=$LOG_ROOT/${CFG}.log

mkdir -p "$LOG_ROOT"
expected_config=$("$VENV/bin/python" - "$GRID" "$CFG" <<'PY'
import json
import sys

grid, cfg_id = sys.argv[1:]
matches = [cfg for cfg in json.load(open(grid)) if cfg["cfg_id"] == cfg_id]
if len(matches) != 1:
    raise SystemExit(f"expected one config for {cfg_id}")
config = matches[0]
params = config["system_params"]
required = {
    "reward_update_rule": "candidate_distill_instance",
    "grpo_candidate_proposer": "unit_interval_jitter",
    "ttt_lr": 0.0,
    "reward_pg_lr": 0.0,
    "lora_param_norm_clip": 0.0,
    "freeze_parameter_updates": False,
}
for key, expected in required.items():
    if params.get(key) != expected:
        raise SystemExit(f"unsafe LR0 gate config: {key}={params.get(key)!r}")
print(json.dumps(config, sort_keys=True, separators=(",", ":")))
PY
)
system_json=$("$VENV/bin/python" -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["system_params"],sort_keys=True,separators=(",",":")))' <<<"$expected_config")
task_json=$("$VENV/bin/python" -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["task_params"],sort_keys=True,separators=(",",":")))' <<<"$expected_config")
result_dir=$REPO/results/cohort_studies/live/$CFG

if [[ -e "$result_dir" ]]; then
  echo "refusing to overwrite existing result dir: $result_dir" >&2
  exit 2
fi

cd "$REPO"
echo "[$(date -Is)] CANDIDATE DISTILL LR0 GATE START cfg=$CFG gpu=$GPU"
env CUDA_VISIBLE_DEVICES="$GPU" TOKENIZERS_PARALLELISM=false \
  PYTHONDONTWRITEBYTECODE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1 \
  CLBENCH_FAULT_TOLERANT=1 CLBENCH_INSTANCE_TIMEOUT=3600 \
  CLBENCH_MAX_CONSEC_FAILURES=4 \
  "$VENV/bin/python" run_benchmark.py run \
    --system qwen_local --task cohort_studies \
    --task-params "$task_json" --system-params "$system_json" \
    --runs 1 --max-workers 1 --run-mode replicate --verbose-runs \
    --no-live-server --run-group-id "$CFG" >"$LOG" 2>&1

manifest=$result_dir/run_1.json
"$VENV/bin/python" validate_group_pg_manifest.py \
  "$manifest" --expected-config "$expected_config" --strict-smoke
"$VENV/bin/python" - "$manifest" "$LOG_ROOT/${CFG}.summary.json" <<'PY'
import json
import sys

manifest, output = sys.argv[1:]
payload = json.load(open(manifest))
metrics = payload["system_update_metrics"]
summary = {
    "status": payload["status"],
    "score": payload["result"]["score"],
    "rewards": [row["reward"] for row in payload["result"]["instance_outcomes"]],
    "updates": metrics["grpo_updates"],
    "optimizer_steps": metrics["grpo_optimizer_steps"],
    "low_std": metrics["grpo_skipped_low_std"],
    "no_group": metrics["grpo_skipped_no_group"],
    "objective": metrics["grpo_objective"],
    "candidate_proposer": metrics["grpo_candidate_proposer"],
    "trainable_param_sha256_initial": metrics[
        "grpo_trainable_param_sha256_initial"
    ],
    "trainable_param_sha256_current": metrics[
        "grpo_trainable_param_sha256_current"
    ],
    "rows": metrics["grpo_instance_log"],
}
with open(output, "w") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
print(json.dumps(summary, sort_keys=True))
PY
echo "[$(date -Is)] CANDIDATE DISTILL LR0 GATE PASS cfg=$CFG"
