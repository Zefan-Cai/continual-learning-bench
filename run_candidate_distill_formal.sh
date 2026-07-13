#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <cfg_id> <gpu_index>" >&2
  exit 2
fi

CFG=$1
GPU=$2
REPO=${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
VENV=${VENV:-/mnt/localssd/ttt-rl/cl-venv}
GRID=$REPO/grid_candidate_distill_formal.json
LOG_ROOT=${LOG_ROOT:-/mnt/localssd/ttt-rl-candidate-distill-formal/logs}
LOG=$LOG_ROOT/${CFG}.log

if ! [[ $GPU =~ ^[0-9]+$ ]]; then
  echo "gpu_index must be a nonnegative integer: $GPU" >&2
  exit 2
fi
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
arm = config.get("candidate_arm")
expected_lr = 1e-4 if arm == "active" else 0.0 if arm == "lr0" else None
required = {
    "reward_update_rule": "candidate_distill_instance",
    "grpo_candidate_proposer": "unit_interval_jitter",
    "ttt_lr": 0.0,
    "reward_pg_lr": expected_lr,
    "lora_param_norm_clip": 0.0,
    "freeze_parameter_updates": False,
}
if expected_lr is None:
    raise SystemExit(f"unsupported candidate_arm={arm!r}")
for key, expected in required.items():
    if params.get(key) != expected:
        raise SystemExit(
            f"unsafe candidate-distill config: {key}={params.get(key)!r}"
        )
if config.get("task_params", {}).get("expected_num_instances") != 20:
    raise SystemExit("formal cell must register expected_num_instances=20")
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
echo "[$(date -Is)] CANDIDATE DISTILL FORMAL START cfg=$CFG gpu=$GPU"
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
"$VENV/bin/python" - "$manifest" "$expected_config" "$LOG_ROOT/${CFG}.summary.json" <<'PY'
import json
import sys

manifest, expected_config, output = sys.argv[1:]
payload = json.load(open(manifest))
config = json.loads(expected_config)
metrics = payload["system_update_metrics"]
summary = {
    "candidate_arm": config["candidate_arm"],
    "cfg_id": config["cfg_id"],
    "pair_id": config["pair_id"],
    "sampling_seed": config["sampling_seed"],
    "status": payload["status"],
    "score": payload["result"]["score"],
    "rewards": [
        row["reward"] for row in payload["result"]["instance_outcomes"]
    ],
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
}
with open(output, "w") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
print(json.dumps(summary, sort_keys=True))
PY
echo "[$(date -Is)] CANDIDATE DISTILL FORMAL PASS cfg=$CFG gpu=$GPU"
