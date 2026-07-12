#!/usr/bin/env bash
# Integration draft for the existing collision-fixed main_grpo launcher.
# It deliberately omits Pluto submission and shared-tree deployment.
set -euo pipefail

: "${GRID:?local grid JSON is required}"
: "${LOCAL:?local scratch root is required}"
: "${REPO:?local CLBench repo is required}"
: "${V:?venv root is required}"
: "${LOGD:?log directory is required}"
: "${S3:?S3 root is required}"
: "${PREFIX:?S3 results prefix is required}"

JOB_IDX=${JOB_IDX:-0}
NODE_RANK=${NODE_RANK:-0}
NJOBS=${NJOBS:-1}
RELEASE_STAGE=${TTT_RL_RELEASE_STAGE:-}
STRICT_SMOKE=${TTT_RL_STRICT_SMOKE:-0}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

mkdir -p "$LOCAL" "$LOCAL/locks" "$LOCAL/tmp" "$LOGD"
stage_args=()
if [[ -n "$RELEASE_STAGE" ]]; then
  stage_args+=(--release-stage "$RELEASE_STAGE")
fi
python3 "$SCRIPT_DIR/prepare_group_pg_assignments.py" \
  "$GRID" "$LOCAL" \
  --job-index "$JOB_IDX" --node-rank "$NODE_RANK" --num-jobs "$NJOBS" \
  "${stage_args[@]}"

validate_manifest() {
  local manifest=$1
  local args=()
  if [[ "$STRICT_SMOKE" == 1 ]]; then
    args+=(--strict-smoke)
  fi
  python3 "$SCRIPT_DIR/validate_group_pg_manifest.py" "$manifest" "${args[@]}"
}

run_worker() {
  local gpu=$1
  local failed=0
  while IFS=$'\t' read -r cfg task system_path task_path runs run_mode; do
    [[ -n "$cfg" ]] || continue
    runs=${runs:-1}
    check="$LOCAL/tmp/check_gpu${gpu}.json"
    if aws s3 cp "$S3/$PREFIX/$task/live/$cfg/run_${runs}.json" "$check" --only-show-errors >/dev/null 2>&1 \
      && validate_manifest "$check" >/dev/null 2>&1; then
      rm -f "$check"
      continue
    fi
    rm -f "$check"

    if ! (
      flock -n 9 || exit 0
      echo "[gpu$gpu $(date +%H:%M)] RUN $cfg"
      rc=0
      (
        cd "$REPO"
        env CUDA_VISIBLE_DEVICES="$gpu" TOKENIZERS_PARALLELISM=false \
          PYTHONDONTWRITEBYTECODE=1 CLBENCH_FAULT_TOLERANT=1 \
          CLBENCH_INSTANCE_TIMEOUT=1800 CLBENCH_MAX_CONSEC_FAILURES=4 \
          "$V/bin/python" run_benchmark.py run \
            --system qwen_local --task "$task" \
            --task-params "$(cat "$task_path")" \
            --system-params "$(cat "$system_path")" \
            --runs "$runs" --max-workers 1 --run-mode "$run_mode" \
            --verbose-runs --no-live-server --run-group-id "$cfg"
      ) >"$LOGD/${cfg}.log" 2>&1 || rc=$?

      result_dir="$REPO/results/$task/live/$cfg"
      manifest="$result_dir/run_${runs}.json"
      if [[ "$rc" == 0 ]] && validate_manifest "$manifest"; then
        aws s3 sync "$result_dir/" "$S3/$PREFIX/$task/live/$cfg/" --only-show-errors
        # Manifest-last upload: an object is canonical only after strict validation.
        aws s3 cp "$manifest" "$S3/$PREFIX/$task/live/$cfg/run_${runs}.json" --only-show-errors
      else
        [[ -d "$result_dir" ]] && aws s3 sync "$result_dir/" \
          "$S3/${PREFIX}_partial/$task/live/$cfg/" --only-show-errors || true
        exit 1
      fi
    ) 9>"$LOCAL/locks/${cfg}.lock"; then
      failed=1
    fi
  done <"$LOCAL/assign/gpu${gpu}.list"
  return "$failed"
}

pids=()
for gpu in 0 1 2 3 4 5 6 7; do
  run_worker "$gpu" >"$LOGD/worker_gpu${gpu}.log" 2>&1 &
  pids+=("$!")
done
failed=0
for pid in "${pids[@]}"; do
  wait "$pid" || failed=1
done
exit "$failed"
