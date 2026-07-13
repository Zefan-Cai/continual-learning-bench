#!/usr/bin/env bash
set -uo pipefail

REPO=${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
VENV=${VENV:-/mnt/localssd/ttt-rl/cl-venv}
LOG_ROOT=${LOG_ROOT:-/mnt/localssd/ttt-rl-candidate-distill-formal/logs}
GPU_LIST=${GPU_LIST:-0,1,2,3,4,5}
GRID=$REPO/grid_candidate_distill_formal.json
DECISION_FILE=formal_decision_v3_adapterseed2026071200.json

"$VENV/bin/python" "$REPO/generate_candidate_distill_grids.py" --check || exit 2

IFS=, read -r -a gpus <<<"$GPU_LIST"
if [[ ${#gpus[@]} -ne 6 ]]; then
  echo "GPU_LIST must contain exactly six comma-separated GPU indices" >&2
  exit 2
fi
if [[ $(printf '%s\n' "${gpus[@]}" | sort -u | wc -l | tr -d ' ') -ne 6 ]]; then
  echo "GPU_LIST entries must be unique" >&2
  exit 2
fi
for gpu in "${gpus[@]}"; do
  if ! [[ $gpu =~ ^[0-9]+$ ]]; then
    echo "invalid GPU index: $gpu" >&2
    exit 2
  fi
done

mapfile_cmd=("$VENV/bin/python" - "$GRID")
configs=$(
  "${mapfile_cmd[@]}" <<'PY'
import json
import sys

configs = json.load(open(sys.argv[1]))
if len(configs) != 6:
    raise SystemExit("formal grid must contain exactly six cells")
for config in configs:
    print(config["cfg_id"])
PY
)
cfgs=()
while IFS= read -r cfg; do
  [[ -n $cfg ]] && cfgs+=("$cfg")
done <<<"$configs"
if [[ ${#cfgs[@]} -ne 6 ]]; then
  echo "failed to resolve six formal configs" >&2
  exit 2
fi

mkdir -p "$LOG_ROOT"
pids=()
for index in "${!cfgs[@]}"; do
  cfg=${cfgs[$index]}
  gpu=${gpus[$index]}
  REPO="$REPO" VENV="$VENV" LOG_ROOT="$LOG_ROOT" \
    "$REPO/run_candidate_distill_formal.sh" "$cfg" "$gpu" \
    >"$LOG_ROOT/${cfg}.launcher.log" 2>&1 &
  pid=$!
  pids+=("$pid")
  echo "launched cfg=$cfg gpu=$gpu pid=$pid"
done

failed=0
for index in "${!pids[@]}"; do
  if wait "${pids[$index]}"; then
    echo "completed cfg=${cfgs[$index]} gpu=${gpus[$index]}"
  else
    status=$?
    echo "failed cfg=${cfgs[$index]} gpu=${gpus[$index]} status=$status" >&2
    failed=1
  fi
done
if [[ $failed -ne 0 ]]; then
  exit 1
fi

"$VENV/bin/python" "$REPO/validate_candidate_distill_pairing.py" \
  --grid "$GRID" \
  --results-root "$REPO/results/cohort_studies/live" \
  --output "$LOG_ROOT/$DECISION_FILE"
