#!/usr/bin/env bash
# Bounded single-node launcher for the preregistered Cohort causal gate.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND="${1:-}"
if [[ "$KIND" != "smoke" && "$KIND" != "formal" ]]; then
  echo "usage: $0 {smoke|formal} --provenance FILE" \
    "[--collector-gpus CSV] [--eval-gpus CSV]" \
    "[--max-used-memory-mib N]" >&2
  exit 2
fi
shift

if [[ "$KIND" == "smoke" ]]; then
  COLLECTOR_GPUS="0"
  EVAL_GPUS="2,3"
else
  COLLECTOR_GPUS="0,2,3"
  EVAL_GPUS="0,2,3,4,5,6"
fi
PROVENANCE=""
MAX_USED_MEMORY_MIB="${COHORT_CAUSAL_MAX_USED_MEMORY_MIB:-1024}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provenance)
      PROVENANCE="${2:?missing provenance path}"
      shift 2
      ;;
    --collector-gpus)
      COLLECTOR_GPUS="${2:?missing collector GPU CSV}"
      shift 2
      ;;
    --eval-gpus)
      EVAL_GPUS="${2:?missing eval GPU CSV}"
      shift 2
      ;;
    --max-used-memory-mib)
      MAX_USED_MEMORY_MIB="${2:?missing memory threshold}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! "$MAX_USED_MEMORY_MIB" =~ ^[0-9]+$ ]]; then
  echo "--max-used-memory-mib must be a non-negative integer" >&2
  exit 2
fi

if [[ -z "$PROVENANCE" || ! -f "$PROVENANCE" ]]; then
  echo "--provenance must name an existing audited provenance JSON" >&2
  exit 2
fi
PROVENANCE="$(cd "$(dirname "$PROVENANCE")" && pwd)/$(basename "$PROVENANCE")"
GRID="$ROOT/grid_cohort_causal_${KIND}.json"
LOG_DIR="$ROOT/artifacts/cohort_causal/logs"
mkdir -p "$LOG_DIR"

IFS=',' read -r -a COLLECTOR_GPU_ARRAY <<< "$COLLECTOR_GPUS"
IFS=',' read -r -a EVAL_GPU_ARRAY <<< "$EVAL_GPUS"
for gpu in "${COLLECTOR_GPU_ARRAY[@]}" "${EVAL_GPU_ARRAY[@]}"; do
  if [[ ! "$gpu" =~ ^[0-9]+$ ]]; then
    echo "GPU lists must contain explicit integer device IDs: $gpu" >&2
    exit 2
  fi
done

COLLECTOR_IDS_CSV="$(
  python - "$GRID" <<'PY'
import json, sys
print(",".join(row["cfg_id"] for row in json.load(open(sys.argv[1]))["collectors"]))
PY
)"
EVAL_IDS_CSV="$(
  python - "$GRID" <<'PY'
import json, sys
print(",".join(row["cfg_id"] for row in json.load(open(sys.argv[1]))["evaluation_cells"]))
PY
)"
IFS=',' read -r -a COLLECTOR_IDS <<< "$COLLECTOR_IDS_CSV"
IFS=',' read -r -a EVAL_IDS <<< "$EVAL_IDS_CSV"

if [[ ${#COLLECTOR_GPU_ARRAY[@]} -ne ${#COLLECTOR_IDS[@]} ]]; then
  echo "collector GPU count must be ${#COLLECTOR_IDS[@]} for $KIND" >&2
  exit 2
fi
if [[ ${#EVAL_GPU_ARRAY[@]} -ne ${#EVAL_IDS[@]} ]]; then
  echo "eval GPU count must be ${#EVAL_IDS[@]} for $KIND" >&2
  exit 2
fi
if [[ "$(printf '%s\n' "${COLLECTOR_GPU_ARRAY[@]}" | sort -u | wc -l | tr -d ' ')" -ne ${#COLLECTOR_GPU_ARRAY[@]} ]]; then
  echo "collector GPU IDs must be unique within the phase" >&2
  exit 2
fi
if [[ "$(printf '%s\n' "${EVAL_GPU_ARRAY[@]}" | sort -u | wc -l | tr -d ' ')" -ne ${#EVAL_GPU_ARRAY[@]} ]]; then
  echo "eval GPU IDs must be unique within the phase" >&2
  exit 2
fi

for cfg_id in "${COLLECTOR_IDS[@]}" "${EVAL_IDS[@]}"; do
  if [[ -e "$LOG_DIR/${cfg_id}.log" ]]; then
    echo "refusing existing log: $LOG_DIR/${cfg_id}.log" >&2
    exit 1
  fi
done
if [[ "$KIND" == "formal" ]] && {
  [[ -e "$ROOT/artifacts/cohort_causal/formal_manifest.json" ]] ||
  [[ -e "$ROOT/artifacts/cohort_causal/formal_decision.json" ]];
}; then
  echo "refusing existing formal manifest/decision report" >&2
  exit 1
fi
if [[ "$KIND" == "smoke" && -e "$ROOT/artifacts/cohort_causal/smoke_gate.json" ]]; then
  echo "refusing existing smoke gate report" >&2
  exit 1
fi
if [[ "$KIND" == "formal" ]]; then
  SMOKE_REPORT="$ROOT/artifacts/cohort_causal/smoke_gate.json"
  if [[ ! -f "$SMOKE_REPORT" ]]; then
    echo "formal launch requires a prior passing smoke gate: $SMOKE_REPORT" >&2
    exit 1
  fi
  python - "$SMOKE_REPORT" "$PROVENANCE" <<'PY'
import hashlib
import json
import sys

report = json.load(open(sys.argv[1]))
provenance = json.load(open(sys.argv[2]))
encoded = json.dumps(
    provenance,
    ensure_ascii=False,
    allow_nan=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
digest = hashlib.sha256(encoded).hexdigest()
if report.get("status") != "pass" or report.get("decision") != "pass":
    raise SystemExit("formal launch requires smoke status=pass decision=pass")
if report.get("provenance_sha256") != digest:
    raise SystemExit(
        "formal provenance differs from the provenance bound to smoke gate"
    )
print(f"SMOKE_PREREQUISITE_OK provenance_sha256={digest}")
PY
fi

# Refuse the whole invocation before allocating a model if any target artifact
# already exists.  This supplements each runner's own atomic no-overwrite gate.
python - "$ROOT" "$GRID" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
grid = json.load(open(sys.argv[2]))
paths = []
for row in grid["collectors"]:
    paths += [
        root / row["tape_path"],
        root / f"artifacts/cohort_causal/collectors/{row['cfg_id']}.manifest.json",
        root / f"artifacts/cohort_causal/traces/{row['cfg_id']}.trace.json",
        root / f"artifacts/cohort_causal/traces/{row['cfg_id']}.trace.live.json",
    ]
for row in grid["evaluation_cells"]:
    paths += [
        root / row["cell_manifest_path"],
        root / f"artifacts/cohort_causal/traces/{row['cfg_id']}.trace.json",
        root / f"artifacts/cohort_causal/traces/{row['cfg_id']}.trace.live.json",
    ]
existing = [str(path) for path in paths if path.exists()]
if existing:
    raise SystemExit("refusing existing causal artifacts:\n" + "\n".join(existing))
PY

check_gpus_idle() {
  local gpus_csv="$1"
  python - "$gpus_csv" "$MAX_USED_MEMORY_MIB" <<'PY'
import subprocess
import sys

selected = {int(value) for value in sys.argv[1].split(",")}
threshold = int(sys.argv[2])

def query(arguments):
    try:
        return subprocess.run(
            ["nvidia-smi", *arguments],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except FileNotFoundError as exc:
        raise SystemExit("nvidia-smi is required for GPU occupancy preflight") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"nvidia-smi preflight failed: {exc.stderr.strip()}") from exc

gpu_rows = query([
    "--query-gpu=index,uuid,memory.used",
    "--format=csv,noheader,nounits",
])
observed = {}
for line in gpu_rows.splitlines():
    if not line.strip():
        continue
    index_text, uuid, memory_text = (part.strip() for part in line.split(",", 2))
    observed[int(index_text)] = (uuid, int(memory_text))
missing = selected - set(observed)
if missing:
    raise SystemExit(f"selected physical GPU indexes do not exist: {sorted(missing)}")

errors = []
selected_uuids = {observed[index][0]: index for index in selected}
for index in sorted(selected):
    used = observed[index][1]
    if used > threshold:
        errors.append(f"GPU {index} memory.used={used} MiB > {threshold} MiB")

process_rows = query([
    "--query-compute-apps=gpu_uuid,pid,used_gpu_memory",
    "--format=csv,noheader,nounits",
])
for line in process_rows.splitlines():
    if not line.strip() or "No running processes" in line:
        continue
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2:
        raise SystemExit(f"cannot parse nvidia-smi compute row: {line!r}")
    uuid, pid = parts[:2]
    if uuid in selected_uuids:
        errors.append(
            f"GPU {selected_uuids[uuid]} has compute process pid={pid}"
        )
if errors:
    raise SystemExit("GPU occupancy preflight failed:\n" + "\n".join(errors))
print(
    "GPU_PREFLIGHT_OK selected="
    + ",".join(str(index) for index in sorted(selected))
    + f" max_used_memory_mib={threshold}"
)
PY
}

run_phase() {
  local ids_csv="$1"
  local gpus_csv="$2"
  local -a ids_ref gpus_ref
  IFS=',' read -r -a ids_ref <<< "$ids_csv"
  IFS=',' read -r -a gpus_ref <<< "$gpus_csv"
  # Query immediately before each phase; the prior snapshot may already be stale.
  check_gpus_idle "$gpus_csv"
  local pids=()
  local index cfg_id gpu log_path run_seed
  for index in "${!ids_ref[@]}"; do
    cfg_id="${ids_ref[$index]}"
    gpu="${gpus_ref[$index]}"
    log_path="$LOG_DIR/${cfg_id}.log"
    run_seed="$(python - "$GRID" "$cfg_id" <<'PY'
import json, sys
grid = json.load(open(sys.argv[1]))
matches = [
    row for section in ("collectors", "evaluation_cells")
    for row in grid[section] if row["cfg_id"] == sys.argv[2]
]
if len(matches) != 1:
    raise SystemExit("cfg_id/run_seed lookup failed")
print(matches[0]["run_seed"])
PY
)"
    echo "launch cfg=$cfg_id CUDA_VISIBLE_DEVICES=$gpu log=$log_path"
    (
      cd "$ROOT"
      CUDA_VISIBLE_DEVICES="$gpu" \
      PYTHONHASHSEED="$run_seed" \
      CLBENCH_FAULT_TOLERANT=0 \
      PYTHONUNBUFFERED=1 \
      python run_cohort_causal.py \
        --grid "$GRID" \
        --cfg-id "$cfg_id" \
        --provenance "$PROVENANCE"
    ) >"$log_path" 2>&1 &
    pids+=("$!")
  done
  local failed=0 pid
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      failed=1
    fi
  done
  if [[ "$failed" -ne 0 ]]; then
    echo "causal phase failed; inspect $LOG_DIR" >&2
    return 1
  fi
}

# Hard barrier: no replay cell starts until every collector tape has completed.
run_phase "$COLLECTOR_IDS_CSV" "$COLLECTOR_GPUS"
run_phase "$EVAL_IDS_CSV" "$EVAL_GPUS"

if [[ "$KIND" == "formal" ]]; then
  FORMAL_MANIFEST="$ROOT/artifacts/cohort_causal/formal_manifest.json"
  DECISION_REPORT="$ROOT/artifacts/cohort_causal/formal_decision.json"
  python "$ROOT/assemble_cohort_causal_manifest.py" \
    --grid "$GRID" \
    --provenance "$PROVENANCE" \
    --output "$FORMAL_MANIFEST"
  python "$ROOT/validate_cohort_causal_results.py" \
    --manifest "$FORMAL_MANIFEST" \
    --output "$DECISION_REPORT"
  echo "formal decision: $DECISION_REPORT"
else
  SMOKE_REPORT="$ROOT/artifacts/cohort_causal/smoke_gate.json"
  python "$ROOT/validate_cohort_causal_smoke.py" \
    --grid "$GRID" \
    --provenance "$PROVENANCE" \
    --output "$SMOKE_REPORT"
  echo "smoke gate passed: $SMOKE_REPORT"
fi
