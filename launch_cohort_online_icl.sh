#!/usr/bin/env bash
# Bounded launcher for the preregistered reward-aware online-ICL comparator.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND="${1:-}"
if [[ "$KIND" != "smoke" && "$KIND" != "formal" ]]; then
  echo "usage: $0 {smoke|formal} --provenance FILE --protocol-seal FILE --gpus CSV [gate args]" >&2
  exit 2
fi
shift

PROVENANCE=""
PROTOCOL_SEAL=""
GPUS="4"
CAUSAL_SMOKE_GATE=""
CAUSAL_PROVENANCE=""
CAUSAL_ROOT=""
CAUSAL_MANIFEST=""
CAUSAL_DECISION=""
ICL_SMOKE_GATE=""
MAX_USED_MEMORY_MIB="${COHORT_ONLINE_ICL_MAX_USED_MEMORY_MIB:-1024}"
if [[ "$KIND" == "formal" ]]; then
  GPUS="0,2,3"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provenance) PROVENANCE="${2:?missing provenance}"; shift 2 ;;
    --protocol-seal) PROTOCOL_SEAL="${2:?missing protocol seal}"; shift 2 ;;
    --gpus) GPUS="${2:?missing GPU CSV}"; shift 2 ;;
    --causal-smoke-gate) CAUSAL_SMOKE_GATE="${2:?missing gate}"; shift 2 ;;
    --causal-provenance) CAUSAL_PROVENANCE="${2:?missing provenance}"; shift 2 ;;
    --causal-root) CAUSAL_ROOT="${2:?missing causal root}"; shift 2 ;;
    --causal-manifest) CAUSAL_MANIFEST="${2:?missing manifest}"; shift 2 ;;
    --causal-decision) CAUSAL_DECISION="${2:?missing decision}"; shift 2 ;;
    --icl-smoke-gate) ICL_SMOKE_GATE="${2:?missing ICL smoke gate}"; shift 2 ;;
    --max-used-memory-mib)
      MAX_USED_MEMORY_MIB="${2:?missing threshold}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$PROVENANCE" || ! -f "$PROVENANCE" ]]; then
  echo "--provenance must name an existing file" >&2
  exit 2
fi
if [[ -z "$PROTOCOL_SEAL" || ! -f "$PROTOCOL_SEAL" ]]; then
  echo "--protocol-seal must name an existing immutable seal" >&2
  exit 2
fi
if [[ ! "$MAX_USED_MEMORY_MIB" =~ ^[0-9]+$ ]]; then
  echo "--max-used-memory-mib must be a non-negative integer" >&2
  exit 2
fi

# This recomputes the current provenance and both grid bindings before any
# model is loaded. The same no-overwrite seal must survive smoke and formal.
python "$ROOT/build_cohort_online_icl_protocol_seal.py" \
  --root "$ROOT" \
  --provenance "$PROVENANCE" \
  --verify "$PROTOCOL_SEAL"

if [[ "$KIND" == "smoke" ]]; then
  if [[ -z "$CAUSAL_SMOKE_GATE" || ! -f "$CAUSAL_SMOKE_GATE" ]]; then
    echo "smoke requires --causal-smoke-gate from the paired causal smoke" >&2
    exit 2
  fi
  if [[ -z "$CAUSAL_PROVENANCE" || ! -f "$CAUSAL_PROVENANCE" ]]; then
    echo "smoke requires --causal-provenance from the paired causal smoke" >&2
    exit 2
  fi
  if [[ -z "$CAUSAL_ROOT" || ! -d "$CAUSAL_ROOT" ]]; then
    echo "smoke requires --causal-root containing the paired raw artifacts" >&2
    exit 2
  fi
  python - "$ROOT" "$CAUSAL_ROOT" "$CAUSAL_SMOKE_GATE" \
    "$CAUSAL_PROVENANCE" "$PROVENANCE" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
from run_cohort_causal import load_provenance as load_causal_provenance
from run_cohort_online_icl import load_provenance as load_online_provenance
from validate_cohort_online_icl_smoke import validate_causal_smoke_prerequisite

causal_gate = json.load(open(sys.argv[3]))
if not isinstance(causal_gate, dict):
    raise SystemExit("causal smoke gate must be an object")
causal_provenance = load_causal_provenance(pathlib.Path(sys.argv[4]))
online_provenance = load_online_provenance(pathlib.Path(sys.argv[5]))
binding = validate_causal_smoke_prerequisite(
    causal_root=pathlib.Path(sys.argv[2]),
    causal_gate=causal_gate,
    causal_provenance=causal_provenance,
)
for field in (
    "environment_lock_sha256", "model_path", "model_sha256", "tokenizer_sha256"
):
    if binding[field] != online_provenance[field]:
        raise SystemExit(f"causal/online smoke shared provenance differs: {field}")
if binding["causal_source_commit"] != online_provenance["base_causal_commit"]:
    raise SystemExit("online-ICL base commit differs from causal smoke source")
print("CAUSAL_SMOKE_PREREQUISITE_OK " + binding["causal_smoke_gate_sha256"])
PY
else
  for path in "$CAUSAL_MANIFEST" "$CAUSAL_DECISION"; do
    if [[ -z "$path" || ! -f "$path" ]]; then
      echo "formal requires --causal-manifest and --causal-decision" >&2
      exit 2
    fi
  done
  if [[ -z "$ICL_SMOKE_GATE" || ! -f "$ICL_SMOKE_GATE" ]]; then
    echo "formal requires --icl-smoke-gate from this exact protocol seal" >&2
    exit 2
  fi
  if [[ -z "$CAUSAL_SMOKE_GATE" || ! -f "$CAUSAL_SMOKE_GATE" ]]; then
    echo "formal requires --causal-smoke-gate from the paired causal smoke" >&2
    exit 2
  fi
  if [[ -z "$CAUSAL_PROVENANCE" || ! -f "$CAUSAL_PROVENANCE" ]]; then
    echo "formal requires --causal-provenance from the paired causal smoke" >&2
    exit 2
  fi
  if [[ -z "$CAUSAL_ROOT" || ! -d "$CAUSAL_ROOT" ]]; then
    echo "formal requires --causal-root containing the paired raw artifacts" >&2
    exit 2
  fi
  python - "$ROOT" "$CAUSAL_MANIFEST" "$CAUSAL_DECISION" "$PROVENANCE" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
from validate_cohort_causal_results import evaluate

manifest = json.load(open(sys.argv[2]))
decision = json.load(open(sys.argv[3]))
provenance = json.load(open(sys.argv[4]))
if evaluate(manifest) != decision:
    raise SystemExit("causal decision is not the exact evaluation of its manifest")
if (
    decision.get("status") != "valid"
    or decision.get("decision") != "pass"
    or decision.get("decision_scope") != "internal_gate_pass"
):
    raise SystemExit("online-ICL formal requires paired causal internal gate pass")
causal_provenance = manifest.get("provenance", {})
for field in (
    "environment_lock_sha256", "model_path", "model_sha256", "tokenizer_sha256"
):
    if provenance.get(field) != causal_provenance.get(field):
        raise SystemExit(f"three-arm shared provenance differs: {field}")
if provenance.get("base_causal_commit") != causal_provenance.get("source_commit"):
    raise SystemExit("online-ICL base commit differs from causal source commit")
PY
  python - "$ROOT" "$PROVENANCE" "$PROTOCOL_SEAL" "$ICL_SMOKE_GATE" \
    "$CAUSAL_ROOT" "$CAUSAL_SMOKE_GATE" "$CAUSAL_PROVENANCE" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
from build_cohort_online_icl_protocol_seal import load_protocol_seal
from run_cohort_causal import load_provenance as load_causal_provenance
from validate_cohort_online_icl_results import revalidate_registered_formal_smoke_gate

provenance = json.load(open(sys.argv[2]))
seal = load_protocol_seal(pathlib.Path(sys.argv[3]))
gate = json.load(open(sys.argv[4]))
causal_gate = json.load(open(sys.argv[6]))
causal_provenance = load_causal_provenance(pathlib.Path(sys.argv[7]))
revalidate_registered_formal_smoke_gate(
    root=root,
    smoke_gate=gate,
    provenance=provenance,
    protocol_seal=seal,
    protocol_seal_sha256=seal["protocol_seal_sha256"],
    causal_root=pathlib.Path(sys.argv[5]),
    causal_smoke_gate=causal_gate,
    causal_provenance=causal_provenance,
)
PY
fi

GRID="$ROOT/grid_cohort_online_icl_${KIND}.json"
if [[ "$KIND" == "smoke" ]]; then
  REPORT_OUTPUT="$ROOT/artifacts/cohort_online_icl/smoke_gate.json"
else
  REPORT_OUTPUT="$ROOT/artifacts/cohort_online_icl/internal_screen.json"
fi
if [[ -e "$REPORT_OUTPUT" || -L "$REPORT_OUTPUT" ]]; then
  echo "refusing existing online-ICL report: $REPORT_OUTPUT" >&2
  exit 1
fi
python "$ROOT/generate_cohort_online_icl_grid.py" --check

IFS=',' read -r -a GPU_ARRAY <<< "$GPUS"
mapfile -t CFG_IDS < <(python - "$GRID" <<'PY'
import json, sys
for row in json.load(open(sys.argv[1]))["cells"]:
    print(row["cfg_id"])
PY
)
if [[ ${#GPU_ARRAY[@]} -ne ${#CFG_IDS[@]} ]]; then
  echo "$KIND requires exactly ${#CFG_IDS[@]} GPU IDs" >&2
  exit 2
fi
for gpu in "${GPU_ARRAY[@]}"; do
  [[ "$gpu" =~ ^[0-9]+$ ]] || { echo "invalid GPU ID: $gpu" >&2; exit 2; }
done
if [[ "$(printf '%s\n' "${GPU_ARRAY[@]}" | sort -u | wc -l | tr -d ' ')" -ne ${#GPU_ARRAY[@]} ]]; then
  echo "GPU IDs must be unique" >&2
  exit 2
fi

python - "$GPUS" "$MAX_USED_MEMORY_MIB" <<'PY'
import subprocess, sys
selected = {int(value) for value in sys.argv[1].split(",")}
threshold = int(sys.argv[2])
rows = subprocess.run(
    ["nvidia-smi", "--query-gpu=index,memory.used", "--format=csv,noheader,nounits"],
    check=True, capture_output=True, text=True,
).stdout.splitlines()
observed = {}
for row in rows:
    index, used = (part.strip() for part in row.split(",", 1))
    observed[int(index)] = int(used)
missing = selected - set(observed)
if missing:
    raise SystemExit(f"selected GPU IDs do not exist: {sorted(missing)}")
busy = {index: observed[index] for index in selected if observed[index] > threshold}
if busy:
    raise SystemExit(f"selected GPUs exceed memory threshold: {busy}")
print("GPU_PREFLIGHT_OK " + ",".join(map(str, sorted(selected))))
PY

LOG_DIR="$ROOT/artifacts/cohort_online_icl/logs"
mkdir -p "$LOG_DIR"
python - "$ROOT" "$GRID" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
grid = json.load(open(sys.argv[2]))
paths = []
for row in grid["cells"]:
    for key in (
        "adaptation_trace_path", "cell_manifest_path", "context_inventory_path",
        "heldout_trace_path", "restoration_audit_path", "snapshot_path",
    ):
        paths.append(root / row[key])
existing = [str(path) for path in paths if path.exists() or path.is_symlink()]
if existing:
    raise SystemExit("refusing existing online-ICL artifacts:\n" + "\n".join(existing))
PY
for cfg_id in "${CFG_IDS[@]}"; do
  [[ ! -e "$LOG_DIR/${cfg_id}.log" && ! -L "$LOG_DIR/${cfg_id}.log" ]] || {
    echo "refusing existing log: $LOG_DIR/${cfg_id}.log" >&2; exit 1;
  }
done

pids=()
for index in "${!CFG_IDS[@]}"; do
  cfg_id="${CFG_IDS[$index]}"
  gpu="${GPU_ARRAY[$index]}"
  run_seed="$(python - "$GRID" "$cfg_id" <<'PY'
import json, sys
matches = [row for row in json.load(open(sys.argv[1]))["cells"] if row["cfg_id"] == sys.argv[2]]
if len(matches) != 1:
    raise SystemExit("cfg lookup failed")
print(matches[0]["run_seed"])
PY
)"
  echo "launch cfg=$cfg_id CUDA_VISIBLE_DEVICES=$gpu"
  (
    cd "$ROOT"
    CUDA_VISIBLE_DEVICES="$gpu" \
    PYTHONHASHSEED="$run_seed" \
    CLBENCH_FAULT_TOLERANT=0 \
    PYTHONUNBUFFERED=1 \
    python run_cohort_online_icl.py \
      --grid "$GRID" \
      --cfg-id "$cfg_id" \
      --provenance "$PROVENANCE" \
      --protocol-seal "$PROTOCOL_SEAL"
  ) >"$LOG_DIR/${cfg_id}.log" 2>&1 &
  pids+=("$!")
done

failed=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then failed=1; fi
done
if [[ "$failed" -ne 0 ]]; then
  echo "online-ICL phase failed; inspect $LOG_DIR" >&2
  exit 1
fi

CELL_ARGS=()
for cfg_id in "${CFG_IDS[@]}"; do
  CELL_ARGS+=(--cell-manifest "$ROOT/artifacts/cohort_online_icl/${cfg_id}.manifest.json")
done
if [[ "$KIND" == "smoke" ]]; then
  python "$ROOT/validate_cohort_online_icl_smoke.py" \
    --grid "$GRID" --provenance "$PROVENANCE" \
    --protocol-seal "$PROTOCOL_SEAL" \
    --causal-root "$CAUSAL_ROOT" \
    --causal-smoke-gate "$CAUSAL_SMOKE_GATE" \
    --causal-provenance "$CAUSAL_PROVENANCE" \
    "${CELL_ARGS[@]}" --output "$REPORT_OUTPUT"
else
  python "$ROOT/validate_cohort_online_icl_results.py" \
    --grid "$GRID" --provenance "$PROVENANCE" \
    --protocol-seal "$PROTOCOL_SEAL" \
    "${CELL_ARGS[@]}" \
    --causal-manifest "$CAUSAL_MANIFEST" \
    --causal-decision "$CAUSAL_DECISION" \
    --causal-root "$CAUSAL_ROOT" \
    --causal-smoke-gate "$CAUSAL_SMOKE_GATE" \
    --causal-provenance "$CAUSAL_PROVENANCE" \
    --icl-smoke-gate "$ICL_SMOKE_GATE" \
    --output "$REPORT_OUTPUT"
fi
echo "online-ICL $KIND report: $REPORT_OUTPUT"
