#!/usr/bin/env python3
"""Run one preregistered Cohort frozen-tape collector or replay cell.

The collector is deliberately an LR=0 policy run.  It captures the exact two
terminal update calls before ``observe`` consumes them and refuses to publish a
tape unless the collector's trainable-parameter hash is unchanged.  A replay
cell restores the common initialized adapter, replays that tape, hard-freezes
all updates, and only then evaluates the held-out corpus.

This file writes one atomic artifact per stage and never overwrites an existing
artifact.  That makes retries explicit instead of silently mixing attempts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from validate_cohort_causal_results import (
    LIMITATION,
    MECHANISM_LABEL,
    PREREGISTERED_PARENT_COMMIT,
    canonical_sha256,
    corpus_projection_from_dataset_manifest,
    masked_pair_config_sha256,
)


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
TASK_NAME = "cohort_studies"
REQUIRED_PROVENANCE_FIELDS = {
    "source_commit",
    "preregistered_parent_commit",
    "environment_lock_sha256",
    "model_sha256",
    "tokenizer_sha256",
    "evaluation_code_sha256",
    "model_path",
    "adapter_init_seed",
}
INTEGRITY_BOOLEAN_FIELDS = (
    "schema_valid",
    "synthetic",
    "timed_out",
    "fallback",
    "missing",
    "hard_schema_failure",
)


@dataclass(frozen=True)
class RuntimeBindings:
    """Late-bound runtime classes, replaceable by CPU-only unit tests."""

    system_cls: type
    task_cls: type
    run_task: Callable[..., Any]
    trace_recorder_cls: type


def load_runtime_bindings() -> RuntimeBindings:
    """Import model-heavy CLBench modules only when a cell actually runs."""

    from src.runtime.runner import run_task
    from src.systems.qwen_local.system import QwenLocalSystem
    from src.tasks.cohort_studies.task import CohortStudiesTask
    from src.trace_storage import TraceRecorder

    return RuntimeBindings(
        system_cls=QwenLocalSystem,
        task_cls=CohortStudiesTask,
        run_task=run_task,
        trace_recorder_cls=TraceRecorder,
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    with temporary.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_write_json(path: Path, payload: Any) -> None:
    _atomic_write_bytes(path, _canonical_bytes(payload) + b"\n")


def _refuse_existing(paths: list[Path]) -> None:
    existing = [str(path) for path in paths if path.exists()]
    if existing:
        raise FileExistsError(
            "refusing to overwrite causal artifact(s): " + ", ".join(existing)
        )


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def load_grid(path: Path) -> dict[str, Any]:
    grid = json.loads(path.read_text())
    if not isinstance(grid, dict):
        raise ValueError("grid must be a JSON object")
    if grid.get("protocol") != "cohort_qonly_frozen_tape_weight_update_ablation_v1":
        raise ValueError("unexpected causal protocol")
    kind = grid.get("kind")
    if kind not in {"smoke", "formal"}:
        raise ValueError("causal grid kind must be smoke or formal")

    # A provenance digest binds the checked-in grids, but callers could otherwise
    # pass a different untracked JSON file with the same protocol label.  Rebuild
    # the preregistered grid and require byte-equivalent canonical content before
    # any cell is selected or a model is allocated.
    from generate_cohort_causal_grid import make_grid

    registered = make_grid(smoke=kind == "smoke")
    if _canonical_bytes(grid) != _canonical_bytes(registered):
        raise ValueError(f"{kind} grid differs from the preregistered grid")
    return grid


def select_config(grid: dict[str, Any], cfg_id: str) -> dict[str, Any]:
    candidates = [
        row
        for section in ("collectors", "evaluation_cells")
        for row in grid.get(section, [])
        if isinstance(row, dict) and row.get("cfg_id") == cfg_id
    ]
    if len(candidates) != 1:
        raise ValueError(f"cfg_id must identify exactly one grid row: {cfg_id!r}")
    return candidates[0]


def seed_everything(seed: int) -> None:
    """Set every available process-global RNG before model construction."""

    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("run_seed must be a non-negative integer")
    inherited_hash_seed = os.environ.get("PYTHONHASHSEED")
    if inherited_hash_seed != str(seed):
        raise RuntimeError(
            "PYTHONHASHSEED must be set before process start and equal run_seed; "
            f"expected {seed}, inherited {inherited_hash_seed!r}"
        )
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    random.seed(seed)
    try:
        import numpy as np

        np.random.seed(seed % (2**32))
    except ImportError:
        pass
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        torch.use_deterministic_algorithms(True)
    except ImportError:
        pass


def _assert_run_seed_contract(cfg: dict[str, Any]) -> None:
    if cfg.get("system_params", {}).get("grpo_run_seed") != cfg.get("run_seed"):
        raise ValueError("system grpo_run_seed must equal the registered pair run_seed")


def _dataset_projection(root: Path, grid: dict[str, Any], role: str) -> dict[str, Any]:
    dataset = grid["datasets"][role]
    dataset_dir = _resolve(root, dataset["path"])
    manifest_path = dataset_dir / "manifest.json"
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError(f"{role} dataset manifest has no artifact inventory")
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            raise ValueError(f"{role} dataset artifact entry is malformed")
        artifact_path = dataset_dir / artifact["path"]
        if not artifact_path.is_file():
            raise FileNotFoundError(f"{role} dataset artifact is missing: {artifact_path}")
        if artifact_path.stat().st_size != artifact.get("size_bytes"):
            raise ValueError(f"{role} dataset artifact size drift: {artifact_path}")
        if _sha256_file(artifact_path) != artifact.get("sha256"):
            raise ValueError(f"{role} dataset artifact SHA-256 drift: {artifact_path}")

    schedule_relative = (
        Path("src/tasks/cohort_studies/schedules")
        / f"{manifest.get('schedule_id')}.json"
    )
    schedule_path = root / schedule_relative
    if not schedule_path.is_file():
        raise FileNotFoundError(f"{role} schedule file is missing: {schedule_path}")
    if _sha256_file(schedule_path) != manifest.get("schedule_sha256"):
        raise ValueError(f"{role} schedule SHA-256 drift: {schedule_path}")
    return corpus_projection_from_dataset_manifest(
        manifest,
        dataset_manifest_sha256=_sha256_bytes(raw),
        role=role,
    )


def _absolute_task_params(root: Path, task_params: dict[str, Any]) -> dict[str, Any]:
    runtime = dict(task_params)
    runtime["dataset_path"] = str(_resolve(root, runtime["dataset_path"]))
    return runtime


def _task_manifest_config(task_params: dict[str, Any]) -> dict[str, Any]:
    return {
        **task_params,
        "runs": 1,
        "max_workers": 1,
        "run_mode": "replicate",
    }


def _trace_paths(root: Path, cfg: dict[str, Any]) -> tuple[Path, Path]:
    trace_path = _resolve(
        root,
        cfg.get(
            "trace_path",
            f"artifacts/cohort_causal/traces/{cfg['cfg_id']}.trace.json",
        ),
    )
    live_path = trace_path.with_name(f"{trace_path.stem}.live.json")
    return trace_path, live_path


def _collector_manifest_path(root: Path, cfg: dict[str, Any]) -> Path:
    return _resolve(
        root,
        cfg.get(
            "collector_manifest_path",
            f"artifacts/cohort_causal/collectors/{cfg['cfg_id']}.manifest.json",
        ),
    )


def _build_trace_recorder(
    bindings: RuntimeBindings,
    *,
    cfg: dict[str, Any],
    task: Any,
    trace_path: Path,
    live_path: Path,
    phase: str,
) -> Any:
    return bindings.trace_recorder_cls(
        system_name="qwen_local",
        task_name=TASK_NAME,
        system_params=cfg["system_params"],
        task_params=cfg["task_params"],
        trace_path=trace_path,
        run_group_id=cfg.get("pair_id", cfg["cfg_id"]),
        run_index=0,
        task_brief=task.get_agent_brief(),
        phase=phase,
        live_trace_path=live_path,
    )


def _assert_outcome_identity(result: Any, expected_count: int) -> None:
    outcomes = list(result.instance_outcomes)
    if len(outcomes) != expected_count:
        raise RuntimeError(
            f"expected {expected_count} real outcomes, received {len(outcomes)}"
        )
    identities = [(row.instance_id, row.instance_index) for row in outcomes]
    if any(
        not isinstance(instance_id, str)
        or not instance_id.startswith("cohort_studies:")
        or instance_id.startswith("cohort_studies:__failed")
        or instance_index != position
        for position, (instance_id, instance_index) in enumerate(identities)
    ):
        raise RuntimeError("outcomes contain fallback IDs or non-canonical order")
    if len(set(identities)) != expected_count:
        raise RuntimeError("outcomes contain duplicate identities")


def _assert_outcome_order_matches_corpus(
    result: Any, corpus: dict[str, Any], expected_count: int
) -> None:
    observed = [row.instance_id for row in result.instance_outcomes]
    expected = corpus["canonical_instance_ids"][:expected_count]
    if observed != expected:
        raise RuntimeError("runtime outcome IDs/order differ from frozen corpus manifest")


def _finalize_trace(recorder: Any, result: Any, path: Path) -> dict[str, Any]:
    payload = recorder.finalize(result, status="completed")
    _atomic_write_json(path, payload)
    return payload


def _response_integrity(metadata: dict[str, Any]) -> dict[str, Any]:
    llm_error = metadata.get("llm_error")
    integrity = {
        "schema_valid": llm_error is None,
        "synthetic": llm_error is not None,
        "timed_out": bool(
            isinstance(llm_error, dict)
            and llm_error.get("error_type") == "_InstanceTimeout"
        ),
        "fallback": llm_error is not None,
        "missing": False,
        "hard_schema_failure": bool(
            isinstance(llm_error, dict)
            and "did not parse as the required JSON"
            in str(llm_error.get("error_message", ""))
        ),
        "parse_retries": int(metadata.get("parse_retries_used", 0)),
        "repairs": int(bool(metadata.get("parse_repair_used", False))),
    }
    if any(not isinstance(integrity[key], bool) for key in INTEGRITY_BOOLEAN_FIELDS):
        raise RuntimeError("malformed response integrity")
    return integrity


def _heldout_rows(
    trace: dict[str, Any], result: Any
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    integrity_by_identity: dict[tuple[str, int], dict[str, Any]] = {}
    for interaction in trace.get("interactions", []):
        observation = interaction.get("observation", {})
        if observation.get("instance_complete") is not True:
            continue
        query = interaction.get("query", {})
        identity = (query.get("instance_id"), query.get("instance_index"))
        metadata = interaction.get("response", {}).get("metadata", {})
        integrity_by_identity[identity] = _response_integrity(metadata)

    rows: list[dict[str, Any]] = []
    for outcome in result.instance_outcomes:
        identity = (outcome.instance_id, outcome.instance_index)
        integrity = integrity_by_identity.get(identity)
        if integrity is None:
            raise RuntimeError(f"missing terminal response integrity for {identity!r}")
        rows.append(
            {
                "instance_id": outcome.instance_id,
                "instance_index": outcome.instance_index,
                "reward": float(outcome.reward),
                "integrity": integrity,
            }
        )
    counters = {
        "synthetic_outcomes": sum(row["integrity"]["synthetic"] for row in rows),
        "timed_out_outcomes": sum(row["integrity"]["timed_out"] for row in rows),
        "fallbacks": sum(row["integrity"]["fallback"] for row in rows),
        "missing_outcomes": sum(row["integrity"]["missing"] for row in rows),
        "hard_schema_failures": sum(
            row["integrity"]["hard_schema_failure"] for row in rows
        ),
        "parse_retries": sum(row["integrity"]["parse_retries"] for row in rows),
        "repairs": sum(row["integrity"]["repairs"] for row in rows),
    }
    if any(counters[key] for key in (
        "synthetic_outcomes",
        "timed_out_outcomes",
        "fallbacks",
        "missing_outcomes",
        "hard_schema_failures",
    )):
        raise RuntimeError("held-out integrity gate failed; refusing cell manifest")
    return rows, counters


def load_provenance(path: Path) -> dict[str, Any]:
    provenance = json.loads(path.read_text())
    if not isinstance(provenance, dict) or set(provenance) != REQUIRED_PROVENANCE_FIELDS:
        raise ValueError(
            "provenance JSON must contain exactly: "
            + ", ".join(sorted(REQUIRED_PROVENANCE_FIELDS))
        )
    sha_fields = {
        key
        for key in REQUIRED_PROVENANCE_FIELDS
        if key.endswith("_sha256") or key in {"source_commit", "preregistered_parent_commit"}
    }
    for key in sha_fields:
        value = provenance[key]
        expected_length = 40 if key in {"source_commit", "preregistered_parent_commit"} else 64
        if (
            not isinstance(value, str)
            or len(value) != expected_length
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"invalid provenance digest: {key}")
    if provenance["preregistered_parent_commit"] != PREREGISTERED_PARENT_COMMIT:
        raise ValueError("provenance preregistered_parent_commit mismatch")
    return provenance


def run_collection(
    *,
    root: Path,
    grid: dict[str, Any],
    cfg: dict[str, Any],
    bindings: RuntimeBindings,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    if cfg.get("mode") != "collect_tape" or cfg.get("arm") != "collector_lr0":
        raise ValueError("collection requires a collector_lr0 grid row")
    if cfg["system_params"].get("ttt_lr") != 0.0 or cfg["system_params"].get(
        "reward_pg_lr"
    ) != 0.0:
        raise ValueError("frozen-tape collector learning rates must both be zero")
    _assert_run_seed_contract(cfg)
    if provenance["model_path"] != cfg["system_params"]["model_path"]:
        raise ValueError("provenance model_path differs from collector config")
    if provenance["adapter_init_seed"] != grid["adapter_init_seed"]:
        raise ValueError("provenance adapter_init_seed differs from grid")
    projection = _dataset_projection(root, grid, "adaptation")

    tape_path = _resolve(root, cfg["tape_path"])
    manifest_path = _collector_manifest_path(root, cfg)
    trace_path, live_path = _trace_paths(root, cfg)
    _refuse_existing([tape_path, manifest_path, trace_path, live_path])

    seed_everything(cfg["run_seed"])
    system = bindings.system_cls(**cfg["system_params"])
    initial_hash = system.initialize_and_snapshot_adapter_state()
    task = bindings.task_cls(**_absolute_task_params(root, cfg["task_params"]))
    recorder = _build_trace_recorder(
        bindings,
        cfg=cfg,
        task=task,
        trace_path=trace_path,
        live_path=live_path,
        phase="rollout",
    )
    items: list[dict[str, Any]] = []

    def capture_terminal(_step: int, query: Any, response: Any, step_result: Any) -> None:
        observation = step_result.observation
        if not bool(getattr(observation, "instance_complete", False)):
            return
        integrity = _response_integrity(dict(response.metadata or {}))
        items.append(
            system.capture_frozen_tape_item(
                observation,
                sequence_index=len(items),
                instance_id=query.instance_id,
                instance_index=query.instance_index,
                integrity=integrity,
            )
        )

    result = bindings.run_task(
        task,
        system,
        trace_recorder=recorder,
        show_progress=True,
        verbose_logging=True,
        rollout_label=cfg["cfg_id"],
        reset_system=False,
        phase="rollout",
        before_observe=capture_terminal,
    )
    expected = int(cfg["expected_num_instances"])
    _assert_outcome_identity(result, expected)
    _assert_outcome_order_matches_corpus(result, projection, expected)
    if len(items) != expected:
        raise RuntimeError(f"expected {expected} tape items, captured {len(items)}")
    final_hash = system.current_trainable_param_sha256()
    if final_hash != initial_hash:
        raise RuntimeError("LR0 collector changed trainable parameters")

    tape = system.assemble_frozen_update_tape(items)
    tape_bytes = system.serialize_frozen_update_tape(tape)
    if json.loads(tape_bytes)["tape_sha256"] != tape["tape_sha256"]:
        raise RuntimeError("serialized tape digest changed")
    trace = _finalize_trace(recorder, result, trace_path)
    if system.current_trainable_param_sha256() != initial_hash:
        raise RuntimeError("trace finalization changed LR0 collector parameters")
    verification = {
        "digest_verified": True,
        "items": [
            {
                "sequence_index": item["sequence_index"],
                "item_sha256": item["item_sha256"],
                "digest_verified": True,
            }
            for item in tape["items"]
        ],
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "protocol": grid["protocol"],
        "mechanism_label": MECHANISM_LABEL,
        "limitation": LIMITATION,
        "cfg_id": cfg["cfg_id"],
        "run_seed": cfg["run_seed"],
        "adapter_init_seed": grid["adapter_init_seed"],
        "provenance": provenance,
        "expected_num_instances": expected,
        "trainable_param_sha256_initial": initial_hash,
        "trainable_param_sha256_final": final_hash,
        "tape_path": str(tape_path),
        "tape_sha256": tape["tape_sha256"],
        "tape_verification": verification,
        "adaptation_corpus": projection,
        "trace_path": str(trace_path),
        "trace_sha256": canonical_sha256(trace),
    }
    # Tape first, manifest last: a manifest therefore certifies the tape exists.
    _atomic_write_bytes(tape_path, tape_bytes)
    _atomic_write_json(manifest_path, manifest)
    live_path.unlink(missing_ok=True)
    return manifest


def run_replay_eval(
    *,
    root: Path,
    grid: dict[str, Any],
    cfg: dict[str, Any],
    bindings: RuntimeBindings,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    if cfg.get("mode") != "replay_eval" or cfg.get("arm") not in {"active", "lr0"}:
        raise ValueError("replay evaluation requires an active or lr0 grid row")
    _assert_run_seed_contract(cfg)
    if provenance["model_path"] != cfg["system_params"]["model_path"]:
        raise ValueError("provenance model_path differs from cell config")
    if provenance["adapter_init_seed"] != grid["adapter_init_seed"]:
        raise ValueError("provenance adapter_init_seed differs from grid")

    tape_path = _resolve(root, cfg["tape_path"])
    if not tape_path.is_file():
        raise FileNotFoundError(f"collector tape is missing: {tape_path}")
    tape_bytes = tape_path.read_bytes()
    tape = json.loads(tape_bytes)
    expected_digest = tape.get("tape_sha256")
    if not isinstance(expected_digest, str):
        raise ValueError("collector tape has no embedded digest")

    manifest_path = _resolve(root, cfg["cell_manifest_path"])
    trace_path, live_path = _trace_paths(root, cfg)
    _refuse_existing([manifest_path, trace_path, live_path])

    seed_everything(cfg["run_seed"])
    system = bindings.system_cls(**cfg["system_params"])
    initialized_hash = system.initialize_and_snapshot_adapter_state()
    restored_hash = system.restore_initial_adapter_state()
    if restored_hash != initialized_hash:
        raise RuntimeError("adapter restore did not reproduce initialized hash")
    replay = system.replay_frozen_update_tape(
        tape_bytes, expected_tape_sha256=expected_digest
    )
    frozen_hash = system.freeze_updates_for_heldout_eval()
    if frozen_hash != replay["trainable_param_sha256_final"]:
        raise RuntimeError("hard-freeze hash differs from replay final hash")

    task = bindings.task_cls(**_absolute_task_params(root, cfg["task_params"]))
    recorder = _build_trace_recorder(
        bindings,
        cfg=cfg,
        task=task,
        trace_path=trace_path,
        live_path=live_path,
        phase="baseline",
    )
    result = bindings.run_task(
        task,
        system,
        trace_recorder=recorder,
        show_progress=True,
        verbose_logging=True,
        rollout_label=cfg["cfg_id"],
        reset_system=False,
        phase="baseline",
    )
    expected = int(cfg["expected_num_instances"])
    _assert_outcome_identity(result, expected)
    heldout = _dataset_projection(root, grid, "heldout")
    _assert_outcome_order_matches_corpus(result, heldout, expected)
    trace = _finalize_trace(recorder, result, trace_path)
    if system.current_trainable_param_sha256() != frozen_hash:
        raise RuntimeError("held-out evaluation or trace finalization changed parameters")
    outcomes, counters = _heldout_rows(trace, result)

    adaptation = _dataset_projection(root, grid, "adaptation")
    task_config = _task_manifest_config(cfg["task_params"])
    system_config = dict(cfg["system_params"])
    cell = {
        "outcome_schema_version": SCHEMA_VERSION,
        "status": "completed",
        "arm": cfg["arm"],
        "run_seed": cfg["run_seed"],
        "heldout_updates_frozen": True,
        "tape_sha256": expected_digest,
        "adaptation_corpus_sha256": adaptation["aggregate_sha256"],
        "heldout_corpus_sha256": heldout["aggregate_sha256"],
        "provenance": provenance,
        "system_config": system_config,
        "system_config_sha256": canonical_sha256(system_config),
        "masked_pair_config_sha256": masked_pair_config_sha256(system_config),
        "task_config": task_config,
        "task_config_sha256": canonical_sha256(task_config),
        "evaluation_order_sha256": canonical_sha256(
            heldout["canonical_instance_ids"][:expected]
        ),
        "replay": replay,
        "heldout_outcomes": outcomes,
        "integrity_counters": counters,
        "score": statistics.mean(row["reward"] for row in outcomes),
        "trace_path": str(trace_path),
        "trace_sha256": canonical_sha256(trace),
    }
    _atomic_write_json(manifest_path, cell)
    live_path.unlink(missing_ok=True)
    return cell


def current_source_commit(root: Path = ROOT) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def verify_runtime_provenance(
    root: Path,
    provenance: dict[str, Any],
    *,
    expected_model_path: Path | None = None,
) -> None:
    """Fail closed on checkout, code, model, tokenizer, or environment drift."""

    # Lazy import avoids the provenance builder's import of this module for the
    # shared consumer schema while keeping model-heavy CLBench imports deferred.
    from build_cohort_causal_provenance import verify_current_provenance

    verify_current_provenance(
        root=root,
        provenance=provenance,
        expected_model_path=expected_model_path,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument("--cfg-id", required=True)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()

    root = args.root.resolve()
    grid = load_grid(args.grid.resolve())
    cfg = select_config(grid, args.cfg_id)
    if args.provenance is None:
        parser.error("--provenance is required for both collect_tape and replay_eval")
    provenance = load_provenance(args.provenance.resolve())
    verify_runtime_provenance(
        root,
        provenance,
        expected_model_path=Path(cfg["system_params"]["model_path"]),
    )
    bindings = load_runtime_bindings()
    if cfg["mode"] == "collect_tape":
        result = run_collection(
            root=root,
            grid=grid,
            cfg=cfg,
            bindings=bindings,
            provenance=provenance,
        )
    elif cfg["mode"] == "replay_eval":
        result = run_replay_eval(
            root=root,
            grid=grid,
            cfg=cfg,
            bindings=bindings,
            provenance=provenance,
        )
    else:
        raise SystemExit(f"unsupported grid mode: {cfg.get('mode')!r}")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
