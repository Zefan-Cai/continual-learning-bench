#!/usr/bin/env python3
"""Emit collision-safe worker assignments for a D2 group-PG grid.

Unlike the legacy launcher, every assignment carries both system_params and
task_params plus the requested run_mode.  This prevents the launcher from
silently replacing the registered task order with schedule=default/run_index=0.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("grid", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--job-index", type=int, default=0)
    parser.add_argument("--node-rank", type=int, default=0)
    parser.add_argument("--num-jobs", type=int, default=1)
    parser.add_argument("--gpus-per-node", type=int, default=8)
    parser.add_argument(
        "--release-stage",
        type=int,
        choices=(1, 2),
        help="Only emit configs whose release_stage is <= this gate.",
    )
    args = parser.parse_args()

    configs = json.loads(args.grid.read_text())
    if not isinstance(configs, list) or not configs:
        raise SystemExit("grid must be a non-empty JSON list")
    if args.release_stage is not None:
        configs = [
            cfg
            for cfg in configs
            if int(cfg.get("release_stage", 1)) <= args.release_stage
        ]

    ids = [cfg.get("cfg_id") for cfg in configs]
    if any(not isinstance(cfg_id, str) or not cfg_id for cfg_id in ids):
        raise SystemExit("every config needs a non-empty cfg_id")
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate cfg_id in grid")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    params_dir = args.output_dir / "params"
    assign_dir = args.output_dir / "assign"
    params_dir.mkdir(exist_ok=True)
    assign_dir.mkdir(exist_ok=True)

    total_workers = args.num_jobs * args.gpus_per_node
    for gpu in range(args.gpus_per_node):
        worker = (
            args.job_index * args.gpus_per_node
            + args.node_rank * args.gpus_per_node
            + gpu
        )
        mine = configs[worker::total_workers]
        mine_ids = {cfg["cfg_id"] for cfg in mine}
        rest = [cfg for cfg in configs if cfg["cfg_id"] not in mine_ids]
        rotation = worker % max(1, len(rest)) if rest else 0
        ordered = mine + rest[rotation:] + rest[:rotation]

        lines: list[str] = []
        for cfg in ordered:
            cfg_id = cfg["cfg_id"]
            system_params = cfg.get("system_params")
            task_params = cfg.get("task_params")
            run_mode = cfg.get("run_mode")
            if not isinstance(system_params, dict):
                raise SystemExit(f"{cfg_id}: system_params must be an object")
            if not isinstance(task_params, dict):
                raise SystemExit(f"{cfg_id}: task_params must be an object")
            if run_mode not in {"replicate", "resample", "permute"}:
                raise SystemExit(f"{cfg_id}: invalid run_mode={run_mode!r}")
            if system_params.get("reward_update_rule") != "group_pg_instance":
                raise SystemExit(f"{cfg_id}: wrong reward_update_rule")
            if task_params.get("seed") != 42:
                raise SystemExit(f"{cfg_id}: registered task-order seed must be 42")
            if not isinstance(system_params.get("grpo_run_seed"), int):
                raise SystemExit(f"{cfg_id}: grpo_run_seed must be explicit")
            if run_mode == "replicate" and int(task_params.get("run_index", 0)) <= 0:
                raise SystemExit(
                    f"{cfg_id}: explicit nonzero run_index required for registered permutation"
                )

            system_path = params_dir / f"{cfg_id}.system.json"
            task_path = params_dir / f"{cfg_id}.task.json"
            dump_json(system_path, system_params)
            dump_json(task_path, task_params)
            lines.append(
                "\t".join(
                    (
                        cfg_id,
                        cfg["task"],
                        str(system_path),
                        str(task_path),
                        str(cfg.get("runs", 1)),
                        run_mode,
                    )
                )
            )
        (assign_dir / f"gpu{gpu}.list").write_text(
            ("\n".join(lines) + "\n") if lines else ""
        )

    print(
        f"GROUP_PG_ASSIGNMENTS_OK configs={len(configs)} workers={total_workers} "
        f"release_stage={args.release_stage or 'all'}"
    )


if __name__ == "__main__":
    main()
