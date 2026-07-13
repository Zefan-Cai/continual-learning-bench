#!/usr/bin/env python3
"""Validate the preregistered candidate-distillation formal experiment.

The integrity gate is deliberately separate from the scientific decision.  A
missing/tampered manifest exits nonzero with ``decision=invalid``.  A complete
experiment that misses the preregistered effect thresholds remains a valid
measurement, exits zero, and reports ``decision=no_go``.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from validate_group_pg_manifest import (
    strict_json_equal,
    validate as validate_manifest,
)


EXPECTED_PAIRS = 3
EXPECTED_OUTCOMES = 20
GO_MEAN_DELTA = 0.03
GO_MIN_DELTA = -0.03


def _real_outcomes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("result", {}).get("instance_outcomes", [])
    if not isinstance(rows, list):
        return []
    return [
        row
        for row in rows
        if isinstance(row, dict)
        and not str(row.get("instance_id", "")).startswith("__failed")
    ]


def _score_relevant_outcomes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Project outcomes onto fields that can affect benchmark score semantics.

    Runtime-derived ``cost_usd`` and ``latency_seconds`` are intentionally not
    included.  They can differ across otherwise identical LR0 executions.
    """

    fields = (
        "instance_id",
        "instance_index",
        "reward",
        "success",
        "raw_metric_name",
        "raw_metric_value",
        "raw_metric_higher_is_better",
        "metadata",
    )
    return [
        {field: row[field] for field in fields if field in row}
        for row in _real_outcomes(payload)
    ]


def _first_instance_trajectory(payload: dict[str, Any]) -> tuple[bool, Any]:
    """Return a timing/usage-free first-instance trajectory when available."""

    outcomes = _real_outcomes(payload)
    interactions = payload.get("interactions")
    if not outcomes or not isinstance(interactions, list) or not interactions:
        return False, None
    first_id = outcomes[0].get("instance_id")
    first_index = outcomes[0].get("instance_index")
    selected: list[dict[str, Any]] = []
    for interaction in interactions:
        if not isinstance(interaction, dict):
            continue
        query = interaction.get("query")
        if not isinstance(query, dict):
            continue
        matches = (first_id is not None and query.get("instance_id") == first_id) or (
            first_index is not None and query.get("instance_index") == first_index
        )
        if not matches:
            continue
        selected.append(
            {
                key: interaction.get(key)
                for key in (
                    "step_number",
                    "query",
                    "response",
                    "observation",
                    "done",
                )
            }
        )
    return bool(selected), selected


def _json_load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("top-level JSON value is not an object")
    return payload


def _candidate_paths(root: Path, cfg: dict[str, Any]) -> list[Path]:
    cfg_id = cfg["cfg_id"]
    task = cfg.get("task")
    direct = [
        root / cfg_id / "run_1.json",
        root / f"{cfg_id}.run1.json",
        root / cfg_id / "manifest.json",
        root / "live" / cfg_id / "manifest.json",
    ]
    if isinstance(task, str) and task:
        direct.append(root / task / "live" / cfg_id / "manifest.json")
    found = [path for path in direct if path.is_file()]
    if found:
        return found

    recursive = set(root.rglob(f"{cfg_id}.run1.json"))
    recursive.update(root.rglob(f"{cfg_id}/run_1.json"))
    for path in (*root.rglob("run_1.json"), *root.rglob("manifest.json")):
        try:
            payload = _json_load(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if payload.get("execution", {}).get("run_group_id") == cfg_id:
            recursive.add(path)
    return sorted(recursive, key=lambda path: str(path))


def load_manifests(
    expected_grid: list[dict[str, Any]], results_root: Path
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Load one unambiguous manifest for every registered cell."""

    manifests: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    if not results_root.is_dir():
        return {}, [f"results root is not a directory: {results_root}"]
    for cfg in expected_grid:
        if not isinstance(cfg, dict):
            continue
        cfg_id = cfg.get("cfg_id")
        if not isinstance(cfg_id, str) or not cfg_id:
            continue
        paths = _candidate_paths(results_root, cfg)
        if not paths:
            errors.append(f"{cfg_id}: missing result manifest")
            continue
        payloads: list[tuple[Path, dict[str, Any]]] = []
        for path in paths:
            try:
                payloads.append((path, _json_load(path)))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{cfg_id}: cannot load {path.name}: {exc}")
        if not payloads:
            continue
        reference = payloads[0][1]
        if any(
            not strict_json_equal(payload, reference) for _, payload in payloads[1:]
        ):
            errors.append(f"{cfg_id}: conflicting duplicate result manifests")
            continue
        manifests[cfg_id] = reference
    return manifests, errors


def _normalized_pair_config(cfg: dict[str, Any]) -> dict[str, Any]:
    normalized = json.loads(json.dumps(cfg))
    for key in ("cfg_id", "group", "candidate_arm"):
        normalized.pop(key, None)
    params = normalized.get("system_params")
    if isinstance(params, dict):
        params["reward_pg_lr"] = "<paired-learning-rate>"
    return normalized


def validate_grid(
    expected_grid: list[dict[str, Any]],
) -> tuple[list[tuple[int, str, dict[str, Any], dict[str, Any]]], list[str]]:
    """Return seed-sorted ``(seed, pair_id, active, lr0)`` registrations."""

    errors: list[str] = []
    if len(expected_grid) != 2 * EXPECTED_PAIRS:
        errors.append(f"formal grid must contain exactly {2 * EXPECTED_PAIRS} cells")
    if any(not isinstance(cfg, dict) for cfg in expected_grid):
        return [], [*errors, "formal grid contains a non-object cell"]
    cfg_ids = [cfg.get("cfg_id") for cfg in expected_grid]
    if any(not isinstance(cfg_id, str) or not cfg_id for cfg_id in cfg_ids):
        errors.append("formal grid contains a missing/invalid cfg_id")
    duplicates = sorted(
        cfg_id
        for cfg_id, count in Counter(
            cfg_id for cfg_id in cfg_ids if isinstance(cfg_id, str)
        ).items()
        if count > 1
    )
    if duplicates:
        errors.append(f"formal grid contains duplicate cfg_id(s): {duplicates}")

    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for cfg in expected_grid:
        pair_id = cfg.get("pair_id")
        if not isinstance(pair_id, str) or not pair_id:
            errors.append(f"{cfg.get('cfg_id')}: missing/invalid pair_id")
            continue
        grouped[pair_id].append(cfg)
    if len(grouped) != EXPECTED_PAIRS:
        errors.append(
            f"formal grid must contain exactly {EXPECTED_PAIRS} pair_id values"
        )

    pairs: list[tuple[int, str, dict[str, Any], dict[str, Any]]] = []
    seen_seeds: set[int] = set()
    for pair_id in sorted(grouped):
        cells = grouped[pair_id]
        if any(not isinstance(cfg.get("candidate_arm"), str) for cfg in cells):
            errors.append(f"{pair_id}: contains a missing/invalid candidate_arm")
            continue
        arms = {cfg.get("candidate_arm"): cfg for cfg in cells}
        if len(cells) != 2 or set(arms) != {"active", "lr0"}:
            errors.append(f"{pair_id}: requires exactly one active and one lr0 cell")
            continue
        active, lr0 = arms["active"], arms["lr0"]
        seed = active.get("sampling_seed")
        if (
            not isinstance(seed, int)
            or isinstance(seed, bool)
            or lr0.get("sampling_seed") != seed
        ):
            errors.append(f"{pair_id}: paired sampling_seed mismatch")
            continue
        if seed in seen_seeds:
            errors.append(f"{pair_id}: sampling_seed {seed} is reused")
        seen_seeds.add(seed)
        if not strict_json_equal(
            _normalized_pair_config(active), _normalized_pair_config(lr0)
        ):
            errors.append(f"{pair_id}: paired configs differ beyond arm/lr/cfg labels")
        for arm_name, cfg, expected_lr in (
            ("active", active, 1e-4),
            ("lr0", lr0, 0.0),
        ):
            sp = cfg.get("system_params", {})
            tp = cfg.get("task_params", {})
            if not isinstance(sp, dict):
                errors.append(f"{pair_id}/{arm_name}: system_params must be an object")
                continue
            if not isinstance(tp, dict):
                errors.append(f"{pair_id}/{arm_name}: task_params must be an object")
                continue
            if (
                cfg.get("arm") != "active"
                or sp.get("freeze_parameter_updates") is not False
            ):
                errors.append(f"{pair_id}/{arm_name}: must execute the active path")
            if sp.get("reward_pg_lr") != expected_lr:
                errors.append(f"{pair_id}/{arm_name}: wrong reward_pg_lr")
            if sp.get("ttt_lr") != 0.0:
                errors.append(f"{pair_id}/{arm_name}: ttt_lr must be zero")
            if sp.get("reward_update_rule") != "candidate_distill_instance":
                errors.append(f"{pair_id}/{arm_name}: wrong reward_update_rule")
            if sp.get("grpo_candidate_proposer") != "unit_interval_jitter":
                errors.append(f"{pair_id}/{arm_name}: wrong candidate proposer")
            if sp.get("grpo_run_seed") != seed:
                errors.append(f"{pair_id}/{arm_name}: grpo_run_seed mismatch")
            if (
                tp.get("expected_num_instances", tp.get("num_instances"))
                != EXPECTED_OUTCOMES
            ):
                errors.append(f"{pair_id}/{arm_name}: expected instances must be 20")
        pairs.append((seed, pair_id, active, lr0))
    return sorted(pairs, key=lambda item: item[0]), errors


def _valid_score(payload: dict[str, Any]) -> float | None:
    score = payload.get("result", {}).get("score")
    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not math.isfinite(float(score))
    ):
        return None
    return float(score)


def _check_hash_contract(
    *, cfg_id: str, payload: dict[str, Any], candidate_arm: str
) -> list[str]:
    errors: list[str] = []
    metrics = payload.get("system_update_metrics", {})
    initial = metrics.get("grpo_trainable_param_sha256_initial")
    current = metrics.get("grpo_trainable_param_sha256_current")
    if not isinstance(initial, str) or len(initial) != 64:
        errors.append(f"{cfg_id}: missing initial trainable-parameter hash")
    if not isinstance(current, str) or len(current) != 64:
        errors.append(f"{cfg_id}: missing current trainable-parameter hash")
    if not errors:
        if candidate_arm == "lr0" and initial != current:
            errors.append(f"{cfg_id}: LR0 trainable-parameter hash changed")
        if candidate_arm == "active" and initial == current:
            errors.append(f"{cfg_id}: active trainable-parameter hash did not change")
    if candidate_arm == "lr0":
        log = metrics.get("grpo_instance_log", [])
        if isinstance(log, list):
            for index, row in enumerate(log):
                if not isinstance(row, dict):
                    continue
                if (
                    row.get("trainable_param_sha256_before") != initial
                    or row.get("trainable_param_sha256_after") != initial
                ):
                    errors.append(f"{cfg_id}: LR0 log[{index}] hash changed")
    return errors


def _check_first_log_pair(
    pair_id: str, active: dict[str, Any], lr0: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    logs = []
    for arm_name, payload in (("active", active), ("lr0", lr0)):
        log = payload.get("system_update_metrics", {}).get("grpo_instance_log")
        if not isinstance(log, list) or not log or not isinstance(log[0], dict):
            errors.append(f"{pair_id}/{arm_name}: missing first proposer log row")
            logs.append({})
        else:
            logs.append(log[0])
    if errors:
        return errors
    active_log, lr0_log = logs
    required = (
        "candidate_proposer",
        "sampling_seed",
        "sampling_prompt_sha256",
        "group_size",
        "reward_mean",
        "reward_std",
        "committed_reward",
    )
    for field in required:
        if field not in active_log or field not in lr0_log:
            errors.append(f"{pair_id}: first log missing {field}")
        elif not strict_json_equal(active_log[field], lr0_log[field]):
            errors.append(f"{pair_id}: first log {field} mismatch")
    for arm_name, row in (("active", active_log), ("lr0", lr0_log)):
        sampling = row.get("candidate_sampling")
        if not isinstance(sampling, dict):
            errors.append(f"{pair_id}/{arm_name}: missing first candidate_sampling")
            continue
        for field in ("proposal_seed_scheme", "proposal_seed_digests"):
            if field not in sampling:
                errors.append(f"{pair_id}/{arm_name}: missing first {field}")
    active_sampling = active_log.get("candidate_sampling")
    lr0_sampling = lr0_log.get("candidate_sampling")
    if isinstance(active_sampling, dict) and isinstance(lr0_sampling, dict):
        for field in ("proposal_seed_scheme", "proposal_seed_digests"):
            if (
                field in active_sampling
                and field in lr0_sampling
                and not strict_json_equal(active_sampling[field], lr0_sampling[field])
            ):
                errors.append(f"{pair_id}: first {field} mismatch")
    return errors


def evaluate(
    expected_grid: list[dict[str, Any]],
    manifests: dict[str, dict[str, Any]],
    *,
    load_errors: list[str] | None = None,
) -> dict[str, Any]:
    """Return a deterministic integrity report and preregistered decision."""

    pairs, errors = validate_grid(expected_grid)
    errors.extend(load_errors or [])
    config_by_id = {
        cfg["cfg_id"]: cfg
        for cfg in expected_grid
        if isinstance(cfg, dict)
        and isinstance(cfg.get("cfg_id"), str)
        and cfg.get("cfg_id")
    }
    unexpected_manifests = sorted(set(manifests) - set(config_by_id))
    if unexpected_manifests:
        errors.append(f"unexpected result manifest(s): {unexpected_manifests}")
    for cfg_id in sorted(config_by_id):
        payload = manifests.get(cfg_id)
        if payload is None:
            if not any(error.startswith(f"{cfg_id}: missing") for error in errors):
                errors.append(f"{cfg_id}: missing result manifest")
            continue
        errors.extend(
            f"{cfg_id}: {error}"
            for error in validate_manifest(
                payload,
                strict_smoke=True,
                expected_config=config_by_id[cfg_id],
            )
        )
        outcomes = _real_outcomes(payload)
        if len(outcomes) != EXPECTED_OUTCOMES:
            errors.append(f"{cfg_id}: outcome count must be exactly 20")
        identities = [
            (row.get("instance_id"), row.get("instance_index")) for row in outcomes
        ]
        if any(
            not isinstance(instance_id, str)
            or not instance_id
            or not isinstance(instance_index, int)
            or isinstance(instance_index, bool)
            for instance_id, instance_index in identities
        ):
            errors.append(f"{cfg_id}: outcome identity is missing/invalid")
        elif len(set(identities)) != len(identities):
            errors.append(f"{cfg_id}: duplicate outcome identity")
        score = _valid_score(payload)
        if score is None:
            errors.append(f"{cfg_id}: result.score is not finite")
        elif len(outcomes) == EXPECTED_OUTCOMES:
            rewards = [row.get("reward") for row in outcomes]
            if any(
                not isinstance(value, (int, float)) or isinstance(value, bool)
                for value in rewards
            ):
                errors.append(f"{cfg_id}: outcome reward is not numeric")
            elif score != float(statistics.mean(rewards)):
                errors.append(f"{cfg_id}: result.score is not the outcome reward mean")
        candidate_arm = config_by_id[cfg_id].get("candidate_arm")
        if candidate_arm in {"active", "lr0"}:
            errors.extend(
                _check_hash_contract(
                    cfg_id=cfg_id,
                    payload=payload,
                    candidate_arm=candidate_arm,
                )
            )

    reference_order: list[tuple[Any, Any]] | None = None
    for cfg in expected_grid:
        cfg_id = cfg.get("cfg_id") if isinstance(cfg, dict) else None
        payload = manifests.get(cfg_id) if isinstance(cfg_id, str) else None
        if payload is None:
            continue
        order = [
            (row.get("instance_id"), row.get("instance_index"))
            for row in _real_outcomes(payload)
        ]
        if reference_order is None:
            reference_order = order
        elif not strict_json_equal(order, reference_order):
            errors.append(f"{cfg_id}: exact instance ID/order mismatch")

    pair_reports: list[dict[str, Any]] = []
    raw_deltas: list[float] = []
    lr0_records: list[tuple[str, dict[str, Any]]] = []
    trajectory_pairs_checked = 0
    for seed, pair_id, active_cfg, lr0_cfg in pairs:
        active_id, lr0_id = active_cfg["cfg_id"], lr0_cfg["cfg_id"]
        active = manifests.get(active_id)
        lr0 = manifests.get(lr0_id)
        if active is None or lr0 is None:
            continue
        active_outcomes = _real_outcomes(active)
        lr0_outcomes = _real_outcomes(lr0)
        if (
            len(active_outcomes) == EXPECTED_OUTCOMES
            and len(lr0_outcomes) == EXPECTED_OUTCOMES
        ):
            if active_outcomes[0].get("reward") != lr0_outcomes[0].get("reward"):
                errors.append(f"{pair_id}: first outcome reward mismatch")
        active_available, active_trajectory = _first_instance_trajectory(active)
        lr0_available, lr0_trajectory = _first_instance_trajectory(lr0)
        if active_available or lr0_available:
            if not active_available or not lr0_available:
                errors.append(
                    f"{pair_id}: first trajectory is only available in one arm"
                )
            elif not strict_json_equal(active_trajectory, lr0_trajectory):
                errors.append(f"{pair_id}: first trajectory mismatch")
            else:
                trajectory_pairs_checked += 1
        errors.extend(_check_first_log_pair(pair_id, active, lr0))
        active_initial = active.get("system_update_metrics", {}).get(
            "grpo_trainable_param_sha256_initial"
        )
        lr0_initial = lr0.get("system_update_metrics", {}).get(
            "grpo_trainable_param_sha256_initial"
        )
        if active_initial != lr0_initial:
            errors.append(f"{pair_id}: paired initial trainable hashes differ")
        active_score, lr0_score = _valid_score(active), _valid_score(lr0)
        if active_score is not None and lr0_score is not None:
            raw_delta = active_score - lr0_score
            raw_deltas.append(raw_delta)
            pair_reports.append(
                {
                    "active_cfg_id": active_id,
                    "active_score": active_score,
                    "delta_seed": round(raw_delta, 12),
                    "lr0_cfg_id": lr0_id,
                    "lr0_score": lr0_score,
                    "pair_id": pair_id,
                    "sampling_seed": seed,
                }
            )
        lr0_records.append((lr0_id, lr0))

    if len(lr0_records) >= 2:
        reference_id, reference = lr0_records[0]
        reference_outcomes = _score_relevant_outcomes(reference)
        reference_score = reference.get("result", {}).get("score")
        for cfg_id, payload in lr0_records[1:]:
            if not strict_json_equal(
                _score_relevant_outcomes(payload), reference_outcomes
            ):
                errors.append(
                    f"{cfg_id}: LR0 score-relevant outcomes are not bit-exact "
                    f"with {reference_id}"
                )
            if not strict_json_equal(
                payload.get("result", {}).get("score"), reference_score
            ):
                errors.append(
                    f"{cfg_id}: LR0 score is not bit-exact with {reference_id}"
                )

    aggregate: dict[str, Any] | None = None
    threshold_checks: dict[str, bool] | None = None
    if len(pair_reports) == EXPECTED_PAIRS:
        raw_mean_delta = float(statistics.mean(raw_deltas))
        raw_median_delta = float(statistics.median(raw_deltas))
        raw_min_delta = min(raw_deltas)
        positive_seeds = sum(delta > 0 for delta in raw_deltas)
        aggregate = {
            "mean_delta": round(raw_mean_delta, 12),
            "median_delta": round(raw_median_delta, 12),
            "min_delta": round(raw_min_delta, 12),
            "positive_seeds": positive_seeds,
        }
        threshold_checks = {
            "mean_delta_gte_0_03": raw_mean_delta >= GO_MEAN_DELTA,
            "median_delta_gt_0": raw_median_delta > 0,
            "min_delta_gt_neg_0_03": raw_min_delta > GO_MIN_DELTA,
            "positive_seeds_gte_2": positive_seeds >= 2,
        }

    unique_errors = sorted(set(errors))
    if unique_errors:
        decision = "invalid"
        status = "invalid"
    elif threshold_checks is not None and all(threshold_checks.values()):
        decision = "go"
        status = "valid"
    else:
        decision = "no_go"
        status = "valid"
    return {
        "aggregate": aggregate,
        "checks": {
            "expected_manifests": 2 * EXPECTED_PAIRS,
            "loaded_manifests": len(manifests),
            "lr0_bit_exact_arms": len(lr0_records),
            "trajectory_pairs_checked": trajectory_pairs_checked,
        },
        "decision": decision,
        "errors": unique_errors,
        "experiment": "candidate_distill_formal",
        "pairs": pair_reports,
        "preregistered_thresholds": {
            "mean_delta_gte": GO_MEAN_DELTA,
            "median_delta_gt": 0.0,
            "min_delta_gt": GO_MIN_DELTA,
            "positive_seeds_gte": 2,
        },
        "schema_version": 1,
        "status": status,
        "threshold_checks": threshold_checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("grid_positional", type=Path, nargs="?")
    parser.add_argument("results_root_positional", type=Path, nargs="?")
    parser.add_argument("--grid", dest="grid_flag", type=Path)
    parser.add_argument("--results-root", dest="results_root_flag", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.grid_flag is not None and args.grid_positional is not None:
        parser.error("grid may be provided either positionally or with --grid")
    if args.results_root_flag is not None and args.results_root_positional is not None:
        parser.error(
            "results root may be provided either positionally or with --results-root"
        )
    grid_path = args.grid_flag or args.grid_positional
    results_root = args.results_root_flag or args.results_root_positional
    if grid_path is None or results_root is None:
        parser.error("grid and results root are required")

    grid_errors: list[str] = []
    try:
        raw_grid = json.loads(grid_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raw_grid = []
        grid_errors.append(f"cannot load grid: {exc}")
    if not isinstance(raw_grid, list):
        grid = []
        grid_errors.append("grid must contain a JSON list")
    else:
        grid = raw_grid
    manifests, load_errors = load_manifests(grid, results_root)
    load_errors.extend(grid_errors)
    report = evaluate(grid, manifests, load_errors=load_errors)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    if report["decision"] == "invalid":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
