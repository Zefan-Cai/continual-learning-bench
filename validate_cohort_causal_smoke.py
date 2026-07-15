#!/usr/bin/env python3
"""Fail-closed validator for the 2-instance Cohort causal smoke gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from assemble_cohort_causal_manifest import _verify_tape
from run_cohort_causal import (
    ROOT,
    _collector_manifest_path,
    _dataset_projection,
    _resolve,
    _trace_paths,
    load_grid,
    load_provenance,
)
from validate_cohort_causal_results import (
    EXPECTED_STATISTICAL_ADDENDUM_SHA256,
    LIMITATION,
    MECHANISM_LABEL,
    STATISTICAL_ADDENDUM_FILENAME,
    _exact_zero_value_count,
    canonical_sha256,
    masked_pair_config_sha256,
    validate_tape_nested_semantics,
)


HARD_ZERO_COUNTERS = {
    "synthetic_outcomes",
    "timed_out_outcomes",
    "fallbacks",
    "missing_outcomes",
    "hard_schema_failures",
}
EXPECTED_COUNTERS = {
    *HARD_ZERO_COUNTERS,
    "parse_retries",
    "repairs",
}


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _equal(left: Any, right: Any) -> bool:
    return canonical_sha256(left) == canonical_sha256(right)


def _terminal_action_summary(
    *,
    root: Path,
    cfg: dict[str, Any],
    cell: dict[str, Any],
    heldout_ids: list[str],
    label: str,
    errors: list[str],
) -> dict[str, Any]:
    """Bind the registered 2-ID trace and enforce deterministic qonly output."""

    summary = {
        "canonical_hash_count": 0,
        "canonical_sha256": [],
        "count": 0,
        "unique_count": 0,
        "zero_value_count": None,
    }
    expected_trace_path, _ = _trace_paths(root, cfg)
    recorded_path = cell.get("trace_path")
    if not isinstance(recorded_path, str) or not recorded_path:
        errors.append(f"{label} has no trace_path")
        return summary
    if _resolve(root, recorded_path).resolve() != expected_trace_path.resolve():
        errors.append(f"{label} trace_path is not registered")
        return summary
    try:
        trace = _load_object(expected_trace_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"{label} trace cannot be loaded: {exc}")
        return summary
    try:
        trace_digest = canonical_sha256(trace)
    except (TypeError, ValueError) as exc:
        errors.append(f"{label} trace cannot be canonicalized: {exc}")
    else:
        if cell.get("trace_sha256") != trace_digest:
            errors.append(f"{label} trace SHA-256 mismatch")
    interactions = trace.get("interactions")
    if not isinstance(interactions, list):
        errors.append(f"{label} trace interactions must be a list")
        return summary
    actions: list[Any] = []
    for interaction in interactions:
        if not isinstance(interaction, dict):
            continue
        observation = interaction.get("observation")
        if (
            not isinstance(observation, dict)
            or observation.get("instance_complete") is not True
        ):
            continue
        position = len(actions)
        query = interaction.get("query")
        if not isinstance(query, dict) or (
            query.get("instance_id"),
            query.get("instance_index"),
        ) != (
            heldout_ids[position] if position < len(heldout_ids) else None,
            position,
        ):
            errors.append(f"{label} terminal identity/order mismatch")
        response = interaction.get("response")
        action = response.get("action") if isinstance(response, dict) else None
        if not isinstance(action, dict):
            errors.append(f"{label} terminal action must be an object")
            continue
        actions.append(action)
    hashes: list[str] = []
    zero_value_counts: list[int] = []
    for position, action in enumerate(actions):
        try:
            hashes.append(canonical_sha256(action))
            zero_value_counts.append(_exact_zero_value_count(action))
        except (TypeError, ValueError) as exc:
            errors.append(
                f"{label} terminal action {position} cannot be canonicalized: {exc}"
            )
    unique_hashes = sorted(set(hashes))
    summary = {
        "canonical_hash_count": len(hashes),
        "canonical_sha256": unique_hashes,
        "count": len(actions),
        "unique_count": len(unique_hashes),
        "zero_value_count": (
            zero_value_counts[0]
            if zero_value_counts and len(set(zero_value_counts)) == 1
            else None
        ),
    }
    if len(actions) != 2:
        errors.append(f"{label} trace must contain exactly 2 terminal actions")
    elif len(hashes) != 2:
        errors.append(f"{label} trace requires 2 canonical terminal action hashes")
    elif len(unique_hashes) != 1:
        errors.append(
            f"{label} deterministic qonly contract requires terminal action "
            "canonical SHA-256 unique count=1"
        )
    return summary


def validate_smoke(
    *, root: Path, grid: dict[str, Any], provenance: dict[str, Any]
) -> dict[str, Any]:
    errors: list[str] = []
    if provenance.get("statistical_addendum_sha256") != (
        EXPECTED_STATISTICAL_ADDENDUM_SHA256
    ):
        errors.append("provenance statistical addendum SHA-256 mismatch")
    try:
        addendum_digest = hashlib.sha256(
            (root / STATISTICAL_ADDENDUM_FILENAME).read_bytes()
        ).hexdigest()
    except OSError as exc:
        errors.append(f"checked-in statistical addendum cannot be read: {exc}")
    else:
        if addendum_digest != EXPECTED_STATISTICAL_ADDENDUM_SHA256:
            errors.append("checked-in statistical addendum SHA-256 drift")
    if grid.get("kind") != "smoke":
        errors.append("grid kind must be smoke")
    collectors = grid.get("collectors", [])
    cells = grid.get("evaluation_cells", [])
    if len(collectors) != 1 or len(cells) != 2:
        errors.append("smoke grid must contain exactly 1 collector and 2 cells")
        return _report(errors, None, None, provenance)

    collector_cfg = collectors[0]
    collector = _load_object(_collector_manifest_path(root, collector_cfg))
    tape = _load_object(_resolve(root, collector_cfg["tape_path"]))
    adaptation = _dataset_projection(root, grid, "adaptation")
    heldout = _dataset_projection(root, grid, "heldout")
    validate_tape_nested_semantics(
        tape,
        run_seed=collector_cfg.get("run_seed"),
        expected_items=2,
        expected_instance_ids=adaptation["canonical_instance_ids"][:2],
        label="smoke/tape",
        errors=errors,
    )
    try:
        verification = _verify_tape(tape)
    except Exception as exc:
        errors.append(f"tape verification failed: {exc}")
        verification = None
    tape_digest = tape.get("tape_sha256")
    tape_items = tape.get("items")
    if not isinstance(tape_items, list) or len(tape_items) != 2:
        errors.append("smoke tape must contain exactly 2 items")
    if collector.get("status") != "completed":
        errors.append("collector status is not completed")
    collector_initial = collector.get("trainable_param_sha256_initial")
    collector_final = collector.get("trainable_param_sha256_final")
    if collector_initial != collector_final:
        errors.append("LR0 collector trainable parameters changed")
    if tape.get("collector_trainable_param_sha256_initial") != collector_initial:
        errors.append("tape/collector initial parameter hash mismatch")
    if tape.get("collector_trainable_param_sha256_final") != collector_final:
        errors.append("tape/collector final parameter hash mismatch")
    if tape.get("collector_lr0_verified") is not True:
        errors.append("tape does not certify LR0 collector invariance")
    if collector.get("tape_sha256") != tape_digest:
        errors.append("collector/tape digest mismatch")
    if verification is not None and collector.get("tape_verification") != verification:
        errors.append("collector tape_verification mismatch")
    if not _equal(collector.get("provenance"), provenance):
        errors.append("collector provenance mismatch")
    if not _equal(collector.get("adaptation_corpus"), adaptation):
        errors.append("collector adaptation corpus mismatch")

    by_arm = {
        cfg.get("arm"): (
            cfg,
            _load_object(_resolve(root, cfg["cell_manifest_path"])),
        )
        for cfg in cells
    }
    if set(by_arm) != {"active", "lr0"}:
        errors.append("smoke must contain one active and one lr0 cell")
        return _report(errors, tape_digest, collector_initial, provenance)

    identities: dict[str, list[tuple[Any, Any]]] = {}
    masked_hashes: dict[str, str | None] = {}
    replay_hashes: dict[str, tuple[Any, Any]] = {}
    replay_signatures: dict[str, list[list[tuple[Any, Any, Any]]]] = {}
    repair_totals: dict[str, int] = {}
    changed_operation_counts: dict[str, int] = {}
    terminal_actions: dict[str, dict[str, Any]] = {}
    for arm in ("active", "lr0"):
        cfg, cell = by_arm[arm]
        label = f"{arm} cell"
        if cell.get("status") != "completed":
            errors.append(f"{label} status is not completed")
        if cell.get("arm") != arm:
            errors.append(f"{label} arm mismatch")
        if cell.get("run_seed") != collector_cfg.get("run_seed"):
            errors.append(f"{label} run_seed mismatch")
        if cell.get("tape_sha256") != tape_digest:
            errors.append(f"{label} consumed a different tape")
        if cell.get("heldout_updates_frozen") is not True:
            errors.append(f"{label} did not hard-freeze held-out updates")
        if cell.get("adaptation_corpus_sha256") != adaptation["aggregate_sha256"]:
            errors.append(f"{label} adaptation corpus mismatch")
        if cell.get("heldout_corpus_sha256") != heldout["aggregate_sha256"]:
            errors.append(f"{label} held-out corpus mismatch")
        if not _equal(cell.get("provenance"), provenance):
            errors.append(f"{label} provenance mismatch")
        system_config = cell.get("system_config")
        if not _equal(system_config, cfg.get("system_params")):
            errors.append(f"{label} system config differs from registered grid")
        expected_masked = (
            masked_pair_config_sha256(system_config)
            if isinstance(system_config, dict)
            else None
        )
        if cell.get("masked_pair_config_sha256") != expected_masked:
            errors.append(f"{label} masked config digest mismatch")
        masked_hashes[arm] = expected_masked
        expected_task_config = {
            **cfg.get("task_params", {}),
            "runs": 1,
            "max_workers": 1,
            "run_mode": "replicate",
        }
        if not _equal(cell.get("task_config"), expected_task_config):
            errors.append(f"{label} task config differs from registered grid")
        if cell.get("task_config_sha256") != canonical_sha256(expected_task_config):
            errors.append(f"{label} task config digest mismatch")
        expected_order = heldout["canonical_instance_ids"][:2]
        if cell.get("evaluation_order_sha256") != canonical_sha256(expected_order):
            errors.append(f"{label} evaluation order digest mismatch")

        replay = cell.get("replay")
        if not isinstance(replay, dict):
            errors.append(f"{label} replay is missing")
            replay = {}
        if replay.get("status") != "complete":
            errors.append(f"{label} replay is not complete")
        if replay.get("digest_verified") is not True:
            errors.append(f"{label} replay digest was not verified")
        if replay.get("tape_sha256") != tape_digest:
            errors.append(f"{label} replay tape mismatch")
        if replay.get("item_count") != 2 or replay.get("operations_per_item") != 2:
            errors.append(f"{label} replay must cover 2 items x 2 operations")
        if replay.get("operation_count") != 4:
            errors.append(f"{label} replay operation_count must be 4")
        replay_items = replay.get("items")
        if not isinstance(replay_items, list) or len(replay_items) != 2:
            errors.append(f"{label} replay item count mismatch")
            replay_items = []
        replay_initial = replay.get("trainable_param_sha256_initial")
        replay_final = replay.get("trainable_param_sha256_final")
        for name, value in (("initial", replay_initial), ("final", replay_final)):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                errors.append(f"{label} replay {name} parameter hash is invalid")
        replay_hashes[arm] = (replay_initial, replay_final)
        if replay_initial != collector_initial:
            errors.append(f"{label} did not start from collector initial parameters")
        previous_hash = replay_initial
        arm_signatures: list[list[tuple[Any, Any, Any]]] = []
        changed_operations = 0
        for item_index, replay_item in enumerate(replay_items):
            if not isinstance(replay_item, dict):
                errors.append(f"{label} replay item {item_index} is malformed")
                continue
            if replay_item.get("trainable_param_sha256_before") != previous_hash:
                errors.append(f"{label} replay hash chain broke at item {item_index}")
            tape_item = (
                tape_items[item_index]
                if isinstance(tape_items, list) and item_index < len(tape_items)
                else {}
            )
            if replay_item.get("sequence_index") != item_index:
                errors.append(f"{label} replay item {item_index} order mismatch")
            if replay_item.get("item_sha256") != tape_item.get("item_sha256"):
                errors.append(f"{label} replay item {item_index} tape digest mismatch")
            for field in (
                "instance_id",
                "instance_index",
                "integrity",
                "sampling_provenance",
            ):
                if not _equal(replay_item.get(field), tape_item.get(field)):
                    errors.append(
                        f"{label} replay item {item_index} {field} differs from tape"
                    )
            operations = replay_item.get("operations")
            if not isinstance(operations, list) or len(operations) != 2:
                errors.append(f"{label} replay item {item_index} needs 2 operations")
                operations = []
            operation_previous = replay_item.get("trainable_param_sha256_before")
            item_signature: list[tuple[Any, Any, Any]] = []
            for operation_index, operation in enumerate(operations):
                if not isinstance(operation, dict):
                    errors.append(
                        f"{label} replay operation {item_index}/{operation_index} malformed"
                    )
                    continue
                before = operation.get("trainable_param_sha256_before")
                after = operation.get("trainable_param_sha256_after")
                if before != operation_previous:
                    errors.append(
                        f"{label} replay operation hash chain broke at "
                        f"{item_index}/{operation_index}"
                    )
                input_sha256 = operation.get("input_sha256")
                if (
                    not isinstance(input_sha256, list)
                    or not input_sha256
                    or any(
                        not isinstance(digest, str)
                        or len(digest) != 64
                        or any(
                            character not in "0123456789abcdef" for character in digest
                        )
                        for digest in input_sha256
                    )
                ):
                    errors.append(
                        f"{label} replay operation {item_index}/{operation_index} "
                        "has no input digests"
                    )
                if operation_index == 0:
                    committed = tape_item.get("committed_reward_pg", {})
                    expected_inputs = [
                        committed.get("training_example_sha256"),
                        committed.get("reward_sha256"),
                    ]
                else:
                    batches = tape_item.get("env_bon", {}).get("selected_batches", [])
                    expected_inputs = [
                        batch.get("batch_sha256")
                        for batch in batches
                        if isinstance(batch, dict)
                    ]
                if input_sha256 != expected_inputs:
                    errors.append(
                        f"{label} replay operation {item_index}/{operation_index} "
                        "input digests differ from tape"
                    )
                expected_operation = (
                    "reward_pg_terminal"
                    if operation_index == 0
                    else "bon_env_best_worst_sft"
                )
                if operation.get("operation") != expected_operation:
                    errors.append(
                        f"{label} replay operation {item_index}/{operation_index} "
                        "name/order mismatch"
                    )
                batch_count = operation.get("batch_count")
                if (
                    isinstance(batch_count, bool)
                    or not isinstance(batch_count, int)
                    or batch_count <= 0
                    or (operation_index == 0 and batch_count != 1)
                ):
                    errors.append(
                        f"{label} replay operation {item_index}/{operation_index} "
                        "batch_count mismatch"
                    )
                if operation_index == 1 and batch_count != len(expected_inputs):
                    errors.append(
                        f"{label} replay operation {item_index}/{operation_index} "
                        "batch_count differs from tape"
                    )
                item_signature.append(
                    (
                        operation.get("operation"),
                        operation.get("batch_count"),
                        tuple(input_sha256) if isinstance(input_sha256, list) else None,
                    )
                )
                if before != after:
                    changed_operations += 1
                if arm == "lr0" and (
                    before != replay_initial or after != replay_initial
                ):
                    errors.append(
                        f"LR0 replay operation changed parameters at "
                        f"{item_index}/{operation_index}"
                    )
                operation_previous = after
            if (
                operations
                and replay_item.get("trainable_param_sha256_after")
                != operation_previous
            ):
                errors.append(f"{label} replay item {item_index} final hash mismatch")
            previous_hash = replay_item.get("trainable_param_sha256_after")
            arm_signatures.append(item_signature)
        if replay_items and replay_final != previous_hash:
            errors.append(f"{label} replay final hash does not close the chain")
        replay_signatures[arm] = arm_signatures
        changed_operation_counts[arm] = changed_operations

        outcomes = cell.get("heldout_outcomes")
        if not isinstance(outcomes, list) or len(outcomes) != 2:
            errors.append(f"{label} must contain exactly 2 held-out outcomes")
            outcomes = []
        identities[arm] = [
            (row.get("instance_id"), row.get("instance_index"))
            for row in outcomes
            if isinstance(row, dict)
        ]
        counters = cell.get("integrity_counters")
        if not isinstance(counters, dict) or set(counters) != EXPECTED_COUNTERS:
            errors.append(f"{label} integrity counter schema mismatch")
            counters = {}
        elif any(counters[field] != 0 for field in HARD_ZERO_COUNTERS):
            errors.append(f"{label} hard-failure integrity counters are nonzero")
        for field in ("parse_retries", "repairs"):
            if (
                isinstance(counters.get(field), bool)
                or not isinstance(counters.get(field), int)
                or counters.get(field, -1) < 0
            ):
                errors.append(f"{label} {field} counter must be nonnegative")
        repair_totals[arm] = int(counters.get("parse_retries", 0)) + int(
            counters.get("repairs", 0)
        )
        observed_parse_retries = 0
        observed_repairs = 0
        for position, row in enumerate(outcomes):
            if not isinstance(row, dict) or row.get("instance_index") != position:
                errors.append(f"{label} held-out order mismatch at {position}")
                continue
            if row.get("instance_id") != heldout["canonical_instance_ids"][position]:
                errors.append(f"{label} held-out corpus ID mismatch at {position}")
            reward = row.get("reward")
            if (
                isinstance(reward, bool)
                or not isinstance(reward, (int, float))
                or not math.isfinite(float(reward))
            ):
                errors.append(f"{label} held-out reward is invalid at {position}")
            integrity = row.get("integrity")
            if not isinstance(integrity, dict):
                errors.append(f"{label} outcome {position} has no integrity evidence")
                continue
            if integrity.get("schema_valid") is not True or any(
                integrity.get(field) is not False
                for field in (
                    "synthetic",
                    "timed_out",
                    "fallback",
                    "missing",
                    "hard_schema_failure",
                )
            ):
                errors.append(f"{label} outcome {position} failed integrity gate")
            for field in ("parse_retries", "repairs"):
                value = integrity.get(field)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    errors.append(
                        f"{label} outcome {position} {field} must be nonnegative"
                    )
                elif field == "parse_retries":
                    observed_parse_retries += value
                else:
                    observed_repairs += value
        if counters.get("parse_retries") != observed_parse_retries:
            errors.append(f"{label} parse_retries counter mismatch")
        if counters.get("repairs") != observed_repairs:
            errors.append(f"{label} repairs counter mismatch")
        rewards = [
            float(row["reward"])
            for row in outcomes
            if isinstance(row, dict)
            and isinstance(row.get("reward"), (int, float))
            and not isinstance(row.get("reward"), bool)
            and math.isfinite(float(row["reward"]))
        ]
        if len(rewards) == 2:
            recorded_score = cell.get("score")
            expected_score = sum(rewards) / len(rewards)
            if (
                isinstance(recorded_score, bool)
                or not isinstance(recorded_score, (int, float))
                or not math.isclose(
                    float(recorded_score), expected_score, rel_tol=0.0, abs_tol=1e-12
                )
            ):
                errors.append(f"{label} score is not the held-out reward mean")
        terminal_actions[arm] = _terminal_action_summary(
            root=root,
            cfg=cfg,
            cell=cell,
            heldout_ids=heldout["canonical_instance_ids"][:2],
            label=label,
            errors=errors,
        )

    if masked_hashes.get("active") != masked_hashes.get("lr0"):
        errors.append("paired configs differ beyond the registered learning rates")
    if identities.get("active") != identities.get("lr0"):
        errors.append("paired held-out IDs/order differ")
    active_initial, active_final = replay_hashes.get("active", (None, None))
    lr0_initial, lr0_final = replay_hashes.get("lr0", (None, None))
    if lr0_initial != lr0_final:
        errors.append("LR0 replay changed trainable parameters")
    if active_initial == active_final:
        errors.append("active replay produced no trainable-parameter change")
    if active_initial != lr0_initial:
        errors.append("paired replay initial parameter hashes differ")
    if changed_operation_counts.get("active", 0) < 1:
        errors.append("active replay has no audited changed operation")
    if replay_signatures.get("active") != replay_signatures.get("lr0"):
        errors.append("paired ordered operation/input signatures differ")
    if repair_totals.get("active", 0) > repair_totals.get("lr0", 0):
        errors.append("active parse retry/repair total exceeds LR0")
    return _report(
        errors,
        tape_digest,
        collector_initial,
        provenance,
        terminal_actions=terminal_actions,
    )


def _report(
    errors: list[str],
    tape_sha256: Any,
    initial_sha256: Any,
    provenance: dict[str, Any],
    terminal_actions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "pass" if not errors else "failed",
        "decision": "pass" if not errors else "invalid",
        "mechanism_label": MECHANISM_LABEL,
        "limitation": LIMITATION,
        "tape_sha256": tape_sha256,
        "trainable_param_sha256_initial": initial_sha256,
        "provenance_sha256": canonical_sha256(provenance),
        "statistical_addendum_sha256": provenance.get("statistical_addendum_sha256"),
        "terminal_actions": terminal_actions or {},
        "errors": sorted(set(errors)),
    }


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or path.parent.is_symlink():
        raise ValueError("smoke gate parent must be a real directory")
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.tmp.publish."
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite smoke gate report: {output}")
    report = validate_smoke(
        root=args.root.resolve(),
        grid=load_grid(args.grid.resolve()),
        provenance=load_provenance(args.provenance.resolve()),
    )
    _atomic_write(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["decision"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
