#!/usr/bin/env python3
"""Cross-manifest order and frozen-control validator for the formal wave."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def real_outcomes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("result", {}).get("instance_outcomes", [])
    return [
        row
        for row in rows
        if isinstance(row, dict)
        and not str(row.get("instance_id", "")).startswith("__failed")
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifests", type=Path, nargs="+")
    parser.add_argument("--require-formal-counts", action="store_true")
    args = parser.parse_args()

    payloads = [json.loads(path.read_text()) for path in args.manifests]
    records: list[
        tuple[
            Path,
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            list[dict[str, Any]],
        ]
    ] = []
    for path, payload in zip(args.manifests, payloads):
        system_params = payload.get("system", {}).get("params", {})
        task_params = payload.get("task", {}).get("params", {})
        if task_params.get("seed") != 42 or task_params.get("run_index") != 1:
            raise SystemExit(f"{path}: task order is not the registered seed=42/run_index=1")
        records.append(
            (path, payload, system_params, task_params, real_outcomes(payload))
        )

    orders = [
        tuple(row.get("instance_id") for row in outcomes)
        for _, _, _, _, outcomes in records
    ]
    if not orders or any(order != orders[0] for order in orders[1:]):
        raise SystemExit("instance order mismatch across arms")

    frozen = [
        record
        for record in records
        if record[2].get("freeze_parameter_updates") is True
    ]
    if len(frozen) >= 2:
        reference = frozen[0][4]
        reference_score = frozen[0][1].get("result", {}).get("score")
        for path, payload, _, _, outcomes in frozen[1:]:
            if outcomes != reference:
                raise SystemExit(f"{path}: frozen instance_outcomes are not bit-exact")
            if payload.get("result", {}).get("score") != reference_score:
                raise SystemExit(f"{path}: frozen score is not bit-exact")

    if args.require_formal_counts:
        full_active = sum(
            sp.get("context_policy") == "full"
            and sp.get("freeze_parameter_updates") is not True
            for _, _, sp, _, _ in records
        )
        full_frozen = sum(
            sp.get("context_policy") == "full"
            and sp.get("freeze_parameter_updates") is True
            for _, _, sp, _, _ in records
        )
        qonly_active = sum(
            sp.get("context_policy") == "question_only"
            and sp.get("freeze_parameter_updates") is not True
            for _, _, sp, _, _ in records
        )
        if (full_active, full_frozen, qonly_active) != (5, 2, 3):
            raise SystemExit(
                "formal arm counts mismatch: "
                f"full_active={full_active} full_frozen={full_frozen} "
                f"qonly_active={qonly_active}"
            )
        if len(frozen) != 2:
            raise SystemExit("formal wave requires exactly two frozen controls")

    print(f"GROUP_PG_PAIRING_OK manifests={len(records)} frozen={len(frozen)}")


if __name__ == "__main__":
    main()
