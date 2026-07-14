#!/usr/bin/env python3
"""Generate the preregistered Cohort reward-aware online-ICL grids.

The grids are prospective configuration artifacts only.  They bind the
competitive-ICL preregistration and the corresponding frozen causal grid, and
they contain no measured outcome or decision field.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
PROTOCOL = "cohort_reward_aware_online_icl_v1"
SNAPSHOT_PROTOCOL = "qwen_local_icl_context_snapshot_v1"
BASE_CAUSAL_IMPLEMENTATION_COMMIT = "1caf142f6ce611da8da8691d4c336388a4c3c4b3"
PREREGISTRATION_PATH = "COHORT_MATCHED_ICL_PREREG_V1.md"
FORMAL_SEEDS = (2026071401, 2026071402, 2026071403)
SMOKE_SEED = 2026071498
NUM_INSTANCES = 20
SMOKE_INSTANCES = 2
ACTION_BUDGET = 20

GRID_PATHS = {
    True: "grid_cohort_online_icl_smoke.json",
    False: "grid_cohort_online_icl_formal.json",
}
PAIRED_CAUSAL_GRID_PATHS = {
    True: "grid_cohort_causal_smoke.json",
    False: "grid_cohort_causal_formal.json",
}

FORMAL_DATASETS: dict[str, dict[str, Any]] = {
    "adaptation": {
        "path": "data/cohort_studies/causal_adapt_2026071411",
        "schedule": "causal_adapt_2026071411",
        "seed": 2026071411,
        "corpus_sha256": (
            "31f94d0130573e347ef8276a44c8d71c7b2159b881334798a7b73cd084ae9d9a"
        ),
        "schedule_sha256": (
            "a471a2e1dca55317dda9d6858b2103f3cd51539d9cfa081836a338058eed44f5"
        ),
    },
    "heldout": {
        "path": "data/cohort_studies/causal_eval_2026071412",
        "schedule": "causal_eval_2026071412",
        "seed": 2026071412,
        "corpus_sha256": (
            "a5c56f2c408b0d909a31cbfad490a95d5facd583eb8d3cbb3190aea4c39e0b80"
        ),
        "schedule_sha256": (
            "81dde8ec92fe18af6410fbf38ff9cebd52fc298d534d9fb5107df3da5afe09ea"
        ),
    },
}

# The infrastructure smoke must not reveal any row from the internal-screen
# adaptation or held-out DGPs.  These independently generated corpora use the
# byte-identical default schedule/order but fresh patient-population seeds.
SMOKE_DATASETS: dict[str, dict[str, Any]] = {
    "adaptation": {
        "path": "data/cohort_studies/online_icl_smoke_adapt_2026071496",
        "schedule": "default",
        "seed": 2026071496,
        "corpus_sha256": (
            "43aaf213a341b96514a3f22926fb7ff976d6a6af9888b6f295a059775d000e6b"
        ),
        "schedule_sha256": (
            "9afb2b7c569b8fea700073fb8484b57b2ce86d1b94c401e0ee8e7db3e45996f7"
        ),
    },
    "heldout": {
        "path": "data/cohort_studies/online_icl_smoke_eval_2026071497",
        "schedule": "default",
        "seed": 2026071497,
        "corpus_sha256": (
            "f5adba01d7ef5d124fb46a77f3b5da8adecec12548e3ee850947f594141243cf"
        ),
        "schedule_sha256": (
            "9afb2b7c569b8fea700073fb8484b57b2ce86d1b94c401e0ee8e7db3e45996f7"
        ),
    },
}

# This is the complete frozen settings object in
# COHORT_MATCHED_ICL_PREREG_V1.md.  Do not add constructor defaults here: an
# omitted default is not part of the registered protocol.
SYSTEM_PARAMS: dict[str, Any] = {
    "model_path": "/sensei-fs/users/zcai/models/Qwen3-4B",
    "method": "icl",
    "context_policy": "full",
    "adaptation_context_policy": "full",
    "max_context_tokens": 32768,
    "head_tokens": 4096,
    "tail_tokens": 4096,
    "max_new_tokens": 8192,
    "action_max_new_tokens": 4096,
    "temperature": 0.0,
    "top_p": 1.0,
    "parse_retries": 2,
    "system_prompt": "",
    "trust_remote_code": True,
    "inject_env_reward": True,
    "ttt_steps": 0,
    "ttt_lr": 0.0,
    "reward_pg_steps": 0,
    "reward_pg_lr": 0.0,
    "history_ttt": False,
    "best_of_n": 1,
    "distill_provider": "off",
}

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_PROSPECTIVE_FORBIDDEN_KEYS = {
    "decision",
    "delta",
    "heldout_outcomes",
    "mean_reward",
    "outcomes",
    "p_value",
    "result",
    "results",
    "reward",
    "score",
}


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("grid payload is not canonical-JSON encodable") from exc


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            value[key] = item
        return value

    return json.loads(path.read_text(), object_pairs_hook=reject_duplicates)


def _exact_keys(value: Any, expected: set[str], *, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{where} schema mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _assert_sha(value: Any, *, where: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{where} must be a lowercase SHA-256 digest")
    return value


def _assert_int(value: Any, expected: int, *, where: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise ValueError(f"{where} must equal {expected}")


def _datasets(*, smoke: bool) -> dict[str, dict[str, Any]]:
    return SMOKE_DATASETS if smoke else FORMAL_DATASETS


def _task_params(
    datasets: dict[str, dict[str, Any]], dataset_key: str, count: int
) -> dict[str, Any]:
    dataset = datasets[dataset_key]
    return {
        "schedule": dataset["schedule"],
        "dataset_path": dataset["path"],
        "num_instances": count,
        "action_budget": ACTION_BUDGET,
        "seed": dataset["seed"],
        "repeat_instructions": True,
    }


def _execution_contract() -> dict[str, Any]:
    return {
        "phase_order": [
            "verify_protocol_seal",
            "revalidate_paired_causal_gate",
            "online_adaptation",
            "seal_context",
            "heldout_evaluation",
        ],
        "causal_prerequisite": {
            "bind_exact_gate_and_provenance_sha256": True,
            "recompute_gate_from_registered_raw_artifacts": True,
            "require_empty_errors_and_pass": True,
            "shared_environment_model_tokenizer_required": True,
        },
        "protocol_seal": {
            "atomic_no_overwrite_required": True,
            "binds_both_smoke_and_formal_grid_digests": True,
            "binds_exact_runtime_provenance": True,
            "created_before_first_icl_outcome": True,
            "same_artifact_and_source_commit_for_smoke_and_formal": True,
        },
        "online_adaptation": {
            "consume_own_trajectory_only": True,
            "candidate_sampler_forbidden": True,
            "extra_model_calls_per_action": 0,
            "terminal_reward_visible_only_after_report_commit_and_score": True,
            "terminal_reward_template": (
                "ENV_REWARD (score of your previous answer, higher is better): "
                "{reward:.4f}"
            ),
        },
        "seal_context": {
            "canonical_json": {
                "allow_nan": False,
                "encoding": "utf-8",
                "separators": [",", ":"],
                "sort_keys": True,
            },
            "one_way_feedback_gate_required": True,
            "quiescent_state_required": True,
            "snapshot_digest_independently_recomputed": True,
            "snapshot_state_bound_to_adaptation_trace": True,
            "message_and_token_inventory_independently_recomputed": True,
            "snapshot_protocol": SNAPSHOT_PROTOCOL,
            "write_snapshot_and_inventory_before_heldout": True,
        },
        "heldout_evaluation": {
            "allow_within_condition_public_tool_context": True,
            "forbidden_sensitive_fields": [
                "cohort_gt",
                "env_feedback_reward",
                "ref_survival",
                "terminal_content",
                "terminal_reward",
            ],
            "initial_snapshot_digest_identical_for_every_condition": True,
            "restore_snapshot_after_every_completed_condition_including_last": True,
            "terminal_query_feedback_ingestion_forbidden": True,
            "terminal_observe_content_ingestion_forbidden": True,
        },
        "integrity": {
            "adapter_creation_forbidden": True,
            "candidate_sample_count_required": 0,
            "distiller_creation_forbidden": True,
            "immutable_artifacts_atomic_no_overwrite": True,
            "model_state_hash_unchanged_required": True,
            "model_state_hash_covers_parameters_and_persistent_buffers": True,
            "optimizer_creation_forbidden": True,
            "parameter_update_count_required": 0,
            "real_unique_non_synthetic_non_timeout_conditions_required": True,
            "smoke_dgp_overlap_with_internal_screen_forbidden": True,
            "smoke_user_visible_efficacy_fields_forbidden": True,
            "validated_report_binds_every_raw_artifact_sha256": True,
        },
        "compute_accounting": {
            "metrics": [
                "generation_calls",
                "input_tokens",
                "output_tokens",
                "candidate_samples",
                "optimizer_forward_calls",
                "optimizer_backward_calls",
                "optimizer_steps",
                "wall_seconds",
                "gpu_seconds",
                "peak_allocated_gpu_memory",
                "retries",
                "repairs",
                "failures",
            ],
            "phases": [
                "model_initialization",
                "online_adaptation",
                "snapshot_seal",
                "heldout_evaluation",
            ],
        },
    }


def _artifact_paths(cfg_id: str) -> dict[str, str]:
    prefix = f"artifacts/cohort_online_icl/{cfg_id}"
    return {
        "adaptation_trace_path": f"{prefix}.adaptation.trace.json",
        "cell_manifest_path": f"{prefix}.manifest.json",
        "context_inventory_path": f"{prefix}.context_inventory.json",
        "heldout_trace_path": f"{prefix}.heldout.trace.json",
        "restoration_audit_path": f"{prefix}.restoration_audit.json",
        "snapshot_path": f"{prefix}.sealed_snapshot.json",
    }


def _cell(
    *,
    seed: int,
    count: int,
    label: str,
    datasets: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    cfg_id = f"cohort_online_icl_{label}_seed{seed}_n{count}"
    adaptation = _task_params(datasets, "adaptation", count)
    heldout = _task_params(datasets, "heldout", count)
    contract = _execution_contract()
    cell: dict[str, Any] = {
        "cfg_id": cfg_id,
        "mode": "online_icl_eval",
        "algorithm": PROTOCOL,
        "arm": "online_icl",
        "task_name": "cohort_studies",
        "system_name": "qwen_local",
        "run_seed": seed,
        "expected_num_instances": count,
        "adaptation_task_params": adaptation,
        "adaptation_task_params_sha256": _canonical_sha(adaptation),
        "heldout_task_params": heldout,
        "heldout_task_params_sha256": _canonical_sha(heldout),
        "system_params": deepcopy(SYSTEM_PARAMS),
        "system_params_sha256": _canonical_sha(SYSTEM_PARAMS),
        "execution_contract": contract,
        "execution_contract_sha256": _canonical_sha(contract),
        **_artifact_paths(cfg_id),
    }
    cell["cell_config_sha256"] = _canonical_sha(cell)
    return cell


def _binding(path: str) -> dict[str, str]:
    absolute = ROOT / path
    if not absolute.is_file():
        raise FileNotFoundError(f"required registered artifact is missing: {absolute}")
    return {"path": path, "sha256": _file_sha(absolute)}


def _payload_without_grid_sha(grid: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(grid)
    payload.pop("grid_sha256", None)
    return payload


def make_grid(*, smoke: bool) -> dict[str, Any]:
    seeds = (SMOKE_SEED,) if smoke else FORMAL_SEEDS
    count = SMOKE_INSTANCES if smoke else NUM_INSTANCES
    label = "smoke" if smoke else "formal"
    datasets = _datasets(smoke=smoke)
    grid: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "protocol": PROTOCOL,
        "base_causal_implementation_commit": BASE_CAUSAL_IMPLEMENTATION_COMMIT,
        "preregistration": _binding(PREREGISTRATION_PATH),
        "paired_causal_grid": _binding(PAIRED_CAUSAL_GRID_PATHS[smoke]),
        "kind": label,
        "decision_scope": "infrastructure_smoke" if smoke else "internal_screen",
        "publication_grade": False,
        "datasets": deepcopy(datasets),
        "cells": [
            _cell(seed=seed, count=count, label=label, datasets=datasets)
            for seed in seeds
        ],
    }
    grid["grid_sha256"] = _canonical_sha(grid)
    validate(grid, smoke=smoke)
    return grid


def _validate_dataset_manifest(dataset: dict[str, Any], *, key: str) -> None:
    manifest_path = ROOT / dataset["path"] / "manifest.json"
    manifest = _read_json(manifest_path)
    expected = {
        "schedule_id": dataset["schedule"],
        "seed": dataset["seed"],
        "corpus_sha256": dataset["corpus_sha256"],
        "schedule_sha256": dataset["schedule_sha256"],
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise ValueError(f"{key} dataset manifest {field} drift")
    if manifest.get("n_instances") != NUM_INSTANCES:
        raise ValueError(f"{key} dataset must contain {NUM_INSTANCES} instances")


def _validate_causal_pairing(grid: dict[str, Any], *, smoke: bool) -> None:
    binding = grid["paired_causal_grid"]
    causal_path = ROOT / binding["path"]
    if binding != _binding(PAIRED_CAUSAL_GRID_PATHS[smoke]):
        raise ValueError("paired causal grid binding drift")
    causal = _read_json(causal_path)
    if causal.get("datasets") != FORMAL_DATASETS:
        raise ValueError("paired causal grid datasets drifted from the causal protocol")
    if smoke:
        if grid["datasets"] != SMOKE_DATASETS:
            raise ValueError("online-ICL smoke datasets drifted")
        for role in ("adaptation", "heldout"):
            smoke_dataset = grid["datasets"][role]
            causal_dataset = causal["datasets"][role]
            if any(
                smoke_dataset[field] == causal_dataset[field]
                for field in ("path", "seed", "corpus_sha256")
            ):
                raise ValueError(
                    f"online-ICL smoke {role} DGP overlaps the internal screen"
                )
    elif grid["datasets"] != causal.get("datasets"):
        raise ValueError("formal online-ICL datasets differ from paired causal grid")

    seeds = (SMOKE_SEED,) if smoke else FORMAL_SEEDS
    count = SMOKE_INSTANCES if smoke else NUM_INSTANCES
    collectors = causal.get("collectors")
    evaluation_cells = causal.get("evaluation_cells")
    if not isinstance(collectors, list) or not isinstance(evaluation_cells, list):
        raise ValueError("paired causal grid has an invalid prospective schema")
    if [row.get("run_seed") for row in collectors] != list(seeds):
        raise ValueError("paired causal collector seeds drift")
    for seed in seeds:
        collector = next(row for row in collectors if row.get("run_seed") == seed)
        paired = [row for row in evaluation_cells if row.get("run_seed") == seed]
        if len(paired) != 2 or {row.get("arm") for row in paired} != {"active", "lr0"}:
            raise ValueError("paired causal active/LR0 cells drift")
        if not smoke:
            if collector.get("task_params") != _task_params(
                FORMAL_DATASETS, "adaptation", count
            ):
                raise ValueError("adaptation task differs from paired causal grid")
            if any(
                row.get("task_params")
                != _task_params(FORMAL_DATASETS, "heldout", count)
                for row in paired
            ):
                raise ValueError("held-out task differs from paired causal grid")


def _assert_prospective(value: Any, *, where: str = "grid") -> None:
    if isinstance(value, dict):
        forbidden = _PROSPECTIVE_FORBIDDEN_KEYS.intersection(value)
        if forbidden:
            raise ValueError(
                f"{where} contains forbidden outcome keys: {sorted(forbidden)}"
            )
        for key, item in value.items():
            _assert_prospective(item, where=f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_prospective(item, where=f"{where}[{index}]")


def validate(grid: dict[str, Any], *, smoke: bool) -> None:
    _exact_keys(
        grid,
        {
            "base_causal_implementation_commit",
            "cells",
            "datasets",
            "decision_scope",
            "grid_sha256",
            "kind",
            "paired_causal_grid",
            "preregistration",
            "protocol",
            "publication_grade",
            "schema_version",
        },
        where="grid",
    )
    _assert_prospective(grid)
    _assert_int(grid["schema_version"], SCHEMA_VERSION, where="schema_version")
    if grid["protocol"] != PROTOCOL:
        raise ValueError("protocol drift")
    if grid["base_causal_implementation_commit"] != BASE_CAUSAL_IMPLEMENTATION_COMMIT:
        raise ValueError("base causal implementation commit drift")
    if grid["kind"] != ("smoke" if smoke else "formal"):
        raise ValueError("grid kind drift")
    expected_scope = "infrastructure_smoke" if smoke else "internal_screen"
    if (
        grid["decision_scope"] != expected_scope
        or grid["publication_grade"] is not False
    ):
        raise ValueError("decision scope drift")

    for where in ("preregistration", "paired_causal_grid"):
        _exact_keys(grid[where], {"path", "sha256"}, where=where)
        _assert_sha(grid[where]["sha256"], where=f"{where}.sha256")
    if grid["preregistration"] != _binding(PREREGISTRATION_PATH):
        raise ValueError("preregistration binding drift")

    expected_datasets = _datasets(smoke=smoke)
    if grid["datasets"] != expected_datasets:
        raise ValueError("registered dataset contract drift")
    if (
        expected_datasets["adaptation"]["corpus_sha256"]
        == expected_datasets["heldout"]["corpus_sha256"]
    ):
        raise ValueError("adaptation and held-out corpora must differ")
    for key, dataset in grid["datasets"].items():
        _exact_keys(
            dataset,
            {"corpus_sha256", "path", "schedule", "schedule_sha256", "seed"},
            where=f"datasets.{key}",
        )
        _assert_sha(dataset["corpus_sha256"], where=f"datasets.{key}.corpus_sha256")
        _assert_sha(dataset["schedule_sha256"], where=f"datasets.{key}.schedule_sha256")
        _validate_dataset_manifest(dataset, key=key)
    _validate_causal_pairing(grid, smoke=smoke)

    seeds = (SMOKE_SEED,) if smoke else FORMAL_SEEDS
    count = SMOKE_INSTANCES if smoke else NUM_INSTANCES
    cells = grid["cells"]
    if not isinstance(cells, list) or len(cells) != len(seeds):
        raise ValueError("one online-ICL cell per registered seed is required")
    if [cell.get("run_seed") for cell in cells if isinstance(cell, dict)] != list(
        seeds
    ):
        raise ValueError("cell seed/order drift")
    cfg_ids: list[str] = []
    for seed, cell in zip(seeds, cells, strict=True):
        _exact_keys(
            cell,
            {
                "adaptation_task_params",
                "adaptation_task_params_sha256",
                "algorithm",
                "arm",
                "adaptation_trace_path",
                "cell_config_sha256",
                "cell_manifest_path",
                "cfg_id",
                "context_inventory_path",
                "execution_contract",
                "execution_contract_sha256",
                "expected_num_instances",
                "heldout_trace_path",
                "heldout_task_params",
                "heldout_task_params_sha256",
                "mode",
                "restoration_audit_path",
                "run_seed",
                "snapshot_path",
                "system_name",
                "system_params",
                "system_params_sha256",
                "task_name",
            },
            where=f"cell[{seed}]",
        )
        expected_cfg_id = (
            f"cohort_online_icl_{'smoke' if smoke else 'formal'}_seed{seed}_n{count}"
        )
        if cell["cfg_id"] != expected_cfg_id:
            raise ValueError("cfg_id drift")
        cfg_ids.append(cell["cfg_id"])
        if (
            cell["mode"] != "online_icl_eval"
            or cell["algorithm"] != PROTOCOL
            or cell["arm"] != "online_icl"
            or cell["task_name"] != "cohort_studies"
            or cell["system_name"] != "qwen_local"
        ):
            raise ValueError("online-ICL cell identity drift")
        _assert_int(cell["run_seed"], seed, where=f"cell[{seed}].run_seed")
        _assert_int(
            cell["expected_num_instances"],
            count,
            where=f"cell[{seed}].expected_num_instances",
        )
        if cell["adaptation_task_params"] != _task_params(
            expected_datasets, "adaptation", count
        ):
            raise ValueError("adaptation task contract drift")
        if cell["heldout_task_params"] != _task_params(
            expected_datasets, "heldout", count
        ):
            raise ValueError("held-out task contract drift")
        if cell["system_params"] != SYSTEM_PARAMS:
            raise ValueError("frozen online-ICL system settings drift")
        if cell["execution_contract"] != _execution_contract():
            raise ValueError("online adaptation/seal/held-out contract drift")
        if any(
            cell[key] != value for key, value in _artifact_paths(cell["cfg_id"]).items()
        ):
            raise ValueError("prospective artifact path drift")
        hashed_fields = {
            "adaptation_task_params_sha256": cell["adaptation_task_params"],
            "heldout_task_params_sha256": cell["heldout_task_params"],
            "system_params_sha256": cell["system_params"],
            "execution_contract_sha256": cell["execution_contract"],
        }
        for field, payload in hashed_fields.items():
            _assert_sha(cell[field], where=f"cell[{seed}].{field}")
            if cell[field] != _canonical_sha(payload):
                raise ValueError(f"cell[{seed}] {field} drift")
        cell_payload = deepcopy(cell)
        cell_sha = cell_payload.pop("cell_config_sha256")
        _assert_sha(cell_sha, where=f"cell[{seed}].cell_config_sha256")
        if cell_sha != _canonical_sha(cell_payload):
            raise ValueError("cell config digest drift")
    if len(cfg_ids) != len(set(cfg_ids)):
        raise ValueError("cfg_id values must be unique")

    grid_sha = _assert_sha(grid["grid_sha256"], where="grid_sha256")
    if grid_sha != _canonical_sha(_payload_without_grid_sha(grid)):
        raise ValueError("grid canonical digest drift")


def _json_text(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    outputs = {
        args.output_dir / GRID_PATHS[True]: make_grid(smoke=True),
        args.output_dir / GRID_PATHS[False]: make_grid(smoke=False),
    }
    for path, payload in outputs.items():
        expected = _json_text(payload)
        if args.check:
            if not path.is_file() or path.read_text() != expected:
                raise SystemExit(f"registered grid is stale: {path}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected)
            print(f"wrote {path}")
    if args.check:
        print("COHORT_ONLINE_ICL_GRID_CHECK_OK smoke=1 formal=3")


if __name__ == "__main__":
    main()
