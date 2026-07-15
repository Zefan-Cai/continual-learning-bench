from __future__ import annotations

import json
import hashlib
import shutil
import statistics
from pathlib import Path

import pytest

import run_cohort_causal_cell_sealed as sealed
from assemble_cohort_causal_manifest import _verify_tape
from run_cohort_causal import (
    PREREGISTERED_PARENT_COMMIT,
    _collector_manifest_path,
    _dataset_projection,
    _trace_paths,
)
from validate_cohort_causal_results import (
    EXPECTED_STATISTICAL_ADDENDUM_SHA256,
    EXPECTED_SYSTEM_CONFIG,
    LIMITATION,
    MECHANISM_LABEL,
    PROTOCOL,
    STATISTICAL_ADDENDUM_FILENAME,
    canonical_sha256,
    masked_pair_config_sha256,
    tape_item_sha256,
    tape_sha256,
)
from validate_cohort_causal_smoke import validate_smoke


REPO_ROOT = Path(__file__).resolve().parents[1]
HASH_A = "a" * 64
HASH_B = "b" * 64


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def _provenance(grid):
    return {
        "source_commit": "1" * 40,
        "preregistered_parent_commit": PREREGISTERED_PARENT_COMMIT,
        "environment_lock_sha256": "3" * 64,
        "model_sha256": "4" * 64,
        "tokenizer_sha256": "5" * 64,
        "evaluation_code_sha256": "6" * 64,
        "statistical_addendum_sha256": EXPECTED_STATISTICAL_ADDENDUM_SHA256,
        "model_path": grid["collectors"][0]["system_params"]["model_path"],
        "adapter_init_seed": grid["adapter_init_seed"],
    }


def _integrity():
    return {
        "schema_valid": True,
        "synthetic": False,
        "timed_out": False,
        "fallback": False,
        "missing": False,
        "hard_schema_failure": False,
        "parse_retries": 0,
        "repairs": 0,
    }


def _install_valid_smoke(tmp_path: Path):
    grid = json.loads((REPO_ROOT / "grid_cohort_causal_smoke.json").read_text())
    shutil.copy2(
        REPO_ROOT / STATISTICAL_ADDENDUM_FILENAME,
        tmp_path / STATISTICAL_ADDENDUM_FILENAME,
    )
    for role in ("adaptation", "heldout"):
        relative = Path(grid["datasets"][role]["path"])
        shutil.copytree(REPO_ROOT / relative, tmp_path / relative)
        schedule = grid["datasets"][role]["schedule"] + ".json"
        source = REPO_ROOT / "src/tasks/cohort_studies/schedules" / schedule
        target = tmp_path / "src/tasks/cohort_studies/schedules" / schedule
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    adaptation = _dataset_projection(tmp_path, grid, "adaptation")
    heldout = _dataset_projection(tmp_path, grid, "heldout")
    provenance = _provenance(grid)
    collector_cfg = grid["collectors"][0]
    instance_ids = heldout["canonical_instance_ids"][:2]
    tape_items = []
    for index in range(2):
        committed_ids = [101, index, 201, 202]
        committed_payload = {"ids": committed_ids, "prompt_tokens": 2}
        reward = 0.2 + index / 100
        candidates = []
        for candidate_index in range(8):
            candidate = f"candidate-{index}-{candidate_index}"
            candidate_reward = candidate_index / 10
            candidates.append(
                {
                    "candidate": candidate,
                    "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
                    "reward": candidate_reward,
                    "reward_sha256": canonical_sha256(float(candidate_reward)),
                }
            )
        selected_batches = []
        for role, candidate_index, signed_weight in (
            ("positive", 7, 1.0),
            ("negative", 0, -0.5),
        ):
            batch = {
                "role": role,
                "candidate_index": candidate_index,
                "ids": [301, candidate_index, 401, 402],
                "prompt_tokens": 2,
                "signed_weight": signed_weight,
            }
            batch["batch_sha256"] = canonical_sha256(batch)
            selected_batches.append(batch)
        sampling = {
            "registered_run_seed": collector_cfg["run_seed"],
            "interaction_step": 21 * (index + 1),
            "requested_best_of_n": 8,
            "initial_sample_attempts": 7,
            "generation_failures": 0,
            "parse_failures": 0,
            "duplicates": 0,
            "valid_unique": 8,
            "candidate_count": 8,
            "sampling_prompt_sha256": hashlib.sha256(
                f"sampling-{index}".encode()
            ).hexdigest(),
            "sampling_rng_binding": (
                "ambient_runner_rng; grpo_run_seed registered but not locally forked"
            ),
        }
        sampling["provenance_sha256"] = canonical_sha256(sampling)
        prompt = f"prompt-{index}"
        item = {
            "schema_version": 1,
            "sequence_index": index,
            "instance_id": adaptation["canonical_instance_ids"][index],
            "instance_index": index,
            "integrity": _integrity(),
            "sampling_provenance": sampling,
            "committed_reward_pg": {
                **committed_payload,
                "prompt_token_ids_sha256": canonical_sha256(committed_ids[:2]),
                "target_token_ids_sha256": canonical_sha256(committed_ids[2:]),
                "training_example_sha256": canonical_sha256(committed_payload),
                "reward": reward,
                "reward_sha256": canonical_sha256(float(reward)),
            },
            "env_bon": {
                "prompt": prompt,
                "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                "candidates": candidates,
                "candidate_order_sha256": canonical_sha256(candidates),
                "selected_batches": selected_batches,
            },
        }
        item["item_sha256"] = tape_item_sha256(item)
        tape_items.append(item)
    contract_keys = (
        "adapter_init_seed", "adaptation_context_policy", "best_of_n",
        "bon_critic", "bon_env_reward", "context_policy", "distill_contrastive",
        "history_ttt", "method", "model_path", "num_virtual_tokens", "peft_method",
        "reward_negative_weight", "reward_pg_steps", "reward_positive_weight",
        "reward_update_rule", "ttt_max_tokens", "ttt_steps",
    )
    tape = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "mechanism_label": f"{MECHANISM_LABEL}; {LIMITATION}",
        "learning_rate_ablation_fields": ["ttt_lr", "reward_pg_lr"],
        "collector_trainable_param_sha256_initial": HASH_A,
        "collector_trainable_param_sha256_final": HASH_A,
        "collector_lr0_verified": True,
        "update_contract": {
            key: EXPECTED_SYSTEM_CONFIG[key] for key in contract_keys
        },
        "items": tape_items,
    }
    tape["tape_sha256"] = tape_sha256(tape)
    verification = _verify_tape(tape)
    _write(tmp_path / collector_cfg["tape_path"], tape)
    _write(
        _collector_manifest_path(tmp_path, collector_cfg),
        {
            "status": "completed",
            "run_seed": collector_cfg["run_seed"],
            "trainable_param_sha256_initial": HASH_A,
            "trainable_param_sha256_final": HASH_A,
            "tape_sha256": tape["tape_sha256"],
            "tape_verification": verification,
            "provenance": provenance,
            "adaptation_corpus": adaptation,
        },
    )
    cell_paths = {}
    for cfg in grid["evaluation_cells"]:
        arm = cfg["arm"]
        final_hash = HASH_B if arm == "active" else HASH_A
        system_config = cfg["system_params"]
        replay_items = []
        previous_hash = HASH_A
        for item_index in range(2):
            first_after = HASH_B if arm == "active" else HASH_A
            if arm == "active" and item_index > 0:
                first_after = HASH_B
            operations = [
                {
                    "operation": "reward_pg_terminal",
                    "batch_count": 1,
                    "input_sha256": [
                        tape_items[item_index]["committed_reward_pg"][
                            "training_example_sha256"
                        ],
                        tape_items[item_index]["committed_reward_pg"]["reward_sha256"],
                    ],
                    "trainable_param_sha256_before": previous_hash,
                    "trainable_param_sha256_after": first_after,
                },
                {
                    "operation": "bon_env_best_worst_sft",
                    "batch_count": 2,
                    "input_sha256": [
                        batch["batch_sha256"]
                        for batch in tape_items[item_index]["env_bon"][
                            "selected_batches"
                        ]
                    ],
                    "trainable_param_sha256_before": first_after,
                    "trainable_param_sha256_after": first_after,
                },
            ]
            replay_items.append(
                {
                    "sequence_index": item_index,
                    "instance_id": tape_items[item_index]["instance_id"],
                    "instance_index": item_index,
                    "integrity": tape_items[item_index]["integrity"],
                    "sampling_provenance": tape_items[item_index][
                        "sampling_provenance"
                    ],
                    "item_sha256": tape_items[item_index]["item_sha256"],
                    "trainable_param_sha256_before": previous_hash,
                    "trainable_param_sha256_after": first_after,
                    "operations": operations,
                }
            )
            previous_hash = first_after
        trace_path, _ = _trace_paths(tmp_path, cfg)
        trace = {
            "interactions": [
                {
                    "observation": {"instance_complete": True},
                    "query": {
                        "instance_id": instance_id,
                        "instance_index": index,
                    },
                    "response": {"action": {"fixed_report": arm}},
                }
                for index, instance_id in enumerate(instance_ids)
            ]
        }
        _write(trace_path, trace)
        cell = {
            "status": "completed",
            "arm": arm,
            "run_seed": cfg["run_seed"],
            "heldout_updates_frozen": True,
            "tape_sha256": tape["tape_sha256"],
            "adaptation_corpus_sha256": adaptation["aggregate_sha256"],
            "heldout_corpus_sha256": heldout["aggregate_sha256"],
            "provenance": provenance,
            "system_config": system_config,
            "system_config_sha256": canonical_sha256(system_config),
            "masked_pair_config_sha256": masked_pair_config_sha256(system_config),
            "task_config": {
                **cfg["task_params"],
                "runs": 1,
                "max_workers": 1,
                "run_mode": "replicate",
            },
            "task_config_sha256": canonical_sha256(
                {
                    **cfg["task_params"],
                    "runs": 1,
                    "max_workers": 1,
                    "run_mode": "replicate",
                }
            ),
            "evaluation_order_sha256": canonical_sha256(instance_ids),
            "replay": {
                "status": "complete",
                "digest_verified": True,
                "tape_sha256": tape["tape_sha256"],
                "item_count": 2,
                "operations_per_item": 2,
                "operation_count": 4,
                "trainable_param_sha256_initial": HASH_A,
                "trainable_param_sha256_final": final_hash,
                "items": replay_items,
            },
            "heldout_outcomes": [
                {
                    "instance_id": instance_id,
                    "instance_index": index,
                    "reward": 0.1 + index,
                    "integrity": _integrity(),
                }
                for index, instance_id in enumerate(instance_ids)
            ],
            "integrity_counters": {
                "synthetic_outcomes": 0,
                "timed_out_outcomes": 0,
                "fallbacks": 0,
                "missing_outcomes": 0,
                "hard_schema_failures": 0,
                "parse_retries": 0,
                "repairs": 0,
            },
            "score": statistics.mean((0.1, 1.1)),
            "trace_path": str(trace_path),
            "trace_sha256": canonical_sha256(trace),
        }
        path = tmp_path / cfg["cell_manifest_path"]
        _write(path, cell)
        cell_paths[arm] = path

    recipient_path = tmp_path / "COHORT_CAUSAL_LOG_RECIPIENT_V1.txt"
    shutil.copy2(REPO_ROOT / recipient_path.name, recipient_path)
    runtime_contract_path = tmp_path / "COHORT_CAUSAL_SEALED_LOG_RUNTIME_V1.json"
    shutil.copy2(REPO_ROOT / runtime_contract_path.name, runtime_contract_path)
    runtime_contract = json.loads(runtime_contract_path.read_text())
    runtime_contract_sha256 = hashlib.sha256(
        runtime_contract_path.read_bytes()
    ).hexdigest()
    recipient_sha256 = hashlib.sha256(recipient_path.read_bytes()).hexdigest()
    for section in ("collectors", "evaluation_cells"):
        for index, cfg in enumerate(grid[section]):
            cfg_id = cfg["cfg_id"]
            sealed_root = (
                tmp_path
                / "artifacts"
                / "cohort_causal"
                / "sealed_logs"
                / "smoke"
            )
            ciphertext = f"age-ciphertext-placeholder-{cfg_id}".encode()
            start = {
                "age_binary_sha256": runtime_contract["age_binary_sha256"],
                "age_version": runtime_contract["age_version"],
                "boot_id": "smoke-test-boot",
                "cfg_id": cfg_id,
                "event": "start",
                "experiment_kind": "smoke",
                "phase": section,
                "published_at_utc": "2026-07-14T00:00:00Z",
                "private_identity_absence_verified": True,
                "recipient_sha256": recipient_sha256,
                "runner_pid": 1000 + index,
                "runner_start_time_ticks": 2000 + index,
                "schema_version": 1,
                "sealer_pid": 3000 + index,
                "sealer_start_time_ticks": 4000 + index,
                "supervisor_pid": 5000 + index,
                "supervisor_start_time_ticks": 6000 + index,
                "runtime_contract_sha256": runtime_contract_sha256,
                "runtime_home_sha256": hashlib.sha256(
                    f"runtime-home-{cfg_id}".encode()
                ).hexdigest(),
            }
            start_payload = sealed._canonical_bytes(start)
            receipt = {
                "age_binary_sha256": start["age_binary_sha256"],
                "age_version": start["age_version"],
                "boot_id": start["boot_id"],
                "cfg_id": cfg_id,
                "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                "ciphertext_size_bytes": len(ciphertext),
                "event": "finish",
                "experiment_kind": "smoke",
                "phase": section,
                "published_at_utc": "2026-07-14T00:01:00Z",
                "private_identity_absence_verified": True,
                "recipient_sha256": recipient_sha256,
                "runner_exit_code": 0,
                "runner_pid": start["runner_pid"],
                "runner_start_time_ticks": start["runner_start_time_ticks"],
                "schema_version": 1,
                "sealer_exit_code": 0,
                "sealer_pid": start["sealer_pid"],
                "sealer_start_time_ticks": start["sealer_start_time_ticks"],
                "start_receipt_sha256": hashlib.sha256(start_payload).hexdigest(),
                "supervisor_pid": start["supervisor_pid"],
                "supervisor_start_time_ticks": start[
                    "supervisor_start_time_ticks"
                ],
                "runtime_contract_sha256": start["runtime_contract_sha256"],
                "runtime_home_sha256": start["runtime_home_sha256"],
            }
            _write_bytes = {
                sealed_root / f"{cfg_id}.stdout_stderr.age": ciphertext,
                sealed_root / f"{cfg_id}.start.json": start_payload,
                sealed_root / f"{cfg_id}.receipt.json": sealed._canonical_bytes(receipt),
            }
            for output_path, payload in _write_bytes.items():
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(payload)
    return grid, provenance, cell_paths


def test_smoke_gate_accepts_only_nonzero_paired_weight_update(tmp_path):
    grid, provenance, _paths = _install_valid_smoke(tmp_path)
    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)
    assert report["decision"] == "pass"
    assert report["errors"] == []
    assert report["provenance_sha256"] == canonical_sha256(provenance)
    assert (
        report["statistical_addendum_sha256"]
        == EXPECTED_STATISTICAL_ADDENDUM_SHA256
    )
    for arm in ("active", "lr0"):
        assert report["terminal_actions"][arm]["count"] == 2
        assert report["terminal_actions"][arm]["unique_count"] == 1
        assert len(report["terminal_actions"][arm]["canonical_sha256"]) == 1


def test_smoke_rejects_second_same_arm_terminal_action(tmp_path):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    active = json.loads(paths["active"].read_text())
    trace_path = Path(active["trace_path"])
    trace = json.loads(trace_path.read_text())
    trace["interactions"][1]["response"]["action"] = {"fixed_report": "drift"}
    _write(trace_path, trace)
    active["trace_sha256"] = canonical_sha256(trace)
    _write(paths["active"], active)

    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)

    assert report["decision"] == "invalid"
    assert report["terminal_actions"]["active"]["unique_count"] == 2
    assert any(
        "terminal action canonical SHA-256 unique count=1" in error
        for error in report["errors"]
    )


def test_smoke_reports_fixed_action_zero_fields_without_rejecting(tmp_path):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    for arm in ("active", "lr0"):
        cell = json.loads(paths[arm].read_text())
        trace_path = Path(cell["trace_path"])
        trace = json.loads(trace_path.read_text())
        for interaction in trace["interactions"]:
            interaction["response"]["action"] = {"fixed_report": 0.0}
        _write(trace_path, trace)
        cell["trace_sha256"] = canonical_sha256(trace)
        _write(paths[arm], cell)

    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)

    assert report["decision"] == "pass"
    assert report["errors"] == []
    assert report["terminal_actions"]["active"]["zero_value_count"] == 1
    assert report["terminal_actions"]["lr0"]["zero_value_count"] == 1


def test_smoke_reports_uncanonicalizable_terminal_action(tmp_path):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    active = json.loads(paths["active"].read_text())
    trace_path = Path(active["trace_path"])
    trace = json.loads(trace_path.read_text())
    trace["interactions"][1]["response"]["action"] = {"value": float("nan")}
    _write(trace_path, trace)

    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)

    assert report["decision"] == "invalid"
    assert report["terminal_actions"]["active"]["canonical_hash_count"] == 1
    assert any("cannot be canonicalized" in error for error in report["errors"])


def test_smoke_rejects_statistical_addendum_provenance_tamper(tmp_path):
    grid, provenance, _paths = _install_valid_smoke(tmp_path)
    provenance["statistical_addendum_sha256"] = "0" * 64

    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)

    assert report["decision"] == "invalid"
    assert any(
        "provenance statistical addendum SHA-256 mismatch" in error
        for error in report["errors"]
    )


def test_smoke_rejects_checked_in_statistical_addendum_tamper(tmp_path):
    grid, provenance, _paths = _install_valid_smoke(tmp_path)
    addendum = tmp_path / STATISTICAL_ADDENDUM_FILENAME
    addendum.write_bytes(addendum.read_bytes() + b"\n")

    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)

    assert report["decision"] == "invalid"
    assert any(
        "checked-in statistical addendum SHA-256 drift" in error
        for error in report["errors"]
    )


def test_smoke_gate_allows_successful_retries_when_active_does_not_regress(tmp_path):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    for arm, retry_count in (("active", 1), ("lr0", 2)):
        cell = json.loads(paths[arm].read_text())
        cell["heldout_outcomes"][0]["integrity"]["parse_retries"] = retry_count
        cell["integrity_counters"]["parse_retries"] = retry_count
        _write(paths[arm], cell)
    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)
    assert report["decision"] == "pass"


def test_smoke_gate_rejects_active_retry_repair_regression(tmp_path):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    active = json.loads(paths["active"].read_text())
    active["heldout_outcomes"][0]["integrity"]["repairs"] = 1
    active["integrity_counters"]["repairs"] = 1
    _write(paths["active"], active)
    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)
    assert report["decision"] == "invalid"
    assert any("active parse retry/repair total exceeds LR0" in error for error in report["errors"])


@pytest.mark.parametrize(
    ("arm", "mutation", "message"),
    [
        (
            "active",
            lambda cell: cell["replay"].update(
                trainable_param_sha256_final=HASH_A
            ),
            "active replay produced no trainable-parameter change",
        ),
        (
            "lr0",
            lambda cell: cell["integrity_counters"].update(fallbacks=1),
            "hard-failure integrity counters are nonzero",
        ),
        (
            "active",
            lambda cell: cell["provenance"].update(model_sha256="9" * 64),
            "provenance mismatch",
        ),
        (
            "active",
            lambda cell: cell["heldout_outcomes"][0].update(instance_id="wrong"),
            "paired held-out IDs/order differ",
        ),
        (
            "active",
            lambda cell: cell["replay"]["items"][0]["operations"][0].update(
                input_sha256=["9" * 64]
            ),
            "paired ordered operation/input signatures differ",
        ),
        (
            "lr0",
            lambda cell: cell["replay"]["items"][0]["operations"][0].update(
                trainable_param_sha256_after=HASH_B
            ),
            "LR0 replay operation changed parameters",
        ),
    ],
)
def test_smoke_gate_rejects_integrity_and_pairing_failures(
    tmp_path, arm, mutation, message
):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    cell = json.loads(paths[arm].read_text())
    mutation(cell)
    _write(paths[arm], cell)
    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)
    assert report["decision"] == "invalid"
    assert any(message in error for error in report["errors"])


def test_smoke_rejects_identical_but_non_tape_replay_inputs(tmp_path):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    for arm in ("active", "lr0"):
        cell = json.loads(paths[arm].read_text())
        cell["replay"]["items"][0]["operations"][0]["input_sha256"] = [
            "9" * 64,
            "8" * 64,
        ]
        _write(paths[arm], cell)

    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)

    assert report["decision"] == "invalid"
    assert any("input digests differ from tape" in error for error in report["errors"])


def test_smoke_rejects_rehashed_semantically_invalid_tape(tmp_path):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    collector_cfg = grid["collectors"][0]
    tape_path = tmp_path / collector_cfg["tape_path"]
    tape = json.loads(tape_path.read_text())
    tape["items"][0]["env_bon"]["candidates"][2]["candidate_sha256"] = "0" * 64
    tape["items"][0]["item_sha256"] = tape_item_sha256(tape["items"][0])
    tape["tape_sha256"] = tape_sha256(tape)
    verification = _verify_tape(tape)
    _write(tape_path, tape)

    collector_path = _collector_manifest_path(tmp_path, collector_cfg)
    collector = json.loads(collector_path.read_text())
    collector["tape_sha256"] = tape["tape_sha256"]
    collector["tape_verification"] = verification
    _write(collector_path, collector)
    for arm in ("active", "lr0"):
        cell = json.loads(paths[arm].read_text())
        cell["tape_sha256"] = tape["tape_sha256"]
        cell["replay"]["tape_sha256"] = tape["tape_sha256"]
        cell["replay"]["items"][0]["item_sha256"] = tape["items"][0][
            "item_sha256"
        ]
        _write(paths[arm], cell)

    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)

    assert report["decision"] == "invalid"
    assert any("candidate_sha256 mismatch" in error for error in report["errors"])


def test_smoke_rejects_same_wrong_heldout_ids_in_both_arms(tmp_path):
    grid, provenance, paths = _install_valid_smoke(tmp_path)
    for arm in ("active", "lr0"):
        cell = json.loads(paths[arm].read_text())
        cell["heldout_outcomes"][0]["instance_id"] = "cohort_studies:wrong"
        _write(paths[arm], cell)

    report = validate_smoke(root=tmp_path, grid=grid, provenance=provenance)

    assert report["decision"] == "invalid"
    assert any("held-out corpus ID mismatch" in error for error in report["errors"])
