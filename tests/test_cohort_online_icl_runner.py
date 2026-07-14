"""CPU-only contract tests for the canonical online-ICL cell runner."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import run_cohort_online_icl as runner
import validate_cohort_online_icl_results as validator
import validate_cohort_online_icl_smoke as smoke_validator
from src.tasks.cohort_studies.tool_schemas import build_submission_schema
from validate_cohort_causal_results import canonical_sha256
from validate_cohort_online_icl_results import validate_cell


NO_UPDATE = {
    "adaptation_count": 0,
    "adapter_enabled": False,
    "bon_updates": 0,
    "distill_updates": 0,
    "grpo_optimizer_steps": 0,
    "grpo_updates": 0,
    "peft_config_present": False,
    "reward_pg_updates": 0,
}


class FakeTokenizer:
    @staticmethod
    def apply_chat_template(
        messages,
        *,
        tokenize,
        add_generation_prompt,
        enable_thinking=False,
    ):
        assert tokenize is False
        assert add_generation_prompt is True
        assert enable_thinking is False
        return json.dumps(
            messages,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def encode(text: str, *, add_special_tokens: bool) -> list[int]:
        assert add_special_tokens is False
        return list(text.encode("utf-8"))


class FakeSystem:
    def __init__(self, **params):
        self.params = params
        self.messages: list[dict[str, str]] = []
        self.icl_env_reward_injections = 0
        self._icl_context_sealed_eval = False
        self._icl_context_sensitive_feedback_drops = 0

    def current_model_param_sha256(self) -> str:
        return "a" * 64

    def icl_no_update_audit(self) -> dict:
        return dict(NO_UPDATE)

    def seal_icl_context_for_evaluation(self) -> None:
        self._icl_context_sealed_eval = True

    def _snapshot_payload(self) -> dict:
        return {
            "protocol": "qwen_local_icl_context_snapshot_v1",
            "schema_version": 1,
            "state": {
                "has_truncated_flag": False,
                "icl_env_reward_injections": self.icl_env_reward_injections,
                "interaction_count": 2,
                "messages": deepcopy(self.messages),
                "truncation_count": 0,
            },
            "system_contract": validator._expected_snapshot_system_contract(
                self.params
            ),
        }

    def snapshot_icl_context(self) -> dict:
        payload = self._snapshot_payload()
        return {
            **payload,
            "snapshot_sha256": canonical_sha256(payload),
        }

    def restore_icl_context(self, snapshot: dict) -> None:
        self.messages = deepcopy(snapshot["state"]["messages"])
        self.icl_env_reward_injections = snapshot["state"]["icl_env_reward_injections"]

    def tokenize_icl_context_snapshot(self, snapshot: dict) -> dict:
        return validator._token_inventory(
            tokenizer=FakeTokenizer(),
            system_prompt=self.params["system_prompt"],
            messages=snapshot["state"]["messages"],
            snapshot_sha256=snapshot["snapshot_sha256"],
        )

    def get_run_artifacts(self) -> dict:
        return {}


class FakeTask:
    def __init__(self, **params):
        self.params = params

    def get_agent_brief(self):
        return None


class FakeRecorder:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.interactions: list[dict] = []

    def finalize(self, result, *, status="completed"):
        outcomes = [
            {
                "instance_id": outcome.instance_id,
                "instance_index": outcome.instance_index,
                "reward": outcome.reward,
            }
            for outcome in result.instance_outcomes
        ]
        return {
            "status": status,
            "phase": self.kwargs["phase"],
            "system": {
                "name": self.kwargs["system_name"],
                "params": self.kwargs["system_params"],
            },
            "task": {
                "name": self.kwargs["task_name"],
                "params": self.kwargs["task_params"],
            },
            "execution": {
                "usage": {
                    "interaction": {
                        "call_count": len(self.interactions),
                        "input_tokens": 20 * len(self.interactions),
                        "output_tokens": 3 * len(self.interactions),
                        "total_tokens": 23 * len(self.interactions),
                    }
                }
            },
            "interactions": deepcopy(self.interactions),
            "instance_outcomes": outcomes,
            "result": {"instance_outcomes": outcomes},
        }


def _outcome(role: str, index: int) -> SimpleNamespace:
    return SimpleNamespace(
        instance_id=f"cohort_studies:{role}-{index}",
        instance_index=index,
        reward=0.1 + 0.1 * index,
    )


def _interaction(role: str, index: int, *, sealed: bool) -> dict:
    reward = 0.1 + 0.1 * index
    schema = build_submission_schema()
    action_payload = {field: 0.5 for field in schema.model_fields}
    if index == 0:
        action_payload[next(iter(schema.model_fields))] = 0.0
    return {
        "query": {
            "feedback": None,
            "instance_id": f"cohort_studies:{role}-{index}",
            "instance_index": index,
            "metadata": {},
            "prompt": f"{role} prompt {index}",
            "response_schema": schema.__name__,
        },
        "response": {
            "action": schema.model_validate(action_payload).model_dump(),
            "metadata": {
                "generation_calls": 1,
                "generation_input_tokens_total": 20,
                "generation_output_tokens_total": 3,
                "generation_prompt_hard_truncations": 0,
                "icl_context_sealed_eval": sealed,
                "parse_repair_used": False,
                "parse_retries_used": 0,
                "prompt_hard_truncated": False,
            },
        },
        "observation": {
            "content": f"{role} terminal observation {index}",
            "instance_complete": True,
            "metadata": {
                "env_feedback_instance_id": f"cohort_studies:{role}-{index}",
                "env_feedback_instance_index": index,
                "env_feedback_reward": reward,
            },
        },
    }


def fake_run_task(task, system, *, trace_recorder, phase, **kwargs):
    del task
    assert kwargs["show_progress"] is False
    assert kwargs["verbose_logging"] is False
    role = "adaptation" if phase == "rollout" else "heldout"
    outcomes = [_outcome(role, index) for index in range(2)]
    if role == "adaptation":
        trace_recorder.interactions = [
            _interaction(role, index, sealed=False) for index in range(2)
        ]
        reconstructed = validator._reconstruct_adaptation_snapshot_state(
            trace={"interactions": trace_recorder.interactions},
            system_params=system.params,
            tokenizer=FakeTokenizer(),
        )
        system.messages = reconstructed["messages"]
        system.icl_env_reward_injections = reconstructed["icl_env_reward_injections"]
    else:
        before = kwargs["before_respond"]
        after = kwargs["after_observe"]
        interactions = []
        for index in range(2):
            query = SimpleNamespace(
                instance_id=f"cohort_studies:heldout-{index}",
                instance_index=index,
            )
            before(index + 1, query)
            system.messages.append(
                {"role": "user", "content": f"heldout state {index}"}
            )
            system._icl_context_sensitive_feedback_drops += 1
            step_result = SimpleNamespace(
                observation=SimpleNamespace(instance_complete=True)
            )
            after(index + 1, query, None, step_result)
            interactions.append(_interaction(role, index, sealed=True))
        trace_recorder.interactions = interactions
    return SimpleNamespace(instance_outcomes=outcomes)


def make_cfg() -> dict:
    cfg_id = "cohort_online_icl_smoke_seed2026071498_n2"
    prefix = f"artifacts/cohort_online_icl/{cfg_id}"
    return {
        "cfg_id": cfg_id,
        "mode": "online_icl_eval",
        "arm": "online_icl",
        "run_seed": 2026071498,
        "expected_num_instances": 2,
        "system_params": {
            "action_max_new_tokens": 4096,
            "adaptation_context_policy": "full",
            "best_of_n": 1,
            "context_policy": "full",
            "distill_provider": "off",
            "head_tokens": 4096,
            "inject_env_reward": True,
            "max_context_tokens": 32768,
            "max_new_tokens": 8192,
            "method": "icl",
            "model_path": "fake-model",
            "parse_retries": 2,
            "system_prompt": "",
            "tail_tokens": 4096,
            "temperature": 0.0,
            "top_p": 1.0,
            "trust_remote_code": True,
        },
        "adaptation_task_params": {"dataset_path": "adaptation"},
        "heldout_task_params": {"dataset_path": "heldout"},
        "adaptation_trace_path": f"{prefix}.adaptation.trace.json",
        "heldout_trace_path": f"{prefix}.heldout.trace.json",
        "snapshot_path": f"{prefix}.sealed_snapshot.json",
        "context_inventory_path": f"{prefix}.context_inventory.json",
        "restoration_audit_path": f"{prefix}.restoration_audit.json",
        "cell_manifest_path": f"{prefix}.manifest.json",
    }


def test_online_icl_runner_seals_restores_and_publishes_atomic_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = make_cfg()
    grid = {
        "protocol": runner.PROTOCOL,
        "kind": "smoke",
        "cells": [cfg],
        "datasets": {
            "adaptation": {"corpus_sha256": "adaptation-hash"},
            "heldout": {"corpus_sha256": "heldout-hash"},
        },
    }

    def projection(role):
        return {
            "aggregate_sha256": f"{role}-hash",
            "canonical_instance_ids": [
                f"cohort_studies:{role}-{index}" for index in range(2)
            ],
        }

    monkeypatch.setattr(
        runner,
        "_load_verified_dataset_bundle",
        lambda _root, _grid, role: {
            "artifact_bytes": {"metadata.json": b"{}\n"},
            "manifest_bytes": b"{}\n",
            "projection": projection(role),
        },
    )
    monkeypatch.setattr(runner, "_phase_peak_memory_reset", lambda: None)
    monkeypatch.setattr(
        runner,
        "_phase_peak_memory",
        lambda: {"peak_allocated_bytes": 10, "peak_reserved_bytes": 20},
    )
    protocol_seal_sha256 = "b" * 64
    monkeypatch.setattr(
        runner,
        "verify_runtime_protocol_seal",
        lambda *_args, **_kwargs: protocol_seal_sha256,
    )
    monkeypatch.setenv("PYTHONHASHSEED", str(cfg["run_seed"]))
    monkeypatch.setattr(validator, "_scoring_contract", lambda **_kwargs: {})
    monkeypatch.setattr(
        validator,
        "_load_registered_tokenizer",
        lambda _system_params: FakeTokenizer(),
    )
    monkeypatch.setattr(
        validator,
        "_independent_reward",
        lambda _action, *, instance_id, **_kwargs: (
            0.1 + 0.1 * int(instance_id.rsplit("-", 1)[1])
        ),
    )
    bindings = runner.RuntimeBindings(
        system_cls=FakeSystem,
        task_cls=FakeTask,
        run_task=fake_run_task,
        trace_recorder_cls=FakeRecorder,
    )
    provenance = {
        "base_causal_commit": "d" * 40,
        "environment_lock_sha256": "e" * 64,
        "model_path": "fake-model",
        "model_sha256": "3" * 64,
        "source_commit": "a" * 40,
        "tokenizer_sha256": "4" * 64,
    }

    cell = runner.run_online_icl_eval(
        root=tmp_path,
        grid=grid,
        cfg=cfg,
        bindings=bindings,
        provenance=provenance,
        protocol_seal={"protocol_seal_sha256": protocol_seal_sha256},
    )

    assert cell["status"] == "completed"
    assert cell["score"] == pytest.approx(0.15)
    assert cell["no_update_audit"] == NO_UPDATE
    assert cell["protocol_seal_sha256"] == protocol_seal_sha256
    assert len(cell["heldout"]["initial_snapshot_audit"]) == 2
    assert len(cell["heldout"]["restoration_audit"]) == 2
    assert cell["heldout"]["sensitive_feedback_drops"] == 2
    assert len(set(cell["model_param_sha256"].values())) == 1
    completion = runner._outcome_blind_completion(cfg, cell)
    assert set(completion) == {
        "cell_manifest_sha256",
        "cfg_id",
        "protocol",
        "protocol_seal_sha256",
        "run_seed",
        "status",
    }
    serialized_completion = json.dumps(completion, sort_keys=True)
    assert '"score"' not in serialized_completion
    assert '"reward"' not in serialized_completion
    for key in (
        "adaptation_trace_path",
        "heldout_trace_path",
        "snapshot_path",
        "context_inventory_path",
        "restoration_audit_path",
        "cell_manifest_path",
    ):
        assert (tmp_path / cfg[key]).is_file()

    validated = validate_cell(
        root=tmp_path,
        grid=grid,
        cfg=cfg,
        provenance=provenance,
        protocol_seal_sha256=protocol_seal_sha256,
        cell=cell,
    )
    assert validated["valid"] is True
    assert validated["cell_manifest_sha256"] == canonical_sha256(cell)
    assert validated["adaptation_trace_sha256"] == cell["adaptation"]["trace_sha256"]
    assert validated["heldout_trace_sha256"] == cell["heldout"]["trace_sha256"]
    for field, config_key in (
        ("adaptation_trace_file_sha256", "adaptation_trace_path"),
        ("heldout_trace_file_sha256", "heldout_trace_path"),
        ("snapshot_file_sha256", "snapshot_path"),
        ("context_inventory_file_sha256", "context_inventory_path"),
        ("restoration_audit_file_sha256", "restoration_audit_path"),
        ("cell_manifest_file_sha256", "cell_manifest_path"),
    ):
        assert (
            validated[field]
            == hashlib.sha256((tmp_path / cfg[config_key]).read_bytes()).hexdigest()
        )
    assert [row["exact_zero_value_count"] for row in validated["terminal_actions"]] == [
        1,
        0,
    ]

    tampered = deepcopy(cell)
    tampered["heldout"]["sensitive_feedback_drops"] = 1
    with pytest.raises(ValueError, match="feedback-drop"):
        validate_cell(
            root=tmp_path,
            grid=grid,
            cfg=cfg,
            provenance=provenance,
            protocol_seal_sha256=protocol_seal_sha256,
            cell=tampered,
        )

    score_tampered = deepcopy(cell)
    score_tampered["heldout"]["outcomes"][0]["reward"] = 0.9
    score_tampered["score"] = 0.55
    with pytest.raises(ValueError, match="outcomes differ from bound trace"):
        validate_cell(
            root=tmp_path,
            grid=grid,
            cfg=cfg,
            provenance=provenance,
            protocol_seal_sha256=protocol_seal_sha256,
            cell=score_tampered,
        )

    action_hash_tampered = deepcopy(cell)
    action_hash_tampered["heldout"]["terminal_action_hashes"][0]["action_sha256"] = (
        "f" * 64
    )
    with pytest.raises(ValueError, match="action hashes differ from bound trace"):
        validate_cell(
            root=tmp_path,
            grid=grid,
            cfg=cfg,
            provenance=provenance,
            protocol_seal_sha256=protocol_seal_sha256,
            cell=action_hash_tampered,
        )

    snapshot_path = tmp_path / cfg["snapshot_path"]
    inventory_path = tmp_path / cfg["context_inventory_path"]
    restoration_path = tmp_path / cfg["restoration_audit_path"]
    original_payloads = {
        snapshot_path: json.loads(snapshot_path.read_text()),
        inventory_path: json.loads(inventory_path.read_text()),
        restoration_path: json.loads(restoration_path.read_text()),
    }

    def resign_artifact(payload: dict) -> str:
        unsigned = {
            key: value for key, value in payload.items() if key != "artifact_sha256"
        }
        payload["artifact_sha256"] = canonical_sha256(unsigned)
        return payload["artifact_sha256"]

    def write_payload(path: Path, payload: dict) -> None:
        path.write_text(
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )

    inner_digest_tamper = deepcopy(original_payloads[snapshot_path])
    inner_digest_tamper["snapshot"]["state"]["messages"].append(
        {"role": "user", "content": "heldout secret"}
    )
    inner_digest_cell = deepcopy(cell)
    inner_digest_cell["snapshot_artifact_sha256"] = resign_artifact(inner_digest_tamper)
    write_payload(snapshot_path, inner_digest_tamper)
    with pytest.raises(ValueError, match="snapshot digest binding"):
        validate_cell(
            root=tmp_path,
            grid=grid,
            cfg=cfg,
            provenance=provenance,
            protocol_seal_sha256=protocol_seal_sha256,
            cell=inner_digest_cell,
        )
    write_payload(snapshot_path, original_payloads[snapshot_path])

    message_inventory_tamper = deepcopy(original_payloads[inventory_path])
    message_inventory_tamper["message_inventory"]["rows"][0]["content_sha256"] = (
        "f" * 64
    )
    message_inventory_cell = deepcopy(cell)
    message_inventory_cell["context_inventory_sha256"] = resign_artifact(
        message_inventory_tamper
    )
    write_payload(inventory_path, message_inventory_tamper)
    with pytest.raises(ValueError, match="message inventory differs"):
        validate_cell(
            root=tmp_path,
            grid=grid,
            cfg=cfg,
            provenance=provenance,
            protocol_seal_sha256=protocol_seal_sha256,
            cell=message_inventory_cell,
        )
    write_payload(inventory_path, original_payloads[inventory_path])

    token_inventory_tamper = deepcopy(original_payloads[inventory_path])
    token_inventory_tamper["token_inventory"]["token_ids"].append(999)
    token_inventory_tamper["token_inventory"]["token_count"] += 1
    token_inventory_tamper["token_inventory"]["token_ids_sha256"] = canonical_sha256(
        token_inventory_tamper["token_inventory"]["token_ids"]
    )
    token_inventory_cell = deepcopy(cell)
    token_inventory_cell["context_inventory_sha256"] = resign_artifact(
        token_inventory_tamper
    )
    write_payload(inventory_path, token_inventory_tamper)
    with pytest.raises(ValueError, match="registered tokenizer"):
        validate_cell(
            root=tmp_path,
            grid=grid,
            cfg=cfg,
            provenance=provenance,
            protocol_seal_sha256=protocol_seal_sha256,
            cell=token_inventory_cell,
        )
    write_payload(inventory_path, original_payloads[inventory_path])

    trajectory_snapshot = deepcopy(original_payloads[snapshot_path])
    trajectory_snapshot["snapshot"]["state"]["messages"][0]["content"] = (
        "self-consistent but unobserved heldout secret"
    )
    inner = trajectory_snapshot["snapshot"]
    inner["snapshot_sha256"] = canonical_sha256(
        {
            key: inner[key]
            for key in ("protocol", "schema_version", "state", "system_contract")
        }
    )
    new_snapshot_sha = inner["snapshot_sha256"]
    trajectory_inventory = deepcopy(original_payloads[inventory_path])
    trajectory_inventory["snapshot_sha256"] = new_snapshot_sha
    trajectory_inventory["message_inventory"] = validator._message_inventory(
        inner["state"]["messages"]
    )
    trajectory_inventory["token_inventory"] = validator._token_inventory(
        tokenizer=FakeTokenizer(),
        system_prompt=cfg["system_params"]["system_prompt"],
        messages=inner["state"]["messages"],
        snapshot_sha256=new_snapshot_sha,
    )
    trajectory_restoration = deepcopy(original_payloads[restoration_path])
    trajectory_restoration["snapshot_sha256"] = new_snapshot_sha
    for row in trajectory_restoration["initial_snapshot_audit"]:
        row["snapshot_sha256"] = new_snapshot_sha
    for row in trajectory_restoration["restoration_audit"]:
        row["restored_snapshot_sha256"] = new_snapshot_sha
    trajectory_cell = deepcopy(cell)
    trajectory_cell["snapshot_sha256"] = new_snapshot_sha
    trajectory_cell["snapshot_artifact_sha256"] = resign_artifact(trajectory_snapshot)
    trajectory_cell["context_inventory_sha256"] = resign_artifact(trajectory_inventory)
    trajectory_cell["restoration_audit_sha256"] = resign_artifact(
        trajectory_restoration
    )
    trajectory_cell["heldout"]["initial_snapshot_audit"] = deepcopy(
        trajectory_restoration["initial_snapshot_audit"]
    )
    trajectory_cell["heldout"]["restoration_audit"] = deepcopy(
        trajectory_restoration["restoration_audit"]
    )
    write_payload(snapshot_path, trajectory_snapshot)
    write_payload(inventory_path, trajectory_inventory)
    write_payload(restoration_path, trajectory_restoration)
    with pytest.raises(ValueError, match="prompt-bearing trajectory"):
        validate_cell(
            root=tmp_path,
            grid=grid,
            cfg=cfg,
            provenance=provenance,
            protocol_seal_sha256=protocol_seal_sha256,
            cell=trajectory_cell,
        )
    for path, payload in original_payloads.items():
        write_payload(path, payload)

    monkeypatch.setattr(
        smoke_validator,
        "verify_runtime_protocol_seal",
        lambda *_args, **_kwargs: protocol_seal_sha256,
    )
    causal_prerequisite = {
        "causal_provenance_sha256": "1" * 64,
        "causal_smoke_gate_sha256": "2" * 64,
        "causal_source_commit": provenance["base_causal_commit"],
        "environment_lock_sha256": provenance["environment_lock_sha256"],
        "model_path": provenance["model_path"],
        "model_sha256": provenance["model_sha256"],
        "tokenizer_sha256": provenance["tokenizer_sha256"],
    }
    smoke_gate = smoke_validator.validate_smoke(
        root=tmp_path,
        grid=grid,
        provenance=provenance,
        protocol_seal={"protocol_seal_sha256": protocol_seal_sha256},
        cell=cell,
        causal_prerequisite=causal_prerequisite,
    )
    assert set(smoke_gate["cell"]) == smoke_validator.SMOKE_CELL_INTEGRITY_FIELDS
    assert "adaptation_score" not in smoke_gate["cell"]
    assert "heldout_score" not in smoke_gate["cell"]
    assert "terminal_actions" not in smoke_gate["cell"]
    assert '"score"' not in json.dumps(smoke_gate, sort_keys=True)
    smoke_grid_path = tmp_path / "registered-smoke-grid.json"
    smoke_grid_path.write_text("{}\n")
    protocol_seal = {
        "grids": {
            "smoke": {
                "file_sha256": hashlib.sha256(smoke_grid_path.read_bytes()).hexdigest(),
                "grid_sha256": "6" * 64,
                "path": smoke_grid_path.name,
            }
        },
        "protocol_seal_sha256": protocol_seal_sha256,
    }
    grid["grid_sha256"] = "6" * 64
    monkeypatch.setattr(runner, "load_grid", lambda _path: grid)
    monkeypatch.setattr(
        smoke_validator,
        "validate_causal_smoke_prerequisite",
        lambda **_kwargs: causal_prerequisite,
    )
    causal_revalidation_args = {
        "causal_root": tmp_path / "causal-root",
        "causal_smoke_gate": {"decision": "pass"},
        "causal_provenance": {"source_commit": provenance["base_causal_commit"]},
    }
    assert validator.revalidate_registered_formal_smoke_gate(
        root=tmp_path,
        smoke_gate=smoke_gate,
        provenance=provenance,
        protocol_seal=protocol_seal,
        protocol_seal_sha256=protocol_seal_sha256,
        **causal_revalidation_args,
    ) == canonical_sha256(smoke_gate)

    adaptation_trace_path = tmp_path / cfg["adaptation_trace_path"]
    adaptation_trace_bytes = adaptation_trace_path.read_bytes()
    adaptation_trace_path.write_text(
        json.dumps(json.loads(adaptation_trace_bytes), indent=4, sort_keys=False) + "\n"
    )
    with pytest.raises(ValueError, match="not canonical JSON"):
        validator.revalidate_registered_formal_smoke_gate(
            root=tmp_path,
            smoke_gate=smoke_gate,
            provenance=provenance,
            protocol_seal=protocol_seal,
            protocol_seal_sha256=protocol_seal_sha256,
            **causal_revalidation_args,
        )
    adaptation_trace_path.write_bytes(adaptation_trace_bytes)

    trace_symlink_target = tmp_path / "trace-symlink-target.json"
    trace_symlink_target.write_bytes(adaptation_trace_bytes)
    adaptation_trace_path.unlink()
    adaptation_trace_path.symlink_to(trace_symlink_target)
    with pytest.raises(ValueError, match="final-component artifact symlink"):
        validator.revalidate_registered_formal_smoke_gate(
            root=tmp_path,
            smoke_gate=smoke_gate,
            provenance=provenance,
            protocol_seal=protocol_seal,
            protocol_seal_sha256=protocol_seal_sha256,
            **causal_revalidation_args,
        )
    adaptation_trace_path.unlink()
    adaptation_trace_path.write_bytes(adaptation_trace_bytes)
    trace_symlink_target.unlink()

    cell_manifest_path = tmp_path / cfg["cell_manifest_path"]
    cell_manifest_bytes = cell_manifest_path.read_bytes()
    cell_manifest_path.write_text(
        json.dumps(json.loads(cell_manifest_bytes), indent=4, sort_keys=False) + "\n"
    )
    with pytest.raises(ValueError, match="not canonical JSON"):
        validator.revalidate_registered_formal_smoke_gate(
            root=tmp_path,
            smoke_gate=smoke_gate,
            provenance=provenance,
            protocol_seal=protocol_seal,
            protocol_seal_sha256=protocol_seal_sha256,
            **causal_revalidation_args,
        )
    cell_manifest_path.write_bytes(cell_manifest_bytes)

    adaptation_trace_path.unlink()
    with pytest.raises(ValueError, match="raw artifact is missing"):
        validator.revalidate_registered_formal_smoke_gate(
            root=tmp_path,
            smoke_gate=smoke_gate,
            provenance=provenance,
            protocol_seal=protocol_seal,
            protocol_seal_sha256=protocol_seal_sha256,
            **causal_revalidation_args,
        )
    adaptation_trace_path.write_bytes(adaptation_trace_bytes)
    adaptation_trace = json.loads(adaptation_trace_bytes)
    adaptation_trace["status"] = "tampered"
    adaptation_trace_path.write_bytes(runner._canonical_bytes(adaptation_trace) + b"\n")
    with pytest.raises(ValueError, match="trace digest mismatch"):
        validator.revalidate_registered_formal_smoke_gate(
            root=tmp_path,
            smoke_gate=smoke_gate,
            provenance=provenance,
            protocol_seal=protocol_seal,
            protocol_seal_sha256=protocol_seal_sha256,
            **causal_revalidation_args,
        )
    adaptation_trace_path.write_bytes(adaptation_trace_bytes)

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        runner.run_online_icl_eval(
            root=tmp_path,
            grid=grid,
            cfg=cfg,
            bindings=bindings,
            provenance=provenance,
            protocol_seal={"protocol_seal_sha256": protocol_seal_sha256},
        )


def test_immutable_json_publish_cannot_overwrite_existing_artifact(
    tmp_path: Path,
) -> None:
    output = tmp_path / "immutable.json"
    runner._atomic_write_json_no_overwrite(output, {"attempt": 1})
    original = output.read_bytes()

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        runner._atomic_write_json_no_overwrite(output, {"attempt": 2})

    assert output.read_bytes() == original


def test_online_preflight_rejects_dangling_final_symlink(tmp_path: Path) -> None:
    output = tmp_path / "future-artifact.json"
    missing_target = tmp_path / "missing-target.json"
    output.symlink_to(missing_target)

    with pytest.raises(FileExistsError, match="refusing to overwrite online-ICL"):
        runner._refuse_existing_online([output])
    assert output.is_symlink()
    assert not missing_target.exists()


def test_raw_artifact_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    artifact = tmp_path / "duplicate.json"
    artifact.write_bytes(b'{"schema_version":1,"schema_version":2}\n')

    with pytest.raises(ValueError, match="duplicate JSON key"):
        validator._load_with_file_sha256(artifact)


def test_immutable_json_publish_refuses_dangling_final_symlink(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.json"
    output = tmp_path / "immutable.json"
    output.symlink_to(outside)

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        runner._atomic_write_json_no_overwrite(output, {"attempt": 1})

    assert output.is_symlink()
    assert not outside.exists()
