from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import diagnose_cohort_causal_invalid as diagnostic


ROOT = Path(__file__).resolve().parents[1]
TEST_HOSTNAME = "test-host"
TEST_BOOT_ID = "00000000-0000-0000-0000-000000000001"
GIT_PROOF = {
    "head": diagnostic.SOURCE_COMMIT,
    "status": "clean_artifacts_link_only",
}


def _tooling_proof(
    layout: diagnostic.AttemptLayout, source_raw: bytes, amendment_raw: bytes
) -> dict[str, Any]:
    return {
        "amendment_blob_sha256": diagnostic._sha256(amendment_raw),
        "deployed_blobs_match_commit": True,
        "fetched_remote_ref": diagnostic.TOOLING_REMOTE_REF,
        "formal_source_is_ancestor": True,
        "remote_ref_contains_tooling_commit": True,
        "script_blob_sha256": diagnostic._sha256(source_raw),
        "tooling_commit": layout.tooling_commit,
    }


def _write(path: Path, raw: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def _invalid_decision(*, secret: str = "opaque-secret") -> dict[str, Any]:
    errors = sorted(
        [
            "pair[seed=1]/active/replay: final parameter hash mismatch",
            "unregistered integrity condition opaque-private-token",
        ]
    )
    return {
        "aggregate": None,
        "bootstrap": None,
        "decision": "invalid",
        "decision_scope": "invalid",
        "errors": errors,
        "experiment": "cohort_qonly_frozen_tape_causal_formal",
        "limitation": "not exact historical replication",
        "mechanism_label": "frozen-tape weight-update ablation",
        "pairs": [
            {
                "active_score": secret,
                "delta_seed": secret,
                "lr0_score": secret,
            }
        ],
        "protocol": "cohort_qonly_frozen_tape_weight_update_ablation_v1",
        "publication_inference": {
            "effective_n": None,
            "publication_grade": False,
            "status": "invalid_not_publication_grade",
        },
        "publication_grade": False,
        "schema_version": 1,
        "status": "invalid",
        "threshold_checks": None,
    }


def _launch_expectation(
    layout: diagnostic.AttemptLayout, pid_raw: bytes
) -> dict[str, Any]:
    return {
        "artifact_root": layout.artifact_root.as_posix(),
        "attempt_id": diagnostic.ATTEMPT_ID,
        "boot_id": TEST_BOOT_ID,
        "checkout_root": layout.checkout_root.as_posix(),
        "collector_gpus": [0, 2, 3],
        "created_at_utc": "2026-07-15T00:00:00Z",
        "durable_attempt_root": layout.durable_root.as_posix(),
        "eval_gpus": [0, 2, 3, 4, 5, 6],
        "exit_file": layout.inputs()["wrapper_exit"].as_posix(),
        "expected_final_inventory": {},
        "formal_grid_file_sha256": "1" * 64,
        "launch_mode": "formal",
        "launcher_file_sha256": "2" * 64,
        "max_used_memory_mib": 1024,
        "node_hostname": TEST_HOSTNAME,
        "pid_file": layout.inputs()["wrapper_pid"].as_posix(),
        "pid_file_sha256_at_registration": diagnostic._sha256(pid_raw),
        "protocol": "cohort_causal_formal_launch_expectation_v1",
        "provenance_file_sha256": "3" * 64,
        "schema_version": 1,
        "source_commit": diagnostic.SOURCE_COMMIT,
        "wrapper_cmdline_sha256_at_registration": "4" * 64,
        "wrapper_pid": int(pid_raw.rstrip(b"\n")),
        "wrapper_start_ticks": 123456,
    }


@pytest.fixture
def attempt(tmp_path: Path) -> tuple[diagnostic.AttemptLayout, Path]:
    layout = diagnostic.AttemptLayout(
        tooling_commit="a" * 40,
        checkout_base=tmp_path / "checkout-base",
        durable_base=tmp_path / "durable-base",
    )
    source = _write(layout.self_path, (ROOT / diagnostic.SCRIPT_FILENAME).read_bytes())
    _write(layout.amendment_path(), b"prospective invalid diagnostic amendment\n")
    inputs = layout.inputs()
    pid_raw = b"999999991\n"
    _write(inputs["formal_decision"], diagnostic._canonical_bytes(_invalid_decision()))
    _write(inputs["formal_manifest"], b"not-json-and-must-remain-opaque\n")
    _write(
        inputs["launch_expectation"],
        diagnostic._canonical_bytes(_launch_expectation(layout, pid_raw)),
    )
    _write(inputs["validator_source"], (ROOT / diagnostic.VALIDATOR_FILENAME).read_bytes())
    source_files = {
        "attester_v1_source": "attest_cohort_causal_completion.py",
        "attester_v2_source": "attest_cohort_causal_completion_v2.py",
        "seal_v1_source": "build_cohort_structured_state_execution_seal.py",
        "seal_v2_source": "build_cohort_structured_state_execution_seal_v2.py",
    }
    for role, filename in source_files.items():
        raw = (ROOT / filename).read_bytes()
        _write(inputs[role], raw)
        _write(layout.checkout_root / filename, raw)
    _write(inputs["procfs_exception_inventory"], b"opaque-v2-inventory\n")
    _write(inputs["wrapper_exit"], b"1\n")
    _write(inputs["wrapper_pid"], pid_raw)
    os.utime(inputs["formal_decision"], ns=(1_000_000_000, 1_000_000_000))
    os.utime(inputs["formal_manifest"], ns=(1_000_000_000, 1_000_000_000))
    os.utime(inputs["wrapper_exit"], ns=(2_000_000_000, 2_000_000_000))
    return layout, source


def _freeze(
    layout: diagnostic.AttemptLayout, source: Path
) -> dict[str, Any]:
    return diagnostic.freeze(
        layout=layout,
        actual_argv=diagnostic._phase_argv(layout, "freeze"),
        source_path=source,
        pid_is_live_fn=lambda _pid: False,
        scan_fn=lambda _layout: None,
        git_check_fn=lambda _layout: GIT_PROOF,
        tooling_check_fn=_tooling_proof,
        temporary_audit_fn=lambda _layout: None,
        hostname_fn=lambda: TEST_HOSTNAME,
        boot_id_fn=lambda: TEST_BOOT_ID,
        cwd_fn=lambda: "/tmp",
        environ_fn=lambda: diagnostic.DIAGNOSTIC_ENV,
        isolated=1,
        sleep_fn=lambda _seconds: None,
    )


def _diagnose(
    layout: diagnostic.AttemptLayout, source: Path
) -> dict[str, Any]:
    return diagnostic.diagnose(
        layout=layout,
        actual_argv=diagnostic._phase_argv(layout, "diagnose"),
        source_path=source,
        pid_is_live_fn=lambda _pid: False,
        scan_fn=lambda _layout: None,
        git_check_fn=lambda _layout: GIT_PROOF,
        tooling_check_fn=_tooling_proof,
        temporary_audit_fn=lambda _layout: None,
        hostname_fn=lambda: TEST_HOSTNAME,
        boot_id_fn=lambda: TEST_BOOT_ID,
        cwd_fn=lambda: "/tmp",
        environ_fn=lambda: diagnostic.DIAGNOSTIC_ENV,
        isolated=1,
    )


def _retime_completed_outputs(layout: diagnostic.AttemptLayout) -> None:
    inputs = layout.inputs()
    os.utime(inputs["formal_decision"], ns=(1_000_000_000, 1_000_000_000))
    os.utime(inputs["formal_manifest"], ns=(1_000_000_000, 1_000_000_000))
    os.utime(inputs["wrapper_exit"], ns=(2_000_000_000, 2_000_000_000))


def test_freeze_and_diagnose_emit_only_safe_reason_contract(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    secret = "NEVER_EMIT_SCORE_DELTA_0_9375"
    layout.inputs()["formal_decision"].write_bytes(
        diagnostic._canonical_bytes(_invalid_decision(secret=secret))
    )
    layout.inputs()["formal_manifest"].write_bytes(
        f"manifest-secret:{secret}\n".encode()
    )
    _retime_completed_outputs(layout)

    plan = _freeze(layout, source)
    result = _diagnose(layout, source)
    rendered = diagnostic._canonical_bytes(result)

    assert plan["formal_manifest_parsed"] is False
    assert set(result) == {
        "attempt_binding",
        "diagnosed_at_utc",
        "efficacy_fields_emitted",
        "formal_manifest_parsed",
        "input_hashes",
        "plan_binding",
        "protocol",
        "raw_errors_emitted",
        "reason_category_counts",
        "reason_rule_counts",
        "schema_version",
        "status",
    }
    assert result["efficacy_fields_emitted"] is False
    assert result["formal_manifest_parsed"] is False
    assert result["raw_errors_emitted"] is False
    assert sum(item["count"] for item in result["reason_rule_counts"]) == 2
    assert any(
        item
        == {
            "category": "other_integrity",
            "count": 1,
            "reason_rule_id": "UNKNOWN_INTEGRITY_FAILURE",
        }
        for item in result["reason_rule_counts"]
    )
    assert secret.encode() not in rendered
    assert b"opaque-private-token" not in rendered
    for forbidden in (
        b'"errors"',
        b'"pairs"',
        b'"scores"',
        b'"deltas"',
        b'"aggregate"',
        b'"bootstrap"',
        b'"ci"',
    ):
        assert forbidden not in rendered
    assert layout.result_path.read_bytes() == rendered


@pytest.mark.parametrize(
    "target_name", ["formal_decision", "formal_manifest", "launch_expectation"]
)
def test_diagnose_rejects_tampered_opaque_input(
    attempt: tuple[diagnostic.AttemptLayout, Path], target_name: str
) -> None:
    layout, source = attempt
    _freeze(layout, source)
    with layout.inputs()[target_name].open("ab") as handle:
        handle.write(b"tamper")

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="binding changed"):
        _diagnose(layout, source)
    assert not layout.result_path.exists()


def test_diagnose_rejects_tampered_amendment(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    _freeze(layout, source)
    with layout.amendment_path().open("ab") as handle:
        handle.write(b"tamper")

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="binding changed"):
        _diagnose(layout, source)


def test_freeze_requires_exact_nonzero_exit_and_dead_wrapper(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    layout.inputs()["wrapper_exit"].write_bytes(b"0\n")
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="exact invalid"):
        _freeze(layout, source)

    layout.inputs()["wrapper_exit"].write_bytes(b"1\n")
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="remains live"):
        diagnostic.freeze(
            layout=layout,
            actual_argv=diagnostic._phase_argv(layout, "freeze"),
            source_path=source,
            pid_is_live_fn=lambda _pid: True,
            scan_fn=lambda _layout: None,
            git_check_fn=lambda _layout: GIT_PROOF,
            tooling_check_fn=_tooling_proof,
            temporary_audit_fn=lambda _layout: None,
            hostname_fn=lambda: TEST_HOSTNAME,
            boot_id_fn=lambda: TEST_BOOT_ID,
            cwd_fn=lambda: "/tmp",
            environ_fn=lambda: diagnostic.DIAGNOSTIC_ENV,
            isolated=1,
            sleep_fn=lambda _seconds: None,
        )


def test_process_scan_rejects_live_cmdline_reference(
    attempt: tuple[diagnostic.AttemptLayout, Path], tmp_path: Path
) -> None:
    layout, _ = attempt
    proc = tmp_path / "proc"
    entry = proc / "4321"
    entry.mkdir(parents=True)
    (entry / "cmdline").write_bytes(
        b"python\0worker.py\0" + layout.durable_root.as_posix().encode()
    )
    os.symlink("/", entry / "cwd")

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="live process"):
        diagnostic._scan_process_references(layout, proc_root=proc, self_pid=9999)


def test_no_overwrite_preserves_plan_and_result(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    _freeze(layout, source)
    plan_raw = layout.plan_path.read_bytes()
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="already exists"):
        _freeze(layout, source)
    assert layout.plan_path.read_bytes() == plan_raw

    _diagnose(layout, source)
    result_raw = layout.result_path.read_bytes()
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="already exists"):
        _diagnose(layout, source)
    assert layout.result_path.read_bytes() == result_raw


def test_diagnose_requires_exact_invalid_top_level_contract(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    value = _invalid_decision()
    value["mean_delta"] = 1.0
    layout.inputs()["formal_decision"].write_bytes(diagnostic._canonical_bytes(value))
    _retime_completed_outputs(layout)
    _freeze(layout, source)

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="top-level"):
        _diagnose(layout, source)
    assert not layout.result_path.exists()


@pytest.mark.parametrize("decision", ["pass", "valid_no_go"])
def test_diagnose_rejects_noninvalid_decision(
    attempt: tuple[diagnostic.AttemptLayout, Path], decision: str
) -> None:
    layout, source = attempt
    value = _invalid_decision()
    value["decision"] = decision
    layout.inputs()["formal_decision"].write_bytes(diagnostic._canonical_bytes(value))
    _retime_completed_outputs(layout)
    _freeze(layout, source)

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="invalid envelope"):
        _diagnose(layout, source)


def test_specific_update_failures_have_distinct_preregistered_reason_ids(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    value = _invalid_decision()
    value["errors"] = sorted(
        [
            "pair[0]/active: active final parameter hash did not change",
            "pair[0]/active: no audited active replay update changed parameters",
        ]
    )
    layout.inputs()["formal_decision"].write_bytes(diagnostic._canonical_bytes(value))
    _retime_completed_outputs(layout)
    _freeze(layout, source)

    result = _diagnose(layout, source)
    assert result["reason_rule_counts"] == [
        {
            "category": "update_contract",
            "count": 1,
            "reason_rule_id": "vcr_2879_active_final_hash_unchanged",
        },
        {
            "category": "update_contract",
            "count": 1,
            "reason_rule_id": "vcr_2881_no_audited_active_parameter_change",
        },
    ]


def test_freeze_rejects_exit_not_strictly_after_outputs(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    os.utime(
        layout.inputs()["wrapper_exit"],
        ns=(1_000_000_000, 1_000_000_000),
    )
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="strictly postdate"):
        _freeze(layout, source)


def test_freeze_rejects_drift_between_two_snapshots(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    sleeps: list[float] = []

    def mutate(seconds: float) -> None:
        sleeps.append(seconds)
        with source.open("ab") as handle:
            handle.write(b"drift")

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="freeze snapshots"):
        diagnostic.freeze(
            layout=layout,
            actual_argv=diagnostic._phase_argv(layout, "freeze"),
            source_path=source,
            pid_is_live_fn=lambda _pid: False,
            scan_fn=lambda _layout: None,
            git_check_fn=lambda _layout: GIT_PROOF,
            tooling_check_fn=_tooling_proof,
            temporary_audit_fn=lambda _layout: None,
            hostname_fn=lambda: TEST_HOSTNAME,
            boot_id_fn=lambda: TEST_BOOT_ID,
            cwd_fn=lambda: "/tmp",
            environ_fn=lambda: diagnostic.DIAGNOSTIC_ENV,
            isolated=1,
            sleep_fn=mutate,
        )
    assert sleeps == [diagnostic.MINIMUM_FREEZE_STABILITY_SECONDS]
    assert not layout.plan_path.exists()


def test_post_semantic_process_scan_failure_prevents_receipt(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    _freeze(layout, source)
    calls = 0

    def scan(_layout: diagnostic.AttemptLayout) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise diagnostic.InvalidDiagnosticError("post-semantic live process")

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="post-semantic"):
        diagnostic.diagnose(
            layout=layout,
            actual_argv=diagnostic._phase_argv(layout, "diagnose"),
            source_path=source,
            pid_is_live_fn=lambda _pid: False,
            scan_fn=scan,
            git_check_fn=lambda _layout: GIT_PROOF,
            tooling_check_fn=_tooling_proof,
            temporary_audit_fn=lambda _layout: None,
            hostname_fn=lambda: TEST_HOSTNAME,
            boot_id_fn=lambda: TEST_BOOT_ID,
            cwd_fn=lambda: "/tmp",
            environ_fn=lambda: diagnostic.DIAGNOSTIC_ENV,
            isolated=1,
        )
    assert calls == 2
    assert not layout.result_path.exists()


def test_diagnose_plan_is_sole_cli_authority_and_derives_tooling_commit(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    _freeze(layout, source)

    derived = diagnostic._layout_from_plan_authority(
        layout.plan_path,
        source_path=source,
        checkout_base=layout.checkout_base,
        durable_base=layout.durable_base,
    )
    assert derived == layout
    assert diagnostic._phase_argv(layout, "diagnose") == [
        diagnostic.EXPECTED_PYTHON_PATH,
        "-I",
        source.as_posix(),
        "diagnose",
        "--plan",
        layout.plan_path.as_posix(),
    ]
    assert "--tooling-commit" not in diagnostic._phase_argv(layout, "diagnose")


@pytest.mark.parametrize(
    ("cwd", "environment"),
    [
        ("/not-tmp", diagnostic.DIAGNOSTIC_ENV),
        ("/tmp", {**diagnostic.DIAGNOSTIC_ENV, "EXTRA": "forbidden"}),
    ],
)
def test_diagnose_runtime_requires_tmp_and_exact_minimal_environment(
    attempt: tuple[diagnostic.AttemptLayout, Path],
    cwd: str,
    environment: dict[str, str],
) -> None:
    layout, source = attempt
    _freeze(layout, source)

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="runtime contract"):
        diagnostic.diagnose(
            layout=layout,
            actual_argv=diagnostic._phase_argv(layout, "diagnose"),
            source_path=source,
            pid_is_live_fn=lambda _pid: False,
            scan_fn=lambda _layout: None,
            git_check_fn=lambda _layout: GIT_PROOF,
            tooling_check_fn=_tooling_proof,
            temporary_audit_fn=lambda _layout: None,
            hostname_fn=lambda: TEST_HOSTNAME,
            boot_id_fn=lambda: TEST_BOOT_ID,
            cwd_fn=lambda: cwd,
            environ_fn=lambda: environment,
            isolated=1,
        )


@pytest.mark.parametrize(
    ("hostname", "boot_id"),
    [("wrong-host", TEST_BOOT_ID), (TEST_HOSTNAME, "f" * 36)],
)
def test_freeze_rejects_wrong_current_host_or_boot(
    attempt: tuple[diagnostic.AttemptLayout, Path],
    hostname: str,
    boot_id: str,
) -> None:
    layout, source = attempt
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="identity differs"):
        diagnostic.freeze(
            layout=layout,
            actual_argv=diagnostic._phase_argv(layout, "freeze"),
            source_path=source,
            pid_is_live_fn=lambda _pid: False,
            scan_fn=lambda _layout: None,
            git_check_fn=lambda _layout: GIT_PROOF,
            tooling_check_fn=_tooling_proof,
            temporary_audit_fn=lambda _layout: None,
            hostname_fn=lambda: hostname,
            boot_id_fn=lambda: boot_id,
            cwd_fn=lambda: "/tmp",
            environ_fn=lambda: diagnostic.DIAGNOSTIC_ENV,
            isolated=1,
            sleep_fn=lambda _seconds: None,
        )


def test_unknown_error_emits_only_unknown_enum_without_digest(
    attempt: tuple[diagnostic.AttemptLayout, Path],
) -> None:
    layout, source = attempt
    raw_error = "totally opaque unregistered failure text"
    value = _invalid_decision()
    value["errors"] = [raw_error]
    layout.inputs()["formal_decision"].write_bytes(diagnostic._canonical_bytes(value))
    _retime_completed_outputs(layout)
    _freeze(layout, source)

    result = _diagnose(layout, source)
    rendered = diagnostic._canonical_bytes(result)
    legacy_digest = diagnostic._sha256(
        b"cohort-causal-invalid-error-v1\0" + raw_error.encode()
    ).encode()
    assert result["reason_rule_counts"] == [
        {
            "category": "other_integrity",
            "count": 1,
            "reason_rule_id": "UNKNOWN_INTEGRITY_FAILURE",
        }
    ]
    assert "error_digests" not in result
    assert raw_error.encode() not in rendered
    assert legacy_digest not in rendered


def test_freeze_default_process_gate_uses_v2_policy_twice(
    attempt: tuple[diagnostic.AttemptLayout, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    layout, source = attempt
    calls: list[tuple[str, str]] = []

    def scan(
        selected: diagnostic.AttemptLayout,
        *,
        hostname_fn,
        boot_id_fn,
    ) -> None:
        assert selected == layout
        calls.append((hostname_fn(), boot_id_fn()))

    monkeypatch.setattr(diagnostic, "_scan_with_v2_policy", scan)
    diagnostic.freeze(
        layout=layout,
        actual_argv=diagnostic._phase_argv(layout, "freeze"),
        source_path=source,
        pid_is_live_fn=lambda _pid: False,
        git_check_fn=lambda _layout: GIT_PROOF,
        tooling_check_fn=_tooling_proof,
        temporary_audit_fn=lambda _layout: None,
        hostname_fn=lambda: TEST_HOSTNAME,
        boot_id_fn=lambda: TEST_BOOT_ID,
        cwd_fn=lambda: "/tmp",
        environ_fn=lambda: diagnostic.DIAGNOSTIC_ENV,
        isolated=1,
        sleep_fn=lambda _seconds: None,
    )
    assert calls == [(TEST_HOSTNAME, TEST_BOOT_ID)] * 2


def test_published_stability_requires_two_identical_single_link_observations(
    tmp_path: Path,
) -> None:
    path = tmp_path / "receipt.json"
    payload = b"receipt\n"
    info = {
        "device": 1,
        "inode": 2,
        "mode": 0o100444,
        "nlink": 1,
        "size_bytes": len(payload),
        "uid": 3,
        "gid": 4,
        "mtime_ns": 5,
        "ctime_ns": 6,
    }
    calls = 0

    def read(_path: Path, _label: str):
        nonlocal calls
        calls += 1
        return payload, {
            "path": path.as_posix(),
            "sha256": diagnostic._sha256(payload),
            "stat": info,
        }

    diagnostic._wait_for_published_stability(
        path,
        payload,
        expected_identity=diagnostic._publication_identity(info),
        timeout_seconds=2.0,
        poll_seconds=0.1,
        read_fn=read,
        sleep_fn=lambda _seconds: None,
    )
    assert calls == 2


def test_published_stability_timeout_fails_closed(tmp_path: Path) -> None:
    clock = 0.0

    def monotonic() -> float:
        return clock

    def sleep(seconds: float) -> None:
        nonlocal clock
        clock += seconds

    def pending(_path: Path, _label: str):
        raise diagnostic.InvalidDiagnosticError("nlink still converging")

    with pytest.raises(diagnostic.InvalidDiagnosticError, match="stably visible"):
        diagnostic._wait_for_published_stability(
            tmp_path / "receipt.json",
            b"receipt\n",
            expected_identity={
                "device": 1,
                "inode": 2,
                "mode": 0o100444,
                "size_bytes": 8,
                "uid": 3,
                "gid": 4,
                "mtime_ns": 5,
            },
            timeout_seconds=0.5,
            poll_seconds=0.1,
            monotonic_fn=monotonic,
            sleep_fn=sleep,
            read_fn=pending,
        )


def test_clean_checkout_gate_uses_real_git_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging-repo"
    staging.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=staging, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=staging, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=staging, check=True)
    (staging / "tracked.txt").write_text("tracked\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=staging, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=staging, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=staging,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setattr(diagnostic, "SOURCE_COMMIT", commit)
    layout = diagnostic.AttemptLayout(
        tooling_commit="a" * 40,
        checkout_base=tmp_path / "checkout-base",
        durable_base=tmp_path / "durable-base",
    )
    layout.checkout_root.parent.mkdir(parents=True)
    staging.rename(layout.checkout_root)
    os.symlink(tmp_path / "artifact-target", layout.checkout_root / "artifacts")

    assert diagnostic._validate_clean_checkout(layout) == {
        "head": commit,
        "status": "clean_artifacts_link_only",
    }
    (layout.checkout_root / "tracked.txt").write_text("dirty\n")
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="not clean"):
        diagnostic._validate_clean_checkout(layout)


def test_temporary_and_component_symlink_gates(
    attempt: tuple[diagnostic.AttemptLayout, Path], tmp_path: Path
) -> None:
    layout, _ = attempt
    diagnostic._audit_temporary_artifacts(layout)
    partial = layout.prep_root / "leftover.partial"
    partial.write_bytes(b"partial")
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="temporary"):
        diagnostic._audit_temporary_artifacts(layout)

    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "linked"
    os.symlink(target, link)
    with pytest.raises(diagnostic.InvalidDiagnosticError, match="symlink"):
        diagnostic._assert_no_symlink_components(link, "synthetic path")


def test_main_enforces_exact_environment_before_success(
    attempt: tuple[diagnostic.AttemptLayout, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    layout, source = attempt
    argv = diagnostic._phase_argv(layout, "diagnose")
    monkeypatch.chdir("/tmp")
    monkeypatch.setattr(diagnostic.sys, "argv", argv[2:])
    monkeypatch.setattr(diagnostic.sys, "orig_argv", argv)
    monkeypatch.setattr(
        diagnostic,
        "_layout_from_plan_authority",
        lambda _path, source_path: layout,
    )

    def check_runtime(**kwargs) -> None:
        diagnostic._validate_runtime(
            layout=layout,
            phase="diagnose",
            runtime_python_path=diagnostic.EXPECTED_PYTHON_PATH,
            runtime_python_version=diagnostic.EXPECTED_PYTHON_VERSION,
            actual_argv=kwargs["actual_argv"],
            cwd_fn=lambda: "/tmp",
            environ_fn=lambda: dict(os.environ),
            isolated=1,
        )

    monkeypatch.setattr(diagnostic, "diagnose", check_runtime)
    monkeypatch.setattr(os, "environ", dict(diagnostic.DIAGNOSTIC_ENV))
    diagnostic.main()
    assert capsys.readouterr().out == "CAUSAL_FORMAL_INVALID_DIAGNOSTIC_DIAGNOSE_OK\n"


def test_synthetic_v2_inventory_and_dynamic_module_integration(
    attempt: tuple[diagnostic.AttemptLayout, Path], tmp_path: Path
) -> None:
    layout, _ = attempt
    marker = tmp_path / "v2-scan-called"
    seal_v2 = b'''\ndef validate_exception_inventory(value, **kwargs):
    assert value == {"synthetic": True}
    assert kwargs["wrapper_pid"] == 999999991
    return {"dynamic_policy": {"kind": "synthetic"}, "dynamic_policy_sha256": "d" * 64}, [{"pid": 7}]
'''
    attester_v2 = f'''\ndef _scan_process_references(**kwargs):
    assert kwargs["exception_records"] == [{{"pid": 7}}]
    assert kwargs["dynamic_policy"] == {{"kind": "synthetic"}}
    open({marker.as_posix()!r}, "wb").write(b"called")
'''.encode()
    replacements = {
        "attester_v1_source": b"# synthetic v1 attester\n",
        "attester_v2_source": attester_v2,
        "seal_v1_source": b"# synthetic v1 seal\n",
        "seal_v2_source": seal_v2,
    }
    for role, raw in replacements.items():
        layout.inputs()[role].write_bytes(raw)
        filename = layout.inputs()[role].name
        (layout.checkout_root / filename).write_bytes(raw)
    layout.inputs()["procfs_exception_inventory"].write_bytes(
        diagnostic._canonical_bytes({"synthetic": True})
    )

    diagnostic._scan_with_v2_policy(
        layout,
        hostname_fn=lambda: TEST_HOSTNAME,
        boot_id_fn=lambda: TEST_BOOT_ID,
        proc_root=tmp_path,
    )
    assert marker.read_bytes() == b"called"
    assert not (layout.formal_tooling_root / "__pycache__").exists()
