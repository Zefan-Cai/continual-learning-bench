from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import run_cohort_causal_cell_sealed as sealed


PLAINTEXT_SENTINEL = "CAUSAL_PRIVATE_RESULT_SENTINEL_7f6c4e"


@pytest.fixture(autouse=True)
def _fast_visibility(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sealed, "PUBLISHED_STABILITY_SECONDS", 0.0)
    monkeypatch.setattr(sealed, "PUBLISHED_POLL_SECONDS", 0.001)
    monkeypatch.setattr(sealed, "_boot_id", lambda: "test-boot-id")
    monkeypatch.setattr(sealed, "_process_start_time_ticks", lambda pid: pid * 10)


def _age_binary() -> Path:
    configured = os.environ.get("COHORT_CAUSAL_TEST_AGE_BINARY")
    value = configured or shutil.which("age")
    if value is None:
        pytest.skip("real age binary is unavailable")
    return Path(value).resolve()


def _keypair(tmp_path: Path, age_binary: Path) -> tuple[Path, str]:
    keygen = age_binary.with_name("age-keygen")
    if not keygen.is_file():
        pytest.skip("matching age-keygen binary is unavailable")
    identity = tmp_path / "test-identity.txt"
    subprocess.run(
        [str(keygen), "-o", str(identity)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    recipient = subprocess.run(
        [str(keygen), "-y", str(identity)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return identity, recipient


def _runtime(
    tmp_path: Path, age_binary: Path, recipient: str
) -> tuple[Path, Path]:
    recipient_file = tmp_path / "COHORT_CAUSAL_LOG_RECIPIENT_V1.txt"
    recipient_file.write_text(recipient + "\n")
    version = subprocess.run(
        [str(age_binary), "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    contract = tmp_path / "runtime.json"
    contract.write_text(
        json.dumps(
            {
                "age_archive_sha256": "0" * 64,
                "age_archive_url": "https://example.invalid/age.tar.gz",
                "age_binary_sha256": hashlib.sha256(age_binary.read_bytes()).hexdigest(),
                "age_version": version,
                "private_identity_on_experiment_host": False,
                "recipient_file": recipient_file.name,
                "recipient_sha256": hashlib.sha256(
                    recipient_file.read_bytes()
                ).hexdigest(),
                "schema_version": 1,
            },
            sort_keys=True,
        )
    )
    return recipient_file, contract


def _run_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    age_binary = _age_binary()
    identity, recipient = _keypair(tmp_path, age_binary)
    recipient_file, contract = _runtime(tmp_path, age_binary, recipient)
    root = tmp_path / "root"
    root.mkdir()
    root_contract = root / "COHORT_CAUSAL_SEALED_LOG_RUNTIME_V1.json"
    shutil.copy2(contract, root_contract)
    contract = root_contract
    cfg_id = "sealed_smoke_cell"
    sealed_root = root / "artifacts/cohort_causal/sealed_logs/smoke"
    sealed_root.mkdir(parents=True)
    runtime_home_root = tmp_path / "runtime-homes"
    runtime_home_root.mkdir()
    runtime_home = runtime_home_root / cfg_id
    ciphertext = sealed_root / f"{cfg_id}.stdout_stderr.age"
    start = sealed_root / f"{cfg_id}.start.json"
    receipt = sealed_root / f"{cfg_id}.receipt.json"
    monkeypatch.delenv("SOPS_AGE_KEY", raising=False)
    return_code = sealed.run_sealed_cell(
        age_binary=age_binary,
        recipient_file=recipient_file,
        runtime_contract=contract,
        ciphertext_path=ciphertext,
        start_receipt_path=start,
        receipt_path=receipt,
        cwd=root,
        runtime_home=runtime_home,
        kind="smoke",
        phase="evaluation_cells",
        cfg_id=cfg_id,
        command=[
            sys.executable,
            "-c",
            (
                "import sys; "
                f"print({PLAINTEXT_SENTINEL!r}); "
                f"print({(PLAINTEXT_SENTINEL + '_STDERR')!r}, file=sys.stderr)"
            ),
        ],
    )
    return {
        "age": age_binary,
        "ciphertext": ciphertext,
        "cfg_id": cfg_id,
        "contract": contract,
        "identity": identity,
        "receipt": receipt,
        "recipient": recipient_file,
        "root": root,
        "runtime_home": runtime_home,
        "start": start,
        "return_code": return_code,
    }


def test_plaintext_never_reaches_artifacts_and_test_identity_recovers_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run_once(tmp_path, monkeypatch)
    assert run["return_code"] == 0
    for path in (run["ciphertext"], run["start"], run["receipt"]):
        assert PLAINTEXT_SENTINEL.encode() not in path.read_bytes()
    decrypted = subprocess.run(
        [
            str(run["age"]),
            "--decrypt",
            "--identity",
            str(run["identity"]),
            str(run["ciphertext"]),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert set(decrypted.splitlines()) == {
        PLAINTEXT_SENTINEL,
        f"{PLAINTEXT_SENTINEL}_STDERR",
    }

    grid = {
        "kind": "smoke",
        "collectors": [],
        "evaluation_cells": [{"cfg_id": run["cfg_id"]}],
    }
    assert (
        sealed.validate_sealed_phase_value(
            root=run["root"],
            grid=grid,
            section="evaluation_cells",
            recipient_file=run["recipient"],
        )
        == 1
    )


def test_ciphertext_tamper_and_overwrite_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run_once(tmp_path, monkeypatch)
    grid = {
        "kind": "smoke",
        "collectors": [],
        "evaluation_cells": [{"cfg_id": run["cfg_id"]}],
    }
    payload = bytearray(run["ciphertext"].read_bytes())
    payload[-1] ^= 1
    run["ciphertext"].write_bytes(payload)
    with pytest.raises(sealed.SealedCellError, match="sealed_phase_binding_invalid"):
        sealed.validate_sealed_phase_value(
            root=run["root"],
            grid=grid,
            section="evaluation_cells",
            recipient_file=run["recipient"],
        )
    with pytest.raises(sealed.SealedCellError, match="sealed_output_path_invalid"):
        sealed.run_sealed_cell(
            age_binary=run["age"],
            recipient_file=run["recipient"],
            runtime_contract=run["contract"],
            ciphertext_path=run["ciphertext"],
            start_receipt_path=run["start"],
            receipt_path=run["receipt"],
            cwd=run["root"],
            runtime_home=run["runtime_home"],
            kind="smoke",
            phase="evaluation_cells",
            cfg_id=run["cfg_id"],
            command=[sys.executable, "-c", "print('should not run')"],
        )


def test_publication_waits_through_transient_hardlink_nlink_visibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_snapshot = sealed._safe_regular_snapshot
    target = tmp_path / "published.json"
    failures_remaining = 2
    target_calls = 0

    def delayed_snapshot(path: Path) -> tuple[object, ...]:
        nonlocal failures_remaining, target_calls
        if path == target:
            target_calls += 1
            if failures_remaining:
                failures_remaining -= 1
                raise sealed.SealedCellError("sealed_artifact_identity_invalid")
        return real_snapshot(path)

    monkeypatch.setattr(sealed, "_safe_regular_snapshot", delayed_snapshot)
    payload = b'{"fixed":"liveness"}\n'

    snapshot = sealed._publish_bytes(target, payload)

    assert target.read_bytes() == payload
    assert snapshot[-1] == hashlib.sha256(payload).hexdigest()
    assert target_calls >= 3


def test_private_identity_environment_and_runtime_tamper_fail_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    age_binary = _age_binary()
    _identity, recipient = _keypair(tmp_path, age_binary)
    recipient_file, contract = _runtime(tmp_path, age_binary, recipient)
    monkeypatch.setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-TEST-DO-NOT-USE")
    with pytest.raises(sealed.SealedCellError, match="private_identity_in_environment"):
        sealed._reject_private_identity(["python", "runner.py"], os.environ)
    monkeypatch.delenv("SOPS_AGE_KEY")

    value = json.loads(contract.read_text())
    value["age_binary_sha256"] = "f" * 64
    contract.write_text(json.dumps(value))
    with pytest.raises(sealed.SealedCellError, match="age_binary_digest_mismatch"):
        sealed._validate_runtime(
            age_binary=age_binary,
            recipient_file=recipient_file,
            runtime_contract=contract,
        )


def test_liveness_status_exposes_only_fixed_safe_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run_once(tmp_path, monkeypatch)
    status = sealed.liveness_status(run["start"].parent)
    encoded = json.dumps(status, sort_keys=True)
    assert PLAINTEXT_SENTINEL not in encoded
    assert ".age" not in encoded
    assert "ciphertext" not in encoded
    assert status["records"] == [
        {
            "cfg_id": run["cfg_id"],
            "experiment_kind": "smoke",
            "phase": "evaluation_cells",
            "runner_exit_code": 0,
            "sealer_exit_code": 0,
            "state": "finished",
        }
    ]


def test_sigterm_reaps_runner_process_group_and_never_publishes_finish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    age_binary = _age_binary()
    _identity, recipient = _keypair(tmp_path, age_binary)
    recipient_file, contract = _runtime(tmp_path, age_binary, recipient)
    root = tmp_path / "root"
    sealed_root = root / "artifacts/cohort_causal/sealed_logs/smoke"
    sealed_root.mkdir(parents=True)
    root_contract = root / "COHORT_CAUSAL_SEALED_LOG_RUNTIME_V1.json"
    shutil.copy2(contract, root_contract)
    contract = root_contract
    runtime_home_root = tmp_path / "runtime-homes"
    runtime_home_root.mkdir()
    cfg_id = "sealed_signal_cell"
    runtime_home = runtime_home_root / cfg_id
    pid_file = tmp_path / "processes.json"
    ciphertext = sealed_root / f"{cfg_id}.stdout_stderr.age"
    start = sealed_root / f"{cfg_id}.start.json"
    receipt = sealed_root / f"{cfg_id}.receipt.json"
    code = (
        "import json,os,pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
        f"pathlib.Path({str(pid_file)!r}).write_text(json.dumps([os.getpid(),child.pid]));"
        "time.sleep(60)"
    )

    def interrupt_after_start() -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if start.exists() and pid_file.exists():
                os.kill(os.getpid(), sealed.signal.SIGTERM)
                return
            time.sleep(0.01)
        raise AssertionError("sealed supervisor did not publish its start receipt")

    interrupter = threading.Thread(target=interrupt_after_start, daemon=True)
    interrupter.start()
    with pytest.raises(sealed._SignalInterruption):
        sealed.run_sealed_cell(
            age_binary=age_binary,
            recipient_file=recipient_file,
            runtime_contract=contract,
            ciphertext_path=ciphertext,
            start_receipt_path=start,
            receipt_path=receipt,
            cwd=root,
            runtime_home=runtime_home,
            kind="smoke",
            phase="evaluation_cells",
            cfg_id=cfg_id,
            command=[sys.executable, "-c", code],
        )
    interrupter.join(timeout=2)
    assert not interrupter.is_alive()
    process_ids = json.loads(pid_file.read_text())
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        alive = []
        for pid in process_ids:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            alive.append(pid)
        if not alive:
            break
        time.sleep(0.05)
    assert alive == []
    assert start.is_file()
    assert not receipt.exists()
    assert not ciphertext.exists()
