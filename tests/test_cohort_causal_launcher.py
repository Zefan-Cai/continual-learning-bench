from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _install_launcher(tmp_path: Path) -> tuple[Path, Path]:
    launcher = tmp_path / "launch_cohort_causal.sh"
    shutil.copyfile(REPO_ROOT / "launch_cohort_causal.sh", launcher)
    shutil.copyfile(
        REPO_ROOT / "grid_cohort_causal_smoke.json",
        tmp_path / "grid_cohort_causal_smoke.json",
    )
    shutil.copyfile(
        REPO_ROOT / "grid_cohort_causal_formal.json",
        tmp_path / "grid_cohort_causal_formal.json",
    )
    provenance = tmp_path / "provenance.json"
    provenance.write_text("{}")
    return launcher, provenance


def _run(launcher: Path, provenance: Path, *extra: str, env=None):
    return subprocess.run(
        [
            "bash",
            str(launcher),
            "smoke",
            "--provenance",
            str(provenance),
            *extra,
        ],
        capture_output=True,
        text=True,
        env=env,
    )


def _run_formal(launcher: Path, provenance: Path, *extra: str, env=None):
    return subprocess.run(
        [
            "bash",
            str(launcher),
            "formal",
            "--provenance",
            str(provenance),
            *extra,
        ],
        capture_output=True,
        text=True,
        env=env,
    )


def test_launcher_rejects_duplicate_eval_gpus_before_launch(tmp_path):
    launcher, provenance = _install_launcher(tmp_path)
    completed = _run(
        launcher,
        provenance,
        "--collector-gpus",
        "0",
        "--eval-gpus",
        "2,2",
    )
    assert completed.returncode != 0
    assert "eval GPU IDs must be unique" in completed.stderr
    assert not list((tmp_path / "artifacts").rglob("*.log"))


def _fake_nvidia_smi(tmp_path: Path, *, memory: int, process: bool) -> dict[str, str]:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    binary = binary_dir / "nvidia-smi"
    process_row = "echo 'GPU-0, 4321, 10'" if process else ":"
    binary.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  --query-gpu=*)\n"
        f"    echo '0, GPU-0, {memory}'\n"
        "    echo '2, GPU-2, 0'\n"
        "    echo '3, GPU-3, 0'\n"
        "    ;;\n"
        "  --query-compute-apps=*)\n"
        f"    {process_row}\n"
        "    ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n"
    )
    binary.chmod(0o755)
    return {**os.environ, "PATH": f"{binary_dir}:{os.environ['PATH']}"}


def test_launcher_rechecks_memory_immediately_before_phase(tmp_path):
    launcher, provenance = _install_launcher(tmp_path)
    completed = _run(
        launcher,
        provenance,
        "--max-used-memory-mib",
        "1024",
        env=_fake_nvidia_smi(tmp_path, memory=2048, process=False),
    )
    assert completed.returncode != 0
    assert "GPU 0 memory.used=2048 MiB > 1024 MiB" in completed.stderr
    assert not list((tmp_path / "artifacts").rglob("*.log"))


def test_launcher_rejects_compute_process_even_below_memory_threshold(tmp_path):
    launcher, provenance = _install_launcher(tmp_path)
    completed = _run(
        launcher,
        provenance,
        "--max-used-memory-mib",
        "1024",
        env=_fake_nvidia_smi(tmp_path, memory=10, process=True),
    )
    assert completed.returncode != 0
    assert "GPU 0 has compute process pid=4321" in completed.stderr
    assert not list((tmp_path / "artifacts").rglob("*.log"))


def test_formal_launcher_requires_prior_smoke_gate(tmp_path):
    launcher, provenance = _install_launcher(tmp_path)
    completed = _run_formal(launcher, provenance)
    assert completed.returncode != 0
    assert "formal launch requires a prior passing smoke gate" in completed.stderr


def test_formal_launcher_binds_smoke_to_exact_provenance(tmp_path):
    launcher, provenance = _install_launcher(tmp_path)
    report = tmp_path / "artifacts/cohort_causal/smoke_gate.json"
    report.parent.mkdir(parents=True)
    report.write_text(
        json.dumps(
            {
                "status": "pass",
                "decision": "pass",
                "provenance_sha256": "0" * 64,
            }
        )
    )
    completed = _run_formal(launcher, provenance)
    assert completed.returncode != 0
    assert "formal provenance differs" in completed.stderr


def test_formal_launcher_accepts_bound_smoke_then_rechecks_gpus(tmp_path):
    launcher, provenance = _install_launcher(tmp_path)
    provenance_payload = json.loads(provenance.read_text())
    digest = hashlib.sha256(
        json.dumps(
            provenance_payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    report = tmp_path / "artifacts/cohort_causal/smoke_gate.json"
    report.parent.mkdir(parents=True)
    report.write_text(
        json.dumps(
            {
                "status": "pass",
                "decision": "pass",
                "provenance_sha256": digest,
            }
        )
    )
    completed = _run_formal(
        launcher,
        provenance,
        env=_fake_nvidia_smi(tmp_path, memory=2048, process=False),
    )
    assert completed.returncode != 0
    assert "GPU 0 memory.used=2048 MiB" in completed.stderr
