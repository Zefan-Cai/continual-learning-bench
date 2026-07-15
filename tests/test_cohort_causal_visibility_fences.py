from __future__ import annotations

import errno
import json
import os
import sys
from pathlib import Path

import pytest

import run_cohort_causal_formal_registered as wrapper
import validate_cohort_causal_results as validator
import wait_cohort_causal_phase_outputs as phase


REPO_ROOT = Path(__file__).resolve().parents[1]


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.on_sleep = None

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        if self.on_sleep is not None:
            self.on_sleep(seconds)


@pytest.fixture(autouse=True)
def _fast_default_publications(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wrapper, "PUBLISHED_STABILITY_SECONDS", 0.0)
    monkeypatch.setattr(validator, "PUBLISHED_STABILITY_SECONDS", 0.0)


def _write(path: Path, payload: bytes = b"stable") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def test_registered_phase_inventory_covers_every_final_and_live_path(
    tmp_path: Path,
) -> None:
    grid = json.loads((REPO_ROOT / "grid_cohort_causal_smoke.json").read_bytes())
    collector_required, collector_forbidden = phase.registered_paths(
        root=tmp_path, grid=grid, section="collectors"
    )
    eval_required, eval_forbidden = phase.registered_paths(
        root=tmp_path, grid=grid, section="evaluation_cells"
    )

    assert len(collector_required) == 3 * len(grid["collectors"])
    assert len(collector_forbidden) == len(grid["collectors"])
    assert len(eval_required) == 2 * len(grid["evaluation_cells"])
    assert len(eval_forbidden) == len(grid["evaluation_cells"])
    assert all(
        path.name.endswith(".trace.live.json")
        for path in [
            *collector_forbidden,
            *eval_forbidden,
        ]
    )


def test_phase_fence_waits_for_live_temp_absence_and_two_stable_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    required = [_write(tmp_path / "trace.json")]
    forbidden = [tmp_path / "trace.live.json"]
    live_temp = _write(tmp_path / "trace.live.json.tmp", b"in-progress")
    clock = _Clock()

    def remove_live_temp(_seconds: float) -> None:
        live_temp.unlink(missing_ok=True)

    clock.on_sleep = remove_live_temp
    monkeypatch.setattr(phase.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(phase.time, "sleep", clock.sleep)

    snapshot = phase.wait_for_phase_outputs(
        required=required,
        forbidden=forbidden,
        timeout_seconds=5.0,
        stability_seconds=1.0,
        poll_seconds=0.25,
    )

    assert list(snapshot) == [required[0].as_posix()]
    assert clock.now >= 1.25


def test_phase_fence_rejects_change_after_first_successful_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _write(tmp_path / "trace.json", b"first")
    clock = _Clock()
    changed = False

    def replace_after_first_snapshot(seconds: float) -> None:
        nonlocal changed
        if seconds == 1.0 and not changed:
            target.write_bytes(b"second")
            changed = True

    clock.on_sleep = replace_after_first_snapshot
    monkeypatch.setattr(phase.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(phase.time, "sleep", clock.sleep)

    with pytest.raises(phase.PhaseVisibilityError, match="changed between"):
        phase.wait_for_phase_outputs(
            required=[target],
            forbidden=[],
            timeout_seconds=5.0,
            stability_seconds=1.0,
            poll_seconds=0.25,
        )


def test_phase_fence_retries_estale_pathname_then_accepts_same_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _write(tmp_path / "trace.json")
    original_lstat = Path.lstat
    stale_once = True

    def lstat_once(path: Path):
        nonlocal stale_once
        if path == target and stale_once:
            stale_once = False
            raise OSError(errno.ESTALE, "stale")
        return original_lstat(path)

    clock = _Clock()
    monkeypatch.setattr(Path, "lstat", lstat_once)
    monkeypatch.setattr(phase.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(phase.time, "sleep", clock.sleep)

    snapshot = phase.wait_for_phase_outputs(
        required=[target],
        forbidden=[],
        timeout_seconds=5.0,
        stability_seconds=1.0,
        poll_seconds=0.25,
    )

    assert target.as_posix() in snapshot
    assert clock.now >= 1.25


def test_phase_fence_rejects_symlink_leaf(tmp_path: Path) -> None:
    target = _write(tmp_path / "real.json")
    alias = tmp_path / "trace.json"
    alias.symlink_to(target)

    with pytest.raises(phase.PhaseVisibilityError, match="safely open"):
        phase.wait_for_phase_outputs(
            required=[alias],
            forbidden=[],
            timeout_seconds=0.01,
            stability_seconds=0.0,
            poll_seconds=0.001,
        )


def test_validator_waits_through_nlink_two_then_binds_original_inode(
    tmp_path: Path,
) -> None:
    target = _write(tmp_path / "manifest.json", b"manifest")
    alias = tmp_path / "publisher-temp"
    os.link(target, alias)
    expected_inode = (target.stat().st_dev, target.stat().st_ino)
    clock = _Clock()

    def finish_publication(_seconds: float) -> None:
        alias.unlink(missing_ok=True)

    clock.on_sleep = finish_publication
    raw = validator._wait_for_stable_file(
        target,
        "manifest",
        expected_payload=b"manifest",
        expected_inode=expected_inode,
        maximum_wait_seconds=5.0,
        stability_seconds=1.0,
        poll_seconds=0.25,
        sleep_fn=clock.sleep,
        monotonic_fn=clock.monotonic,
    )

    assert raw == b"manifest"
    assert clock.now >= 1.25


def test_validator_rejects_changed_successful_snapshot(tmp_path: Path) -> None:
    target = _write(tmp_path / "manifest.json", b"first")
    clock = _Clock()
    changed = False

    def mutate(seconds: float) -> None:
        nonlocal changed
        if seconds == 1.0 and not changed:
            target.write_bytes(b"second")
            changed = True
        clock.now += seconds

    with pytest.raises(validator.PublicationVisibilityError, match="changed between"):
        validator._wait_for_stable_file(
            target,
            "manifest",
            maximum_wait_seconds=5.0,
            stability_seconds=1.0,
            poll_seconds=0.25,
            sleep_fn=mutate,
            monotonic_fn=clock.monotonic,
        )


def test_manifest_visibility_failure_is_infrastructure_only_and_writes_no_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write(tmp_path / "formal_manifest.json", b"{}")
    decision = tmp_path / "formal_decision.json"
    monkeypatch.setattr(
        validator,
        "_wait_for_stable_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            validator.PublicationVisibilityError("timed out")
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_cohort_causal_results.py",
            "--manifest",
            manifest.as_posix(),
            "--output",
            decision.as_posix(),
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        validator.main()

    assert exc_info.value.code == 2
    assert not decision.exists()


def test_wrapper_waits_through_nlink_two_then_binds_original_inode(
    tmp_path: Path,
) -> None:
    target = _write(tmp_path / "expectation.json", b"expectation")
    alias = tmp_path / "publisher-temp"
    os.link(target, alias)
    expected_inode = (target.stat().st_dev, target.stat().st_ino)
    clock = _Clock()

    def finish_publication(_seconds: float) -> None:
        alias.unlink(missing_ok=True)

    clock.on_sleep = finish_publication
    raw = wrapper._wait_for_stable_regular(
        target,
        "launch expectation",
        expected_payload=b"expectation",
        expected_inode=expected_inode,
        maximum_wait_seconds=5.0,
        stability_seconds=1.0,
        poll_seconds=0.25,
        sleep_fn=clock.sleep,
        monotonic_fn=clock.monotonic,
    )

    assert raw == b"expectation"
    assert clock.now >= 1.25


def test_opaque_second_snapshot_enoent_is_bounded_and_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcome = _write(tmp_path / "formal_manifest.json", b"opaque")
    original_verify = wrapper._verify_open_outcome
    calls = 0

    def transient_verify(path: Path, descriptor: int, info: os.stat_result) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise FileNotFoundError(path)
        original_verify(path, descriptor, info)

    monkeypatch.setattr(wrapper, "_verify_open_outcome", transient_verify)
    descriptor, _ = wrapper._wait_for_stable_opaque_outcome(
        outcome,
        maximum_wait_seconds=1.0,
        stability_seconds=0.0,
        poll_seconds=0.01,
    )
    os.close(descriptor)

    assert calls == 2


def test_nonzero_exit_still_requires_both_opaque_outcomes(tmp_path: Path) -> None:
    manifest = _write(tmp_path / "formal_manifest.json", b"opaque")
    exit_path = tmp_path / "causal_formal.exit"

    with pytest.raises(wrapper.RegisteredFormalError, match="two opaque"):
        wrapper.publish_exit_marker(
            exit_path=exit_path,
            return_code=2,
            outcome_paths=[manifest],
            maximum_wait_seconds=0.01,
        )

    assert not exit_path.exists()
