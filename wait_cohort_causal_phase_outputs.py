#!/usr/bin/env python3
"""Fence causal phase outputs across delayed-visibility filesystems.

The fence is outcome-blind: it checks only registered paths, regular-file
metadata, exact bytes through SHA-256, and the absence of live/temporary files.
Per-cell stdout/stderr is present only as age ciphertext. The fence never
decrypts, parses, or prints a model trace, tape, cell result, or log.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any


class PhaseVisibilityError(RuntimeError):
    """A registered phase output did not reach a stable filesystem view."""


class _VisibilityPending(RuntimeError):
    """A bounded publication transition has not converged yet."""


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _relative_path(root: Path, value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise PhaseVisibilityError(f"{label} is not a path string")
    relative = Path(value)
    if (
        relative.is_absolute()
        or os.path.normpath(value) != value
        or ".." in relative.parts
    ):
        raise PhaseVisibilityError(f"{label} is not a normalized relative path")
    return root / relative


def registered_paths(
    *, root: Path, grid: dict[str, Any], section: str
) -> tuple[list[Path], list[Path]]:
    rows = grid.get(section)
    if not isinstance(rows, list) or not rows:
        raise PhaseVisibilityError(f"grid section is empty or invalid: {section}")
    kind = grid.get("kind")
    if kind not in {"smoke", "formal"}:
        raise PhaseVisibilityError("grid kind is invalid")
    required: list[Path] = []
    forbidden: list[Path] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("cfg_id"), str):
            raise PhaseVisibilityError(f"invalid {section} row {index}")
        cfg_id = row["cfg_id"]
        trace_root = root / "artifacts" / "cohort_causal" / "traces"
        sealed_root = (
            root / "artifacts" / "cohort_causal" / "sealed_logs" / kind
        )
        required.append(trace_root / f"{cfg_id}.trace.json")
        required.extend(
            [
                sealed_root / f"{cfg_id}.stdout_stderr.age",
                sealed_root / f"{cfg_id}.start.json",
                sealed_root / f"{cfg_id}.receipt.json",
            ]
        )
        forbidden.append(trace_root / f"{cfg_id}.trace.live.json")
        if section == "collectors":
            required.extend(
                [
                    _relative_path(
                        root, row.get("tape_path"), label=f"collector {index} tape"
                    ),
                    root
                    / "artifacts"
                    / "cohort_causal"
                    / "collectors"
                    / f"{cfg_id}.manifest.json",
                ]
            )
        elif section == "evaluation_cells":
            required.append(
                _relative_path(
                    root,
                    row.get("cell_manifest_path"),
                    label=f"evaluation cell {index} manifest",
                )
            )
        else:
            raise PhaseVisibilityError(f"unsupported grid section: {section}")
    if len(set(required)) != len(required) or len(set(forbidden)) != len(forbidden):
        raise PhaseVisibilityError("registered phase paths are not unique")
    return sorted(required), sorted(forbidden)


def _read_snapshot(path: Path) -> tuple[tuple[int, ...], str]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError as exc:
        raise _VisibilityPending(f"missing phase output: {path}") from exc
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ESTALE}:
            raise _VisibilityPending(f"stale phase output: {path}") from exc
        raise PhaseVisibilityError(f"cannot safely open phase output: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink not in {1, 2}:
            raise PhaseVisibilityError(f"unsafe phase output object: {path}")
        if before.st_size <= 0 or before.st_nlink != 1:
            raise _VisibilityPending(f"phase output metadata is not settled: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        pathname = path.lstat()
    except FileNotFoundError as exc:
        raise _VisibilityPending(f"phase output pathname disappeared: {path}") from exc
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ESTALE}:
            raise _VisibilityPending(f"phase output pathname is stale: {path}") from exc
        raise PhaseVisibilityError(
            f"cannot inspect phase output pathname: {path}"
        ) from exc
    if stat.S_ISLNK(pathname.st_mode) or not stat.S_ISREG(pathname.st_mode):
        raise PhaseVisibilityError(f"unsafe phase output pathname: {path}")
    if _stat_identity(before) != _stat_identity(after) or _stat_identity(
        after
    ) != _stat_identity(pathname):
        raise _VisibilityPending(f"phase output changed during read: {path}")
    return _stat_identity(after), digest.hexdigest()


def _temporary_paths(paths: list[Path]) -> list[Path]:
    temporary: set[Path] = set()
    for target in paths:
        temporary.update(target.parent.glob(f".{target.name}.tmp*"))
        temporary.update(target.parent.glob(f"{target.name}.tmp*"))
    return sorted(temporary)


def _snapshot(
    *, required: list[Path], forbidden: list[Path]
) -> dict[str, tuple[tuple[int, ...], str]]:
    present_forbidden = [path for path in forbidden if os.path.lexists(path)]
    temporary = _temporary_paths([*required, *forbidden])
    if present_forbidden or temporary:
        raise _VisibilityPending(
            "live or temporary phase outputs remain: "
            + ", ".join(path.as_posix() for path in [*present_forbidden, *temporary])
        )
    return {path.as_posix(): _read_snapshot(path) for path in required}


def wait_for_phase_outputs(
    *,
    required: list[Path],
    forbidden: list[Path],
    timeout_seconds: float,
    stability_seconds: float,
    poll_seconds: float,
) -> dict[str, tuple[tuple[int, ...], str]]:
    if timeout_seconds <= 0 or stability_seconds < 0 or poll_seconds <= 0:
        raise PhaseVisibilityError("phase visibility timing is invalid")
    deadline = time.monotonic() + timeout_seconds
    previous: dict[str, tuple[tuple[int, ...], str]] | None = None
    previous_at: float | None = None
    observed: dict[str, tuple[tuple[int, ...], str]] | None = None
    last_error: BaseException | None = None
    while True:
        try:
            current = _snapshot(required=required, forbidden=forbidden)
        except _VisibilityPending as exc:
            previous = None
            previous_at = None
            last_error = exc
            delay = poll_seconds
        else:
            now = time.monotonic()
            if now > deadline:
                break
            if observed is None:
                observed = current
            elif current != observed:
                raise PhaseVisibilityError(
                    "phase output changed between visibility snapshots"
                )
            if previous == current and previous_at is not None:
                elapsed = now - previous_at
                if elapsed >= stability_seconds:
                    return current
                delay = stability_seconds - elapsed
            else:
                previous = current
                previous_at = now
                delay = stability_seconds
            last_error = None
            if delay > max(0.0, deadline - now):
                break
            time.sleep(delay)
            continue
        now = time.monotonic()
        if now >= deadline:
            break
        time.sleep(min(delay, max(0.0, deadline - now)))
    raise PhaseVisibilityError(
        "phase outputs did not become stably visible"
    ) from last_error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument(
        "--section", choices=("collectors", "evaluation_cells"), required=True
    )
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--stability-seconds", type=float, default=1.0)
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    args = parser.parse_args()
    root = args.root
    if not root.is_absolute() or os.path.normpath(os.fspath(root)) != os.fspath(root):
        raise SystemExit("--root must be a normalized absolute path")
    grid_path = args.grid
    if not grid_path.is_absolute() or os.path.normpath(
        os.fspath(grid_path)
    ) != os.fspath(grid_path):
        raise SystemExit("--grid must be a normalized absolute path")
    try:
        grid = json.loads(grid_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot load phase grid: {exc}") from exc
    if not isinstance(grid, dict):
        raise SystemExit("phase grid must be a JSON object")
    required, forbidden = registered_paths(root=root, grid=grid, section=args.section)
    snapshot = wait_for_phase_outputs(
        required=required,
        forbidden=forbidden,
        timeout_seconds=args.timeout_seconds,
        stability_seconds=args.stability_seconds,
        poll_seconds=args.poll_seconds,
    )
    combined = hashlib.sha256()
    for path, record in sorted(snapshot.items()):
        combined.update(path.encode("utf-8"))
        combined.update(repr(record).encode("ascii"))
    print(
        f"PHASE_VISIBILITY_OK section={args.section} "
        f"files={len(snapshot)} sha256={combined.hexdigest()}"
    )


if __name__ == "__main__":
    main()
