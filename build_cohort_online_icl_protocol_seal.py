#!/usr/bin/env python3
"""Build or verify the immutable pre-outcome Cohort online-ICL protocol seal.

The seal is deliberately separate from the Git-tracked grids and runtime
provenance.  It is created only after both are final, binds both the smoke and
formal grids, and is then reused byte-for-byte for every online-ICL cell.  The
output is canonical JSON, atomically published, and never overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

from build_cohort_online_icl_provenance import (
    ONLINE_ICL_PROTOCOL,
    REQUIRED_PROVENANCE_FIELDS,
)


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
SEAL_KIND = "cohort_online_icl_protocol_seal"
GRID_FILENAMES = {
    "smoke": "grid_cohort_online_icl_smoke.json",
    "formal": "grid_cohort_online_icl_formal.json",
}
PROVENANCE_BINDING_FIELDS = (
    "environment_lock_sha256",
    "evaluation_code_sha256",
    "icl_prereg_sha256",
    "model_path",
    "model_sha256",
    "shared_causal_code_sha256",
    "source_commit",
    "tokenizer_sha256",
)
# These are the fields whose equality with the paired causal provenance is
# checked by the three-arm validator.  Recording them explicitly makes that
# shared-parity surface inspectable even though the canonical provenance digest
# already binds every field.
SHARED_PARITY_FIELDS = (
    "base_causal_commit",
    "environment_lock_sha256",
    "model_path",
    "model_sha256",
    "shared_causal_code_sha256",
    "tokenizer_sha256",
)
_SHA256_FIELDS = frozenset(
    {
        "environment_lock_sha256",
        "evaluation_code_sha256",
        "icl_prereg_sha256",
        "model_sha256",
        "shared_causal_code_sha256",
        "tokenizer_sha256",
    }
)


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
        raise ValueError(
            "protocol-seal payload is not canonical-JSON encodable"
        ) from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_object(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    value = json.loads(path.read_text(), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _validate_provenance(provenance: dict[str, Any]) -> None:
    if set(provenance) != set(REQUIRED_PROVENANCE_FIELDS):
        raise ValueError("online-ICL provenance field schema mismatch")
    if provenance.get("protocol") != ONLINE_ICL_PROTOCOL:
        raise ValueError("online-ICL provenance protocol mismatch")
    for field in _SHA256_FIELDS:
        if not _is_lower_hex(provenance.get(field), 64):
            raise ValueError(f"invalid provenance SHA-256 field: {field}")
    for field in ("base_causal_commit", "source_commit"):
        if not _is_lower_hex(provenance.get(field), 40):
            raise ValueError(f"invalid provenance commit field: {field}")
    if (
        not isinstance(provenance.get("model_path"), str)
        or not provenance["model_path"]
    ):
        raise ValueError("invalid provenance model_path")


def _grid_binding(path: Path, *, kind: str) -> dict[str, Any]:
    path = path.resolve()
    expected_name = GRID_FILENAMES[kind]
    if path.name != expected_name:
        raise ValueError(f"{kind} grid must use registered filename {expected_name!r}")
    grid = _load_object(path)
    if grid.get("protocol") != ONLINE_ICL_PROTOCOL or grid.get("kind") != kind:
        raise ValueError(f"{kind} grid identity mismatch")
    embedded = grid.get("grid_sha256")
    without_digest = deepcopy(grid)
    without_digest.pop("grid_sha256", None)
    calculated = canonical_sha256(without_digest)
    if embedded != calculated:
        raise ValueError(f"{kind} grid canonical digest mismatch")
    return {
        "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "grid_sha256": embedded,
        "path": expected_name,
    }


def create_protocol_seal(
    *,
    provenance: dict[str, Any],
    smoke_grid_path: Path,
    formal_grid_path: Path,
) -> dict[str, Any]:
    """Create a deterministic outcome-free seal without writing it."""

    _validate_provenance(provenance)
    payload: dict[str, Any] = {
        "grids": {
            "formal": _grid_binding(formal_grid_path, kind="formal"),
            "smoke": _grid_binding(smoke_grid_path, kind="smoke"),
        },
        "kind": SEAL_KIND,
        "protocol": ONLINE_ICL_PROTOCOL,
        "provenance_bindings": {
            field: provenance[field] for field in PROVENANCE_BINDING_FIELDS
        },
        "provenance_sha256": canonical_sha256(provenance),
        "schema_version": SCHEMA_VERSION,
        "shared_parity_bindings": {
            field: provenance[field]
            for field in SHARED_PARITY_FIELDS
            if field in provenance
        },
    }
    payload["protocol_seal_sha256"] = canonical_sha256(payload)
    return payload


def load_protocol_seal(path: Path) -> dict[str, Any]:
    """Load a seal and reject schema, digest, or canonicalization drift."""

    seal = _load_object(path)
    expected_keys = {
        "grids",
        "kind",
        "protocol",
        "protocol_seal_sha256",
        "provenance_bindings",
        "provenance_sha256",
        "schema_version",
        "shared_parity_bindings",
    }
    if set(seal) != expected_keys:
        raise ValueError("online-ICL protocol-seal field schema mismatch")
    if (
        seal.get("kind") != SEAL_KIND
        or seal.get("protocol") != ONLINE_ICL_PROTOCOL
        or seal.get("schema_version") != SCHEMA_VERSION
    ):
        raise ValueError("online-ICL protocol-seal identity mismatch")
    embedded = seal.get("protocol_seal_sha256")
    without_digest = deepcopy(seal)
    without_digest.pop("protocol_seal_sha256")
    if not _is_lower_hex(embedded, 64) or embedded != canonical_sha256(without_digest):
        raise ValueError("online-ICL protocol-seal digest mismatch")
    return seal


def verify_protocol_seal(
    *,
    seal: dict[str, Any],
    provenance: dict[str, Any],
    smoke_grid_path: Path,
    formal_grid_path: Path,
) -> str:
    """Recompute every seal binding and return the immutable seal digest."""

    # Validate an in-memory payload through the same strict schema/digest path
    # without introducing a temporary artifact.
    expected = create_protocol_seal(
        provenance=provenance,
        smoke_grid_path=smoke_grid_path,
        formal_grid_path=formal_grid_path,
    )
    if _canonical_bytes(seal) != _canonical_bytes(expected):
        raise ValueError("protocol seal differs from current provenance or grids")
    return expected["protocol_seal_sha256"]


def _publish_atomic_no_overwrite(path: Path, payload: bytes) -> None:
    requested = path.expanduser()
    requested.parent.mkdir(parents=True, exist_ok=True)
    path = requested.parent.resolve() / requested.name
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.tmp."
    )
    temporary = Path(temporary_name)
    linked = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
            linked = True
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to overwrite protocol seal: {path}"
            ) from exc
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if linked:
            path.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def write_protocol_seal(*, output: Path, seal: dict[str, Any]) -> None:
    """Atomically publish the canonical seal as a no-overwrite artifact."""

    embedded = seal.get("protocol_seal_sha256")
    without_digest = deepcopy(seal)
    without_digest.pop("protocol_seal_sha256", None)
    if embedded != canonical_sha256(without_digest):
        raise ValueError("refusing to write an invalid protocol seal")
    _publish_atomic_no_overwrite(output, _canonical_bytes(seal) + b"\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--smoke-grid", type=Path)
    parser.add_argument("--formal-grid", type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path)
    action.add_argument("--verify", type=Path, metavar="SEAL")
    args = parser.parse_args()

    root = args.root.resolve()
    smoke_grid = (
        args.smoke_grid.resolve()
        if args.smoke_grid is not None
        else root / GRID_FILENAMES["smoke"]
    )
    formal_grid = (
        args.formal_grid.resolve()
        if args.formal_grid is not None
        else root / GRID_FILENAMES["formal"]
    )

    from build_cohort_online_icl_provenance import verify_current_provenance

    provenance = _load_object(args.provenance.resolve())
    _validate_provenance(provenance)
    verify_current_provenance(
        root=root,
        provenance=provenance,
        expected_model_path=Path(provenance["model_path"]),
    )
    if args.output is not None:
        seal = create_protocol_seal(
            provenance=provenance,
            smoke_grid_path=smoke_grid,
            formal_grid_path=formal_grid,
        )
        write_protocol_seal(output=args.output, seal=seal)
        print(json.dumps(seal, indent=2, sort_keys=True))
        return

    seal = load_protocol_seal(args.verify.resolve())
    digest = verify_protocol_seal(
        seal=seal,
        provenance=provenance,
        smoke_grid_path=smoke_grid,
        formal_grid_path=formal_grid,
    )
    print(f"COHORT_ONLINE_ICL_PROTOCOL_SEAL_OK sha256={digest}")


if __name__ == "__main__":
    main()
