"""Prospective, impure publication chain for the non-authorizing Trigger A.

Two modes are deliberately separate:

``preregister_validator_inventory``
    Runs before any causal semantic artifact is opened.  It verifies a clean,
    exact source checkout, binds eight source files, requires an otherwise
    empty structured root, and atomically publishes only the validator
    inventory.

``publish_trigger_a_chain``
    Observes that committed inventory, source-binds every participant, obtains
    a fresh absence attestation, publishes it, calls the pure builder with its
    complete raw evidence interface, calls the independently implemented
    revalidator, and only then publishes the non-authorizing receipt.

The module imports no model, scorer, task, environment, or DGP implementation.
Any post-absence validation failure leaves the absence publication as a poison
marker and never publishes a receipt.  The deterministic absence publication
intent is also the single-winner serialization point, so a second invocation
fails before it can produce a second receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

import cohort_closed_loop_structured_atomic_publish as atomic_publish
import cohort_closed_loop_structured_trigger_absence_adapter as absence_adapter
import cohort_closed_loop_structured_trigger_receipt as receipt_builder
import cohort_closed_loop_structured_trigger_receipt_revalidator as receipt_revalidator

__all__ = (
    "PROSPECTIVE_FINAL_PATHS",
    "PublisherError",
    "prospective_publication_inventory",
    "preregister_validator_inventory",
    "publish_trigger_a_chain",
)


class PublisherError(RuntimeError):
    """Raised when a Trigger-A publication transition fails closed."""


class _RevalidationResult(Protocol):
    attempt_id: str
    trigger_branch: str
    trigger_receipt_sha256: str
    model_calls_authorized: bool
    operational_authorization: bool


INVENTORY_RELATIVE_PATH = "control/trigger_validator_inventory.json"
ABSENCE_RELATIVE_PATH = "control/pretrigger_absence_attestation.json"
RECEIPT_RELATIVE_PATH = "control/trigger_receipt.json"
PROSPECTIVE_FINAL_PATHS = (
    INVENTORY_RELATIVE_PATH,
    ABSENCE_RELATIVE_PATH,
    RECEIPT_RELATIVE_PATH,
)

TRIGGER_A = "causal_valid_no_go"
TRIGGER_RECEIPT_PROTOCOL = "cohort_structured_trigger_receipt_v1"
VALIDATOR_INVENTORY_PROTOCOL = "cohort_structured_trigger_validator_inventory_v1"
SCHEMA_VERSION = 1
REQUIRED_BINDING_IDS = tuple(receipt_builder.REQUIRED_VALIDATOR_BINDING_IDS)

_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_PRODUCTION_ROOT_RE = re.compile(
    r"/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
    r"[0-9a-f]{40}/attempts/attempt-[0-9]{3}\Z"
)
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_DIRECTORY_FLAGS = _READ_FLAGS | os.O_DIRECTORY

_RAW_EVIDENCE_KEYS = frozenset(
    {
        "trigger_execution_seal_bytes",
        "causal_original_decision_bytes",
        "causal_revalidated_decision_bytes",
        "causal_completion_attestation_bytes",
        "causal_revalidation_receipt_bytes",
        "causal_pid_file_bytes",
        "causal_exit_file_bytes",
        "terminal_verifier_execution_plan_bytes",
        "causal_launch_expectation_bytes",
        "causal_inventory_bytes",
        "structured_preregistration_bytes",
    }
)
_SOURCE_KWARG_BY_ID = {
    "causal_completion_attester": "attester_source_bytes",
    "causal_terminal_revalidator": "causal_revalidator_source_bytes",
    "pretrigger_absence_adapter": "pretrigger_absence_adapter_source_bytes",
    "structured_atomic_publisher": "structured_atomic_publisher_source_bytes",
    "trigger_execution_seal_builder": "execution_seal_builder_source_bytes",
    "trigger_receipt_builder": "trigger_receipt_builder_source_bytes",
    "trigger_receipt_publisher": "trigger_receipt_publisher_source_bytes",
    "trigger_receipt_revalidator": "trigger_receipt_revalidator_source_bytes",
}
_LOCAL_MODULE_BY_ID = {
    "pretrigger_absence_adapter": absence_adapter,
    "structured_atomic_publisher": atomic_publish,
    "trigger_receipt_builder": receipt_builder,
    "trigger_receipt_publisher": sys.modules[__name__],
    "trigger_receipt_revalidator": receipt_revalidator,
}


def _default_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_git(repo_root: Path, arguments: tuple[str, ...]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repo_root), *arguments],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PublisherError(f"git verification failed: {' '.join(arguments)}") from exc
    return completed.stdout


@dataclass(frozen=True, slots=True)
class PublisherRuntime:
    """Runtime dependencies; non-default callables are for local tests only."""

    now_utc: Callable[[], str] = _default_now
    git: Callable[[Path, tuple[str, ...]], bytes] = _default_git
    absence: absence_adapter.AbsenceRuntime = field(
        default_factory=absence_adapter.AbsenceRuntime
    )
    build_receipt: Callable[..., bytes] = receipt_builder.build_trigger_a_receipt_bytes
    revalidate_receipt: Callable[..., _RevalidationResult] = (
        receipt_revalidator.validate_trigger_a_receipt_bytes
    )


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PublisherError("canonical JSON encoding failed") from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PublisherError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PublisherError(f"nonfinite JSON constant is forbidden: {value}")


def _parse_canonical(raw: bytes, *, label: str) -> object:
    if type(raw) is not bytes:
        raise PublisherError(f"{label} must be exact bytes")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublisherError(f"{label} is not canonical JSON") from exc
    if raw != _canonical(value):
        raise PublisherError(f"{label} bytes are not canonical")
    return value


def _normalized_absolute(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise PublisherError(f"{label} must be an absolute pathlib.Path")
    normalized = Path(os.path.normpath(os.fspath(path)))
    if normalized != path or normalized == Path("/"):
        raise PublisherError(f"{label} must be normalized and non-root")
    return normalized


def _validate_commit_attempt(source_commit: str, attempt_id: str) -> None:
    if type(source_commit) is not str or _COMMIT_RE.fullmatch(source_commit) is None:
        raise PublisherError("source_commit must be exact 40-hex text")
    if type(attempt_id) is not str or _ATTEMPT_RE.fullmatch(attempt_id) is None:
        raise PublisherError("attempt_id must match attempt-NNN")


def _logical_root(source_commit: str, attempt_id: str) -> str:
    return (
        "/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
        f"{source_commit}/attempts/{attempt_id}"
    )


def _require_nonproduction_test_root(root: Path) -> Path:
    root = _normalized_absolute(root, label="test structured physical root")
    if _PRODUCTION_ROOT_RE.fullmatch(root.as_posix()) is not None:
        raise PublisherError("test runtime is forbidden for a production root")
    return root


def prospective_publication_inventory() -> tuple[tuple[str, str], ...]:
    """Return the complete fixed final/intent/pending path inventory."""

    rows: list[tuple[str, str]] = []
    for final_path in PROSPECTIVE_FINAL_PATHS:
        intent, pending = atomic_publish.publication_sidecar_relative_paths(final_path)
        rows.extend(
            (
                ("final", final_path),
                ("atomic_publication_intent", intent),
                ("atomic_publication_pending_absent", pending),
            )
        )
    return tuple(rows)


def _stable_regular_bytes(path: Path, *, label: str) -> bytes:
    path = _normalized_absolute(path, label=f"{label} path")
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")

    def read_once() -> tuple[bytes, tuple[tuple[int, int], ...], tuple[int, ...]]:
        directory = os.open("/", _DIRECTORY_FLAGS)
        chain: list[tuple[int, int]] = []
        descriptor = -1
        try:
            root_metadata = os.fstat(directory)
            chain.append((root_metadata.st_dev, root_metadata.st_ino))
            for component in path.parts[1:-1]:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=directory)
                os.close(directory)
                directory = child
                metadata = os.fstat(directory)
                chain.append((metadata.st_dev, metadata.st_ino))
            descriptor = os.open(path.name, _READ_FLAGS, dir_fd=directory)
            before = os.fstat(descriptor)
            path_metadata = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (
                path_metadata.st_dev,
                path_metadata.st_ino,
            ):
                raise PublisherError(f"{label} is not a stable regular non-symlink")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor)
            before_fields = tuple(getattr(before, key) for key in stable)
            if before_fields != tuple(getattr(after, key) for key in stable):
                raise PublisherError(f"{label} changed while reading")
            return b"".join(chunks), tuple(chain), before_fields
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory)

    try:
        first = read_once()
        second = read_once()
    except PublisherError:
        raise
    except OSError as exc:
        raise PublisherError(f"anchored source/evidence read failed: {label}") from exc
    if first != second:
        raise PublisherError(f"{label} changed across fresh anchored reads")
    return second[0]


def _module_source_path(binding_id: str) -> Path:
    module = _LOCAL_MODULE_BY_ID[binding_id]
    source = getattr(module, "__file__", None)
    if type(source) is not str:
        raise PublisherError(f"local module path is unavailable: {binding_id}")
    try:
        return Path(source).resolve(strict=True)
    except OSError as exc:
        raise PublisherError(
            f"local module source is unavailable: {binding_id}"
        ) from exc


def _verify_clean_checkout(
    *,
    repo_root: Path,
    source_commit: str,
    source_paths: dict[str, Path],
    runtime: PublisherRuntime,
) -> None:
    repo_root = _normalized_absolute(repo_root, label="repo root")
    try:
        if repo_root.resolve(strict=True) != repo_root:
            raise PublisherError("repo root must be a real non-symlink path")
    except OSError as exc:
        raise PublisherError("repo root cannot be resolved") from exc
    top = (
        runtime.git(repo_root, ("rev-parse", "--show-toplevel")).decode("utf-8").strip()
    )
    head = runtime.git(repo_root, ("rev-parse", "HEAD")).decode("ascii").strip()
    dirty = runtime.git(
        repo_root, ("status", "--porcelain=v1", "--untracked-files=all")
    )
    if top != repo_root.as_posix() or head != source_commit or dirty != b"":
        raise PublisherError("source checkout is not clean at the exact source commit")

    for binding_id in _LOCAL_MODULE_BY_ID:
        path = source_paths[binding_id]
        try:
            relative = path.relative_to(repo_root).as_posix()
        except ValueError as exc:
            raise PublisherError(
                f"local source escapes clean checkout: {binding_id}"
            ) from exc
        tracked = (
            runtime.git(repo_root, ("ls-files", "--error-unmatch", "--", relative))
            .decode("utf-8")
            .strip()
        )
        if tracked != relative:
            raise PublisherError(f"local source is not exactly tracked: {binding_id}")
        committed = runtime.git(
            repo_root, ("cat-file", "blob", f"{source_commit}:{relative}")
        )
        if committed != _stable_regular_bytes(path, label=binding_id):
            raise PublisherError(
                f"local source differs from committed blob: {binding_id}"
            )


def _validated_source_paths(source_paths: dict[str, Path]) -> dict[str, Path]:
    if type(source_paths) is not dict or set(source_paths) != set(REQUIRED_BINDING_IDS):
        raise PublisherError("source path id set differs from the exact eight bindings")
    normalized: dict[str, Path] = {}
    for binding_id in REQUIRED_BINDING_IDS:
        path = _normalized_absolute(source_paths[binding_id], label=binding_id)
        if binding_id in _LOCAL_MODULE_BY_ID and path != _module_source_path(
            binding_id
        ):
            raise PublisherError(f"registered local source path differs: {binding_id}")
        normalized[binding_id] = path
    if len(set(normalized.values())) != len(normalized):
        raise PublisherError("validator source paths must be unique")
    return normalized


def _preregister_validator_inventory_impl(
    *,
    root: Path,
    repo_root: Path,
    source_commit: str,
    attempt_id: str,
    source_paths: dict[str, Path],
    runtime: PublisherRuntime,
) -> atomic_publish.PublishedArtifactObservation:
    """Implement Mode A using an already selected runtime."""

    _validate_commit_attempt(source_commit, attempt_id)
    root = _normalized_absolute(root, label="structured physical root")
    paths = _validated_source_paths(source_paths)
    _verify_clean_checkout(
        repo_root=repo_root,
        source_commit=source_commit,
        source_paths=paths,
        runtime=runtime,
    )
    source_raw = {
        binding_id: _stable_regular_bytes(path, label=binding_id)
        for binding_id, path in paths.items()
    }
    records = [
        {
            "binding_id": binding_id,
            "path": paths[binding_id].as_posix(),
            "sha256": _sha(source_raw[binding_id]),
            "size_bytes": len(source_raw[binding_id]),
        }
        for binding_id in REQUIRED_BINDING_IDS
    ]
    created_at = runtime.now_utc()
    if type(created_at) is not str or _UTC_RE.fullmatch(created_at) is None:
        raise PublisherError("inventory clock did not return canonical UTC seconds")
    try:
        inventory_raw = receipt_builder.build_trigger_validator_inventory_bytes(
            binding_records_bytes=_canonical(records),
            tooling_source_commit=source_commit,
            created_at_utc=created_at,
        )
        absence_adapter.validate_preinventory_root(
            root=root,
            structured_durable_root=_logical_root(source_commit, attempt_id),
            source_commit=source_commit,
            attempt_id=attempt_id,
            runtime=runtime.absence,
        )
        observation = atomic_publish.publish_readonly_no_overwrite(
            root=root,
            relative_path=INVENTORY_RELATIVE_PATH,
            payload=inventory_raw,
        )
        atomic_publish.read_and_validate_readonly_artifact(
            root=root,
            relative_path=INVENTORY_RELATIVE_PATH,
            expected_payload=inventory_raw,
        )
        return observation
    except (ValueError, RuntimeError, OSError) as exc:
        if isinstance(exc, PublisherError):
            raise
        raise PublisherError("validator inventory publication failed closed") from exc


def _preregister_validator_inventory_for_test(
    *,
    root: Path,
    repo_root: Path,
    source_commit: str,
    attempt_id: str,
    source_paths: dict[str, Path],
    runtime: PublisherRuntime,
) -> atomic_publish.PublishedArtifactObservation:
    """Test-only Mode A entrypoint, forbidden for the production root grammar."""

    return _preregister_validator_inventory_impl(
        root=_require_nonproduction_test_root(root),
        repo_root=repo_root,
        source_commit=source_commit,
        attempt_id=attempt_id,
        source_paths=source_paths,
        runtime=runtime,
    )


def preregister_validator_inventory(
    *,
    root: Path,
    repo_root: Path,
    source_commit: str,
    attempt_id: str,
    source_paths: dict[str, Path],
    runtime: PublisherRuntime | None = None,
) -> atomic_publish.PublishedArtifactObservation:
    """Mode A production entrypoint; runtime injection is always forbidden."""

    if runtime is not None:
        raise PublisherError("public production API forbids runtime injection")
    return _preregister_validator_inventory_impl(
        root=root,
        repo_root=repo_root,
        source_commit=source_commit,
        attempt_id=attempt_id,
        source_paths=source_paths,
        runtime=PublisherRuntime(),
    )


def _parse_inventory(
    raw: bytes,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    value = _parse_canonical(raw, label="trigger validator inventory")
    if type(value) is not dict:
        raise PublisherError("trigger validator inventory must be an object")
    required = {
        "protocol",
        "schema_version",
        "status",
        "tooling_source_commit",
        "bindings",
        "created_at_utc",
        "operational_authorization",
        "binding_inventory_sha256",
    }
    if set(value) != required or type(value["bindings"]) is not list:
        raise PublisherError("trigger validator inventory exact schema differs")
    rows = value["bindings"]
    records_raw = _canonical(rows)
    try:
        rebuilt = receipt_builder.build_trigger_validator_inventory_bytes(
            binding_records_bytes=records_raw,
            tooling_source_commit=value["tooling_source_commit"],
            created_at_utc=value["created_at_utc"],
        )
    except (TypeError, ValueError) as exc:
        raise PublisherError("trigger validator inventory validation failed") from exc
    if rebuilt != raw:
        raise PublisherError("trigger validator inventory reconstruction differs")
    by_id = {str(row["binding_id"]): row for row in rows}
    return value, by_id


def _load_registered_sources(
    *, inventory_raw: bytes
) -> tuple[dict[str, object], dict[str, bytes]]:
    inventory, by_id = _parse_inventory(inventory_raw)
    source_raw: dict[str, bytes] = {}
    for binding_id in REQUIRED_BINDING_IDS:
        row = by_id[binding_id]
        path = Path(str(row["path"]))
        if binding_id in _LOCAL_MODULE_BY_ID and path != _module_source_path(
            binding_id
        ):
            raise PublisherError(f"registered local source path differs: {binding_id}")
        raw = _stable_regular_bytes(path, label=binding_id)
        if _sha(raw) != row["sha256"] or len(raw) != row["size_bytes"]:
            raise PublisherError(f"registered source bytes drifted: {binding_id}")
        source_raw[binding_id] = raw
    return inventory, source_raw


def _load_raw_evidence(paths: dict[str, Path]) -> dict[str, bytes]:
    if type(paths) is not dict or set(paths) != _RAW_EVIDENCE_KEYS:
        raise PublisherError("raw evidence path id set differs")
    return {
        key: _stable_regular_bytes(paths[key], label=key)
        for key in sorted(_RAW_EVIDENCE_KEYS)
    }


def _validate_receipt_result(
    *, receipt_raw: bytes, result: _RevalidationResult, attempt_id: str
) -> None:
    value = _parse_canonical(receipt_raw, label="Trigger-A receipt")
    if type(value) is not dict:
        raise PublisherError("Trigger-A receipt must be an object")
    if (
        value.get("protocol") != TRIGGER_RECEIPT_PROTOCOL
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") != "validated_non_authorizing"
        or value.get("attempt_id") != attempt_id
        or value.get("trigger_branch") != TRIGGER_A
        or type(value.get("trigger_receipt_sha256")) is not str
        or _SHA256_RE.fullmatch(str(value.get("trigger_receipt_sha256"))) is None
    ):
        raise PublisherError("Trigger-A receipt top-level contract differs")
    if (
        result.attempt_id != attempt_id
        or result.trigger_branch != TRIGGER_A
        or result.trigger_receipt_sha256 != value["trigger_receipt_sha256"]
        or result.model_calls_authorized is not False
        or result.operational_authorization is not False
    ):
        raise PublisherError("independent Trigger-A revalidation result differs")


def _publish_trigger_a_chain_impl(
    *,
    root: Path,
    source_commit: str,
    attempt_id: str,
    raw_evidence_paths: dict[str, Path],
    runtime: PublisherRuntime,
) -> atomic_publish.PublishedArtifactObservation:
    """Implement Mode B using an already selected runtime."""

    _validate_commit_attempt(source_commit, attempt_id)
    root = _normalized_absolute(root, label="structured physical root")
    logical_root = _logical_root(source_commit, attempt_id)

    try:
        inventory_raw, _ = atomic_publish.read_and_validate_readonly_artifact(
            root=root, relative_path=INVENTORY_RELATIVE_PATH
        )
        inventory, source_raw = _load_registered_sources(inventory_raw=inventory_raw)
        if inventory["tooling_source_commit"] != source_commit:
            raise PublisherError("inventory/source commit join differs")
        raw_evidence = _load_raw_evidence(raw_evidence_paths)

        absence_raw = absence_adapter.attest_pretrigger_absence(
            root=root,
            structured_durable_root=logical_root,
            source_commit=source_commit,
            attempt_id=attempt_id,
            trigger_execution_seal_bytes=raw_evidence["trigger_execution_seal_bytes"],
            trigger_validator_inventory_bytes=inventory_raw,
            runtime=runtime.absence,
        )
        absence_value = _parse_canonical(
            absence_raw, label="pretrigger absence attestation"
        )
        if type(absence_value) is not dict:
            raise PublisherError("pretrigger absence attestation must be an object")
        created_at = absence_value.get("receipt_created_at_utc")
        if type(created_at) is not str or _UTC_RE.fullmatch(created_at) is None:
            raise PublisherError("pretrigger absence timestamp differs")

        atomic_publish.publish_readonly_no_overwrite(
            root=root,
            relative_path=ABSENCE_RELATIVE_PATH,
            payload=absence_raw,
        )

        builder_kwargs: dict[str, object] = dict(raw_evidence)
        builder_kwargs["trigger_validator_inventory_bytes"] = inventory_raw
        for binding_id, kwarg in _SOURCE_KWARG_BY_ID.items():
            builder_kwargs[kwarg] = source_raw[binding_id]
        builder_kwargs["pretrigger_absence_evidence_bytes"] = absence_raw
        builder_kwargs["structured_attempt_id"] = attempt_id
        builder_kwargs["created_at_utc"] = created_at
        receipt_raw = runtime.build_receipt(**builder_kwargs)
        if type(receipt_raw) is not bytes or not receipt_raw:
            raise PublisherError(
                "Trigger-A builder did not return nonempty exact bytes"
            )

        revalidator_kwargs = {
            key: value
            for key, value in builder_kwargs.items()
            if key not in {"structured_attempt_id", "created_at_utc"}
        }
        result = runtime.revalidate_receipt(receipt_raw, **revalidator_kwargs)
        _validate_receipt_result(
            receipt_raw=receipt_raw, result=result, attempt_id=attempt_id
        )

        # Reobserve the immutable upstreams and the exact post-absence tree
        # immediately before the receipt's no-replace publication.
        atomic_publish.read_and_validate_readonly_artifact(
            root=root,
            relative_path=INVENTORY_RELATIVE_PATH,
            expected_payload=inventory_raw,
        )
        atomic_publish.read_and_validate_readonly_artifact(
            root=root,
            relative_path=ABSENCE_RELATIVE_PATH,
            expected_payload=absence_raw,
        )
        _, reread_sources = _load_registered_sources(inventory_raw=inventory_raw)
        if reread_sources != source_raw:
            raise PublisherError(
                "registered source bytes changed before receipt commit"
            )
        reread_evidence = _load_raw_evidence(raw_evidence_paths)
        if reread_evidence != raw_evidence:
            raise PublisherError("raw causal evidence changed before receipt commit")
        absence_adapter.validate_prereceipt_root_after_absence(
            root=root,
            structured_durable_root=logical_root,
            source_commit=source_commit,
            attempt_id=attempt_id,
            expected_root_identity=absence_value["filesystem_root_identity"],
            runtime=runtime.absence,
        )
        observation = atomic_publish.publish_readonly_no_overwrite(
            root=root,
            relative_path=RECEIPT_RELATIVE_PATH,
            payload=receipt_raw,
        )
        atomic_publish.read_and_validate_readonly_artifact(
            root=root,
            relative_path=RECEIPT_RELATIVE_PATH,
            expected_payload=receipt_raw,
        )
        return observation
    except PublisherError:
        raise
    except (ValueError, RuntimeError, OSError) as exc:
        raise PublisherError("Trigger-A publication chain failed closed") from exc


def _publish_trigger_a_chain_for_test(
    *,
    root: Path,
    source_commit: str,
    attempt_id: str,
    raw_evidence_paths: dict[str, Path],
    runtime: PublisherRuntime,
) -> atomic_publish.PublishedArtifactObservation:
    """Test-only Mode B entrypoint, forbidden for the production root grammar."""

    return _publish_trigger_a_chain_impl(
        root=_require_nonproduction_test_root(root),
        source_commit=source_commit,
        attempt_id=attempt_id,
        raw_evidence_paths=raw_evidence_paths,
        runtime=runtime,
    )


def publish_trigger_a_chain(
    *,
    root: Path,
    source_commit: str,
    attempt_id: str,
    raw_evidence_paths: dict[str, Path],
    runtime: PublisherRuntime | None = None,
) -> atomic_publish.PublishedArtifactObservation:
    """Mode B production entrypoint; runtime injection is always forbidden."""

    if runtime is not None:
        raise PublisherError("public production API forbids runtime injection")
    return _publish_trigger_a_chain_impl(
        root=root,
        source_commit=source_commit,
        attempt_id=attempt_id,
        raw_evidence_paths=raw_evidence_paths,
        runtime=PublisherRuntime(),
    )


def _binding_arguments(namespace: argparse.Namespace) -> dict[str, Path]:
    return {
        binding_id: Path(getattr(namespace, binding_id))
        for binding_id in REQUIRED_BINDING_IDS
    }


def _evidence_arguments(namespace: argparse.Namespace) -> dict[str, Path]:
    return {
        key: Path(getattr(namespace, key.removesuffix("_bytes")))
        for key in _RAW_EVIDENCE_KEYS
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    register = subparsers.add_parser("register-inventory", allow_abbrev=False)
    register.add_argument("--root", required=True)
    register.add_argument("--repo-root", required=True)
    register.add_argument("--source-commit", required=True)
    register.add_argument("--attempt-id", required=True)
    for binding_id in REQUIRED_BINDING_IDS:
        register.add_argument(f"--{binding_id.replace('_', '-')}", required=True)

    publish = subparsers.add_parser("publish-trigger-a", allow_abbrev=False)
    publish.add_argument("--root", required=True)
    publish.add_argument("--source-commit", required=True)
    publish.add_argument("--attempt-id", required=True)
    for key in sorted(_RAW_EVIDENCE_KEYS):
        argument = key.removesuffix("_bytes").replace("_", "-")
        publish.add_argument(f"--{argument}", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    namespace = _parser().parse_args(argv)
    if namespace.mode == "register-inventory":
        preregister_validator_inventory(
            root=Path(namespace.root),
            repo_root=Path(namespace.repo_root),
            source_commit=namespace.source_commit,
            attempt_id=namespace.attempt_id,
            source_paths=_binding_arguments(namespace),
        )
    elif namespace.mode == "publish-trigger-a":
        publish_trigger_a_chain(
            root=Path(namespace.root),
            source_commit=namespace.source_commit,
            attempt_id=namespace.attempt_id,
            raw_evidence_paths=_evidence_arguments(namespace),
        )
    else:  # pragma: no cover - argparse closes the mode set.
        raise AssertionError("unknown publisher mode")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
