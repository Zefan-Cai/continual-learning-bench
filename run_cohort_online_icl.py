#!/usr/bin/env python3
"""Run one preregistered Cohort reward-aware online-ICL cell.

Each cell performs a full online adaptation rollout, irreversibly seals the
resulting ICL context, and evaluates the held-out corpus while restoring the
same sealed snapshot after every completed condition. All artifacts are atomic
and no-overwrite so retries cannot silently mix attempts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sqlite3
import statistics
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from run_cohort_causal import (
    _absolute_task_params,
    _assert_outcome_identity,
    _assert_outcome_order_matches_corpus,
    _build_trace_recorder,
    _canonical_bytes,
    _heldout_rows,
    _resolve,
    seed_everything,
)
from validate_cohort_causal_results import canonical_sha256


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
PROTOCOL = "cohort_reward_aware_online_icl_v1"
ARM = "online_icl"

_MANIFEST_FIELDS = {
    "artifacts",
    "builder",
    "corpus_sha256",
    "instances",
    "manifest_version",
    "n_instances",
    "patient_ids_hash_encoding",
    "population_size",
    "runtime",
    "schedule_id",
    "schedule_sha256",
    "seed",
    "seed_derivation",
    "source_sha256",
}
_MANIFEST_INSTANCE_FIELDS = {
    "db_seed",
    "db_sha256",
    "instance_index",
    "patient_ids_sha256",
    "split_index",
    "variant_id",
}
_METADATA_FIELDS = {
    "instances",
    "n_instances",
    "population_size",
    "schedule_id",
    "schema_version",
    "seed",
}
_METADATA_INSTANCE_FIELDS = {
    "db_filename",
    "db_sha256",
    "instance_index",
    "n_patients",
    "region_slice",
    "stage_index",
    "study_name",
    "variant_id",
}
_SAFE_SCHEDULE_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")
_DB_SEED_NAMESPACE = "clbench:cohort-studies:db:v1"


def _json_no_duplicates(raw: bytes, *, where: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{where} contains duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{where} is not valid UTF-8 JSON") from exc


def _assert_exact_keys(value: Any, expected: set[str], *, where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        actual = set(value) if isinstance(value, dict) else set()
        raise ValueError(
            f"{where} schema mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _assert_no_symlink_components(root: Path, path: Path, *, where: str) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{where} escapes the registered root") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"{where} contains a symlink component: {cursor}")


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _cohort_instance_id(schedule_id: str, variant_id: str) -> str:
    """Mirror the shared task's legacy default-schedule identity contract."""

    if schedule_id == "default":
        return f"cohort_studies:{variant_id}"
    return f"cohort_studies:{schedule_id}:{variant_id}"


def _inspect_frozen_database_bytes(
    raw: bytes,
) -> tuple[list[int], list[str], list[Any]]:
    """Read semantic DB bindings from the exact bytes already hash-verified."""

    with tempfile.TemporaryDirectory(prefix="cohort-online-icl-db-audit-") as scratch:
        audit_path = Path(scratch) / "verified.db"
        audit_path.write_bytes(raw)
        audit_path.chmod(0o400)
        database_uri = audit_path.as_uri() + "?mode=ro&immutable=1"
        with sqlite3.connect(database_uri, uri=True) as connection:
            connection.execute("PRAGMA query_only=ON")
            patient_ids = [
                row[0]
                for row in connection.execute(
                    "SELECT patient_id FROM patients ORDER BY patient_id"
                )
            ]
            db_regions = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT region FROM patients ORDER BY region"
                )
            ]
            study_info_rows = list(
                connection.execute(
                    "SELECT value FROM _study_info WHERE key = 'study_name'"
                )
            )
    return patient_ids, db_regions, study_info_rows


def _load_verified_dataset_bundle(
    root: Path, grid: dict[str, Any], role: str
) -> dict[str, Any]:
    """Verify one registered corpus byte-for-byte without causal-DGP constants."""

    if role not in {"adaptation", "heldout"}:
        raise ValueError(f"unknown online-ICL corpus role: {role}")
    dataset = grid.get("datasets", {}).get(role)
    if not isinstance(dataset, dict) or set(dataset) != {
        "corpus_sha256",
        "path",
        "schedule",
        "schedule_sha256",
        "seed",
    }:
        raise ValueError(f"{role} registered dataset contract is malformed")
    if (
        not isinstance(dataset["path"], str)
        or not dataset["path"]
        or Path(dataset["path"]).is_absolute()
        or ".." in Path(dataset["path"]).parts
        or not isinstance(dataset["schedule"], str)
        or not dataset["schedule"]
        or _SAFE_SCHEDULE_RE.fullmatch(dataset["schedule"]) is None
        or isinstance(dataset["seed"], bool)
        or not isinstance(dataset["seed"], int)
        or not _is_sha256(dataset["corpus_sha256"])
        or not _is_sha256(dataset["schedule_sha256"])
    ):
        raise ValueError(f"{role} registered dataset identity is invalid")

    root = root.resolve()
    requested_dataset_dir = root / dataset["path"]
    _assert_no_symlink_components(
        root, requested_dataset_dir, where=f"{role} dataset path"
    )
    dataset_dir = requested_dataset_dir.resolve()
    try:
        dataset_dir.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{role} dataset path escapes the registered root") from exc
    manifest_path = dataset_dir / "manifest.json"
    _assert_no_symlink_components(root, manifest_path, where=f"{role} manifest path")
    manifest_bytes = manifest_path.read_bytes()
    manifest = _assert_exact_keys(
        _json_no_duplicates(manifest_bytes, where=f"{role} manifest"),
        _MANIFEST_FIELDS,
        where=f"{role} manifest",
    )
    expected_manifest_fields = {
        "corpus_sha256": dataset["corpus_sha256"],
        "n_instances": 20,
        "schedule_id": dataset["schedule"],
        "schedule_sha256": dataset["schedule_sha256"],
        "seed": dataset["seed"],
    }
    for field, expected_value in expected_manifest_fields.items():
        if manifest.get(field) != expected_value:
            raise ValueError(f"{role} dataset manifest {field} drift")
    if (
        manifest["manifest_version"] != 1
        or manifest["builder"] != "experiments/cohort_studies/build_frozen_dataset.py"
        or manifest["patient_ids_hash_encoding"] != "concatenated big-endian uint64"
        or isinstance(manifest["population_size"], bool)
        or not isinstance(manifest["population_size"], int)
        or manifest["population_size"] <= 0
    ):
        raise ValueError(f"{role} dataset manifest static contract drift")
    runtime = _assert_exact_keys(
        manifest["runtime"],
        {"numpy", "python", "sqlite"},
        where=f"{role} manifest runtime",
    )
    if any(
        not isinstance(runtime[field], str) or not runtime[field] for field in runtime
    ):
        raise ValueError(f"{role} dataset build runtime is invalid")
    seed_derivation = _assert_exact_keys(
        manifest["seed_derivation"],
        {"database", "population", "study_sample"},
        where=f"{role} manifest seed derivation",
    )
    expected_seed_derivation = {
        "database": (
            "uint64_be(first_8_bytes(sha256("
            "f'clbench:cohort-studies:db:v1:{base_seed}:{schedule_id}:{variant_id}')))"
        ),
        "population": "numpy.default_rng(base_seed)",
        "study_sample": (
            "uint32_be(first_4_bytes(sha256(f'{base_seed}:{study_name}')))"
        ),
    }
    if seed_derivation != expected_seed_derivation:
        raise ValueError(f"{role} dataset seed derivation is invalid")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError(f"{role} dataset manifest has no artifact inventory")
    artifact_bytes: dict[str, bytes] = {}
    seen_paths: set[str] = set()
    dataset_root = dataset_dir.resolve()
    for position, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or set(artifact) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ValueError(f"{role} dataset artifact {position} schema drift")
        relative_value = artifact["path"]
        if not isinstance(relative_value, str) or not relative_value:
            raise ValueError(f"{role} dataset artifact {position} path is invalid")
        relative = Path(relative_value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"{role} dataset artifact path escapes its corpus")
        requested_artifact_path = dataset_dir / relative
        _assert_no_symlink_components(
            root,
            requested_artifact_path,
            where=f"{role} dataset artifact {relative_value}",
        )
        artifact_path = requested_artifact_path.resolve()
        try:
            artifact_path.relative_to(dataset_root)
        except ValueError as exc:
            raise ValueError(
                f"{role} dataset artifact path escapes its corpus"
            ) from exc
        if relative_value in seen_paths:
            raise ValueError(f"{role} dataset artifact path is duplicated")
        seen_paths.add(relative_value)
        expected_size = artifact["size_bytes"]
        expected_sha256 = artifact["sha256"]
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or not _is_sha256(expected_sha256)
        ):
            raise ValueError(f"{role} dataset artifact metadata is invalid")
        raw = artifact_path.read_bytes()
        if len(raw) != expected_size:
            raise ValueError(f"{role} dataset artifact size drift: {relative_value}")
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError(f"{role} dataset artifact hash drift: {relative_value}")
        if relative.suffix == ".json":
            _json_no_duplicates(raw, where=f"{role} artifact {relative_value}")
        artifact_bytes[relative_value] = raw
    dataset_entries = list(dataset_root.rglob("*"))
    unexpected_symlinks = [path for path in dataset_entries if path.is_symlink()]
    if unexpected_symlinks:
        raise ValueError(f"{role} dataset contains an unregistered symlink")
    actual_files = {
        path.relative_to(dataset_root).as_posix()
        for path in dataset_entries
        if path.is_file() and path != manifest_path
    }
    if actual_files != seen_paths:
        raise ValueError(f"{role} dataset file inventory differs from its manifest")
    if canonical_sha256(artifacts) != manifest["corpus_sha256"]:
        raise ValueError(f"{role} dataset corpus inventory digest drift")

    source_sha256 = manifest.get("source_sha256")
    schedule_relative = f"src/tasks/cohort_studies/schedules/{dataset['schedule']}.json"
    expected_source_paths = {
        "experiments/cohort_studies/build_frozen_dataset.py",
        "src/tasks/cohort_studies/dgp.py",
        "src/tasks/cohort_studies/frozen_db.py",
        schedule_relative,
        "src/tasks/cohort_studies/scoring_cohorts.py",
        "src/tasks/cohort_studies/study_configs.py",
    }
    if (
        not isinstance(source_sha256, dict)
        or set(source_sha256) != expected_source_paths
    ):
        raise ValueError(f"{role} dataset source inventory schema drift")
    for relative_value, expected_sha256 in source_sha256.items():
        relative = Path(relative_value) if isinstance(relative_value, str) else Path()
        if (
            not isinstance(relative_value, str)
            or not relative_value
            or relative.is_absolute()
            or ".." in relative.parts
            or not _is_sha256(expected_sha256)
        ):
            raise ValueError(f"{role} dataset source inventory is malformed")
        requested_source_path = root / relative
        _assert_no_symlink_components(
            root, requested_source_path, where=f"{role} dataset source {relative_value}"
        )
        source_path = requested_source_path.resolve()
        try:
            source_path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"{role} dataset source path escapes the root") from exc
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != expected_sha256:
            raise ValueError(f"{role} dataset source bytes drift: {relative_value}")

    schedule_path = root / schedule_relative
    _assert_no_symlink_components(root, schedule_path, where=f"{role} schedule path")
    schedule_bytes = schedule_path.read_bytes()
    if (
        hashlib.sha256(schedule_bytes).hexdigest() != dataset["schedule_sha256"]
        or source_sha256[schedule_relative] != dataset["schedule_sha256"]
    ):
        raise ValueError(f"{role} registered schedule bytes drift")
    schedule = _json_no_duplicates(schedule_bytes, where=f"{role} schedule")
    if not isinstance(schedule, dict) or schedule.get("id") != dataset["schedule"]:
        raise ValueError(f"{role} registered schedule identity drift")

    stages = schedule.get("stages")
    if not isinstance(stages, list) or not stages:
        raise ValueError(f"{role} registered schedule has no stages")
    scheduled_instances: list[dict[str, Any]] = []
    for stage_position, stage in enumerate(stages, start=1):
        if not isinstance(stage, dict):
            raise ValueError(f"{role} schedule stage {stage_position} is malformed")
        stage_schedule = stage.get("schedule")
        stage_variant = stage.get("variant")
        if not isinstance(stage_schedule, dict):
            raise ValueError(
                f"{role} schedule stage {stage_position} has no instance schedule"
            )
        if (
            not isinstance(stage_variant, str)
            or not stage_variant
            or _SAFE_SCHEDULE_RE.fullmatch(stage_variant) is None
        ):
            raise ValueError(
                f"{role} schedule stage {stage_position} study identity is invalid"
            )
        regions = stage_schedule.get("regions")
        if (
            not isinstance(regions, list)
            or isinstance(stage_schedule.get("num_instances"), bool)
            or not isinstance(stage_schedule.get("num_instances"), int)
            or stage_schedule["num_instances"] != len(regions)
        ):
            raise ValueError(
                f"{role} schedule stage {stage_position} instance count drift"
            )
        region_occurrences: dict[tuple[str, ...], int] = {}
        for region_position, region in enumerate(regions):
            variant_id = region.get("variant_id") if isinstance(region, dict) else None
            region_values = region.get("regions") if isinstance(region, dict) else None
            if (
                not isinstance(variant_id, str)
                or not variant_id
                or _SAFE_SCHEDULE_RE.fullmatch(variant_id) is None
                or not isinstance(region_values, list)
                or not region_values
                or any(
                    not isinstance(value, str) or not value for value in region_values
                )
            ):
                raise ValueError(
                    f"{role} schedule stage {stage_position} region "
                    f"{region_position} identity is invalid"
                )
            region_key = tuple(region_values)
            split_index = region_occurrences.get(region_key, 0) + 1
            region_occurrences[region_key] = split_index
            scheduled_instances.append(
                {
                    "region_slice": "+".join(region_values),
                    "regions": region_values,
                    "split_index": split_index,
                    "stage_index": stage_position,
                    "study_name": stage_variant.upper(),
                    "variant_id": variant_id,
                }
            )
        if set(region_occurrences.values()) != {2}:
            raise ValueError(
                f"{role} schedule stage {stage_position} must contain two draws "
                "per region slice"
            )
    scheduled_variant_ids = [row["variant_id"] for row in scheduled_instances]
    if len(scheduled_instances) != 20 or len(set(scheduled_variant_ids)) != 20:
        raise ValueError(f"{role} registered schedule must name 20 unique instances")

    if "metadata.json" not in artifact_bytes:
        raise ValueError(f"{role} dataset metadata artifact is missing")
    metadata = _assert_exact_keys(
        _json_no_duplicates(artifact_bytes["metadata.json"], where=f"{role} metadata"),
        _METADATA_FIELDS,
        where=f"{role} metadata",
    )
    if (
        metadata["schema_version"] != 1
        or metadata["schedule_id"] != manifest["schedule_id"]
        or metadata["seed"] != manifest["seed"]
        or metadata["population_size"] != manifest["population_size"]
        or metadata["n_instances"] != manifest["n_instances"]
        or not isinstance(metadata["instances"], list)
        or len(metadata["instances"]) != 20
    ):
        raise ValueError(f"{role} dataset metadata header drift")

    instances = manifest.get("instances")
    if not isinstance(instances, list) or len(instances) != 20:
        raise ValueError(f"{role} dataset must have exactly 20 ordered instances")
    canonical_ids: list[str] = []
    database_sha256: dict[str, str] = {}
    for position, instance in enumerate(instances):
        instance = _assert_exact_keys(
            instance,
            _MANIFEST_INSTANCE_FIELDS,
            where=f"{role} manifest instance {position}",
        )
        if (
            isinstance(instance["instance_index"], bool)
            or not isinstance(instance["instance_index"], int)
            or instance["instance_index"] != position
        ):
            raise ValueError(f"{role} dataset instance order drift at {position}")
        scheduled = scheduled_instances[position]
        variant_id = instance["variant_id"]
        db_sha256 = instance["db_sha256"]
        db_seed_payload = (
            f"{_DB_SEED_NAMESPACE}:{manifest['seed']}:"
            f"{manifest['schedule_id']}:{variant_id}"
        )
        expected_db_seed = int.from_bytes(
            hashlib.sha256(db_seed_payload.encode("utf-8")).digest()[:8], "big"
        )
        if (
            not isinstance(variant_id, str)
            or not variant_id
            or _SAFE_SCHEDULE_RE.fullmatch(variant_id) is None
            or variant_id != scheduled["variant_id"]
            or not _is_sha256(db_sha256)
            or not _is_sha256(instance["patient_ids_sha256"])
            or isinstance(instance["db_seed"], bool)
            or not isinstance(instance["db_seed"], int)
            or instance["db_seed"] != expected_db_seed
            or isinstance(instance["split_index"], bool)
            or not isinstance(instance["split_index"], int)
            or instance["split_index"] != scheduled["split_index"]
        ):
            raise ValueError(f"{role} dataset instance {position} identity is invalid")
        db_path = f"dbs/{variant_id}.db"
        artifact = next((row for row in artifacts if row.get("path") == db_path), None)
        if not isinstance(artifact, dict) or artifact.get("sha256") != db_sha256:
            raise ValueError(f"{role} dataset instance database binding drift")

        metadata_instance = _assert_exact_keys(
            metadata["instances"][position],
            _METADATA_INSTANCE_FIELDS,
            where=f"{role} metadata instance {position}",
        )
        if (
            isinstance(metadata_instance["instance_index"], bool)
            or not isinstance(metadata_instance["instance_index"], int)
            or metadata_instance["instance_index"] != position
            or isinstance(metadata_instance["stage_index"], bool)
            or not isinstance(metadata_instance["stage_index"], int)
            or metadata_instance["stage_index"] != scheduled["stage_index"]
            or metadata_instance["variant_id"] != variant_id
            or metadata_instance["db_filename"] != f"{variant_id}.db"
            or metadata_instance["db_sha256"] != db_sha256
            or isinstance(metadata_instance["n_patients"], bool)
            or not isinstance(metadata_instance["n_patients"], int)
            or metadata_instance["n_patients"] <= 0
            or metadata_instance["study_name"] != scheduled["study_name"]
            or metadata_instance["region_slice"] != scheduled["region_slice"]
        ):
            raise ValueError(
                f"{role} dataset metadata instance {position} binding drift"
            )

        try:
            patient_ids, db_regions, study_info_rows = _inspect_frozen_database_bytes(
                artifact_bytes[db_path]
            )
        except (KeyError, sqlite3.Error) as exc:
            raise ValueError(
                f"{role} dataset database {db_path} cannot be audited"
            ) from exc
        if (
            len(patient_ids) != metadata_instance["n_patients"]
            or any(
                isinstance(patient_id, bool)
                or not isinstance(patient_id, int)
                or patient_id < 0
                for patient_id in patient_ids
            )
            or db_regions != sorted(set(scheduled["regions"]))
            or study_info_rows != [(scheduled["study_name"],)]
        ):
            raise ValueError(f"{role} dataset database {db_path} prompt metadata drift")
        patient_digest = hashlib.sha256()
        for patient_id in patient_ids:
            patient_digest.update(patient_id.to_bytes(8, "big", signed=False))
        if patient_digest.hexdigest() != instance["patient_ids_sha256"]:
            raise ValueError(
                f"{role} dataset database {db_path} patient identity drift"
            )
        database_sha256[db_path] = db_sha256
        canonical_ids.append(_cohort_instance_id(dataset["schedule"], variant_id))
    if len(set(canonical_ids)) != 20:
        raise ValueError(f"{role} dataset canonical instance IDs are not unique")
    all_database_artifacts = {
        row["path"]: row["sha256"]
        for row in artifacts
        if row["path"].startswith("dbs/") and row["path"].endswith(".db")
    }
    if all_database_artifacts != database_sha256:
        raise ValueError(f"{role} dataset database inventory differs from instances")
    ground_truth_sha256: dict[str, str] = {}
    for name in ("ground_truth.json", "instance_references.json"):
        matches = [row for row in artifacts if row.get("path") == name]
        if len(matches) != 1:
            raise ValueError(f"{role} dataset ground-truth binding is incomplete")
        ground_truth_sha256[name] = matches[0]["sha256"]
    projection: dict[str, Any] = {
        "aggregate_sha256": manifest["corpus_sha256"],
        "canonical_instance_ids": canonical_ids,
        "database_sha256": database_sha256,
        "dataset_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "dgp_seed": manifest["seed"],
        "ground_truth_sha256": ground_truth_sha256,
        "schedule_id": manifest["schedule_id"],
        "schedule_sha256": manifest["schedule_sha256"],
        "used_for_evaluation": role == "heldout",
        "used_for_updates": role == "adaptation",
    }
    if role == "heldout":
        projection["never_updated"] = True
    return {
        "artifact_bytes": artifact_bytes,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "manifest_sha256": projection["dataset_manifest_sha256"],
        "projection": projection,
    }


def _dataset_projection(root: Path, grid: dict[str, Any], role: str) -> dict[str, Any]:
    return _load_verified_dataset_bundle(root, grid, role)["projection"]


def _materialize_verified_dataset_bundle(
    bundle: dict[str, Any], destination: Path
) -> Path:
    """Publish a private, byte-exact runtime snapshot of a verified corpus."""

    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    payloads = {"manifest.json": bundle["manifest_bytes"], **bundle["artifact_bytes"]}
    for relative_value, raw in payloads.items():
        relative = Path(relative_value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("verified dataset snapshot contains an unsafe path")
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        if hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(raw).digest():
            raise RuntimeError("private verified dataset snapshot changed during write")
    return destination


def _atomic_write_bytes_no_overwrite(path: Path, payload: bytes) -> None:
    """Publish one immutable artifact atomically without a TOCTOU overwrite."""

    requested = path.expanduser()
    requested.parent.mkdir(parents=True, exist_ok=True)
    # Resolve only the parent.  The registered ``artifacts`` directory may be a
    # deliberate durable-storage symlink, but a pre-planted final-component
    # symlink (including a dangling one) must remain an occupied destination,
    # never be followed as the publish target.
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
                f"refusing to overwrite online-ICL artifact: {path}"
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


def _atomic_write_json_no_overwrite(path: Path, payload: Any) -> None:
    _atomic_write_bytes_no_overwrite(path, _canonical_bytes(payload) + b"\n")


def _refuse_existing_online(paths: list[Path]) -> None:
    """Fail before model allocation on files or dangling final symlinks."""

    occupied = [path for path in paths if path.exists() or path.is_symlink()]
    if occupied:
        raise FileExistsError(
            "refusing to overwrite online-ICL artifact(s): "
            + ", ".join(str(path) for path in occupied)
        )


def _finalize_trace_no_overwrite(
    recorder: Any, result: Any, path: Path
) -> dict[str, Any]:
    payload = recorder.finalize(result, status="completed")
    _atomic_write_json_no_overwrite(path, payload)
    return payload


@dataclass(frozen=True)
class RuntimeBindings:
    """Late-bound model-heavy runtime, replaceable in CPU unit tests."""

    system_cls: type
    task_cls: type
    run_task: Callable[..., Any]
    trace_recorder_cls: type


def load_runtime_bindings() -> RuntimeBindings:
    from src.runtime.runner import run_task
    from src.systems.qwen_local.system import QwenLocalSystem
    from src.tasks.cohort_studies.task import CohortStudiesTask
    from src.trace_storage import TraceRecorder

    return RuntimeBindings(
        system_cls=QwenLocalSystem,
        task_cls=CohortStudiesTask,
        run_task=run_task,
        trace_recorder_cls=TraceRecorder,
    )


def load_grid(path: Path) -> dict[str, Any]:
    grid = json.loads(path.read_text())
    if not isinstance(grid, dict) or grid.get("protocol") != PROTOCOL:
        raise ValueError("unexpected online-ICL grid protocol")
    kind = grid.get("kind")
    if kind not in {"smoke", "formal"}:
        raise ValueError("online-ICL grid kind must be smoke or formal")

    from generate_cohort_online_icl_grid import make_grid

    registered = make_grid(smoke=kind == "smoke")
    if _canonical_bytes(grid) != _canonical_bytes(registered):
        raise ValueError(f"{kind} online-ICL grid differs from preregistration")
    return grid


def select_config(grid: dict[str, Any], cfg_id: str) -> dict[str, Any]:
    matches = [
        row
        for row in grid.get("cells", [])
        if isinstance(row, dict) and row.get("cfg_id") == cfg_id
    ]
    if len(matches) != 1:
        raise ValueError(f"cfg_id must select exactly one online-ICL row: {cfg_id!r}")
    return matches[0]


def load_provenance(path: Path) -> dict[str, Any]:
    from build_cohort_online_icl_provenance import REQUIRED_PROVENANCE_FIELDS

    provenance = json.loads(path.read_text())
    if not isinstance(provenance, dict) or set(provenance) != set(
        REQUIRED_PROVENANCE_FIELDS
    ):
        raise ValueError("online-ICL provenance field schema mismatch")
    for key in (
        "environment_lock_sha256",
        "evaluation_code_sha256",
        "icl_prereg_sha256",
        "model_sha256",
        "shared_causal_code_sha256",
        "tokenizer_sha256",
    ):
        value = provenance[key]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"invalid online-ICL provenance digest: {key}")
    for key in ("base_causal_commit", "source_commit"):
        value = provenance[key]
        if (
            not isinstance(value, str)
            or len(value) != 40
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"invalid online-ICL provenance commit: {key}")
    if provenance["protocol"] != PROTOCOL:
        raise ValueError("online-ICL provenance protocol mismatch")
    return provenance


def verify_runtime_provenance(
    root: Path, provenance: dict[str, Any], *, expected_model_path: Path
) -> None:
    from build_cohort_online_icl_provenance import verify_current_provenance

    verify_current_provenance(
        root=root,
        provenance=provenance,
        expected_model_path=expected_model_path,
    )


def load_protocol_seal(path: Path) -> dict[str, Any]:
    from build_cohort_online_icl_protocol_seal import load_protocol_seal as load

    return load(path)


def verify_runtime_protocol_seal(
    root: Path,
    *,
    protocol_seal: dict[str, Any],
    provenance: dict[str, Any],
) -> str:
    """Verify the one immutable seal against both registered grids."""

    from build_cohort_online_icl_protocol_seal import (
        GRID_FILENAMES,
        verify_protocol_seal,
    )

    return verify_protocol_seal(
        seal=protocol_seal,
        provenance=provenance,
        smoke_grid_path=root / GRID_FILENAMES["smoke"],
        formal_grid_path=root / GRID_FILENAMES["formal"],
    )


def _trace_paths(root: Path, cfg: dict[str, Any]) -> tuple[Path, Path, Path, Path]:
    adaptation = _resolve(root, cfg["adaptation_trace_path"])
    heldout = _resolve(root, cfg["heldout_trace_path"])
    return (
        adaptation,
        adaptation.with_name(f"{adaptation.stem}.live.json"),
        heldout,
        heldout.with_name(f"{heldout.stem}.live.json"),
    )


def _assert_no_update(audit: dict[str, Any], *, where: str) -> None:
    expected = {
        "adaptation_count": 0,
        "adapter_enabled": False,
        "bon_updates": 0,
        "distill_updates": 0,
        "grpo_optimizer_steps": 0,
        "grpo_updates": 0,
        "peft_config_present": False,
        "reward_pg_updates": 0,
    }
    if audit != expected:
        raise RuntimeError(f"{where} online-ICL no-update audit failed: {audit!r}")


def _phase_peak_memory_reset() -> None:
    try:
        import torch

        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
    except ImportError:
        pass


def _phase_peak_memory() -> dict[str, int]:
    try:
        import torch

        if torch.cuda.is_available():
            return {
                "peak_allocated_bytes": int(torch.cuda.max_memory_allocated()),
                "peak_reserved_bytes": int(torch.cuda.max_memory_reserved()),
            }
    except ImportError:
        pass
    return {"peak_allocated_bytes": 0, "peak_reserved_bytes": 0}


def _trace_phase_accounting(
    trace: dict[str, Any], *, wall_seconds: float, peak_memory: dict[str, int]
) -> dict[str, Any]:
    interactions = trace.get("interactions", [])
    metadata_rows = [
        row.get("response", {}).get("metadata", {}) for row in interactions
    ]
    generation_calls = sum(int(row.get("generation_calls", 0)) for row in metadata_rows)
    input_tokens = sum(
        int(row.get("generation_input_tokens_total", 0)) for row in metadata_rows
    )
    output_tokens = sum(
        int(row.get("generation_output_tokens_total", 0)) for row in metadata_rows
    )
    hard_truncations = sum(
        int(row.get("generation_prompt_hard_truncations", 0)) for row in metadata_rows
    )
    retries = sum(int(row.get("parse_retries_used", 0)) for row in metadata_rows)
    repairs = sum(int(bool(row.get("parse_repair_used"))) for row in metadata_rows)
    failures = sum(int(isinstance(row.get("llm_error"), dict)) for row in metadata_rows)
    if generation_calls != len(interactions) + retries:
        raise RuntimeError("generation-call accounting differs from parse retries")
    return {
        "candidate_samples": 0,
        "failures": failures,
        "generation_calls": generation_calls,
        "gpu_count": 1,
        "gpu_seconds": round(float(wall_seconds), 6),
        "input_tokens": input_tokens,
        "optimizer_backward_calls": 0,
        "optimizer_forward_calls": 0,
        "optimizer_steps": 0,
        "output_tokens": output_tokens,
        "parse_repairs": repairs,
        "parse_retries": retries,
        "prompt_hard_truncations": hard_truncations,
        "total_tokens": input_tokens + output_tokens,
        "wall_seconds": round(float(wall_seconds), 6),
        **peak_memory,
    }


def _message_inventory(snapshot: dict[str, Any]) -> dict[str, Any]:
    messages = snapshot["state"]["messages"]
    rows = [
        {
            "content_sha256": hashlib.sha256(
                message["content"].encode("utf-8")
            ).hexdigest(),
            "index": index,
            "role": message["role"],
            "utf8_bytes": len(message["content"].encode("utf-8")),
        }
        for index, message in enumerate(messages)
    ]
    return {
        "count": len(rows),
        "inventory_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def _terminal_action_hashes(trace: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for interaction in trace.get("interactions", []):
        observation = interaction.get("observation", {})
        if observation.get("instance_complete") is not True:
            continue
        query = interaction.get("query", {})
        action = interaction.get("response", {}).get("action")
        rows.append(
            {
                "action_sha256": canonical_sha256(action),
                "instance_id": query.get("instance_id"),
                "instance_index": query.get("instance_index"),
            }
        )
    return rows


def _run_online_icl_eval_materialized(
    *,
    root: Path,
    grid: dict[str, Any],
    cfg: dict[str, Any],
    bindings: RuntimeBindings,
    provenance: dict[str, Any],
    protocol_seal_sha256: str,
    adaptation_corpus: dict[str, Any],
    heldout_corpus: dict[str, Any],
    adaptation_task: Any,
    heldout_task: Any,
) -> dict[str, Any]:
    expected = int(cfg["expected_num_instances"])
    snapshot_path = _resolve(root, cfg["snapshot_path"])
    context_inventory_path = _resolve(root, cfg["context_inventory_path"])
    restoration_audit_path = _resolve(root, cfg["restoration_audit_path"])
    manifest_path = _resolve(root, cfg["cell_manifest_path"])
    (
        adaptation_trace_path,
        adaptation_live_path,
        heldout_trace_path,
        heldout_live_path,
    ) = _trace_paths(root, cfg)
    _refuse_existing_online(
        [
            snapshot_path,
            context_inventory_path,
            restoration_audit_path,
            manifest_path,
            adaptation_trace_path,
            adaptation_live_path,
            heldout_trace_path,
            heldout_live_path,
        ]
    )

    seed_everything(int(cfg["run_seed"]))
    _phase_peak_memory_reset()
    model_init_started = time.perf_counter()
    system = bindings.system_cls(**cfg["system_params"])
    model_hash_initial = system.current_model_param_sha256()
    model_init_wall = time.perf_counter() - model_init_started
    model_init_peak_memory = _phase_peak_memory()
    _assert_no_update(system.icl_no_update_audit(), where="initial")

    adaptation_recorder = _build_trace_recorder(
        bindings,
        cfg={
            **cfg,
            "task_params": cfg["adaptation_task_params"],
            "trace_path": str(adaptation_trace_path),
        },
        task=adaptation_task,
        trace_path=adaptation_trace_path,
        live_path=adaptation_live_path,
        phase="rollout",
    )
    _phase_peak_memory_reset()
    adaptation_started = time.perf_counter()
    adaptation_result = bindings.run_task(
        adaptation_task,
        system,
        trace_recorder=adaptation_recorder,
        show_progress=False,
        verbose_logging=False,
        rollout_label=f"{cfg['cfg_id']}:adaptation",
        reset_system=True,
        phase="rollout",
    )
    adaptation_wall = time.perf_counter() - adaptation_started
    adaptation_peak_memory = _phase_peak_memory()
    _assert_outcome_identity(adaptation_result, expected)
    _assert_outcome_order_matches_corpus(adaptation_result, adaptation_corpus, expected)
    adaptation_trace = _finalize_trace_no_overwrite(
        adaptation_recorder, adaptation_result, adaptation_trace_path
    )
    adaptation_rows, adaptation_integrity = _heldout_rows(
        adaptation_trace, adaptation_result
    )
    _assert_no_update(system.icl_no_update_audit(), where="post-adaptation")
    if system.icl_env_reward_injections != expected:
        raise RuntimeError(
            "online-ICL adaptation must ingest exactly one terminal reward per item"
        )
    model_hash_after_adaptation = system.current_model_param_sha256()
    if model_hash_after_adaptation != model_hash_initial:
        raise RuntimeError("online-ICL adaptation changed base-model parameters")

    _phase_peak_memory_reset()
    snapshot_started = time.perf_counter()
    system.seal_icl_context_for_evaluation()
    sealed_snapshot = system.snapshot_icl_context()
    token_inventory = system.tokenize_icl_context_snapshot(sealed_snapshot)
    snapshot_artifact = {
        "protocol": PROTOCOL,
        "run_seed": cfg["run_seed"],
        "schema_version": SCHEMA_VERSION,
        "snapshot": sealed_snapshot,
    }
    snapshot_artifact["artifact_sha256"] = canonical_sha256(snapshot_artifact)
    _atomic_write_json_no_overwrite(snapshot_path, snapshot_artifact)
    context_inventory = {
        "message_inventory": _message_inventory(sealed_snapshot),
        "protocol": PROTOCOL,
        "run_seed": cfg["run_seed"],
        "schema_version": SCHEMA_VERSION,
        "snapshot_sha256": sealed_snapshot["snapshot_sha256"],
        "token_inventory": token_inventory,
    }
    context_inventory["artifact_sha256"] = canonical_sha256(context_inventory)
    _atomic_write_json_no_overwrite(context_inventory_path, context_inventory)
    snapshot_wall = time.perf_counter() - snapshot_started
    snapshot_peak_memory = _phase_peak_memory()

    initial_snapshot_audit: list[dict[str, Any]] = []
    restoration_audit: list[dict[str, Any]] = []
    seen_instances: set[tuple[str | None, int | None]] = set()

    def before_respond(_step: int, query: Any) -> None:
        identity = (query.instance_id, query.instance_index)
        if identity in seen_instances:
            return
        current = system.snapshot_icl_context()
        if current != sealed_snapshot:
            raise RuntimeError(
                f"held-out instance {identity!r} did not start from sealed snapshot"
            )
        seen_instances.add(identity)
        initial_snapshot_audit.append(
            {
                "instance_id": query.instance_id,
                "instance_index": query.instance_index,
                "snapshot_sha256": current["snapshot_sha256"],
            }
        )

    def after_observe(_step: int, query: Any, _response: Any, step_result: Any) -> None:
        if not bool(getattr(step_result.observation, "instance_complete", False)):
            return
        dirty = system.snapshot_icl_context()
        system.restore_icl_context(sealed_snapshot)
        restored = system.snapshot_icl_context()
        if restored != sealed_snapshot:
            raise RuntimeError("held-out ICL snapshot restoration mismatch")
        restoration_audit.append(
            {
                "instance_id": query.instance_id,
                "instance_index": query.instance_index,
                "pre_restore_snapshot_sha256": dirty["snapshot_sha256"],
                "restored_snapshot_sha256": restored["snapshot_sha256"],
            }
        )

    heldout_recorder = _build_trace_recorder(
        bindings,
        cfg={
            **cfg,
            "task_params": cfg["heldout_task_params"],
            "trace_path": str(heldout_trace_path),
        },
        task=heldout_task,
        trace_path=heldout_trace_path,
        live_path=heldout_live_path,
        phase="baseline",
    )
    _phase_peak_memory_reset()
    heldout_started = time.perf_counter()
    heldout_result = bindings.run_task(
        heldout_task,
        system,
        trace_recorder=heldout_recorder,
        show_progress=False,
        verbose_logging=False,
        rollout_label=f"{cfg['cfg_id']}:heldout",
        reset_system=False,
        phase="baseline",
        before_respond=before_respond,
        after_observe=after_observe,
    )
    heldout_wall = time.perf_counter() - heldout_started
    heldout_peak_memory = _phase_peak_memory()
    _assert_outcome_identity(heldout_result, expected)
    _assert_outcome_order_matches_corpus(heldout_result, heldout_corpus, expected)
    heldout_trace = _finalize_trace_no_overwrite(
        heldout_recorder, heldout_result, heldout_trace_path
    )
    heldout_rows, heldout_integrity = _heldout_rows(heldout_trace, heldout_result)
    if len(initial_snapshot_audit) != expected or len(restoration_audit) != expected:
        raise RuntimeError("held-out snapshot isolation audit cardinality mismatch")
    if len(seen_instances) != expected:
        raise RuntimeError("held-out snapshot isolation observed duplicate identities")
    if system.snapshot_icl_context() != sealed_snapshot:
        raise RuntimeError("final held-out state differs from sealed ICL snapshot")
    _assert_no_update(system.icl_no_update_audit(), where="post-heldout")
    if system._icl_context_sensitive_feedback_drops != expected:
        raise RuntimeError(
            "sealed ICL must reject exactly one terminal feedback payload per held-out item"
        )
    model_hash_final = system.current_model_param_sha256()
    if model_hash_final != model_hash_initial:
        raise RuntimeError("online-ICL held-out evaluation changed model parameters")

    restoration_artifact = {
        "initial_snapshot_audit": initial_snapshot_audit,
        "protocol": PROTOCOL,
        "restoration_audit": restoration_audit,
        "run_seed": cfg["run_seed"],
        "schema_version": SCHEMA_VERSION,
        "sensitive_feedback_drops": system._icl_context_sensitive_feedback_drops,
        "snapshot_sha256": sealed_snapshot["snapshot_sha256"],
    }
    restoration_artifact["artifact_sha256"] = canonical_sha256(restoration_artifact)
    _atomic_write_json_no_overwrite(restoration_audit_path, restoration_artifact)

    adaptation_compute = _trace_phase_accounting(
        adaptation_trace,
        wall_seconds=adaptation_wall,
        peak_memory=adaptation_peak_memory,
    )
    heldout_compute = _trace_phase_accounting(
        heldout_trace,
        wall_seconds=heldout_wall,
        peak_memory=heldout_peak_memory,
    )
    adaptation_compute["peak_memory_scope"] = "adaptation_phase"
    heldout_compute["peak_memory_scope"] = "heldout_phase"

    score = statistics.mean(row["reward"] for row in heldout_rows)
    if not math.isfinite(score):
        raise RuntimeError("online-ICL held-out score is non-finite")
    cell = {
        "arm": ARM,
        "adaptation": {
            "corpus": adaptation_corpus,
            "integrity_counters": adaptation_integrity,
            "outcomes": adaptation_rows,
            "trace_path": cfg["adaptation_trace_path"],
            "trace_sha256": canonical_sha256(adaptation_trace),
        },
        "cell_manifest_path": cfg["cell_manifest_path"],
        "context_inventory_path": cfg["context_inventory_path"],
        "context_inventory_sha256": context_inventory["artifact_sha256"],
        "compute": {
            "adaptation": adaptation_compute,
            "heldout": heldout_compute,
            "model_initialization": {
                "candidate_samples": 0,
                "failures": 0,
                "generation_calls": 0,
                "gpu_count": 1,
                "gpu_seconds": round(model_init_wall, 6),
                "input_tokens": 0,
                "optimizer_backward_calls": 0,
                "optimizer_forward_calls": 0,
                "optimizer_steps": 0,
                "output_tokens": 0,
                "parse_repairs": 0,
                "parse_retries": 0,
                "prompt_hard_truncations": 0,
                "total_tokens": 0,
                "wall_seconds": round(model_init_wall, 6),
                **model_init_peak_memory,
            },
            "snapshot": {
                "candidate_samples": 0,
                "failures": 0,
                "generation_calls": 0,
                "gpu_count": 1,
                "gpu_seconds": round(snapshot_wall, 6),
                "input_tokens": 0,
                "optimizer_backward_calls": 0,
                "optimizer_forward_calls": 0,
                "optimizer_steps": 0,
                "output_tokens": 0,
                "parse_repairs": 0,
                "parse_retries": 0,
                "prompt_hard_truncations": 0,
                "total_tokens": 0,
                "wall_seconds": round(snapshot_wall, 6),
                **snapshot_peak_memory,
            },
        },
        "expected_num_instances": expected,
        "heldout": {
            "corpus": heldout_corpus,
            "initial_snapshot_audit": initial_snapshot_audit,
            "integrity_counters": heldout_integrity,
            "outcomes": heldout_rows,
            "restoration_audit": restoration_audit,
            "sensitive_feedback_drops": (system._icl_context_sensitive_feedback_drops),
            "terminal_action_hashes": _terminal_action_hashes(heldout_trace),
            "trace_path": cfg["heldout_trace_path"],
            "trace_sha256": canonical_sha256(heldout_trace),
        },
        "model_param_sha256": {
            "after_adaptation": model_hash_after_adaptation,
            "final": model_hash_final,
            "initial": model_hash_initial,
        },
        "no_update_audit": system.icl_no_update_audit(),
        "protocol": PROTOCOL,
        "protocol_seal_sha256": protocol_seal_sha256,
        "provenance": provenance,
        "run_seed": cfg["run_seed"],
        "schema_version": SCHEMA_VERSION,
        "score": score,
        "snapshot_artifact_sha256": snapshot_artifact["artifact_sha256"],
        "snapshot_path": cfg["snapshot_path"],
        "snapshot_sha256": sealed_snapshot["snapshot_sha256"],
        "restoration_audit_path": cfg["restoration_audit_path"],
        "restoration_audit_sha256": restoration_artifact["artifact_sha256"],
        "status": "completed",
        "system_config": cfg["system_params"],
        "system_config_sha256": canonical_sha256(cfg["system_params"]),
    }
    _atomic_write_json_no_overwrite(manifest_path, cell)
    adaptation_live_path.unlink(missing_ok=True)
    heldout_live_path.unlink(missing_ok=True)
    return cell


def run_online_icl_eval(
    *,
    root: Path,
    grid: dict[str, Any],
    cfg: dict[str, Any],
    bindings: RuntimeBindings,
    provenance: dict[str, Any],
    protocol_seal: dict[str, Any],
) -> dict[str, Any]:
    """Verify, privately snapshot, and execute one online-ICL cell."""

    if cfg.get("mode") != "online_icl_eval" or cfg.get("arm") != ARM:
        raise ValueError("online-ICL cell has unexpected mode or arm")
    if provenance["model_path"] != cfg["system_params"]["model_path"]:
        raise ValueError("online-ICL model path differs from provenance")
    protocol_seal_sha256 = verify_runtime_protocol_seal(
        root,
        protocol_seal=protocol_seal,
        provenance=provenance,
    )
    adaptation_bundle = _load_verified_dataset_bundle(root, grid, "adaptation")
    heldout_bundle = _load_verified_dataset_bundle(root, grid, "heldout")

    with tempfile.TemporaryDirectory(
        prefix=f"cohort-online-icl-{cfg['run_seed']}-"
    ) as scratch:
        scratch_root = Path(scratch)
        adaptation_path = _materialize_verified_dataset_bundle(
            adaptation_bundle, scratch_root / "adaptation"
        )
        heldout_path = _materialize_verified_dataset_bundle(
            heldout_bundle, scratch_root / "heldout"
        )
        adaptation_params = _absolute_task_params(
            root,
            {
                **cfg["adaptation_task_params"],
                "dataset_path": str(adaptation_path),
            },
        )
        heldout_params = _absolute_task_params(
            root,
            {
                **cfg["heldout_task_params"],
                "dataset_path": str(heldout_path),
            },
        )
        adaptation_task = bindings.task_cls(**adaptation_params)
        heldout_task = bindings.task_cls(**heldout_params)

        # Both task constructors have now consumed the shared schedule, while
        # every corpus artifact they may read later comes from the private
        # snapshot. Reverify the registered source/corpus bytes once more so a
        # concurrent mutation cannot hide in the verify-to-constructor window.
        for role, expected_projection in (
            ("adaptation", adaptation_bundle["projection"]),
            ("heldout", heldout_bundle["projection"]),
        ):
            reverified = _load_verified_dataset_bundle(root, grid, role)
            if _canonical_bytes(reverified["projection"]) != _canonical_bytes(
                expected_projection
            ):
                raise RuntimeError(
                    f"{role} registered corpus changed while materializing runtime snapshot"
                )

        return _run_online_icl_eval_materialized(
            root=root,
            grid=grid,
            cfg=cfg,
            bindings=bindings,
            provenance=provenance,
            protocol_seal_sha256=protocol_seal_sha256,
            adaptation_corpus=adaptation_bundle["projection"],
            heldout_corpus=heldout_bundle["projection"],
            adaptation_task=adaptation_task,
            heldout_task=heldout_task,
        )


def _outcome_blind_completion(
    cfg: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    """Return the only cell fields that may be emitted to stdout/run logs."""

    return {
        "cell_manifest_sha256": canonical_sha256(result),
        "cfg_id": cfg["cfg_id"],
        "protocol": PROTOCOL,
        "protocol_seal_sha256": result["protocol_seal_sha256"],
        "run_seed": result["run_seed"],
        "status": result["status"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument("--cfg-id", required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--protocol-seal", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()

    root = args.root.resolve()
    grid = load_grid(args.grid.resolve())
    cfg = select_config(grid, args.cfg_id)
    provenance = load_provenance(args.provenance.resolve())
    protocol_seal = load_protocol_seal(args.protocol_seal.resolve())
    verify_runtime_provenance(
        root,
        provenance,
        expected_model_path=Path(cfg["system_params"]["model_path"]),
    )
    result = run_online_icl_eval(
        root=root,
        grid=grid,
        cfg=cfg,
        bindings=load_runtime_bindings(),
        provenance=provenance,
        protocol_seal=protocol_seal,
    )
    # The immutable cell manifest remains available to the validators, but
    # stdout is deliberately efficacy-blind so an infrastructure smoke cannot
    # preview rewards from its raw artifacts.
    print(
        json.dumps(
            _outcome_blind_completion(cfg, result),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
