"""Strict, pure Trigger-A receipt reconstruction for the structured pivot.

This module is deliberately downstream of the causal terminal attester,
independent revalidator, and trigger execution-seal builder.  A public receipt
builder cannot accept an execution seal by itself: it requires the exact bytes
of every causal decision and completion edge, all three upstream verifier
sources, the complete causal inventory, a prospectively registered validator
inventory, and an independently source-bound structured-root absence
attestation.

The implementation is pure.  It performs no filesystem, process, model, or
scorer I/O and grants no operational authority.  Filesystem absence is accepted
only as an exact adapter attestation whose source is bound by the validator
inventory; a future impure wrapper must freshly verify that claim before it may
publish anything operational.
"""

from __future__ import annotations

import hashlib
import json
import math
import posixpath
import re
import statistics
from datetime import datetime, timezone
from typing import Any


class TriggerReceiptError(ValueError):
    """Raised when a Trigger-A evidence chain fails closed."""


class DuplicateKeyError(ValueError):
    """Raised when strict JSON parsing observes a duplicate object key."""


SCHEMA_VERSION = 1
TRIGGER_A = "causal_valid_no_go"
TRIGGER_B = "causal_pass_online_internal_screen_valid_no_go"

TRIGGER_EXECUTION_SEAL_PROTOCOL = (
    "cohort_closed_loop_structured_state_trigger_execution_seal_v1"
)
TRIGGER_RECEIPT_PROTOCOL = "cohort_structured_trigger_receipt_v1"
TRIGGER_VALIDATOR_INVENTORY_PROTOCOL = (
    "cohort_structured_trigger_validator_inventory_v1"
)
PRETRIGGER_ABSENCE_PROTOCOL = "cohort_structured_pretrigger_absence_attestation_v1"
# The execution contract did not assign a numeric service account.  V1 freezes
# this identity/UID pair prospectively; changing either requires a schema bump.
PRETRIGGER_ABSENCE_SERVICE_IDENTITY = "cohort-structured-trigger-absence-v1"
PRETRIGGER_ABSENCE_SERVICE_UID = 41001
TERMINAL_PLAN_PROTOCOL = "cohort_causal_terminal_verifier_execution_plan_v1"
CAUSAL_ATTESTATION_PROTOCOL = "cohort_causal_terminal_completion_attestation_v1"
CAUSAL_LAUNCH_EXPECTATION_PROTOCOL = "cohort_causal_formal_launch_expectation_v1"
CAUSAL_PROTOCOL = "cohort_qonly_frozen_tape_weight_update_ablation_v1"
CAUSAL_EXPERIMENT = "cohort_qonly_frozen_tape_causal_formal"
CAUSAL_MECHANISM_LABEL = "frozen-tape weight-update ablation"
CAUSAL_LIMITATION = "not exact historical replication"
CAUSAL_PROTOCOL_SEAL_STATUS = "not_applicable_existing_implementation_has_none"

EXPECTED_PYTHON_PATH = "/usr/bin/python3.10"
EXPECTED_PYTHON_VERSION = "3.10.12"
EXPECTED_RUN_SEEDS = (2026071401, 2026071402, 2026071403)
EXPECTED_BOOTSTRAP_SEED = 2026071499
EXPECTED_BOOTSTRAP_REPLICATES = 50_000
EXPECTED_FIXED_SCORING_CONDITIONS = 20
EXPECTED_T_CRITICAL = 4.302652729911275
GO_MEAN_DELTA = 0.02

EXPECTED_REGISTERED_COUNTS = {
    "cell_final_traces": 6,
    "cell_manifests": 6,
    "collector_final_traces": 3,
    "collector_manifests": 3,
    "formal_decisions": 1,
    "formal_manifests": 1,
    "sealed_cell_log_receipts": 9,
    "sealed_cell_log_start_receipts": 9,
    "sealed_cell_logs": 9,
    "tapes": 3,
    "total": 50,
}

REQUIRED_VALIDATOR_BINDING_IDS = tuple(
    sorted(
        (
            "causal_completion_attester",
            "causal_terminal_revalidator",
            "pretrigger_absence_adapter",
            "structured_atomic_publisher",
            "trigger_execution_seal_builder",
            "trigger_receipt_builder",
            "trigger_receipt_publisher",
            "trigger_receipt_revalidator",
        )
    )
)

ABSENCE_FORBIDDEN_CLASSES = tuple(
    sorted(
        (
            "context_registry",
            "decision",
            "model_output",
            "precommit",
            "production_structured_dgp",
            "raw_trace",
            "receipt",
            "report",
        )
    )
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_UTC_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?Z\Z"
)
_PID_RE = re.compile(rb"[1-9][0-9]*\n?\Z")

_LEGACY_BINDING_KEYS = frozenset({"path", "sha256"})
_BINDING_KEYS = frozenset({"path", "sha256", "size_bytes"})
_NAMED_BINDING_KEYS = frozenset({"binding_id", "path", "sha256", "size_bytes"})
_FILE_RECORD_KEYS = frozenset(
    {"device", "inode", "mtime_ns", "path", "roles", "sha256", "size_bytes"}
)

_PLAN_KEYS = frozenset(
    {
        "attempt_id",
        "causal_protocol_seal_sha256",
        "causal_protocol_seal_status",
        "causal_checkout_root",
        "created_at_utc",
        "durable_attempt_root",
        "invocations",
        "launch_expectation",
        "online_icl",
        "protocol",
        "runtime",
        "schema_version",
        "status",
        "structured_preregistration",
        "tooling_root",
        "tooling_source_commit",
        "tools",
    }
)
_PLAN_TOOL_NAMES = frozenset({"attester", "revalidator", "execution_seal_builder"})
_PLAN_INVOCATION_KEYS = frozenset({"argv", "inputs", "outputs", "parameters"})
_PLAN_INVOCATION_SCHEMAS = {
    "attester": (
        frozenset(
            {
                "execution_plan",
                "launch_expectation",
                "provenance",
                "provenance_details",
                "root",
            }
        ),
        frozenset({"attestation"}),
        frozenset({"stability_seconds"}),
    ),
    "revalidator": (
        frozenset(
            {
                "attestation",
                "execution_plan",
                "formal_decision",
                "formal_manifest",
                "grid",
                "launch_expectation",
                "preregistration",
                "provenance",
                "root",
                "statistical_addendum",
            }
        ),
        frozenset({"revalidated_decision", "revalidation_receipt"}),
        frozenset(),
    ),
    "execution_seal_builder": (
        frozenset(
            {
                "attestation",
                "causal_original",
                "causal_revalidated",
                "execution_plan",
                "launch_expectation",
                "revalidation_receipt",
                "structured_preregistration",
            }
        ),
        frozenset({"execution_seal"}),
        frozenset(),
    ),
}

_LAUNCH_EXPECTATION_KEYS = frozenset(
    {
        "artifact_root",
        "attempt_id",
        "boot_id",
        "checkout_root",
        "collector_gpus",
        "created_at_utc",
        "durable_attempt_root",
        "eval_gpus",
        "exit_file",
        "expected_final_inventory",
        "formal_grid_file_sha256",
        "launch_mode",
        "launcher_file_sha256",
        "max_used_memory_mib",
        "node_hostname",
        "pid_file",
        "pid_file_sha256_at_registration",
        "protocol",
        "provenance_file_sha256",
        "schema_version",
        "source_commit",
        "wrapper_cmdline_sha256_at_registration",
        "wrapper_pid",
        "wrapper_start_ticks",
    }
)

_ATTESTATION_KEYS = frozenset(
    {
        "causal_pre_attestation_inventory_sha256",
        "completed_at_utc",
        "execution_plan_path",
        "execution_plan_sha256",
        "expected_launcher",
        "no_live_or_temporary",
        "pid_exit",
        "process_absence",
        "protocol",
        "registered_counts",
        "schema_version",
        "snapshots",
        "stability",
        "status",
    }
)
_EXPECTED_LAUNCHER_KEYS = frozenset(
    {
        "formal_grid_file_sha256",
        "launch_expectation_path",
        "launch_expectation_sha256",
        "launcher_file_sha256",
        "provenance_file_sha256",
        "source_commit",
        "wrapper_cmdline_sha256_at_registration",
    }
)
_PID_EXIT_KEYS = frozenset(
    {
        "exit_after_outputs_status",
        "exit_file_mtime_ns",
        "exit_file_path",
        "exit_file_sha256",
        "exit_file_size_bytes",
        "exit_zero_status",
        "pid_ascii_status",
        "pid_file_mtime_ns",
        "pid_file_path",
        "pid_file_sha256",
        "pid_file_size_bytes",
        "pid_liveness_status",
    }
)
_SNAPSHOT_KEYS = frozenset(
    {"captured_at_utc", "file_count", "files", "inventory_sha256", "sequence"}
)
_STABILITY_KEYS = frozenset(
    {"minimum_interval_seconds", "observed_interval_seconds", "snapshots_identical"}
)
_PROCESS_AUDIT_KEYS = frozenset(
    {"artifact_root_path", "attempt_checkout_path", "audit_sha256", "method", "status"}
)
_TEMPORARY_AUDIT_KEYS = frozenset(
    {"audit_sha256", "forbidden_match_count", "roots", "status"}
)

_DECISION_KEYS = frozenset(
    {
        "aggregate",
        "bootstrap",
        "decision",
        "decision_scope",
        "errors",
        "experiment",
        "limitation",
        "mechanism_label",
        "pairs",
        "preregistered_thresholds",
        "protocol",
        "publication_inference",
        "publication_grade",
        "schema_version",
        "status",
        "threshold_checks",
    }
)
_AGGREGATE_KEYS = frozenset(
    {"ci_95_lower", "ci_95_upper", "mean_delta", "positive_seeds"}
)
_BOOTSTRAP_KEYS = frozenset(
    {
        "ci_95",
        "fixed_scoring_conditions",
        "method",
        "publication_grade",
        "replicates",
        "seed",
    }
)
_THRESHOLD_KEYS = frozenset(
    {
        "all_3_seed_deltas_gt_0",
        "ci_95_lower_gt_0",
        "integrity_gate_passed",
        "mean_delta_gte_0_02",
        "no_schema_format_regression",
    }
)
_PREREGISTERED_THRESHOLD_KEYS = frozenset(
    {"all_seed_deltas_gt", "bootstrap_ci_lower_gt", "mean_delta_gte"}
)
_PAIR_KEYS = frozenset(
    {
        "active_score",
        "delta_seed",
        "lr0_score",
        "pair_id",
        "run_seed",
        "tape_sha256",
        "terminal_actions",
    }
)
_TERMINAL_ACTIONS_KEYS = frozenset({"active", "lr0"})
_TERMINAL_ACTION_KEYS = frozenset(
    {"canonical_sha256", "count", "unique_count", "zero_value_count"}
)
_PUBLICATION_INFERENCE_KEYS = frozenset(
    {
        "confirmation_contract",
        "effective_n",
        "exact_sign_test",
        "fixed_scoring_conditions",
        "internal_screen_status",
        "legacy_hierarchical_bootstrap_publication_grade",
        "negative_interpretation",
        "primary_inferential_unit",
        "publication_grade",
        "raw_seed_deltas",
        "sample_sd",
        "seed_level_t_interval_95",
        "seed_mean_delta",
        "status",
    }
)
_CONFIRMATION_KEYS = frozenset(
    {
        "causal_component_ablations_required",
        "fixed_population_scope_only_if_dgp_requirement_not_met",
        "independent_dgp_population_per_seed_preferred",
        "mean_seed_delta_gte",
        "minimum_new_adaptation_seeds",
        "minimum_independent_frozen_dgp_populations",
        "must_exclude_screen_seeds",
        "primary_inference",
        "primary_inferential_unit",
        "seed_level_interval_95_lower_gt",
        "seed_to_population_mapping_preregistered_required",
        "separate_preregistration_required",
    }
)
_SIGN_TEST_KEYS = frozenset(
    {
        "alternative",
        "method",
        "negative_seed_deltas",
        "nonzero_seed_deltas",
        "p_value",
        "positive_seed_deltas",
        "zero_seed_deltas",
    }
)
_NEGATIVE_INTERPRETATION_KEYS = frozenset(
    {
        "harm_established",
        "harm_requires",
        "practical_benefit_at_least_0_02_ruled_out",
        "practical_benefit_exclusion_requires",
        "valid_no_go_establishes_zero_or_harm",
    }
)
_T_INTERVAL_KEYS = frozenset(
    {
        "critical_value",
        "df",
        "lower",
        "method",
        "normality_dependent_descriptive",
        "upper",
    }
)

_REVALIDATION_RECEIPT_KEYS = frozenset(
    {
        "decision",
        "decision_scope",
        "execution_plan_path",
        "execution_plan_sha256",
        "formal_decision_file_sha256",
        "formal_manifest_file_sha256",
        "status",
    }
)

_SEAL_KEYS = frozenset(
    {
        "bindings",
        "causal_completion_attestation_sha256",
        "causal_decision_sha256",
        "causal_exit_file_sha256",
        "causal_inventory",
        "causal_inventory_recheck_matches_attestation",
        "causal_inventory_sha256",
        "causal_original_file_sha256",
        "causal_pid_file_sha256",
        "causal_pre_attestation_inventory_sha256",
        "causal_protocol_seal_sha256",
        "causal_protocol_seal_status",
        "causal_revalidation_file_sha256",
        "causal_source_commit",
        "created_at_utc",
        "online_icl_decision_sha256",
        "online_icl_inventory_recheck_matches_marker",
        "online_icl_inventory_sha256",
        "online_icl_original_file_sha256",
        "online_icl_protocol_seal_sha256",
        "online_icl_revalidation_file_sha256",
        "online_icl_wrapper_contract_sha256",
        "online_icl_wrapper_exit_marker_sha256",
        "protocol",
        "schema_version",
        "status",
        "terminal_verifier_execution_plan_path",
        "terminal_verifier_execution_plan_sha256",
        "tooling_source_commit",
        "trigger_branch",
        "verifier_execution",
    }
)
_SEAL_BINDING_NAMES = frozenset(
    {
        "attester_code",
        "causal_original",
        "causal_revalidated",
        "causal_revalidation_receipt",
        "causal_trigger_completion_attestation",
        "execution_plan",
        "execution_seal_builder_code",
        "launch_expectation",
        "revalidator_code",
        "structured_preregistration",
    }
)
_VERIFIER_EXECUTION_KEYS = frozenset(
    {"invocations", "invocations_sha256", "runtime", "tools"}
)

_VALIDATOR_INVENTORY_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "tooling_source_commit",
        "bindings",
        "created_at_utc",
        "operational_authorization",
    }
)
_VALIDATOR_INVENTORY_KEYS = _VALIDATOR_INVENTORY_UNSIGNED_KEYS | {
    "binding_inventory_sha256"
}

_ROOT_IDENTITY_KEYS = frozenset(
    {"access_boundary", "device", "inode", "mode", "mount_id", "owner_uid"}
)
_ABSENCE_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "attempt_id",
        "structured_durable_root",
        "method",
        "service_identity",
        "service_uid",
        "adapter_source_path",
        "adapter_source_sha256",
        "filesystem_root_identity",
        "checked_at_utc",
        "receipt_created_at_utc",
        "trigger_execution_seal_sha256",
        "forbidden_classes",
        "forbidden_match_count",
        "forbidden_matches",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_ABSENCE_KEYS = _ABSENCE_UNSIGNED_KEYS | {"absence_attestation_sha256"}

_WRAPPED_PAYLOAD_KEYS = frozenset({"path", "file_sha256", "size_bytes", "payload"})
_WRAPPED_BYTES_KEYS = frozenset({"path", "file_sha256", "size_bytes"})
_CAUSAL_EVIDENCE_KEYS = frozenset(
    {
        "source_commit",
        "causal_protocol_seal_sha256",
        "causal_protocol_seal_status",
        "decision",
        "decision_scope",
        "decision_payload",
        "canonical_decision_sha256",
        "original_decision",
        "revalidated_decision",
        "completion_attestation",
        "revalidation_receipt",
        "pid_file",
        "exit_file",
        "launch_expectation",
        "terminal_verifier_execution_plan",
        "causal_inventory",
        "original_revalidated_bytes_equal",
        "inventory_recheck_matches_attestation",
        "full_evidence_revalidated",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_CAUSAL_INVENTORY_WRAPPER_KEYS = frozenset(
    {"canonical_bytes_sha256", "size_bytes", "payload"}
)
_TRIGGER_RECEIPT_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "status",
        "attempt_id",
        "trigger_branch",
        "tooling_source_commit",
        "structured_preregistration",
        "trigger_execution_seal",
        "trigger_validator_inventory",
        "causal",
        "online_icl",
        "pretrigger_absence_evidence",
        "created_at_utc",
    }
)
_TRIGGER_RECEIPT_KEYS = _TRIGGER_RECEIPT_UNSIGNED_KEYS | {"trigger_receipt_sha256"}


def _raw(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        raise TriggerReceiptError(f"{label} must be exact bytes")
    return value


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(value: object, *, ensure_ascii: bool) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=ensure_ascii,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TriggerReceiptError(f"canonical JSON encoding failed: {exc}") from exc


def legacy_canonical_json_bytes(value: object) -> bytes:
    """Serialize legacy causal artifacts with their frozen UTF-8 convention."""

    return _json_bytes(value, ensure_ascii=False)


def canonical_json_bytes(value: object) -> bytes:
    """Serialize new structured control artifacts with ASCII escaping."""

    return _json_bytes(value, ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return _sha(canonical_json_bytes(value))


def _legacy_canonical_sha(value: object) -> str:
    return _sha(legacy_canonical_json_bytes(value))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _parse_json(
    raw: object, label: str, *, canonical: bool, legacy: bool = False
) -> Any:
    payload = _raw(raw, label)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateKeyError,
        ValueError,
    ) as exc:
        raise TriggerReceiptError(
            f"strict JSON load failed for {label}: {exc}"
        ) from exc
    serializer = legacy_canonical_json_bytes if legacy else canonical_json_bytes
    if canonical and payload != serializer(value):
        raise TriggerReceiptError(f"{label} must be exact canonical JSON bytes")
    return value


def _object(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        observed = sorted(value) if type(value) is dict else type(value).__name__
        raise TriggerReceiptError(
            f"{label} exact-key schema differs; observed {observed!r}"
        )
    return value


def _list(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise TriggerReceiptError(f"{label} must be a JSON array")
    return value


def _text(value: object, label: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        raise TriggerReceiptError(f"{label} must be text")
    return value


def _bool(value: object, expected: bool, label: str) -> bool:
    if type(value) is not bool or value is not expected:
        raise TriggerReceiptError(f"{label} must be exactly {expected!r}")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise TriggerReceiptError(f"{label} must be an integer >= {minimum}")
    return value


def _float(value: object, label: str) -> float:
    if type(value) is not float or not math.isfinite(value):
        raise TriggerReceiptError(f"{label} must be an exact finite JSON float")
    return value


def _sha_text(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise TriggerReceiptError(f"{label} must be lowercase SHA-256")
    return value


def _commit(value: object, label: str) -> str:
    if type(value) is not str or _COMMIT_RE.fullmatch(value) is None:
        raise TriggerReceiptError(f"{label} must be a full lowercase git commit")
    return value


def _attempt(value: object, label: str) -> str:
    if type(value) is not str or _ATTEMPT_RE.fullmatch(value) is None:
        raise TriggerReceiptError(f"{label} must match attempt-[0-9]{{3}}")
    return value


def _utc(value: object, label: str) -> str:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise TriggerReceiptError(f"{label} must be UTC Z timestamp text")
    return value


def _utc_instant(value: object, label: str) -> datetime:
    text = _utc(value, label)
    try:
        instant = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise TriggerReceiptError(f"{label} is not a real UTC timestamp") from exc
    if instant.tzinfo != timezone.utc:
        raise TriggerReceiptError(f"{label} must resolve to UTC")
    return instant


def _absolute_path(value: object, label: str) -> str:
    path = _text(value, label)
    if (
        not path.startswith("/")
        or path == "//"
        or "\x00" in path
        or posixpath.normpath(path) != path
        or "/../" in f"{path}/"
    ):
        raise TriggerReceiptError(f"{label} must be a normalized absolute POSIX path")
    return path


def _binding(value: object, label: str) -> dict[str, Any]:
    record = _object(value, _BINDING_KEYS, label)
    _absolute_path(record["path"], f"{label}.path")
    _sha_text(record["sha256"], f"{label}.sha256")
    _int(record["size_bytes"], f"{label}.size_bytes")
    return record


def _legacy_binding(value: object, label: str) -> dict[str, Any]:
    """Validate the deployed plan's frozen two-field binding projection."""

    record = _object(value, _LEGACY_BINDING_KEYS, label)
    _absolute_path(record["path"], f"{label}.path")
    _sha_text(record["sha256"], f"{label}.sha256")
    return record


def _named_binding(value: object, label: str) -> dict[str, Any]:
    record = _object(value, _NAMED_BINDING_KEYS, label)
    _text(record["binding_id"], f"{label}.binding_id")
    _absolute_path(record["path"], f"{label}.path")
    _sha_text(record["sha256"], f"{label}.sha256")
    _int(record["size_bytes"], f"{label}.size_bytes")
    return record


def _assert_raw_binding(
    binding: dict[str, Any],
    raw: object,
    label: str,
    *,
    expected_path: str | None = None,
) -> bytes:
    payload = _raw(raw, f"{label}_bytes")
    if binding["sha256"] != _sha(payload) or binding["size_bytes"] != len(payload):
        raise TriggerReceiptError(f"{label} full-byte binding differs")
    if expected_path is not None and binding["path"] != expected_path:
        raise TriggerReceiptError(f"{label} registered path differs")
    return payload


def _validate_file_records(value: object, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(_list(value, label)):
        row_label = f"{label}[{index}]"
        row = _object(item, _FILE_RECORD_KEYS, row_label)
        for key in ("device", "inode", "mtime_ns", "size_bytes"):
            _int(row[key], f"{row_label}.{key}")
        _absolute_path(row["path"], f"{row_label}.path")
        roles = _list(row["roles"], f"{row_label}.roles")
        if not roles or any(type(role) is not str or not role for role in roles):
            raise TriggerReceiptError(f"{row_label}.roles must be nonempty text")
        if roles != sorted(set(roles)):
            raise TriggerReceiptError(f"{row_label}.roles must be sorted unique")
        _sha_text(row["sha256"], f"{row_label}.sha256")
        rows.append(row)
    if not rows:
        raise TriggerReceiptError(f"{label} may not be empty")
    paths = [row["path"] for row in rows]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise TriggerReceiptError(f"{label} paths must be sorted unique")
    return rows


def _record_by_role(
    records: list[dict[str, Any]], role: str, *, count: int = 1
) -> list[dict[str, Any]]:
    found = [row for row in records if role in row["roles"]]
    if len(found) != count:
        raise TriggerReceiptError(
            f"causal inventory role {role!r} must occur exactly {count} time(s)"
        )
    return found


def _is_path_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _validate_launch_expectation(value: object) -> dict[str, Any]:
    obj = _object(value, _LAUNCH_EXPECTATION_KEYS, "causal launch expectation")
    _int(obj["schema_version"], "launch expectation.schema_version", minimum=1)
    if (
        obj["protocol"] != CAUSAL_LAUNCH_EXPECTATION_PROTOCOL
        or obj["schema_version"] != SCHEMA_VERSION
        or obj["launch_mode"] != "formal"
        or obj["expected_final_inventory"] != EXPECTED_REGISTERED_COUNTS
    ):
        raise TriggerReceiptError("causal launch expectation contract differs")
    _attempt(obj["attempt_id"], "launch expectation.attempt_id")
    _utc(obj["created_at_utc"], "launch expectation.created_at_utc")
    _commit(obj["source_commit"], "launch expectation.source_commit")
    for key in (
        "artifact_root",
        "checkout_root",
        "durable_attempt_root",
        "exit_file",
        "pid_file",
    ):
        _absolute_path(obj[key], f"launch expectation.{key}")
    if posixpath.basename(obj["durable_attempt_root"]) != obj["attempt_id"]:
        raise TriggerReceiptError("launch expectation attempt root differs")
    counts = _object(
        obj["expected_final_inventory"],
        frozenset(EXPECTED_REGISTERED_COUNTS),
        "launch expectation.expected_final_inventory",
    )
    for key, expected in EXPECTED_REGISTERED_COUNTS.items():
        _int(counts[key], f"launch expectation.expected_final_inventory.{key}")
        if counts[key] != expected:
            raise TriggerReceiptError(
                f"launch expectation expected count differs: {key}"
            )
    for key in (
        "formal_grid_file_sha256",
        "launcher_file_sha256",
        "pid_file_sha256_at_registration",
        "provenance_file_sha256",
        "wrapper_cmdline_sha256_at_registration",
    ):
        _sha_text(obj[key], f"launch expectation.{key}")
    _int(obj["wrapper_pid"], "launch expectation.wrapper_pid", minimum=1)
    _int(
        obj["wrapper_start_ticks"], "launch expectation.wrapper_start_ticks", minimum=1
    )
    _int(obj["max_used_memory_mib"], "launch expectation.max_used_memory_mib")
    for key in ("collector_gpus", "eval_gpus"):
        values = _list(obj[key], f"launch expectation.{key}")
        if not values or any(type(item) is not int or item < 0 for item in values):
            raise TriggerReceiptError(f"launch expectation.{key} must be GPU integers")
        if len(values) != len(set(values)):
            raise TriggerReceiptError(f"launch expectation.{key} repeats a GPU")
    _text(obj["boot_id"], "launch expectation.boot_id")
    _text(obj["node_hostname"], "launch expectation.node_hostname")
    return obj


def _expected_argv(plan: dict[str, Any], stage: str) -> list[str]:
    runtime = plan["runtime"]["python_path"]
    tool = plan["tools"][stage]["path"]
    invocation = plan["invocations"][stage]
    inputs = invocation["inputs"]
    outputs = invocation["outputs"]
    if stage == "attester":
        return [
            runtime,
            tool,
            "--execution-plan",
            inputs["execution_plan"],
            "--root",
            inputs["root"],
            "--launch-expectation",
            inputs["launch_expectation"],
            "--provenance",
            inputs["provenance"],
            "--provenance-details",
            inputs["provenance_details"],
            "--output",
            outputs["attestation"],
            "--stability-seconds",
            invocation["parameters"]["stability_seconds"],
        ]
    if stage == "revalidator":
        return [
            runtime,
            tool,
            "--execution-plan",
            inputs["execution_plan"],
            "--root",
            inputs["root"],
            "--attestation",
            inputs["attestation"],
            "--launch-expectation",
            inputs["launch_expectation"],
            "--grid",
            inputs["grid"],
            "--provenance",
            inputs["provenance"],
            "--formal-manifest",
            inputs["formal_manifest"],
            "--formal-decision",
            inputs["formal_decision"],
            "--preregistration",
            inputs["preregistration"],
            "--statistical-addendum",
            inputs["statistical_addendum"],
            "--output",
            outputs["revalidated_decision"],
            "--receipt",
            outputs["revalidation_receipt"],
        ]
    if stage == "execution_seal_builder":
        return [
            runtime,
            tool,
            "--execution-plan",
            inputs["execution_plan"],
            "--attestation",
            inputs["attestation"],
            "--launch-expectation",
            inputs["launch_expectation"],
            "--causal-original",
            inputs["causal_original"],
            "--causal-revalidated",
            inputs["causal_revalidated"],
            "--revalidation-receipt",
            inputs["revalidation_receipt"],
            "--structured-preregistration",
            inputs["structured_preregistration"],
            "--output",
            outputs["execution_seal"],
        ]
    raise AssertionError(stage)


def _validate_terminal_plan(value: object) -> dict[str, Any]:
    plan = _object(value, _PLAN_KEYS, "terminal verifier execution plan")
    _int(plan["schema_version"], "execution plan.schema_version", minimum=1)
    if (
        plan["protocol"] != TERMINAL_PLAN_PROTOCOL
        or plan["schema_version"] != SCHEMA_VERSION
        or plan["status"] != "registered"
    ):
        raise TriggerReceiptError("terminal execution plan contract differs")
    _attempt(plan["attempt_id"], "execution plan.attempt_id")
    _utc(plan["created_at_utc"], "execution plan.created_at_utc")
    _commit(plan["tooling_source_commit"], "execution plan.tooling_source_commit")
    if plan["online_icl"] is not None:
        raise TriggerReceiptError("Trigger-A plan must keep online_icl exactly null")
    if (
        plan["causal_protocol_seal_sha256"] is not None
        or plan["causal_protocol_seal_status"] != CAUSAL_PROTOCOL_SEAL_STATUS
    ):
        raise TriggerReceiptError("execution plan invents a causal protocol seal")
    causal_root = _absolute_path(
        plan["causal_checkout_root"], "execution plan.causal_checkout_root"
    )
    durable_root = _absolute_path(
        plan["durable_attempt_root"], "execution plan.durable_attempt_root"
    )
    tooling_root = _absolute_path(plan["tooling_root"], "execution plan.tooling_root")
    if posixpath.basename(durable_root) != plan["attempt_id"]:
        raise TriggerReceiptError("execution plan attempt/root mismatch")
    expected_tooling_root = posixpath.join(
        durable_root, "control", "verifier", plan["tooling_source_commit"]
    )
    if tooling_root != expected_tooling_root:
        raise TriggerReceiptError("execution plan tooling root differs")
    runtime = _object(
        plan["runtime"],
        frozenset({"python_path", "python_version"}),
        "execution plan.runtime",
    )
    if runtime != {
        "python_path": EXPECTED_PYTHON_PATH,
        "python_version": EXPECTED_PYTHON_VERSION,
    }:
        raise TriggerReceiptError("execution plan runtime differs")
    launch = _legacy_binding(
        plan["launch_expectation"], "execution plan.launch_expectation"
    )
    prereg = _legacy_binding(
        plan["structured_preregistration"], "execution plan.structured_preregistration"
    )
    if launch["path"] != posixpath.join(
        durable_root, "control", "CAUSAL_FORMAL_ATTEMPT_002_LAUNCH_EXPECTATION.json"
    ):
        raise TriggerReceiptError("execution plan launch-expectation path differs")
    if prereg["path"] != posixpath.join(
        tooling_root, "COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md"
    ):
        raise TriggerReceiptError(
            "execution plan structured-preregistration path differs"
        )
    tools = _object(plan["tools"], _PLAN_TOOL_NAMES, "execution plan.tools")
    expected_tool_paths = {
        "attester": posixpath.join(tooling_root, "attest_cohort_causal_completion.py"),
        "revalidator": posixpath.join(
            tooling_root, "revalidate_cohort_causal_terminal.py"
        ),
        "execution_seal_builder": posixpath.join(
            tooling_root, "build_cohort_structured_state_execution_seal.py"
        ),
    }
    for name in sorted(_PLAN_TOOL_NAMES):
        binding = _legacy_binding(tools[name], f"execution plan.tools.{name}")
        if binding["path"] != expected_tool_paths[name]:
            raise TriggerReceiptError(f"execution plan tool path differs: {name}")
    invocations = _object(
        plan["invocations"], _PLAN_TOOL_NAMES, "execution plan.invocations"
    )
    for name in sorted(_PLAN_TOOL_NAMES):
        invocation = _object(
            invocations[name],
            _PLAN_INVOCATION_KEYS,
            f"execution plan.invocations.{name}",
        )
        input_keys, output_keys, parameter_keys = _PLAN_INVOCATION_SCHEMAS[name]
        for field, keys in (
            ("inputs", input_keys),
            ("outputs", output_keys),
            ("parameters", parameter_keys),
        ):
            values = _object(
                invocation[field], keys, f"execution plan.invocations.{name}.{field}"
            )
            for key, item in values.items():
                if field == "parameters":
                    _text(item, f"execution plan.{name}.{field}.{key}")
                else:
                    _absolute_path(item, f"execution plan.{name}.{field}.{key}")
        if name == "attester" and invocation["parameters"] != {
            "stability_seconds": "1.0"
        }:
            raise TriggerReceiptError("attester stability interval differs")
        argv = _list(invocation["argv"], f"execution plan.{name}.argv")
        if any(type(item) is not str or not item for item in argv):
            raise TriggerReceiptError(f"execution plan.{name}.argv must be text")
        if argv != _expected_argv(plan, name):
            raise TriggerReceiptError(f"execution plan.{name}.argv differs")

    prep = posixpath.join(durable_root, "prep")
    artifact = posixpath.join(durable_root, "artifacts", "cohort_causal")
    plan_path = posixpath.join(
        durable_root, "control", "CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN.json"
    )
    expected = {
        ("attester", "inputs", "execution_plan"): plan_path,
        ("revalidator", "inputs", "execution_plan"): plan_path,
        ("execution_seal_builder", "inputs", "execution_plan"): plan_path,
        ("attester", "inputs", "root"): causal_root,
        ("revalidator", "inputs", "root"): causal_root,
        ("attester", "inputs", "launch_expectation"): launch["path"],
        ("revalidator", "inputs", "launch_expectation"): launch["path"],
        ("execution_seal_builder", "inputs", "launch_expectation"): launch["path"],
        ("attester", "outputs", "attestation"): posixpath.join(
            prep, "causal_trigger_completion_attestation.json"
        ),
        ("revalidator", "inputs", "attestation"): posixpath.join(
            prep, "causal_trigger_completion_attestation.json"
        ),
        ("execution_seal_builder", "inputs", "attestation"): posixpath.join(
            prep, "causal_trigger_completion_attestation.json"
        ),
        ("revalidator", "inputs", "formal_decision"): posixpath.join(
            artifact, "formal_decision.json"
        ),
        ("execution_seal_builder", "inputs", "causal_original"): posixpath.join(
            artifact, "formal_decision.json"
        ),
        ("revalidator", "inputs", "formal_manifest"): posixpath.join(
            artifact, "formal_manifest.json"
        ),
        ("revalidator", "outputs", "revalidated_decision"): posixpath.join(
            prep, "causal_formal.revalidated.json"
        ),
        ("execution_seal_builder", "inputs", "causal_revalidated"): posixpath.join(
            prep, "causal_formal.revalidated.json"
        ),
        ("revalidator", "outputs", "revalidation_receipt"): posixpath.join(
            prep, "causal_formal.revalidation_receipt.json"
        ),
        ("execution_seal_builder", "inputs", "revalidation_receipt"): posixpath.join(
            prep, "causal_formal.revalidation_receipt.json"
        ),
        ("execution_seal_builder", "inputs", "structured_preregistration"): prereg[
            "path"
        ],
        ("execution_seal_builder", "outputs", "execution_seal"): posixpath.join(
            prep, "cohort_closed_loop_structured_state.execution_seal.json"
        ),
    }
    for (stage, direction, key), expected_path in expected.items():
        if invocations[stage][direction][key] != expected_path:
            raise TriggerReceiptError(
                f"execution plan fixed topology differs: {stage}.{direction}.{key}"
            )
    return plan


def _validate_snapshot(
    value: object, sequence: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    obj = _object(value, _SNAPSHOT_KEYS, f"attestation.snapshot[{sequence}]")
    _int(
        obj["sequence"],
        f"attestation.snapshot[{sequence}].sequence",
        minimum=1,
    )
    if obj["sequence"] != sequence:
        raise TriggerReceiptError("attestation snapshot sequence differs")
    _utc(obj["captured_at_utc"], f"attestation.snapshot[{sequence}].captured_at_utc")
    records = _validate_file_records(
        obj["files"], f"attestation.snapshot[{sequence}].files"
    )
    _int(
        obj["file_count"],
        f"attestation.snapshot[{sequence}].file_count",
    )
    if obj["file_count"] != len(records):
        raise TriggerReceiptError("attestation snapshot file_count differs")
    if obj["inventory_sha256"] != _legacy_canonical_sha(records):
        raise TriggerReceiptError("attestation snapshot inventory digest differs")
    return obj, records


def _validate_audit(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    obj = _object(value, keys, label)
    _sha_text(obj["audit_sha256"], f"{label}.audit_sha256")
    if obj["status"] != "pass":
        raise TriggerReceiptError(f"{label} status differs")
    unsigned = {key: obj[key] for key in obj if key != "audit_sha256"}
    if obj["audit_sha256"] != _legacy_canonical_sha(unsigned):
        raise TriggerReceiptError(f"{label} self digest differs")
    return obj


def _validate_attestation(
    value: object,
    *,
    plan: dict[str, Any],
    plan_raw: bytes,
    launch: dict[str, Any],
    launch_raw: bytes,
    pid_raw: bytes,
    exit_raw: bytes,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    obj = _object(value, _ATTESTATION_KEYS, "causal completion attestation")
    _int(obj["schema_version"], "causal attestation.schema_version", minimum=1)
    if (
        obj["protocol"] != CAUSAL_ATTESTATION_PROTOCOL
        or obj["schema_version"] != SCHEMA_VERSION
        or obj["status"] != "complete"
    ):
        raise TriggerReceiptError("causal completion attestation contract differs")
    _utc(obj["completed_at_utc"], "causal attestation.completed_at_utc")
    plan_path = plan["invocations"]["attester"]["inputs"]["execution_plan"]
    if obj["execution_plan_path"] != plan_path or obj["execution_plan_sha256"] != _sha(
        plan_raw
    ):
        raise TriggerReceiptError("completion attestation plan binding differs")
    counts = _object(
        obj["registered_counts"],
        frozenset(EXPECTED_REGISTERED_COUNTS),
        "causal attestation.registered_counts",
    )
    for key, expected_count in EXPECTED_REGISTERED_COUNTS.items():
        _int(counts[key], f"causal attestation.registered_counts.{key}")
        if counts[key] != expected_count:
            raise TriggerReceiptError("completion attestation formal counts differ")
    expected_launcher = _object(
        obj["expected_launcher"],
        _EXPECTED_LAUNCHER_KEYS,
        "attestation.expected_launcher",
    )
    expected = {
        "formal_grid_file_sha256": launch["formal_grid_file_sha256"],
        "launch_expectation_path": plan["launch_expectation"]["path"],
        "launch_expectation_sha256": _sha(launch_raw),
        "launcher_file_sha256": launch["launcher_file_sha256"],
        "provenance_file_sha256": launch["provenance_file_sha256"],
        "source_commit": launch["source_commit"],
        "wrapper_cmdline_sha256_at_registration": launch[
            "wrapper_cmdline_sha256_at_registration"
        ],
    }
    if expected_launcher != expected:
        raise TriggerReceiptError("completion attestation launcher binding differs")
    pid_exit = _object(obj["pid_exit"], _PID_EXIT_KEYS, "attestation.pid_exit")
    statuses = {
        "exit_after_outputs_status": "pass",
        "exit_zero_status": "pass",
        "pid_ascii_status": "pass",
        "pid_liveness_status": "dead",
    }
    if {key: pid_exit[key] for key in statuses} != statuses:
        raise TriggerReceiptError("completion attestation PID/exit statuses differ")
    for key in ("pid_file_path", "exit_file_path"):
        _absolute_path(pid_exit[key], f"attestation.pid_exit.{key}")
    for key in ("pid_file_sha256", "exit_file_sha256"):
        _sha_text(pid_exit[key], f"attestation.pid_exit.{key}")
    for key in (
        "pid_file_mtime_ns",
        "pid_file_size_bytes",
        "exit_file_mtime_ns",
        "exit_file_size_bytes",
    ):
        _int(pid_exit[key], f"attestation.pid_exit.{key}")
    if (
        pid_exit["pid_file_path"] != launch["pid_file"]
        or pid_exit["exit_file_path"] != launch["exit_file"]
    ):
        raise TriggerReceiptError("completion attestation PID/exit paths differ")
    if _PID_RE.fullmatch(pid_raw) is None:
        raise TriggerReceiptError("PID file bytes are not canonical ASCII")
    if int(pid_raw.rstrip(b"\n")) != launch["wrapper_pid"]:
        raise TriggerReceiptError("PID bytes differ from launch expectation")
    try:
        exit_text = exit_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TriggerReceiptError("exit file bytes are not ASCII") from exc
    if exit_text.strip(" \t\r\n\v\f") != "0":
        raise TriggerReceiptError("exit file does not contain exact zero after strip")
    if (
        pid_exit["pid_file_sha256"] != _sha(pid_raw)
        or pid_exit["pid_file_size_bytes"] != len(pid_raw)
        or pid_exit["exit_file_sha256"] != _sha(exit_raw)
        or pid_exit["exit_file_size_bytes"] != len(exit_raw)
        or launch["pid_file_sha256_at_registration"] != _sha(pid_raw)
    ):
        raise TriggerReceiptError("PID/exit raw-byte binding differs")
    stability = _object(obj["stability"], _STABILITY_KEYS, "attestation.stability")
    minimum = _float(
        stability["minimum_interval_seconds"], "attestation.minimum_interval_seconds"
    )
    observed = _float(
        stability["observed_interval_seconds"], "attestation.observed_interval_seconds"
    )
    if (
        stability["snapshots_identical"] is not True
        or minimum < 1.0
        or observed < minimum
    ):
        raise TriggerReceiptError("completion attestation stability proof differs")
    snapshots = _list(obj["snapshots"], "attestation.snapshots")
    if len(snapshots) != 2:
        raise TriggerReceiptError("completion attestation requires two snapshots")
    first, first_records = _validate_snapshot(snapshots[0], 1)
    second, second_records = _validate_snapshot(snapshots[1], 2)
    if legacy_canonical_json_bytes(first_records) != legacy_canonical_json_bytes(
        second_records
    ):
        raise TriggerReceiptError("completion attestation snapshots differ")
    if (
        first["inventory_sha256"] != second["inventory_sha256"]
        or obj["causal_pre_attestation_inventory_sha256"] != first["inventory_sha256"]
    ):
        raise TriggerReceiptError("completion attestation inventory joins differ")
    process = _validate_audit(
        obj["process_absence"], _PROCESS_AUDIT_KEYS, "attestation.process_absence"
    )
    temporary = _validate_audit(
        obj["no_live_or_temporary"],
        _TEMPORARY_AUDIT_KEYS,
        "attestation.no_live_or_temporary",
    )
    _int(
        temporary["forbidden_match_count"],
        "attestation.no_live_or_temporary.forbidden_match_count",
    )
    if (
        process["artifact_root_path"] != launch["artifact_root"]
        or process["attempt_checkout_path"] != launch["checkout_root"]
        or process["method"] != "linux_procfs_cmdline_and_cwd"
    ):
        raise TriggerReceiptError("completion process-absence audit differs")
    expected_roots = sorted(
        [
            launch["artifact_root"],
            posixpath.join(launch["durable_attempt_root"], "prep"),
        ]
    )
    if temporary["roots"] != expected_roots or temporary["forbidden_match_count"] != 0:
        raise TriggerReceiptError("completion no-live/no-temporary audit differs")
    return obj, first_records


def _validate_terminal_action(value: object, label: str) -> None:
    obj = _object(value, _TERMINAL_ACTION_KEYS, label)
    digests = _list(obj["canonical_sha256"], f"{label}.canonical_sha256")
    if digests != sorted(set(digests)):
        raise TriggerReceiptError(f"{label}.canonical_sha256 must be sorted unique")
    for index, digest in enumerate(digests):
        _sha_text(digest, f"{label}.canonical_sha256[{index}]")
    count = _int(obj["count"], f"{label}.count")
    unique_count = _int(obj["unique_count"], f"{label}.unique_count")
    if count != 20 or unique_count != len(digests) or unique_count > count:
        raise TriggerReceiptError(f"{label} counts differ")
    zero_count = obj["zero_value_count"]
    _int(zero_count, f"{label}.zero_value_count")


def _validate_publication_inference(
    value: object, *, deltas: list[float], passed: bool, mean_delta: float
) -> None:
    obj = _object(value, _PUBLICATION_INFERENCE_KEYS, "publication_inference")
    _int(obj["effective_n"], "publication_inference.effective_n", minimum=1)
    _int(
        obj["fixed_scoring_conditions"],
        "publication_inference.fixed_scoring_conditions",
        minimum=1,
    )
    _bool(
        obj["legacy_hierarchical_bootstrap_publication_grade"],
        False,
        "publication_inference.legacy_hierarchical_bootstrap_publication_grade",
    )
    _bool(obj["publication_grade"], False, "publication_inference.publication_grade")
    if (
        obj["effective_n"] != 3
        or obj["fixed_scoring_conditions"] != EXPECTED_FIXED_SCORING_CONDITIONS
        or obj["internal_screen_status"]
        != ("internal_gate_pass" if passed else "internal_gate_no_go")
        or obj["legacy_hierarchical_bootstrap_publication_grade"] is not False
        or obj["primary_inferential_unit"] != "adaptation_seed"
        or obj["publication_grade"] is not False
        or obj["status"] != "confirmation_required_not_publication_grade"
    ):
        raise TriggerReceiptError("publication inference envelope differs")
    raw_deltas = _list(obj["raw_seed_deltas"], "publication_inference.raw_seed_deltas")
    if len(raw_deltas) != 3 or any(
        not math.isclose(
            _float(item, "raw_seed_delta"), delta, rel_tol=0.0, abs_tol=1e-12
        )
        for item, delta in zip(raw_deltas, deltas, strict=True)
    ):
        raise TriggerReceiptError("publication inference seed deltas differ")
    sample_sd = statistics.stdev(deltas)
    if not math.isclose(
        _float(obj["sample_sd"], "publication_inference.sample_sd"),
        sample_sd,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise TriggerReceiptError("publication inference sample SD differs")
    if not math.isclose(
        _float(obj["seed_mean_delta"], "publication_inference.seed_mean_delta"),
        mean_delta,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise TriggerReceiptError("publication inference seed mean differs")
    confirmation = _object(
        obj["confirmation_contract"],
        _CONFIRMATION_KEYS,
        "publication_inference.confirmation_contract",
    )
    expected_confirmation = {
        "causal_component_ablations_required": True,
        "fixed_population_scope_only_if_dgp_requirement_not_met": True,
        "independent_dgp_population_per_seed_preferred": True,
        "mean_seed_delta_gte": GO_MEAN_DELTA,
        "minimum_new_adaptation_seeds": 6,
        "minimum_independent_frozen_dgp_populations": 2,
        "must_exclude_screen_seeds": list(EXPECTED_RUN_SEEDS),
        "primary_inference": "two_sided_exact_sign_flip",
        "primary_inferential_unit": "adaptation_seed",
        "seed_level_interval_95_lower_gt": 0.0,
        "seed_to_population_mapping_preregistered_required": True,
        "separate_preregistration_required": True,
    }
    _int(
        confirmation["minimum_new_adaptation_seeds"],
        "publication_inference.confirmation_contract.minimum_new_adaptation_seeds",
        minimum=1,
    )
    _int(
        confirmation["minimum_independent_frozen_dgp_populations"],
        "publication_inference.confirmation_contract.minimum_independent_frozen_dgp_populations",
        minimum=1,
    )
    for index, seed in enumerate(
        _list(
            confirmation["must_exclude_screen_seeds"],
            "publication_inference.confirmation_contract.must_exclude_screen_seeds",
        )
    ):
        _int(
            seed,
            f"publication_inference.confirmation_contract.must_exclude_screen_seeds[{index}]",
            minimum=1,
        )
    for key in (
        "causal_component_ablations_required",
        "fixed_population_scope_only_if_dgp_requirement_not_met",
        "independent_dgp_population_per_seed_preferred",
        "seed_to_population_mapping_preregistered_required",
        "separate_preregistration_required",
    ):
        _bool(
            confirmation[key],
            True,
            f"publication_inference.confirmation_contract.{key}",
        )
    _float(
        confirmation["mean_seed_delta_gte"],
        "publication_inference.confirmation_contract.mean_seed_delta_gte",
    )
    _float(
        confirmation["seed_level_interval_95_lower_gt"],
        "publication_inference.confirmation_contract.seed_level_interval_95_lower_gt",
    )
    if confirmation != expected_confirmation:
        raise TriggerReceiptError("publication confirmation contract differs")
    negative = _object(
        obj["negative_interpretation"],
        _NEGATIVE_INTERPRETATION_KEYS,
        "publication_inference.negative_interpretation",
    )
    expected_negative = {
        "harm_established": False,
        "harm_requires": "publication_grade_seed_level_one_sided_95_upper_lt_0",
        "practical_benefit_at_least_0_02_ruled_out": False,
        "practical_benefit_exclusion_requires": "publication_grade_seed_level_one_sided_95_upper_lt_0_02",
        "valid_no_go_establishes_zero_or_harm": False,
    }
    for key in (
        "harm_established",
        "practical_benefit_at_least_0_02_ruled_out",
        "valid_no_go_establishes_zero_or_harm",
    ):
        _bool(
            negative[key],
            False,
            f"publication_inference.negative_interpretation.{key}",
        )
    if negative != expected_negative:
        raise TriggerReceiptError("publication negative interpretation differs")
    sign = _object(
        obj["exact_sign_test"], _SIGN_TEST_KEYS, "publication_inference.exact_sign_test"
    )
    for key in (
        "negative_seed_deltas",
        "nonzero_seed_deltas",
        "positive_seed_deltas",
        "zero_seed_deltas",
    ):
        _int(sign[key], f"publication_inference.exact_sign_test.{key}")
    _float(sign["p_value"], "publication_inference.exact_sign_test.p_value")
    positives = sum(delta > 0.0 for delta in deltas)
    negatives = sum(delta < 0.0 for delta in deltas)
    zeros = 3 - positives - negatives
    nonzero = positives + negatives
    if nonzero == 0:
        p_value = 1.0
    else:
        extreme = max(positives, negatives)
        tail = sum(math.comb(nonzero, n) for n in range(extreme, nonzero + 1)) / (
            2**nonzero
        )
        p_value = round(min(1.0, 2.0 * tail), 12)
    expected_sign = {
        "alternative": "two_sided",
        "method": "exact_binomial_sign_test_zero_deltas_excluded",
        "negative_seed_deltas": negatives,
        "nonzero_seed_deltas": nonzero,
        "p_value": p_value,
        "positive_seed_deltas": positives,
        "zero_seed_deltas": zeros,
    }
    if sign != expected_sign:
        raise TriggerReceiptError("publication sign-test reconstruction differs")
    interval = _object(
        obj["seed_level_t_interval_95"],
        _T_INTERVAL_KEYS,
        "publication_inference.seed_level_t_interval_95",
    )
    _int(interval["df"], "publication_inference.seed_level_t_interval_95.df", minimum=1)
    _float(
        interval["critical_value"],
        "publication_inference.seed_level_t_interval_95.critical_value",
    )
    _float(interval["lower"], "publication_inference.seed_level_t_interval_95.lower")
    _float(interval["upper"], "publication_inference.seed_level_t_interval_95.upper")
    _bool(
        interval["normality_dependent_descriptive"],
        True,
        "publication_inference.seed_level_t_interval_95.normality_dependent_descriptive",
    )
    half_width = EXPECTED_T_CRITICAL * sample_sd / math.sqrt(3)
    expected_interval = {
        "critical_value": EXPECTED_T_CRITICAL,
        "df": 2,
        "lower": round(mean_delta - half_width, 12),
        "method": "two_sided_student_t_interval_over_seed_deltas",
        "normality_dependent_descriptive": True,
        "upper": round(mean_delta + half_width, 12),
    }
    if interval != expected_interval:
        raise TriggerReceiptError("publication seed-level interval differs")


def _validate_causal_decision(value: object) -> dict[str, Any]:
    report = _object(value, _DECISION_KEYS, "causal decision")
    _int(report["schema_version"], "causal decision.schema_version", minimum=1)
    required = {
        "protocol": CAUSAL_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "experiment": CAUSAL_EXPERIMENT,
        "mechanism_label": CAUSAL_MECHANISM_LABEL,
        "limitation": CAUSAL_LIMITATION,
        "status": "valid",
        "errors": [],
        "publication_grade": False,
    }
    for key, expected in required.items():
        if report[key] != expected:
            raise TriggerReceiptError(f"causal decision predicate differs: {key}")
    _bool(report["publication_grade"], False, "causal decision.publication_grade")
    thresholds = _object(
        report["preregistered_thresholds"],
        _PREREGISTERED_THRESHOLD_KEYS,
        "causal decision.preregistered_thresholds",
    )
    for key in (
        "all_seed_deltas_gt",
        "bootstrap_ci_lower_gt",
        "mean_delta_gte",
    ):
        _float(thresholds[key], f"causal decision.preregistered_thresholds.{key}")
    if thresholds != {
        "all_seed_deltas_gt": 0.0,
        "bootstrap_ci_lower_gt": 0.0,
        "mean_delta_gte": GO_MEAN_DELTA,
    }:
        raise TriggerReceiptError("causal preregistered thresholds differ")
    pairs = _list(report["pairs"], "causal decision.pairs")
    if len(pairs) != 3:
        raise TriggerReceiptError("causal decision must contain exactly three pairs")
    deltas: list[float] = []
    observed_seeds: list[int] = []
    observed_pair_ids: list[str] = []
    for index, item in enumerate(pairs):
        label = f"causal decision.pairs[{index}]"
        pair = _object(item, _PAIR_KEYS, label)
        seed = _int(pair["run_seed"], f"{label}.run_seed", minimum=1)
        observed_seeds.append(seed)
        observed_pair_ids.append(_text(pair["pair_id"], f"{label}.pair_id"))
        _sha_text(pair["tape_sha256"], f"{label}.tape_sha256")
        active = _float(pair["active_score"], f"{label}.active_score")
        lr0 = _float(pair["lr0_score"], f"{label}.lr0_score")
        delta = _float(pair["delta_seed"], f"{label}.delta_seed")
        if not math.isclose(delta, active - lr0, rel_tol=0.0, abs_tol=1e-12):
            raise TriggerReceiptError(f"{label}.delta_seed differs from active-lr0")
        actions = _object(
            pair["terminal_actions"],
            _TERMINAL_ACTIONS_KEYS,
            f"{label}.terminal_actions",
        )
        _validate_terminal_action(actions["active"], f"{label}.terminal_actions.active")
        _validate_terminal_action(actions["lr0"], f"{label}.terminal_actions.lr0")
        deltas.append(delta)
    if tuple(observed_seeds) != EXPECTED_RUN_SEEDS:
        raise TriggerReceiptError("causal decision seed order/set differs")
    if len(observed_pair_ids) != len(set(observed_pair_ids)):
        raise TriggerReceiptError("causal decision pair ids must be unique")
    mean_delta = statistics.mean(deltas)
    aggregate = _object(
        report["aggregate"], _AGGREGATE_KEYS, "causal decision.aggregate"
    )
    ci_lower = _float(aggregate["ci_95_lower"], "aggregate.ci_95_lower")
    ci_upper = _float(aggregate["ci_95_upper"], "aggregate.ci_95_upper")
    if ci_lower > ci_upper:
        raise TriggerReceiptError("causal aggregate CI order differs")
    if not math.isclose(
        _float(aggregate["mean_delta"], "aggregate.mean_delta"),
        mean_delta,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise TriggerReceiptError("causal aggregate mean differs")
    _int(aggregate["positive_seeds"], "aggregate.positive_seeds")
    if aggregate["positive_seeds"] != sum(delta > 0.0 for delta in deltas):
        raise TriggerReceiptError("causal positive seed count differs")
    bootstrap = _object(
        report["bootstrap"], _BOOTSTRAP_KEYS, "causal decision.bootstrap"
    )
    _int(
        bootstrap["fixed_scoring_conditions"],
        "causal decision.bootstrap.fixed_scoring_conditions",
        minimum=1,
    )
    _int(
        bootstrap["replicates"],
        "causal decision.bootstrap.replicates",
        minimum=1,
    )
    _int(bootstrap["seed"], "causal decision.bootstrap.seed", minimum=1)
    ci = _list(bootstrap["ci_95"], "causal decision.bootstrap.ci_95")
    if (
        len(ci) != 2
        or not math.isclose(
            _float(ci[0], "bootstrap.ci_95[0]"), ci_lower, rel_tol=0.0, abs_tol=1e-12
        )
        or not math.isclose(
            _float(ci[1], "bootstrap.ci_95[1]"), ci_upper, rel_tol=0.0, abs_tol=1e-12
        )
    ):
        raise TriggerReceiptError("causal bootstrap/aggregate CI differs")
    if (
        bootstrap["fixed_scoring_conditions"] != EXPECTED_FIXED_SCORING_CONDITIONS
        or bootstrap["method"]
        != "hierarchical_paired_common_instance_ids_percentile_type7"
        or bootstrap["publication_grade"] is not False
        or bootstrap["replicates"] != EXPECTED_BOOTSTRAP_REPLICATES
        or bootstrap["seed"] != EXPECTED_BOOTSTRAP_SEED
    ):
        raise TriggerReceiptError("causal bootstrap contract differs")
    checks = _object(
        report["threshold_checks"], _THRESHOLD_KEYS, "causal decision.threshold_checks"
    )
    for key in _THRESHOLD_KEYS:
        if type(checks[key]) is not bool:
            raise TriggerReceiptError(
                f"causal decision.threshold_checks.{key} must be boolean"
            )
    expected_checks = {
        "all_3_seed_deltas_gt_0": all(delta > 0.0 for delta in deltas),
        "mean_delta_gte_0_02": mean_delta >= GO_MEAN_DELTA,
        "ci_95_lower_gt_0": ci_lower > 0.0,
        "integrity_gate_passed": True,
        "no_schema_format_regression": True,
    }
    if checks != expected_checks:
        raise TriggerReceiptError("causal threshold checks are not reconstructed")
    passed = all(expected_checks.values())
    expected_branch = (
        ("pass", "internal_gate_pass")
        if passed
        else ("valid_no_go", "internal_gate_no_go")
    )
    if (report["decision"], report["decision_scope"]) != expected_branch:
        raise TriggerReceiptError("causal decision/scope do not follow thresholds")
    _validate_publication_inference(
        report["publication_inference"],
        deltas=deltas,
        passed=passed,
        mean_delta=mean_delta,
    )
    return report


def _validate_revalidation_receipt(
    value: object,
    *,
    report: dict[str, Any],
    plan: dict[str, Any],
    plan_raw: bytes,
    original_raw: bytes,
    inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    obj = _object(value, _REVALIDATION_RECEIPT_KEYS, "causal revalidation receipt")
    manifest = _record_by_role(inventory, "formal_manifest")[0]
    expected = {
        "decision": report["decision"],
        "decision_scope": report["decision_scope"],
        "execution_plan_path": plan["invocations"]["revalidator"]["inputs"][
            "execution_plan"
        ],
        "execution_plan_sha256": _sha(plan_raw),
        "formal_decision_file_sha256": _sha(original_raw),
        "formal_manifest_file_sha256": manifest["sha256"],
        "status": "valid",
    }
    if obj != expected:
        raise TriggerReceiptError("causal revalidation receipt bindings differ")
    return obj


def _validate_validator_inventory(
    value: object,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    obj = _object(value, _VALIDATOR_INVENTORY_KEYS, "trigger validator inventory")
    _int(
        obj["schema_version"],
        "trigger validator inventory.schema_version",
        minimum=1,
    )
    if (
        obj["protocol"] != TRIGGER_VALIDATOR_INVENTORY_PROTOCOL
        or obj["schema_version"] != SCHEMA_VERSION
        or obj["status"] != "prospectively_registered"
    ):
        raise TriggerReceiptError("trigger validator inventory contract differs")
    _commit(obj["tooling_source_commit"], "validator inventory.tooling_source_commit")
    _utc(obj["created_at_utc"], "validator inventory.created_at_utc")
    _bool(
        obj["operational_authorization"],
        False,
        "validator inventory.operational_authorization",
    )
    rows = [
        _named_binding(item, f"validator inventory.bindings[{index}]")
        for index, item in enumerate(
            _list(obj["bindings"], "validator inventory.bindings")
        )
    ]
    ids = tuple(row["binding_id"] for row in rows)
    if ids != REQUIRED_VALIDATOR_BINDING_IDS:
        raise TriggerReceiptError("trigger validator binding ids/order differ")
    paths = [row["path"] for row in rows]
    if len(paths) != len(set(paths)):
        raise TriggerReceiptError("trigger validator binding paths must be unique")
    by_id = {row["binding_id"]: row for row in rows}
    builder = by_id["trigger_receipt_builder"]
    revalidator = by_id["trigger_receipt_revalidator"]
    if (
        builder["path"] == revalidator["path"]
        or builder["sha256"] == revalidator["sha256"]
    ):
        raise TriggerReceiptError(
            "trigger receipt builder/revalidator path and source digest must be distinct"
        )
    for publisher_id in (
        "structured_atomic_publisher",
        "trigger_receipt_publisher",
    ):
        publisher_digest = by_id[publisher_id]["sha256"]
        if any(
            row["binding_id"] != publisher_id and row["sha256"] == publisher_digest
            for row in rows
        ):
            raise TriggerReceiptError(
                f"{publisher_id} source digest must not be reused by another validator role"
            )
    if obj["binding_inventory_sha256"] != _canonical_sha(
        {key: obj[key] for key in _VALIDATOR_INVENTORY_UNSIGNED_KEYS}
    ):
        raise TriggerReceiptError("trigger validator inventory self digest differs")
    return obj, by_id


def build_trigger_validator_inventory_bytes(
    *,
    binding_records_bytes: object,
    tooling_source_commit: object,
    created_at_utc: object,
) -> bytes:
    """Build the prospective source inventory; this grants no authority."""

    rows = _parse_json(binding_records_bytes, "binding_records_bytes", canonical=True)
    parsed = [
        _named_binding(item, f"binding_records[{index}]")
        for index, item in enumerate(_list(rows, "binding_records"))
    ]
    if tuple(row["binding_id"] for row in parsed) != REQUIRED_VALIDATOR_BINDING_IDS:
        raise TriggerReceiptError("trigger validator binding ids/order differ")
    unsigned = {
        "protocol": TRIGGER_VALIDATOR_INVENTORY_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": "prospectively_registered",
        "tooling_source_commit": _commit(
            tooling_source_commit, "tooling_source_commit"
        ),
        "bindings": parsed,
        "created_at_utc": _utc(created_at_utc, "created_at_utc"),
        "operational_authorization": False,
    }
    payload = dict(unsigned)
    payload["binding_inventory_sha256"] = _canonical_sha(unsigned)
    _validate_validator_inventory(payload)
    return canonical_json_bytes(payload)


def _validate_absence(
    value: object,
    *,
    attempt_id: str,
    receipt_created_at_utc: str,
    seal_sha256: str,
    absence_binding: dict[str, Any],
    structured_tooling_source_commit: str,
) -> dict[str, Any]:
    obj = _object(value, _ABSENCE_KEYS, "pretrigger absence evidence")
    _int(obj["schema_version"], "pretrigger absence.schema_version", minimum=1)
    if (
        obj["protocol"] != PRETRIGGER_ABSENCE_PROTOCOL
        or obj["schema_version"] != SCHEMA_VERSION
        or obj["status"] != "attested_absent"
        or obj["attempt_id"] != attempt_id
        or obj["method"] != "root_relative_no_follow_full_walk_v1"
    ):
        raise TriggerReceiptError("pretrigger absence contract differs")
    _absolute_path(obj["structured_durable_root"], "absence.structured_durable_root")
    root_match = re.fullmatch(
        r"/sensei-fs/users/zcai/TTT-RL/cohort-closed-loop-structured-state/"
        r"(?P<commit>[0-9a-f]{40})/attempts/(?P<attempt>attempt-[0-9]{3})",
        obj["structured_durable_root"],
    )
    if root_match is None or root_match.group("attempt") != attempt_id:
        raise TriggerReceiptError("pretrigger absence root/attempt differs")
    if root_match.group("commit") != structured_tooling_source_commit:
        raise TriggerReceiptError("pretrigger absence root/source commit differs")
    if obj["service_identity"] != PRETRIGGER_ABSENCE_SERVICE_IDENTITY:
        raise TriggerReceiptError("pretrigger absence service identity differs")
    _int(obj["service_uid"], "absence.service_uid")
    if obj["service_uid"] != PRETRIGGER_ABSENCE_SERVICE_UID:
        raise TriggerReceiptError("pretrigger absence service UID differs")
    if (
        obj["adapter_source_path"] != absence_binding["path"]
        or obj["adapter_source_sha256"] != absence_binding["sha256"]
    ):
        raise TriggerReceiptError("pretrigger absence adapter source differs")
    root_identity = _object(
        obj["filesystem_root_identity"],
        _ROOT_IDENTITY_KEYS,
        "absence.filesystem_root_identity",
    )
    if (
        root_identity["access_boundary"]
        != "dedicated_absence_adapter_lstat_boundary_v1"
    ):
        raise TriggerReceiptError("pretrigger absence access boundary differs")
    for key in ("device", "inode", "mode", "owner_uid"):
        _int(root_identity[key], f"absence.filesystem_root_identity.{key}")
    if root_identity["mode"] != 0o700:
        raise TriggerReceiptError(
            "pretrigger absence filesystem root mode must be exactly 0700"
        )
    if root_identity["owner_uid"] != obj["service_uid"]:
        raise TriggerReceiptError(
            "pretrigger absence service_uid must equal filesystem owner_uid"
        )
    _text(root_identity["mount_id"], "absence.filesystem_root_identity.mount_id")
    checked_at = _utc_instant(obj["checked_at_utc"], "absence.checked_at_utc")
    if obj["receipt_created_at_utc"] != receipt_created_at_utc:
        raise TriggerReceiptError("pretrigger absence freshness join differs")
    receipt_at = _utc_instant(
        obj["receipt_created_at_utc"], "absence.receipt_created_at_utc"
    )
    age_seconds = (receipt_at - checked_at).total_seconds()
    if age_seconds < 0.0 or age_seconds > 60.0:
        raise TriggerReceiptError(
            "pretrigger absence observation must be no more than 60 seconds old"
        )
    if obj["trigger_execution_seal_sha256"] != seal_sha256:
        raise TriggerReceiptError("pretrigger absence execution-seal join differs")
    if tuple(obj["forbidden_classes"]) != ABSENCE_FORBIDDEN_CLASSES:
        raise TriggerReceiptError("pretrigger absence forbidden classes differ")
    _int(obj["forbidden_match_count"], "absence.forbidden_match_count")
    if obj["forbidden_match_count"] != 0 or obj["forbidden_matches"] != []:
        raise TriggerReceiptError("pretrigger structured artifacts already exist")
    _bool(obj["model_calls_authorized"], False, "absence.model_calls_authorized")
    _bool(obj["operational_authorization"], False, "absence.operational_authorization")
    if obj["absence_attestation_sha256"] != _canonical_sha(
        {key: obj[key] for key in _ABSENCE_UNSIGNED_KEYS}
    ):
        raise TriggerReceiptError("pretrigger absence self digest differs")
    return obj


def _validate_seal_shape(
    value: object,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    seal = _object(value, _SEAL_KEYS, "trigger execution seal")
    _int(seal["schema_version"], "trigger execution seal.schema_version", minimum=1)
    if (
        seal["protocol"] != TRIGGER_EXECUTION_SEAL_PROTOCOL
        or seal["schema_version"] != SCHEMA_VERSION
        or seal["status"] != "sealed"
    ):
        raise TriggerReceiptError("trigger execution seal contract differs")
    if seal["trigger_branch"] == TRIGGER_B:
        raise TriggerReceiptError("Trigger B is fail-closed in receipt v1")
    if seal["trigger_branch"] != TRIGGER_A:
        raise TriggerReceiptError("unregistered trigger branch")
    online_keys = (
        "online_icl_decision_sha256",
        "online_icl_inventory_recheck_matches_marker",
        "online_icl_inventory_sha256",
        "online_icl_original_file_sha256",
        "online_icl_protocol_seal_sha256",
        "online_icl_revalidation_file_sha256",
        "online_icl_wrapper_contract_sha256",
        "online_icl_wrapper_exit_marker_sha256",
    )
    if any(seal[key] is not None for key in online_keys):
        raise TriggerReceiptError(
            "Trigger A requires an exactly null online evidence arm"
        )
    bindings_obj = _object(
        seal["bindings"], _SEAL_BINDING_NAMES, "execution seal.bindings"
    )
    bindings = {
        name: _binding(bindings_obj[name], f"execution seal.bindings.{name}")
        for name in sorted(_SEAL_BINDING_NAMES)
    }
    if len({row["path"] for row in bindings.values()}) != len(bindings):
        raise TriggerReceiptError("execution seal bindings reuse a path")
    _commit(seal["causal_source_commit"], "execution seal.causal_source_commit")
    _commit(seal["tooling_source_commit"], "execution seal.tooling_source_commit")
    _utc(seal["created_at_utc"], "execution seal.created_at_utc")
    _absolute_path(
        seal["terminal_verifier_execution_plan_path"],
        "execution seal.terminal_verifier_execution_plan_path",
    )
    for key in (
        "causal_completion_attestation_sha256",
        "causal_decision_sha256",
        "causal_exit_file_sha256",
        "causal_inventory_sha256",
        "causal_original_file_sha256",
        "causal_pid_file_sha256",
        "causal_pre_attestation_inventory_sha256",
        "causal_revalidation_file_sha256",
        "terminal_verifier_execution_plan_sha256",
    ):
        _sha_text(seal[key], f"execution seal.{key}")
    if (
        seal["causal_protocol_seal_sha256"] is not None
        or seal["causal_protocol_seal_status"] != CAUSAL_PROTOCOL_SEAL_STATUS
    ):
        raise TriggerReceiptError("execution seal invents a causal protocol seal")
    _bool(
        seal["causal_inventory_recheck_matches_attestation"],
        True,
        "execution seal.causal_inventory_recheck_matches_attestation",
    )
    return seal, bindings


def _validate_verifier_execution(value: object, *, plan: dict[str, Any]) -> None:
    obj = _object(value, _VERIFIER_EXECUTION_KEYS, "execution seal.verifier_execution")
    if obj["invocations"] != plan["invocations"]:
        raise TriggerReceiptError(
            "execution seal verifier invocations differ from plan"
        )
    if obj["invocations_sha256"] != _legacy_canonical_sha(plan["invocations"]):
        raise TriggerReceiptError("execution seal verifier invocation digest differs")
    if obj["runtime"] != plan["runtime"] or obj["tools"] != plan["tools"]:
        raise TriggerReceiptError(
            "execution seal verifier runtime/tools differ from plan"
        )


def _validate_full_inventory(
    *,
    inventory: list[dict[str, Any]],
    pre_attestation_records: list[dict[str, Any]],
    attestation_raw: bytes,
    attestation_path: str,
    original_raw: bytes,
    original_path: str,
    pid_raw: bytes,
    pid_path: str,
    exit_raw: bytes,
    exit_path: str,
    launch_raw: bytes,
    launch_path: str,
) -> None:
    if len(inventory) != len(pre_attestation_records) + 1:
        raise TriggerReceiptError("full causal inventory omits or adds records")
    if legacy_canonical_json_bytes(inventory[:-1]) == legacy_canonical_json_bytes(
        pre_attestation_records
    ):
        # The attestation record need not sort last, so do not rely on this fast path.
        pass
    pre_by_path = {row["path"]: row for row in pre_attestation_records}
    full_by_path = {row["path"]: row for row in inventory}
    for path, row in pre_by_path.items():
        if full_by_path.get(path) != row:
            raise TriggerReceiptError(
                "full causal inventory differs from attested snapshot"
            )
    attestation_record = full_by_path.get(attestation_path)
    if attestation_record is None or attestation_record["roles"] != [
        "causal_trigger_completion_attestation"
    ]:
        raise TriggerReceiptError("full causal inventory omits completion attestation")
    if attestation_record["sha256"] != _sha(attestation_raw) or attestation_record[
        "size_bytes"
    ] != len(attestation_raw):
        raise TriggerReceiptError("completion attestation inventory record differs")
    checks = (
        (original_path, "formal_decision", original_raw),
        (pid_path, "wrapper_pid_file", pid_raw),
        (exit_path, "wrapper_exit_file", exit_raw),
        (launch_path, "launch_expectation", launch_raw),
    )
    for path, role, raw in checks:
        row = full_by_path.get(path)
        if row is None or role not in row["roles"]:
            raise TriggerReceiptError(f"full causal inventory omits {role}")
        if row["sha256"] != _sha(raw) or row["size_bytes"] != len(raw):
            raise TriggerReceiptError(
                f"full causal inventory raw binding differs: {role}"
            )
    singleton_roles = (
        "adaptation_corpus_manifest",
        "adaptation_schedule",
        "causal_prereg",
        "causal_smoke_gate",
        "compact_provenance",
        "detailed_provenance",
        "formal_decision",
        "formal_grid",
        "formal_manifest",
        "heldout_corpus_manifest",
        "heldout_schedule",
        "launch_expectation",
        "launcher_source",
        "statistical_addendum",
        "wrapper_exit_file",
        "wrapper_pid_file",
        "causal_trigger_completion_attestation",
    )
    for role in singleton_roles:
        _record_by_role(inventory, role)
    for role, count in (
        ("formal_tape", 3),
        ("collector_manifest", 3),
        ("collector_final_trace", 3),
        ("cell_manifest", 6),
        ("cell_final_trace", 6),
    ):
        _record_by_role(inventory, role, count=count)
    if not any("evaluation_code" in row["roles"] for row in inventory):
        raise TriggerReceiptError("full causal inventory omits evaluation code")
    for role in ("adaptation_corpus_artifact", "heldout_corpus_artifact"):
        if not any(role in row["roles"] for row in inventory):
            raise TriggerReceiptError(f"full causal inventory omits {role}")
    manifest = _record_by_role(inventory, "formal_manifest")[0]
    decision = _record_by_role(inventory, "formal_decision")[0]
    exit_record = _record_by_role(inventory, "wrapper_exit_file")[0]
    if exit_record["mtime_ns"] <= max(manifest["mtime_ns"], decision["mtime_ns"]):
        raise TriggerReceiptError("wrapper exit record predates formal outputs")


def _wrapped_payload(path: str, raw: bytes, payload: object) -> dict[str, object]:
    return {
        "path": path,
        "file_sha256": _sha(raw),
        "size_bytes": len(raw),
        "payload": payload,
    }


def _wrapped_bytes(path: str, raw: bytes) -> dict[str, object]:
    return {"path": path, "file_sha256": _sha(raw), "size_bytes": len(raw)}


def _validate_all_evidence(
    *,
    trigger_execution_seal_bytes: object,
    causal_original_decision_bytes: object,
    causal_revalidated_decision_bytes: object,
    causal_completion_attestation_bytes: object,
    causal_revalidation_receipt_bytes: object,
    causal_pid_file_bytes: object,
    causal_exit_file_bytes: object,
    terminal_verifier_execution_plan_bytes: object,
    causal_launch_expectation_bytes: object,
    causal_inventory_bytes: object,
    structured_preregistration_bytes: object,
    trigger_validator_inventory_bytes: object,
    attester_source_bytes: object,
    causal_revalidator_source_bytes: object,
    execution_seal_builder_source_bytes: object,
    trigger_receipt_builder_source_bytes: object,
    trigger_receipt_revalidator_source_bytes: object,
    pretrigger_absence_adapter_source_bytes: object,
    structured_atomic_publisher_source_bytes: object,
    trigger_receipt_publisher_source_bytes: object,
    pretrigger_absence_evidence_bytes: object,
    structured_attempt_id: object,
    created_at_utc: object,
) -> dict[str, Any]:
    attempt_id = _attempt(structured_attempt_id, "structured_attempt_id")
    created_at = _utc(created_at_utc, "created_at_utc")
    seal_raw = _raw(trigger_execution_seal_bytes, "trigger_execution_seal_bytes")
    seal_obj = _parse_json(
        seal_raw, "trigger_execution_seal_bytes", canonical=True, legacy=True
    )
    seal, seal_bindings = _validate_seal_shape(seal_obj)
    plan_raw = _raw(
        terminal_verifier_execution_plan_bytes,
        "terminal_verifier_execution_plan_bytes",
    )
    plan_obj = _parse_json(
        plan_raw,
        "terminal_verifier_execution_plan_bytes",
        canonical=True,
        legacy=True,
    )
    plan = _validate_terminal_plan(plan_obj)
    if (
        seal["terminal_verifier_execution_plan_path"]
        != plan["invocations"]["execution_seal_builder"]["inputs"]["execution_plan"]
        or seal["terminal_verifier_execution_plan_sha256"] != _sha(plan_raw)
        or seal["tooling_source_commit"] != plan["tooling_source_commit"]
    ):
        raise TriggerReceiptError("execution seal terminal-plan join differs")
    _validate_verifier_execution(seal["verifier_execution"], plan=plan)

    launch_raw = _raw(
        causal_launch_expectation_bytes, "causal_launch_expectation_bytes"
    )
    launch = _validate_launch_expectation(
        _parse_json(launch_raw, "causal_launch_expectation_bytes", canonical=False)
    )
    expected_artifact_root = posixpath.join(
        plan["durable_attempt_root"], "artifacts", "cohort_causal"
    )
    expected_prep_root = posixpath.join(plan["durable_attempt_root"], "prep")
    exact_plan_launch_joins = {
        "attempt_id": (plan["attempt_id"], launch["attempt_id"]),
        "checkout_root": (plan["causal_checkout_root"], launch["checkout_root"]),
        "durable_attempt_root": (
            plan["durable_attempt_root"],
            launch["durable_attempt_root"],
        ),
        "artifact_root": (expected_artifact_root, launch["artifact_root"]),
        "pid_file": (
            posixpath.join(expected_prep_root, "causal_formal.pid"),
            launch["pid_file"],
        ),
        "exit_file": (
            posixpath.join(expected_prep_root, "causal_formal.exit"),
            launch["exit_file"],
        ),
    }
    for label, (expected_value, observed_value) in exact_plan_launch_joins.items():
        if observed_value != expected_value:
            raise TriggerReceiptError(f"plan/launch exact join differs: {label}")
    if (
        plan["launch_expectation"]["sha256"] != _sha(launch_raw)
        or launch["source_commit"] != seal["causal_source_commit"]
    ):
        raise TriggerReceiptError("launch expectation plan/seal join differs")
    prereg_raw = _raw(
        structured_preregistration_bytes, "structured_preregistration_bytes"
    )
    if plan["structured_preregistration"]["sha256"] != _sha(prereg_raw):
        raise TriggerReceiptError("structured preregistration plan binding differs")

    tool_raw = {
        "attester": _raw(attester_source_bytes, "attester_source_bytes"),
        "revalidator": _raw(
            causal_revalidator_source_bytes, "causal_revalidator_source_bytes"
        ),
        "execution_seal_builder": _raw(
            execution_seal_builder_source_bytes, "execution_seal_builder_source_bytes"
        ),
    }
    for name, raw in tool_raw.items():
        if plan["tools"][name]["sha256"] != _sha(raw):
            raise TriggerReceiptError(f"terminal verifier source bytes differ: {name}")

    original_raw = _raw(
        causal_original_decision_bytes, "causal_original_decision_bytes"
    )
    revalidated_raw = _raw(
        causal_revalidated_decision_bytes, "causal_revalidated_decision_bytes"
    )
    if original_raw != revalidated_raw:
        raise TriggerReceiptError("causal original/revalidated decision bytes differ")
    original_obj = _parse_json(
        original_raw, "causal_original_decision_bytes", canonical=False
    )
    revalidated_obj = _parse_json(
        revalidated_raw, "causal_revalidated_decision_bytes", canonical=False
    )
    report = _validate_causal_decision(original_obj)
    revalidated_report = _validate_causal_decision(revalidated_obj)
    if legacy_canonical_json_bytes(report) != legacy_canonical_json_bytes(
        revalidated_report
    ):
        raise TriggerReceiptError("causal original/revalidated decision objects differ")
    if (report["decision"], report["decision_scope"]) != (
        "valid_no_go",
        "internal_gate_no_go",
    ):
        raise TriggerReceiptError("Trigger A requires reconstructed causal valid_no_go")

    pid_raw = _raw(causal_pid_file_bytes, "causal_pid_file_bytes")
    exit_raw = _raw(causal_exit_file_bytes, "causal_exit_file_bytes")
    attestation_raw = _raw(
        causal_completion_attestation_bytes, "causal_completion_attestation_bytes"
    )
    attestation_obj = _parse_json(
        attestation_raw,
        "causal_completion_attestation_bytes",
        canonical=True,
        legacy=True,
    )
    attestation, pre_records = _validate_attestation(
        attestation_obj,
        plan=plan,
        plan_raw=plan_raw,
        launch=launch,
        launch_raw=launch_raw,
        pid_raw=pid_raw,
        exit_raw=exit_raw,
    )
    inventory_raw = _raw(causal_inventory_bytes, "causal_inventory_bytes")
    inventory_obj = _parse_json(
        inventory_raw, "causal_inventory_bytes", canonical=True, legacy=True
    )
    inventory = _validate_file_records(inventory_obj, "causal_inventory")
    allowed_inventory_roots = (
        plan["causal_checkout_root"],
        plan["durable_attempt_root"],
    )
    for row in inventory:
        if not any(
            _is_path_within(row["path"], root) for root in allowed_inventory_roots
        ):
            raise TriggerReceiptError(
                "causal inventory path escapes the registered checkout/durable roots"
            )
    if seal["causal_inventory"] != inventory:
        raise TriggerReceiptError("execution seal full causal inventory differs")
    if seal["causal_inventory_sha256"] != _legacy_canonical_sha(inventory):
        raise TriggerReceiptError("execution seal causal inventory digest differs")
    _validate_full_inventory(
        inventory=inventory,
        pre_attestation_records=pre_records,
        attestation_raw=attestation_raw,
        attestation_path=plan["invocations"]["attester"]["outputs"]["attestation"],
        original_raw=original_raw,
        original_path=plan["invocations"]["revalidator"]["inputs"]["formal_decision"],
        pid_raw=pid_raw,
        pid_path=launch["pid_file"],
        exit_raw=exit_raw,
        exit_path=launch["exit_file"],
        launch_raw=launch_raw,
        launch_path=plan["launch_expectation"]["path"],
    )
    if (
        seal["causal_pre_attestation_inventory_sha256"]
        != attestation["causal_pre_attestation_inventory_sha256"]
    ):
        raise TriggerReceiptError(
            "execution seal pre-attestation inventory join differs"
        )

    receipt_raw = _raw(
        causal_revalidation_receipt_bytes, "causal_revalidation_receipt_bytes"
    )
    receipt_obj = _parse_json(
        receipt_raw, "causal_revalidation_receipt_bytes", canonical=False
    )
    _validate_revalidation_receipt(
        receipt_obj,
        report=report,
        plan=plan,
        plan_raw=plan_raw,
        original_raw=original_raw,
        inventory=inventory,
    )

    expected_binding_raw = {
        "causal_trigger_completion_attestation": attestation_raw,
        "causal_original": original_raw,
        "causal_revalidated": revalidated_raw,
        "causal_revalidation_receipt": receipt_raw,
        "execution_plan": plan_raw,
        "launch_expectation": launch_raw,
        "structured_preregistration": prereg_raw,
        "attester_code": tool_raw["attester"],
        "revalidator_code": tool_raw["revalidator"],
        "execution_seal_builder_code": tool_raw["execution_seal_builder"],
    }
    expected_binding_paths = {
        "causal_trigger_completion_attestation": plan["invocations"]["attester"][
            "outputs"
        ]["attestation"],
        "causal_original": plan["invocations"]["revalidator"]["inputs"][
            "formal_decision"
        ],
        "causal_revalidated": plan["invocations"]["revalidator"]["outputs"][
            "revalidated_decision"
        ],
        "causal_revalidation_receipt": plan["invocations"]["revalidator"]["outputs"][
            "revalidation_receipt"
        ],
        "execution_plan": plan["invocations"]["attester"]["inputs"]["execution_plan"],
        "launch_expectation": plan["launch_expectation"]["path"],
        "structured_preregistration": plan["structured_preregistration"]["path"],
        "attester_code": plan["tools"]["attester"]["path"],
        "revalidator_code": plan["tools"]["revalidator"]["path"],
        "execution_seal_builder_code": plan["tools"]["execution_seal_builder"]["path"],
    }
    for name in sorted(_SEAL_BINDING_NAMES):
        _assert_raw_binding(
            seal_bindings[name],
            expected_binding_raw[name],
            f"execution seal binding {name}",
            expected_path=expected_binding_paths[name],
        )

    decision_sha = _legacy_canonical_sha(report)
    direct_seal_hashes = {
        "causal_completion_attestation_sha256": _sha(attestation_raw),
        "causal_decision_sha256": decision_sha,
        "causal_exit_file_sha256": _sha(exit_raw),
        "causal_original_file_sha256": _sha(original_raw),
        "causal_pid_file_sha256": _sha(pid_raw),
        "causal_revalidation_file_sha256": _sha(revalidated_raw),
    }
    for key, expected in direct_seal_hashes.items():
        if seal[key] != expected:
            raise TriggerReceiptError(f"execution seal direct digest differs: {key}")

    validator_raw = _raw(
        trigger_validator_inventory_bytes, "trigger_validator_inventory_bytes"
    )
    validator_obj = _parse_json(
        validator_raw, "trigger_validator_inventory_bytes", canonical=True
    )
    validator_inventory, validators = _validate_validator_inventory(validator_obj)
    validator_registered_at = _utc_instant(
        validator_inventory["created_at_utc"],
        "trigger validator inventory.created_at_utc",
    )
    seal_created_at = _utc_instant(
        seal["created_at_utc"], "trigger execution seal.created_at_utc"
    )
    if validator_registered_at >= seal_created_at:
        raise TriggerReceiptError(
            "trigger validator inventory must be strictly earlier than the execution seal"
        )
    validator_source_raw = {
        "causal_completion_attester": tool_raw["attester"],
        "causal_terminal_revalidator": tool_raw["revalidator"],
        "trigger_execution_seal_builder": tool_raw["execution_seal_builder"],
        "trigger_receipt_builder": _raw(
            trigger_receipt_builder_source_bytes, "trigger_receipt_builder_source_bytes"
        ),
        "trigger_receipt_revalidator": _raw(
            trigger_receipt_revalidator_source_bytes,
            "trigger_receipt_revalidator_source_bytes",
        ),
        "pretrigger_absence_adapter": _raw(
            pretrigger_absence_adapter_source_bytes,
            "pretrigger_absence_adapter_source_bytes",
        ),
        "structured_atomic_publisher": _raw(
            structured_atomic_publisher_source_bytes,
            "structured_atomic_publisher_source_bytes",
        ),
        "trigger_receipt_publisher": _raw(
            trigger_receipt_publisher_source_bytes,
            "trigger_receipt_publisher_source_bytes",
        ),
    }
    for binding_id, raw in validator_source_raw.items():
        binding = validators[binding_id]
        if binding["sha256"] != _sha(raw) or binding["size_bytes"] != len(raw):
            raise TriggerReceiptError(f"trigger validator source differs: {binding_id}")
    upstream_paths = {
        "causal_completion_attester": plan["tools"]["attester"]["path"],
        "causal_terminal_revalidator": plan["tools"]["revalidator"]["path"],
        "trigger_execution_seal_builder": plan["tools"]["execution_seal_builder"][
            "path"
        ],
    }
    for binding_id, path in upstream_paths.items():
        if validators[binding_id]["path"] != path:
            raise TriggerReceiptError(
                f"trigger validator upstream path differs: {binding_id}"
            )

    absence_raw = _raw(
        pretrigger_absence_evidence_bytes, "pretrigger_absence_evidence_bytes"
    )
    absence_obj = _parse_json(
        absence_raw, "pretrigger_absence_evidence_bytes", canonical=True
    )
    absence = _validate_absence(
        absence_obj,
        attempt_id=attempt_id,
        receipt_created_at_utc=created_at,
        seal_sha256=_sha(seal_raw),
        absence_binding=validators["pretrigger_absence_adapter"],
        structured_tooling_source_commit=validator_inventory["tooling_source_commit"],
    )
    attestation_completed_at = _utc_instant(
        attestation["completed_at_utc"],
        "causal completion attestation.completed_at_utc",
    )
    absence_checked_at = _utc_instant(
        absence["checked_at_utc"], "pretrigger absence evidence.checked_at_utc"
    )
    if not attestation_completed_at <= seal_created_at <= absence_checked_at:
        raise TriggerReceiptError(
            "trigger evidence timestamps violate completion/seal/absence order"
        )

    seal_path = plan["invocations"]["execution_seal_builder"]["outputs"][
        "execution_seal"
    ]
    causal = {
        "source_commit": seal["causal_source_commit"],
        "causal_protocol_seal_sha256": None,
        "causal_protocol_seal_status": CAUSAL_PROTOCOL_SEAL_STATUS,
        "decision": "valid_no_go",
        "decision_scope": "internal_gate_no_go",
        "decision_payload": report,
        "canonical_decision_sha256": decision_sha,
        "original_decision": _wrapped_bytes(
            plan["invocations"]["revalidator"]["inputs"]["formal_decision"],
            original_raw,
        ),
        "revalidated_decision": _wrapped_bytes(
            plan["invocations"]["revalidator"]["outputs"]["revalidated_decision"],
            revalidated_raw,
        ),
        "completion_attestation": _wrapped_bytes(
            plan["invocations"]["attester"]["outputs"]["attestation"], attestation_raw
        ),
        "revalidation_receipt": _wrapped_bytes(
            plan["invocations"]["revalidator"]["outputs"]["revalidation_receipt"],
            receipt_raw,
        ),
        "pid_file": _wrapped_bytes(launch["pid_file"], pid_raw),
        "exit_file": _wrapped_bytes(launch["exit_file"], exit_raw),
        "launch_expectation": _wrapped_bytes(
            plan["launch_expectation"]["path"], launch_raw
        ),
        "terminal_verifier_execution_plan": _wrapped_bytes(
            seal["terminal_verifier_execution_plan_path"], plan_raw
        ),
        "causal_inventory": {
            "canonical_bytes_sha256": _sha(inventory_raw),
            "size_bytes": len(inventory_raw),
            "payload": inventory,
        },
        "original_revalidated_bytes_equal": True,
        "inventory_recheck_matches_attestation": True,
        "full_evidence_revalidated": True,
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    if set(causal) != _CAUSAL_EVIDENCE_KEYS:
        raise AssertionError("causal receipt schema drift")
    return {
        "attempt_id": attempt_id,
        "created_at_utc": created_at,
        "seal": seal,
        "seal_raw": seal_raw,
        "seal_path": seal_path,
        "validator_inventory": validator_inventory,
        "validator_raw": validator_raw,
        "absence": absence,
        "absence_raw": absence_raw,
        "prereg_raw": prereg_raw,
        "prereg_path": plan["structured_preregistration"]["path"],
        "tooling_source_commit": validator_inventory["tooling_source_commit"],
        "causal": causal,
    }


def build_trigger_a_receipt_bytes(
    *,
    trigger_execution_seal_bytes: object,
    causal_original_decision_bytes: object,
    causal_revalidated_decision_bytes: object,
    causal_completion_attestation_bytes: object,
    causal_revalidation_receipt_bytes: object,
    causal_pid_file_bytes: object,
    causal_exit_file_bytes: object,
    terminal_verifier_execution_plan_bytes: object,
    causal_launch_expectation_bytes: object,
    causal_inventory_bytes: object,
    structured_preregistration_bytes: object,
    trigger_validator_inventory_bytes: object,
    attester_source_bytes: object,
    causal_revalidator_source_bytes: object,
    execution_seal_builder_source_bytes: object,
    trigger_receipt_builder_source_bytes: object,
    trigger_receipt_revalidator_source_bytes: object,
    pretrigger_absence_adapter_source_bytes: object,
    structured_atomic_publisher_source_bytes: object,
    trigger_receipt_publisher_source_bytes: object,
    pretrigger_absence_evidence_bytes: object,
    structured_attempt_id: object,
    created_at_utc: object,
) -> bytes:
    """Reconstruct and bind Trigger A from every registered raw evidence edge."""

    evidence = _validate_all_evidence(
        trigger_execution_seal_bytes=trigger_execution_seal_bytes,
        causal_original_decision_bytes=causal_original_decision_bytes,
        causal_revalidated_decision_bytes=causal_revalidated_decision_bytes,
        causal_completion_attestation_bytes=causal_completion_attestation_bytes,
        causal_revalidation_receipt_bytes=causal_revalidation_receipt_bytes,
        causal_pid_file_bytes=causal_pid_file_bytes,
        causal_exit_file_bytes=causal_exit_file_bytes,
        terminal_verifier_execution_plan_bytes=terminal_verifier_execution_plan_bytes,
        causal_launch_expectation_bytes=causal_launch_expectation_bytes,
        causal_inventory_bytes=causal_inventory_bytes,
        structured_preregistration_bytes=structured_preregistration_bytes,
        trigger_validator_inventory_bytes=trigger_validator_inventory_bytes,
        attester_source_bytes=attester_source_bytes,
        causal_revalidator_source_bytes=causal_revalidator_source_bytes,
        execution_seal_builder_source_bytes=execution_seal_builder_source_bytes,
        trigger_receipt_builder_source_bytes=trigger_receipt_builder_source_bytes,
        trigger_receipt_revalidator_source_bytes=trigger_receipt_revalidator_source_bytes,
        pretrigger_absence_adapter_source_bytes=pretrigger_absence_adapter_source_bytes,
        structured_atomic_publisher_source_bytes=structured_atomic_publisher_source_bytes,
        trigger_receipt_publisher_source_bytes=trigger_receipt_publisher_source_bytes,
        pretrigger_absence_evidence_bytes=pretrigger_absence_evidence_bytes,
        structured_attempt_id=structured_attempt_id,
        created_at_utc=created_at_utc,
    )
    unsigned = {
        "protocol": TRIGGER_RECEIPT_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": "validated_non_authorizing",
        "attempt_id": evidence["attempt_id"],
        "trigger_branch": TRIGGER_A,
        "tooling_source_commit": evidence["tooling_source_commit"],
        "structured_preregistration": _wrapped_bytes(
            evidence["prereg_path"], evidence["prereg_raw"]
        ),
        "trigger_execution_seal": _wrapped_payload(
            evidence["seal_path"], evidence["seal_raw"], evidence["seal"]
        ),
        "trigger_validator_inventory": {
            "path": posixpath.join(
                evidence["absence"]["structured_durable_root"],
                "control",
                "trigger_validator_inventory.json",
            ),
            "file_sha256": _sha(evidence["validator_raw"]),
            "size_bytes": len(evidence["validator_raw"]),
            "payload": evidence["validator_inventory"],
        },
        "causal": evidence["causal"],
        "online_icl": None,
        "pretrigger_absence_evidence": _wrapped_payload(
            posixpath.join(
                evidence["absence"]["structured_durable_root"],
                "control",
                "pretrigger_absence_attestation.json",
            ),
            evidence["absence_raw"],
            evidence["absence"],
        ),
        "created_at_utc": evidence["created_at_utc"],
    }
    payload = dict(unsigned)
    payload["trigger_receipt_sha256"] = _canonical_sha(unsigned)
    return canonical_json_bytes(payload)
