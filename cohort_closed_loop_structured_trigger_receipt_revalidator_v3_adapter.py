"""Independent V3-envelope revalidation for the structured Trigger-A adapter.

This module deliberately does not import or call either Trigger-A receipt
builder.  Core V3 validators independently produce a private receipt projection
only after validating the closure/fence/control chain.  The unchanged legacy
independent revalidator consumes that private value; only a truthful,
non-authorizing V3 envelope is returned.
"""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import importlib
import inspect
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any


PROTOCOL = "cohort_structured_trigger_receipt_revalidator_v3_adapter_v1"
BUILDER_ADAPTER_PROTOCOL = "cohort_structured_trigger_receipt_v3_adapter_v1"
SCHEMA_VERSION = 1
STATUS = "valid_non_authorizing"
BUILDER_STATUS = "validated_non_authorizing"
BRANCH = "structured_trigger_no_go"
VALIDATOR_ADAPTER_KIND = "structured_trigger_no_go_revalidator"

LEGACY_STRICT_MTIME_PROOF = False
MTIME_RELATION = "formal_manifest_before_formal_decision_equal_wrapper_exit"
COMPLETION_METHOD = "post-wrapper-death two-snapshot fence"
HISTORICAL_EXIT_ORDER_CLAIMED = False
LEGACY_PUBLICATION = False
TRUTH_FIELDS = {
    "completion_method": COMPLETION_METHOD,
    "historical_exit_order_claimed": HISTORICAL_EXIT_ORDER_CLAIMED,
    "legacy_publication": LEGACY_PUBLICATION,
    "legacy_strict_mtime_proof": LEGACY_STRICT_MTIME_PROOF,
    "mtime_relation": MTIME_RELATION,
}

FAILURE_CLOSURE_PROTOCOL = "cohort_causal_terminal_verifier_v2_failure_closure_v1"
FAILURE_CLOSURE_STATUS = "closed_equal_second_false_negative"
COMPLETION_FENCE_PROTOCOL = "cohort_causal_terminal_verifier_completion_fence_v3"
COMPLETION_FENCE_STATUS = "frozen_terminal_quiescence"
PLAN_PROTOCOL = "cohort_causal_terminal_verifier_execution_plan_v3"

AUTHORITATIVE_RELATIVE_PATHS = {
    "failure_closure": Path(
        "control/CAUSAL_TERMINAL_VERIFIER_V2_FAILURE_CLOSURE_V1.json"
    ),
    "completion_fence": Path(
        "control/CAUSAL_TERMINAL_VERIFIER_COMPLETION_FENCE_V3.json"
    ),
    "execution_plan": Path("control/CAUSAL_TERMINAL_VERIFIER_EXECUTION_PLAN_V3.json"),
    "launch_claim": Path("control/CAUSAL_TERMINAL_VERIFIER_V3_LAUNCH_CLAIM.json"),
    "detached_receipt": Path(
        "control/CAUSAL_TERMINAL_VERIFIER_V3_DETACHED_RECEIPT.json"
    ),
    "completion_attestation": Path(
        "prep/causal_trigger_completion_attestation.v3.json"
    ),
    "revalidated_decision": Path("prep/causal_formal.revalidated.v3.json"),
    "revalidation_receipt": Path("prep/causal_formal.revalidation_receipt.v3.json"),
    "execution_seal": Path(
        "prep/cohort_closed_loop_structured_state.execution_seal.v3.json"
    ),
}

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_CLASSIFICATION = {
    "decision": "valid_no_go",
    "decision_scope": "internal_gate_no_go",
    "status": "valid",
}
_CONTEXT_KEYS = frozenset(
    {
        "attempt_id",
        "causal_classification",
        "private_projection",
        "tooling_source_commit",
        "truth_fields",
    }
)

AuthoritativeValidator = Callable[..., Mapping[str, Any]]
LegacyRevalidator = Callable[..., object]


class V3TriggerRevalidatorAdapterError(RuntimeError):
    """Raised when independent V3 adapter revalidation fails closed."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise V3TriggerRevalidatorAdapterError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise V3TriggerRevalidatorAdapterError(f"non-finite JSON constant {value}")


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    if not isinstance(payload, bytes):
        raise V3TriggerRevalidatorAdapterError(f"{label} is not bytes")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise V3TriggerRevalidatorAdapterError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise V3TriggerRevalidatorAdapterError(f"{label} is not a JSON object")
    return value


def _normalized_root(value: str | Path) -> Path:
    root = Path(value)
    if (
        not root.is_absolute()
        or root != Path(os.path.normpath(root.as_posix()))
        or _ATTEMPT_RE.fullmatch(root.name) is None
    ):
        raise V3TriggerRevalidatorAdapterError("durable attempt root differs")
    return root


def _normalize_artifacts(
    *,
    durable_attempt_root: str | Path,
    authoritative_artifacts: Mapping[str, object],
    authoritative_paths: Mapping[str, object],
) -> tuple[Path, dict[str, bytes], dict[str, str], dict[str, dict[str, Any]]]:
    root = _normalized_root(durable_attempt_root)
    names = set(AUTHORITATIVE_RELATIVE_PATHS)
    if set(authoritative_artifacts) != names or set(authoritative_paths) != names:
        raise V3TriggerRevalidatorAdapterError(
            "authoritative V3 artifact/path names differ"
        )
    raws: dict[str, bytes] = {}
    paths: dict[str, str] = {}
    bindings: dict[str, dict[str, Any]] = {}
    for name in sorted(names):
        raw = authoritative_artifacts[name]
        path = authoritative_paths[name]
        expected = root / AUTHORITATIVE_RELATIVE_PATHS[name]
        if not isinstance(raw, bytes) or not isinstance(path, str):
            raise V3TriggerRevalidatorAdapterError(
                f"authoritative V3 input type differs: {name}"
            )
        candidate = Path(path)
        if (
            not candidate.is_absolute()
            or candidate != Path(os.path.normpath(candidate.as_posix()))
            or candidate != expected
        ):
            raise V3TriggerRevalidatorAdapterError(
                f"authoritative V3 path differs: {name}"
            )
        raws[name] = raw
        paths[name] = path
        bindings[name] = {
            "path": path,
            "sha256": _sha256(raw),
            "size_bytes": len(raw),
        }
    return root, raws, paths, bindings


def _protocol_precheck(raws: Mapping[str, bytes]) -> None:
    closure = _strict_json(raws["failure_closure"], "failure closure")
    fence = _strict_json(raws["completion_fence"], "completion fence")
    plan = _strict_json(raws["execution_plan"], "execution plan")
    if (
        closure.get("protocol") != FAILURE_CLOSURE_PROTOCOL
        or closure.get("schema_version") != 1
        or closure.get("status") != FAILURE_CLOSURE_STATUS
    ):
        raise V3TriggerRevalidatorAdapterError("failure closure differs")
    if (
        fence.get("protocol") != COMPLETION_FENCE_PROTOCOL
        or fence.get("schema_version") != 3
        or fence.get("status") != COMPLETION_FENCE_STATUS
    ):
        raise V3TriggerRevalidatorAdapterError("completion fence differs")
    if plan.get("protocol") != PLAN_PROTOCOL or plan.get("schema_version") != 3:
        raise V3TriggerRevalidatorAdapterError("execution plan is not V3")


def _call_supported(
    function: Callable[..., Any], value: Any, context: Mapping[str, Any]
) -> Any:
    signature = inspect.signature(function)
    var_kw = any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    )
    kwargs = (
        dict(context)
        if var_kw
        else {key: item for key, item in context.items() if key in signature.parameters}
    )
    return function(value, **kwargs)


def _default_authoritative_validator(
    *,
    authoritative_artifacts: Mapping[str, bytes],
    authoritative_paths: Mapping[str, str],
    durable_attempt_root: Path,
    require_execution_seal: bool,
    adapter_kind: str,
) -> Mapping[str, Any]:
    if require_execution_seal is not True or adapter_kind != VALIDATOR_ADAPTER_KIND:
        raise V3TriggerRevalidatorAdapterError("independent adapter mode differs")
    try:
        recovery = importlib.import_module("freeze_cohort_causal_terminal_recovery_v3")
        attester = importlib.import_module("attest_cohort_causal_completion_v3")
        revalidator = importlib.import_module("revalidate_cohort_causal_terminal_v3")
        seal_builder = importlib.import_module(
            "build_cohort_structured_state_execution_seal_v3"
        )
    except ImportError as exc:
        raise V3TriggerRevalidatorAdapterError(
            "authoritative V3 validator modules are unavailable"
        ) from exc
    documents = {
        name: _strict_json(raw, f"authoritative {name}")
        for name, raw in authoritative_artifacts.items()
    }
    context = {
        "adapter_kind": adapter_kind,
        "artifacts": documents,
        "artifact_bytes": dict(authoritative_artifacts),
        "artifact_paths": dict(authoritative_paths),
        "durable_attempt_root": durable_attempt_root,
        "expected_path": Path(authoritative_paths["failure_closure"]),
        "failure_closure_path": Path(authoritative_paths["failure_closure"]),
        "failure_closure_sha256": _sha256(authoritative_artifacts["failure_closure"]),
        "require_execution_seal": True,
    }
    closure = _call_supported(
        recovery.validate_failure_closure_document,
        documents["failure_closure"],
        context,
    )
    fence_context = {
        **context,
        "expected_path": Path(authoritative_paths["completion_fence"]),
        "failure_closure": closure,
    }
    fence = _call_supported(
        recovery.validate_completion_fence_document,
        documents["completion_fence"],
        fence_context,
    )
    validation = {**context, "failure_closure": closure, "completion_fence": fence}
    attested = _call_supported(
        attester.validate_attestation_document,
        documents["completion_attestation"],
        validation,
    )
    revalidated = _call_supported(
        revalidator.validate_revalidation_receipt_document,
        documents["revalidation_receipt"],
        {**validation, "completion_attestation": attested},
    )
    sealed = _call_supported(
        seal_builder.validate_execution_seal_document,
        documents["execution_seal"],
        {
            **validation,
            "completion_attestation": attested,
            "revalidation_receipt": revalidated,
        },
    )
    projection_builder = getattr(
        seal_builder, "build_downstream_private_projection", None
    )
    if projection_builder is None:
        raise V3TriggerRevalidatorAdapterError(
            "core V3 validators expose no private downstream projection"
        )
    result = projection_builder(
        adapter_kind=adapter_kind,
        artifacts=documents,
        artifact_bytes=dict(authoritative_artifacts),
        artifact_paths=dict(authoritative_paths),
        durable_attempt_root=durable_attempt_root,
        failure_closure=closure,
        completion_fence=fence,
        completion_attestation=attested,
        revalidation_receipt=revalidated,
        execution_seal=sealed,
    )
    if not isinstance(result, Mapping):
        raise V3TriggerRevalidatorAdapterError("private projection is invalid")
    return result


def _validate_context(value: Mapping[str, Any], *, attempt_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CONTEXT_KEYS:
        raise V3TriggerRevalidatorAdapterError("validator context schema differs")
    context = dict(value)
    if context["attempt_id"] != attempt_id:
        raise V3TriggerRevalidatorAdapterError("validator attempt differs")
    commit = context["tooling_source_commit"]
    if not isinstance(commit, str) or _COMMIT_RE.fullmatch(commit) is None:
        raise V3TriggerRevalidatorAdapterError("validator commit is invalid")
    if context["causal_classification"] != _CLASSIFICATION:
        raise V3TriggerRevalidatorAdapterError("validator causal branch differs")
    if context["truth_fields"] != TRUTH_FIELDS:
        raise V3TriggerRevalidatorAdapterError("validator truth fields differ")
    projection = context["private_projection"]
    if (
        not isinstance(projection, Mapping)
        or set(projection) != {"receipt_bytes", "revalidator_kwargs"}
        or not isinstance(projection["receipt_bytes"], bytes)
        or not projection["receipt_bytes"]
        or not isinstance(projection["revalidator_kwargs"], Mapping)
        or not projection["revalidator_kwargs"]
        or any(
            not isinstance(key, str) or not key
            for key in projection["revalidator_kwargs"]
        )
    ):
        raise V3TriggerRevalidatorAdapterError("private projection differs")
    context["causal_classification"] = dict(context["causal_classification"])
    context["private_projection"] = {
        "receipt_bytes": projection["receipt_bytes"],
        "revalidator_kwargs": dict(projection["revalidator_kwargs"]),
    }
    return context


def _projection_manifest(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"private_bytes_sha256": _sha256(value), "size_bytes": len(value)}
    if isinstance(value, Path):
        return {"private_path": value.as_posix()}
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise V3TriggerRevalidatorAdapterError(
                "private projection has non-string key"
            )
        return {key: _projection_manifest(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_projection_manifest(item) for item in value]
    raise V3TriggerRevalidatorAdapterError(
        "private projection contains unsupported value"
    )


def _validate_public_bindings(
    value: Any, *, attempt_id: str
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != set(AUTHORITATIVE_RELATIVE_PATHS):
        raise V3TriggerRevalidatorAdapterError(
            "public authoritative V3 binding names differ"
        )
    closure = value["failure_closure"]
    if not isinstance(closure, dict) or set(closure) != {
        "path",
        "sha256",
        "size_bytes",
    }:
        raise V3TriggerRevalidatorAdapterError("public failure-closure binding differs")
    if not isinstance(closure["path"], str):
        raise V3TriggerRevalidatorAdapterError("public failure-closure path differs")
    closure_path = Path(closure["path"])
    if len(closure_path.parents) < 2:
        raise V3TriggerRevalidatorAdapterError(
            "public authoritative V3 root is invalid"
        )
    root = closure_path.parents[1]
    if (
        not root.is_absolute()
        or root != Path(os.path.normpath(root.as_posix()))
        or root.name != attempt_id
    ):
        raise V3TriggerRevalidatorAdapterError("public authoritative V3 root differs")
    normalized: dict[str, dict[str, Any]] = {}
    for name in sorted(AUTHORITATIVE_RELATIVE_PATHS):
        binding = value[name]
        if not isinstance(binding, dict) or set(binding) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise V3TriggerRevalidatorAdapterError(
                f"public V3 binding schema differs: {name}"
            )
        digest = binding["sha256"]
        size = binding["size_bytes"]
        if (
            binding["path"] != (root / AUTHORITATIVE_RELATIVE_PATHS[name]).as_posix()
            or not isinstance(digest, str)
            or _SHA256_RE.fullmatch(digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
        ):
            raise V3TriggerRevalidatorAdapterError(f"public V3 binding differs: {name}")
        normalized[name] = dict(binding)
    return normalized


def _validate_builder_envelope(payload: bytes) -> dict[str, Any]:
    value = _strict_json(payload, "V3 trigger adapter envelope")
    unsigned_keys = {
        "attempt_id",
        "authoritative_v3_artifacts",
        "branch",
        "causal_classification",
        "completion_method",
        "historical_exit_order_claimed",
        "legacy_engine_proof_sha256",
        "legacy_publication",
        "legacy_strict_mtime_proof",
        "model_calls_authorized",
        "mtime_relation",
        "operational_authorization",
        "outcome_blind_adapter_registration",
        "private_projection_sha256",
        "protocol",
        "schema_version",
        "status",
        "tooling_source_commit",
    }
    if set(value) != unsigned_keys | {"adapter_receipt_sha256"}:
        raise V3TriggerRevalidatorAdapterError("builder envelope schema differs")
    if payload != _canonical_bytes(value):
        raise V3TriggerRevalidatorAdapterError("builder envelope is not canonical")
    if (
        value["protocol"] != BUILDER_ADAPTER_PROTOCOL
        or value["schema_version"] != 1
        or value["status"] != BUILDER_STATUS
        or value["branch"] != BRANCH
        or value["causal_classification"] != _CLASSIFICATION
        or value["completion_method"] != COMPLETION_METHOD
        or value["historical_exit_order_claimed"] is not False
        or value["legacy_publication"] is not False
        or value["legacy_strict_mtime_proof"] is not False
        or value["model_calls_authorized"] is not False
        or value["mtime_relation"] != MTIME_RELATION
        or value["operational_authorization"] is not False
        or value["outcome_blind_adapter_registration"] is not True
    ):
        raise V3TriggerRevalidatorAdapterError("builder envelope claims differ")
    if (
        not isinstance(value["attempt_id"], str)
        or _ATTEMPT_RE.fullmatch(value["attempt_id"]) is None
        or not isinstance(value["tooling_source_commit"], str)
        or _COMMIT_RE.fullmatch(value["tooling_source_commit"]) is None
    ):
        raise V3TriggerRevalidatorAdapterError("builder envelope identity differs")
    _validate_public_bindings(
        value["authoritative_v3_artifacts"], attempt_id=value["attempt_id"]
    )
    for key in (
        "adapter_receipt_sha256",
        "legacy_engine_proof_sha256",
        "private_projection_sha256",
    ):
        item = value[key]
        if not isinstance(item, str) or _SHA256_RE.fullmatch(item) is None:
            raise V3TriggerRevalidatorAdapterError(
                f"builder envelope digest is invalid: {key}"
            )
    if value["adapter_receipt_sha256"] != _canonical_sha256(
        {key: value[key] for key in unsigned_keys}
    ):
        raise V3TriggerRevalidatorAdapterError("builder envelope digest differs")
    return value


def _legacy_manifest(value: object) -> dict[str, Any]:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        raw = dataclasses.asdict(value)
    elif isinstance(value, Mapping):
        raw = dict(value)
    else:
        names = (
            "attempt_id",
            "causal_decision_sha256",
            "model_calls_authorized",
            "operational_authorization",
            "tooling_source_commit",
            "trigger_branch",
            "trigger_receipt_sha256",
        )
        if any(not hasattr(value, name) for name in names):
            raise V3TriggerRevalidatorAdapterError(
                "private legacy revalidation result is invalid"
            )
        raw = {name: getattr(value, name) for name in names}
    required = {
        "attempt_id",
        "causal_decision_sha256",
        "model_calls_authorized",
        "operational_authorization",
        "tooling_source_commit",
        "trigger_branch",
        "trigger_receipt_sha256",
    }
    if (
        set(raw) != required
        or raw["model_calls_authorized"] is not False
        or raw["operational_authorization"] is not False
        or raw["trigger_branch"] != "causal_valid_no_go"
    ):
        raise V3TriggerRevalidatorAdapterError(
            "private legacy revalidation result differs"
        )
    return raw


def revalidate_trigger_a_receipt_v3_adapter_bytes(
    receipt_bytes: bytes,
    *,
    durable_attempt_root: str | Path,
    authoritative_artifacts: Mapping[str, object],
    authoritative_paths: Mapping[str, object],
    authoritative_validator: AuthoritativeValidator | None = None,
    legacy_revalidator: LegacyRevalidator | None = None,
) -> bytes:
    """Independently validate V3 and a private legacy receipt; return V3 only."""

    public_receipt = _validate_builder_envelope(receipt_bytes)
    root, raws, paths, bindings = _normalize_artifacts(
        durable_attempt_root=durable_attempt_root,
        authoritative_artifacts=authoritative_artifacts,
        authoritative_paths=authoritative_paths,
    )
    _protocol_precheck(raws)
    if public_receipt["authoritative_v3_artifacts"] != bindings:
        raise V3TriggerRevalidatorAdapterError(
            "builder authoritative V3 bindings differ"
        )
    validate = authoritative_validator or _default_authoritative_validator
    try:
        raw_context = validate(
            authoritative_artifacts=raws,
            authoritative_paths=paths,
            durable_attempt_root=root,
            require_execution_seal=True,
            adapter_kind=VALIDATOR_ADAPTER_KIND,
        )
        context = _validate_context(raw_context, attempt_id=root.name)
    except V3TriggerRevalidatorAdapterError:
        raise
    except Exception as exc:
        raise V3TriggerRevalidatorAdapterError(
            "independent authoritative V3 validation failed"
        ) from exc
    projection = context["private_projection"]
    projection_sha = _canonical_sha256(_projection_manifest(projection))
    private_receipt = projection["receipt_bytes"]
    if (
        projection_sha != public_receipt["private_projection_sha256"]
        or _sha256(private_receipt) != public_receipt["legacy_engine_proof_sha256"]
        or context["causal_classification"] != public_receipt["causal_classification"]
        or context["tooling_source_commit"] != public_receipt["tooling_source_commit"]
    ):
        raise V3TriggerRevalidatorAdapterError(
            "builder envelope differs from private reconstruction"
        )

    if legacy_revalidator is None:
        legacy_revalidator = importlib.import_module(
            "cohort_closed_loop_structured_trigger_receipt_revalidator"
        ).validate_trigger_a_receipt_bytes
    try:
        result = legacy_revalidator(private_receipt, **projection["revalidator_kwargs"])
    except Exception as exc:
        raise V3TriggerRevalidatorAdapterError(
            "private independent legacy revalidation failed"
        ) from exc
    legacy_manifest = _legacy_manifest(result)

    unsigned = {
        "adapter_receipt_file_sha256": _sha256(receipt_bytes),
        "adapter_receipt_sha256": public_receipt["adapter_receipt_sha256"],
        "attempt_id": root.name,
        "authoritative_v3_artifacts": bindings,
        "branch": BRANCH,
        "causal_classification": context["causal_classification"],
        "completion_method": COMPLETION_METHOD,
        "historical_exit_order_claimed": HISTORICAL_EXIT_ORDER_CLAIMED,
        "legacy_engine_proof_sha256": _sha256(private_receipt),
        "legacy_publication": LEGACY_PUBLICATION,
        "legacy_revalidation_proof_sha256": _canonical_sha256(legacy_manifest),
        "legacy_strict_mtime_proof": LEGACY_STRICT_MTIME_PROOF,
        "model_calls_authorized": False,
        "mtime_relation": MTIME_RELATION,
        "operational_authorization": False,
        "outcome_blind_adapter_registration": True,
        "private_projection_sha256": projection_sha,
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tooling_source_commit": context["tooling_source_commit"],
    }
    envelope = dict(unsigned)
    envelope["adapter_revalidation_sha256"] = _canonical_sha256(unsigned)
    return _canonical_bytes(envelope)


def validate_revalidation_envelope_bytes(payload: bytes) -> dict[str, Any]:
    value = _strict_json(payload, "V3 adapter revalidation envelope")
    unsigned = dict(value)
    digest = unsigned.pop("adapter_revalidation_sha256", None)
    expected_keys = {
        "adapter_receipt_file_sha256",
        "adapter_receipt_sha256",
        "attempt_id",
        "authoritative_v3_artifacts",
        "branch",
        "causal_classification",
        "completion_method",
        "historical_exit_order_claimed",
        "legacy_engine_proof_sha256",
        "legacy_publication",
        "legacy_revalidation_proof_sha256",
        "legacy_strict_mtime_proof",
        "model_calls_authorized",
        "mtime_relation",
        "operational_authorization",
        "outcome_blind_adapter_registration",
        "private_projection_sha256",
        "protocol",
        "schema_version",
        "status",
        "tooling_source_commit",
    }
    if set(unsigned) != expected_keys or not isinstance(digest, str):
        raise V3TriggerRevalidatorAdapterError(
            "V3 adapter revalidation envelope schema differs"
        )
    if payload != _canonical_bytes(value):
        raise V3TriggerRevalidatorAdapterError(
            "V3 adapter revalidation envelope is not canonical"
        )
    if (
        value["protocol"] != PROTOCOL
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] != STATUS
        or value["branch"] != BRANCH
        or value["causal_classification"] != _CLASSIFICATION
        or value["completion_method"] != COMPLETION_METHOD
        or value["historical_exit_order_claimed"] is not False
        or value["legacy_publication"] is not False
        or value["legacy_strict_mtime_proof"] is not False
        or value["model_calls_authorized"] is not False
        or value["mtime_relation"] != MTIME_RELATION
        or value["operational_authorization"] is not False
        or value["outcome_blind_adapter_registration"] is not True
        or digest != _canonical_sha256(unsigned)
    ):
        raise V3TriggerRevalidatorAdapterError(
            "V3 adapter revalidation public claims differ"
        )
    if (
        not isinstance(value["attempt_id"], str)
        or _ATTEMPT_RE.fullmatch(value["attempt_id"]) is None
        or not isinstance(value["tooling_source_commit"], str)
        or _COMMIT_RE.fullmatch(value["tooling_source_commit"]) is None
    ):
        raise V3TriggerRevalidatorAdapterError(
            "V3 adapter revalidation identity differs"
        )
    _validate_public_bindings(
        value["authoritative_v3_artifacts"], attempt_id=value["attempt_id"]
    )
    for key in (
        "adapter_receipt_file_sha256",
        "adapter_receipt_sha256",
        "adapter_revalidation_sha256",
        "legacy_engine_proof_sha256",
        "legacy_revalidation_proof_sha256",
        "private_projection_sha256",
    ):
        item = value[key]
        if not isinstance(item, str) or _SHA256_RE.fullmatch(item) is None:
            raise V3TriggerRevalidatorAdapterError(
                f"V3 adapter revalidation digest is invalid: {key}"
            )
    return value


def _assert_no_symlink(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            raise V3TriggerRevalidatorAdapterError(
                f"authoritative input is missing: {path}"
            ) from None
        if stat.S_ISLNK(mode):
            raise V3TriggerRevalidatorAdapterError(
                f"authoritative input traverses a symlink: {path}"
            )


def _read_stable(path: Path) -> bytes:
    _assert_no_symlink(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise V3TriggerRevalidatorAdapterError(
            f"cannot open authoritative input: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise V3TriggerRevalidatorAdapterError(
                f"authoritative input is not regular: {path}"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_id = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_id = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_id != after_id:
        raise V3TriggerRevalidatorAdapterError(
            f"authoritative input drifted while reading: {path}"
        )
    return b"".join(chunks)


def _assert_output_absent(path: str | Path) -> None:
    output = Path(path)
    if not output.is_absolute() or output != Path(os.path.normpath(output.as_posix())):
        raise V3TriggerRevalidatorAdapterError("prospective output path differs")
    try:
        os.lstat(output)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise V3TriggerRevalidatorAdapterError(
                "cannot inspect prospective output"
            ) from exc
    else:
        raise FileExistsError(f"refusing a pre-existing adapter output: {output}")
    if output.parent.exists():
        _assert_no_symlink(output.parent)


def revalidate_trigger_a_receipt_v3_adapter_from_root(
    *,
    receipt_path: str | Path,
    durable_attempt_root: str | Path,
    prospective_output_path: str | Path,
    authoritative_validator: AuthoritativeValidator | None = None,
    legacy_revalidator: LegacyRevalidator | None = None,
) -> bytes:
    """Safely load fixed V3 inputs and return bytes without publication."""

    root = _normalized_root(durable_attempt_root)
    _assert_output_absent(prospective_output_path)
    receipt_file = Path(receipt_path)
    receipt_raw = _read_stable(receipt_file)
    _validate_builder_envelope(receipt_raw)
    paths = {
        name: (root / relative).as_posix()
        for name, relative in AUTHORITATIVE_RELATIVE_PATHS.items()
    }
    control_names = ("failure_closure", "completion_fence", "execution_plan")
    raws = {name: _read_stable(Path(paths[name])) for name in control_names}
    _protocol_precheck(raws)
    raws.update(
        {
            name: _read_stable(Path(path))
            for name, path in paths.items()
            if name not in raws
        }
    )
    result = revalidate_trigger_a_receipt_v3_adapter_bytes(
        receipt_raw,
        durable_attempt_root=root,
        authoritative_artifacts=raws,
        authoritative_paths=paths,
        authoritative_validator=authoritative_validator,
        legacy_revalidator=legacy_revalidator,
    )
    if _read_stable(receipt_file) != receipt_raw:
        raise V3TriggerRevalidatorAdapterError(
            "public adapter receipt drifted before return"
        )
    for name, path in paths.items():
        if _read_stable(Path(path)) != raws[name]:
            raise V3TriggerRevalidatorAdapterError(
                f"authoritative input drifted before return: {name}"
            )
    _assert_output_absent(prospective_output_path)
    return result


__all__ = (
    "PROTOCOL",
    "SCHEMA_VERSION",
    "V3TriggerRevalidatorAdapterError",
    "revalidate_trigger_a_receipt_v3_adapter_bytes",
    "revalidate_trigger_a_receipt_v3_adapter_from_root",
    "validate_revalidation_envelope_bytes",
)
