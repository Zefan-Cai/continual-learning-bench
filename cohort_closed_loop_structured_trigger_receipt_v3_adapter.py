"""Outcome-blind V3 adapter for the structured Trigger-A receipt engine.

The equal-second incident closed the legacy completion proof.  Consequently,
this adapter never presents V3 evidence directly to a V1/V2 downstream
consumer.  It first requires the authoritative V3 closure, completion fence,
transport receipt, completion attestation, revalidation receipt, and execution
seal to validate.  Only then may a validator construct a private compatibility
projection for the unchanged legacy Trigger-A engine.

The compatibility projection and legacy receipt are never returned or
published.  The sole public value is a truthful V3 envelope that binds their
digests and explicitly disclaims the legacy mtime/exit-order claims and all
operational authority.
"""

from __future__ import annotations

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


PROTOCOL = "cohort_structured_trigger_receipt_v3_adapter_v1"
SCHEMA_VERSION = 1
STATUS = "validated_non_authorizing"
BRANCH = "structured_trigger_no_go"

LEGACY_STRICT_MTIME_PROOF = False
MTIME_RELATION = "formal_manifest_before_formal_decision_equal_wrapper_exit"
COMPLETION_METHOD = "post-wrapper-death two-snapshot fence"
HISTORICAL_EXIT_ORDER_CLAIMED = False
LEGACY_PUBLICATION = False

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

TRUTH_FIELDS = {
    "completion_method": COMPLETION_METHOD,
    "historical_exit_order_claimed": HISTORICAL_EXIT_ORDER_CLAIMED,
    "legacy_publication": LEGACY_PUBLICATION,
    "legacy_strict_mtime_proof": LEGACY_STRICT_MTIME_PROOF,
    "mtime_relation": MTIME_RELATION,
}

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_CLASSIFICATION_KEYS = frozenset({"decision", "decision_scope", "status"})
_VALIDATED_CONTEXT_KEYS = frozenset(
    {
        "attempt_id",
        "causal_classification",
        "private_projection",
        "tooling_source_commit",
        "truth_fields",
    }
)
_EXPECTED_CLASSIFICATION = {
    "decision": "valid_no_go",
    "decision_scope": "internal_gate_no_go",
    "status": "valid",
}

AuthoritativeValidator = Callable[..., Mapping[str, Any]]
LegacyBuilder = Callable[..., bytes]


class V3TriggerAdapterError(RuntimeError):
    """Raised when the authoritative V3-to-private-legacy boundary fails."""


def canonical_bytes(value: Any) -> bytes:
    """Return the adapter's sole canonical JSON representation."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise V3TriggerAdapterError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise V3TriggerAdapterError(f"non-finite JSON constant {value}")


def strict_json_object(payload: bytes, label: str) -> dict[str, Any]:
    """Parse strict JSON without granting canonicality or semantic authority."""

    if not isinstance(payload, bytes):
        raise V3TriggerAdapterError(f"{label} is not bytes")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise V3TriggerAdapterError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise V3TriggerAdapterError(f"{label} is not a JSON object")
    return value


def _normalized_root(value: str | Path) -> Path:
    root = Path(value)
    if not root.is_absolute() or root != Path(os.path.normpath(root.as_posix())):
        raise V3TriggerAdapterError("durable attempt root is not normalized absolute")
    if _ATTEMPT_RE.fullmatch(root.name) is None:
        raise V3TriggerAdapterError("durable attempt root has no exact attempt id")
    return root


def _normalize_artifacts(
    *,
    durable_attempt_root: str | Path,
    authoritative_artifacts: Mapping[str, object],
    authoritative_paths: Mapping[str, object],
    require_execution_seal: bool,
) -> tuple[Path, dict[str, bytes], dict[str, str], dict[str, dict[str, Any]]]:
    root = _normalized_root(durable_attempt_root)
    expected_names = set(AUTHORITATIVE_RELATIVE_PATHS)
    if not require_execution_seal:
        expected_names.remove("execution_seal")
    if set(authoritative_artifacts) != expected_names:
        raise V3TriggerAdapterError("authoritative V3 artifact names differ")
    if set(authoritative_paths) != expected_names:
        raise V3TriggerAdapterError("authoritative V3 path names differ")

    raws: dict[str, bytes] = {}
    paths: dict[str, str] = {}
    bindings: dict[str, dict[str, Any]] = {}
    for name in sorted(expected_names):
        raw = authoritative_artifacts[name]
        path = authoritative_paths[name]
        if not isinstance(raw, bytes):
            raise V3TriggerAdapterError(f"authoritative artifact is not bytes: {name}")
        if not isinstance(path, str):
            raise V3TriggerAdapterError(
                f"authoritative artifact path is invalid: {name}"
            )
        expected = root / AUTHORITATIVE_RELATIVE_PATHS[name]
        candidate = Path(path)
        if (
            not candidate.is_absolute()
            or candidate != Path(os.path.normpath(candidate.as_posix()))
            or candidate != expected
        ):
            raise V3TriggerAdapterError(f"authoritative V3 path differs: {name}")
        raws[name] = raw
        paths[name] = path
        bindings[name] = {
            "path": path,
            "sha256": _sha256(raw),
            "size_bytes": len(raw),
        }
    return root, raws, paths, bindings


def _protocol_precheck(raws: Mapping[str, bytes]) -> None:
    """Reject obvious V1/V2 poisoning before any private engine can run."""

    closure = strict_json_object(raws["failure_closure"], "failure closure")
    fence = strict_json_object(raws["completion_fence"], "completion fence")
    plan = strict_json_object(raws["execution_plan"], "execution plan")
    if (
        closure.get("protocol") != FAILURE_CLOSURE_PROTOCOL
        or closure.get("schema_version") != 1
        or closure.get("status") != FAILURE_CLOSURE_STATUS
    ):
        raise V3TriggerAdapterError("authoritative failure closure differs")
    if (
        fence.get("protocol") != COMPLETION_FENCE_PROTOCOL
        or fence.get("schema_version") != 3
        or fence.get("status") != COMPLETION_FENCE_STATUS
    ):
        raise V3TriggerAdapterError("authoritative completion fence differs")
    if plan.get("protocol") != PLAN_PROTOCOL or plan.get("schema_version") != 3:
        raise V3TriggerAdapterError("authoritative execution plan is not V3")


def _call_with_supported_keywords(
    function: Callable[..., Any], value: Any, context: Mapping[str, Any]
) -> Any:
    """Call a lazy V3 validator while keeping its eventual signature explicit."""

    signature = inspect.signature(function)
    accepts_var_kw = any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    )
    kwargs = (
        dict(context)
        if accepts_var_kw
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
    """Lazily enter core V3 validators; fail closed until they expose projection."""

    try:
        recovery = importlib.import_module("freeze_cohort_causal_terminal_recovery_v3")
        attester = importlib.import_module("attest_cohort_causal_completion_v3")
        revalidator = importlib.import_module("revalidate_cohort_causal_terminal_v3")
        seal_builder = importlib.import_module(
            "build_cohort_structured_state_execution_seal_v3"
        )
    except ImportError as exc:
        raise V3TriggerAdapterError(
            "authoritative V3 validator modules are unavailable"
        ) from exc

    documents = {
        name: strict_json_object(raw, f"authoritative {name}")
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
        "require_execution_seal": require_execution_seal,
    }
    closure = _call_with_supported_keywords(
        recovery.validate_failure_closure_document,
        documents["failure_closure"],
        context,
    )
    fence_context = {
        **context,
        "expected_path": Path(authoritative_paths["completion_fence"]),
        "failure_closure": closure,
    }
    fence = _call_with_supported_keywords(
        recovery.validate_completion_fence_document,
        documents["completion_fence"],
        fence_context,
    )
    validation_context = {
        **context,
        "failure_closure": closure,
        "completion_fence": fence,
    }
    attested = _call_with_supported_keywords(
        attester.validate_attestation_document,
        documents["completion_attestation"],
        validation_context,
    )
    revalidated = _call_with_supported_keywords(
        revalidator.validate_revalidation_receipt_document,
        documents["revalidation_receipt"],
        {**validation_context, "completion_attestation": attested},
    )
    sealed = None
    if require_execution_seal:
        sealed = _call_with_supported_keywords(
            seal_builder.validate_execution_seal_document,
            documents["execution_seal"],
            {
                **validation_context,
                "completion_attestation": attested,
                "revalidation_receipt": revalidated,
            },
        )

    projection_builder = getattr(
        seal_builder, "build_downstream_private_projection", None
    )
    if projection_builder is None:
        raise V3TriggerAdapterError(
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
        raise V3TriggerAdapterError("private downstream projection is invalid")
    return result


def _validate_context(value: Mapping[str, Any], *, attempt_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _VALIDATED_CONTEXT_KEYS:
        raise V3TriggerAdapterError("authoritative validator context schema differs")
    context = dict(value)
    if context["attempt_id"] != attempt_id:
        raise V3TriggerAdapterError("authoritative validator attempt differs")
    commit = context["tooling_source_commit"]
    if not isinstance(commit, str) or _COMMIT_RE.fullmatch(commit) is None:
        raise V3TriggerAdapterError("authoritative validator commit is invalid")
    classification = context["causal_classification"]
    if (
        not isinstance(classification, Mapping)
        or set(classification) != _CLASSIFICATION_KEYS
        or dict(classification) != _EXPECTED_CLASSIFICATION
    ):
        raise V3TriggerAdapterError("structured adapter causal branch differs")
    if context["truth_fields"] != TRUTH_FIELDS:
        raise V3TriggerAdapterError("authoritative V3 truth fields differ")
    projection = context["private_projection"]
    if (
        not isinstance(projection, Mapping)
        or set(projection) != {"builder_kwargs", "revalidator_kwargs"}
        or not isinstance(projection["builder_kwargs"], Mapping)
        or not projection["builder_kwargs"]
        or not isinstance(projection["revalidator_kwargs"], Mapping)
        or not projection["revalidator_kwargs"]
    ):
        raise V3TriggerAdapterError("private compatibility projection is missing")
    for stage in ("builder_kwargs", "revalidator_kwargs"):
        if any(not isinstance(key, str) or not key for key in projection[stage]):
            raise V3TriggerAdapterError("private compatibility projection keys differ")
    context["causal_classification"] = dict(classification)
    context["private_projection"] = dict(projection)
    return context


def _projection_manifest(value: Any) -> Any:
    """Create a public-safe digest manifest without exposing legacy bytes."""

    if isinstance(value, bytes):
        return {"private_bytes_sha256": _sha256(value), "size_bytes": len(value)}
    if isinstance(value, Path):
        return {"private_path": value.as_posix()}
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise V3TriggerAdapterError("private projection has a non-string key")
        return {key: _projection_manifest(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_projection_manifest(item) for item in value]
    raise V3TriggerAdapterError("private projection contains an unsupported value")


def _validate_public_bindings(
    value: Any, *, attempt_id: str, require_execution_seal: bool
) -> dict[str, dict[str, Any]]:
    names = set(AUTHORITATIVE_RELATIVE_PATHS)
    if not require_execution_seal:
        names.remove("execution_seal")
    if not isinstance(value, dict) or set(value) != names:
        raise V3TriggerAdapterError("public authoritative V3 binding names differ")
    closure = value["failure_closure"]
    if not isinstance(closure, dict) or set(closure) != {
        "path",
        "sha256",
        "size_bytes",
    }:
        raise V3TriggerAdapterError("public failure-closure binding differs")
    if not isinstance(closure["path"], str):
        raise V3TriggerAdapterError("public failure-closure path differs")
    closure_path = Path(closure["path"])
    if len(closure_path.parents) < 2:
        raise V3TriggerAdapterError("public authoritative V3 root is invalid")
    root = closure_path.parents[1]
    if (
        not root.is_absolute()
        or root != Path(os.path.normpath(root.as_posix()))
        or root.name != attempt_id
    ):
        raise V3TriggerAdapterError("public authoritative V3 root differs")
    normalized: dict[str, dict[str, Any]] = {}
    for name in sorted(names):
        binding = value[name]
        if not isinstance(binding, dict) or set(binding) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise V3TriggerAdapterError(f"public V3 binding schema differs: {name}")
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
            raise V3TriggerAdapterError(f"public V3 binding differs: {name}")
        normalized[name] = dict(binding)
    return normalized


def build_trigger_a_receipt_v3_adapter_bytes(
    *,
    durable_attempt_root: str | Path,
    authoritative_artifacts: Mapping[str, object],
    authoritative_paths: Mapping[str, object],
    authoritative_validator: AuthoritativeValidator | None = None,
    legacy_builder: LegacyBuilder | None = None,
) -> bytes:
    """Validate V3 first, privately run Trigger A, and return only a V3 envelope."""

    root, raws, paths, bindings = _normalize_artifacts(
        durable_attempt_root=durable_attempt_root,
        authoritative_artifacts=authoritative_artifacts,
        authoritative_paths=authoritative_paths,
        require_execution_seal=True,
    )
    _protocol_precheck(raws)
    validate = authoritative_validator or _default_authoritative_validator
    try:
        raw_context = validate(
            authoritative_artifacts=raws,
            authoritative_paths=paths,
            durable_attempt_root=root,
            require_execution_seal=True,
            adapter_kind=BRANCH,
        )
    except V3TriggerAdapterError:
        raise
    except Exception as exc:
        raise V3TriggerAdapterError("authoritative V3 validation failed") from exc
    context = _validate_context(raw_context, attempt_id=root.name)

    # The legacy engine is deliberately resolved only after every V3 gate above.
    if legacy_builder is None:
        legacy_module = importlib.import_module(
            "cohort_closed_loop_structured_trigger_receipt"
        )
        legacy_builder = legacy_module.build_trigger_a_receipt_bytes
    projection = context["private_projection"]
    try:
        legacy_receipt = legacy_builder(**projection["builder_kwargs"])
    except Exception as exc:
        raise V3TriggerAdapterError(
            "private legacy Trigger-A engine rejected projection"
        ) from exc
    if not isinstance(legacy_receipt, bytes) or not legacy_receipt:
        raise V3TriggerAdapterError("private legacy Trigger-A proof is invalid")
    # The public projection digest is independently reproducible by the
    # revalidator without importing or calling this builder.
    revalidation_projection = {
        "receipt_bytes": legacy_receipt,
        "revalidator_kwargs": projection["revalidator_kwargs"],
    }
    projection_sha = canonical_sha256(_projection_manifest(revalidation_projection))

    unsigned = {
        "attempt_id": root.name,
        "authoritative_v3_artifacts": bindings,
        "branch": BRANCH,
        "causal_classification": context["causal_classification"],
        "completion_method": COMPLETION_METHOD,
        "historical_exit_order_claimed": HISTORICAL_EXIT_ORDER_CLAIMED,
        "legacy_engine_proof_sha256": _sha256(legacy_receipt),
        "legacy_publication": LEGACY_PUBLICATION,
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
    envelope["adapter_receipt_sha256"] = canonical_sha256(unsigned)
    return canonical_bytes(envelope)


def validate_adapter_envelope_bytes(payload: bytes) -> dict[str, Any]:
    """Validate the public envelope without reconstructing private evidence."""

    value = strict_json_object(payload, "V3 trigger adapter envelope")
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
        raise V3TriggerAdapterError("V3 trigger adapter envelope schema differs")
    if payload != canonical_bytes(value):
        raise V3TriggerAdapterError("V3 trigger adapter envelope is not canonical")
    if (
        value["protocol"] != PROTOCOL
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] != STATUS
        or value["branch"] != BRANCH
        or value["causal_classification"] != _EXPECTED_CLASSIFICATION
        or value["completion_method"] != COMPLETION_METHOD
        or value["historical_exit_order_claimed"] is not False
        or value["legacy_publication"] is not False
        or value["legacy_strict_mtime_proof"] is not False
        or value["model_calls_authorized"] is not False
        or value["mtime_relation"] != MTIME_RELATION
        or value["operational_authorization"] is not False
        or value["outcome_blind_adapter_registration"] is not True
    ):
        raise V3TriggerAdapterError("V3 trigger adapter public claims differ")
    if (
        not isinstance(value["attempt_id"], str)
        or _ATTEMPT_RE.fullmatch(value["attempt_id"]) is None
        or not isinstance(value["tooling_source_commit"], str)
        or _COMMIT_RE.fullmatch(value["tooling_source_commit"]) is None
    ):
        raise V3TriggerAdapterError("V3 trigger adapter identity differs")
    _validate_public_bindings(
        value["authoritative_v3_artifacts"],
        attempt_id=value["attempt_id"],
        require_execution_seal=True,
    )
    for key in (
        "adapter_receipt_sha256",
        "legacy_engine_proof_sha256",
        "private_projection_sha256",
    ):
        if not isinstance(value[key], str) or _SHA256_RE.fullmatch(value[key]) is None:
            raise V3TriggerAdapterError(f"V3 trigger adapter digest is invalid: {key}")
    if value["adapter_receipt_sha256"] != canonical_sha256(
        {key: value[key] for key in unsigned_keys}
    ):
        raise V3TriggerAdapterError("V3 trigger adapter self digest differs")
    return value


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            raise V3TriggerAdapterError(
                f"authoritative input is missing: {path}"
            ) from None
        if stat.S_ISLNK(mode):
            raise V3TriggerAdapterError(
                f"authoritative input traverses a symlink: {path}"
            )


def _read_stable_no_symlink(path: Path) -> bytes:
    _assert_no_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise V3TriggerAdapterError(f"cannot open authoritative input: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise V3TriggerAdapterError(f"authoritative input is not regular: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    def identity(item: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if identity(before) != identity(after):
        raise V3TriggerAdapterError(
            f"authoritative input drifted while reading: {path}"
        )
    return b"".join(chunks)


def assert_prospective_output_absent(path: str | Path) -> Path:
    """Perform a no-publication preflight; this function never creates the path."""

    output = Path(path)
    if not output.is_absolute() or output != Path(os.path.normpath(output.as_posix())):
        raise V3TriggerAdapterError(
            "prospective output path is not normalized absolute"
        )
    try:
        os.lstat(output)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise V3TriggerAdapterError("cannot inspect prospective output") from exc
    else:
        raise FileExistsError(f"refusing a pre-existing adapter output: {output}")
    if output.parent.exists():
        _assert_no_symlink_components(output.parent)
        if not output.parent.is_dir():
            raise V3TriggerAdapterError("prospective output parent is not a directory")
    return output


def build_trigger_a_receipt_v3_adapter_from_root(
    *,
    durable_attempt_root: str | Path,
    prospective_output_path: str | Path,
    authoritative_validator: AuthoritativeValidator | None = None,
    legacy_builder: LegacyBuilder | None = None,
) -> bytes:
    """Safely load fixed V3 inputs, preflight output absence, and return bytes only."""

    root = _normalized_root(durable_attempt_root)
    assert_prospective_output_absent(prospective_output_path)
    paths = {
        name: (root / relative).as_posix()
        for name, relative in AUTHORITATIVE_RELATIVE_PATHS.items()
    }
    control_names = ("failure_closure", "completion_fence", "execution_plan")
    raws = {name: _read_stable_no_symlink(Path(paths[name])) for name in control_names}
    # Reject the closed incident, fence, or plan poisoning before opening the
    # branch-bearing revalidated decision.
    _protocol_precheck(raws)
    raws.update(
        {
            name: _read_stable_no_symlink(Path(path))
            for name, path in paths.items()
            if name not in raws
        }
    )
    result = build_trigger_a_receipt_v3_adapter_bytes(
        durable_attempt_root=root,
        authoritative_artifacts=raws,
        authoritative_paths=paths,
        authoritative_validator=authoritative_validator,
        legacy_builder=legacy_builder,
    )
    for name, path in paths.items():
        if _read_stable_no_symlink(Path(path)) != raws[name]:
            raise V3TriggerAdapterError(
                f"authoritative input drifted before adapter return: {name}"
            )
    assert_prospective_output_absent(prospective_output_path)
    return result


__all__ = (
    "AUTHORITATIVE_RELATIVE_PATHS",
    "BRANCH",
    "COMPLETION_METHOD",
    "HISTORICAL_EXIT_ORDER_CLAIMED",
    "LEGACY_PUBLICATION",
    "LEGACY_STRICT_MTIME_PROOF",
    "MTIME_RELATION",
    "PROTOCOL",
    "SCHEMA_VERSION",
    "TRUTH_FIELDS",
    "V3TriggerAdapterError",
    "assert_prospective_output_absent",
    "build_trigger_a_receipt_v3_adapter_bytes",
    "build_trigger_a_receipt_v3_adapter_from_root",
    "canonical_bytes",
    "canonical_sha256",
    "strict_json_object",
    "validate_adapter_envelope_bytes",
)
