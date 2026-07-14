from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import pytest

import cohort_closed_loop_structured_trigger_receipt as builder
import cohort_closed_loop_structured_trigger_receipt_revalidator as revalidator
import cohort_closed_loop_structured_atomic_publish as atomic
import cohort_closed_loop_structured_trigger_absence_adapter as absence
import cohort_closed_loop_structured_trigger_publisher as publisher


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _builder_test_module() -> ModuleType:
    name = "_trigger_receipt_builder_fixture_for_independent_revalidator"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).with_name(
        "test_cohort_closed_loop_structured_trigger_receipt.py"
    )
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load the receipt fixture module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_PUBLISHER_PATHS = {
    "structured_atomic_publisher": (
        "/registered/structured/tools/cohort_closed_loop_structured_atomic_publish.py"
    ),
    "trigger_receipt_publisher": (
        "/registered/structured/tools/"
        "publish_cohort_closed_loop_structured_trigger_receipt.py"
    ),
}


def _publisher_sources() -> dict[str, bytes]:
    root = Path(__file__).resolve().parent.parent
    atomic = (root / "cohort_closed_loop_structured_atomic_publish.py").read_bytes()
    trigger_path = root / "publish_cohort_closed_loop_structured_trigger_receipt.py"
    trigger = (
        trigger_path.read_bytes()
        if trigger_path.exists()
        else b"prospective trigger receipt publisher fixture v1\n"
    )
    return {
        "structured_atomic_publisher": atomic,
        "trigger_receipt_publisher": trigger,
    }


def _bind_independent_sources(
    evidence: dict[str, Any], *, include_publishers: bool
) -> None:
    source_path = Path(revalidator.__file__).resolve()
    source_raw = source_path.read_bytes()
    inventory = json.loads(evidence["trigger_validator_inventory_bytes"])
    rows = {row["binding_id"]: row for row in inventory["bindings"]}
    binding = rows["trigger_receipt_revalidator"]
    binding.update(
        {
            "path": f"/registered/structured/tools/{source_path.name}",
            "sha256": _sha(source_raw),
            "size_bytes": len(source_raw),
        }
    )
    evidence["trigger_receipt_revalidator_source_bytes"] = source_raw
    if include_publishers:
        sources = _publisher_sources()
        for binding_id, raw in sources.items():
            row = rows.get(binding_id)
            record = {
                "binding_id": binding_id,
                "path": _PUBLISHER_PATHS[binding_id],
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
            if row is None:
                inventory["bindings"].append(record)
            else:
                row.update(record)
        evidence["structured_atomic_publisher_source_bytes"] = sources[
            "structured_atomic_publisher"
        ]
        evidence["trigger_receipt_publisher_source_bytes"] = sources[
            "trigger_receipt_publisher"
        ]
    inventory["bindings"] = sorted(
        inventory["bindings"], key=lambda row: row["binding_id"]
    )
    unsigned = {
        key: inventory[key] for key in revalidator._VALIDATOR_INVENTORY_UNSIGNED_KEYS
    }
    inventory["binding_inventory_sha256"] = _sha(_canonical(unsigned))
    evidence["trigger_validator_inventory_bytes"] = _canonical(inventory)


def _fixture() -> dict[str, Any]:
    fixture_module = _builder_test_module()
    evidence = fixture_module._fixture()
    builder_has_publishers = {
        "structured_atomic_publisher",
        "trigger_receipt_publisher",
    }.issubset(builder.REQUIRED_VALIDATOR_BINDING_IDS)
    _bind_independent_sources(evidence, include_publishers=builder_has_publishers)
    return evidence


def _receipt_and_inputs() -> tuple[bytes, dict[str, Any]]:
    evidence = _fixture()
    raw = builder.build_trigger_a_receipt_bytes(**evidence)
    _bind_independent_sources(evidence, include_publishers=True)
    receipt = json.loads(raw)
    validator_raw = evidence["trigger_validator_inventory_bytes"]
    receipt["trigger_validator_inventory"].update(
        {
            "file_sha256": _sha(validator_raw),
            "size_bytes": len(validator_raw),
            "payload": json.loads(validator_raw),
        }
    )
    unsigned = {key: receipt[key] for key in revalidator._TRIGGER_RECEIPT_UNSIGNED_KEYS}
    receipt["trigger_receipt_sha256"] = _sha(_canonical(unsigned))
    raw = _canonical(receipt)
    inputs = {
        key: value
        for key, value in evidence.items()
        if key not in {"structured_attempt_id", "created_at_utc"}
    }
    return raw, inputs


def _retarget_inventory(
    inputs: dict[str, Any], binding_id: str, **updates: object
) -> None:
    inventory = json.loads(inputs["trigger_validator_inventory_bytes"])
    row = next(
        item for item in inventory["bindings"] if item["binding_id"] == binding_id
    )
    row.update(updates)
    unsigned = {
        key: inventory[key] for key in revalidator._VALIDATOR_INVENTORY_UNSIGNED_KEYS
    }
    inventory["binding_inventory_sha256"] = _sha(_canonical(unsigned))
    inputs["trigger_validator_inventory_bytes"] = _canonical(inventory)


def _retarget_inventory_payload(inputs: dict[str, Any], mutate: Any) -> None:
    inventory = json.loads(inputs["trigger_validator_inventory_bytes"])
    mutate(inventory)
    unsigned = {
        key: inventory[key] for key in revalidator._VALIDATOR_INVENTORY_UNSIGNED_KEYS
    }
    inventory["binding_inventory_sha256"] = _sha(_canonical(unsigned))
    inputs["trigger_validator_inventory_bytes"] = _canonical(inventory)


def _retarget_absence(inputs: dict[str, Any], mutate: Any) -> None:
    claim = json.loads(inputs["pretrigger_absence_evidence_bytes"])
    mutate(claim)
    unsigned = {key: claim[key] for key in revalidator._ABSENCE_UNSIGNED_KEYS}
    claim["absence_attestation_sha256"] = _sha(_canonical(unsigned))
    inputs["pretrigger_absence_evidence_bytes"] = _canonical(claim)


def _integration_mountinfo(root: Path) -> bytes:
    metadata = root.stat()
    major_minor = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    return (
        f"101 1 {major_minor} / {root.as_posix()} rw,nosuid - testfs /dev/test rw\n"
    ).encode("ascii")


def _integration_absence_runtime(
    root: Path, *, now_utc: Callable[[], str]
) -> absence.AbsenceRuntime:
    return absence.AbsenceRuntime(
        euid=lambda: absence.PRETRIGGER_ABSENCE_SERVICE_UID,
        identity_for_uid=lambda uid: absence.PRETRIGGER_ABSENCE_SERVICE_IDENTITY,
        mountinfo_bytes=lambda: _integration_mountinfo(root),
        now_utc=now_utc,
        uid_translate=lambda uid: absence.PRETRIGGER_ABSENCE_SERVICE_UID,
        physical_root_override=root,
    )


def _integration_fake_git(
    repo_root: Path, source_commit: str
) -> Callable[[Path, tuple[str, ...]], bytes]:
    def run(observed_root: Path, arguments: tuple[str, ...]) -> bytes:
        assert observed_root == repo_root
        if arguments == ("rev-parse", "--show-toplevel"):
            return (repo_root.as_posix() + "\n").encode("utf-8")
        if arguments == ("rev-parse", "HEAD"):
            return (source_commit + "\n").encode("ascii")
        if arguments == ("status", "--porcelain=v1", "--untracked-files=all"):
            return b""
        if arguments[:3] == ("ls-files", "--error-unmatch", "--"):
            return (arguments[3] + "\n").encode("utf-8")
        if arguments[:2] == ("cat-file", "blob"):
            observed_commit, relative = arguments[2].split(":", 1)
            assert observed_commit == source_commit
            return (repo_root / relative).read_bytes()
        raise AssertionError(f"unexpected git invocation: {arguments}")

    return run


def test_independent_revalidator_accepts_exact_receipt_without_authority() -> None:
    raw, inputs = _receipt_and_inputs()

    result = revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)

    assert result.trigger_branch == revalidator.TRIGGER_A
    assert result.tooling_source_commit == json.loads(raw)["tooling_source_commit"]
    assert result.tooling_source_commit == "b" * 40
    assert result.model_calls_authorized is False
    assert result.operational_authorization is False
    assert raw == _canonical(json.loads(raw))
    assert "cohort_closed_loop_structured_trigger_receipt" not in (
        value.__name__
        for value in revalidator.__dict__.values()
        if isinstance(value, ModuleType)
    )


def test_builder_callable_monkeypatch_and_module_deletion_are_irrelevant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw, inputs = _receipt_and_inputs()

    def forbidden_builder_call(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("independent revalidator called the builder")

    monkeypatch.setattr(
        builder, "build_trigger_a_receipt_bytes", forbidden_builder_call
    )
    monkeypatch.delitem(
        sys.modules,
        "cohort_closed_loop_structured_trigger_receipt",
        raising=False,
    )

    result = revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)
    assert result.operational_authorization is False


def test_registered_revalidator_must_be_this_exact_source() -> None:
    raw, inputs = _receipt_and_inputs()
    substituted = b"independent revalidator substitute"
    inputs["trigger_receipt_revalidator_source_bytes"] = substituted
    _retarget_inventory(
        inputs,
        "trigger_receipt_revalidator",
        sha256=_sha(substituted),
        size_bytes=len(substituted),
    )

    with pytest.raises(
        revalidator.TriggerReceiptError,
        match="not this exact independent source",
    ):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


@pytest.mark.parametrize("field", ["path", "sha256"])
def test_builder_and_revalidator_registration_must_be_distinct(field: str) -> None:
    raw, inputs = _receipt_and_inputs()
    inventory = json.loads(inputs["trigger_validator_inventory_bytes"])
    rows = {row["binding_id"]: row for row in inventory["bindings"]}
    _retarget_inventory(
        inputs,
        "trigger_receipt_revalidator",
        **{field: rows["trigger_receipt_builder"][field]},
    )

    with pytest.raises(
        revalidator.TriggerReceiptError,
        match="must be (?:unique|distinct)",
    ):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


def test_validator_inventory_is_exactly_the_sorted_eight_id_contract() -> None:
    raw, inputs = _receipt_and_inputs()
    inventory = json.loads(inputs["trigger_validator_inventory_bytes"])

    assert tuple(row["binding_id"] for row in inventory["bindings"]) == (
        "causal_completion_attester",
        "causal_terminal_revalidator",
        "pretrigger_absence_adapter",
        "structured_atomic_publisher",
        "trigger_execution_seal_builder",
        "trigger_receipt_builder",
        "trigger_receipt_publisher",
        "trigger_receipt_revalidator",
    )
    assert revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


def test_validator_inventory_strictly_before_seal_is_accepted() -> None:
    raw, inputs = _receipt_and_inputs()
    inventory = json.loads(inputs["trigger_validator_inventory_bytes"])
    seal = json.loads(inputs["trigger_execution_seal_bytes"])

    assert inventory["created_at_utc"] < seal["created_at_utc"]
    assert revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


@pytest.mark.parametrize(
    "registered_at",
    ("2026-07-14T11:00:04Z", "2026-07-14T11:00:05Z"),
)
def test_validator_inventory_equal_or_later_than_seal_is_rejected(
    registered_at: str,
) -> None:
    raw, inputs = _receipt_and_inputs()
    _retarget_inventory_payload(
        inputs,
        lambda inventory: inventory.__setitem__("created_at_utc", registered_at),
    )

    with pytest.raises(
        revalidator.TriggerReceiptError,
        match="prospectively registered before the seal",
    ):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


@pytest.mark.parametrize(
    ("binding_id", "argument"),
    [
        (
            "structured_atomic_publisher",
            "structured_atomic_publisher_source_bytes",
        ),
        ("trigger_receipt_publisher", "trigger_receipt_publisher_source_bytes"),
    ],
)
def test_each_publisher_source_has_an_independent_full_byte_binding(
    binding_id: str, argument: str
) -> None:
    raw, inputs = _receipt_and_inputs()
    inputs[argument] = b"substituted publisher source"

    with pytest.raises(
        revalidator.TriggerReceiptError,
        match=f"validator source differs: {binding_id}",
    ):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


@pytest.mark.parametrize(
    ("publisher_id", "aliased_id"),
    [
        ("structured_atomic_publisher", "trigger_receipt_builder"),
        ("trigger_receipt_publisher", "structured_atomic_publisher"),
    ],
)
def test_publisher_source_digests_cannot_alias_any_registered_role(
    publisher_id: str, aliased_id: str
) -> None:
    raw, inputs = _receipt_and_inputs()
    inventory = json.loads(inputs["trigger_validator_inventory_bytes"])
    rows = {row["binding_id"]: row for row in inventory["bindings"]}
    _retarget_inventory(
        inputs,
        publisher_id,
        sha256=rows[aliased_id]["sha256"],
    )

    with pytest.raises(
        revalidator.TriggerReceiptError,
        match="publisher source digests must not alias",
    ):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


def test_all_eight_registered_paths_must_be_unique() -> None:
    raw, inputs = _receipt_and_inputs()
    inventory = json.loads(inputs["trigger_validator_inventory_bytes"])
    rows = {row["binding_id"]: row for row in inventory["bindings"]}
    _retarget_inventory(
        inputs,
        "trigger_receipt_publisher",
        path=rows["structured_atomic_publisher"]["path"],
    )

    with pytest.raises(revalidator.TriggerReceiptError, match="paths must be unique"):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


@pytest.mark.parametrize(
    "publisher_id",
    ["structured_atomic_publisher", "trigger_receipt_publisher"],
)
def test_each_publisher_path_must_be_exact_normalized_absolute_text(
    publisher_id: str,
) -> None:
    raw, inputs = _receipt_and_inputs()
    _retarget_inventory(inputs, publisher_id, path="relative/publisher.py")

    with pytest.raises(
        revalidator.TriggerReceiptError,
        match="normalized absolute POSIX path",
    ):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


def test_substituted_parent_decision_is_rejected_byte_exactly() -> None:
    raw, inputs = _receipt_and_inputs()
    report = json.loads(inputs["causal_revalidated_decision_bytes"])
    report["aggregate"]["ci_95_upper"] = 0.05
    inputs["causal_revalidated_decision_bytes"] = (
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    with pytest.raises(revalidator.TriggerReceiptError, match="bytes differ"):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


def test_forged_receipt_with_fresh_self_digest_fails_reconstruction() -> None:
    raw, inputs = _receipt_and_inputs()
    receipt = json.loads(raw)
    receipt["causal"]["full_evidence_revalidated"] = False
    unsigned = {key: receipt[key] for key in revalidator._TRIGGER_RECEIPT_UNSIGNED_KEYS}
    receipt["trigger_receipt_sha256"] = _sha(_canonical(unsigned))

    with pytest.raises(
        revalidator.TriggerReceiptError,
        match="independent reconstruction",
    ):
        revalidator.validate_trigger_a_receipt_bytes(_canonical(receipt), **inputs)


def test_absence_service_uid_must_equal_registered_root_owner() -> None:
    raw, inputs = _receipt_and_inputs()
    absence = json.loads(inputs["pretrigger_absence_evidence_bytes"])
    absence["filesystem_root_identity"]["owner_uid"] = 41002
    unsigned = {key: absence[key] for key in revalidator._ABSENCE_UNSIGNED_KEYS}
    absence["absence_attestation_sha256"] = _sha(_canonical(unsigned))
    inputs["pretrigger_absence_evidence_bytes"] = _canonical(absence)

    with pytest.raises(revalidator.TriggerReceiptError, match="filesystem owner_uid"):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


def test_legacy_absence_without_root_mode_is_rejected() -> None:
    raw, inputs = _receipt_and_inputs()
    _retarget_absence(
        inputs,
        lambda claim: claim["filesystem_root_identity"].pop("mode"),
    )

    with pytest.raises(revalidator.TriggerReceiptError, match="exact-key schema"):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


@pytest.mark.parametrize("bad_mode", (0o755, 0o770, True))
def test_absence_root_mode_is_exact_integer_0700(bad_mode: object) -> None:
    raw, inputs = _receipt_and_inputs()
    _retarget_absence(
        inputs,
        lambda claim: claim["filesystem_root_identity"].__setitem__("mode", bad_mode),
    )
    expected = "integer" if bad_mode is True else "exactly 0700"

    with pytest.raises(revalidator.TriggerReceiptError, match=expected):
        revalidator.validate_trigger_a_receipt_bytes(raw, **inputs)


def test_real_adapter_builder_revalidator_and_atomic_publication_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = _fixture()
    source_commit = json.loads(evidence["trigger_validator_inventory_bytes"])[
        "tooling_source_commit"
    ]
    attempt_id = evidence["structured_attempt_id"]
    root = tmp_path / "structured-root"
    (root / "control").mkdir(parents=True)
    root.chmod(0o700)
    (root / "control").chmod(0o700)

    source_paths = {
        binding_id: publisher._module_source_path(binding_id)
        for binding_id in publisher._LOCAL_MODULE_BY_ID
    }
    upstream_sources = {
        "causal_completion_attester": (
            "attester",
            evidence["attester_source_bytes"],
        ),
        "causal_terminal_revalidator": (
            "revalidator",
            evidence["causal_revalidator_source_bytes"],
        ),
        "trigger_execution_seal_builder": (
            "execution_seal_builder",
            evidence["execution_seal_builder_source_bytes"],
        ),
    }
    upstream_root = tmp_path / "upstream-sources"
    upstream_root.mkdir()
    plan = json.loads(evidence["terminal_verifier_execution_plan_bytes"])
    source_redirects: dict[Path, Path] = {}
    for binding_id, (tool_id, source_raw) in upstream_sources.items():
        path = upstream_root / f"{binding_id}.py"
        path.write_bytes(source_raw)
        path.chmod(0o444)
        registered_path = Path(plan["tools"][tool_id]["path"])
        source_paths[binding_id] = registered_path
        source_redirects[registered_path] = path
    assert set(source_paths) == set(publisher.REQUIRED_BINDING_IDS)

    real_source_probe = publisher._stable_regular_bytes

    def source_probe(path: Path, *, label: str) -> bytes:
        return real_source_probe(source_redirects.get(path, path), label=label)

    monkeypatch.setattr(publisher, "_stable_regular_bytes", source_probe)

    evidence_root = tmp_path / "causal-evidence"
    evidence_root.mkdir()
    evidence_paths: dict[str, Path] = {}
    for key in publisher._RAW_EVIDENCE_KEYS:
        path = evidence_root / f"{key}.bin"
        path.write_bytes(evidence[key])
        path.chmod(0o444)
        evidence_paths[key] = path

    repo_root = Path(publisher.__file__).resolve().parent
    registration_runtime = publisher.PublisherRuntime(
        now_utc=lambda: "2026-07-14T09:00:00Z",
        git=_integration_fake_git(repo_root, source_commit),
        absence=_integration_absence_runtime(
            root, now_utc=lambda: "2026-07-14T09:00:00Z"
        ),
    )
    publisher._preregister_validator_inventory_for_test(
        root=root,
        repo_root=repo_root,
        source_commit=source_commit,
        attempt_id=attempt_id,
        source_paths=source_paths,
        runtime=registration_runtime,
    )

    event_order: list[str] = []

    def absence_now() -> str:
        event_order.append("absence_adapter")
        return "2026-07-14T11:00:05Z"

    def real_builder(**kwargs: object) -> bytes:
        event_order.append("builder")
        return builder.build_trigger_a_receipt_bytes(**kwargs)

    def real_revalidator(
        raw: bytes, **kwargs: object
    ) -> revalidator.TriggerReceiptRevalidation:
        event_order.append("independent_revalidator")
        return revalidator.validate_trigger_a_receipt_bytes(raw, **kwargs)

    publisher._publish_trigger_a_chain_for_test(
        root=root,
        source_commit=source_commit,
        attempt_id=attempt_id,
        raw_evidence_paths=evidence_paths,
        runtime=publisher.PublisherRuntime(
            absence=_integration_absence_runtime(root, now_utc=absence_now),
            build_receipt=real_builder,
            revalidate_receipt=real_revalidator,
        ),
    )
    assert event_order == ["absence_adapter", "builder", "independent_revalidator"]

    receipt_raw, _ = atomic.read_and_validate_readonly_artifact(
        root=root,
        relative_path=publisher.RECEIPT_RELATIVE_PATH,
    )
    receipt = json.loads(receipt_raw)
    assert (
        receipt["pretrigger_absence_evidence"]["payload"]["filesystem_root_identity"][
            "mode"
        ]
        == 0o700
    )
    assert receipt["causal"]["model_calls_authorized"] is False
    assert receipt["causal"]["operational_authorization"] is False
    receipt_path = root / publisher.RECEIPT_RELATIVE_PATH
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o444
    intent, pending = atomic.publication_sidecar_relative_paths(
        publisher.RECEIPT_RELATIVE_PATH
    )
    assert (root / intent).is_file()
    assert not (root / pending).exists()


def test_new_receipt_requires_ascii_canonical_json() -> None:
    raw, inputs = _receipt_and_inputs()
    receipt = json.loads(raw)
    receipt["status"] = "validated_non_authorizing_é"
    non_ascii = json.dumps(
        receipt,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(revalidator.TriggerReceiptError, match="canonical JSON"):
        revalidator.validate_trigger_a_receipt_bytes(non_ascii, **inputs)
