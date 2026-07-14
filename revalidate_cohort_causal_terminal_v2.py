#!/usr/bin/env python3
"""Revalidate a V2-attested causal terminal with the exact V1 statistic engine."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import attest_cohort_causal_completion as attester_v1
import build_cohort_structured_state_execution_seal_v2 as seal_v2
import revalidate_cohort_causal_terminal as v1


REVALIDATED_FILENAME = seal_v2.REVALIDATED_FILENAME
RECEIPT_FILENAME = seal_v2.REVALIDATION_RECEIPT_FILENAME


class RevalidationV2Error(v1.RevalidationError):
    """A fail-closed V2 control or revalidation error."""


@contextmanager
def _v1_revalidation_engine_as_v2(
    *,
    validated_v2_attestation: dict[str, Any],
    projected_v1_attestation: dict[str, Any],
    attested_files: list[dict[str, Any]],
) -> Iterable[None]:
    """Route the exact V1 function through strict V2 control validators."""

    def validate_attestation(value: Any):
        if seal_v2.canonical_bytes(value) != seal_v2.canonical_bytes(
            validated_v2_attestation
        ):
            raise RevalidationV2Error("V2 attestation drifted before V1 engine entry")
        return copy.deepcopy(projected_v1_attestation), copy.deepcopy(attested_files)

    replacements = {
        "load_and_validate_execution_plan_stage": seal_v2.load_and_validate_execution_plan_stage,
        "_validate_attestation": validate_attestation,
        "REVALIDATED_FILENAME": REVALIDATED_FILENAME,
        "RECEIPT_FILENAME": RECEIPT_FILENAME,
    }
    previous = {name: getattr(v1, name) for name in replacements}
    try:
        for name, item in replacements.items():
            setattr(v1, name, item)
        yield
    finally:
        for name, item in previous.items():
            setattr(v1, name, item)


def revalidate_terminal(
    *,
    root: Path,
    execution_plan_path: Path,
    attestation_path: Path,
    launch_expectation_path: Path,
    grid_path: Path,
    provenance_path: Path,
    formal_manifest_path: Path,
    formal_decision_path: Path,
    revalidated_output: Path,
    receipt_output: Path,
    preregistration_path: Path | None = None,
    statistical_addendum_path: Path | None = None,
    assemble_fn: Callable[..., dict[str, Any]] | None = None,
    evaluate_fn: Callable[[Any], dict[str, Any]] | None = None,
    make_grid_fn: Callable[..., dict[str, Any]] | None = None,
    actual_argv: Sequence[str] | None = None,
    runtime_python_path: str | None = None,
    runtime_python_version: str | None = None,
) -> dict[str, Any]:
    """Validate V2 evidence, then execute V1's unchanged revalidation function."""

    normalized_root = root.expanduser().resolve()
    plan_path = execution_plan_path.expanduser().resolve()
    attestation_path = attestation_path.expanduser().resolve()
    expectation_path = launch_expectation_path.expanduser().resolve()
    preregistration = (
        (normalized_root / v1.PREREGISTRATION_FILENAME).resolve()
        if preregistration_path is None
        else preregistration_path.expanduser().resolve()
    )
    addendum = (
        (normalized_root / v1.STATISTICAL_ADDENDUM_FILENAME).resolve()
        if statistical_addendum_path is None
        else statistical_addendum_path.expanduser().resolve()
    )
    expected_inputs = {
        "attestation": attestation_path,
        "execution_plan": plan_path,
        "formal_decision": formal_decision_path.expanduser().resolve(),
        "formal_manifest": formal_manifest_path.expanduser().resolve(),
        "grid": grid_path.expanduser().resolve(),
        "launch_expectation": expectation_path,
        "preregistration": preregistration,
        "provenance": provenance_path.expanduser().resolve(),
        "root": normalized_root,
        "statistical_addendum": addendum,
    }
    expected_outputs = {
        "revalidated_decision": revalidated_output.expanduser().resolve(),
        "revalidation_receipt": receipt_output.expanduser().resolve(),
    }
    try:
        _, plan_raw = seal_v2.load_and_validate_execution_plan_stage(
            execution_plan_path=plan_path,
            stage="revalidator",
            expected_inputs=expected_inputs,
            expected_outputs=expected_outputs,
            expected_parameters={},
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )
    except seal_v2.ExecutionSealV2Error as exc:
        raise RevalidationV2Error("V2 execution plan is invalid") from exc

    expectation, expectation_raw = attester_v1._load_launch_expectation(
        expectation_path
    )
    attestation_raw, _ = v1._read_stable_file(attestation_path)
    attestation_object = v1._load_json_bytes(
        attestation_raw, label="V2 completion attestation"
    )
    if attestation_raw != seal_v2.canonical_bytes(attestation_object):
        raise RevalidationV2Error("V2 completion attestation is not canonical")
    validated, projected, files = seal_v2._project_v2_attestation_for_v1(
        attestation_object,
        execution_plan_path=plan_path,
        execution_plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
        expectation=expectation,
        launch_expectation_path=expectation_path,
        launch_expectation_sha256=hashlib.sha256(expectation_raw).hexdigest(),
    )

    with _v1_revalidation_engine_as_v2(
        validated_v2_attestation=validated,
        projected_v1_attestation=projected,
        attested_files=files,
    ):
        return v1.revalidate_terminal(
            root=normalized_root,
            execution_plan_path=plan_path,
            attestation_path=attestation_path,
            launch_expectation_path=expectation_path,
            grid_path=grid_path,
            provenance_path=provenance_path,
            formal_manifest_path=formal_manifest_path,
            formal_decision_path=formal_decision_path,
            revalidated_output=revalidated_output,
            receipt_output=receipt_output,
            preregistration_path=preregistration,
            statistical_addendum_path=addendum,
            assemble_fn=assemble_fn,
            evaluate_fn=evaluate_fn,
            make_grid_fn=make_grid_fn,
            actual_argv=actual_argv,
            runtime_python_path=runtime_python_path,
            runtime_python_version=runtime_python_version,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--launch-expectation", type=Path, required=True)
    parser.add_argument("--grid", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--formal-manifest", type=Path, required=True)
    parser.add_argument("--formal-decision", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--statistical-addendum", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        revalidate_terminal(
            root=args.root,
            execution_plan_path=args.execution_plan,
            attestation_path=args.attestation,
            launch_expectation_path=args.launch_expectation,
            grid_path=args.grid,
            provenance_path=args.provenance,
            formal_manifest_path=args.formal_manifest,
            formal_decision_path=args.formal_decision,
            revalidated_output=args.output,
            receipt_output=args.receipt,
            preregistration_path=args.preregistration,
            statistical_addendum_path=args.statistical_addendum,
        )
    except (
        RevalidationV2Error,
        v1.RevalidationError,
        seal_v2.ExecutionSealV2Error,
        FileExistsError,
    ):
        # Formal decisions and branch-bearing exception text are never emitted.
        raise SystemExit(1) from None
    print(json.dumps({"status": "complete"}, sort_keys=True))


if __name__ == "__main__":
    main()
