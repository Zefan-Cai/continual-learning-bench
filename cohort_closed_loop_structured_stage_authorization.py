"""Pure, outcome-blind authorization-chain contracts for structured stages.

This module is the first, deliberately non-operational layer of the structured
closed-loop runner.  It validates exact canonical bytes and constructs a
one-way chain::

    trigger receipt -> protocol-plan seal -> stage plan -> generated DGP
                    -> per-stage protocol seal -> launch expectation
                    -> prelaunch claim eligibility gate

No function performs filesystem or process I/O, imports a model, resolves a
hidden scoring context, calls a scorer, or authorizes a model/scorer call.  In
particular, a validated prelaunch gate is only *eligible* for a future impure
launcher to perform fresh filesystem/process checks and atomically create one
``O_EXCL`` launch claim.  That future adapter, which does not exist here, is
the only component that may turn the claim into operational permission.

Filesystem absence, process absence, lock ownership, and publication facts are
therefore represented here only as exact, digest-bound adapter claims.  The
pure layer validates their schema and chain placement; it does not assert that
the claimed operating-system facts are true.
"""

from __future__ import annotations

import hashlib
import json
import math
import posixpath
import re
from dataclasses import dataclass
from typing import Any

from cohort_closed_loop_structured_atomic_publish import (
    publication_sidecar_relative_paths,
)
from cohort_closed_loop_structured_commitments import (
    CANDIDATE_ACTION_IDS,
    REGISTERED_BRANCH_IDS,
)
from cohort_closed_loop_structured_dgp_context import (
    EXPECTED_STAGE_SEEDS,
    PREREG_DOCUMENT_SHA256,
    STAGE_MANIFEST_PROTOCOL,
    STAGE_SHAPES,
    StageKind,
    load_stage_manifest,
    validate_stage_integrity,
)
from cohort_closed_loop_structured_execution_validation import (
    STRUCTURED_ADAPTATION_BRANCHES,
    STRUCTURED_HELDOUT_BRANCHES,
)


class StructuredStageAuthorizationError(ValueError):
    """Raised when an authorization-chain artifact fails closed."""


SCHEMA_VERSION = 1
TRIGGER_EXECUTION_SEAL_PROTOCOL = (
    "cohort_closed_loop_structured_state_trigger_execution_seal_v1"
)
TRIGGER_RECEIPT_PROTOCOL = "cohort_structured_trigger_receipt_v1"
SOURCE_BINDING_INVENTORY_PROTOCOL = "cohort_structured_source_bindings_v1"
ASSET_BINDING_INVENTORY_PROTOCOL = "cohort_structured_asset_bindings_v1"
PROTOCOL_PLAN_SEAL_PROTOCOL = "cohort_structured_protocol_plan_seal_v1"
STRUCTURED_STAGE_PROTOCOL_SEAL_PROTOCOL = "cohort_structured_stage_protocol_seal_v1"
STAGE_TRANSITION_RECEIPT_PROTOCOL = "cohort_structured_stage_transition_v1"
STAGE_PLAN_PROTOCOL = "cohort_structured_stage_plan_v1"
DGP_GENERATION_CLAIM_PROTOCOL = "cohort_structured_dgp_generation_claim_v1"
DGP_COMPLETION_RECEIPT_PROTOCOL = "cohort_structured_dgp_completion_receipt_v1"
ABSENCE_CLAIMS_PROTOCOL = "cohort_structured_prelaunch_absence_claims_v1"
PROCESS_CLAIM_PROTOCOL = "cohort_structured_prelaunch_process_claim_v1"
LAUNCH_EXPECTATION_PROTOCOL = "cohort_structured_launch_expectation_v1"
PRELAUNCH_GATE_PROTOCOL = "cohort_structured_prelaunch_gate_v1"

TRIGGER_A = "causal_valid_no_go"
TRIGGER_B = "causal_pass_online_internal_screen_valid_no_go"
CAUSAL_PROTOCOL_SEAL_STATUS = "not_applicable_existing_implementation_has_none"
PRELAUNCH_ELIGIBILITY_SCOPE = "eligible_for_one_registered_stage_launch_claim"
EXECUTION_CONTRACT_SHA256 = (
    "47755097a112132d20e2cbaa76e71a0948930966cd410b51714323b0a80f1828"
)

REQUIRED_SOURCE_BINDING_IDS: tuple[str, ...] = tuple(
    sorted(
        {
            "structured_state",
            "structured_commitments",
            "structured_execution_validation",
            "structured_dgp_context_validation",
            "structured_stage_authorization",
            "structured_atomic_publisher",
            "trigger_receipt_builder",
            "trigger_receipt_revalidator",
            "dgp_generator",
            "context_registrar",
            "pure_scorer",
            "stage_grid_builder",
            "runner",
            "launcher",
            "wrapper",
            "provenance_builder",
            "protocol_seal_builder",
            "stage_plan_builder",
            "dgp_completion_validator",
            "stage_protocol_seal_builder",
            "launch_expectation_builder",
            "prelaunch_gate_builder",
            "stage_assembler",
            "smoke_validator",
            "formal_validator",
            "independent_private_validator",
            "report_serializer",
            "environment_lock",
            "private_context_access_boundary",
        }
    )
)
REQUIRED_ASSET_BINDING_IDS: tuple[str, ...] = tuple(
    sorted(
        {
            "model_config",
            "model_state_dict",
            "tokenizer",
            "environment",
            "task",
            "schema",
            "official_scorer",
            "cohort_layer_inventory",
            "structured_raw_policy_config",
            "canonical_online_icl_config",
        }
    )
)

ARM_IDS: tuple[str, ...] = tuple(REGISTERED_BRANCH_IDS)
ADAPTATION_STRUCTURED_BRANCH_IDS: tuple[str, ...] = tuple(
    STRUCTURED_ADAPTATION_BRANCHES
)
HELDOUT_STRUCTURED_BRANCH_IDS: tuple[str, ...] = tuple(STRUCTURED_HELDOUT_BRANCHES)
CANONICAL_BRANCH_ID = "canonical_online_icl"

PATH_LAYOUT_TEMPLATES: dict[str, str] = {
    "stage_root_template": "{durable_root}/stages/{stage_kind}/{attempt_id}",
    "source_inventory_path_template": "{durable_root}/control/source_inventory.json",
    "asset_inventory_path_template": "{durable_root}/control/asset_inventory.json",
    "trigger_receipt_path_template": "{durable_root}/control/trigger_receipt.json",
    "protocol_plan_seal_path_template": (
        "{durable_root}/control/structured_protocol_plan_seal.json"
    ),
    "corpus_inventory_path_template": (
        "{stage_root}/dgp/corpora/{block_id}/{phase}/corpus_inventory.json"
    ),
    "dgp_row_path_template": (
        "{stage_root}/dgp/corpora/{block_id}/{phase}/rows/{item_id}.json"
    ),
    "context_attestation_path_template": (
        "{stage_root}/contexts/{block_id}/{phase}/{item_id}/public_attestation.json"
    ),
    "context_registry_digest_path_template": (
        "{stage_root}/contexts/{block_id}/{phase}/{item_id}/registry_digest_record.json"
    ),
    "precommit_path_template": (
        "{stage_root}/precommits/{block_id}/{phase}/{item_id}/{family}.json"
    ),
    "receipt_path_template": (
        "{stage_root}/receipts/{block_id}/{phase}/{item_id}/{receipt_path}.json"
    ),
    "raw_trace_path_template": (
        "{stage_root}/raw_traces/{block_id}/{phase}/{item_id}/{policy_family}.json"
    ),
    "state_path_template": (
        "{stage_root}/states/{block_id}/{phase}/{item_id}/{branch_id}.json"
    ),
    "snapshot_path_template": (
        "{stage_root}/snapshots/{block_id}/canonical_online_icl/"
        "adaptation_complete.json"
    ),
    "restore_attestation_path_template": (
        "{stage_root}/restorations/{block_id}/held_out/{item_id}/"
        "canonical_online_icl.json"
    ),
    "cell_manifest_path_template": (
        "{stage_root}/cell_manifests/{block_id}/{arm_id}.json"
    ),
    "compute_path_template": ("{stage_root}/compute/{block_id}/{arm_id}/{phase}.json"),
    "stage_plan_path_template": "{stage_root}/control/stage_plan.json",
    "dgp_generation_claim_path_template": (
        "{stage_root}/control/dgp_generation.claim.json"
    ),
    "dgp_completion_receipt_path_template": (
        "{stage_root}/control/dgp_completion_receipt.json"
    ),
    "stage_protocol_seal_path_template": (
        "{stage_root}/control/structured_stage_protocol_seal.json"
    ),
    "dgp_manifest_path_template": "{stage_root}/dgp/stage_manifest.json",
    "launch_expectation_path_template": (
        "{stage_root}/control/launch_expectation.json"
    ),
    "prelaunch_gate_path_template": "{stage_root}/control/prelaunch_gate.json",
    "launch_claim_path_template": "{stage_root}/control/launch.claim",
    "pid_path_template": "{stage_root}/control/wrapper.pid",
    "lock_path_template": "{stage_root}/control/wrapper.lock",
    "exit_path_template": "{stage_root}/control/wrapper.exit.json",
    "completion_marker_path_template": ("{stage_root}/control/completion_marker.json"),
    "private_validation_receipt_path_template": (
        "{stage_root}/control/private_validation_receipt.json"
    ),
    "private_validation_revalidation_receipt_path_template": (
        "{stage_root}/control/private_validation_revalidation_receipt.json"
    ),
    "poison_test_receipt_path_template": (
        "{stage_root}/control/poison_test_receipt.json"
    ),
    "stage_report_revalidated_path_template": (
        "{stage_root}/control/stage_report.revalidated.json"
    ),
    "failed_attempt_closure_receipt_path_template": (
        "{stage_root}/control/failed_attempt_closure_receipt.json"
    ),
    "retry_authorization_receipt_path_template": (
        "{stage_root}/control/retry_authorization_receipt.json"
    ),
    "stage_transition_receipt_path_template": (
        "{stage_root}/control/stage_transition_receipt.json"
    ),
    "sealed_inventory_path_template": (
        "{stage_root}/control/sealed_artifact_inventory.json"
    ),
    "stage_report_path_template": "{stage_root}/reports/stage_report.json",
}

_CONCRETE_PATH_KEYS: tuple[str, ...] = (
    "stage_root",
    "stage_plan_path",
    "dgp_generation_claim_path",
    "dgp_completion_receipt_path",
    "stage_protocol_seal_path",
    "dgp_manifest_path",
    "launch_expectation_path",
    "prelaunch_gate_path",
    "launch_claim_path",
    "sealed_inventory_path",
    "completion_marker_path",
    "stage_report_path",
    "stage_report_revalidated_path",
    "private_validation_receipt_path",
    "private_validation_revalidation_receipt_path",
    "poison_test_receipt_path",
    "failed_attempt_closure_receipt_path",
    "retry_authorization_receipt_path",
    "stage_transition_receipt_path",
    "lock_path",
    "pid_path",
    "exit_path",
)

_PRELAUNCH_EXISTING_ARTIFACT_ROLES = frozenset(
    {
        "stage_plan",
        "dgp_generation_claim",
        "dgp_completion_receipt",
        "structured_stage_protocol_seal",
        "dgp_stage_manifest",
        "dgp_corpus_inventory",
        "dgp_row_identity",
        "public_context_attestation",
        "context_registry_digest_record",
        # The process adapter may hold this lock while taking the absence
        # snapshot; its ownership is covered by the separate process claim.
        "wrapper_lock",
    }
)
_ATOMIC_PUBLICATION_INTENT_ROLE = "atomic_publication_intent"
_ATOMIC_PUBLICATION_PENDING_ABSENT_ROLE = "atomic_publication_pending_absent"

# Diagnostic only.  Exact-key allowlists are the primary defense.  Matching is
# on complete JSON keys, never substrings or values, so benign paths such as
# ``reward_aware_state_scorer.py`` remain valid binding values.
_EFFICACY_POISON_KEYS = frozenset(
    {
        "candidate_rewards",
        "confidence_interval",
        "delta",
        "deltas",
        "effect_size",
        "efficacy",
        "ground_truth",
        "mean_delta",
        "outcome",
        "p_value",
        "raw_error",
        "reward",
        "rewards",
        "score",
        "scores",
        "state",
        "state_vector",
    }
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_RE = re.compile(r"attempt-[0-9]{3}\Z")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}\Z")

_BINDING_RECORD_KEYS = frozenset({"binding_id", "path", "sha256", "size_bytes"})
_BINDING_INVENTORY_UNSIGNED_KEYS = frozenset({"protocol", "schema_version", "bindings"})
_BINDING_INVENTORY_KEYS = _BINDING_INVENTORY_UNSIGNED_KEYS | {
    "binding_inventory_sha256"
}

_TRIGGER_SEAL_KEYS = frozenset(
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
_TRIGGER_FILE_RECORD_KEYS = frozenset(
    {"device", "inode", "mtime_ns", "path", "roles", "sha256", "size_bytes"}
)
_VERIFIER_EXECUTION_KEYS = frozenset(
    {"invocations", "invocations_sha256", "runtime", "tools"}
)
_VERIFIER_TOOL_NAMES = frozenset({"attester", "revalidator", "execution_seal_builder"})
_VERIFIER_INVOCATION_KEYS = frozenset({"argv", "inputs", "outputs", "parameters"})
_VERIFIER_RUNTIME_KEYS = frozenset({"python_path", "python_version"})
_VERIFIER_TOOL_KEYS = frozenset({"path", "sha256"})
_VERIFIER_INVOCATION_SCHEMAS: dict[
    str, tuple[frozenset[str], frozenset[str], frozenset[str]]
] = {
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

_TRIGGER_RECEIPT_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "trigger_branch",
        "trigger_execution_seal",
        "trigger_execution_seal_file_sha256",
        "upstream_self_digest_status",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_TRIGGER_RECEIPT_KEYS = _TRIGGER_RECEIPT_UNSIGNED_KEYS | {"trigger_receipt_sha256"}

_DGP_BINDING_KEYS = frozenset(
    {
        "dgp_context_source_sha256",
        "dgp_generator_source_sha256",
        "prereg_document_sha256",
        "stage_manifest_protocol",
    }
)
_PATH_LAYOUT_KEYS = frozenset({"durable_root", *PATH_LAYOUT_TEMPLATES})
_PROTOCOL_PLAN_SEAL_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "trigger_receipt_file_sha256",
        "source_binding_inventory",
        "source_binding_inventory_file_sha256",
        "asset_binding_inventory",
        "asset_binding_inventory_file_sha256",
        "execution_contract_sha256",
        "dgp_binding",
        "path_layout",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_PROTOCOL_PLAN_SEAL_KEYS = _PROTOCOL_PLAN_SEAL_UNSIGNED_KEYS | {
    "protocol_plan_seal_sha256"
}

_STAGE_SHAPE_KEYS = frozenset({"blocks", "items_per_phase"})
_SEED_KEYS = frozenset(
    {
        "block_id",
        "block_index",
        "run_seed",
        "adaptation_dgp_seed",
        "held_out_dgp_seed",
    }
)
_BRANCH_CONTRACT_KEYS = frozenset(
    {
        "logical_arms",
        "structured_adaptation_branches",
        "structured_heldout_branches",
        "canonical_branch",
        "candidate_actions_per_adaptation_branch_item",
        "rollback_adaptation_is_active_alias",
        "rollback_has_separate_adaptation_candidates",
        "candidate_actions_make_model_calls",
        "canonical_comparator_required",
        "canonical_online_join_must_be_true",
        "structured_raw_trajectory_shared_across_branches",
    }
)
_ACCOUNTING_KEYS = frozenset(
    {
        "logical_arm_cell_count",
        "corpus_count",
        "dgp_row_count",
        "public_context_count",
        "precommit_bundle_count",
        "candidate_scorer_call_count",
        "official_scorer_call_count",
        "total_scorer_receipt_count",
        "closed_loop_active_scorer_call_count",
        "closed_loop_lr0_scorer_call_count",
        "pair_sign_reverse_scorer_call_count",
        "closed_loop_rollback_scorer_call_count",
        "canonical_online_icl_scorer_call_count",
        "structured_raw_initial_generation_count",
        "canonical_initial_generation_count",
        "initial_model_generation_count",
        "maximum_model_generation_attempt_count",
        "parse_retries_per_trajectory",
        "candidate_action_model_generation_count",
    }
)
_STAGE_PLAN_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "trigger_receipt_file_sha256",
        "protocol_plan_seal_file_sha256",
        "stage_kind",
        "attempt_id",
        "stage_shape",
        "seeds",
        "branch_contract",
        "accounting",
        "parent_transition_chain",
        "parent_transition_receipt_file_sha256s",
        "paths",
        "expected_path_inventory",
        "expected_path_inventory_sha256",
        "eligible_for_dgp_generation_claim",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_STAGE_PLAN_KEYS = _STAGE_PLAN_UNSIGNED_KEYS | {"stage_plan_sha256"}
_EXPECTED_PATH_RECORD_KEYS = frozenset({"path", "role"})

_DGP_GENERATION_CLAIM_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "trigger_receipt_file_sha256",
        "protocol_plan_seal_file_sha256",
        "stage_plan_file_sha256",
        "stage_kind",
        "attempt_id",
        "dgp_generator_source_sha256",
        "expected_path_inventory_sha256",
        "dgp_manifest_path",
        "claim_path",
        "adapter_attestation_sha256",
        "adapter_claimed_o_excl_created",
        "pure_layer_runtime_verified",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_DGP_GENERATION_CLAIM_KEYS = _DGP_GENERATION_CLAIM_UNSIGNED_KEYS | {
    "dgp_generation_claim_sha256"
}
_DGP_COMPLETION_RECEIPT_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "stage_kind",
        "attempt_id",
        "trigger_receipt_file_sha256",
        "protocol_plan_seal_file_sha256",
        "stage_plan_file_sha256",
        "dgp_generation_claim_file_sha256",
        "current_manifest_file_sha256",
        "prior_manifest_file_sha256s",
        "stage_manifest_sha256",
        "context_inventory_sha256",
        "hidden_registry_inventory_sha256",
        "attestation_inventory_sha256",
        "status",
        "adapter_attestation_sha256",
        "pure_layer_runtime_verified",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_DGP_COMPLETION_RECEIPT_KEYS = _DGP_COMPLETION_RECEIPT_UNSIGNED_KEYS | {
    "dgp_completion_receipt_sha256"
}

_STAGE_PROTOCOL_SEAL_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "trigger_receipt_file_sha256",
        "protocol_plan_seal_file_sha256",
        "stage_plan_file_sha256",
        "dgp_generation_claim_file_sha256",
        "dgp_completion_receipt_file_sha256",
        "stage_kind",
        "attempt_id",
        "dgp_integrity",
        "dgp_generator_source_sha256",
        "context_inventory_sha256",
        "hidden_registry_inventory_sha256",
        "attestation_inventory_sha256",
        "dgp_manifest_path",
        "model_calls_authorized",
        "operational_authorization",
    }
)
_STAGE_PROTOCOL_SEAL_KEYS = _STAGE_PROTOCOL_SEAL_UNSIGNED_KEYS | {
    "structured_stage_protocol_seal_sha256"
}

_ABSENCE_CLAIM_KEYS = frozenset(
    {"claim_id", "path", "role", "claimed_absent", "adapter_attestation_sha256"}
)
_ABSENCE_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "stage_kind",
        "attempt_id",
        "expected_path_inventory_sha256",
        "claim_count",
        "claims",
        "pure_layer_runtime_verified",
        "fresh_runtime_recheck_required",
    }
)
_ABSENCE_KEYS = _ABSENCE_UNSIGNED_KEYS | {"absence_claims_sha256"}
_PROCESS_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "stage_kind",
        "attempt_id",
        "lock_path",
        "pid_path",
        "exit_path",
        "claimed_exclusive_lock_held",
        "claimed_no_live_stage_process",
        "adapter_attestation_sha256",
        "pure_layer_runtime_verified",
        "fresh_runtime_recheck_required",
    }
)
_PROCESS_KEYS = _PROCESS_UNSIGNED_KEYS | {"process_claim_sha256"}

_DGP_INTEGRITY_KEYS = frozenset(
    {
        "stage_manifest_sha256",
        "current_manifest_file_sha256",
        "prior_manifest_file_sha256s",
        "block_count",
        "corpus_count",
        "row_count",
        "public_context_count",
        "prereg_seed_table_validated",
        "public_context_identities_recomputed",
        "hidden_registry_digest_metadata_bound",
        "hidden_registry_contents_validated",
        "scorer_reexecution_performed",
    }
)
_EXPECTED_ARTIFACT_KEYS = frozenset(
    {
        "logical_arm_cells",
        "corpora",
        "public_context_attestations",
        "precommit_bundles",
        "candidate_scalar_receipts",
        "official_scalar_receipts",
        "total_scalar_receipts",
        "initial_raw_traces",
        "stage_reports",
        "sealed_inventories",
        "completion_markers",
    }
)
_COMPARATOR_KEYS = frozenset(
    {
        "canonical_online_icl_required",
        "canonical_online_join_must_be_true",
        "canonical_adaptation_precommit_per_item",
        "canonical_heldout_precommit_per_item",
        "canonical_adaptation_official_receipt_per_item",
        "canonical_heldout_official_receipt_per_item",
    }
)
_EXPECTATION_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "trigger_receipt_file_sha256",
        "protocol_plan_seal_file_sha256",
        "stage_plan_file_sha256",
        "structured_stage_protocol_seal_file_sha256",
        "dgp_generation_claim_file_sha256",
        "dgp_completion_receipt_file_sha256",
        "stage_kind",
        "attempt_id",
        "dgp_integrity",
        "dgp_generator_source_sha256",
        "canonical_comparator_contract",
        "expected_artifact_inventory",
        "absence_claims",
        "absence_claims_file_sha256",
        "process_claim",
        "process_claim_file_sha256",
        "model_calls_authorized",
        "operational_authorization",
        "future_runtime_adapter_required",
    }
)
_EXPECTATION_KEYS = _EXPECTATION_UNSIGNED_KEYS | {"launch_expectation_sha256"}

_CLAIM_REQUIREMENT_KEYS = frozenset(
    {
        "fresh_filesystem_recheck_required",
        "fresh_process_recheck_required",
        "exclusive_lock_required",
        "o_excl_claim_creation_required",
        "claim_must_precede_model_or_scorer_import",
        "claim_verified_by_pure_layer",
    }
)
_GATE_UNSIGNED_KEYS = frozenset(
    {
        "protocol",
        "schema_version",
        "trigger_receipt_file_sha256",
        "protocol_plan_seal_file_sha256",
        "stage_plan_file_sha256",
        "structured_stage_protocol_seal_file_sha256",
        "dgp_generation_claim_file_sha256",
        "dgp_completion_receipt_file_sha256",
        "launch_expectation_file_sha256",
        "stage_kind",
        "attempt_id",
        "status",
        "authorization_scope",
        "single_use",
        "launch_claim_path",
        "launch_claim_expected_absent",
        "claim_requirements",
        "dgp_current_manifest_file_sha256",
        "dgp_prior_manifest_file_sha256s",
        "model_calls_authorized",
        "operational_authorization",
        "future_runtime_adapter_required",
    }
)
_GATE_KEYS = _GATE_UNSIGNED_KEYS | {"prelaunch_gate_sha256"}


@dataclass(frozen=True, slots=True)
class TriggerReceiptValidation:
    trigger_branch: str
    trigger_execution_seal_file_sha256: str
    trigger_receipt_sha256: str
    model_calls_authorized: bool


@dataclass(frozen=True, slots=True)
class ProtocolPlanSealValidation:
    trigger_receipt_file_sha256: str
    protocol_plan_seal_sha256: str
    dgp_generator_source_sha256: str
    durable_root: str
    source_bindings: tuple[tuple[str, str], ...]
    asset_bindings: tuple[tuple[str, str], ...]
    model_calls_authorized: bool


@dataclass(frozen=True, slots=True)
class StagePlanValidation:
    stage_kind: StageKind
    attempt_id: str
    stage_plan_sha256: str
    logical_arm_cell_count: int
    total_scorer_receipt_count: int
    initial_model_generation_count: int
    parent_transition_receipt_file_sha256s: tuple[str, ...]
    paths: tuple[tuple[str, str], ...]
    expected_path_inventory_sha256: str
    expected_path_inventory: tuple[tuple[str, str], ...]
    model_calls_authorized: bool


@dataclass(frozen=True, slots=True)
class StageProtocolSealValidation:
    stage_kind: StageKind
    attempt_id: str
    structured_stage_protocol_seal_sha256: str
    current_manifest_file_sha256: str
    prior_manifest_file_sha256s: tuple[str, ...]
    context_inventory_sha256: str
    model_calls_authorized: bool


@dataclass(frozen=True, slots=True)
class LaunchExpectationValidation:
    stage_kind: StageKind
    attempt_id: str
    launch_expectation_sha256: str
    structured_stage_protocol_seal_file_sha256: str
    current_manifest_file_sha256: str
    prior_manifest_file_sha256s: tuple[str, ...]
    canonical_online_icl_required: bool
    filesystem_claims_runtime_verified: bool
    process_claim_runtime_verified: bool
    model_calls_authorized: bool


@dataclass(frozen=True, slots=True)
class PrelaunchEligibilityValidation:
    stage_kind: StageKind
    attempt_id: str
    prelaunch_gate_sha256: str
    status: str
    authorization_scope: str
    single_use: bool
    eligible_for_one_registered_stage_launch_claim: bool
    model_calls_authorized: bool
    operational_authorization: bool
    future_runtime_adapter_required: bool


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole canonical public JSON representation."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StructuredStageAuthorizationError(
            "value is not canonical-JSON encodable"
        ) from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha(value: object) -> str:
    return _sha(canonical_json_bytes(value))


def _exact_type_equal(actual: object, expected: object) -> bool:
    """Compare canonical-JSON values without Python's bool/int coercions."""

    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        actual_dict = actual
        expected_dict = expected
        if set(actual_dict) != set(expected_dict):
            return False
        return all(
            _exact_type_equal(actual_dict[key], expected_dict[key])
            for key in expected_dict
        )
    if type(expected) is list:
        actual_list = actual
        expected_list = expected
        return len(actual_list) == len(expected_list) and all(
            _exact_type_equal(left, right)
            for left, right in zip(actual_list, expected_list, strict=True)
        )
    return actual == expected


def _require_exact_match(actual: object, expected: object, label: str) -> None:
    if not _exact_type_equal(actual, expected):
        raise StructuredStageAuthorizationError(f"{label} drift")


def _reject_constant(value: str) -> None:
    raise StructuredStageAuthorizationError(
        f"non-finite JSON number is forbidden: {value}"
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StructuredStageAuthorizationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_efficacy_poison(value: object, *, label: str) -> None:
    if type(value) is dict:
        for key, nested in value.items():
            if type(key) is not str:
                raise StructuredStageAuthorizationError(
                    f"{label} contains a non-string JSON key"
                )
            if key.casefold() in _EFFICACY_POISON_KEYS:
                raise StructuredStageAuthorizationError(
                    f"{label} contains forbidden efficacy key: {key}"
                )
            _reject_efficacy_poison(nested, label=label)
    elif type(value) is list:
        for nested in value:
            _reject_efficacy_poison(nested, label=label)
    elif type(value) is float and not math.isfinite(value):
        raise StructuredStageAuthorizationError(
            f"{label} contains a non-finite JSON number"
        )


def _parse_canonical_object(raw: object, label: str) -> dict[str, object]:
    if type(raw) is not bytes:
        raise StructuredStageAuthorizationError(
            f"{label} must be exact canonical bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StructuredStageAuthorizationError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except StructuredStageAuthorizationError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StructuredStageAuthorizationError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise StructuredStageAuthorizationError(f"{label} must be one JSON object")
    _reject_efficacy_poison(value, label=label)
    if raw != canonical_json_bytes(value):
        raise StructuredStageAuthorizationError(
            f"{label} is not exact canonical JSON bytes"
        )
    return value


def _parse_canonical_array(raw: object, label: str) -> list[object]:
    if type(raw) is not bytes:
        raise StructuredStageAuthorizationError(
            f"{label} must be exact canonical bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StructuredStageAuthorizationError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except StructuredStageAuthorizationError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StructuredStageAuthorizationError(f"{label} is not strict JSON") from exc
    if type(value) is not list:
        raise StructuredStageAuthorizationError(f"{label} must be one JSON array")
    _reject_efficacy_poison(value, label=label)
    if raw != canonical_json_bytes(value):
        raise StructuredStageAuthorizationError(
            f"{label} is not exact canonical JSON bytes"
        )
    return value


def _exact_keys(value: object, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise StructuredStageAuthorizationError(f"{label} must be a plain object")
    if len(value) != len(expected) or set(value) != expected:
        raise StructuredStageAuthorizationError(
            f"{label} has missing or additional fields"
        )
    return value


def _exact_list(value: object, label: str) -> list[object]:
    if type(value) is not list:
        raise StructuredStageAuthorizationError(f"{label} must be an exact list")
    return value


def _exact_bytes_tuple(value: object, label: str) -> tuple[bytes, ...]:
    if type(value) is not tuple:
        raise StructuredStageAuthorizationError(
            f"{label} must be an exact tuple of bytes"
        )
    for index, item in enumerate(value):
        if type(item) is not bytes:
            raise StructuredStageAuthorizationError(
                f"{label}[{index}] must be exact canonical bytes"
            )
    return value


def _require_sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise StructuredStageAuthorizationError(f"{label} must be lowercase SHA256 hex")
    return value


def _require_commit(value: object, label: str) -> str:
    if type(value) is not str or _COMMIT_RE.fullmatch(value) is None:
        raise StructuredStageAuthorizationError(f"{label} must be a 40-hex commit")
    return value


def _require_bool(value: object, expected: bool, label: str) -> None:
    if type(value) is not bool or value is not expected:
        raise StructuredStageAuthorizationError(f"{label} must be {expected!r}")


def _require_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise StructuredStageAuthorizationError(
            f"{label} must be an integer >= {minimum}"
        )
    return value


def _require_schema_version(value: object, label: str = "schema_version") -> int:
    if type(value) is not int or value != SCHEMA_VERSION:
        raise StructuredStageAuthorizationError(
            f"{label} must be the exact integer {SCHEMA_VERSION}"
        )
    return value


def _require_safe_id(value: object, label: str) -> str:
    if type(value) is not str or _SAFE_ID_RE.fullmatch(value) is None:
        raise StructuredStageAuthorizationError(f"{label} is not a safe identifier")
    return value


def _require_attempt_id(value: object, label: str = "attempt_id") -> str:
    if type(value) is not str or _ATTEMPT_RE.fullmatch(value) is None:
        raise StructuredStageAuthorizationError(
            f"{label} must match attempt-[0-9]{{3}}"
        )
    return value


def _require_absolute_path(value: object, label: str) -> str:
    if type(value) is not str or not value.startswith("/") or "\x00" in value:
        raise StructuredStageAuthorizationError(
            f"{label} must be an absolute POSIX path"
        )
    normalized = posixpath.normpath(value)
    if value != normalized or any(
        part in ("", ".", "..") for part in value.split("/")[1:]
    ):
        raise StructuredStageAuthorizationError(f"{label} is not a normalized path")
    return value


def _require_relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\x00" in value:
        raise StructuredStageAuthorizationError(
            f"{label} must be a nonempty relative POSIX path"
        )
    normalized = posixpath.normpath(value)
    if value != normalized or any(part in ("", ".", "..") for part in value.split("/")):
        raise StructuredStageAuthorizationError(f"{label} is not a normalized path")
    return value


def _require_stage(value: object, label: str = "stage_kind") -> StageKind:
    if type(value) is not str:
        raise StructuredStageAuthorizationError(f"{label} must be an exact string")
    try:
        return StageKind(value)
    except ValueError as exc:
        raise StructuredStageAuthorizationError(f"{label} is not registered") from exc


def _validate_self_digest(
    obj: dict[str, Any], unsigned_keys: frozenset[str], digest_key: str, label: str
) -> str:
    digest = _require_sha(obj[digest_key], f"{label}.{digest_key}")
    unsigned = {key: obj[key] for key in unsigned_keys}
    if digest != _canonical_sha(unsigned):
        raise StructuredStageAuthorizationError(f"{label} self digest mismatch")
    return digest


def _with_self_digest(unsigned: dict[str, object], *, digest_key: str) -> bytes:
    payload = dict(unsigned)
    payload[digest_key] = _canonical_sha(unsigned)
    return canonical_json_bytes(payload)


def _validate_binding_record(value: object, label: str) -> dict[str, Any]:
    record = _exact_keys(value, _BINDING_RECORD_KEYS, label)
    _require_safe_id(record["binding_id"], f"{label}.binding_id")
    _require_absolute_path(record["path"], f"{label}.path")
    _require_sha(record["sha256"], f"{label}.sha256")
    _require_int(record["size_bytes"], f"{label}.size_bytes")
    return record


def _validate_binding_inventory_object(
    value: object, *, expected_protocol: str, required_ids: tuple[str, ...], label: str
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    obj = _exact_keys(value, _BINDING_INVENTORY_KEYS, label)
    if obj["protocol"] != expected_protocol:
        raise StructuredStageAuthorizationError(f"{label} protocol drift")
    _require_schema_version(obj["schema_version"], f"{label}.schema_version")
    rows = tuple(
        _validate_binding_record(row, f"{label}.bindings[{index}]")
        for index, row in enumerate(_exact_list(obj["bindings"], f"{label}.bindings"))
    )
    ids = tuple(row["binding_id"] for row in rows)
    if ids != required_ids:
        raise StructuredStageAuthorizationError(
            f"{label} binding ids/order differ from the exact registered set"
        )
    paths = tuple(row["path"] for row in rows)
    if len(paths) != len(set(paths)):
        raise StructuredStageAuthorizationError(f"{label} reuses a path")
    _validate_self_digest(
        obj,
        _BINDING_INVENTORY_UNSIGNED_KEYS,
        "binding_inventory_sha256",
        label,
    )
    return obj, rows


def _build_binding_inventory_bytes(
    *, binding_records_bytes: object, protocol: str, required_ids: tuple[str, ...]
) -> bytes:
    rows = _parse_canonical_array(binding_records_bytes, "binding_records_bytes")
    for index, row in enumerate(rows):
        _validate_binding_record(row, f"binding_records[{index}]")
    if tuple(row["binding_id"] for row in rows) != required_ids:
        raise StructuredStageAuthorizationError(
            "binding ids/order differ from the exact registered set"
        )
    unsigned = {
        "protocol": protocol,
        "schema_version": SCHEMA_VERSION,
        "bindings": rows,
    }
    return _with_self_digest(unsigned, digest_key="binding_inventory_sha256")


def build_source_binding_inventory_bytes(*, binding_records_bytes: object) -> bytes:
    """Build the exact self-digested source inventory from canonical list bytes."""

    return _build_binding_inventory_bytes(
        binding_records_bytes=binding_records_bytes,
        protocol=SOURCE_BINDING_INVENTORY_PROTOCOL,
        required_ids=REQUIRED_SOURCE_BINDING_IDS,
    )


def build_asset_binding_inventory_bytes(*, binding_records_bytes: object) -> bytes:
    """Build the exact self-digested asset inventory from canonical list bytes."""

    return _build_binding_inventory_bytes(
        binding_records_bytes=binding_records_bytes,
        protocol=ASSET_BINDING_INVENTORY_PROTOCOL,
        required_ids=REQUIRED_ASSET_BINDING_IDS,
    )


def _validate_trigger_file_records(value: object) -> tuple[dict[str, Any], ...]:
    records = tuple(
        _exact_keys(row, _TRIGGER_FILE_RECORD_KEYS, f"causal_inventory[{index}]")
        for index, row in enumerate(_exact_list(value, "causal_inventory"))
    )
    if not records:
        raise StructuredStageAuthorizationError("causal inventory may not be empty")
    paths: list[str] = []
    for index, row in enumerate(records):
        label = f"causal_inventory[{index}]"
        _require_int(row["device"], f"{label}.device")
        _require_int(row["inode"], f"{label}.inode")
        _require_int(row["mtime_ns"], f"{label}.mtime_ns")
        paths.append(_require_absolute_path(row["path"], f"{label}.path"))
        roles = _exact_list(row["roles"], f"{label}.roles")
        if not roles or any(type(role) is not str for role in roles):
            raise StructuredStageAuthorizationError(f"{label}.roles must be strings")
        if roles != sorted(set(roles)):
            raise StructuredStageAuthorizationError(f"{label}.roles drift")
        _require_sha(row["sha256"], f"{label}.sha256")
        _require_int(row["size_bytes"], f"{label}.size_bytes")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise StructuredStageAuthorizationError(
            "causal inventory paths must be unique and sorted"
        )
    return records


def _validate_trigger_bindings(value: object) -> None:
    records = tuple(
        _exact_keys(row, _BINDING_RECORD_KEYS - {"binding_id"}, f"bindings[{index}]")
        for index, row in enumerate(_exact_list(value, "bindings"))
    )
    if not records:
        raise StructuredStageAuthorizationError("trigger bindings may not be empty")
    paths: list[str] = []
    for index, row in enumerate(records):
        label = f"bindings[{index}]"
        paths.append(_require_absolute_path(row["path"], f"{label}.path"))
        _require_sha(row["sha256"], f"{label}.sha256")
        _require_int(row["size_bytes"], f"{label}.size_bytes")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise StructuredStageAuthorizationError(
            "trigger bindings must be unique and sorted"
        )


def _validate_verifier_execution(value: object) -> None:
    obj = _exact_keys(value, _VERIFIER_EXECUTION_KEYS, "verifier_execution")
    invocations = _exact_keys(
        obj["invocations"], _VERIFIER_TOOL_NAMES, "verifier_execution.invocations"
    )
    for name in sorted(_VERIFIER_TOOL_NAMES):
        invocation = _exact_keys(
            invocations[name],
            _VERIFIER_INVOCATION_KEYS,
            f"verifier_execution.invocations.{name}",
        )
        argv = _exact_list(invocation["argv"], f"{name}.argv")
        if any(type(arg) is not str for arg in argv):
            raise StructuredStageAuthorizationError(f"{name}.argv must be strings")
        input_keys, output_keys, parameter_keys = _VERIFIER_INVOCATION_SCHEMAS[name]
        for key, expected_keys in (
            ("inputs", input_keys),
            ("outputs", output_keys),
            ("parameters", parameter_keys),
        ):
            values = _exact_keys(
                invocation[key], expected_keys, f"verifier_execution.{name}.{key}"
            )
            if any(type(item) is not str for item in values.values()):
                raise StructuredStageAuthorizationError(
                    f"verifier_execution.{name}.{key} values must be strings"
                )
    expected_invocations_sha = _require_sha(
        obj["invocations_sha256"], "verifier_execution.invocations_sha256"
    )
    if expected_invocations_sha != _canonical_sha(invocations):
        raise StructuredStageAuthorizationError("verifier invocations digest mismatch")
    runtime = _exact_keys(
        obj["runtime"], _VERIFIER_RUNTIME_KEYS, "verifier_execution.runtime"
    )
    if any(type(runtime[key]) is not str for key in _VERIFIER_RUNTIME_KEYS):
        raise StructuredStageAuthorizationError(
            "verifier runtime values must be strings"
        )
    tools = _exact_keys(obj["tools"], _VERIFIER_TOOL_NAMES, "verifier_execution.tools")
    for name in sorted(_VERIFIER_TOOL_NAMES):
        tool = _exact_keys(
            tools[name], _VERIFIER_TOOL_KEYS, f"verifier_execution.tools.{name}"
        )
        _require_absolute_path(tool["path"], f"verifier_execution.tools.{name}.path")
        _require_sha(tool["sha256"], f"verifier_execution.tools.{name}.sha256")


def _validate_trigger_execution_seal(value: object) -> tuple[dict[str, Any], str]:
    seal = _exact_keys(value, _TRIGGER_SEAL_KEYS, "trigger_execution_seal")
    if (
        seal["protocol"] != TRIGGER_EXECUTION_SEAL_PROTOCOL
        or seal["status"] != "sealed"
    ):
        raise StructuredStageAuthorizationError("trigger execution seal protocol drift")
    _require_schema_version(
        seal["schema_version"], "trigger execution seal.schema_version"
    )
    branch = seal["trigger_branch"]
    if branch not in (TRIGGER_A, TRIGGER_B):
        raise StructuredStageAuthorizationError("unregistered trigger branch")
    _validate_trigger_bindings(seal["bindings"])
    inventory = _validate_trigger_file_records(seal["causal_inventory"])
    if _canonical_sha(list(inventory)) != _require_sha(
        seal["causal_inventory_sha256"], "causal_inventory_sha256"
    ):
        raise StructuredStageAuthorizationError("causal inventory digest mismatch")
    for key in (
        "causal_completion_attestation_sha256",
        "causal_decision_sha256",
        "causal_exit_file_sha256",
        "causal_original_file_sha256",
        "causal_pid_file_sha256",
        "causal_pre_attestation_inventory_sha256",
        "causal_revalidation_file_sha256",
        "terminal_verifier_execution_plan_sha256",
    ):
        _require_sha(seal[key], key)
    _require_bool(
        seal["causal_inventory_recheck_matches_attestation"],
        True,
        "causal_inventory_recheck_matches_attestation",
    )
    if seal["causal_protocol_seal_sha256"] is not None:
        raise StructuredStageAuthorizationError("causal route invents a protocol seal")
    if seal["causal_protocol_seal_status"] != CAUSAL_PROTOCOL_SEAL_STATUS:
        raise StructuredStageAuthorizationError("causal protocol-seal status drift")
    _require_commit(seal["causal_source_commit"], "causal_source_commit")
    _require_commit(seal["tooling_source_commit"], "tooling_source_commit")
    _require_absolute_path(
        seal["terminal_verifier_execution_plan_path"],
        "terminal_verifier_execution_plan_path",
    )
    if type(seal["created_at_utc"]) is not str or not seal["created_at_utc"].endswith(
        "Z"
    ):
        raise StructuredStageAuthorizationError("created_at_utc must be UTC Z text")
    _validate_verifier_execution(seal["verifier_execution"])

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
    if branch == TRIGGER_A:
        if any(seal[key] is not None for key in online_keys):
            raise StructuredStageAuthorizationError(
                "Trigger A must have an exactly null online evidence arm"
            )
    else:
        # There is not yet a committed exact online completion/revalidation
        # evidence schema in this pure layer.  Register the discriminator, but
        # fail closed rather than accepting a hand-written approximation.
        raise StructuredStageAuthorizationError(
            "Trigger B is unsupported in authorization v1 until the real online evidence schema is sealed"
        )
    return seal, branch


def build_trigger_receipt_bytes(*, trigger_execution_seal_bytes: object) -> bytes:
    """Disabled: a seal alone is never sufficient trigger evidence."""

    del trigger_execution_seal_bytes
    raise StructuredStageAuthorizationError(
        "seal-only trigger receipts are disabled; use the strict trigger bridge "
        "with the full independent-revalidator evidence closure"
    )


def validate_trigger_receipt_bytes(raw: object) -> TriggerReceiptValidation:
    """Disabled: validation must use all strict raw evidence edges."""

    del raw
    raise StructuredStageAuthorizationError(
        "legacy trigger receipt validation is disabled; use "
        "cohort_closed_loop_structured_trigger_bridge"
    )


def _binding_map(rows: tuple[dict[str, Any], ...]) -> dict[str, dict[str, Any]]:
    return {row["binding_id"]: row for row in rows}


def _path_layout(durable_root: str) -> dict[str, object]:
    return {"durable_root": durable_root, **PATH_LAYOUT_TEMPLATES}


def _validate_path_layout(value: object) -> dict[str, Any]:
    layout = _exact_keys(value, _PATH_LAYOUT_KEYS, "path_layout")
    _require_absolute_path(layout["durable_root"], "path_layout.durable_root")
    if layout["durable_root"] == "/":
        raise StructuredStageAuthorizationError(
            "durable_root may not be filesystem root"
        )
    for key, expected in PATH_LAYOUT_TEMPLATES.items():
        if layout[key] != expected:
            raise StructuredStageAuthorizationError(
                f"path layout template drift: {key}"
            )
    return layout


def _validate_dgp_binding(
    value: object,
    *,
    sources: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    binding = _exact_keys(value, _DGP_BINDING_KEYS, "dgp_binding")
    if binding["stage_manifest_protocol"] != STAGE_MANIFEST_PROTOCOL:
        raise StructuredStageAuthorizationError("DGP stage-manifest protocol drift")
    if binding["prereg_document_sha256"] != PREREG_DOCUMENT_SHA256:
        raise StructuredStageAuthorizationError("DGP preregistration digest drift")
    dgp_generator = _require_sha(
        binding["dgp_generator_source_sha256"],
        "dgp_binding.dgp_generator_source_sha256",
    )
    dgp_context = _require_sha(
        binding["dgp_context_source_sha256"],
        "dgp_binding.dgp_context_source_sha256",
    )
    if dgp_generator != sources["dgp_generator"]["sha256"]:
        raise StructuredStageAuthorizationError("DGP generator source substitution")
    if dgp_context != sources["structured_dgp_context_validation"]["sha256"]:
        raise StructuredStageAuthorizationError("DGP context source substitution")
    return binding


def build_protocol_plan_seal_bytes(
    *,
    trigger_receipt_bytes: object,
    source_binding_inventory_bytes: object,
    asset_binding_inventory_bytes: object,
    durable_root: object,
) -> bytes:
    """Disabled: the embedded-claim-only protocol plan is forbidden."""

    del (
        trigger_receipt_bytes,
        source_binding_inventory_bytes,
        asset_binding_inventory_bytes,
        durable_root,
    )
    raise StructuredStageAuthorizationError(
        "legacy protocol-plan construction is disabled; use the raw-byte "
        "structured protocol plan"
    )


def _load_protocol_plan_seal_object(
    raw: object, *, trigger_receipt_bytes: object
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    del raw, trigger_receipt_bytes
    raise StructuredStageAuthorizationError(
        "legacy protocol-plan validation is disabled; use the raw-byte "
        "structured protocol plan"
    )


def validate_protocol_plan_seal_bytes(
    raw: object, *, trigger_receipt_bytes: object
) -> ProtocolPlanSealValidation:
    """Disabled with the legacy embedded-claim-only protocol plan."""

    del raw, trigger_receipt_bytes
    raise StructuredStageAuthorizationError(
        "legacy protocol-plan validation is disabled; use "
        "cohort_closed_loop_structured_protocol_plan"
    )


def _expected_stage_shape(stage: StageKind) -> dict[str, int]:
    shape = STAGE_SHAPES[stage]
    return {"blocks": shape.blocks, "items_per_phase": shape.items_per_phase}


def _expected_seeds(stage: StageKind) -> list[dict[str, object]]:
    return [
        {
            "block_id": seed.block_id,
            "block_index": seed.block_index,
            "run_seed": seed.run_seed,
            "adaptation_dgp_seed": seed.adaptation_dgp_seed,
            "held_out_dgp_seed": seed.held_out_dgp_seed,
        }
        for seed in EXPECTED_STAGE_SEEDS[stage]
    ]


def _expected_branch_contract() -> dict[str, object]:
    return {
        "logical_arms": list(ARM_IDS),
        "structured_adaptation_branches": list(ADAPTATION_STRUCTURED_BRANCH_IDS),
        "structured_heldout_branches": list(HELDOUT_STRUCTURED_BRANCH_IDS),
        "canonical_branch": CANONICAL_BRANCH_ID,
        "candidate_actions_per_adaptation_branch_item": 16,
        "rollback_adaptation_is_active_alias": True,
        "rollback_has_separate_adaptation_candidates": False,
        "candidate_actions_make_model_calls": False,
        "canonical_comparator_required": True,
        "canonical_online_join_must_be_true": True,
        "structured_raw_trajectory_shared_across_branches": True,
    }


def _expected_accounting(stage: StageKind) -> dict[str, int]:
    shape = STAGE_SHAPES[stage]
    b = shape.blocks
    n = shape.items_per_phase
    return {
        "logical_arm_cell_count": 5 * b,
        "corpus_count": 2 * b,
        "dgp_row_count": 2 * b * n,
        "public_context_count": 2 * b * n,
        "precommit_bundle_count": 4 * b * n,
        "candidate_scorer_call_count": 48 * b * n,
        "official_scorer_call_count": 9 * b * n,
        "total_scorer_receipt_count": 57 * b * n,
        "closed_loop_active_scorer_call_count": 18 * b * n,
        "closed_loop_lr0_scorer_call_count": 18 * b * n,
        "pair_sign_reverse_scorer_call_count": 18 * b * n,
        "closed_loop_rollback_scorer_call_count": b * n,
        "canonical_online_icl_scorer_call_count": 2 * b * n,
        "structured_raw_initial_generation_count": 2 * b * n,
        "canonical_initial_generation_count": 2 * b * n,
        "initial_model_generation_count": 4 * b * n,
        "maximum_model_generation_attempt_count": 12 * b * n,
        "parse_retries_per_trajectory": 2,
        "candidate_action_model_generation_count": 0,
    }


def registered_stage_accounting(stage_kind: object) -> dict[str, int]:
    """Return a detached copy of fixed preregistered accounting constants.

    This is descriptive metadata only.  It does not construct a stage plan or
    accept a parent transition.
    """

    return dict(_expected_accounting(_require_stage(stage_kind)))


def build_stage_transition_receipt_bytes(
    *,
    stage_kind: object,
    attempt_id: object,
    structured_stage_protocol_seal_bytes: object,
    prelaunch_gate_bytes: object,
    stage_report_bytes: object,
    stage_report_revalidated_bytes: object,
    private_validation_bytes: object,
    completion_marker_bytes: object,
    sealed_inventory_bytes: object,
    prior_transition_receipt_bytes: object,
) -> bytes:
    """Fail closed until semantic report/private/completion validators exist."""

    del (
        stage_kind,
        attempt_id,
        structured_stage_protocol_seal_bytes,
        prelaunch_gate_bytes,
        stage_report_bytes,
        stage_report_revalidated_bytes,
        private_validation_bytes,
        completion_marker_bytes,
        sealed_inventory_bytes,
        prior_transition_receipt_bytes,
    )
    raise StructuredStageAuthorizationError(
        "stage transitions are unavailable until exact semantic completion "
        "validators are sealed"
    )


def _validate_parent_transition_chain(
    *, stage: StageKind, supplied_bytes: object, embedded_value: object
) -> tuple[str, ...]:
    raws = _exact_bytes_tuple(supplied_bytes, "parent_transition_receipt_bytes")
    if stage is StageKind.SMOKE:
        if raws:
            raise StructuredStageAuthorizationError(
                "smoke requires exactly zero parent transitions"
            )
        if embedded_value is not None:
            raise StructuredStageAuthorizationError(
                "smoke parent transition must be null"
            )
        return ()
    del embedded_value
    raise StructuredStageAuthorizationError(
        "internal and confirmation plans are unavailable until exact semantic "
        "transition validators are sealed"
    )


def _concrete_paths(
    *, durable_root: str, stage: StageKind, attempt_id: str
) -> dict[str, str]:
    _require_attempt_id(attempt_id)
    stage_root = PATH_LAYOUT_TEMPLATES["stage_root_template"].format(
        durable_root=durable_root,
        stage_kind=stage.value,
        attempt_id=attempt_id,
    )
    values = {
        "stage_root": stage_root,
        "stage_plan_path": PATH_LAYOUT_TEMPLATES["stage_plan_path_template"].format(
            stage_root=stage_root
        ),
        "dgp_generation_claim_path": PATH_LAYOUT_TEMPLATES[
            "dgp_generation_claim_path_template"
        ].format(stage_root=stage_root),
        "dgp_completion_receipt_path": PATH_LAYOUT_TEMPLATES[
            "dgp_completion_receipt_path_template"
        ].format(stage_root=stage_root),
        "stage_protocol_seal_path": PATH_LAYOUT_TEMPLATES[
            "stage_protocol_seal_path_template"
        ].format(stage_root=stage_root),
        "dgp_manifest_path": PATH_LAYOUT_TEMPLATES["dgp_manifest_path_template"].format(
            stage_root=stage_root
        ),
        "launch_expectation_path": PATH_LAYOUT_TEMPLATES[
            "launch_expectation_path_template"
        ].format(stage_root=stage_root),
        "prelaunch_gate_path": PATH_LAYOUT_TEMPLATES[
            "prelaunch_gate_path_template"
        ].format(stage_root=stage_root),
        "launch_claim_path": PATH_LAYOUT_TEMPLATES["launch_claim_path_template"].format(
            stage_root=stage_root
        ),
        "sealed_inventory_path": PATH_LAYOUT_TEMPLATES[
            "sealed_inventory_path_template"
        ].format(stage_root=stage_root),
        "completion_marker_path": PATH_LAYOUT_TEMPLATES[
            "completion_marker_path_template"
        ].format(stage_root=stage_root),
        "stage_report_path": PATH_LAYOUT_TEMPLATES["stage_report_path_template"].format(
            stage_root=stage_root
        ),
        "stage_report_revalidated_path": PATH_LAYOUT_TEMPLATES[
            "stage_report_revalidated_path_template"
        ].format(stage_root=stage_root),
        "private_validation_receipt_path": PATH_LAYOUT_TEMPLATES[
            "private_validation_receipt_path_template"
        ].format(stage_root=stage_root),
        "private_validation_revalidation_receipt_path": PATH_LAYOUT_TEMPLATES[
            "private_validation_revalidation_receipt_path_template"
        ].format(stage_root=stage_root),
        "poison_test_receipt_path": PATH_LAYOUT_TEMPLATES[
            "poison_test_receipt_path_template"
        ].format(stage_root=stage_root),
        "failed_attempt_closure_receipt_path": PATH_LAYOUT_TEMPLATES[
            "failed_attempt_closure_receipt_path_template"
        ].format(stage_root=stage_root),
        "retry_authorization_receipt_path": PATH_LAYOUT_TEMPLATES[
            "retry_authorization_receipt_path_template"
        ].format(stage_root=stage_root),
        "stage_transition_receipt_path": PATH_LAYOUT_TEMPLATES[
            "stage_transition_receipt_path_template"
        ].format(stage_root=stage_root),
        "lock_path": PATH_LAYOUT_TEMPLATES["lock_path_template"].format(
            stage_root=stage_root
        ),
        "pid_path": PATH_LAYOUT_TEMPLATES["pid_path_template"].format(
            stage_root=stage_root
        ),
        "exit_path": PATH_LAYOUT_TEMPLATES["exit_path_template"].format(
            stage_root=stage_root
        ),
    }
    for key, value in values.items():
        _require_absolute_path(value, f"paths.{key}")
    if len(values.values()) != len(set(values.values())):
        raise StructuredStageAuthorizationError("concrete control paths collide")
    return values


def _expected_path_inventory(
    *, stage: StageKind, paths: dict[str, str]
) -> list[dict[str, str]]:
    """Expand the complete registered stage path/role inventory.

    Paths are relative to the concrete stage root, contain no wildcards, and
    are sorted bytewise by their canonical ASCII spelling.  This enumerator is
    intentionally independent of runtime directory listings.
    """

    stage_root = paths["stage_root"]
    records: list[dict[str, str]] = []
    seen: set[str] = set()

    def add_relative(path: str, role: str) -> None:
        relative = _require_relative_path(path, "expected path inventory.path")
        _require_safe_id(role, "expected path inventory.role")
        if relative in seen:
            raise StructuredStageAuthorizationError(
                f"expected path inventory collision: {relative}"
            )
        seen.add(relative)
        records.append({"path": relative, "role": role})

    def add_absolute(path: str, role: str) -> None:
        absolute = _require_absolute_path(path, "expected path inventory absolute path")
        prefix = stage_root + "/"
        if not absolute.startswith(prefix):
            raise StructuredStageAuthorizationError(
                "expected stage artifact escapes the concrete stage root"
            )
        add_relative(absolute[len(prefix) :], role)

    control_roles = {
        "stage_plan_path": "stage_plan",
        "dgp_generation_claim_path": "dgp_generation_claim",
        "dgp_completion_receipt_path": "dgp_completion_receipt",
        "stage_protocol_seal_path": "structured_stage_protocol_seal",
        "dgp_manifest_path": "dgp_stage_manifest",
        "launch_expectation_path": "launch_expectation",
        "prelaunch_gate_path": "prelaunch_gate",
        "launch_claim_path": "single_use_launch_claim",
        "sealed_inventory_path": "sealed_artifact_inventory",
        "completion_marker_path": "completion_marker",
        "stage_report_path": "stage_report",
        "stage_report_revalidated_path": "stage_report_revalidation",
        "private_validation_receipt_path": "private_validation_receipt",
        "private_validation_revalidation_receipt_path": (
            "private_validation_revalidation_receipt"
        ),
        "poison_test_receipt_path": "poison_test_receipt",
        "failed_attempt_closure_receipt_path": ("failed_attempt_closure_receipt"),
        "retry_authorization_receipt_path": "retry_authorization_receipt",
        "stage_transition_receipt_path": "stage_transition_receipt",
        "lock_path": "wrapper_lock",
        "pid_path": "wrapper_pid",
        "exit_path": "wrapper_exit",
    }
    for path_key, role in control_roles.items():
        add_absolute(paths[path_key], role)

    for seed in EXPECTED_STAGE_SEEDS[stage]:
        block_id = seed.block_id
        for phase in ("adaptation", "held_out"):
            add_absolute(
                PATH_LAYOUT_TEMPLATES["corpus_inventory_path_template"].format(
                    stage_root=stage_root,
                    block_id=block_id,
                    phase=phase,
                ),
                "dgp_corpus_inventory",
            )
            for item_id in range(1, STAGE_SHAPES[stage].items_per_phase + 1):
                format_args = {
                    "stage_root": stage_root,
                    "block_id": block_id,
                    "phase": phase,
                    "item_id": item_id,
                }
                add_absolute(
                    PATH_LAYOUT_TEMPLATES["dgp_row_path_template"].format(
                        **format_args
                    ),
                    "dgp_row_identity",
                )
                add_absolute(
                    PATH_LAYOUT_TEMPLATES["context_attestation_path_template"].format(
                        **format_args
                    ),
                    "public_context_attestation",
                )
                add_absolute(
                    PATH_LAYOUT_TEMPLATES[
                        "context_registry_digest_path_template"
                    ].format(**format_args),
                    "context_registry_digest_record",
                )
                for policy_family in ("structured_shared", CANONICAL_BRANCH_ID):
                    add_absolute(
                        PATH_LAYOUT_TEMPLATES["raw_trace_path_template"].format(
                            **format_args,
                            policy_family=policy_family,
                        ),
                        f"{policy_family}_raw_trace",
                    )
                for family in ("structured", CANONICAL_BRANCH_ID):
                    add_absolute(
                        PATH_LAYOUT_TEMPLATES["precommit_path_template"].format(
                            **format_args,
                            family=family,
                        ),
                        f"{family}_precommit_bundle",
                    )
                for branch_id in HELDOUT_STRUCTURED_BRANCH_IDS:
                    add_absolute(
                        PATH_LAYOUT_TEMPLATES["state_path_template"].format(
                            **format_args,
                            branch_id=branch_id,
                        ),
                        f"{phase}_structured_state",
                    )

                if phase == "adaptation":
                    for branch_id in ADAPTATION_STRUCTURED_BRANCH_IDS:
                        add_absolute(
                            PATH_LAYOUT_TEMPLATES["receipt_path_template"].format(
                                **format_args,
                                receipt_path=f"structured/{branch_id}/official",
                            ),
                            "adaptation_structured_official_scalar_receipt",
                        )
                        for candidate_id in CANDIDATE_ACTION_IDS:
                            add_absolute(
                                PATH_LAYOUT_TEMPLATES["receipt_path_template"].format(
                                    **format_args,
                                    receipt_path=(
                                        f"structured/{branch_id}/candidates/"
                                        f"{candidate_id}"
                                    ),
                                ),
                                "adaptation_structured_candidate_scalar_receipt",
                            )
                else:
                    for branch_id in HELDOUT_STRUCTURED_BRANCH_IDS:
                        add_absolute(
                            PATH_LAYOUT_TEMPLATES["receipt_path_template"].format(
                                **format_args,
                                receipt_path=f"structured/{branch_id}/official",
                            ),
                            "held_out_structured_official_scalar_receipt",
                        )
                    add_absolute(
                        PATH_LAYOUT_TEMPLATES[
                            "restore_attestation_path_template"
                        ].format(**format_args),
                        "canonical_online_icl_restore_attestation",
                    )

                add_absolute(
                    PATH_LAYOUT_TEMPLATES["receipt_path_template"].format(
                        **format_args,
                        receipt_path=f"{CANONICAL_BRANCH_ID}/official",
                    ),
                    f"{phase}_canonical_online_icl_official_scalar_receipt",
                )

        add_absolute(
            PATH_LAYOUT_TEMPLATES["snapshot_path_template"].format(
                stage_root=stage_root,
                block_id=block_id,
            ),
            "canonical_online_icl_adaptation_snapshot",
        )
        for arm_id in ARM_IDS:
            add_absolute(
                PATH_LAYOUT_TEMPLATES["cell_manifest_path_template"].format(
                    stage_root=stage_root,
                    block_id=block_id,
                    arm_id=arm_id,
                ),
                "logical_arm_cell_manifest",
            )
            for phase in ("adaptation", "held_out"):
                add_absolute(
                    PATH_LAYOUT_TEMPLATES["compute_path_template"].format(
                        stage_root=stage_root,
                        block_id=block_id,
                        arm_id=arm_id,
                        phase=phase,
                    ),
                    f"{phase}_logical_arm_compute_receipt",
                )

    base_records = sorted(records, key=lambda row: row["path"])
    stage_relative_root = (
        f"stages/{stage.value}/{posixpath.basename(paths['stage_root'])}"
    )
    for row in base_records:
        durable_relative_path = f"{stage_relative_root}/{row['path']}"
        intent_path, pending_path = publication_sidecar_relative_paths(
            durable_relative_path
        )
        prefix = stage_relative_root + "/"
        if not intent_path.startswith(prefix) or not pending_path.startswith(prefix):
            raise StructuredStageAuthorizationError(
                "atomic publication sidecar escapes the concrete stage root"
            )
        add_relative(
            intent_path[len(prefix) :],
            _ATOMIC_PUBLICATION_INTENT_ROLE,
        )
        add_relative(
            pending_path[len(prefix) :],
            _ATOMIC_PUBLICATION_PENDING_ABSENT_ROLE,
        )

    return sorted(records, key=lambda row: row["path"])


def _validate_expected_path_inventory(
    value: object,
    *,
    stage: StageKind,
    paths: dict[str, str],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for index, value_row in enumerate(_exact_list(value, "expected_path_inventory")):
        row = _exact_keys(
            value_row,
            _EXPECTED_PATH_RECORD_KEYS,
            f"expected_path_inventory[{index}]",
        )
        rows.append(
            {
                "path": _require_relative_path(
                    row["path"], f"expected_path_inventory[{index}].path"
                ),
                "role": _require_safe_id(
                    row["role"], f"expected_path_inventory[{index}].role"
                ),
            }
        )
    expected = _expected_path_inventory(stage=stage, paths=paths)
    _require_exact_match(
        rows,
        expected,
        "complete sorted expected path/role inventory",
    )
    return rows


def _validate_fixed_stage_payload(
    obj: dict[str, Any], *, stage: StageKind, durable_root: str
) -> None:
    shape = _exact_keys(obj["stage_shape"], _STAGE_SHAPE_KEYS, "stage_shape")
    _require_exact_match(shape, _expected_stage_shape(stage), "stage shape")
    seed_values = _exact_list(obj["seeds"], "seeds")
    for index, value in enumerate(seed_values):
        _exact_keys(value, _SEED_KEYS, f"seeds[{index}]")
    _require_exact_match(seed_values, _expected_seeds(stage), "stage seed table")
    branch = _exact_keys(
        obj["branch_contract"], _BRANCH_CONTRACT_KEYS, "branch_contract"
    )
    _require_exact_match(
        branch,
        _expected_branch_contract(),
        "stage branch/family contract",
    )
    accounting = _exact_keys(obj["accounting"], _ACCOUNTING_KEYS, "accounting")
    _require_exact_match(accounting, _expected_accounting(stage), "stage accounting")
    paths = _exact_keys(obj["paths"], frozenset(_CONCRETE_PATH_KEYS), "paths")
    expected_paths = _concrete_paths(
        durable_root=durable_root,
        stage=stage,
        attempt_id=obj["attempt_id"],
    )
    _require_exact_match(paths, expected_paths, "concrete path layout")
    inventory = _validate_expected_path_inventory(
        obj["expected_path_inventory"], stage=stage, paths=paths
    )
    expected_inventory_sha256 = _canonical_sha(inventory)
    if obj["expected_path_inventory_sha256"] != expected_inventory_sha256:
        raise StructuredStageAuthorizationError("expected path inventory digest drift")


def build_stage_plan_bytes(
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_kind: object,
    attempt_id: object,
    parent_transition_receipt_bytes: object,
) -> bytes:
    """Build one stage plan with fixed shapes, seeds, families, and accounting."""

    validate_trigger_receipt_bytes(trigger_receipt_bytes)
    seal, _, _ = _load_protocol_plan_seal_object(
        protocol_plan_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
    )
    stage = _require_stage(stage_kind)
    attempt = _require_attempt_id(attempt_id)
    parents = _exact_bytes_tuple(
        parent_transition_receipt_bytes, "parent_transition_receipt_bytes"
    )
    embedded_parent: object
    if stage is StageKind.SMOKE:
        embedded_parent = None
    else:
        embedded_parent = [
            _parse_canonical_object(raw, f"parent_transition_receipt_bytes[{index}]")
            for index, raw in enumerate(parents)
        ]
    parent_digests = _validate_parent_transition_chain(
        stage=stage,
        supplied_bytes=parents,
        embedded_value=embedded_parent,
    )
    paths = _concrete_paths(
        durable_root=seal["path_layout"]["durable_root"],
        stage=stage,
        attempt_id=attempt,
    )
    expected_path_inventory = _expected_path_inventory(stage=stage, paths=paths)
    unsigned = {
        "protocol": STAGE_PLAN_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_kind": stage.value,
        "attempt_id": attempt,
        "stage_shape": _expected_stage_shape(stage),
        "seeds": _expected_seeds(stage),
        "branch_contract": _expected_branch_contract(),
        "accounting": _expected_accounting(stage),
        "parent_transition_chain": embedded_parent,
        "parent_transition_receipt_file_sha256s": list(parent_digests),
        "paths": paths,
        "expected_path_inventory": expected_path_inventory,
        "expected_path_inventory_sha256": _canonical_sha(expected_path_inventory),
        "eligible_for_dgp_generation_claim": True,
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    return _with_self_digest(unsigned, digest_key="stage_plan_sha256")


def _load_stage_plan_object(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    parent_transition_receipt_bytes: object,
) -> dict[str, Any]:
    validate_trigger_receipt_bytes(trigger_receipt_bytes)
    seal, _, _ = _load_protocol_plan_seal_object(
        protocol_plan_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
    )
    obj = _exact_keys(
        _parse_canonical_object(raw, "stage_plan_bytes"),
        _STAGE_PLAN_KEYS,
        "stage plan",
    )
    if obj["protocol"] != STAGE_PLAN_PROTOCOL:
        raise StructuredStageAuthorizationError("stage plan protocol drift")
    _require_schema_version(obj["schema_version"], "stage plan.schema_version")
    if obj["trigger_receipt_file_sha256"] != _sha(trigger_receipt_bytes):
        raise StructuredStageAuthorizationError(
            "stage plan trigger-receipt substitution"
        )
    if obj["protocol_plan_seal_file_sha256"] != _sha(protocol_plan_seal_bytes):
        raise StructuredStageAuthorizationError("stage plan protocol-seal substitution")
    stage = _require_stage(obj["stage_kind"])
    _require_attempt_id(obj["attempt_id"])
    parent_digests = _validate_parent_transition_chain(
        stage=stage,
        supplied_bytes=parent_transition_receipt_bytes,
        embedded_value=obj["parent_transition_chain"],
    )
    if obj["parent_transition_receipt_file_sha256s"] != list(parent_digests):
        raise StructuredStageAuthorizationError(
            "stage plan parent byte digest mismatch"
        )
    _validate_fixed_stage_payload(
        obj, stage=stage, durable_root=seal["path_layout"]["durable_root"]
    )
    _require_bool(
        obj["eligible_for_dgp_generation_claim"],
        True,
        "eligible_for_dgp_generation_claim",
    )
    _require_bool(obj["model_calls_authorized"], False, "model_calls_authorized")
    _require_bool(obj["operational_authorization"], False, "operational_authorization")
    _validate_self_digest(
        obj, _STAGE_PLAN_UNSIGNED_KEYS, "stage_plan_sha256", "stage plan"
    )
    return obj


def validate_stage_plan_bytes(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    parent_transition_receipt_bytes: object,
) -> StagePlanValidation:
    """Validate a stage plan and all of its exact upstream byte edges."""

    obj = _load_stage_plan_object(
        raw,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    stage = StageKind(obj["stage_kind"])
    accounting = obj["accounting"]
    return StagePlanValidation(
        stage_kind=stage,
        attempt_id=obj["attempt_id"],
        stage_plan_sha256=obj["stage_plan_sha256"],
        logical_arm_cell_count=accounting["logical_arm_cell_count"],
        total_scorer_receipt_count=accounting["total_scorer_receipt_count"],
        initial_model_generation_count=accounting["initial_model_generation_count"],
        parent_transition_receipt_file_sha256s=tuple(
            obj["parent_transition_receipt_file_sha256s"]
        ),
        paths=tuple((key, obj["paths"][key]) for key in _CONCRETE_PATH_KEYS),
        expected_path_inventory_sha256=obj["expected_path_inventory_sha256"],
        expected_path_inventory=tuple(
            (row["path"], row["role"]) for row in obj["expected_path_inventory"]
        ),
        model_calls_authorized=False,
    )


def _expected_pending_production_outputs(
    plan: dict[str, Any],
) -> list[dict[str, str]]:
    stage_root = plan["paths"]["stage_root"]
    stage_relative_root = (
        f"stages/{plan['stage_kind']}/{posixpath.basename(stage_root)}"
    )
    base_records = [
        row
        for row in plan["expected_path_inventory"]
        if row["role"]
        not in {
            _ATOMIC_PUBLICATION_INTENT_ROLE,
            _ATOMIC_PUBLICATION_PENDING_ABSENT_ROLE,
        }
    ]
    existing_paths = {
        row["path"]
        for row in base_records
        if row["role"] in _PRELAUNCH_EXISTING_ARTIFACT_ROLES
    }
    prefix = stage_relative_root + "/"
    for row in base_records:
        if row["path"] not in existing_paths:
            continue
        intent_path, _ = publication_sidecar_relative_paths(
            f"{stage_relative_root}/{row['path']}"
        )
        if not intent_path.startswith(prefix):
            raise StructuredStageAuthorizationError(
                "existing publication intent escapes the concrete stage root"
            )
        existing_paths.add(intent_path[len(prefix) :])
    pending = [
        row
        for row in plan["expected_path_inventory"]
        if row["path"] not in existing_paths
    ]
    return [
        {
            "claim_id": f"production_output_{index:06d}",
            "path": _require_absolute_path(
                f"{stage_root}/{row['path']}",
                f"pending production output[{index}].path",
            ),
            "role": row["role"],
        }
        for index, row in enumerate(pending)
    ]


def build_prelaunch_absence_claims_bytes(
    *,
    stage_plan_bytes: object,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    parent_transition_receipt_bytes: object,
    adapter_attestation_sha256: object,
) -> bytes:
    """Bind a future adapter's claimed-absence snapshot without verifying I/O."""

    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    attestation = _require_sha(adapter_attestation_sha256, "adapter_attestation_sha256")
    expected_outputs = _expected_pending_production_outputs(plan)
    claims = [
        {
            **expected,
            "claimed_absent": True,
            "adapter_attestation_sha256": attestation,
        }
        for expected in expected_outputs
    ]
    unsigned = {
        "protocol": ABSENCE_CLAIMS_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "stage_kind": plan["stage_kind"],
        "attempt_id": plan["attempt_id"],
        "expected_path_inventory_sha256": plan["expected_path_inventory_sha256"],
        "claim_count": len(claims),
        "claims": claims,
        "pure_layer_runtime_verified": False,
        "fresh_runtime_recheck_required": True,
    }
    return _with_self_digest(unsigned, digest_key="absence_claims_sha256")


def _validate_absence_claims_object(
    value: object, *, plan: dict[str, Any]
) -> dict[str, Any]:
    obj = _exact_keys(value, _ABSENCE_KEYS, "absence claims")
    if obj["protocol"] != ABSENCE_CLAIMS_PROTOCOL:
        raise StructuredStageAuthorizationError("absence-claim protocol drift")
    _require_schema_version(obj["schema_version"], "absence claims.schema_version")
    if (
        obj["stage_kind"] != plan["stage_kind"]
        or obj["attempt_id"] != plan["attempt_id"]
    ):
        raise StructuredStageAuthorizationError("absence-claim stage/attempt mismatch")
    if obj["expected_path_inventory_sha256"] != plan["expected_path_inventory_sha256"]:
        raise StructuredStageAuthorizationError(
            "absence claims expected path inventory drift"
        )
    values = _exact_list(obj["claims"], "absence claims.claims")
    claim_count = _require_int(obj["claim_count"], "absence claims.claim_count")
    expected_outputs = _expected_pending_production_outputs(plan)
    if claim_count != len(values) or len(values) != len(expected_outputs):
        raise StructuredStageAuthorizationError("absence-claim count drift")
    attestation_digests: set[str] = set()
    for index, (value, expected) in enumerate(
        zip(values, expected_outputs, strict=True)
    ):
        claim = _exact_keys(value, _ABSENCE_CLAIM_KEYS, f"absence claims[{index}]")
        _require_exact_match(
            {key: claim[key] for key in ("claim_id", "path", "role")},
            expected,
            "absence-claim path/id/role",
        )
        _require_bool(
            claim["claimed_absent"], True, f"absence claims[{index}].claimed_absent"
        )
        attestation_digests.add(
            _require_sha(
                claim["adapter_attestation_sha256"],
                f"absence claims[{index}].adapter_attestation_sha256",
            )
        )
    if len(attestation_digests) != 1:
        raise StructuredStageAuthorizationError(
            "absence claims must share one adapter attestation"
        )
    _require_bool(
        obj["pure_layer_runtime_verified"], False, "pure_layer_runtime_verified"
    )
    _require_bool(
        obj["fresh_runtime_recheck_required"], True, "fresh_runtime_recheck_required"
    )
    _validate_self_digest(
        obj, _ABSENCE_UNSIGNED_KEYS, "absence_claims_sha256", "absence claims"
    )
    return obj


def build_prelaunch_process_claim_bytes(
    *,
    stage_plan_bytes: object,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    parent_transition_receipt_bytes: object,
    adapter_attestation_sha256: object,
) -> bytes:
    """Bind claimed lock/process facts; this pure helper performs no process check."""

    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    unsigned = {
        "protocol": PROCESS_CLAIM_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "stage_kind": plan["stage_kind"],
        "attempt_id": plan["attempt_id"],
        "lock_path": plan["paths"]["lock_path"],
        "pid_path": plan["paths"]["pid_path"],
        "exit_path": plan["paths"]["exit_path"],
        "claimed_exclusive_lock_held": True,
        "claimed_no_live_stage_process": True,
        "adapter_attestation_sha256": _require_sha(
            adapter_attestation_sha256, "adapter_attestation_sha256"
        ),
        "pure_layer_runtime_verified": False,
        "fresh_runtime_recheck_required": True,
    }
    return _with_self_digest(unsigned, digest_key="process_claim_sha256")


def _validate_process_claim_object(
    value: object, *, plan: dict[str, Any]
) -> dict[str, Any]:
    obj = _exact_keys(value, _PROCESS_KEYS, "process claim")
    if obj["protocol"] != PROCESS_CLAIM_PROTOCOL:
        raise StructuredStageAuthorizationError("process-claim protocol drift")
    _require_schema_version(obj["schema_version"], "process claim.schema_version")
    if (
        obj["stage_kind"] != plan["stage_kind"]
        or obj["attempt_id"] != plan["attempt_id"]
    ):
        raise StructuredStageAuthorizationError("process-claim stage/attempt mismatch")
    for key, plan_key in (
        ("lock_path", "lock_path"),
        ("pid_path", "pid_path"),
        ("exit_path", "exit_path"),
    ):
        if obj[key] != plan["paths"][plan_key]:
            raise StructuredStageAuthorizationError(f"process-claim {key} drift")
    _require_bool(
        obj["claimed_exclusive_lock_held"], True, "claimed_exclusive_lock_held"
    )
    _require_bool(
        obj["claimed_no_live_stage_process"], True, "claimed_no_live_stage_process"
    )
    _require_sha(obj["adapter_attestation_sha256"], "adapter_attestation_sha256")
    _require_bool(
        obj["pure_layer_runtime_verified"], False, "pure_layer_runtime_verified"
    )
    _require_bool(
        obj["fresh_runtime_recheck_required"], True, "fresh_runtime_recheck_required"
    )
    _validate_self_digest(
        obj, _PROCESS_UNSIGNED_KEYS, "process_claim_sha256", "process claim"
    )
    return obj


def _expected_comparator_contract() -> dict[str, object]:
    return {
        "canonical_online_icl_required": True,
        "canonical_online_join_must_be_true": True,
        "canonical_adaptation_precommit_per_item": 1,
        "canonical_heldout_precommit_per_item": 1,
        "canonical_adaptation_official_receipt_per_item": 1,
        "canonical_heldout_official_receipt_per_item": 1,
    }


def _expected_artifact_inventory(stage: StageKind) -> dict[str, int]:
    accounting = _expected_accounting(stage)
    return {
        "logical_arm_cells": accounting["logical_arm_cell_count"],
        "corpora": accounting["corpus_count"],
        "public_context_attestations": accounting["public_context_count"],
        "precommit_bundles": accounting["precommit_bundle_count"],
        "candidate_scalar_receipts": accounting["candidate_scorer_call_count"],
        "official_scalar_receipts": accounting["official_scorer_call_count"],
        "total_scalar_receipts": accounting["total_scorer_receipt_count"],
        "initial_raw_traces": accounting["initial_model_generation_count"],
        "stage_reports": 1,
        "sealed_inventories": 1,
        "completion_markers": 1,
    }


def _dgp_integrity_payload(
    *, current_manifest_bytes: bytes, prior_manifest_bytes: tuple[bytes, ...]
) -> tuple[dict[str, object], str]:
    record = validate_stage_integrity(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
    )
    current_manifest = load_stage_manifest(current_manifest_bytes)
    generator_digests = {
        corpus.dgp_generator_sha256 for corpus in current_manifest.corpora
    }
    if len(generator_digests) != 1:
        raise StructuredStageAuthorizationError("DGP generator digest ambiguity")
    payload = {
        "stage_manifest_sha256": record.stage_manifest_sha256,
        "current_manifest_file_sha256": _sha(current_manifest_bytes),
        "prior_manifest_file_sha256s": [_sha(raw) for raw in prior_manifest_bytes],
        "block_count": record.block_count,
        "corpus_count": record.corpus_count,
        "row_count": record.row_count,
        "public_context_count": record.public_context_count,
        "prereg_seed_table_validated": record.prereg_seed_table_validated,
        "public_context_identities_recomputed": (
            record.public_context_identities_recomputed
        ),
        "hidden_registry_digest_metadata_bound": (
            record.hidden_registry_digest_metadata_bound
        ),
        "hidden_registry_contents_validated": (
            record.hidden_registry_contents_validated
        ),
        "scorer_reexecution_performed": record.scorer_reexecution_performed,
    }
    return payload, next(iter(generator_digests))


def build_dgp_generation_claim_bytes(
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    parent_transition_receipt_bytes: object,
    adapter_attestation_sha256: object,
) -> bytes:
    """Bind an impure adapter's O_EXCL DGP-claim assertion without doing I/O."""

    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    protocol_plan, _, _ = _load_protocol_plan_seal_object(
        protocol_plan_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
    )
    unsigned = {
        "protocol": DGP_GENERATION_CLAIM_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "stage_kind": plan["stage_kind"],
        "attempt_id": plan["attempt_id"],
        "dgp_generator_source_sha256": protocol_plan["dgp_binding"][
            "dgp_generator_source_sha256"
        ],
        "expected_path_inventory_sha256": plan["expected_path_inventory_sha256"],
        "dgp_manifest_path": plan["paths"]["dgp_manifest_path"],
        "claim_path": plan["paths"]["dgp_generation_claim_path"],
        "adapter_attestation_sha256": _require_sha(
            adapter_attestation_sha256, "adapter_attestation_sha256"
        ),
        "adapter_claimed_o_excl_created": True,
        "pure_layer_runtime_verified": False,
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    return _with_self_digest(unsigned, digest_key="dgp_generation_claim_sha256")


def _load_dgp_generation_claim_object(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    parent_transition_receipt_bytes: object,
) -> dict[str, Any]:
    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    protocol_plan, _, _ = _load_protocol_plan_seal_object(
        protocol_plan_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
    )
    obj = _exact_keys(
        _parse_canonical_object(raw, "dgp_generation_claim_bytes"),
        _DGP_GENERATION_CLAIM_KEYS,
        "DGP generation claim",
    )
    if obj["protocol"] != DGP_GENERATION_CLAIM_PROTOCOL:
        raise StructuredStageAuthorizationError("DGP generation claim drift")
    _require_schema_version(
        obj["schema_version"], "DGP generation claim.schema_version"
    )
    expected_edges = {
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
    }
    for key, expected in expected_edges.items():
        if obj[key] != expected:
            raise StructuredStageAuthorizationError(
                f"DGP generation claim full-byte edge substitution: {key}"
            )
    if (
        obj["stage_kind"] != plan["stage_kind"]
        or obj["attempt_id"] != plan["attempt_id"]
    ):
        raise StructuredStageAuthorizationError("DGP claim stage/attempt mismatch")
    if (
        obj["dgp_generator_source_sha256"]
        != protocol_plan["dgp_binding"]["dgp_generator_source_sha256"]
    ):
        raise StructuredStageAuthorizationError("DGP claim generator source drift")
    if obj["expected_path_inventory_sha256"] != plan["expected_path_inventory_sha256"]:
        raise StructuredStageAuthorizationError("DGP claim output inventory drift")
    if (
        obj["dgp_manifest_path"] != plan["paths"]["dgp_manifest_path"]
        or obj["claim_path"] != plan["paths"]["dgp_generation_claim_path"]
    ):
        raise StructuredStageAuthorizationError("DGP claim path drift")
    _require_sha(obj["adapter_attestation_sha256"], "adapter_attestation_sha256")
    _require_bool(
        obj["adapter_claimed_o_excl_created"],
        True,
        "adapter_claimed_o_excl_created",
    )
    _require_bool(
        obj["pure_layer_runtime_verified"], False, "pure_layer_runtime_verified"
    )
    _require_bool(obj["model_calls_authorized"], False, "model_calls_authorized")
    _require_bool(obj["operational_authorization"], False, "operational_authorization")
    _validate_self_digest(
        obj,
        _DGP_GENERATION_CLAIM_UNSIGNED_KEYS,
        "dgp_generation_claim_sha256",
        "DGP generation claim",
    )
    return obj


def build_dgp_completion_receipt_bytes(
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    parent_transition_receipt_bytes: object,
    dgp_generation_claim_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
    adapter_attestation_sha256: object,
) -> bytes:
    """Bind the exact generated DGP/context bytes and adapter completion claim."""

    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    _load_dgp_generation_claim_object(
        dgp_generation_claim_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    if type(current_manifest_bytes) is not bytes:
        raise StructuredStageAuthorizationError(
            "current_manifest_bytes must be exact canonical bytes"
        )
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    dgp_integrity, _ = _dgp_integrity_payload(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_raws,
    )
    manifest = load_stage_manifest(current_manifest_bytes)
    if manifest.stage_kind.value != plan["stage_kind"]:
        raise StructuredStageAuthorizationError("DGP completion stage mismatch")
    context = manifest.context_attestation_inventory
    unsigned = {
        "protocol": DGP_COMPLETION_RECEIPT_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "stage_kind": plan["stage_kind"],
        "attempt_id": plan["attempt_id"],
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "dgp_generation_claim_file_sha256": _sha(dgp_generation_claim_bytes),
        "current_manifest_file_sha256": _sha(current_manifest_bytes),
        "prior_manifest_file_sha256s": [_sha(raw) for raw in prior_raws],
        "stage_manifest_sha256": dgp_integrity["stage_manifest_sha256"],
        "context_inventory_sha256": context.context_inventory_sha256,
        "hidden_registry_inventory_sha256": context.hidden_registry_inventory_sha256,
        "attestation_inventory_sha256": context.attestation_inventory_sha256,
        "status": "complete",
        "adapter_attestation_sha256": _require_sha(
            adapter_attestation_sha256, "adapter_attestation_sha256"
        ),
        "pure_layer_runtime_verified": False,
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    return _with_self_digest(unsigned, digest_key="dgp_completion_receipt_sha256")


def _load_dgp_completion_receipt_object(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    parent_transition_receipt_bytes: object,
    dgp_generation_claim_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
) -> dict[str, Any]:
    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    _load_dgp_generation_claim_object(
        dgp_generation_claim_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    if type(current_manifest_bytes) is not bytes:
        raise StructuredStageAuthorizationError(
            "current_manifest_bytes must be exact canonical bytes"
        )
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    dgp_integrity, _ = _dgp_integrity_payload(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_raws,
    )
    manifest = load_stage_manifest(current_manifest_bytes)
    context = manifest.context_attestation_inventory
    obj = _exact_keys(
        _parse_canonical_object(raw, "dgp_completion_receipt_bytes"),
        _DGP_COMPLETION_RECEIPT_KEYS,
        "DGP completion receipt",
    )
    _require_schema_version(
        obj["schema_version"], "DGP completion receipt.schema_version"
    )
    expected = {
        "protocol": DGP_COMPLETION_RECEIPT_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "stage_kind": plan["stage_kind"],
        "attempt_id": plan["attempt_id"],
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "dgp_generation_claim_file_sha256": _sha(dgp_generation_claim_bytes),
        "current_manifest_file_sha256": _sha(current_manifest_bytes),
        "prior_manifest_file_sha256s": [_sha(item) for item in prior_raws],
        "stage_manifest_sha256": dgp_integrity["stage_manifest_sha256"],
        "context_inventory_sha256": context.context_inventory_sha256,
        "hidden_registry_inventory_sha256": context.hidden_registry_inventory_sha256,
        "attestation_inventory_sha256": context.attestation_inventory_sha256,
        "status": "complete",
        "adapter_attestation_sha256": obj["adapter_attestation_sha256"],
        "pure_layer_runtime_verified": False,
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    _require_sha(obj["adapter_attestation_sha256"], "adapter_attestation_sha256")
    _require_exact_match(
        {key: obj[key] for key in _DGP_COMPLETION_RECEIPT_UNSIGNED_KEYS},
        expected,
        "DGP completion receipt binding",
    )
    _validate_self_digest(
        obj,
        _DGP_COMPLETION_RECEIPT_UNSIGNED_KEYS,
        "dgp_completion_receipt_sha256",
        "DGP completion receipt",
    )
    return obj


def build_structured_stage_protocol_seal_bytes(
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    parent_transition_receipt_bytes: object,
    dgp_generation_claim_bytes: object,
    dgp_completion_receipt_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
) -> bytes:
    """Seal one completed stage DGP/context inventory before launch planning.

    This is distinct from the pre-DGP protocol-plan seal.  It is the first
    artifact that binds the actual current/prior DGP manifest byte strings and
    public context-attestation inventory for one concrete stage attempt.
    """

    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    protocol_plan, _, _ = _load_protocol_plan_seal_object(
        protocol_plan_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
    )
    _load_dgp_generation_claim_object(
        dgp_generation_claim_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    _load_dgp_completion_receipt_object(
        dgp_completion_receipt_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
        dgp_generation_claim_bytes=dgp_generation_claim_bytes,
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
    )
    if type(current_manifest_bytes) is not bytes:
        raise StructuredStageAuthorizationError(
            "current_manifest_bytes must be exact canonical bytes"
        )
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    dgp_integrity, generator = _dgp_integrity_payload(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_raws,
    )
    stage = StageKind(plan["stage_kind"])
    manifest = load_stage_manifest(current_manifest_bytes)
    if manifest.stage_kind is not stage:
        raise StructuredStageAuthorizationError(
            "stage plan/DGP manifest stage mismatch"
        )
    if generator != protocol_plan["dgp_binding"]["dgp_generator_source_sha256"]:
        raise StructuredStageAuthorizationError(
            "DGP manifest generator differs from protocol-plan seal"
        )
    context = manifest.context_attestation_inventory
    unsigned = {
        "protocol": STRUCTURED_STAGE_PROTOCOL_SEAL_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "dgp_generation_claim_file_sha256": _sha(dgp_generation_claim_bytes),
        "dgp_completion_receipt_file_sha256": _sha(dgp_completion_receipt_bytes),
        "stage_kind": stage.value,
        "attempt_id": plan["attempt_id"],
        "dgp_integrity": dgp_integrity,
        "dgp_generator_source_sha256": generator,
        "context_inventory_sha256": context.context_inventory_sha256,
        "hidden_registry_inventory_sha256": context.hidden_registry_inventory_sha256,
        "attestation_inventory_sha256": context.attestation_inventory_sha256,
        "dgp_manifest_path": plan["paths"]["dgp_manifest_path"],
        "model_calls_authorized": False,
        "operational_authorization": False,
    }
    return _with_self_digest(
        unsigned, digest_key="structured_stage_protocol_seal_sha256"
    )


def _load_structured_stage_protocol_seal_object(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    parent_transition_receipt_bytes: object,
    dgp_generation_claim_bytes: object,
    dgp_completion_receipt_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
) -> dict[str, Any]:
    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    protocol_plan, _, _ = _load_protocol_plan_seal_object(
        protocol_plan_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
    )
    _load_dgp_generation_claim_object(
        dgp_generation_claim_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    _load_dgp_completion_receipt_object(
        dgp_completion_receipt_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
        dgp_generation_claim_bytes=dgp_generation_claim_bytes,
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
    )
    if type(current_manifest_bytes) is not bytes:
        raise StructuredStageAuthorizationError(
            "current_manifest_bytes must be exact canonical bytes"
        )
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    obj = _exact_keys(
        _parse_canonical_object(raw, "structured_stage_protocol_seal_bytes"),
        _STAGE_PROTOCOL_SEAL_KEYS,
        "structured stage protocol seal",
    )
    if obj["protocol"] != STRUCTURED_STAGE_PROTOCOL_SEAL_PROTOCOL:
        raise StructuredStageAuthorizationError("structured stage protocol seal drift")
    _require_schema_version(
        obj["schema_version"], "structured stage protocol seal.schema_version"
    )
    expected_edges = {
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "dgp_generation_claim_file_sha256": _sha(dgp_generation_claim_bytes),
        "dgp_completion_receipt_file_sha256": _sha(dgp_completion_receipt_bytes),
    }
    for key, expected in expected_edges.items():
        if obj[key] != expected:
            raise StructuredStageAuthorizationError(
                f"stage protocol seal full-byte edge substitution: {key}"
            )
    stage = StageKind(plan["stage_kind"])
    if obj["stage_kind"] != stage.value or obj["attempt_id"] != plan["attempt_id"]:
        raise StructuredStageAuthorizationError(
            "stage protocol seal stage/attempt mismatch"
        )
    _validate_dgp_integrity_payload(
        obj["dgp_integrity"],
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_raws,
        expected_stage=stage,
        expected_generator_sha256=protocol_plan["dgp_binding"][
            "dgp_generator_source_sha256"
        ],
    )
    manifest = load_stage_manifest(current_manifest_bytes)
    context = manifest.context_attestation_inventory
    expected_context = {
        "context_inventory_sha256": context.context_inventory_sha256,
        "hidden_registry_inventory_sha256": context.hidden_registry_inventory_sha256,
        "attestation_inventory_sha256": context.attestation_inventory_sha256,
    }
    for key, expected in expected_context.items():
        if obj[key] != expected:
            raise StructuredStageAuthorizationError(
                f"stage protocol seal context binding drift: {key}"
            )
    if (
        obj["dgp_generator_source_sha256"]
        != protocol_plan["dgp_binding"]["dgp_generator_source_sha256"]
    ):
        raise StructuredStageAuthorizationError("stage protocol seal DGP source drift")
    if obj["dgp_manifest_path"] != plan["paths"]["dgp_manifest_path"]:
        raise StructuredStageAuthorizationError("stage protocol seal DGP path drift")
    _require_bool(obj["model_calls_authorized"], False, "model_calls_authorized")
    _require_bool(obj["operational_authorization"], False, "operational_authorization")
    _validate_self_digest(
        obj,
        _STAGE_PROTOCOL_SEAL_UNSIGNED_KEYS,
        "structured_stage_protocol_seal_sha256",
        "structured stage protocol seal",
    )
    return obj


def validate_structured_stage_protocol_seal_bytes(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    parent_transition_receipt_bytes: object,
    dgp_generation_claim_bytes: object,
    dgp_completion_receipt_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
) -> StageProtocolSealValidation:
    """Validate the post-DGP stage seal from raw current/prior manifests."""

    obj = _load_structured_stage_protocol_seal_object(
        raw,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
        dgp_generation_claim_bytes=dgp_generation_claim_bytes,
        dgp_completion_receipt_bytes=dgp_completion_receipt_bytes,
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
    )
    dgp_integrity = obj["dgp_integrity"]
    return StageProtocolSealValidation(
        stage_kind=StageKind(obj["stage_kind"]),
        attempt_id=obj["attempt_id"],
        structured_stage_protocol_seal_sha256=obj[
            "structured_stage_protocol_seal_sha256"
        ],
        current_manifest_file_sha256=dgp_integrity["current_manifest_file_sha256"],
        prior_manifest_file_sha256s=tuple(dgp_integrity["prior_manifest_file_sha256s"]),
        context_inventory_sha256=obj["context_inventory_sha256"],
        model_calls_authorized=False,
    )


def _validate_dgp_integrity_payload(
    value: object,
    *,
    current_manifest_bytes: bytes,
    prior_manifest_bytes: tuple[bytes, ...],
    expected_stage: StageKind,
    expected_generator_sha256: str,
) -> dict[str, Any]:
    obj = _exact_keys(value, _DGP_INTEGRITY_KEYS, "dgp_integrity")
    expected, generator = _dgp_integrity_payload(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
    )
    if generator != expected_generator_sha256:
        raise StructuredStageAuthorizationError(
            "DGP manifest generator differs from sealed source"
        )
    manifest = load_stage_manifest(current_manifest_bytes)
    if manifest.stage_kind is not expected_stage:
        raise StructuredStageAuthorizationError(
            "DGP manifest stage escalation/substitution"
        )
    _require_exact_match(obj, expected, "DGP integrity receipt")
    return obj


def build_launch_expectation_bytes(
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    structured_stage_protocol_seal_bytes: object,
    dgp_generation_claim_bytes: object,
    dgp_completion_receipt_bytes: object,
    parent_transition_receipt_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
    absence_claims_bytes: object,
    process_claim_bytes: object,
) -> bytes:
    """Bind the exact DGP chain and claimed prelaunch state; authorize no calls."""

    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    seal, _, _ = _load_protocol_plan_seal_object(
        protocol_plan_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
    )
    stage_seal = _load_structured_stage_protocol_seal_object(
        structured_stage_protocol_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
        dgp_generation_claim_bytes=dgp_generation_claim_bytes,
        dgp_completion_receipt_bytes=dgp_completion_receipt_bytes,
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
    )
    if type(current_manifest_bytes) is not bytes:
        raise StructuredStageAuthorizationError(
            "current_manifest_bytes must be exact canonical bytes"
        )
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    dgp_integrity, generator = _dgp_integrity_payload(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_raws,
    )
    stage = StageKind(plan["stage_kind"])
    manifest = load_stage_manifest(current_manifest_bytes)
    if manifest.stage_kind is not stage:
        raise StructuredStageAuthorizationError(
            "stage plan/DGP manifest stage mismatch"
        )
    if generator != seal["dgp_binding"]["dgp_generator_source_sha256"]:
        raise StructuredStageAuthorizationError(
            "DGP manifest generator differs from protocol-plan seal"
        )
    absence = _validate_absence_claims_object(
        _parse_canonical_object(absence_claims_bytes, "absence_claims_bytes"),
        plan=plan,
    )
    process = _validate_process_claim_object(
        _parse_canonical_object(process_claim_bytes, "process_claim_bytes"),
        plan=plan,
    )
    unsigned = {
        "protocol": LAUNCH_EXPECTATION_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "structured_stage_protocol_seal_file_sha256": _sha(
            structured_stage_protocol_seal_bytes
        ),
        "dgp_generation_claim_file_sha256": _sha(dgp_generation_claim_bytes),
        "dgp_completion_receipt_file_sha256": _sha(dgp_completion_receipt_bytes),
        "stage_kind": stage.value,
        "attempt_id": plan["attempt_id"],
        "dgp_integrity": dgp_integrity,
        "dgp_generator_source_sha256": generator,
        "canonical_comparator_contract": _expected_comparator_contract(),
        "expected_artifact_inventory": _expected_artifact_inventory(stage),
        "absence_claims": absence,
        "absence_claims_file_sha256": _sha(absence_claims_bytes),
        "process_claim": process,
        "process_claim_file_sha256": _sha(process_claim_bytes),
        "model_calls_authorized": False,
        "operational_authorization": False,
        "future_runtime_adapter_required": True,
    }
    if not _exact_type_equal(stage_seal["dgp_integrity"], dgp_integrity):
        raise StructuredStageAuthorizationError(
            "launch expectation DGP differs from the stage protocol seal"
        )
    return _with_self_digest(unsigned, digest_key="launch_expectation_sha256")


def _load_launch_expectation_object(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    structured_stage_protocol_seal_bytes: object,
    dgp_generation_claim_bytes: object,
    dgp_completion_receipt_bytes: object,
    parent_transition_receipt_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
    absence_claims_bytes: object,
    process_claim_bytes: object,
) -> dict[str, Any]:
    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    seal, _, _ = _load_protocol_plan_seal_object(
        protocol_plan_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
    )
    stage_seal = _load_structured_stage_protocol_seal_object(
        structured_stage_protocol_seal_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
        dgp_generation_claim_bytes=dgp_generation_claim_bytes,
        dgp_completion_receipt_bytes=dgp_completion_receipt_bytes,
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
    )
    if type(current_manifest_bytes) is not bytes:
        raise StructuredStageAuthorizationError(
            "current_manifest_bytes must be exact canonical bytes"
        )
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    obj = _exact_keys(
        _parse_canonical_object(raw, "launch_expectation_bytes"),
        _EXPECTATION_KEYS,
        "launch expectation",
    )
    if obj["protocol"] != LAUNCH_EXPECTATION_PROTOCOL:
        raise StructuredStageAuthorizationError("launch expectation protocol drift")
    _require_schema_version(obj["schema_version"], "launch expectation.schema_version")
    expected_edges = {
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "structured_stage_protocol_seal_file_sha256": _sha(
            structured_stage_protocol_seal_bytes
        ),
        "dgp_generation_claim_file_sha256": _sha(dgp_generation_claim_bytes),
        "dgp_completion_receipt_file_sha256": _sha(dgp_completion_receipt_bytes),
    }
    for key, expected in expected_edges.items():
        if obj[key] != expected:
            raise StructuredStageAuthorizationError(
                f"launch expectation full-byte edge substitution: {key}"
            )
    stage = StageKind(plan["stage_kind"])
    if obj["stage_kind"] != stage.value or obj["attempt_id"] != plan["attempt_id"]:
        raise StructuredStageAuthorizationError(
            "launch expectation stage/attempt mismatch"
        )
    _validate_dgp_integrity_payload(
        obj["dgp_integrity"],
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_raws,
        expected_stage=stage,
        expected_generator_sha256=seal["dgp_binding"]["dgp_generator_source_sha256"],
    )
    if not _exact_type_equal(obj["dgp_integrity"], stage_seal["dgp_integrity"]):
        raise StructuredStageAuthorizationError(
            "launch expectation does not bind the stage protocol DGP receipt"
        )
    if (
        obj["dgp_generator_source_sha256"]
        != seal["dgp_binding"]["dgp_generator_source_sha256"]
    ):
        raise StructuredStageAuthorizationError("launch expectation DGP source drift")
    comparator = _exact_keys(
        obj["canonical_comparator_contract"],
        _COMPARATOR_KEYS,
        "canonical comparator contract",
    )
    if not _exact_type_equal(comparator, _expected_comparator_contract()):
        raise StructuredStageAuthorizationError(
            "canonical online comparator is missing or weakened"
        )
    inventory = _exact_keys(
        obj["expected_artifact_inventory"],
        _EXPECTED_ARTIFACT_KEYS,
        "expected artifact inventory",
    )
    if not _exact_type_equal(inventory, _expected_artifact_inventory(stage)):
        raise StructuredStageAuthorizationError("expected artifact count drift")
    absence = _validate_absence_claims_object(
        _parse_canonical_object(absence_claims_bytes, "absence_claims_bytes"),
        plan=plan,
    )
    if not _exact_type_equal(obj["absence_claims"], absence) or obj[
        "absence_claims_file_sha256"
    ] != _sha(absence_claims_bytes):
        raise StructuredStageAuthorizationError("absence-claim byte substitution")
    process = _validate_process_claim_object(
        _parse_canonical_object(process_claim_bytes, "process_claim_bytes"),
        plan=plan,
    )
    if not _exact_type_equal(obj["process_claim"], process) or obj[
        "process_claim_file_sha256"
    ] != _sha(process_claim_bytes):
        raise StructuredStageAuthorizationError("process-claim byte substitution")
    _require_bool(obj["model_calls_authorized"], False, "model_calls_authorized")
    _require_bool(obj["operational_authorization"], False, "operational_authorization")
    _require_bool(
        obj["future_runtime_adapter_required"], True, "future_runtime_adapter_required"
    )
    _validate_self_digest(
        obj,
        _EXPECTATION_UNSIGNED_KEYS,
        "launch_expectation_sha256",
        "launch expectation",
    )
    return obj


def validate_launch_expectation_bytes(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    structured_stage_protocol_seal_bytes: object,
    dgp_generation_claim_bytes: object,
    dgp_completion_receipt_bytes: object,
    parent_transition_receipt_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
    absence_claims_bytes: object,
    process_claim_bytes: object,
) -> LaunchExpectationValidation:
    """Validate expectation bytes and re-run DGP integrity on raw manifests."""

    obj = _load_launch_expectation_object(
        raw,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        structured_stage_protocol_seal_bytes=structured_stage_protocol_seal_bytes,
        dgp_generation_claim_bytes=dgp_generation_claim_bytes,
        dgp_completion_receipt_bytes=dgp_completion_receipt_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
        absence_claims_bytes=absence_claims_bytes,
        process_claim_bytes=process_claim_bytes,
    )
    dgp = obj["dgp_integrity"]
    return LaunchExpectationValidation(
        stage_kind=StageKind(obj["stage_kind"]),
        attempt_id=obj["attempt_id"],
        launch_expectation_sha256=obj["launch_expectation_sha256"],
        structured_stage_protocol_seal_file_sha256=obj[
            "structured_stage_protocol_seal_file_sha256"
        ],
        current_manifest_file_sha256=dgp["current_manifest_file_sha256"],
        prior_manifest_file_sha256s=tuple(dgp["prior_manifest_file_sha256s"]),
        canonical_online_icl_required=True,
        filesystem_claims_runtime_verified=False,
        process_claim_runtime_verified=False,
        model_calls_authorized=False,
    )


def _claim_requirements() -> dict[str, bool]:
    return {
        "fresh_filesystem_recheck_required": True,
        "fresh_process_recheck_required": True,
        "exclusive_lock_required": True,
        "o_excl_claim_creation_required": True,
        "claim_must_precede_model_or_scorer_import": True,
        "claim_verified_by_pure_layer": False,
    }


def build_prelaunch_gate_bytes(
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    structured_stage_protocol_seal_bytes: object,
    dgp_generation_claim_bytes: object,
    dgp_completion_receipt_bytes: object,
    parent_transition_receipt_bytes: object,
    launch_expectation_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
    absence_claims_bytes: object,
    process_claim_bytes: object,
) -> bytes:
    """Build claim eligibility only; never operational model/scorer permission."""

    expectation = _load_launch_expectation_object(
        launch_expectation_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        structured_stage_protocol_seal_bytes=structured_stage_protocol_seal_bytes,
        dgp_generation_claim_bytes=dgp_generation_claim_bytes,
        dgp_completion_receipt_bytes=dgp_completion_receipt_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
        absence_claims_bytes=absence_claims_bytes,
        process_claim_bytes=process_claim_bytes,
    )
    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    # Required second independent invocation at the final pure gate.
    _dgp_integrity_payload(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_raws,
    )
    unsigned = {
        "protocol": PRELAUNCH_GATE_PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "structured_stage_protocol_seal_file_sha256": _sha(
            structured_stage_protocol_seal_bytes
        ),
        "dgp_generation_claim_file_sha256": _sha(dgp_generation_claim_bytes),
        "dgp_completion_receipt_file_sha256": _sha(dgp_completion_receipt_bytes),
        "launch_expectation_file_sha256": _sha(launch_expectation_bytes),
        "stage_kind": plan["stage_kind"],
        "attempt_id": plan["attempt_id"],
        "status": "validated",
        "authorization_scope": PRELAUNCH_ELIGIBILITY_SCOPE,
        "single_use": True,
        "launch_claim_path": plan["paths"]["launch_claim_path"],
        "launch_claim_expected_absent": True,
        "claim_requirements": _claim_requirements(),
        "dgp_current_manifest_file_sha256": expectation["dgp_integrity"][
            "current_manifest_file_sha256"
        ],
        "dgp_prior_manifest_file_sha256s": expectation["dgp_integrity"][
            "prior_manifest_file_sha256s"
        ],
        "model_calls_authorized": False,
        "operational_authorization": False,
        "future_runtime_adapter_required": True,
    }
    return _with_self_digest(unsigned, digest_key="prelaunch_gate_sha256")


def validate_prelaunch_gate_bytes(
    raw: object,
    *,
    trigger_receipt_bytes: object,
    protocol_plan_seal_bytes: object,
    stage_plan_bytes: object,
    structured_stage_protocol_seal_bytes: object,
    dgp_generation_claim_bytes: object,
    dgp_completion_receipt_bytes: object,
    parent_transition_receipt_bytes: object,
    launch_expectation_bytes: object,
    current_manifest_bytes: object,
    prior_manifest_bytes: object,
    absence_claims_bytes: object,
    process_claim_bytes: object,
) -> PrelaunchEligibilityValidation:
    """Validate the entire chain and return non-operational claim eligibility."""

    expectation = _load_launch_expectation_object(
        launch_expectation_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        stage_plan_bytes=stage_plan_bytes,
        structured_stage_protocol_seal_bytes=structured_stage_protocol_seal_bytes,
        dgp_generation_claim_bytes=dgp_generation_claim_bytes,
        dgp_completion_receipt_bytes=dgp_completion_receipt_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_manifest_bytes,
        absence_claims_bytes=absence_claims_bytes,
        process_claim_bytes=process_claim_bytes,
    )
    plan = _load_stage_plan_object(
        stage_plan_bytes,
        trigger_receipt_bytes=trigger_receipt_bytes,
        protocol_plan_seal_bytes=protocol_plan_seal_bytes,
        parent_transition_receipt_bytes=parent_transition_receipt_bytes,
    )
    if type(current_manifest_bytes) is not bytes:
        raise StructuredStageAuthorizationError(
            "current_manifest_bytes must be exact canonical bytes"
        )
    prior_raws = _exact_bytes_tuple(prior_manifest_bytes, "prior_manifest_bytes")
    # Do not trust the expectation's summary; re-run the raw-manifest validator.
    dgp_payload, _ = _dgp_integrity_payload(
        current_manifest_bytes=current_manifest_bytes,
        prior_manifest_bytes=prior_raws,
    )
    if not _exact_type_equal(dgp_payload, expectation["dgp_integrity"]):
        raise StructuredStageAuthorizationError("prelaunch DGP revalidation drift")
    obj = _exact_keys(
        _parse_canonical_object(raw, "prelaunch_gate_bytes"),
        _GATE_KEYS,
        "prelaunch gate",
    )
    if obj["protocol"] != PRELAUNCH_GATE_PROTOCOL:
        raise StructuredStageAuthorizationError("prelaunch gate protocol drift")
    _require_schema_version(obj["schema_version"], "prelaunch gate.schema_version")
    expected_edges = {
        "trigger_receipt_file_sha256": _sha(trigger_receipt_bytes),
        "protocol_plan_seal_file_sha256": _sha(protocol_plan_seal_bytes),
        "stage_plan_file_sha256": _sha(stage_plan_bytes),
        "structured_stage_protocol_seal_file_sha256": _sha(
            structured_stage_protocol_seal_bytes
        ),
        "dgp_generation_claim_file_sha256": _sha(dgp_generation_claim_bytes),
        "dgp_completion_receipt_file_sha256": _sha(dgp_completion_receipt_bytes),
        "launch_expectation_file_sha256": _sha(launch_expectation_bytes),
    }
    for key, expected in expected_edges.items():
        if obj[key] != expected:
            raise StructuredStageAuthorizationError(
                f"prelaunch gate full-byte edge substitution: {key}"
            )
    if (
        obj["stage_kind"] != plan["stage_kind"]
        or obj["attempt_id"] != plan["attempt_id"]
    ):
        raise StructuredStageAuthorizationError("prelaunch gate stage/attempt mismatch")
    if (
        obj["status"] != "validated"
        or obj["authorization_scope"] != PRELAUNCH_ELIGIBILITY_SCOPE
    ):
        raise StructuredStageAuthorizationError(
            "prelaunch eligibility status/scope drift"
        )
    _require_bool(obj["single_use"], True, "single_use")
    if obj["launch_claim_path"] != plan["paths"]["launch_claim_path"]:
        raise StructuredStageAuthorizationError("prelaunch launch-claim path drift")
    _require_bool(
        obj["launch_claim_expected_absent"], True, "launch_claim_expected_absent"
    )
    requirements = _exact_keys(
        obj["claim_requirements"], _CLAIM_REQUIREMENT_KEYS, "claim_requirements"
    )
    if not _exact_type_equal(requirements, _claim_requirements()):
        raise StructuredStageAuthorizationError("launch-claim requirements weakened")
    if obj["dgp_current_manifest_file_sha256"] != _sha(current_manifest_bytes):
        raise StructuredStageAuthorizationError("prelaunch current DGP substitution")
    if obj["dgp_prior_manifest_file_sha256s"] != [_sha(raw) for raw in prior_raws]:
        raise StructuredStageAuthorizationError("prelaunch prior DGP substitution")
    _require_bool(obj["model_calls_authorized"], False, "model_calls_authorized")
    _require_bool(obj["operational_authorization"], False, "operational_authorization")
    _require_bool(
        obj["future_runtime_adapter_required"], True, "future_runtime_adapter_required"
    )
    digest = _validate_self_digest(
        obj, _GATE_UNSIGNED_KEYS, "prelaunch_gate_sha256", "prelaunch gate"
    )
    return PrelaunchEligibilityValidation(
        stage_kind=StageKind(obj["stage_kind"]),
        attempt_id=obj["attempt_id"],
        prelaunch_gate_sha256=digest,
        status="validated",
        authorization_scope=PRELAUNCH_ELIGIBILITY_SCOPE,
        single_use=True,
        eligible_for_one_registered_stage_launch_claim=True,
        model_calls_authorized=False,
        operational_authorization=False,
        future_runtime_adapter_required=True,
    )
