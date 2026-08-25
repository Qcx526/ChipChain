"""Closed Phase 10A benchmark configuration enums."""

from __future__ import annotations

from enum import Enum


class BenchmarkSourceKind(str, Enum):
    """Auditable, non-interchangeable benchmark source categories."""

    OWNED_SYNTHETIC = "owned_synthetic"
    PUBLIC_BENCHMARK = "public_benchmark"
    PUBLIC_DOCUMENTED = "public_documented"
    FIXTURE = "fixture"


class BenchmarkCaseLabel(str, Enum):
    """Ground Truth shape for one benchmark case."""

    POSITIVE_FEASIBLE = "positive_feasible"
    NEGATIVE_CONTROL = "negative_control"


class EvaluationScope(str, Enum):
    """Predeclared metric scope, fixed before candidate outcomes exist."""

    PRIMARY_TARGET = "primary_target"
    SECONDARY_ONLY = "secondary_only"
    EXCLUDED_UNSUPPORTED = "excluded_unsupported"


class ChainFeasibilityStatus(str, Enum):
    """Closed candidate-side objective feasibility outcomes."""

    CONFIRMED_FEASIBLE = "confirmed_feasible"
    NOT_SUPPORTED = "not_supported"
    UNRESOLVED = "unresolved"
    UNSUPPORTED = "unsupported"
    INFRA_FAILURE = "infra_failure"


class ChainFeasibilityReason(str, Enum):
    """Deterministic explanations for one oracle-derived outcome."""

    TYPE_II_OBJECTIVELY_TRIGGERABLE = "type_ii_objectively_triggerable"
    NO_STATIC_TRIGGER_MATCH = "no_static_trigger_match"
    RUNTIME_TRIGGER_NOT_OBSERVED = "runtime_trigger_not_observed"
    PRECONDITION_EVIDENCE_INSUFFICIENT = (
        "precondition_evidence_insufficient"
    )
    TRIGGERABILITY_RESULT_MISSING = "triggerability_result_missing"
    CANDIDATE_TYPED_INTERACTION_MISSING = (
        "candidate_typed_interaction_missing"
    )
    TYPE_I_SOFTWARE_VULNERABILITY_TO_TRIGGER_LINK_NOT_IMPLEMENTED = (
        "type_i_software_vulnerability_to_trigger_link_not_implemented"
    )
    TYPE_III_OBJECTIVE_PROPAGATION_NOT_IMPLEMENTED = (
        "type_iii_objective_propagation_not_implemented"
    )
    OBJECTIVE_INFRASTRUCTURE_FAILURE = "objective_infrastructure_failure"


class ObjectiveFailureStage(str, Enum):
    """Bounded objective stages that may explicitly report infrastructure failure."""

    STATIC_TRIGGER_MATCHING = "static_trigger_matching"
    RUNTIME_TRIGGER_EXECUTION = "runtime_trigger_execution"
    TRIGGERABILITY_AGGREGATION = "triggerability_aggregation"
    INTERACTION_VERIFICATION = "interaction_verification"
    OTHER_OBJECTIVE_INFRASTRUCTURE = "other_objective_infrastructure"


class ModelClaimBindingStatus(str, Enum):
    """Closed outcomes for model-claim/candidate-interaction comparison."""

    ALIGNED = "aligned"
    INCOMPLETE = "incomplete"
    MISMATCHED = "mismatched"
    UNBOUND = "unbound"
    MISSING = "missing"


class ModelClaimBindingReason(str, Enum):
    """Deterministic reasons for one model claim binding outcome."""

    CLAIM_ALIGNED = "claim_aligned"
    MODEL_AUTHORED_CLAIM_MISSING = "model_authored_claim_missing"
    CANDIDATE_TYPED_INTERACTION_MISSING = (
        "candidate_typed_interaction_missing"
    )
    CLAIM_REQUIRED_FIELDS_MISSING = "claim_required_fields_missing"
    CLAIM_TYPE_SHAPE_CONFLICT = "claim_type_shape_conflict"
    CLAIM_INTERACTION_TYPE_MISMATCH = "claim_interaction_type_mismatch"
    CLAIM_INITIATING_VULNERABILITY_MISMATCH = (
        "claim_initiating_vulnerability_mismatch"
    )
    CLAIM_TARGET_VULNERABILITY_MISMATCH = (
        "claim_target_vulnerability_mismatch"
    )
    CLAIM_TRIGGER_BEHAVIOR_MISMATCH = "claim_trigger_behavior_mismatch"
    CLAIM_AFFECTED_EXECUTION_MISMATCH = (
        "claim_affected_execution_mismatch"
    )
    CLAIM_OPTIONAL_REFERENCE_MISMATCH = "claim_optional_reference_mismatch"


class BenchmarkCaseRunDisposition(str, Enum):
    """Closed accounting outcome for exactly one manifest-case attempt."""

    CANDIDATE = "candidate"
    EXECUTION_FAILURE = "execution_failure"
    PREDECLARED_EXCLUDED = "predeclared_excluded"


class BenchmarkExecutionStage(str, Enum):
    """Bounded stages that may fail before candidate finalization."""

    REASONING_SESSION = "reasoning_session"
    CANDIDATE_FINALIZATION = "candidate_finalization"
    EVALUATION_INPUT_PREPARATION = "evaluation_input_preparation"


class BenchmarkExecutionFailureCode(str, Enum):
    """Stable pre-finalization failure categories without raw diagnostics."""

    PROVIDER_EXECUTION_FAILED = "provider_execution_failed"
    REASONING_CONTRACT_FAILED = "reasoning_contract_failed"
    CANDIDATE_FINALIZATION_FAILED = "candidate_finalization_failed"
    EVALUATION_INPUT_INVALID = "evaluation_input_invalid"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    OTHER_BOUNDED_EXECUTION_FAILURE = "other_bounded_execution_failure"


class EvaluationMetricName(str, Enum):
    """Closed deterministic Phase 10B benchmark metric names."""

    VERIFICATION_HIT_RATE = "verification_hit_rate"
    GROUND_TRUTH_CHAIN_RECALL = "ground_truth_chain_recall"
    NEGATIVE_CONTROL_FALSE_POSITIVE_RATE = (
        "negative_control_false_positive_rate"
    )
    PRIMARY_CASE_COVERAGE = "primary_case_coverage"


class AblationConditionKind(str, Enum):
    """Closed Phase 10C experimental conditions."""

    FULL_CONTEXT_MODEL = "full_context_model"
    MASKED_CHAIN_CONTEXT_MODEL = "masked_chain_context_model"
    NO_MODEL_BASELINE = "no_model_baseline"
    CONTEXT_OBJECTIVE_UPPER_BOUND = "context_objective_upper_bound"


class PromptVisibilityAuditStatus(str, Enum):
    """Exact-reference prompt leakage audit outcomes."""

    PASS = "pass"
    LEAK_DETECTED = "leak_detected"


class AblationConditionFailureStage(str, Enum):
    """Bounded condition-level execution failure stages."""

    PROVIDER = "provider"
    ORCHESTRATION = "orchestration"
    PROMPT_VISIBILITY = "prompt_visibility"
    REPORT_ASSEMBLY = "report_assembly"


class AblationConditionFailureCode(str, Enum):
    """Stable condition execution failure categories."""

    PROVIDER_UNAVAILABLE = "provider_unavailable"
    CONDITION_ORCHESTRATION_FAILED = "condition_orchestration_failed"
    PROMPT_VISIBILITY_CONSTRUCTION_FAILED = (
        "prompt_visibility_construction_failed"
    )
    REPORT_ASSEMBLY_FAILED = "report_assembly_failed"
