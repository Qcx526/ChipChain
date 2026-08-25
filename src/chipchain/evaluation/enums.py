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
