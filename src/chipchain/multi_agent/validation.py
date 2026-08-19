"""Cross-agent identity, citation, architecture, and condition validation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from chipchain.multi_agent.errors import AgentOutputValidationError
from chipchain.multi_agent.models import (
    CriticReview,
    EvidenceAnalysis,
    MultiAgentContext,
    SecurityReasoningAssessment,
)
from chipchain.reasoning.validation import validate_verification_boundary


def validate_evidence_analysis(
    analysis: EvidenceAnalysis,
    context: MultiAgentContext,
) -> None:
    """Validate evidence citations and preserve every unresolved condition."""

    _validate_identity(analysis.candidate_id, analysis.architecture, context)
    candidate = context.candidate_context
    _require_subset(
        analysis.observed_behavior_evidence_ids,
        (item.id for item in candidate.behavior_evidence),
        "behavior Evidence",
    )
    _require_subset(
        analysis.observed_knowledge_evidence_ids,
        (item.id for item in candidate.knowledge_evidence),
        "knowledge Evidence",
    )
    _require_exact_conditions(
        analysis.unresolved_trigger_node_ids,
        (item.id for item in candidate.trigger_nodes),
        "trigger",
    )
    _require_exact_conditions(
        analysis.unresolved_precondition_node_ids,
        (item.id for item in candidate.precondition_nodes),
        "precondition",
    )
    _validate_all_text(analysis.model_dump(mode="json"))


def validate_security_reasoning(
    assessment: SecurityReasoningAssessment,
    context: MultiAgentContext,
) -> None:
    """Validate top-level and nested hypothesis citations and conditions."""

    _validate_identity(assessment.candidate_id, assessment.architecture, context)
    candidate = context.candidate_context
    observation_ids = {item.id for item in candidate.behavior_evidence}
    chunk_ids = {item.chunk_id for item in context.retrieved_chunks}
    trigger_ids = {item.id for item in candidate.trigger_nodes}
    precondition_ids = {item.id for item in candidate.precondition_nodes}
    _require_subset(
        assessment.supporting_observation_ids,
        observation_ids,
        "behavior Evidence",
    )
    _require_subset(
        assessment.supporting_knowledge_chunk_ids,
        chunk_ids,
        "retrieved Chunk",
    )
    _require_exact_conditions(
        assessment.unresolved_trigger_node_ids,
        trigger_ids,
        "trigger",
    )
    _require_exact_conditions(
        assessment.unresolved_precondition_node_ids,
        precondition_ids,
        "precondition",
    )
    for hypothesis in assessment.hypotheses:
        _require_subset(
            hypothesis.supporting_observation_ids,
            observation_ids,
            "hypothesis behavior Evidence",
        )
        _require_subset(
            hypothesis.supporting_knowledge_chunk_ids,
            chunk_ids,
            "hypothesis retrieved Chunk",
        )
        _require_subset(
            hypothesis.related_trigger_node_ids,
            trigger_ids,
            "hypothesis trigger",
        )
        _require_subset(
            hypothesis.related_precondition_node_ids,
            precondition_ids,
            "hypothesis precondition",
        )
    _validate_all_text(assessment.model_dump(mode="json"))


def validate_critic_review(
    review: CriticReview,
    context: MultiAgentContext,
    evidence_analysis: EvidenceAnalysis,
    security_reasoning: SecurityReasoningAssessment,
) -> None:
    """Validate critic references without allowing it to add facts."""

    _validate_identity(review.candidate_id, review.architecture, context)
    candidate = context.candidate_context
    observation_ids = {
        *(item.id for item in candidate.behavior_evidence),
        *evidence_analysis.observed_behavior_evidence_ids,
        *security_reasoning.supporting_observation_ids,
    }
    chunk_ids = {
        *(item.chunk_id for item in context.retrieved_chunks),
        *security_reasoning.supporting_knowledge_chunk_ids,
    }
    trigger_ids = {item.id for item in candidate.trigger_nodes}
    precondition_ids = {item.id for item in candidate.precondition_nodes}
    hypothesis_ids = {item.id for item in security_reasoning.hypotheses}
    _require_subset(
        review.referenced_observation_ids,
        observation_ids,
        "critic behavior Evidence",
    )
    _require_subset(
        review.referenced_knowledge_chunk_ids,
        chunk_ids,
        "critic retrieved Chunk",
    )
    _require_subset(
        review.referenced_trigger_node_ids,
        trigger_ids,
        "critic trigger",
    )
    _require_subset(
        review.referenced_precondition_node_ids,
        precondition_ids,
        "critic precondition",
    )
    _require_subset(
        review.referenced_hypothesis_ids,
        hypothesis_ids,
        "critic hypothesis",
    )
    _require_exact_conditions(
        review.unresolved_trigger_node_ids,
        trigger_ids,
        "critic unresolved trigger",
    )
    _require_exact_conditions(
        review.unresolved_precondition_node_ids,
        precondition_ids,
        "critic unresolved precondition",
    )
    _validate_all_text(review.model_dump(mode="json"))


def _validate_identity(candidate_id, architecture, context: MultiAgentContext) -> None:
    if candidate_id != context.candidate_id:
        raise AgentOutputValidationError("agent returned the wrong candidate ID")
    if architecture is not context.architecture:
        raise AgentOutputValidationError("agent returned the wrong architecture")


def _require_subset(
    actual: Iterable[str],
    allowed: Iterable[str],
    label: str,
) -> None:
    if not set(actual).issubset(set(allowed)):
        raise AgentOutputValidationError(f"agent cited an unknown {label} ID")


def _require_exact_conditions(
    actual: Iterable[str],
    expected: Iterable[str],
    label: str,
) -> None:
    if set(actual) != set(expected):
        raise AgentOutputValidationError(
            f"all {label} nodes must remain unresolved in Phase 8"
        )


def _validate_all_text(value: object) -> None:
    strings = list(_all_strings(value))
    validate_verification_boundary(strings)
    lowered = " ".join(strings).lower()
    if any(token in lowered for token in ("risc-v", "risc_v", "riscv")):
        raise AgentOutputValidationError(
            "agent output contains architecture leakage"
        )


def _all_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_strings(item)
