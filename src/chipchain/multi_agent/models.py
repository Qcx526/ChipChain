"""Strict Phase 8 context, agent outputs, trace, and final result models."""

from __future__ import annotations

import re

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier, Metadata, NonNegativeOrder
from chipchain.reasoning import (
    CandidateContext,
    CandidateRetrievalQuery,
    CandidateSemanticStatus,
    RetrievalResult,
    RetrievedKnowledgeChunk,
)
from chipchain.reasoning.enums import ArchitectureKnowledgeScope
from chipchain.multi_agent.enums import (
    AgentExecutionStatus,
    AgentRole,
    CriticReviewStatus,
    EvidenceAnalysisStatus,
)

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class MultiAgentContext(DomainModel):
    """One shared immutable-by-contract fact and retrieval view for all agents."""

    candidate_id: Identifier
    architecture: Architecture
    candidate_context: CandidateContext
    retrieval_query: CandidateRetrievalQuery
    retrieved_chunks: list[RetrievedKnowledgeChunk] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_shared_context(self) -> "MultiAgentContext":
        if self.candidate_context.candidate_id != self.candidate_id:
            raise ValueError("multi-agent context candidate ID mismatch")
        if self.candidate_context.architecture is not self.architecture:
            raise ValueError("multi-agent candidate context architecture mismatch")
        if self.retrieval_query.candidate_id != self.candidate_id:
            raise ValueError("multi-agent retrieval query candidate ID mismatch")
        if self.retrieval_query.architecture is not self.architecture:
            raise ValueError("multi-agent retrieval query architecture mismatch")
        chunk_ids = [chunk.chunk_id for chunk in self.retrieved_chunks]
        if len(chunk_ids) != len(set(chunk_ids)):
            raise ValueError("multi-agent retrieved chunk IDs must be unique")
        for chunk in self.retrieved_chunks:
            if (
                chunk.scope is ArchitectureKnowledgeScope.ARCHITECTURE
                and chunk.architecture is not self.architecture
            ):
                raise ValueError("multi-agent retrieved chunk architecture mismatch")
        return self


class EvidenceAnalysis(DomainModel):
    """Evidence inventory and gaps; explicitly not evidence verification."""

    candidate_id: Identifier
    architecture: Architecture
    observed_behavior_evidence_ids: list[Identifier] = Field(default_factory=list)
    observed_knowledge_evidence_ids: list[Identifier] = Field(default_factory=list)
    unresolved_trigger_node_ids: list[Identifier] = Field(default_factory=list)
    unresolved_precondition_node_ids: list[Identifier] = Field(default_factory=list)
    evidence_gaps: list[Identifier] = Field(default_factory=list)
    missing_behavior_evidence: bool
    missing_knowledge_evidence: bool
    recommended_evidence_collection_steps: list[Identifier] = Field(
        default_factory=list
    )
    analysis_status: EvidenceAnalysisStatus
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "observed_behavior_evidence_ids",
        "observed_knowledge_evidence_ids",
        "unresolved_trigger_node_ids",
        "unresolved_precondition_node_ids",
        "evidence_gaps",
        "recommended_evidence_collection_steps",
    )
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "EvidenceAnalysis")


class SemanticHypothesis(DomainModel):
    """A cited semantic proposition awaiting Phase 9 verification."""

    id: Identifier
    statement: Identifier
    supporting_observation_ids: list[Identifier] = Field(default_factory=list)
    supporting_knowledge_chunk_ids: list[Identifier] = Field(default_factory=list)
    related_trigger_node_ids: list[Identifier] = Field(default_factory=list)
    related_precondition_node_ids: list[Identifier] = Field(default_factory=list)
    missing_information: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "supporting_observation_ids",
        "supporting_knowledge_chunk_ids",
        "related_trigger_node_ids",
        "related_precondition_node_ids",
        "missing_information",
    )
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "SemanticHypothesis")


class SecurityReasoningAssessment(DomainModel):
    """Cited semantic hypotheses without confirmation or exploitability claims."""

    candidate_id: Identifier
    architecture: Architecture
    summary: Identifier
    hypotheses: list[SemanticHypothesis] = Field(default_factory=list)
    supporting_observation_ids: list[Identifier] = Field(default_factory=list)
    supporting_knowledge_chunk_ids: list[Identifier] = Field(default_factory=list)
    unresolved_trigger_node_ids: list[Identifier] = Field(default_factory=list)
    unresolved_precondition_node_ids: list[Identifier] = Field(default_factory=list)
    missing_information: list[Identifier] = Field(default_factory=list)
    contradictions: list[Identifier] = Field(default_factory=list)
    recommended_verification_steps: list[Identifier] = Field(default_factory=list)
    semantic_status: CandidateSemanticStatus
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "supporting_observation_ids",
        "supporting_knowledge_chunk_ids",
        "unresolved_trigger_node_ids",
        "unresolved_precondition_node_ids",
        "missing_information",
        "contradictions",
        "recommended_verification_steps",
    )
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "SecurityReasoningAssessment")

    @model_validator(mode="after")
    def validate_hypothesis_ids(self) -> "SecurityReasoningAssessment":
        hypothesis_ids = [item.id for item in self.hypotheses]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("SemanticHypothesis IDs must be unique")
        return self


class CriticReview(DomainModel):
    """Bounded review findings; never an approval or verification decision."""

    candidate_id: Identifier
    architecture: Architecture
    referenced_observation_ids: list[Identifier] = Field(default_factory=list)
    referenced_knowledge_chunk_ids: list[Identifier] = Field(default_factory=list)
    referenced_trigger_node_ids: list[Identifier] = Field(default_factory=list)
    referenced_precondition_node_ids: list[Identifier] = Field(default_factory=list)
    referenced_hypothesis_ids: list[Identifier] = Field(default_factory=list)
    unresolved_trigger_node_ids: list[Identifier] = Field(default_factory=list)
    unresolved_precondition_node_ids: list[Identifier] = Field(default_factory=list)
    unsupported_statements: list[Identifier] = Field(default_factory=list)
    citation_issues: list[Identifier] = Field(default_factory=list)
    architecture_issues: list[Identifier] = Field(default_factory=list)
    condition_issues: list[Identifier] = Field(default_factory=list)
    contradictions: list[Identifier] = Field(default_factory=list)
    required_revisions: list[Identifier] = Field(default_factory=list)
    review_status: CriticReviewStatus
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "referenced_observation_ids",
        "referenced_knowledge_chunk_ids",
        "referenced_trigger_node_ids",
        "referenced_precondition_node_ids",
        "referenced_hypothesis_ids",
        "unresolved_trigger_node_ids",
        "unresolved_precondition_node_ids",
        "unsupported_statements",
        "citation_issues",
        "architecture_issues",
        "condition_issues",
        "contradictions",
        "required_revisions",
    )
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "CriticReview")


class AgentExecutionRecord(DomainModel):
    """Deterministic digest-only audit record for one fixed agent call."""

    sequence: NonNegativeOrder
    role: AgentRole
    candidate_id: Identifier
    architecture: Architecture
    input_digest: Identifier
    prompt_digest: Identifier
    output_digest: Identifier | None = None
    execution_status: AgentExecutionStatus
    error_type: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("input_digest", "prompt_digest", "output_digest")
    @classmethod
    def validate_digest(cls, value: str | None) -> str | None:
        if value is not None and not _DIGEST_PATTERN.fullmatch(value):
            raise ValueError("execution digests must be lowercase SHA-256 values")
        return value

    @model_validator(mode="after")
    def validate_execution_outcome(self) -> "AgentExecutionRecord":
        if self.execution_status is AgentExecutionStatus.COMPLETED:
            if self.output_digest is None or self.error_type is not None:
                raise ValueError("completed execution requires output and no error")
        elif self.error_type is None:
            raise ValueError("failed execution requires an error type")
        return self


class MultiAgentReasoningResult(DomainModel):
    """Auditable three-agent output that remains an unverified interpretation."""

    candidate_id: Identifier
    architecture: Architecture
    context: MultiAgentContext
    retrieval: RetrievalResult
    evidence_analysis: EvidenceAnalysis
    security_reasoning: SecurityReasoningAssessment
    critic_review: CriticReview
    execution_trace: list[AgentExecutionRecord]
    unresolved_trigger_node_ids: list[Identifier] = Field(default_factory=list)
    unresolved_precondition_node_ids: list[Identifier] = Field(default_factory=list)
    final_semantic_status: CandidateSemanticStatus
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "unresolved_trigger_node_ids",
        "unresolved_precondition_node_ids",
    )
    @classmethod
    def normalize_unresolved(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "MultiAgentReasoningResult")

    @model_validator(mode="after")
    def validate_result_identity_and_trace(self) -> "MultiAgentReasoningResult":
        outputs = [
            self.context,
            self.evidence_analysis,
            self.security_reasoning,
            self.critic_review,
        ]
        if any(item.candidate_id != self.candidate_id for item in outputs):
            raise ValueError("multi-agent result candidate ID mismatch")
        if any(item.architecture is not self.architecture for item in outputs):
            raise ValueError("multi-agent result architecture mismatch")
        if self.retrieval.query != self.context.retrieval_query:
            raise ValueError("multi-agent result retrieval query mismatch")
        if self.retrieval.chunks != self.context.retrieved_chunks:
            raise ValueError("multi-agent result retrieved chunks mismatch")
        expected_roles = [
            AgentRole.EVIDENCE_ANALYST,
            AgentRole.SECURITY_REASONER,
            AgentRole.CRITIC,
        ]
        if [record.sequence for record in self.execution_trace] != [1, 2, 3]:
            raise ValueError("multi-agent trace sequence must be 1, 2, 3")
        if [record.role for record in self.execution_trace] != expected_roles:
            raise ValueError("multi-agent trace role order is invalid")
        if any(
            record.execution_status is not AgentExecutionStatus.COMPLETED
            for record in self.execution_trace
        ):
            raise ValueError("successful multi-agent result requires completed trace")
        expected_triggers = sorted(
            item.id for item in self.context.candidate_context.trigger_nodes
        )
        expected_preconditions = sorted(
            item.id for item in self.context.candidate_context.precondition_nodes
        )
        if self.unresolved_trigger_node_ids != expected_triggers:
            raise ValueError("final result must retain all unresolved triggers")
        if self.unresolved_precondition_node_ids != expected_preconditions:
            raise ValueError("final result must retain all unresolved preconditions")
        return self


def _sorted_unique(values: list[str], model_name: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{model_name} lists must not contain duplicates")
    return sorted(values)
