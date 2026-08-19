"""Strict data contracts for context, retrieval, prompting, and assessment."""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture, BehaviorEdge, BehaviorNode, Evidence
from chipchain.models.common import DomainModel, Identifier, Metadata, UnitInterval
from chipchain.knowledge import KnowledgeEdge, KnowledgeNode, KnowledgeNodeKind
from chipchain.reasoning.enums import (
    ArchitectureKnowledgeScope,
    CandidateSemanticStatus,
    LLMAPIStyle,
)


class CandidateContext(DomainModel):
    """Read-only resolved view of facts referenced by a CrossGraphCandidate."""

    candidate_id: Identifier
    architecture: Architecture
    behavior_nodes: list[BehaviorNode]
    behavior_edges: list[BehaviorEdge]
    behavior_evidence: list[Evidence]
    knowledge_vulnerability: KnowledgeNode
    knowledge_anchor: KnowledgeNode
    knowledge_nodes: list[KnowledgeNode]
    knowledge_edges: list[KnowledgeEdge]
    knowledge_evidence: list[Evidence]
    trigger_nodes: list[KnowledgeNode] = Field(default_factory=list)
    precondition_nodes: list[KnowledgeNode] = Field(default_factory=list)
    impact_nodes: list[KnowledgeNode] = Field(default_factory=list)
    security_mechanism_nodes: list[KnowledgeNode] = Field(default_factory=list)
    root_cause_nodes: list[KnowledgeNode] = Field(default_factory=list)
    taxonomy_nodes: list[KnowledgeNode] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_resolved_context(self) -> "CandidateContext":
        """Require unique, architecture-consistent resolved domain objects."""

        _require_unique_ids(self.behavior_nodes, "behavior node")
        _require_unique_ids(self.behavior_edges, "behavior edge")
        _require_unique_ids(self.behavior_evidence, "behavior evidence")
        _require_unique_ids(self.knowledge_nodes, "knowledge node")
        _require_unique_ids(self.knowledge_edges, "knowledge edge")
        _require_unique_ids(self.knowledge_evidence, "knowledge evidence")
        if any(node.architecture is not self.architecture for node in self.behavior_nodes):
            raise ValueError("behavior context nodes must match context architecture")
        if any(edge.architecture is not self.architecture for edge in self.behavior_edges):
            raise ValueError("behavior context edges must match context architecture")
        if self.knowledge_vulnerability.kind is not KnowledgeNodeKind.VULNERABILITY:
            raise ValueError("knowledge vulnerability must have vulnerability kind")
        if self.knowledge_anchor.kind is not KnowledgeNodeKind.HARDWARE_RESOURCE:
            raise ValueError("knowledge anchor must have hardware_resource kind")
        for node in [self.knowledge_vulnerability, *self.knowledge_nodes]:
            if node.architecture is not None and node.architecture is not self.architecture:
                raise ValueError("knowledge context node architecture mismatch")
        if any(edge.architecture is not self.architecture for edge in self.knowledge_edges):
            raise ValueError("knowledge context edge architecture mismatch")
        known_ids = {node.id for node in self.knowledge_nodes}
        if self.knowledge_anchor.id not in known_ids:
            raise ValueError("knowledge anchor must exist in knowledge_nodes")
        categorized = [
            *self.trigger_nodes,
            *self.precondition_nodes,
            *self.impact_nodes,
            *self.security_mechanism_nodes,
            *self.root_cause_nodes,
            *self.taxonomy_nodes,
        ]
        if any(node.id not in known_ids for node in categorized):
            raise ValueError("categorized knowledge nodes must exist in knowledge_nodes")
        _require_node_kind(
            self.trigger_nodes,
            KnowledgeNodeKind.TRIGGER,
            "trigger_nodes",
        )
        _require_node_kind(
            self.precondition_nodes,
            KnowledgeNodeKind.PRECONDITION,
            "precondition_nodes",
        )
        _require_node_kind(
            self.impact_nodes,
            KnowledgeNodeKind.IMPACT,
            "impact_nodes",
        )
        _require_node_kind(
            self.security_mechanism_nodes,
            KnowledgeNodeKind.SECURITY_MECHANISM,
            "security_mechanism_nodes",
        )
        _require_node_kind(
            self.root_cause_nodes,
            KnowledgeNodeKind.ROOT_CAUSE,
            "root_cause_nodes",
        )
        if any(
            node.kind not in {KnowledgeNodeKind.CWE, KnowledgeNodeKind.CAPEC}
            for node in self.taxonomy_nodes
        ):
            raise ValueError("taxonomy_nodes may contain only CWE or CAPEC")
        return self


class ArchitectureKnowledgeDocument(DomainModel):
    """Provenance-aware local retrieval document, never a prompt instruction."""

    id: Identifier
    scope: ArchitectureKnowledgeScope
    architecture: Architecture | None
    title: Identifier
    content: Identifier
    source: Identifier
    reference: Identifier
    section: Identifier | None = None
    tags: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("document tags must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_scope(self) -> "ArchitectureKnowledgeDocument":
        if (
            self.scope is ArchitectureKnowledgeScope.ARCHITECTURE
            and self.architecture is None
        ):
            raise ValueError("architecture-scoped documents require architecture")
        if self.scope is ArchitectureKnowledgeScope.GLOBAL and self.architecture is not None:
            raise ValueError("global documents must not declare architecture")
        return self


class RetrievedKnowledgeChunk(DomainModel):
    """Retrieved reference text with relevance score, not security confidence."""

    document_id: Identifier
    chunk_id: Identifier
    architecture: Architecture | None
    scope: ArchitectureKnowledgeScope
    content: Identifier
    source: Identifier
    reference: Identifier
    section: Identifier | None = None
    score: UnitInterval
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_scope(self) -> "RetrievedKnowledgeChunk":
        if self.scope is ArchitectureKnowledgeScope.ARCHITECTURE and self.architecture is None:
            raise ValueError("architecture chunk requires architecture")
        if self.scope is ArchitectureKnowledgeScope.GLOBAL and self.architecture is not None:
            raise ValueError("global chunk must not declare architecture")
        return self


class CandidateRetrievalQuery(DomainModel):
    """Deterministic, auditable query derived without LLM participation."""

    candidate_id: Identifier
    architecture: Architecture
    text: Identifier
    terms: list[Identifier] = Field(min_length=1)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("terms")
    @classmethod
    def normalize_terms(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("retrieval query terms must be unique")
        return sorted(values)


class RetrievalResult(DomainModel):
    """Architecture-filtered deterministic retrieval result."""

    query: CandidateRetrievalQuery
    architecture: Architecture
    chunks: list[RetrievedKnowledgeChunk] = Field(default_factory=list)
    excluded_document_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("excluded_document_ids")
    @classmethod
    def normalize_excluded_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("excluded document IDs must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_architecture_boundary(self) -> "RetrievalResult":
        if self.query.architecture is not self.architecture:
            raise ValueError("retrieval query architecture mismatch")
        chunk_ids = [chunk.chunk_id for chunk in self.chunks]
        if len(chunk_ids) != len(set(chunk_ids)):
            raise ValueError("retrieved chunk IDs must be unique")
        for chunk in self.chunks:
            if (
                chunk.scope is ArchitectureKnowledgeScope.ARCHITECTURE
                and chunk.architecture is not self.architecture
            ):
                raise ValueError("retrieved architecture chunk mismatch")
        return self


class CandidateReasoningInput(DomainModel):
    """Bounded facts and top-k reference chunks supplied to prompt construction."""

    candidate_id: Identifier
    architecture: Architecture
    candidate_context: CandidateContext
    retrieved_chunks: list[RetrievedKnowledgeChunk] = Field(default_factory=list)
    analysis_instructions: list[Identifier] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_input_identity(self) -> "CandidateReasoningInput":
        if self.candidate_id != self.candidate_context.candidate_id:
            raise ValueError("reasoning input candidate ID mismatch")
        if self.architecture is not self.candidate_context.architecture:
            raise ValueError("reasoning input architecture mismatch")
        return self


class PromptRequest(DomainModel):
    """Deterministic provider request with fixed system and bounded user content."""

    candidate_id: Identifier
    architecture: Architecture
    system_prompt: Identifier
    user_prompt: Identifier
    reasoning_input: CandidateReasoningInput


class StructuredPromptRequest(DomainModel):
    """Generic strict-output request shared by typed Phase 8 agents."""

    candidate_id: Identifier
    architecture: Architecture
    role: Identifier
    schema_name: Identifier
    system_prompt: Identifier
    user_prompt: Identifier


class CandidateSemanticAssessment(DomainModel):
    """Structured LLM interpretation that cannot express verification or confidence."""

    candidate_id: Identifier
    architecture: Architecture
    summary: Identifier
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
    def normalize_unique_values(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("assessment lists must not contain duplicates")
        return sorted(values)


class LLMProviderConfig(DomainModel):
    """Serializable non-secret configuration for an OpenAI-compatible client."""

    base_url: Identifier
    model: Identifier
    api_style: LLMAPIStyle
    json_mode: bool = False
    timeout: float = Field(default=30.0, gt=0)
    reasoning_effort: str | None = None
    max_completion_tokens: int | None = Field(default=None, gt=0)

    @field_validator("reasoning_effort")
    @classmethod
    def validate_reasoning_effort(cls, value: str | None) -> str | None:
        """Accept only explicit effort values documented by compatible APIs."""

        if value is None:
            return None
        normalized = value.strip().lower()
        allowed = {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
        if normalized not in allowed:
            raise ValueError("unsupported LLM reasoning effort")
        return normalized


class CandidateReasoningResult(DomainModel):
    """Auditable output of the single Phase 7 reasoning pipeline."""

    context: CandidateContext
    query: CandidateRetrievalQuery
    retrieval: RetrievalResult
    prompt: PromptRequest
    assessment: CandidateSemanticAssessment


def _require_unique_ids(items: list[object], label: str) -> None:
    ids = [getattr(item, "id") for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label} IDs must be unique")


def _require_node_kind(
    nodes: list[KnowledgeNode],
    expected_kind: KnowledgeNodeKind,
    field_name: str,
) -> None:
    """Require every categorized node to have the field's exact domain kind."""

    if any(node.kind is not expected_kind for node in nodes):
        raise ValueError(f"{field_name} may contain only {expected_kind.value} nodes")
