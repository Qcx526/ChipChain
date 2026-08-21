"""Provider-independent reasoning-agent interface for Phase 9B2B."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.reasoning.enums import (
    EvidenceCategory,
    EvidencePriority,
    HypothesisSource,
    ReasoningAgentType,
)
from chipchain.reasoning.evidence_request import EvidenceRequest
from chipchain.reasoning.hypothesis import (
    AttackHypothesis,
    SupportedReasoningArchitecture,
    _canonical_reasoning_id,
    _validate_non_verdict_metadata,
)
from chipchain.reasoning.reasoning_result import ReasoningResult


def reasoning_context_id(
    *,
    architecture: Architecture,
    subject_id: str,
    affected_components: list[str],
    observed_fact_ids: list[str],
    available_evidence_ids: list[str],
    knowledge_entry_ids: list[str],
    dynamic_trigger_fact_reference: str | None,
    attack_pattern_reference: str | None,
) -> str:
    """Build deterministic context identity without mutable metadata."""

    return _canonical_reasoning_id(
        "reasoning-context",
        {
            "architecture": architecture.value,
            "attack_pattern_reference": attack_pattern_reference,
            "affected_components": sorted(affected_components),
            "available_evidence_ids": sorted(available_evidence_ids),
            "dynamic_trigger_fact_reference": dynamic_trigger_fact_reference,
            "knowledge_entry_ids": sorted(knowledge_entry_ids),
            "observed_fact_ids": sorted(observed_fact_ids),
            "subject_id": subject_id,
        },
    )


class ReasoningContext(DomainModel):
    """Unified, reference-only input shared by every Phase 9B2B agent."""

    id: Identifier
    architecture: SupportedReasoningArchitecture
    subject_id: Identifier
    affected_components: list[Identifier] = Field(min_length=1)
    observed_fact_ids: list[Identifier] = Field(default_factory=list)
    available_evidence_ids: list[Identifier] = Field(default_factory=list)
    knowledge_entry_ids: list[Identifier] = Field(default_factory=list)
    dynamic_trigger_fact_reference: Identifier | None = None
    attack_pattern_reference: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "affected_components",
        "observed_fact_ids",
        "available_evidence_ids",
        "knowledge_entry_ids",
    )
    @classmethod
    def normalize_identifier_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("reasoning context lists must not contain duplicates")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_non_verdict_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "ReasoningContext":
        expected_id = reasoning_context_id(
            architecture=self.architecture,
            subject_id=self.subject_id,
            affected_components=self.affected_components,
            observed_fact_ids=self.observed_fact_ids,
            available_evidence_ids=self.available_evidence_ids,
            knowledge_entry_ids=self.knowledge_entry_ids,
            dynamic_trigger_fact_reference=self.dynamic_trigger_fact_reference,
            attack_pattern_reference=self.attack_pattern_reference,
        )
        if self.id != expected_id:
            raise ValueError("ReasoningContext ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        architecture: Architecture | str,
        subject_id: str,
        affected_components: list[str],
        observed_fact_ids: list[str] | None = None,
        available_evidence_ids: list[str] | None = None,
        knowledge_entry_ids: list[str] | None = None,
        dynamic_trigger_fact_reference: str | None = None,
        attack_pattern_reference: str | None = None,
        metadata: Metadata | None = None,
    ) -> "ReasoningContext":
        """Create a detached-reference context without resolving domain objects."""

        normalized_architecture = Architecture(architecture)
        normalized_subject = subject_id.strip()
        normalized_components = [item.strip() for item in affected_components]
        normalized_facts = [item.strip() for item in (observed_fact_ids or [])]
        normalized_evidence = [
            item.strip() for item in (available_evidence_ids or [])
        ]
        normalized_knowledge = [
            item.strip() for item in (knowledge_entry_ids or [])
        ]
        normalized_trigger_reference = (
            dynamic_trigger_fact_reference.strip()
            if dynamic_trigger_fact_reference is not None
            else None
        )
        normalized_attack_reference = (
            attack_pattern_reference.strip()
            if attack_pattern_reference is not None
            else None
        )
        identity = reasoning_context_id(
            architecture=normalized_architecture,
            subject_id=normalized_subject,
            affected_components=normalized_components,
            observed_fact_ids=normalized_facts,
            available_evidence_ids=normalized_evidence,
            knowledge_entry_ids=normalized_knowledge,
            dynamic_trigger_fact_reference=normalized_trigger_reference,
            attack_pattern_reference=normalized_attack_reference,
        )
        return cls(
            id=identity,
            architecture=normalized_architecture,
            subject_id=normalized_subject,
            affected_components=normalized_components,
            observed_fact_ids=normalized_facts,
            available_evidence_ids=normalized_evidence,
            knowledge_entry_ids=normalized_knowledge,
            dynamic_trigger_fact_reference=normalized_trigger_reference,
            attack_pattern_reference=normalized_attack_reference,
            metadata=metadata or {},
        )


def reasoning_agent_id(agent_type: ReasoningAgentType) -> str:
    """Return the stable identity of one deterministic mock-agent contract."""

    return _canonical_reasoning_id(
        "reasoning-agent",
        {
            "agent_type": agent_type.value,
            "contract": "phase9b2b_deterministic_mock_v1",
        },
    )


class ReasoningAgent(ABC):
    """Define reasoning interfaces without transport, prompts, or execution."""

    agent_id: str
    agent_type: ReasoningAgentType

    def __init__(
        self,
        *,
        agent_id: str,
        agent_type: ReasoningAgentType | str,
    ) -> None:
        normalized_id = agent_id.strip()
        if not normalized_id:
            raise ValueError("agent_id must be a non-empty identifier")
        self.agent_id = normalized_id
        self.agent_type = ReasoningAgentType(agent_type)

    @abstractmethod
    def analyze(self, input_data: object) -> ReasoningResult:
        """Reason over supplied input without creating verification truth."""

    @abstractmethod
    def produce_hypothesis(self) -> AttackHypothesis:
        """Return one explicitly unverified hypothesis."""

    @abstractmethod
    def request_evidence(self) -> list[EvidenceRequest]:
        """Return evidence requests without collecting or creating Evidence."""


EvidenceRequestSpec = tuple[
    EvidenceCategory,
    str,
    EvidencePriority,
    bool,
]
DETERMINISTIC_MOCK_CONFIDENCE = 0.0


class DeterministicMockReasoningAgent(ReasoningAgent):
    """Shared deterministic mechanics for role-isolated mock agents."""

    role: ClassVar[ReasoningAgentType]
    hypothesis_template: ClassVar[str]
    evidence_types: ClassVar[tuple[EvidenceCategory, ...]]
    evidence_request_specs: ClassVar[tuple[EvidenceRequestSpec, ...]]
    reasoning_step_template: ClassVar[str]

    def __init__(self, context: ReasoningContext) -> None:
        self._context = _snapshot_context(context)
        super().__init__(
            agent_id=reasoning_agent_id(self.role),
            agent_type=self.role,
        )

    def produce_hypothesis(self) -> AttackHypothesis:
        """Produce a deterministic role-specific, explicitly unverified hypothesis."""

        return AttackHypothesis.create(
            source=HypothesisSource.ANALYST,
            architecture=self._context.architecture,
            description=self.hypothesis_template.format(
                subject_id=self._context.subject_id
            ),
            affected_components=self._context.affected_components,
            attack_pattern_reference=self._context.attack_pattern_reference,
            required_evidence_types=list(self.evidence_types),
            confidence=DETERMINISTIC_MOCK_CONFIDENCE,
            metadata={
                "agent_id": self.agent_id,
                "agent_type": self.agent_type.value,
                "reasoning_mode": "deterministic_mock",
            },
        )

    def request_evidence(self) -> list[EvidenceRequest]:
        """Produce deterministic evidence requests without collecting Evidence."""

        hypothesis = self.produce_hypothesis()
        return [
            EvidenceRequest.create(
                hypothesis,
                evidence_type=evidence_type,
                required_fact=required_fact.format(
                    subject_id=self._context.subject_id
                ),
                priority=priority,
                dynamic_trigger_fact_reference=(
                    self._context.dynamic_trigger_fact_reference
                    if use_dynamic_trigger_reference
                    else None
                ),
                metadata={
                    "agent_id": self.agent_id,
                    "agent_type": self.agent_type.value,
                    "reasoning_mode": "deterministic_mock",
                },
            )
            for (
                evidence_type,
                required_fact,
                priority,
                use_dynamic_trigger_reference,
            ) in self.evidence_request_specs
        ]

    def analyze(self, input_data: object) -> ReasoningResult:
        """Return deterministic reasoning over references in the bound context."""

        context = _snapshot_context(input_data)
        if context.id != self._context.id:
            raise ValueError("agent reasoning context identity mismatch")
        hypothesis = self.produce_hypothesis()
        requests = self.request_evidence()
        return ReasoningResult.create(
            hypothesis,
            reasoning_steps=[
                self.reasoning_step_template.format(
                    subject_id=context.subject_id
                )
            ],
            supporting_evidence_ids=context.available_evidence_ids,
            missing_evidence=[request.id for request in requests],
            confidence=DETERMINISTIC_MOCK_CONFIDENCE,
            metadata={
                "agent_id": self.agent_id,
                "agent_type": self.agent_type.value,
                "reasoning_mode": "deterministic_mock",
            },
        )


def _snapshot_context(value: object) -> ReasoningContext:
    if not isinstance(value, ReasoningContext):
        raise TypeError("agent input must be a ReasoningContext")
    return ReasoningContext.model_validate(value.model_dump(mode="json"))
