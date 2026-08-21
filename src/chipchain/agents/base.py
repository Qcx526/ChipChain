"""Provider-independent reasoning-agent interface for Phase 9B2B."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import Field, field_validator, model_validator

from chipchain.knowledge.models import KnowledgeRetrievalResult
from chipchain.models import Architecture, CrossLayerInteraction
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
from chipchain.runtime.models import RuntimeObservation


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
    cross_layer_interaction_id: str | None = None,
    runtime_observation_ids: list[str] | None = None,
    knowledge_retrieval_result_id: str | None = None,
) -> str:
    """Build deterministic context identity without mutable metadata."""

    payload: dict[str, object] = {
        "architecture": architecture.value,
        "attack_pattern_reference": attack_pattern_reference,
        "affected_components": sorted(affected_components),
        "available_evidence_ids": sorted(available_evidence_ids),
        "dynamic_trigger_fact_reference": dynamic_trigger_fact_reference,
        "knowledge_entry_ids": sorted(knowledge_entry_ids),
        "observed_fact_ids": sorted(observed_fact_ids),
        "subject_id": subject_id,
    }
    if cross_layer_interaction_id is not None:
        payload["cross_layer_interaction_id"] = cross_layer_interaction_id
    if runtime_observation_ids:
        payload["runtime_observation_ids"] = sorted(runtime_observation_ids)
    if knowledge_retrieval_result_id is not None:
        payload["knowledge_retrieval_result_id"] = knowledge_retrieval_result_id
    return _canonical_reasoning_id("reasoning-context", payload)


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
    cross_layer_interaction: CrossLayerInteraction | None = None
    runtime_observations: list[RuntimeObservation] = Field(default_factory=list)
    knowledge_retrieval_result: KnowledgeRetrievalResult | None = None
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

    @field_validator("runtime_observations")
    @classmethod
    def normalize_runtime_observations(
        cls, values: list[RuntimeObservation]
    ) -> list[RuntimeObservation]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("reasoning runtime observation IDs must be unique")
        return sorted(
            values,
            key=lambda item: (item.trace_id, item.sequence_index, item.id),
        )

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
            cross_layer_interaction_id=(
                self.cross_layer_interaction.id
                if self.cross_layer_interaction is not None
                else None
            ),
            runtime_observation_ids=[
                item.id for item in self.runtime_observations
            ],
            knowledge_retrieval_result_id=(
                self.knowledge_retrieval_result.id
                if self.knowledge_retrieval_result is not None
                else None
            ),
        )
        if self.id != expected_id:
            raise ValueError("ReasoningContext ID is not deterministic")
        if (
            self.cross_layer_interaction is not None
            and self.cross_layer_interaction.architecture is not self.architecture
        ):
            raise ValueError("reasoning interaction architecture mismatch")
        if any(
            item.architecture is not self.architecture
            for item in self.runtime_observations
        ):
            raise ValueError("reasoning runtime observation architecture mismatch")
        if (
            self.knowledge_retrieval_result is not None
            and self.knowledge_retrieval_result.query.architecture
            is not self.architecture
        ):
            raise ValueError("reasoning knowledge architecture mismatch")
        if self.knowledge_retrieval_result is not None and (
            self.knowledge_entry_ids
            != sorted(self.knowledge_retrieval_result.knowledge_entry_ids)
        ):
            raise ValueError("reasoning knowledge references do not match retrieval")
        if self.cross_layer_interaction is not None and (
            self.cross_layer_interaction.metadata
        ):
            raise ValueError("reasoning interaction snapshot metadata must be empty")
        if any(
            item.metadata or item.host_timestamp is not None
            for item in self.runtime_observations
        ):
            raise ValueError(
                "reasoning runtime observation snapshots must exclude metadata and time"
            )
        if self.knowledge_retrieval_result is not None and (
            self.knowledge_retrieval_result.metadata
            or self.knowledge_retrieval_result.query.metadata
        ):
            raise ValueError("reasoning knowledge snapshot metadata must be empty")
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
        cross_layer_interaction: CrossLayerInteraction | None = None,
        runtime_observations: list[RuntimeObservation] | None = None,
        knowledge_retrieval_result: KnowledgeRetrievalResult | None = None,
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
        normalized_knowledge = sorted(
            item.strip() for item in (knowledge_entry_ids or [])
        )
        interaction_snapshot = _snapshot_interaction(cross_layer_interaction)
        runtime_snapshots = [
            _snapshot_runtime_observation(item)
            for item in (runtime_observations or [])
        ]
        knowledge_snapshot = _snapshot_knowledge_result(
            knowledge_retrieval_result
        )
        if knowledge_snapshot is not None:
            retrieved_ids = sorted(knowledge_snapshot.knowledge_entry_ids)
            if normalized_knowledge and normalized_knowledge != retrieved_ids:
                raise ValueError(
                    "knowledge_entry_ids must match knowledge retrieval result"
                )
            normalized_knowledge = retrieved_ids
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
            cross_layer_interaction_id=(
                interaction_snapshot.id
                if interaction_snapshot is not None
                else None
            ),
            runtime_observation_ids=[item.id for item in runtime_snapshots],
            knowledge_retrieval_result_id=(
                knowledge_snapshot.id if knowledge_snapshot is not None else None
            ),
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
            cross_layer_interaction=interaction_snapshot,
            runtime_observations=runtime_snapshots,
            knowledge_retrieval_result=knowledge_snapshot,
            metadata=metadata or {},
        )


def _snapshot_interaction(
    value: CrossLayerInteraction | None,
) -> CrossLayerInteraction | None:
    """Detach an interaction while excluding mutable, untrusted metadata."""

    if value is None:
        return None
    if not isinstance(value, CrossLayerInteraction):
        raise TypeError("cross-layer context must be a CrossLayerInteraction")
    serialized = value.model_dump(mode="json")
    serialized["metadata"] = {}
    return CrossLayerInteraction.model_validate(serialized)


def _snapshot_runtime_observation(value: RuntimeObservation) -> RuntimeObservation:
    """Detach one observation without importing time or metadata into reasoning."""

    if not isinstance(value, RuntimeObservation):
        raise TypeError("runtime context items must be RuntimeObservation objects")
    serialized = value.model_dump(mode="json")
    serialized["host_timestamp"] = None
    serialized["metadata"] = {}
    return RuntimeObservation.model_validate(serialized)


def _snapshot_knowledge_result(
    value: KnowledgeRetrievalResult | None,
) -> KnowledgeRetrievalResult | None:
    """Detach one retrieval result without treating retrieval metadata as facts."""

    if value is None:
        return None
    if not isinstance(value, KnowledgeRetrievalResult):
        raise TypeError("knowledge context must be a KnowledgeRetrievalResult")
    serialized = value.model_dump(mode="json")
    serialized["metadata"] = {}
    serialized["query"]["metadata"] = {}
    return KnowledgeRetrievalResult.model_validate(serialized)


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

        description = self.hypothesis_template.format(
            subject_id=self._context.subject_id
        )
        context_references: list[str] = []
        if self._context.cross_layer_interaction is not None:
            interaction = self._context.cross_layer_interaction
            context_references.append(
                f"interaction {interaction.id} ({interaction.interaction_type.value})"
            )
        context_references.extend(
            f"runtime observation {item.id} ({item.event_kind.value})"
            for item in self._context.runtime_observations
        )
        if self._context.knowledge_retrieval_result is not None:
            context_references.append(
                "knowledge retrieval "
                f"{self._context.knowledge_retrieval_result.id}"
            )
        if context_references:
            description += "; bounded context references: " + ", ".join(
                context_references
            )
        return AttackHypothesis.create(
            source=HypothesisSource.ANALYST,
            architecture=self._context.architecture,
            description=description,
            affected_components=self._context.affected_components,
            attack_pattern_reference=self._context.attack_pattern_reference,
            required_evidence_types=list(self.evidence_types),
            confidence=DETERMINISTIC_MOCK_CONFIDENCE,
            metadata={
                "agent_id": self.agent_id,
                "agent_type": self.agent_type.value,
                "context_binding_semantics": (
                    "reasoning_input_only_not_verification"
                ),
                "reasoning_mode": "deterministic_mock",
            },
        )

    def request_evidence(self) -> list[EvidenceRequest]:
        """Produce deterministic evidence requests without collecting Evidence."""

        hypothesis = self.produce_hypothesis()
        requests: list[EvidenceRequest] = []
        for (
            evidence_type,
            required_fact,
            priority,
            use_dynamic_trigger_reference,
        ) in self.evidence_request_specs:
            request_metadata: Metadata = {
                "agent_id": self.agent_id,
                "agent_type": self.agent_type.value,
                "reasoning_mode": "deterministic_mock",
            }
            if (
                evidence_type
                in {
                    EvidenceCategory.RUNTIME_OBSERVATION,
                    EvidenceCategory.MMIO_ACCESS,
                }
                and not self._context.runtime_observations
            ):
                request_metadata["context_gap"] = (
                    "runtime_observation_context_missing"
                )
            requests.append(
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
                    metadata=request_metadata,
                )
            )
        return requests

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
                "context_binding_semantics": (
                    "reasoning_input_only_not_verification"
                ),
                "reasoning_mode": "deterministic_mock",
                "runtime_observation_semantics": (
                    "observation_context_only_not_verified_evidence"
                ),
            },
        )


def _snapshot_context(value: object) -> ReasoningContext:
    if not isinstance(value, ReasoningContext):
        raise TypeError("agent input must be a ReasoningContext")
    return ReasoningContext.model_validate(value.model_dump(mode="json"))
