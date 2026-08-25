"""Finalized, non-verifying evaluation candidate construction."""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from chipchain.agents.state import ReasoningSession
from chipchain.evaluation.models import _canonical_hash
from chipchain.models.common import (
    DomainModel,
    Identifier,
    Metadata,
    UnitInterval,
)
from chipchain.models.cross_layer import (
    CrossLayerDirection,
    CrossLayerInteractionType,
    direction_for_interaction_type,
)
from chipchain.models.enums import Architecture
from chipchain.reasoning.hypothesis import _validate_non_verdict_metadata


def finalized_candidate_id(
    *,
    benchmark_case_id: str,
    architecture: Architecture,
    reasoning_session_id: str,
    reasoning_context_id: str,
    workflow_contract: str,
    merged_hypothesis_id: str,
    subject_id: str,
    cross_layer_interaction_id: str | None,
    interaction_type: CrossLayerInteractionType | None,
    direction: CrossLayerDirection | None,
    attack_pattern_reference: str | None,
    affected_components: list[str],
) -> str:
    """Build candidate identity without confidence, metadata, or provider data."""

    return _canonical_hash(
        "finalized-candidate",
        {
            "affected_components": sorted(affected_components),
            "architecture": Architecture(architecture).value,
            "attack_pattern_reference": attack_pattern_reference,
            "benchmark_case_id": benchmark_case_id,
            "cross_layer_interaction_id": cross_layer_interaction_id,
            "direction": direction.value if direction is not None else None,
            "interaction_type": (
                interaction_type.value if interaction_type is not None else None
            ),
            "merged_hypothesis_id": merged_hypothesis_id,
            "reasoning_context_id": reasoning_context_id,
            "reasoning_session_id": reasoning_session_id,
            "subject_id": subject_id,
            "workflow_contract": workflow_contract,
        },
    )


class FinalizedCandidateRecord(DomainModel):
    """Exactly one merged, explicitly unverified proposition from one session."""

    id: Identifier
    benchmark_case_id: Identifier
    architecture: Architecture
    reasoning_session_id: Identifier
    reasoning_context_id: Identifier
    workflow_contract: Identifier
    merged_hypothesis_id: Identifier
    subject_id: Identifier
    cross_layer_interaction_id: Identifier | None = None
    interaction_type: CrossLayerInteractionType | None = None
    direction: CrossLayerDirection | None = None
    attack_pattern_reference: Identifier | None = None
    affected_components: list[Identifier] = Field(min_length=1)
    model_confidence: UnitInterval
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("affected_components")
    @classmethod
    def normalize_components(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("finalized candidate components must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_non_verdict_metadata(value)

    @model_validator(mode="after")
    def validate_semantics_and_identity(self) -> "FinalizedCandidateRecord":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10A finalized candidates support ARM only")
        interaction_values = (
            self.cross_layer_interaction_id,
            self.interaction_type,
            self.direction,
        )
        if any(item is None for item in interaction_values) and any(
            item is not None for item in interaction_values
        ):
            raise ValueError("typed interaction candidate fields are all-or-none")
        if (
            self.interaction_type is not None
            and self.direction
            is not direction_for_interaction_type(self.interaction_type)
        ):
            raise ValueError("candidate interaction type and direction mismatch")
        expected_id = finalized_candidate_id(
            benchmark_case_id=self.benchmark_case_id,
            architecture=self.architecture,
            reasoning_session_id=self.reasoning_session_id,
            reasoning_context_id=self.reasoning_context_id,
            workflow_contract=self.workflow_contract,
            merged_hypothesis_id=self.merged_hypothesis_id,
            subject_id=self.subject_id,
            cross_layer_interaction_id=self.cross_layer_interaction_id,
            interaction_type=self.interaction_type,
            direction=self.direction,
            attack_pattern_reference=self.attack_pattern_reference,
            affected_components=self.affected_components,
        )
        if self.id != expected_id:
            raise ValueError("FinalizedCandidateRecord ID is not deterministic")
        return self


class FinalizedCandidateBuilder:
    """Build one candidate from one detached complete ReasoningSession only."""

    @staticmethod
    def from_reasoning_session(
        benchmark_case_id: str,
        session: ReasoningSession,
    ) -> FinalizedCandidateRecord:
        """Finalize only ``merged_hypothesis`` without reading Ground Truth."""

        if not isinstance(session, ReasoningSession):
            raise TypeError("finalized candidate requires a ReasoningSession")
        detached = ReasoningSession.model_validate(
            session.model_dump(mode="json")
        )
        context = detached.reasoning_context
        proposition = detached.merged_hypothesis
        interaction = context.cross_layer_interaction
        interaction_id = interaction.id if interaction is not None else None
        interaction_type = (
            interaction.interaction_type if interaction is not None else None
        )
        direction = interaction.direction if interaction is not None else None
        values = {
            "benchmark_case_id": benchmark_case_id.strip(),
            "architecture": context.architecture,
            "reasoning_session_id": detached.session_id,
            "reasoning_context_id": context.id,
            "workflow_contract": detached.workflow_contract,
            "merged_hypothesis_id": proposition.id,
            "subject_id": context.subject_id,
            "cross_layer_interaction_id": interaction_id,
            "interaction_type": interaction_type,
            "direction": direction,
            "attack_pattern_reference": proposition.attack_pattern_reference,
            "affected_components": proposition.affected_components,
        }
        identity = finalized_candidate_id(**values)
        return FinalizedCandidateRecord(
            id=identity,
            model_confidence=proposition.confidence,
            metadata={
                "candidate_boundary": "one_complete_session_one_merged_hypothesis",
                "evaluation_outcome_creation": False,
                "role_hypotheses_counted_as_candidates": False,
            },
            **values,
        )
