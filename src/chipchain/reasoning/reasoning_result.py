"""Non-verifying result contract for Phase 9B2B reasoning."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier, Metadata, UnitInterval
from chipchain.reasoning.hypothesis import (
    AttackHypothesis,
    _canonical_reasoning_id,
    _validate_non_verdict_metadata,
)


REASONING_RESULT_BOUNDARY = (
    "The result represents reasoning over available evidence. "
    "It is not a vulnerability verification result."
)


def reasoning_result_id(
    *,
    hypothesis_id: str,
    reasoning_steps: list[str],
    supporting_evidence_ids: list[str],
    missing_evidence: list[str],
) -> str:
    """Build identity from reasoning content, never confidence or metadata."""

    return _canonical_reasoning_id(
        "reasoning-result",
        {
            "hypothesis_id": hypothesis_id,
            "missing_evidence": sorted(missing_evidence),
            "reasoning_steps": reasoning_steps,
            "supporting_evidence_ids": sorted(supporting_evidence_ids),
        },
    )


class ReasoningResult(DomainModel):
    """Reasoning over referenced evidence, never a verification decision."""

    id: Identifier
    hypothesis_id: Identifier
    reasoning_steps: list[Identifier] = Field(min_length=1)
    supporting_evidence_ids: list[Identifier]
    missing_evidence: list[Identifier]
    confidence: UnitInterval
    boundary_statement: Literal[
        "The result represents reasoning over available evidence. "
        "It is not a vulnerability verification result."
    ] = REASONING_RESULT_BOUNDARY
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("reasoning_steps")
    @classmethod
    def validate_reasoning_steps(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("reasoning steps must be unique")
        return values

    @field_validator("supporting_evidence_ids", "missing_evidence")
    @classmethod
    def normalize_reference_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("reasoning reference lists must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_non_verdict_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "ReasoningResult":
        expected_id = reasoning_result_id(
            hypothesis_id=self.hypothesis_id,
            reasoning_steps=self.reasoning_steps,
            supporting_evidence_ids=self.supporting_evidence_ids,
            missing_evidence=self.missing_evidence,
        )
        if self.id != expected_id:
            raise ValueError("ReasoningResult ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        hypothesis: AttackHypothesis,
        *,
        reasoning_steps: list[str],
        supporting_evidence_ids: list[str],
        missing_evidence: list[str],
        confidence: float,
        metadata: Metadata | None = None,
    ) -> "ReasoningResult":
        """Create a bounded reasoning result linked to one hypothesis."""

        normalized_steps = [item.strip() for item in reasoning_steps]
        normalized_evidence_ids = [
            item.strip() for item in supporting_evidence_ids
        ]
        normalized_missing_evidence = [item.strip() for item in missing_evidence]
        identity = reasoning_result_id(
            hypothesis_id=hypothesis.id,
            reasoning_steps=normalized_steps,
            supporting_evidence_ids=normalized_evidence_ids,
            missing_evidence=normalized_missing_evidence,
        )
        return cls(
            id=identity,
            hypothesis_id=hypothesis.id,
            reasoning_steps=normalized_steps,
            supporting_evidence_ids=normalized_evidence_ids,
            missing_evidence=normalized_missing_evidence,
            confidence=confidence,
            boundary_statement=REASONING_RESULT_BOUNDARY,
            metadata=metadata or {},
        )

    def validate_against(self, hypothesis: AttackHypothesis) -> None:
        """Fail closed if this result belongs to another hypothesis."""

        if self.hypothesis_id != hypothesis.id:
            raise ValueError("ReasoningResult hypothesis identity mismatch")
