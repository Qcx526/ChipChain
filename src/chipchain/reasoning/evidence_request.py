"""Evidence-request contract for evaluating an unverified hypothesis."""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.reasoning.enums import EvidenceCategory, EvidencePriority
from chipchain.reasoning.hypothesis import (
    AttackHypothesis,
    _canonical_reasoning_id,
    _validate_non_verdict_metadata,
)


def evidence_request_id(
    *,
    hypothesis_id: str,
    evidence_type: EvidenceCategory,
    required_fact: str,
    dynamic_trigger_fact_reference: str | None,
    priority: EvidencePriority,
) -> str:
    """Build a deterministic request identity without mutable metadata."""

    return _canonical_reasoning_id(
        "evidence-request",
        {
            "dynamic_trigger_fact_reference": dynamic_trigger_fact_reference,
            "evidence_type": evidence_type.value,
            "hypothesis_id": hypothesis_id,
            "priority": priority.value,
            "required_fact": required_fact,
        },
    )


class EvidenceRequest(DomainModel):
    """A request for evidence; absence is not evidence of vulnerability absence."""

    id: Identifier
    hypothesis_id: Identifier
    evidence_type: EvidenceCategory
    required_fact: Identifier
    dynamic_trigger_fact_reference: Identifier | None = None
    priority: EvidencePriority
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_non_verdict_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "EvidenceRequest":
        expected_id = evidence_request_id(
            hypothesis_id=self.hypothesis_id,
            evidence_type=self.evidence_type,
            required_fact=self.required_fact,
            dynamic_trigger_fact_reference=self.dynamic_trigger_fact_reference,
            priority=self.priority,
        )
        if self.id != expected_id:
            raise ValueError("EvidenceRequest ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        hypothesis: AttackHypothesis,
        *,
        evidence_type: EvidenceCategory | str,
        required_fact: str,
        priority: EvidencePriority | str,
        dynamic_trigger_fact_reference: str | None = None,
        metadata: Metadata | None = None,
    ) -> "EvidenceRequest":
        """Create a request linked to one hypothesis without producing Evidence."""

        normalized_type = EvidenceCategory(evidence_type)
        normalized_priority = EvidencePriority(priority)
        normalized_fact = required_fact.strip()
        normalized_trigger_reference = (
            dynamic_trigger_fact_reference.strip()
            if dynamic_trigger_fact_reference is not None
            else None
        )
        if normalized_type not in hypothesis.required_evidence_types:
            raise ValueError(
                "requested evidence type is outside hypothesis requirements"
            )
        identity = evidence_request_id(
            hypothesis_id=hypothesis.id,
            evidence_type=normalized_type,
            required_fact=normalized_fact,
            dynamic_trigger_fact_reference=normalized_trigger_reference,
            priority=normalized_priority,
        )
        return cls(
            id=identity,
            hypothesis_id=hypothesis.id,
            evidence_type=normalized_type,
            required_fact=normalized_fact,
            dynamic_trigger_fact_reference=normalized_trigger_reference,
            priority=normalized_priority,
            metadata=metadata or {},
        )

    def validate_against(self, hypothesis: AttackHypothesis) -> None:
        """Fail closed if this request is attached to another hypothesis."""

        if self.hypothesis_id != hypothesis.id:
            raise ValueError("EvidenceRequest hypothesis identity mismatch")
        if self.evidence_type not in hypothesis.required_evidence_types:
            raise ValueError(
                "requested evidence type is outside hypothesis requirements"
            )
