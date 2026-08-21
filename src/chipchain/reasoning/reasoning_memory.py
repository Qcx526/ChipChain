"""Deterministic request/feedback memory for Phase 9B2B Step 5."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.reasoning.feedback import (
    EvidenceFeedback,
    validate_reasoning_feedback_metadata,
)
from chipchain.reasoning.hypothesis import (
    AttackHypothesis,
    _canonical_reasoning_id,
)


def reasoning_memory_id(
    *,
    hypothesis_id: str,
    request_ids: list[str],
    feedback_ids: list[str],
) -> str:
    """Build memory identity without time, run, confidence, or metadata."""

    return _canonical_reasoning_id(
        "reasoning-memory",
        {
            "feedback_ids": sorted(feedback_ids),
            "hypothesis_id": hypothesis_id,
            "request_ids": sorted(request_ids),
        },
    )


class ReasoningMemory(DomainModel):
    """Detached feedback memory with no Evidence or verification state."""

    contract: Literal["phase9b2b_reasoning_memory_v1"] = (
        "phase9b2b_reasoning_memory_v1"
    )
    id: Identifier
    hypothesis_id: Identifier
    request_ids: list[Identifier]
    feedback: list[EvidenceFeedback]
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("request_ids")
    @classmethod
    def normalize_request_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("reasoning memory request IDs must be unique")
        return sorted(values)

    @field_validator("feedback")
    @classmethod
    def normalize_feedback(
        cls, values: list[EvidenceFeedback]
    ) -> list[EvidenceFeedback]:
        request_ids = [item.request_id for item in values]
        feedback_ids = [item.id for item in values]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("reasoning memory permits one feedback per request")
        if len(feedback_ids) != len(set(feedback_ids)):
            raise ValueError("reasoning memory feedback IDs must be unique")
        return sorted(values, key=lambda item: item.request_id)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return validate_reasoning_feedback_metadata(value)

    @model_validator(mode="after")
    def validate_memory(self) -> "ReasoningMemory":
        if any(item.hypothesis_id != self.hypothesis_id for item in self.feedback):
            raise ValueError("reasoning memory hypothesis identity mismatch")
        if {item.request_id for item in self.feedback} != set(self.request_ids):
            raise ValueError("reasoning memory requires feedback for every request")
        expected_id = reasoning_memory_id(
            hypothesis_id=self.hypothesis_id,
            request_ids=self.request_ids,
            feedback_ids=[item.id for item in self.feedback],
        )
        if self.id != expected_id:
            raise ValueError("ReasoningMemory ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        hypothesis: AttackHypothesis,
        feedback: list[EvidenceFeedback],
        *,
        metadata: Metadata | None = None,
    ) -> "ReasoningMemory":
        """Create one detached snapshot from request-level feedback records."""

        snapshots = [
            EvidenceFeedback.model_validate(item.model_dump(mode="json"))
            for item in feedback
        ]
        request_ids = [item.request_id for item in snapshots]
        identity = reasoning_memory_id(
            hypothesis_id=hypothesis.id,
            request_ids=request_ids,
            feedback_ids=[item.id for item in snapshots],
        )
        return cls(
            id=identity,
            hypothesis_id=hypothesis.id,
            request_ids=request_ids,
            feedback=snapshots,
            metadata=metadata or {},
        )

    def feedback_for(self, request_id: str) -> EvidenceFeedback:
        """Return detached feedback for one request, failing closed if absent."""

        for item in self.feedback:
            if item.request_id == request_id:
                return EvidenceFeedback.model_validate(
                    item.model_dump(mode="json")
                )
        raise KeyError(f"reasoning memory has no request {request_id!r}")
