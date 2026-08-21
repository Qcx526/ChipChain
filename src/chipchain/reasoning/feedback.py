"""Reference-only observation feedback contracts for Phase 9B2B Step 5."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.reasoning.enums import EvidenceCategory
from chipchain.reasoning.evidence_request import EvidenceRequest
from chipchain.reasoning.hypothesis import (
    AttackHypothesis,
    _canonical_reasoning_id,
    _validate_non_verdict_metadata,
)


class ObservationFeedbackRelation(str, Enum):
    """Declared relation between one observation and one requested fact."""

    MATCH = "match"
    CONTRADICT = "contradict"
    INCONCLUSIVE = "inconclusive"


class EvidenceFeedbackStatus(str, Enum):
    """Non-verifying outcomes of comparing observations with one request."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


_FEEDBACK_DETAILS = {
    EvidenceFeedbackStatus.SUPPORTED: (
        "At least one supplied observation matches the requested fact."
    ),
    EvidenceFeedbackStatus.UNSUPPORTED: (
        "Supplied observations contradict the requested fact without a match."
    ),
    EvidenceFeedbackStatus.UNKNOWN: (
        "No conclusive observation was supplied for the requested fact."
    ),
    EvidenceFeedbackStatus.CONFLICT: (
        "Supplied observations both match and contradict the requested fact."
    ),
}
_FORBIDDEN_FEEDBACK_METADATA_FIELDS = frozenset(
    {
        "attackchain",
        "behavioredge",
        "evidence",
        "evidenceid",
        "evidenceids",
        "verificationrecord",
    }
)


def validate_reasoning_feedback_metadata(metadata: Metadata) -> Metadata:
    """Reject domain objects hidden inside observation-feedback metadata."""

    _validate_non_verdict_metadata(metadata)

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized_key = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if normalized_key in _FORBIDDEN_FEEDBACK_METADATA_FIELDS:
                    raise ValueError(
                        "feedback metadata must not contain domain truth objects"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(metadata)
    return metadata


def reasoning_observation_id(
    *,
    source_observation_id: str,
    request_id: str,
    architecture: Architecture,
    evidence_type: EvidenceCategory,
    observed_fact: str,
    relation: ObservationFeedbackRelation,
) -> str:
    """Build identity without timestamps, metadata, or verification fields."""

    return _canonical_reasoning_id(
        "reasoning-observation",
        {
            "architecture": architecture.value,
            "evidence_type": evidence_type.value,
            "observed_fact": observed_fact,
            "relation": relation.value,
            "request_id": request_id,
            "source_observation_id": source_observation_id,
        },
    )


class ReasoningObservation(DomainModel):
    """Detached observation reference assessed against one requested fact."""

    id: Identifier
    source_observation_id: Identifier
    request_id: Identifier
    architecture: Architecture
    evidence_type: EvidenceCategory
    observed_fact: Identifier
    relation: ObservationFeedbackRelation
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return validate_reasoning_feedback_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "ReasoningObservation":
        expected_id = reasoning_observation_id(
            source_observation_id=self.source_observation_id,
            request_id=self.request_id,
            architecture=self.architecture,
            evidence_type=self.evidence_type,
            observed_fact=self.observed_fact,
            relation=self.relation,
        )
        if self.id != expected_id:
            raise ValueError("ReasoningObservation ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        source_observation_id: str,
        request: EvidenceRequest,
        architecture: Architecture | str,
        observed_fact: str,
        relation: ObservationFeedbackRelation | str,
        metadata: Metadata | None = None,
    ) -> "ReasoningObservation":
        """Create a detached comparison without creating an Evidence object."""

        normalized_source_id = source_observation_id.strip()
        normalized_architecture = Architecture(architecture)
        normalized_fact = observed_fact.strip()
        normalized_relation = ObservationFeedbackRelation(relation)
        identity = reasoning_observation_id(
            source_observation_id=normalized_source_id,
            request_id=request.id,
            architecture=normalized_architecture,
            evidence_type=request.evidence_type,
            observed_fact=normalized_fact,
            relation=normalized_relation,
        )
        return cls(
            id=identity,
            source_observation_id=normalized_source_id,
            request_id=request.id,
            architecture=normalized_architecture,
            evidence_type=request.evidence_type,
            observed_fact=normalized_fact,
            relation=normalized_relation,
            metadata=metadata or {},
        )


def evidence_feedback_status(
    *,
    matched_observation_ids: list[str],
    contradicted_observation_ids: list[str],
) -> EvidenceFeedbackStatus:
    """Derive feedback status without mapping it to verification semantics."""

    if matched_observation_ids and contradicted_observation_ids:
        return EvidenceFeedbackStatus.CONFLICT
    if matched_observation_ids:
        return EvidenceFeedbackStatus.SUPPORTED
    if contradicted_observation_ids:
        return EvidenceFeedbackStatus.UNSUPPORTED
    return EvidenceFeedbackStatus.UNKNOWN


def evidence_feedback_id(
    *,
    hypothesis_id: str,
    request_id: str,
    status: EvidenceFeedbackStatus,
    observation_ids: list[str],
    matched_observation_ids: list[str],
    contradicted_observation_ids: list[str],
    inconclusive_observation_ids: list[str],
) -> str:
    """Build deterministic identity for one request-level feedback record."""

    return _canonical_reasoning_id(
        "evidence-feedback",
        {
            "contradicted_observation_ids": sorted(
                contradicted_observation_ids
            ),
            "hypothesis_id": hypothesis_id,
            "inconclusive_observation_ids": sorted(
                inconclusive_observation_ids
            ),
            "matched_observation_ids": sorted(matched_observation_ids),
            "observation_ids": sorted(observation_ids),
            "request_id": request_id,
            "status": status.value,
        },
    )


class EvidenceFeedback(DomainModel):
    """Observation feedback for one request, never verification or Evidence."""

    contract: Literal["phase9b2b_evidence_feedback_v1"] = (
        "phase9b2b_evidence_feedback_v1"
    )
    id: Identifier
    hypothesis_id: Identifier
    request_id: Identifier
    status: EvidenceFeedbackStatus
    observation_ids: list[Identifier] = Field(default_factory=list)
    matched_observation_ids: list[Identifier] = Field(default_factory=list)
    contradicted_observation_ids: list[Identifier] = Field(default_factory=list)
    inconclusive_observation_ids: list[Identifier] = Field(default_factory=list)
    detail: Literal[
        "At least one supplied observation matches the requested fact.",
        "Supplied observations contradict the requested fact without a match.",
        "No conclusive observation was supplied for the requested fact.",
        "Supplied observations both match and contradict the requested fact.",
    ]
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "observation_ids",
        "matched_observation_ids",
        "contradicted_observation_ids",
        "inconclusive_observation_ids",
    )
    @classmethod
    def normalize_observation_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("feedback observation IDs must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return validate_reasoning_feedback_metadata(value)

    @model_validator(mode="after")
    def validate_feedback(self) -> "EvidenceFeedback":
        partitions = (
            set(self.matched_observation_ids),
            set(self.contradicted_observation_ids),
            set(self.inconclusive_observation_ids),
        )
        if any(
            left.intersection(right)
            for index, left in enumerate(partitions)
            for right in partitions[index + 1 :]
        ):
            raise ValueError("feedback observation partitions must be disjoint")
        if set().union(*partitions) != set(self.observation_ids):
            raise ValueError("feedback observation partitions must be complete")
        expected_status = evidence_feedback_status(
            matched_observation_ids=self.matched_observation_ids,
            contradicted_observation_ids=self.contradicted_observation_ids,
        )
        if self.status is not expected_status:
            raise ValueError("EvidenceFeedback status is inconsistent")
        if self.detail != _FEEDBACK_DETAILS[expected_status]:
            raise ValueError("EvidenceFeedback detail is inconsistent")
        expected_id = evidence_feedback_id(
            hypothesis_id=self.hypothesis_id,
            request_id=self.request_id,
            status=self.status,
            observation_ids=self.observation_ids,
            matched_observation_ids=self.matched_observation_ids,
            contradicted_observation_ids=self.contradicted_observation_ids,
            inconclusive_observation_ids=self.inconclusive_observation_ids,
        )
        if self.id != expected_id:
            raise ValueError("EvidenceFeedback ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        hypothesis: AttackHypothesis,
        request: EvidenceRequest,
        observations: list[ReasoningObservation],
        *,
        metadata: Metadata | None = None,
    ) -> "EvidenceFeedback":
        """Aggregate explicit observation relations for one request."""

        request.validate_against(hypothesis)
        snapshots = [
            ReasoningObservation.model_validate(item.model_dump(mode="json"))
            for item in observations
        ]
        observation_ids = [item.id for item in snapshots]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("feedback observations must not contain duplicates")
        for observation in snapshots:
            if observation.request_id != request.id:
                raise ValueError("observation request identity mismatch")
            if observation.architecture is not hypothesis.architecture:
                raise ValueError("observation architecture mismatch")
            if observation.evidence_type is not request.evidence_type:
                raise ValueError("observation evidence category mismatch")
            if (
                observation.relation is ObservationFeedbackRelation.MATCH
                and observation.observed_fact != request.required_fact
            ):
                raise ValueError(
                    "matching observation must equal the requested fact"
                )
            if (
                observation.relation is ObservationFeedbackRelation.CONTRADICT
                and observation.observed_fact == request.required_fact
            ):
                raise ValueError(
                    "contradicting observation must differ from the requested fact"
                )
        matched_ids = [
            item.id
            for item in snapshots
            if item.relation is ObservationFeedbackRelation.MATCH
        ]
        contradicted_ids = [
            item.id
            for item in snapshots
            if item.relation is ObservationFeedbackRelation.CONTRADICT
        ]
        inconclusive_ids = [
            item.id
            for item in snapshots
            if item.relation is ObservationFeedbackRelation.INCONCLUSIVE
        ]
        status = evidence_feedback_status(
            matched_observation_ids=matched_ids,
            contradicted_observation_ids=contradicted_ids,
        )
        identity = evidence_feedback_id(
            hypothesis_id=hypothesis.id,
            request_id=request.id,
            status=status,
            observation_ids=observation_ids,
            matched_observation_ids=matched_ids,
            contradicted_observation_ids=contradicted_ids,
            inconclusive_observation_ids=inconclusive_ids,
        )
        return cls(
            id=identity,
            hypothesis_id=hypothesis.id,
            request_id=request.id,
            status=status,
            observation_ids=observation_ids,
            matched_observation_ids=matched_ids,
            contradicted_observation_ids=contradicted_ids,
            inconclusive_observation_ids=inconclusive_ids,
            detail=_FEEDBACK_DETAILS[status],
            metadata=metadata or {},
        )
