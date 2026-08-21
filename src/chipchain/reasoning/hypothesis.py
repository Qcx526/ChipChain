"""Unverified attack-hypothesis contract for Phase 9B2B."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier, Metadata, UnitInterval
from chipchain.reasoning.enums import EvidenceCategory, HypothesisSource


SupportedReasoningArchitecture = Literal[Architecture.ARM]

_FORBIDDEN_VERDICT_FIELDS = {
    "attackchainstatus",
    "attackchainverified",
    "attackchainverifiedstatus",
    "attackchainverdict",
    "causalitystatus",
    "causalityverdict",
    "interactionstatus",
    "interactionverificationstatus",
    "verificationscore",
    "verificationstatus",
    "vulnerabilitystatus",
    "vulnerabilityverdict",
}


def _canonical_reasoning_id(prefix: str, payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(serialized).hexdigest()}"


def _validate_non_verdict_metadata(metadata: Metadata) -> Metadata:
    """Reject verdict fields hidden inside extensible reasoning metadata."""

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized_key = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if normalized_key in _FORBIDDEN_VERDICT_FIELDS:
                    raise ValueError(
                        "reasoning metadata must not contain verdict fields"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(metadata)
    return metadata


def attack_hypothesis_id(
    *,
    source: HypothesisSource,
    architecture: Architecture,
    description: str,
    affected_components: list[str],
    attack_pattern_reference: str | None,
    required_evidence_types: list[EvidenceCategory],
) -> str:
    """Build identity from the proposition, never confidence or metadata."""

    return _canonical_reasoning_id(
        "attack-hypothesis",
        {
            "architecture": architecture.value,
            "attack_pattern_reference": attack_pattern_reference,
            "affected_components": sorted(affected_components),
            "description": description,
            "required_evidence_types": sorted(
                item.value for item in required_evidence_types
            ),
            "source": source.value,
        },
    )


class AttackHypothesis(DomainModel):
    """A possible attack proposition, never a vulnerability conclusion."""

    id: Identifier
    source: HypothesisSource
    architecture: SupportedReasoningArchitecture
    description: Identifier
    affected_components: list[Identifier] = Field(min_length=1)
    attack_pattern_reference: Identifier | None = None
    required_evidence_types: list[EvidenceCategory] = Field(min_length=1)
    confidence: UnitInterval
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("affected_components")
    @classmethod
    def normalize_components(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("affected components must be unique")
        return sorted(values)

    @field_validator("required_evidence_types")
    @classmethod
    def normalize_evidence_types(
        cls, values: list[EvidenceCategory]
    ) -> list[EvidenceCategory]:
        if len(values) != len(set(values)):
            raise ValueError("required evidence types must be unique")
        return sorted(values, key=lambda item: item.value)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_non_verdict_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "AttackHypothesis":
        expected_id = attack_hypothesis_id(
            source=self.source,
            architecture=self.architecture,
            description=self.description,
            affected_components=self.affected_components,
            attack_pattern_reference=self.attack_pattern_reference,
            required_evidence_types=self.required_evidence_types,
        )
        if self.id != expected_id:
            raise ValueError("AttackHypothesis ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        source: HypothesisSource | str,
        architecture: Architecture | str,
        description: str,
        affected_components: list[str],
        required_evidence_types: list[EvidenceCategory | str],
        confidence: float,
        attack_pattern_reference: str | None = None,
        metadata: Metadata | None = None,
    ) -> "AttackHypothesis":
        """Create one deterministic, explicitly unverified hypothesis."""

        normalized_source = HypothesisSource(source)
        normalized_architecture = Architecture(architecture)
        normalized_description = description.strip()
        normalized_components = [item.strip() for item in affected_components]
        normalized_reference = (
            attack_pattern_reference.strip()
            if attack_pattern_reference is not None
            else None
        )
        normalized_evidence_types = [
            EvidenceCategory(item) for item in required_evidence_types
        ]
        identity = attack_hypothesis_id(
            source=normalized_source,
            architecture=normalized_architecture,
            description=normalized_description,
            affected_components=normalized_components,
            attack_pattern_reference=normalized_reference,
            required_evidence_types=normalized_evidence_types,
        )
        return cls(
            id=identity,
            source=normalized_source,
            architecture=normalized_architecture,
            description=normalized_description,
            affected_components=normalized_components,
            attack_pattern_reference=normalized_reference,
            required_evidence_types=normalized_evidence_types,
            confidence=confidence,
            metadata=metadata or {},
        )
