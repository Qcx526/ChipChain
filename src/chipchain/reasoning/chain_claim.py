"""Explicit model-authored, non-verifying cross-layer claim contract."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.cross_layer import CrossLayerInteractionType
from chipchain.models.enums import Architecture
from chipchain.reasoning.enums import ReasoningAgentType


SupportedClaimArchitecture = Literal[Architecture.ARM]

_CLAIM_LIST_FIELDS = (
    "initiating_vulnerability_ids",
    "target_vulnerability_ids",
    "trigger_behavior_ids",
    "propagation_behavior_ids",
    "affected_execution_ids",
    "fault_state_ids",
    "hardware_resource_ids",
    "security_mechanism_ids",
)
_FORBIDDEN_CLAIM_METADATA_FRAGMENTS = (
    "attackchain",
    "causality",
    "confidence",
    "feasibility",
    "probability",
    "score",
    "verification",
    "verified",
    "verdict",
    "vulnerabilitystatus",
)


def model_authored_chain_claim_id(
    *,
    architecture: Architecture,
    author_role: ReasoningAgentType,
    interaction_type: CrossLayerInteractionType,
    initiating_vulnerability_ids: list[str],
    target_vulnerability_ids: list[str],
    trigger_behavior_ids: list[str],
    propagation_behavior_ids: list[str],
    affected_execution_ids: list[str],
    fault_state_ids: list[str],
    hardware_resource_ids: list[str],
    security_mechanism_ids: list[str],
) -> str:
    """Build claim identity from model-authored semantics only."""

    payload = {
        "affected_execution_ids": sorted(affected_execution_ids),
        "architecture": Architecture(architecture).value,
        "author_role": ReasoningAgentType(author_role).value,
        "fault_state_ids": sorted(fault_state_ids),
        "hardware_resource_ids": sorted(hardware_resource_ids),
        "initiating_vulnerability_ids": sorted(
            initiating_vulnerability_ids
        ),
        "interaction_type": CrossLayerInteractionType(
            interaction_type
        ).value,
        "propagation_behavior_ids": sorted(propagation_behavior_ids),
        "security_mechanism_ids": sorted(security_mechanism_ids),
        "target_vulnerability_ids": sorted(target_vulnerability_ids),
        "trigger_behavior_ids": sorted(trigger_behavior_ids),
    }
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"model-authored-chain-claim:{hashlib.sha256(serialized).hexdigest()}"


def _validate_claim_metadata(metadata: Metadata) -> Metadata:
    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if any(
                    fragment in normalized
                    for fragment in _FORBIDDEN_CLAIM_METADATA_FRAGMENTS
                ):
                    raise ValueError(
                        "model-authored claim metadata must not contain verdict fields"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(metadata)
    return metadata


class ModelAuthoredChainClaim(DomainModel):
    """A model proposal that deliberately does not enforce domain truth shape."""

    id: Identifier
    architecture: SupportedClaimArchitecture
    author_role: ReasoningAgentType
    interaction_type: CrossLayerInteractionType
    initiating_vulnerability_ids: list[Identifier] = Field(default_factory=list)
    target_vulnerability_ids: list[Identifier] = Field(default_factory=list)
    trigger_behavior_ids: list[Identifier] = Field(default_factory=list)
    propagation_behavior_ids: list[Identifier] = Field(default_factory=list)
    affected_execution_ids: list[Identifier] = Field(default_factory=list)
    fault_state_ids: list[Identifier] = Field(default_factory=list)
    hardware_resource_ids: list[Identifier] = Field(default_factory=list)
    security_mechanism_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(*_CLAIM_LIST_FIELDS)
    @classmethod
    def normalize_reference_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("model-authored claim reference IDs must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_claim_metadata(value)

    @model_validator(mode="after")
    def validate_role_and_identity(self) -> "ModelAuthoredChainClaim":
        if self.author_role is not ReasoningAgentType.ATTACK_CHAIN:
            raise ValueError(
                "model-authored chain claims require the attack_chain role"
            )
        expected_id = model_authored_chain_claim_id(
            architecture=self.architecture,
            author_role=self.author_role,
            interaction_type=self.interaction_type,
            initiating_vulnerability_ids=self.initiating_vulnerability_ids,
            target_vulnerability_ids=self.target_vulnerability_ids,
            trigger_behavior_ids=self.trigger_behavior_ids,
            propagation_behavior_ids=self.propagation_behavior_ids,
            affected_execution_ids=self.affected_execution_ids,
            fault_state_ids=self.fault_state_ids,
            hardware_resource_ids=self.hardware_resource_ids,
            security_mechanism_ids=self.security_mechanism_ids,
        )
        if self.id != expected_id:
            raise ValueError("ModelAuthoredChainClaim ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        architecture: Architecture | str,
        author_role: ReasoningAgentType | str,
        interaction_type: CrossLayerInteractionType | str,
        initiating_vulnerability_ids: list[str] | None = None,
        target_vulnerability_ids: list[str] | None = None,
        trigger_behavior_ids: list[str] | None = None,
        propagation_behavior_ids: list[str] | None = None,
        affected_execution_ids: list[str] | None = None,
        fault_state_ids: list[str] | None = None,
        hardware_resource_ids: list[str] | None = None,
        security_mechanism_ids: list[str] | None = None,
        metadata: Metadata | None = None,
    ) -> "ModelAuthoredChainClaim":
        """Create a structurally valid proposal without repairing semantics."""

        normalized_architecture = Architecture(architecture)
        normalized_role = ReasoningAgentType(author_role)
        normalized_type = CrossLayerInteractionType(interaction_type)
        references = {
            "initiating_vulnerability_ids": initiating_vulnerability_ids or [],
            "target_vulnerability_ids": target_vulnerability_ids or [],
            "trigger_behavior_ids": trigger_behavior_ids or [],
            "propagation_behavior_ids": propagation_behavior_ids or [],
            "affected_execution_ids": affected_execution_ids or [],
            "fault_state_ids": fault_state_ids or [],
            "hardware_resource_ids": hardware_resource_ids or [],
            "security_mechanism_ids": security_mechanism_ids or [],
        }
        identity = model_authored_chain_claim_id(
            architecture=normalized_architecture,
            author_role=normalized_role,
            interaction_type=normalized_type,
            **references,
        )
        return cls(
            id=identity,
            architecture=normalized_architecture,
            author_role=normalized_role,
            interaction_type=normalized_type,
            metadata=metadata or {},
            **references,
        )
