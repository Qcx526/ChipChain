"""Strict serializable contracts for Phase 9A-R interaction verification."""

from __future__ import annotations

import hashlib
import json
import re

from pydantic import Field, field_validator, model_validator

from chipchain.models import (
    Architecture,
    CrossLayerDirection,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    CrossLayerLocationRole,
    RelationType,
)
from chipchain.models.common import DomainModel, Identifier, Metadata, UnitInterval
from chipchain.verification.enums import (
    ConditionKind,
    ConditionStatus,
    InteractionReferenceRole,
    InteractionSourceKind,
    InteractionVerificationStatus,
    LocationFindingStatus,
    RequiredFactCategory,
    VerificationCapabilityStatus,
    VerificationStatus,
    VerificationSubjectKind,
)

_HEX_ADDRESS = re.compile(r"^0[xX][0-9a-fA-F]+$")


def _sorted_unique(values: list[str], label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")
    return sorted(values)


class ProgramAddress(DomainModel):
    """Canonical program/instruction address namespace."""

    value: Identifier

    @field_validator("value", mode="before")
    @classmethod
    def normalize(cls, value: object) -> str:
        if not isinstance(value, str) or not _HEX_ADDRESS.fullmatch(value.strip()):
            raise ValueError("program address must be a hexadecimal string")
        return hex(int(value, 16))


class HardwareAddress(DomainModel):
    """Canonical hardware/MMIO address namespace."""

    value: Identifier

    @field_validator("value", mode="before")
    @classmethod
    def normalize(cls, value: object) -> str:
        if not isinstance(value, str) or not _HEX_ADDRESS.fullmatch(value.strip()):
            raise ValueError("hardware address must be a hexadecimal string")
        return hex(int(value, 16))


def verification_record_id(
    interaction_id: str,
    architecture: Architecture,
    subject_kind: VerificationSubjectKind,
    subject_id: str,
    verifier: str,
) -> str:
    material = [interaction_id, architecture.value, subject_kind.value, subject_id, verifier]
    digest = hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).hexdigest()[:24]
    return f"verification:{subject_kind.value}:{digest}"


class VerificationRecord(DomainModel):
    """One objective decision tied to exactly one interaction."""

    id: Identifier
    interaction_id: Identifier
    architecture: Architecture
    subject_kind: VerificationSubjectKind
    subject_id: Identifier
    status: VerificationStatus
    verifier: Identifier
    evidence_ids: list[Identifier] = Field(default_factory=list)
    supporting_evidence_ids: list[Identifier] = Field(default_factory=list)
    rule_ids: list[Identifier] = Field(default_factory=list)
    messages: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("evidence_ids", "supporting_evidence_ids", "rule_ids", "messages")
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "verification record lists")

    @model_validator(mode="after")
    def validate_identity(self) -> "VerificationRecord":
        if self.id != verification_record_id(
            self.interaction_id, self.architecture, self.subject_kind, self.subject_id, self.verifier
        ):
            raise ValueError("VerificationRecord ID is not deterministic")
        if not set(self.supporting_evidence_ids).issubset(self.evidence_ids):
            raise ValueError("supporting Evidence IDs must be a subset of inspected Evidence IDs")
        if self.status is not VerificationStatus.VERIFIED and self.supporting_evidence_ids:
            raise ValueError("UNKNOWN or REJECTED records cannot have supporting Evidence")
        return self

    @classmethod
    def create(cls, *, interaction_id: str, architecture: Architecture,
               subject_kind: VerificationSubjectKind, subject_id: str,
               status: VerificationStatus, verifier: str,
               evidence_ids: list[str] | None = None,
               supporting_evidence_ids: list[str] | None = None,
               rule_ids: list[str] | None = None,
               messages: list[str] | None = None, metadata: Metadata | None = None) -> "VerificationRecord":
        return cls(
            id=verification_record_id(interaction_id, architecture, subject_kind, subject_id, verifier),
            interaction_id=interaction_id, architecture=architecture, subject_kind=subject_kind,
            subject_id=subject_id, status=status, verifier=verifier,
            evidence_ids=evidence_ids or [],
            supporting_evidence_ids=supporting_evidence_ids or [], rule_ids=rule_ids or [],
            messages=messages or [], metadata=metadata or {},
        )


class InteractionReferenceBinding(DomainModel):
    """Explicit mapping from an interaction role reference to a source fact."""

    interaction_reference_id: Identifier
    reference_role: InteractionReferenceRole
    source_kind: InteractionSourceKind
    source_id: Identifier
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_source_kind(self) -> "InteractionReferenceBinding":
        allowed = {
            InteractionReferenceRole.INITIATING_VULNERABILITY: {InteractionSourceKind.KNOWLEDGE_NODE, InteractionSourceKind.EVIDENCE},
            InteractionReferenceRole.TARGET_VULNERABILITY: {InteractionSourceKind.KNOWLEDGE_NODE, InteractionSourceKind.EVIDENCE},
            InteractionReferenceRole.TRIGGER_BEHAVIOR: {InteractionSourceKind.BEHAVIOR_EDGE, InteractionSourceKind.BEHAVIOR_NODE, InteractionSourceKind.EVIDENCE},
            InteractionReferenceRole.PROPAGATION_BEHAVIOR: {InteractionSourceKind.BEHAVIOR_EDGE, InteractionSourceKind.BEHAVIOR_NODE, InteractionSourceKind.EVIDENCE},
            InteractionReferenceRole.AFFECTED_EXECUTION: {InteractionSourceKind.BEHAVIOR_NODE, InteractionSourceKind.EVIDENCE},
            InteractionReferenceRole.FAULT_STATE: {InteractionSourceKind.KNOWLEDGE_NODE, InteractionSourceKind.EVIDENCE},
            InteractionReferenceRole.HARDWARE_RESOURCE: {InteractionSourceKind.BEHAVIOR_NODE, InteractionSourceKind.KNOWLEDGE_NODE, InteractionSourceKind.ENTITY_LINK},
            InteractionReferenceRole.SECURITY_MECHANISM: {InteractionSourceKind.KNOWLEDGE_NODE, InteractionSourceKind.EVIDENCE},
        }
        if self.source_kind not in allowed[self.reference_role]:
            raise ValueError("source kind is not allowed for the interaction reference role")
        return self


class InteractionConditionBinding(DomainModel):
    """Explicitly scoped condition; legacy context is advisory unless bound."""

    condition_node_id: Identifier
    condition_kind: ConditionKind
    applies_to_role: CrossLayerLocationRole | None = None
    required: bool = True
    metadata: Metadata = Field(default_factory=dict)


class InteractionVerificationInput(DomainModel):
    """Serializable verification request; repositories remain runtime dependencies."""

    interaction_id: Identifier
    architecture: Architecture
    interaction_type: CrossLayerInteractionType
    direction: CrossLayerDirection
    bindings: list[InteractionReferenceBinding] = Field(default_factory=list)
    condition_bindings: list[InteractionConditionBinding] = Field(default_factory=list)
    legacy_candidate_id: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_unique_bindings(self) -> "InteractionVerificationInput":
        keys = [(b.reference_role, b.interaction_reference_id) for b in self.bindings]
        if len(keys) != len(set(keys)):
            raise ValueError(
                "each interaction reference may have only one source binding in Phase 9A-R MVP"
            )
        condition_ids = [b.condition_node_id for b in self.condition_bindings]
        if len(condition_ids) != len(set(condition_ids)):
            raise ValueError("condition bindings must be unique")
        return self

    @classmethod
    def create(cls, interaction: CrossLayerInteraction, *,
               bindings: list[InteractionReferenceBinding] | None = None,
               condition_bindings: list[InteractionConditionBinding] | None = None,
               legacy_candidate_id: str | None = None,
               metadata: Metadata | None = None) -> "InteractionVerificationInput":
        value = cls(interaction_id=interaction.id, architecture=interaction.architecture,
                    interaction_type=interaction.interaction_type, direction=interaction.direction,
                    bindings=bindings or [], condition_bindings=condition_bindings or [],
                    legacy_candidate_id=legacy_candidate_id, metadata=metadata or {})
        value.validate_against(interaction)
        return value

    def validate_against(self, interaction: CrossLayerInteraction) -> None:
        from chipchain.verification.bindings import validate_reference_bindings

        if (self.interaction_id, self.architecture, self.interaction_type, self.direction) != (
            interaction.id, interaction.architecture, interaction.interaction_type, interaction.direction
        ):
            raise ValueError("verification input identity does not match interaction")
        validate_reference_bindings(interaction, self.bindings)


class ConditionAssessment(DomainModel):
    interaction_id: Identifier
    architecture: Architecture
    condition_node_id: Identifier
    condition_kind: ConditionKind
    applies_to_role: CrossLayerLocationRole | None = None
    required: bool = True
    status: ConditionStatus
    supporting_evidence_ids: list[Identifier] = Field(default_factory=list)
    contradicting_evidence_ids: list[Identifier] = Field(default_factory=list)
    rule_ids: list[Identifier] = Field(default_factory=list)
    messages: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("supporting_evidence_ids", "contradicting_evidence_ids", "rule_ids", "messages")
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "condition assessment lists")


class TriggerFeatureProvenance(DomainModel):
    feature_id: Identifier
    source_kind: Identifier
    source_id: Identifier
    source_field: Identifier


class CrossLayerTriggerFeatureSet(DomainModel):
    interaction_id: Identifier
    architecture: Architecture
    interaction_type: CrossLayerInteractionType
    direction: CrossLayerDirection
    trigger_behavior_ids: list[Identifier] = Field(default_factory=list)
    propagation_behavior_ids: list[Identifier] = Field(default_factory=list)
    fault_state_ids: list[Identifier] = Field(default_factory=list)
    affected_execution_ids: list[Identifier] = Field(default_factory=list)
    behavior_relation_sequence: list[RelationType] = Field(default_factory=list)
    interface_identifiers: list[Identifier] = Field(default_factory=list)
    hardware_addresses: list[HardwareAddress] = Field(default_factory=list)
    memory_map_ids: list[Identifier] = Field(default_factory=list)
    memory_map_regions: list[Identifier] = Field(default_factory=list)
    mmio_access_types: list[RelationType] = Field(default_factory=list)
    trigger_inputs: list[Identifier] = Field(default_factory=list)
    trigger_events: list[Identifier] = Field(default_factory=list)
    required_privileges: list[Identifier] = Field(default_factory=list)
    required_security_states: list[Identifier] = Field(default_factory=list)
    required_configurations: list[Identifier] = Field(default_factory=list)
    security_mechanism_ids: list[Identifier] = Field(default_factory=list)
    cwe_ids: list[Identifier] = Field(default_factory=list)
    capec_ids: list[Identifier] = Field(default_factory=list)
    unresolved_feature_ids: list[Identifier] = Field(default_factory=list)
    provenance: list[TriggerFeatureProvenance] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("trigger_behavior_ids", "propagation_behavior_ids", "fault_state_ids", "affected_execution_ids",
                     "interface_identifiers", "memory_map_ids", "memory_map_regions", "trigger_inputs", "trigger_events",
                     "required_privileges", "required_security_states", "required_configurations", "security_mechanism_ids",
                     "cwe_ids", "capec_ids", "unresolved_feature_ids")
    @classmethod
    def normalize_strings(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "trigger feature lists")

    @model_validator(mode="after")
    def validate_complete_provenance(self) -> "CrossLayerTriggerFeatureSet":
        keys = [
            (item.feature_id, item.source_kind, item.source_id, item.source_field)
            for item in self.provenance
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("trigger feature provenance entries must be unique")
        covered = {item.feature_id for item in self.provenance}
        required = {
            *(f"trigger_behavior:{item}" for item in self.trigger_behavior_ids),
            *(f"propagation_behavior:{item}" for item in self.propagation_behavior_ids),
            *(f"fault_state:{item}" for item in self.fault_state_ids),
            *(f"affected_execution:{item}" for item in self.affected_execution_ids),
            *(f"behavior_relation:{item.value}" for item in self.behavior_relation_sequence),
            *(f"interface:{item}" for item in self.interface_identifiers),
            *(f"hardware_address:{item.value}" for item in self.hardware_addresses),
            *(f"memory_map_id:{item}" for item in self.memory_map_ids),
            *(f"memory_map_region:{item}" for item in self.memory_map_regions),
            *(f"mmio_access:{item.value}" for item in self.mmio_access_types),
            *(f"trigger_input:{item}" for item in self.trigger_inputs),
            *(f"trigger_event:{item}" for item in self.trigger_events),
            *(f"required_privilege:{item}" for item in self.required_privileges),
            *(f"required_security_state:{item}" for item in self.required_security_states),
            *(f"required_configuration:{item}" for item in self.required_configurations),
            *(f"security_mechanism:{item}" for item in self.security_mechanism_ids),
            *(f"cwe:{item}" for item in self.cwe_ids),
            *(f"capec:{item}" for item in self.capec_ids),
            *self.unresolved_feature_ids,
        }
        missing = required.difference(covered)
        if missing:
            raise ValueError("every trigger feature must have structured provenance")
        self.provenance.sort(
            key=lambda item: (
                item.feature_id,
                item.source_kind,
                item.source_id,
                item.source_field,
            )
        )
        return self


class ObjectiveEvidenceInventory(DomainModel):
    required_evidence_count: int = Field(ge=0)
    resolved_evidence_count: int = Field(ge=0)
    verified_non_llm_evidence_count: int = Field(ge=0)
    unknown_evidence_count: int = Field(ge=0)
    rejected_evidence_count: int = Field(ge=0)
    required_evidence_ids: list[Identifier] = Field(default_factory=list)
    resolved_evidence_ids: list[Identifier] = Field(default_factory=list)
    verified_non_llm_evidence_ids: list[Identifier] = Field(default_factory=list)
    unknown_evidence_ids: list[Identifier] = Field(default_factory=list)
    rejected_evidence_ids: list[Identifier] = Field(default_factory=list)
    required_fact_categories: list[RequiredFactCategory] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_counts(self) -> "ObjectiveEvidenceInventory":
        for count, ids in ((self.required_evidence_count, self.required_evidence_ids),
                           (self.resolved_evidence_count, self.resolved_evidence_ids),
                           (self.verified_non_llm_evidence_count, self.verified_non_llm_evidence_ids),
                           (self.unknown_evidence_count, self.unknown_evidence_ids),
                           (self.rejected_evidence_count, self.rejected_evidence_ids)):
            if count != len(ids):
                raise ValueError("evidence inventory counts must match ID lists")
        return self


class CrossLayerLocationFinding(DomainModel):
    interaction_id: Identifier
    architecture: Architecture
    role: CrossLayerLocationRole
    status: LocationFindingStatus
    source_kind: InteractionSourceKind
    source_id: Identifier
    function_id: Identifier | None = None
    function_name: Identifier | None = None
    program_address: ProgramAddress | None = None
    instruction_address: ProgramAddress | None = None
    hardware_address: HardwareAddress | None = None
    source_file: Identifier | None = None
    source_line: int | None = Field(default=None, ge=1)
    supporting_evidence_ids: list[Identifier] = Field(default_factory=list)
    rule_ids: list[Identifier] = Field(default_factory=list)
    reason_codes: list[Identifier] = Field(default_factory=list)
    contradictions: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)


class VerificationScoreProfile(DomainModel):
    enabled: bool
    weights: dict[Identifier, UnitInterval] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_weights(self) -> "VerificationScoreProfile":
        if self.enabled and (not self.weights or abs(sum(self.weights.values()) - 1.0) > 1e-9):
            raise ValueError("enabled verification score weights must sum exactly to 1.0")
        if not self.enabled and self.weights:
            raise ValueError("disabled verification score profile must not define weights")
        return self


class VerificationScoreConfig(DomainModel):
    profile: Identifier
    llm_objective_weight: UnitInterval
    profiles: dict[CrossLayerInteractionType, VerificationScoreProfile]

    @model_validator(mode="after")
    def validate_profile(self) -> "VerificationScoreConfig":
        if self.profile != "engineering_mvp_uncalibrated" or self.llm_objective_weight != 0.0:
            raise ValueError("verification scoring must be uncalibrated with zero LLM weight")
        if set(self.profiles) != set(CrossLayerInteractionType):
            raise ValueError("score config must declare all interaction types")
        return self


class VerificationScoreResult(DomainModel):
    verification_score: UnitInterval | None
    score_components: dict[Identifier, UnitInterval]
    metadata: Metadata = Field(default_factory=dict)


class InteractionVerificationResult(DomainModel):
    interaction_id: Identifier
    architecture: Architecture
    interaction_type: CrossLayerInteractionType
    direction: CrossLayerDirection
    capability_status: VerificationCapabilityStatus
    legacy_candidate_id: Identifier | None = None
    binding_verifications: list[VerificationRecord] = Field(default_factory=list)
    behavior_edge_verifications: list[VerificationRecord] = Field(default_factory=list)
    entity_link_verifications: list[VerificationRecord] = Field(default_factory=list)
    knowledge_edge_verifications: list[VerificationRecord] = Field(default_factory=list)
    architecture_rule_verifications: list[VerificationRecord] = Field(default_factory=list)
    condition_assessments: list[ConditionAssessment] = Field(default_factory=list)
    required_fact_statuses: dict[RequiredFactCategory, VerificationStatus] = Field(
        default_factory=dict
    )
    trigger_features: CrossLayerTriggerFeatureSet
    evidence_inventory: ObjectiveEvidenceInventory
    verification_score: UnitInterval | None = None
    score_components: dict[Identifier, UnitInterval] = Field(default_factory=dict)
    location_findings: list[CrossLayerLocationFinding] = Field(default_factory=list)
    verification_status: InteractionVerificationStatus | None = None
    advisory_verification_steps: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("advisory_verification_steps")
    @classmethod
    def normalize_advisory_steps(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "advisory steps")

    @model_validator(mode="after")
    def validate_result(self) -> "InteractionVerificationResult":
        if self.capability_status is VerificationCapabilityStatus.NOT_IMPLEMENTED:
            if self.verification_status is not None or self.verification_score is not None or self.score_components:
                raise ValueError("not-implemented verification cannot expose status or score")
        elif self.verification_status is None or self.verification_score is None:
            raise ValueError("implemented verification requires status and score")
        if (
            self.capability_status is VerificationCapabilityStatus.PARTIALLY_SUPPORTED
            and self.verification_status is InteractionVerificationStatus.VERIFIED
        ):
            raise ValueError("partially supported capability cannot claim verified interaction")
        if self.trigger_features.interaction_id != self.interaction_id or self.trigger_features.architecture is not self.architecture:
            raise ValueError("trigger feature identity mismatch")
        if self.trigger_features.interaction_type is not self.interaction_type:
            raise ValueError("trigger feature interaction type mismatch")
        if self.trigger_features.direction is not self.direction:
            raise ValueError("trigger feature direction mismatch")
        record_collections = {
            "binding verifications": self.binding_verifications,
            "behavior edge verifications": self.behavior_edge_verifications,
            "entity link verifications": self.entity_link_verifications,
            "knowledge edge verifications": self.knowledge_edge_verifications,
            "architecture rule verifications": self.architecture_rule_verifications,
        }
        for label, collection in record_collections.items():
            record_ids = [record.id for record in collection]
            if len(record_ids) != len(set(record_ids)):
                raise ValueError(f"{label} must not contain duplicate VerificationRecord IDs")
        binding_subject_ids = [record.subject_id for record in self.binding_verifications]
        if len(binding_subject_ids) != len(set(binding_subject_ids)):
            raise ValueError(
                "binding verifications must not contain duplicate subject IDs"
            )
        records = [record for collection in record_collections.values() for record in collection]
        if any(r.interaction_id != self.interaction_id or r.architecture is not self.architecture for r in records):
            raise ValueError("verification record identity mismatch")
        if any(c.interaction_id != self.interaction_id or c.architecture is not self.architecture for c in self.condition_assessments):
            raise ValueError("condition identity mismatch")
        if any(f.interaction_id != self.interaction_id or f.architecture is not self.architecture for f in self.location_findings):
            raise ValueError("location identity mismatch")
        return self
