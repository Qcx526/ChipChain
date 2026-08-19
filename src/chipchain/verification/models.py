"""Strict serializable Phase 9A verification and localization contracts."""

from __future__ import annotations

import hashlib
import json
import re

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture, RelationType
from chipchain.models.common import DomainModel, Identifier, Metadata, UnitInterval
from chipchain.verification.enums import (
    CandidateVerificationStatus,
    ConditionKind,
    ConditionStatus,
    RootCauseLocalizationStatus,
    VerificationStatus,
    VerificationSubjectKind,
)

_HEX_ADDRESS = re.compile(r"^0[xX][0-9a-fA-F]+$")


def _sorted_unique(values: list[str], label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")
    return sorted(values)


def verification_record_id(
    architecture: Architecture,
    subject_kind: VerificationSubjectKind,
    subject_id: str,
    verifier: str,
) -> str:
    """Return the stable identity of one verifier/subject decision slot."""

    payload = [architecture.value, subject_kind.value, subject_id, verifier]
    digest = hashlib.sha256(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]
    return f"verification:{subject_kind.value}:{digest}"


class ProgramAddress(DomainModel):
    """Canonical program code/instruction address namespace."""

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


class VerificationRecord(DomainModel):
    """One immutable-by-contract objective verification decision."""

    id: Identifier
    architecture: Architecture
    subject_kind: VerificationSubjectKind
    subject_id: Identifier
    status: VerificationStatus
    verifier: Identifier
    evidence_ids: list[Identifier] = Field(default_factory=list)
    rule_ids: list[Identifier] = Field(default_factory=list)
    messages: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("evidence_ids", "rule_ids", "messages")
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "verification record lists")

    @model_validator(mode="after")
    def validate_identity(self) -> "VerificationRecord":
        expected = verification_record_id(
            self.architecture, self.subject_kind, self.subject_id, self.verifier
        )
        if self.id != expected:
            raise ValueError("VerificationRecord ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        architecture: Architecture,
        subject_kind: VerificationSubjectKind,
        subject_id: str,
        status: VerificationStatus,
        verifier: str,
        evidence_ids: list[str] | None = None,
        rule_ids: list[str] | None = None,
        messages: list[str] | None = None,
        metadata: Metadata | None = None,
    ) -> "VerificationRecord":
        return cls(
            id=verification_record_id(
                architecture, subject_kind, subject_id, verifier
            ),
            architecture=architecture,
            subject_kind=subject_kind,
            subject_id=subject_id,
            status=status,
            verifier=verifier,
            evidence_ids=evidence_ids or [],
            rule_ids=rule_ids or [],
            messages=messages or [],
            metadata=metadata or {},
        )


class ConditionAssessment(DomainModel):
    """Evidence-only condition result without confidence or probability."""

    condition_node_id: Identifier
    condition_kind: ConditionKind
    status: ConditionStatus
    supporting_evidence_ids: list[Identifier] = Field(default_factory=list)
    contradicting_evidence_ids: list[Identifier] = Field(default_factory=list)
    rule_ids: list[Identifier] = Field(default_factory=list)
    messages: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "supporting_evidence_ids", "contradicting_evidence_ids", "rule_ids", "messages"
    )
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "condition assessment lists")


class TriggerFeatureProvenance(DomainModel):
    """Exact structured origin of one extracted trigger feature."""

    feature_id: Identifier
    source_kind: Identifier
    source_id: Identifier
    source_field: Identifier


class TriggerFeatureSet(DomainModel):
    """Deterministic trigger characteristics; never condition satisfaction."""

    candidate_id: Identifier
    architecture: Architecture
    entrypoint_candidates: list[Identifier] = Field(default_factory=list)
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

    @field_validator(
        "entrypoint_candidates",
        "interface_identifiers",
        "memory_map_ids",
        "memory_map_regions",
        "trigger_inputs",
        "trigger_events",
        "required_privileges",
        "required_security_states",
        "required_configurations",
        "security_mechanism_ids",
        "cwe_ids",
        "capec_ids",
        "unresolved_feature_ids",
    )
    @classmethod
    def normalize_string_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "trigger feature lists")

    @field_validator("hardware_addresses")
    @classmethod
    def normalize_hardware_addresses(
        cls, values: list[HardwareAddress]
    ) -> list[HardwareAddress]:
        if len({item.value for item in values}) != len(values):
            raise ValueError("hardware addresses must be unique")
        return sorted(values, key=lambda item: int(item.value, 16))

    @field_validator("mmio_access_types")
    @classmethod
    def normalize_mmio_types(cls, values: list[RelationType]) -> list[RelationType]:
        allowed = {RelationType.MMIO_READ, RelationType.MMIO_WRITE}
        if any(item not in allowed for item in values):
            raise ValueError("MMIO access types may contain only read/write")
        if len(values) != len(set(values)):
            raise ValueError("MMIO access types must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_provenance(self) -> "TriggerFeatureSet":
        keys = [
            (item.feature_id, item.source_kind, item.source_id, item.source_field)
            for item in self.provenance
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("trigger feature provenance must be unique")
        self.provenance.sort(
            key=lambda item: (
                item.feature_id, item.source_kind, item.source_id, item.source_field
            )
        )
        return self


class ObjectiveEvidenceInventory(DomainModel):
    """Evidence reference resolution recomputed without Agent assessments."""

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

    @field_validator(
        "required_evidence_ids",
        "resolved_evidence_ids",
        "verified_non_llm_evidence_ids",
        "unknown_evidence_ids",
        "rejected_evidence_ids",
    )
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "evidence inventory lists")

    @model_validator(mode="after")
    def validate_counts(self) -> "ObjectiveEvidenceInventory":
        pairs = (
            (self.required_evidence_count, self.required_evidence_ids),
            (self.resolved_evidence_count, self.resolved_evidence_ids),
            (
                self.verified_non_llm_evidence_count,
                self.verified_non_llm_evidence_ids,
            ),
            (self.unknown_evidence_count, self.unknown_evidence_ids),
            (self.rejected_evidence_count, self.rejected_evidence_ids),
        )
        if any(count != len(ids) for count, ids in pairs):
            raise ValueError("evidence inventory counts must match ID lists")
        return self


class VerificationScoreConfig(DomainModel):
    """Externally configured, explicitly uncalibrated score weights."""

    behavior_evidence: UnitInterval
    entity_link: UnitInterval
    knowledge_evidence: UnitInterval
    conditions: UnitInterval
    architecture_rules: UnitInterval
    metadata: Metadata

    @model_validator(mode="after")
    def validate_weights(self) -> "VerificationScoreConfig":
        total = sum(
            (
                self.behavior_evidence,
                self.entity_link,
                self.knowledge_evidence,
                self.conditions,
                self.architecture_rules,
            )
        )
        if abs(total - 1.0) > 1e-9:
            raise ValueError("verification score weights must sum exactly to 1.0")
        if self.metadata.get("profile") != "engineering_mvp_uncalibrated":
            raise ValueError("score metadata must declare the uncalibrated MVP profile")
        return self


class VerificationScoreResult(DomainModel):
    """Deterministic evidence-support score, not an attack probability."""

    verification_score: UnitInterval
    score_components: dict[str, UnitInterval]
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_components(self) -> "VerificationScoreResult":
        expected = {
            "architecture_rules",
            "behavior_evidence",
            "conditions",
            "entity_link",
            "knowledge_evidence",
        }
        if set(self.score_components) != expected:
            raise ValueError("verification score components are incomplete")
        return self


class RootCauseLocalizationResult(DomainModel):
    """Non-LLM security-relevant binary sink localization candidate."""

    candidate_id: Identifier
    architecture: Architecture
    function_id: Identifier | None = None
    function_name: Identifier | None = None
    candidate_binary_addresses: list[ProgramAddress] = Field(default_factory=list)
    candidate_instruction_addresses: list[ProgramAddress] = Field(default_factory=list)
    source_file: Identifier | None = None
    source_line: int | None = Field(default=None, ge=1)
    hardware_address: HardwareAddress | None = None
    knowledge_root_cause_node_ids: list[Identifier] = Field(default_factory=list)
    supporting_behavior_evidence_ids: list[Identifier] = Field(default_factory=list)
    supporting_knowledge_evidence_ids: list[Identifier] = Field(default_factory=list)
    localization_method: Identifier
    localization_status: RootCauseLocalizationStatus
    reason_codes: list[Identifier] = Field(default_factory=list)
    contradictions: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "knowledge_root_cause_node_ids",
        "supporting_behavior_evidence_ids",
        "supporting_knowledge_evidence_ids",
        "reason_codes",
        "contradictions",
    )
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "root-cause localization lists")

    @field_validator("candidate_binary_addresses", "candidate_instruction_addresses")
    @classmethod
    def normalize_program_addresses(
        cls, values: list[ProgramAddress]
    ) -> list[ProgramAddress]:
        if len({item.value for item in values}) != len(values):
            raise ValueError("program addresses must be unique")
        return sorted(values, key=lambda item: int(item.value, 16))


class CandidateVerificationResult(DomainModel):
    """Top-level Phase 9A result without AttackChain projection."""

    candidate_id: Identifier
    architecture: Architecture
    behavior_edge_verifications: list[VerificationRecord]
    entity_link_verification: VerificationRecord
    knowledge_edge_verifications: list[VerificationRecord]
    architecture_rule_verifications: list[VerificationRecord]
    trigger_assessments: list[ConditionAssessment] = Field(default_factory=list)
    precondition_assessments: list[ConditionAssessment] = Field(default_factory=list)
    trigger_features: TriggerFeatureSet
    evidence_inventory: ObjectiveEvidenceInventory
    verification_score: UnitInterval
    score_components: dict[str, UnitInterval]
    root_cause_localization: RootCauseLocalizationResult
    verification_status: CandidateVerificationStatus
    advisory_verification_steps: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("advisory_verification_steps")
    @classmethod
    def normalize_advisory(cls, values: list[str]) -> list[str]:
        return _sorted_unique(values, "advisory verification steps")

    @model_validator(mode="after")
    def validate_identity(self) -> "CandidateVerificationResult":
        if self.trigger_features.candidate_id != self.candidate_id:
            raise ValueError("trigger features candidate mismatch")
        if self.root_cause_localization.candidate_id != self.candidate_id:
            raise ValueError("root-cause candidate mismatch")
        if self.trigger_features.architecture is not self.architecture:
            raise ValueError("trigger features architecture mismatch")
        if self.root_cause_localization.architecture is not self.architecture:
            raise ValueError("root-cause architecture mismatch")
        records = [
            *self.behavior_edge_verifications,
            self.entity_link_verification,
            *self.knowledge_edge_verifications,
            *self.architecture_rule_verifications,
        ]
        if any(item.architecture is not self.architecture for item in records):
            raise ValueError("verification record architecture mismatch")
        return self

