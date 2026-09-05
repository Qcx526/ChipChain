"""Closed, non-verdict contracts for cross-layer verification requirements."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.analysis.static_cross_layer_candidate_models import (
    StaticCrossLayerCandidateObjectiveObligation,
)
from chipchain.analysis.static_trigger_candidate_models import (
    StaticTriggerCandidateObjectiveObligation,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_CANDIDATE_VERIFICATION_REQUIREMENT_CONTRACT = (
    "phase10d_candidate_verification_requirement_v1"
)
PHASE10D_CROSS_LAYER_BINDING_VERIFICATION_REQUIREMENT_CONTRACT = (
    "phase10d_cross_layer_binding_verification_requirement_v1"
)
PHASE10D_CROSS_LAYER_VERIFICATION_REQUIREMENT_PROJECTION_CONTRACT = (
    "phase10d_cross_layer_verification_requirement_projection_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StaticCrossLayerEvidenceRequirementKind(str, Enum):
    """Exact v1 kinds of objective evidence that remain required."""

    RUNTIME_EXECUTION_TRACE_REQUIRED = "runtime_execution_trace_required"
    PATH_FEASIBILITY_EVIDENCE_REQUIRED = "path_feasibility_evidence_required"
    EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED = (
        "effective_memory_type_evidence_required"
    )
    EXECUTION_CONTEXT_EVIDENCE_REQUIRED = "execution_context_evidence_required"
    QUALITATIVE_PROXIMITY_EVIDENCE_REQUIRED = (
        "qualitative_proximity_evidence_required"
    )
    HARDWARE_TIMING_EVIDENCE_REQUIRED = "hardware_timing_evidence_required"
    TARGET_HARDWARE_IDENTITY_EVIDENCE_REQUIRED = (
        "target_hardware_identity_evidence_required"
    )
    TARGET_HARDWARE_APPLICABILITY_EVIDENCE_REQUIRED = (
        "target_hardware_applicability_evidence_required"
    )
    HARDWARE_EFFECT_OBSERVATION_EVIDENCE_REQUIRED = (
        "hardware_effect_observation_evidence_required"
    )


class StaticCrossLayerVerificationRequirementOrigin(str, Enum):
    """Exact layer that declared an unresolved source obligation."""

    CANDIDATE_OBLIGATION = "candidate_obligation"
    CROSS_LAYER_BINDING_OBLIGATION = "cross_layer_binding_obligation"


class StaticCrossLayerVerificationRequirementSemantics(str, Enum):
    """Closed v1 meaning; requirement records are not evidence or outcomes."""

    OBJECTIVE_EVIDENCE_REQUIRED_ONLY = "objective_evidence_required_only"


CandidateObligationV1 = Literal[
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED,
    StaticTriggerCandidateObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED,
    StaticTriggerCandidateObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
]
BindingObligationV1 = Literal[
    StaticCrossLayerCandidateObjectiveObligation.TARGET_HARDWARE_IDENTITY_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation.TARGET_HARDWARE_APPLICABILITY_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation.HARDWARE_EFFECT_OBSERVATION_REQUIRED,
]
CandidateRequirementKindV1 = Literal[
    StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind.EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind.EXECUTION_CONTEXT_EVIDENCE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind.QUALITATIVE_PROXIMITY_EVIDENCE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind.HARDWARE_TIMING_EVIDENCE_REQUIRED,
]
BindingRequirementKindV1 = Literal[
    StaticCrossLayerEvidenceRequirementKind.TARGET_HARDWARE_IDENTITY_EVIDENCE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind.TARGET_HARDWARE_APPLICABILITY_EVIDENCE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind.HARDWARE_EFFECT_OBSERVATION_EVIDENCE_REQUIRED,
]

CANDIDATE_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1: Mapping[
    StaticTriggerCandidateObjectiveObligation,
    StaticCrossLayerEvidenceRequirementKind,
] = MappingProxyType({
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED:
        StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED:
        StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED:
        StaticCrossLayerEvidenceRequirementKind.EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED:
        StaticCrossLayerEvidenceRequirementKind.EXECUTION_CONTEXT_EVIDENCE_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED:
        StaticCrossLayerEvidenceRequirementKind.QUALITATIVE_PROXIMITY_EVIDENCE_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED:
        StaticCrossLayerEvidenceRequirementKind.HARDWARE_TIMING_EVIDENCE_REQUIRED,
})
BINDING_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1: Mapping[
    StaticCrossLayerCandidateObjectiveObligation,
    StaticCrossLayerEvidenceRequirementKind,
] = MappingProxyType({
    StaticCrossLayerCandidateObjectiveObligation.TARGET_HARDWARE_IDENTITY_REQUIRED:
        StaticCrossLayerEvidenceRequirementKind.TARGET_HARDWARE_IDENTITY_EVIDENCE_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation.TARGET_HARDWARE_APPLICABILITY_REQUIRED:
        StaticCrossLayerEvidenceRequirementKind.TARGET_HARDWARE_APPLICABILITY_EVIDENCE_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation.HARDWARE_EFFECT_OBSERVATION_REQUIRED:
        StaticCrossLayerEvidenceRequirementKind.HARDWARE_EFFECT_OBSERVATION_EVIDENCE_REQUIRED,
})


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _id(prefix: str, payload: object) -> str:
    return f"{prefix}:{hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()}"


def static_candidate_verification_requirement_id(payload: object) -> str:
    return _id("static-candidate-verification-requirement", payload)


def static_cross_layer_binding_verification_requirement_id(payload: object) -> str:
    return _id("static-cross-layer-binding-verification-requirement", payload)


def static_cross_layer_verification_requirement_projection_id(payload: object) -> str:
    return _id("static-cross-layer-verification-requirement-projection", payload)


def _ids(values: list[str], label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return sorted(values)


class _ArtifactRequirement(DomainModel):
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier

    @field_validator("artifact_sha256")
    @classmethod
    def sha(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("artifact SHA-256 must contain 64 lowercase hex digits")
        return value


class _CandidateRequirementBody(_ArtifactRequirement):
    contract: Literal["phase10d_candidate_verification_requirement_v1"]
    source_candidate_materialization_id: Identifier
    source_candidate_projection_id: Identifier
    source_case_candidate_id: Identifier
    source_pattern_id: Identifier
    source_pattern_case_id: Identifier
    source_obligation: CandidateObligationV1
    evidence_requirement_kind: CandidateRequirementKindV1
    subject_position_candidate_ids: list[Identifier] = Field(min_length=1)
    subject_fused_fact_node_ids: list[Identifier] = Field(min_length=1)
    subject_order_witness_ids: list[Identifier] = Field(default_factory=list)
    requirement_origin: Literal[
        StaticCrossLayerVerificationRequirementOrigin.CANDIDATE_OBLIGATION
    ] = StaticCrossLayerVerificationRequirementOrigin.CANDIDATE_OBLIGATION
    requirement_semantics: Literal[
        StaticCrossLayerVerificationRequirementSemantics.OBJECTIVE_EVIDENCE_REQUIRED_ONLY
    ] = StaticCrossLayerVerificationRequirementSemantics.OBJECTIVE_EVIDENCE_REQUIRED_ONLY

    @field_validator("subject_position_candidate_ids", "subject_fused_fact_node_ids", "subject_order_witness_ids")
    @classmethod
    def normalize_ids(cls, values: list[str], info) -> list[str]:
        return _ids(values, info.field_name)

    @model_validator(mode="after")
    def mapping(self) -> "_CandidateRequirementBody":
        if (
            CANDIDATE_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1[
                self.source_obligation
            ]
            is not self.evidence_requirement_kind
        ):
            raise ValueError("candidate obligation/evidence requirement mapping mismatch")
        if self.evidence_requirement_kind is (
            StaticCrossLayerEvidenceRequirementKind
            .PATH_FEASIBILITY_EVIDENCE_REQUIRED
        ):
            if len(self.subject_order_witness_ids) < 1:
                raise ValueError("path feasibility requirement needs an order witness")
            if len(self.subject_position_candidate_ids) < 2:
                raise ValueError("path feasibility requirement needs two positions")
            if len(self.subject_fused_fact_node_ids) < 2:
                raise ValueError("path feasibility requirement needs two fused facts")
        return self


class StaticCandidateVerificationRequirement(_CandidateRequirementBody):
    """One source-scoped candidate obligation converted to an evidence need."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticCandidateVerificationRequirement":
        body = _CandidateRequirementBody.model_validate({**values, "contract": PHASE10D_CANDIDATE_VERIFICATION_REQUIREMENT_CONTRACT})
        payload = body.model_dump(mode="json")
        return cls(id=static_candidate_verification_requirement_id(payload), **payload)

    @model_validator(mode="after")
    def deterministic_id(self) -> "StaticCandidateVerificationRequirement":
        if self.id != static_candidate_verification_requirement_id(self.model_dump(mode="json", exclude={"id"})):
            raise ValueError("candidate verification requirement ID mismatch")
        return self


class _BindingRequirementBody(_ArtifactRequirement):
    contract: Literal["phase10d_cross_layer_binding_verification_requirement_v1"]
    source_cross_layer_materialization_id: Identifier
    source_cross_layer_projection_id: Identifier
    source_cross_layer_binding_id: Identifier
    source_case_candidate_id: Identifier
    source_pattern_id: Identifier
    source_hardware_reference_id: Identifier
    source_hardware_reference_record_id: Identifier
    source_obligation: BindingObligationV1
    evidence_requirement_kind: BindingRequirementKindV1
    requirement_origin: Literal[
        StaticCrossLayerVerificationRequirementOrigin.CROSS_LAYER_BINDING_OBLIGATION
    ] = StaticCrossLayerVerificationRequirementOrigin.CROSS_LAYER_BINDING_OBLIGATION
    requirement_semantics: Literal[
        StaticCrossLayerVerificationRequirementSemantics.OBJECTIVE_EVIDENCE_REQUIRED_ONLY
    ] = StaticCrossLayerVerificationRequirementSemantics.OBJECTIVE_EVIDENCE_REQUIRED_ONLY

    @model_validator(mode="after")
    def mapping(self) -> "_BindingRequirementBody":
        if (
            BINDING_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1[
                self.source_obligation
            ]
            is not self.evidence_requirement_kind
        ):
            raise ValueError("binding obligation/evidence requirement mapping mismatch")
        return self


class StaticCrossLayerBindingVerificationRequirement(_BindingRequirementBody):
    """One exact cross-layer binding obligation converted to an evidence need."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticCrossLayerBindingVerificationRequirement":
        body = _BindingRequirementBody.model_validate({**values, "contract": PHASE10D_CROSS_LAYER_BINDING_VERIFICATION_REQUIREMENT_CONTRACT})
        payload = body.model_dump(mode="json")
        return cls(id=static_cross_layer_binding_verification_requirement_id(payload), **payload)

    @model_validator(mode="after")
    def deterministic_id(self) -> "StaticCrossLayerBindingVerificationRequirement":
        if self.id != static_cross_layer_binding_verification_requirement_id(self.model_dump(mode="json", exclude={"id"})):
            raise ValueError("binding verification requirement ID mismatch")
        return self


def static_cross_layer_verification_requirement_diagnostics(
    *, source_case_candidate_count: int, source_resolved_binding_count: int,
    source_unresolved_reference_count: int,
    candidate_requirements: list[StaticCandidateVerificationRequirement],
    binding_requirements: list[StaticCrossLayerBindingVerificationRequirement],
) -> list[str]:
    kinds = [item.evidence_requirement_kind for item in [*candidate_requirements, *binding_requirements]]
    def count(kind: StaticCrossLayerEvidenceRequirementKind) -> int:
        return sum(item is kind for item in kinds)
    values = [
        f"source_case_candidate_count:{source_case_candidate_count}",
        f"source_resolved_binding_count:{source_resolved_binding_count}",
        f"source_unresolved_reference_count:{source_unresolved_reference_count}",
        f"candidate_requirement_count:{len(candidate_requirements)}",
        f"binding_requirement_count:{len(binding_requirements)}",
        f"runtime_execution_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED)}",
        f"path_feasibility_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED)}",
        f"effective_memory_type_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED)}",
        f"execution_context_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.EXECUTION_CONTEXT_EVIDENCE_REQUIRED)}",
        f"qualitative_proximity_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.QUALITATIVE_PROXIMITY_EVIDENCE_REQUIRED)}",
        f"hardware_timing_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.HARDWARE_TIMING_EVIDENCE_REQUIRED)}",
        f"target_hardware_identity_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.TARGET_HARDWARE_IDENTITY_EVIDENCE_REQUIRED)}",
        f"target_hardware_applicability_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.TARGET_HARDWARE_APPLICABILITY_EVIDENCE_REQUIRED)}",
        f"hardware_effect_observation_requirement_count:{count(StaticCrossLayerEvidenceRequirementKind.HARDWARE_EFFECT_OBSERVATION_EVIDENCE_REQUIRED)}",
    ]
    return sorted(values)


class _ProjectionBody(_ArtifactRequirement):
    contract: Literal["phase10d_cross_layer_verification_requirement_projection_v1"]
    source_cross_layer_materialization_id: Identifier
    source_cross_layer_projection_id: Identifier
    source_candidate_materialization_id: Identifier
    source_candidate_projection_id: Identifier
    candidate_requirements: list[StaticCandidateVerificationRequirement] = Field(default_factory=list)
    binding_requirements: list[StaticCrossLayerBindingVerificationRequirement] = Field(default_factory=list)
    source_unresolved_hardware_reference_ids: list[Identifier] = Field(default_factory=list)
    diagnostic_codes: list[Identifier]

    @field_validator("candidate_requirements")
    @classmethod
    def candidates(cls, values):
        result = [StaticCandidateVerificationRequirement.model_validate(v.model_dump(mode="json")) for v in values]
        if len({v.id for v in result}) != len(result) or len({(v.source_case_candidate_id, v.source_obligation) for v in result}) != len(result):
            raise ValueError("candidate requirements must be logically unique")
        return sorted(result, key=lambda v: (v.source_case_candidate_id, v.source_obligation.value, v.id))

    @field_validator("binding_requirements")
    @classmethod
    def bindings(cls, values):
        result = [StaticCrossLayerBindingVerificationRequirement.model_validate(v.model_dump(mode="json")) for v in values]
        if len({v.id for v in result}) != len(result) or len({(v.source_cross_layer_binding_id, v.source_obligation) for v in result}) != len(result):
            raise ValueError("binding requirements must be logically unique")
        return sorted(result, key=lambda v: (v.source_cross_layer_binding_id, v.source_obligation.value, v.id))

    @field_validator("source_unresolved_hardware_reference_ids", "diagnostic_codes")
    @classmethod
    def list_ids(cls, values, info):
        return _ids(values, info.field_name)

    @model_validator(mode="after")
    def integrity(self) -> "_ProjectionBody":
        artifact_common = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.instruction_set,
        )
        candidate_common = (
            *artifact_common,
            self.source_candidate_materialization_id,
            self.source_candidate_projection_id,
        )
        binding_common = (
            *artifact_common,
            self.source_cross_layer_materialization_id,
            self.source_cross_layer_projection_id,
        )
        for item in self.candidate_requirements:
            if (
                item.architecture,
                item.artifact_id,
                item.artifact_sha256,
                item.instruction_set,
                item.source_candidate_materialization_id,
                item.source_candidate_projection_id,
            ) != candidate_common:
                raise ValueError("candidate requirement provenance mismatch")
        for item in self.binding_requirements:
            if (
                item.architecture,
                item.artifact_id,
                item.artifact_sha256,
                item.instruction_set,
                item.source_cross_layer_materialization_id,
                item.source_cross_layer_projection_id,
            ) != binding_common:
                raise ValueError("binding requirement provenance mismatch")
        candidate_tuples: dict[str, tuple[str, str, str, str]] = {}
        for item in self.candidate_requirements:
            value = (
                item.source_candidate_materialization_id,
                item.source_candidate_projection_id,
                item.source_pattern_id,
                item.source_pattern_case_id,
            )
            if item.source_case_candidate_id in candidate_tuples and candidate_tuples[item.source_case_candidate_id] != value:
                raise ValueError("candidate requirement source-ID tuple mismatch")
            candidate_tuples[item.source_case_candidate_id] = value
        binding_tuples: dict[str, tuple[str, str, str, str]] = {}
        for item in self.binding_requirements:
            value = (
                item.source_case_candidate_id,
                item.source_pattern_id,
                item.source_hardware_reference_id,
                item.source_hardware_reference_record_id,
            )
            if item.source_cross_layer_binding_id in binding_tuples and binding_tuples[item.source_cross_layer_binding_id] != value:
                raise ValueError("binding requirement source-ID tuple mismatch")
            binding_tuples[item.source_cross_layer_binding_id] = value
        source_cases = len({item.source_case_candidate_id for item in [*self.candidate_requirements, *self.binding_requirements]})
        expected = static_cross_layer_verification_requirement_diagnostics(
            source_case_candidate_count=source_cases,
            source_resolved_binding_count=len({v.source_cross_layer_binding_id for v in self.binding_requirements}),
            source_unresolved_reference_count=len(self.source_unresolved_hardware_reference_ids),
            candidate_requirements=self.candidate_requirements,
            binding_requirements=self.binding_requirements,
        )
        if self.diagnostic_codes != expected:
            raise ValueError("verification requirement diagnostics mismatch")
        return self


class StaticCrossLayerVerificationRequirementProjection(_ProjectionBody):
    """Standalone internal integrity; source referential integrity needs materialization."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticCrossLayerVerificationRequirementProjection":
        body_values = {**values, "contract": PHASE10D_CROSS_LAYER_VERIFICATION_REQUIREMENT_PROJECTION_CONTRACT}
        candidate_requirements = [
            item if isinstance(item, StaticCandidateVerificationRequirement)
            else StaticCandidateVerificationRequirement.model_validate(item)
            for item in body_values.get("candidate_requirements", [])
        ]
        binding_requirements = [
            item if isinstance(item, StaticCrossLayerBindingVerificationRequirement)
            else StaticCrossLayerBindingVerificationRequirement.model_validate(item)
            for item in body_values.get("binding_requirements", [])
        ]
        body_values["candidate_requirements"] = candidate_requirements
        body_values["binding_requirements"] = binding_requirements
        body_values["diagnostic_codes"] = static_cross_layer_verification_requirement_diagnostics(
            source_case_candidate_count=int(body_values.pop("source_case_candidate_count")),
            source_resolved_binding_count=int(body_values.pop("source_resolved_binding_count")),
            source_unresolved_reference_count=len(body_values.get("source_unresolved_hardware_reference_ids", [])),
            candidate_requirements=candidate_requirements,
            binding_requirements=binding_requirements,
        )
        body = _ProjectionBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_cross_layer_verification_requirement_projection_id(payload), **payload)

    @model_validator(mode="after")
    def deterministic_id(self) -> "StaticCrossLayerVerificationRequirementProjection":
        if self.id != static_cross_layer_verification_requirement_projection_id(self.model_dump(mode="json", exclude={"id"})):
            raise ValueError("verification requirement projection ID mismatch")
        return self
