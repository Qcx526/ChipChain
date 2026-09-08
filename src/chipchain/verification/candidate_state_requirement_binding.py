"""Pure exact B2-A state-source relevance binding for 2D4-A requirements."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier
from chipchain.verification.candidate_state_observation_models import (
    CandidateEffectiveMemoryTypeObservation,
    CandidateExecutionContextObservation,
    CandidateStateObservationMaterialization,
)
from chipchain.verification.candidate_state_requirement_binding_models import (
    CandidateStateObservationFamily,
    CandidateStateRequirementAcquisitionGap,
    CandidateStateRequirementAcquisitionGapReason,
    CandidateStateRequirementBindingProjection,
    CandidateStateRequirementObservationBinding,
    CandidateStateSourceIncompatibility,
    CandidateStateSourceIncompatibilityReason,
)
from chipchain.verification.cross_layer_requirement_models import (
    StaticCandidateVerificationRequirement,
    StaticCrossLayerEvidenceRequirementKind,
)
from chipchain.verification.cross_layer_requirements import (
    StaticCrossLayerVerificationRequirementMaterialization,
)


PHASE10D_CANDIDATE_STATE_REQUIREMENT_BINDING_MATERIALIZATION_CONTRACT = (
    "phase10d_candidate_state_requirement_binding_materialization_v1"
)

_SUPPORTED_REQUIREMENT_KINDS = {
    StaticCrossLayerEvidenceRequirementKind
    .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind
    .EXECUTION_CONTEXT_EVIDENCE_REQUIRED,
}


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def candidate_state_requirement_binding_materialization_id(
    payload: object,
) -> str:
    """Return one deterministic authoritative B2-B materialization ID."""

    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"candidate-state-requirement-binding-materialization:{digest}"


@dataclass(frozen=True)
class _ResolvedSubject:
    position_candidate_id: str
    fused_fact_node_id: str
    instruction_address: str


def _candidate_source(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
):
    return (
        requirements.source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot
    )


def _resolve_requirement_subjects(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
    requirement: StaticCandidateVerificationRequirement,
) -> list[_ResolvedSubject]:
    """Resolve authoritative subject locations through the complete source chain."""

    candidate_source = _candidate_source(requirements)
    candidate = next(
        (
            item
            for item in candidate_source.projection.case_candidates
            if item.id == requirement.source_case_candidate_id
        ),
        None,
    )
    if candidate is None:
        raise ValueError("state requirement references an absent candidate")
    positions = {
        item.id: item
        for item in candidate.position_candidates
        if item.id in requirement.subject_position_candidate_ids
    }
    if set(positions) != set(requirement.subject_position_candidate_ids):
        raise ValueError("state requirement references a foreign position")

    fused = candidate_source.source_fused_graph_materialization_snapshot
    fused_nodes = {item.id: item for item in fused.projection.nodes}
    semantic_facts = {
        item.id: item
        for item in (
            fused.source_semantic_graph_materialization
            .source_inventory_snapshot.facts
        )
    }
    resolved = []
    for position in positions.values():
        if position.source_fused_fact_node_id not in (
            requirement.subject_fused_fact_node_ids
        ):
            raise ValueError("state requirement position/fact linkage mismatch")
        fused_fact = fused_nodes.get(position.source_fused_fact_node_id)
        if fused_fact is None or fused_fact.instruction_address is None:
            raise ValueError("state requirement fused fact is absent")
        if len(position.source_semantic_fact_ids) != 1:
            raise ValueError("state requirement needs one semantic fact source")
        semantic_fact = semantic_facts.get(position.source_semantic_fact_ids[0])
        if semantic_fact is None:
            raise ValueError("state requirement semantic fact is absent")
        if position.source_semantic_fact_ids[0] not in (
            fused_fact.semantic_source_fact_ids
        ):
            raise ValueError("state fused fact semantic provenance mismatch")
        addresses = {
            position.instruction_address,
            fused_fact.instruction_address,
            semantic_fact.instruction_address,
        }
        if len(addresses) != 1:
            raise ValueError("state requirement instruction address mismatch")
        resolved.append(
            _ResolvedSubject(
                position_candidate_id=position.id,
                fused_fact_node_id=position.source_fused_fact_node_id,
                instruction_address=semantic_fact.instruction_address,
            )
        )
    if {item.fused_fact_node_id for item in resolved} != set(
        requirement.subject_fused_fact_node_ids
    ):
        raise ValueError("state requirement subject fact set is incomplete")
    return sorted(resolved, key=lambda item: item.position_candidate_id)


def _validated_state_sources(
    values: list[CandidateStateObservationMaterialization],
) -> list[CandidateStateObservationMaterialization]:
    detached = [
        CandidateStateObservationMaterialization.model_validate(
            item.model_dump(mode="json")
        )
        for item in values
    ]
    materialization_ids = [item.id for item in detached]
    if len(materialization_ids) != len(set(materialization_ids)):
        raise ValueError("state materialization IDs must be unique")
    manifest_ids = [item.source_manifest_snapshot.id for item in detached]
    if len(manifest_ids) != len(set(manifest_ids)):
        raise ValueError(
            "one state source manifest cannot provide competing materializations"
        )
    return sorted(detached, key=lambda item: item.id)


def _incompatibility_reasons(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
    source: CandidateStateObservationMaterialization,
) -> list[CandidateStateSourceIncompatibilityReason]:
    projection = requirements.projection
    manifest = source.source_manifest_snapshot
    reasons = []
    if manifest.architecture is not projection.architecture:
        reasons.append(CandidateStateSourceIncompatibilityReason.ARCHITECTURE_MISMATCH)
    if manifest.artifact_id != projection.artifact_id:
        reasons.append(CandidateStateSourceIncompatibilityReason.ARTIFACT_ID_MISMATCH)
    if manifest.artifact_sha256 != projection.artifact_sha256:
        reasons.append(
            CandidateStateSourceIncompatibilityReason.ARTIFACT_SHA256_MISMATCH
        )
    if manifest.instruction_set != projection.instruction_set:
        reasons.append(
            CandidateStateSourceIncompatibilityReason.INSTRUCTION_SET_MISMATCH
        )
    return reasons


def _binding_common(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
    requirement: StaticCandidateVerificationRequirement,
    source: CandidateStateObservationMaterialization,
    observation: (
        CandidateEffectiveMemoryTypeObservation
        | CandidateExecutionContextObservation
    ),
) -> dict[str, object]:
    projection = requirements.projection
    return {
        "architecture": projection.architecture,
        "artifact_id": projection.artifact_id,
        "artifact_sha256": projection.artifact_sha256,
        "instruction_set": projection.instruction_set,
        "source_requirement_materialization_id": requirements.id,
        "source_requirement_projection_id": projection.id,
        "source_requirement_id": requirement.id,
        "source_requirement_kind": requirement.evidence_requirement_kind,
        "source_case_candidate_id": requirement.source_case_candidate_id,
        "source_state_materialization_id": source.id,
        "source_state_manifest_id": source.source_manifest_snapshot.id,
        "source_state_observation_id": observation.id,
    }


def _project_candidate_state_requirement_bindings(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
    state_sources: list[CandidateStateObservationMaterialization],
) -> CandidateStateRequirementBindingProjection:
    sources = _validated_state_sources(state_sources)
    requirement_projection = requirements.projection
    compatible = []
    incompatible = []
    for source in sources:
        reasons = _incompatibility_reasons(requirements, source)
        if not reasons:
            compatible.append(source)
            continue
        manifest = source.source_manifest_snapshot
        incompatible.append(
            CandidateStateSourceIncompatibility.create(
                source_state_materialization_id=source.id,
                source_state_manifest_id=manifest.id,
                observed_architecture=manifest.architecture,
                observed_artifact_id=manifest.artifact_id,
                observed_artifact_sha256=manifest.artifact_sha256,
                observed_instruction_set=manifest.instruction_set,
                reasons=reasons,
            )
        )

    candidate_requirements = requirement_projection.candidate_requirements
    supported = [
        item
        for item in candidate_requirements
        if item.evidence_requirement_kind in _SUPPORTED_REQUIREMENT_KINDS
    ]
    subjects_by_requirement = {
        item.id: _resolve_requirement_subjects(requirements, item)
        for item in supported
    }

    bindings = []
    for source in compatible:
        families = (
            (
                CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE,
                StaticCrossLayerEvidenceRequirementKind
                .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED,
                source.effective_memory_type_observations,
            ),
            (
                CandidateStateObservationFamily.EXECUTION_CONTEXT,
                StaticCrossLayerEvidenceRequirementKind
                .EXECUTION_CONTEXT_EVIDENCE_REQUIRED,
                source.execution_context_observations,
            ),
        )
        for family, requirement_kind, observations in families:
            relevant_requirements = [
                item
                for item in supported
                if item.evidence_requirement_kind is requirement_kind
            ]
            for requirement in relevant_requirements:
                subjects = subjects_by_requirement[requirement.id]
                for observation in observations:
                    matched = [
                        item
                        for item in subjects
                        if item.instruction_address
                        == observation.instruction_address.value
                    ]
                    if not matched:
                        continue
                    bindings.append(
                        CandidateStateRequirementObservationBinding.create(
                            **_binding_common(
                                requirements, requirement, source, observation
                            ),
                            source_observation_family=family,
                            matched_subject_position_candidate_ids=[
                                item.position_candidate_id for item in matched
                            ],
                            matched_subject_fused_fact_node_ids=[
                                item.fused_fact_node_id for item in matched
                            ],
                        )
                    )

    bound_requirement_ids = {item.source_requirement_id for item in bindings}
    gaps = []
    for requirement in supported:
        if requirement.id in bound_requirement_ids:
            continue
        if not compatible:
            reason = (
                CandidateStateRequirementAcquisitionGapReason
                .NO_COMPATIBLE_STATE_SOURCE
            )
        elif requirement.evidence_requirement_kind is (
            StaticCrossLayerEvidenceRequirementKind
            .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED
        ):
            reason = (
                CandidateStateRequirementAcquisitionGapReason
                .NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT
            )
        else:
            reason = (
                CandidateStateRequirementAcquisitionGapReason
                .NO_EXECUTION_CONTEXT_OBSERVATION_AT_SUBJECT
            )
        gaps.append(
            CandidateStateRequirementAcquisitionGap.create(
                source_requirement_materialization_id=requirements.id,
                source_requirement_projection_id=requirement_projection.id,
                source_requirement_id=requirement.id,
                source_requirement_kind=requirement.evidence_requirement_kind,
                source_case_candidate_id=requirement.source_case_candidate_id,
                reason=reason,
            )
        )

    out_of_scope = [
        item.id
        for item in candidate_requirements
        if item.evidence_requirement_kind not in _SUPPORTED_REQUIREMENT_KINDS
    ] + [item.id for item in requirement_projection.binding_requirements]
    return CandidateStateRequirementBindingProjection.create(
        architecture=requirement_projection.architecture,
        artifact_id=requirement_projection.artifact_id,
        artifact_sha256=requirement_projection.artifact_sha256,
        instruction_set=requirement_projection.instruction_set,
        source_requirement_materialization_id=requirements.id,
        source_requirement_projection_id=requirement_projection.id,
        source_state_materialization_ids=[item.id for item in sources],
        compatible_state_materialization_ids=[item.id for item in compatible],
        incompatible_state_sources=incompatible,
        observation_requirement_bindings=bindings,
        acquisition_gaps=gaps,
        out_of_scope_requirement_ids=out_of_scope,
    )


class _CandidateStateRequirementBindingMaterializationBody(DomainModel):
    contract: Literal[
        "phase10d_candidate_state_requirement_binding_materialization_v1"
    ]
    source_requirement_materialization_id: Identifier
    source_requirement_materialization_snapshot: (
        StaticCrossLayerVerificationRequirementMaterialization
    )
    source_state_observation_materialization_snapshots: list[
        CandidateStateObservationMaterialization
    ] = Field(default_factory=list)
    projection: CandidateStateRequirementBindingProjection

    @field_validator("source_requirement_materialization_snapshot")
    @classmethod
    def detach_requirements(
        cls, value: StaticCrossLayerVerificationRequirementMaterialization
    ) -> StaticCrossLayerVerificationRequirementMaterialization:
        return StaticCrossLayerVerificationRequirementMaterialization.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("source_state_observation_materialization_snapshots")
    @classmethod
    def detach_state_sources(
        cls, values: list[CandidateStateObservationMaterialization]
    ) -> list[CandidateStateObservationMaterialization]:
        return _validated_state_sources(values)

    @field_validator("projection")
    @classmethod
    def detach_projection(
        cls, value: CandidateStateRequirementBindingProjection
    ) -> CandidateStateRequirementBindingProjection:
        return CandidateStateRequirementBindingProjection.model_validate(
            value.model_dump(mode="json")
        )

    @model_validator(mode="after")
    def validate_source_reprojection(
        self,
    ) -> "_CandidateStateRequirementBindingMaterializationBody":
        if (
            self.source_requirement_materialization_id
            != self.source_requirement_materialization_snapshot.id
        ):
            raise ValueError("state binding requirement source ID mismatch")
        expected = _project_candidate_state_requirement_bindings(
            self.source_requirement_materialization_snapshot,
            self.source_state_observation_materialization_snapshots,
        )
        if self.projection != expected:
            raise ValueError(
                "state requirement binding projection differs from deterministic source reprojection"
            )
        return self


class CandidateStateRequirementBindingMaterialization(
    _CandidateStateRequirementBindingMaterializationBody
):
    """Authoritative detached 2D4-A/B2-A sources plus relevance projection."""

    id: Identifier

    @classmethod
    def create(
        cls,
        *,
        requirement_materialization: (
            StaticCrossLayerVerificationRequirementMaterialization
        ),
        state_observation_materializations: list[
            CandidateStateObservationMaterialization
        ],
    ) -> "CandidateStateRequirementBindingMaterialization":
        requirements = StaticCrossLayerVerificationRequirementMaterialization.model_validate(
            requirement_materialization.model_dump(mode="json")
        )
        sources = _validated_state_sources(state_observation_materializations)
        body = _CandidateStateRequirementBindingMaterializationBody.model_validate(
            {
                "contract": (
                    PHASE10D_CANDIDATE_STATE_REQUIREMENT_BINDING_MATERIALIZATION_CONTRACT
                ),
                "source_requirement_materialization_id": requirements.id,
                "source_requirement_materialization_snapshot": requirements,
                "source_state_observation_materialization_snapshots": sources,
                "projection": _project_candidate_state_requirement_bindings(
                    requirements, sources
                ),
            }
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_state_requirement_binding_materialization_id(payload),
            **payload,
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateStateRequirementBindingMaterialization":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_state_requirement_binding_materialization_id(
            payload
        ):
            raise ValueError("state requirement binding materialization ID mismatch")
        return self


def bind_candidate_state_observations_to_requirements(
    requirement_materialization: (
        StaticCrossLayerVerificationRequirementMaterialization
    ),
    state_observation_materializations: list[
        CandidateStateObservationMaterialization
    ],
) -> CandidateStateRequirementBindingMaterialization:
    """Bind exact typed-state source relevance from two logical inputs only."""

    return CandidateStateRequirementBindingMaterialization.create(
        requirement_materialization=requirement_materialization,
        state_observation_materializations=state_observation_materializations,
    )


__all__ = [
    "CandidateStateRequirementBindingMaterialization",
    "bind_candidate_state_observations_to_requirements",
    "candidate_state_requirement_binding_materialization_id",
]
