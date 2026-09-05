"""Pure projection of frozen cross-layer obligations into evidence needs."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import field_validator, model_validator

from chipchain.analysis.static_cross_layer_candidate_binding import (
    StaticCrossLayerCandidateMaterialization,
)
from chipchain.analysis.static_trigger_candidate_models import (
    StaticTriggerCaseCandidate,
    StaticTriggerCandidateObjectiveObligation,
    StaticTriggerOrderBasis,
)
from chipchain.analysis.static_trigger_pattern_models import (
    StaticTriggerObjectiveRequirement,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.verification.cross_layer_requirement_models import (
    BINDING_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1,
    CANDIDATE_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1,
    StaticCandidateVerificationRequirement,
    StaticCrossLayerBindingVerificationRequirement,
    StaticCrossLayerVerificationRequirementProjection,
)


PHASE10D_CROSS_LAYER_VERIFICATION_REQUIREMENT_MATERIALIZATION_CONTRACT = (
    "phase10d_cross_layer_verification_requirement_materialization_v1"
)

def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def static_cross_layer_verification_requirement_materialization_id(payload: object) -> str:
    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"static-cross-layer-verification-requirement-materialization:{digest}"


def _subjects(candidate: StaticTriggerCaseCandidate, obligation, pattern) -> tuple[list[str], list[str], list[str]]:
    positions = list(candidate.position_candidates)
    witnesses = list(candidate.order_witnesses)
    case = next((item for item in pattern.cases if item.id == candidate.source_case_id), None)
    if case is None:
        raise ValueError("candidate source pattern case is absent")
    source_positions = {item.id: item for item in case.positions}

    if obligation is StaticTriggerCandidateObjectiveObligation.SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED:
        witnesses = [item for item in witnesses if item.order_basis is StaticTriggerOrderBasis.DIRECTED_FUNCTION_CFG_PATH]
        participating = {item.source_position_candidate_id for item in witnesses} | {item.target_position_candidate_id for item in witnesses}
        positions = [item for item in positions if item.id in participating]
        if not witnesses or not positions:
            raise ValueError("symbolic feasibility obligation lacks a CFG-path witness")
    elif obligation in {
        StaticTriggerCandidateObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
        StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
    }:
        source_requirement = (
            StaticTriggerObjectiveRequirement.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
            if obligation is StaticTriggerCandidateObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
            else StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED
        )
        selected = []
        for item in positions:
            source_position = source_positions.get(item.source_position_id)
            if source_position is None:
                raise ValueError("candidate source pattern position is absent")
            predicate = next((p for p in source_position.alternatives if p.id == item.source_predicate_id), None)
            if predicate is None:
                raise ValueError("candidate selected source predicate is absent")
            if source_requirement in predicate.objective_requirements:
                if (
                    source_requirement
                    is StaticTriggerObjectiveRequirement
                    .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
                    and not predicate.required_effective_memory_types
                ):
                    raise ValueError(
                        "effective-memory-type obligation lacks a declared "
                        "required memory type"
                    )
                if (
                    source_requirement
                    is StaticTriggerObjectiveRequirement
                    .RUNTIME_EXECUTION_CONTEXT_REQUIRED
                    and not predicate.required_execution_contexts
                ):
                    raise ValueError(
                        "execution-context obligation lacks a declared "
                        "required execution context"
                    )
                selected.append(item)
        positions, witnesses = selected, []
        if not positions:
            raise ValueError("candidate obligation lacks a selected predicate declaration")
    elif obligation is StaticTriggerCandidateObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED:
        if StaticTriggerObjectiveRequirement.RELATION_PROXIMITY_REMAINS_UNRESOLVED not in case.objective_requirements:
            raise ValueError("candidate proximity obligation lacks source case declaration")
    elif obligation is StaticTriggerCandidateObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED:
        if StaticTriggerObjectiveRequirement.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED not in pattern.objective_requirements:
            raise ValueError("candidate timing obligation lacks source pattern declaration")
    return (
        sorted(item.id for item in positions),
        sorted(item.source_fused_fact_node_id for item in positions),
        sorted(item.id for item in witnesses),
    )


def _project(source: StaticCrossLayerCandidateMaterialization) -> StaticCrossLayerVerificationRequirementProjection:
    cross = source.projection
    candidate_source = source.source_candidate_materialization_snapshot
    candidates = sorted(
        candidate_source.projection.case_candidates,
        key=lambda item: item.id,
    )
    patterns = {item.id: item for item in candidate_source.source_pattern_catalog_snapshot.patterns}
    candidate_ids = [item.id for item in candidates]
    artifact_common = {
        "architecture": cross.architecture,
        "artifact_id": cross.artifact_id,
        "artifact_sha256": cross.artifact_sha256,
        "instruction_set": cross.instruction_set,
    }
    candidate_common = {
        **artifact_common,
        "source_candidate_materialization_id": candidate_source.id,
        "source_candidate_projection_id": candidate_source.projection.id,
    }
    binding_common = {
        **artifact_common,
        "source_cross_layer_materialization_id": source.id,
        "source_cross_layer_projection_id": cross.id,
    }
    candidate_requirements = []
    for candidate in candidates:
        pattern = patterns.get(candidate.source_pattern_id)
        if pattern is None:
            raise ValueError("case candidate references an absent source pattern")
        if pattern.architecture is not cross.architecture or pattern.instruction_set != cross.instruction_set:
            raise ValueError("case candidate source pattern provenance mismatch")
        for obligation in candidate.remaining_objective_obligations:
            kind = CANDIDATE_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1[
                obligation
            ]
            position_ids, fact_ids, witness_ids = _subjects(candidate, obligation, pattern)
            candidate_requirements.append(StaticCandidateVerificationRequirement.create(
                **candidate_common,
                source_case_candidate_id=candidate.id,
                source_pattern_id=pattern.id,
                source_pattern_case_id=candidate.source_case_id,
                source_obligation=obligation,
                evidence_requirement_kind=kind,
                subject_position_candidate_ids=position_ids,
                subject_fused_fact_node_ids=fact_ids,
                subject_order_witness_ids=witness_ids,
            ))
    binding_requirements = []
    for binding in cross.bindings:
        for obligation in binding.cross_layer_remaining_objective_obligations:
            binding_requirements.append(StaticCrossLayerBindingVerificationRequirement.create(
                **binding_common,
                source_cross_layer_binding_id=binding.id,
                source_case_candidate_id=binding.source_case_candidate_id,
                source_pattern_id=binding.source_pattern_id,
                source_hardware_reference_id=binding.source_hardware_reference_id,
                source_hardware_reference_record_id=binding.source_hardware_reference_record_id,
                source_obligation=obligation,
                evidence_requirement_kind=(
                    BINDING_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1[
                        obligation
                    ]
                ),
            ))
    return StaticCrossLayerVerificationRequirementProjection.create(
        **artifact_common,
        source_cross_layer_materialization_id=source.id,
        source_cross_layer_projection_id=cross.id,
        source_candidate_materialization_id=candidate_source.id,
        source_candidate_projection_id=candidate_source.projection.id,
        candidate_requirements=candidate_requirements,
        binding_requirements=binding_requirements,
        source_unresolved_hardware_reference_ids=[item.id for item in cross.unresolved_references],
        source_case_candidate_count=len(candidate_ids),
        source_resolved_binding_count=len(cross.bindings),
    )


class _MaterializationBody(DomainModel):
    contract: Literal["phase10d_cross_layer_verification_requirement_materialization_v1"]
    source_cross_layer_candidate_materialization_id: Identifier
    source_cross_layer_candidate_materialization_snapshot: StaticCrossLayerCandidateMaterialization
    projection: StaticCrossLayerVerificationRequirementProjection

    @field_validator("source_cross_layer_candidate_materialization_snapshot")
    @classmethod
    def detach_source(cls, value):
        return StaticCrossLayerCandidateMaterialization.model_validate(value.model_dump(mode="json"))

    @field_validator("projection")
    @classmethod
    def detach_projection(cls, value):
        return StaticCrossLayerVerificationRequirementProjection.model_validate(value.model_dump(mode="json"))

    @model_validator(mode="after")
    def source_reprojection(self) -> "_MaterializationBody":
        if self.source_cross_layer_candidate_materialization_id != self.source_cross_layer_candidate_materialization_snapshot.id:
            raise ValueError("verification requirement source materialization ID mismatch")
        if self.projection != _project(self.source_cross_layer_candidate_materialization_snapshot):
            raise ValueError("requirement projection differs from deterministic source reprojection")
        return self


class StaticCrossLayerVerificationRequirementMaterialization(_MaterializationBody):
    """Authoritative detached cross-layer source plus complete requirement projection."""

    id: Identifier

    @classmethod
    def create(cls, *, cross_layer_materialization: StaticCrossLayerCandidateMaterialization):
        source = StaticCrossLayerCandidateMaterialization.model_validate(cross_layer_materialization.model_dump(mode="json"))
        body = _MaterializationBody.model_validate({
            "contract": PHASE10D_CROSS_LAYER_VERIFICATION_REQUIREMENT_MATERIALIZATION_CONTRACT,
            "source_cross_layer_candidate_materialization_id": source.id,
            "source_cross_layer_candidate_materialization_snapshot": source,
            "projection": _project(source),
        })
        payload = body.model_dump(mode="json")
        return cls(id=static_cross_layer_verification_requirement_materialization_id(payload), **payload)

    @model_validator(mode="after")
    def deterministic_id(self) -> "StaticCrossLayerVerificationRequirementMaterialization":
        if self.id != static_cross_layer_verification_requirement_materialization_id(self.model_dump(mode="json", exclude={"id"})):
            raise ValueError("verification requirement materialization ID mismatch")
        return self


def project_cross_layer_verification_requirements(
    cross_layer_materialization: StaticCrossLayerCandidateMaterialization,
) -> StaticCrossLayerVerificationRequirementMaterialization:
    """Project exactly one detached 2D3-C source into non-verdict evidence needs."""

    return StaticCrossLayerVerificationRequirementMaterialization.create(
        cross_layer_materialization=cross_layer_materialization
    )
