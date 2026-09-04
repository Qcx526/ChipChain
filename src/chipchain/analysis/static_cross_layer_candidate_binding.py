"""Pure exact binding of static candidates to pattern-declared references."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import field_validator, model_validator

from chipchain.analysis.static_cross_layer_candidate_models import (
    StaticCrossLayerCandidateBinding,
    StaticCrossLayerCandidateObjectiveObligation,
    StaticCrossLayerCandidateProjection,
    StaticUnresolvedHardwareReference,
    StaticUnresolvedHardwareReferenceReason,
)
from chipchain.analysis.static_hardware_reference_models import (
    StaticHardwareReferenceCatalog,
)
from chipchain.analysis.static_trigger_candidate_matching import (
    StaticTriggerCandidateMaterialization,
)
from chipchain.models.common import DomainModel, Identifier


PHASE10D_STATIC_CROSS_LAYER_CANDIDATE_MATERIALIZATION_CONTRACT = (
    "phase10d_static_cross_layer_candidate_materialization_v1"
)

_CROSS_LAYER_OBLIGATIONS = [
    StaticCrossLayerCandidateObjectiveObligation.TARGET_HARDWARE_IDENTITY_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation
    .TARGET_HARDWARE_APPLICABILITY_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation
    .HARDWARE_EFFECT_OBSERVATION_REQUIRED,
]


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def static_cross_layer_candidate_materialization_id(payload: object) -> str:
    """Return one deterministic authoritative binding materialization ID."""

    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"static-cross-layer-candidate-materialization:{digest}"


def _detached_sources(
    candidates: StaticTriggerCandidateMaterialization,
    references: StaticHardwareReferenceCatalog,
) -> tuple[StaticTriggerCandidateMaterialization, StaticHardwareReferenceCatalog]:
    return (
        StaticTriggerCandidateMaterialization.model_validate(
            candidates.model_dump(mode="json")
        ),
        StaticHardwareReferenceCatalog.model_validate(
            references.model_dump(mode="json")
        ),
    )


def _project_static_cross_layer_candidates(
    candidates: StaticTriggerCandidateMaterialization,
    references: StaticHardwareReferenceCatalog,
) -> StaticCrossLayerCandidateProjection:
    candidate_projection = candidates.projection
    pattern_by_id = {
        pattern.id: pattern
        for pattern in candidates.source_pattern_catalog_snapshot.patterns
    }
    reference_by_id = {
        reference.reference_id: reference for reference in references.references
    }
    bindings = []
    unresolved = []
    common = {
        "architecture": candidate_projection.architecture,
        "artifact_id": candidate_projection.artifact_id,
        "artifact_sha256": candidate_projection.artifact_sha256,
        "instruction_set": candidate_projection.instruction_set,
        "source_candidate_materialization_id": candidates.id,
        "source_candidate_projection_id": candidate_projection.id,
    }
    for candidate in candidate_projection.case_candidates:
        pattern = pattern_by_id[candidate.source_pattern_id]
        if pattern.architecture is not candidate_projection.architecture:
            raise ValueError("candidate source pattern architecture mismatch")
        for reference_id in pattern.hardware_reference_ids:
            reference = reference_by_id.get(reference_id)
            record_common = {
                **common,
                "source_case_candidate_id": candidate.id,
                "source_pattern_id": pattern.id,
                "source_hardware_reference_id": reference_id,
            }
            if reference is None:
                unresolved.append(
                    StaticUnresolvedHardwareReference.create(
                        **record_common,
                        source_hardware_reference_record_id=None,
                        reason=(
                            StaticUnresolvedHardwareReferenceReason
                            .REFERENCE_NOT_IN_CATALOG
                        ),
                    )
                )
            elif reference.architecture is not candidate_projection.architecture:
                unresolved.append(
                    StaticUnresolvedHardwareReference.create(
                        **record_common,
                        source_hardware_reference_record_id=reference.id,
                        reason=(
                            StaticUnresolvedHardwareReferenceReason
                            .REFERENCE_ARCHITECTURE_MISMATCH
                        ),
                    )
                )
            else:
                bindings.append(
                    StaticCrossLayerCandidateBinding.create(
                        **record_common,
                        source_hardware_reference_record_id=reference.id,
                        hardware_reference_kind=reference.reference_kind,
                        candidate_remaining_objective_obligations=(
                            candidate.remaining_objective_obligations
                        ),
                        cross_layer_remaining_objective_obligations=(
                            _CROSS_LAYER_OBLIGATIONS
                        ),
                    )
                )
    return StaticCrossLayerCandidateProjection.create(
        **common,
        source_hardware_reference_catalog_id=references.id,
        bindings=bindings,
        unresolved_references=unresolved,
    )


class _StaticCrossLayerCandidateMaterializationBody(DomainModel):
    contract: Literal[
        "phase10d_static_cross_layer_candidate_materialization_v1"
    ]
    source_candidate_materialization_id: Identifier
    source_candidate_materialization_snapshot: StaticTriggerCandidateMaterialization
    source_hardware_reference_catalog_id: Identifier
    source_hardware_reference_catalog_snapshot: StaticHardwareReferenceCatalog
    projection: StaticCrossLayerCandidateProjection

    @field_validator("source_candidate_materialization_snapshot")
    @classmethod
    def detach_candidate_materialization(
        cls, value: StaticTriggerCandidateMaterialization
    ) -> StaticTriggerCandidateMaterialization:
        return StaticTriggerCandidateMaterialization.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("source_hardware_reference_catalog_snapshot")
    @classmethod
    def detach_reference_catalog(
        cls, value: StaticHardwareReferenceCatalog
    ) -> StaticHardwareReferenceCatalog:
        return StaticHardwareReferenceCatalog.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("projection")
    @classmethod
    def detach_projection(
        cls, value: StaticCrossLayerCandidateProjection
    ) -> StaticCrossLayerCandidateProjection:
        return StaticCrossLayerCandidateProjection.model_validate(
            value.model_dump(mode="json")
        )

    @model_validator(mode="after")
    def validate_source_reprojection(
        self,
    ) -> "_StaticCrossLayerCandidateMaterializationBody":
        candidates = self.source_candidate_materialization_snapshot
        references = self.source_hardware_reference_catalog_snapshot
        if self.source_candidate_materialization_id != candidates.id:
            raise ValueError("cross-layer candidate source ID mismatch")
        if self.source_hardware_reference_catalog_id != references.id:
            raise ValueError("cross-layer reference catalog source ID mismatch")
        expected = _project_static_cross_layer_candidates(candidates, references)
        if self.projection != expected:
            raise ValueError(
                "cross-layer projection differs from deterministic source reprojection"
            )
        return self


class StaticCrossLayerCandidateMaterialization(
    _StaticCrossLayerCandidateMaterializationBody
):
    """Authoritative detached candidate/reference sources and exact projection."""

    id: Identifier

    @classmethod
    def create(
        cls,
        *,
        candidate_materialization: StaticTriggerCandidateMaterialization,
        hardware_reference_catalog: StaticHardwareReferenceCatalog,
    ) -> "StaticCrossLayerCandidateMaterialization":
        candidates, references = _detached_sources(
            candidate_materialization, hardware_reference_catalog
        )
        values = {
            "contract": (
                PHASE10D_STATIC_CROSS_LAYER_CANDIDATE_MATERIALIZATION_CONTRACT
            ),
            "source_candidate_materialization_id": candidates.id,
            "source_candidate_materialization_snapshot": candidates,
            "source_hardware_reference_catalog_id": references.id,
            "source_hardware_reference_catalog_snapshot": references,
            "projection": _project_static_cross_layer_candidates(
                candidates, references
            ),
        }
        body = _StaticCrossLayerCandidateMaterializationBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(
            id=static_cross_layer_candidate_materialization_id(payload),
            **payload,
        )

    @model_validator(mode="after")
    def validate_deterministic_id(
        self,
    ) -> "StaticCrossLayerCandidateMaterialization":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_cross_layer_candidate_materialization_id(payload):
            raise ValueError("static cross-layer materialization ID mismatch")
        return self


def bind_static_trigger_candidates_to_hardware_references(
    candidate_materialization: StaticTriggerCandidateMaterialization,
    hardware_reference_catalog: StaticHardwareReferenceCatalog,
) -> StaticCrossLayerCandidateMaterialization:
    """Bind exactly two detached inputs without analysis, retrieval, or inference."""

    return StaticCrossLayerCandidateMaterialization.create(
        candidate_materialization=candidate_materialization,
        hardware_reference_catalog=hardware_reference_catalog,
    )
