"""Internal-integrity contracts for static cross-layer reference candidates."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.analysis.static_hardware_reference_models import (
    StaticHardwareReferenceKind,
)
from chipchain.analysis.static_trigger_candidate_models import (
    StaticTriggerCandidateObjectiveObligation,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_CROSS_LAYER_CANDIDATE_BINDING_CONTRACT = (
    "phase10d_static_cross_layer_candidate_binding_v1"
)
PHASE10D_STATIC_UNRESOLVED_HARDWARE_REFERENCE_CONTRACT = (
    "phase10d_static_unresolved_hardware_reference_v1"
)
PHASE10D_STATIC_CROSS_LAYER_CANDIDATE_PROJECTION_CONTRACT = (
    "phase10d_static_cross_layer_candidate_projection_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StaticCrossLayerCandidateBindingSemantics(str, Enum):
    """Closed non-verdict meaning of a v1 cross-layer binding."""

    STATIC_PATTERN_DECLARED_HARDWARE_REFERENCE_CANDIDATE_ONLY = (
        "static_pattern_declared_hardware_reference_candidate_only"
    )


class StaticCrossLayerCandidateObjectiveObligation(str, Enum):
    """Hardware-side objective work not established by static binding."""

    TARGET_HARDWARE_IDENTITY_REQUIRED = "target_hardware_identity_required"
    TARGET_HARDWARE_APPLICABILITY_REQUIRED = (
        "target_hardware_applicability_required"
    )
    HARDWARE_EFFECT_OBSERVATION_REQUIRED = "hardware_effect_observation_required"


class StaticUnresolvedHardwareReferenceReason(str, Enum):
    """Closed catalog-resolution reasons, not hardware verdicts."""

    REFERENCE_NOT_IN_CATALOG = "reference_not_in_catalog"
    REFERENCE_ARCHITECTURE_MISMATCH = "reference_architecture_mismatch"


_CandidateObligationV1 = Literal[
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
    StaticTriggerCandidateObjectiveObligation
    .SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED,
    StaticTriggerCandidateObjectiveObligation
    .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
    StaticTriggerCandidateObjectiveObligation
    .RELATION_PROXIMITY_REMAINS_UNRESOLVED,
    StaticTriggerCandidateObjectiveObligation
    .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
]
_CrossLayerObligationV1 = Literal[
    StaticCrossLayerCandidateObjectiveObligation.TARGET_HARDWARE_IDENTITY_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation
    .TARGET_HARDWARE_APPLICABILITY_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation
    .HARDWARE_EFFECT_OBSERVATION_REQUIRED,
]
_ReferenceKindV1 = Literal[
    StaticHardwareReferenceKind.OWNED_SYNTHETIC_CONDITION,
    StaticHardwareReferenceKind.DOCUMENTED_HARDWARE_ERRATUM,
]

_REQUIRED_CROSS_LAYER_OBLIGATIONS = {
    StaticCrossLayerCandidateObjectiveObligation.TARGET_HARDWARE_IDENTITY_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation
    .TARGET_HARDWARE_APPLICABILITY_REQUIRED,
    StaticCrossLayerCandidateObjectiveObligation
    .HARDWARE_EFFECT_OBSERVATION_REQUIRED,
}


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _deterministic_id(prefix: str, payload: object) -> str:
    return f"{prefix}:{hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()}"


def static_cross_layer_candidate_binding_id(payload: object) -> str:
    """Return one deterministic resolved binding identity."""

    return _deterministic_id("static-cross-layer-candidate-binding", payload)


def static_unresolved_hardware_reference_id(payload: object) -> str:
    """Return one deterministic unresolved reference identity."""

    return _deterministic_id("static-unresolved-hardware-reference", payload)


def static_cross_layer_candidate_projection_id(payload: object) -> str:
    """Return one deterministic static cross-layer projection identity."""

    return _deterministic_id("static-cross-layer-candidate-projection", payload)


def _validate_sha256(value: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError("artifact SHA-256 must contain 64 lowercase hex digits")
    return value


def _normalize_candidate_obligations(
    values: list[_CandidateObligationV1],
) -> list[_CandidateObligationV1]:
    if len(values) != len(set(values)):
        raise ValueError("candidate obligations must be unique")
    return sorted(values, key=lambda item: item.value)


class _StaticCrossLayerCandidateBindingBody(DomainModel):
    contract: Literal["phase10d_static_cross_layer_candidate_binding_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    source_candidate_materialization_id: Identifier
    source_candidate_projection_id: Identifier
    source_case_candidate_id: Identifier
    source_pattern_id: Identifier
    source_hardware_reference_id: Identifier
    source_hardware_reference_record_id: Identifier
    hardware_reference_kind: _ReferenceKindV1
    candidate_remaining_objective_obligations: list[
        _CandidateObligationV1
    ] = Field(min_length=1)
    cross_layer_remaining_objective_obligations: list[
        _CrossLayerObligationV1
    ] = Field(min_length=3, max_length=3)
    binding_semantics: Literal[
        StaticCrossLayerCandidateBindingSemantics
        .STATIC_PATTERN_DECLARED_HARDWARE_REFERENCE_CANDIDATE_ONLY
    ] = (
        StaticCrossLayerCandidateBindingSemantics
        .STATIC_PATTERN_DECLARED_HARDWARE_REFERENCE_CANDIDATE_ONLY
    )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _validate_sha256(value)

    @field_validator("candidate_remaining_objective_obligations")
    @classmethod
    def normalize_candidate_obligations(
        cls, values: list[_CandidateObligationV1]
    ) -> list[_CandidateObligationV1]:
        return _normalize_candidate_obligations(values)

    @field_validator("cross_layer_remaining_objective_obligations")
    @classmethod
    def normalize_cross_layer_obligations(
        cls, values: list[_CrossLayerObligationV1]
    ) -> list[_CrossLayerObligationV1]:
        if len(values) != len(set(values)) or set(values) != (
            _REQUIRED_CROSS_LAYER_OBLIGATIONS
        ):
            raise ValueError("all exact v1 cross-layer obligations are required")
        return sorted(values, key=lambda item: item.value)


class StaticCrossLayerCandidateBinding(_StaticCrossLayerCandidateBindingBody):
    """One exact pattern-declared reference binding, without a verdict."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticCrossLayerCandidateBinding":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_CROSS_LAYER_CANDIDATE_BINDING_CONTRACT
        )
        body = _StaticCrossLayerCandidateBindingBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_cross_layer_candidate_binding_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticCrossLayerCandidateBinding":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_cross_layer_candidate_binding_id(payload):
            raise ValueError("static cross-layer candidate binding ID mismatch")
        return self


class _StaticUnresolvedHardwareReferenceBody(DomainModel):
    contract: Literal["phase10d_static_unresolved_hardware_reference_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    source_candidate_materialization_id: Identifier
    source_candidate_projection_id: Identifier
    source_case_candidate_id: Identifier
    source_pattern_id: Identifier
    source_hardware_reference_id: Identifier
    source_hardware_reference_record_id: Identifier | None = None
    reason: Literal[
        StaticUnresolvedHardwareReferenceReason.REFERENCE_NOT_IN_CATALOG,
        StaticUnresolvedHardwareReferenceReason.REFERENCE_ARCHITECTURE_MISMATCH,
    ]

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _validate_sha256(value)

    @model_validator(mode="after")
    def validate_reason_shape(self) -> "_StaticUnresolvedHardwareReferenceBody":
        if self.reason is (
            StaticUnresolvedHardwareReferenceReason.REFERENCE_NOT_IN_CATALOG
        ):
            if self.source_hardware_reference_record_id is not None:
                raise ValueError("missing catalog reference cannot name a record")
        elif self.source_hardware_reference_record_id is None:
            raise ValueError("architecture mismatch must name the catalog record")
        return self


class StaticUnresolvedHardwareReference(_StaticUnresolvedHardwareReferenceBody):
    """One unresolved exact catalog lookup, not a negative hardware verdict."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticUnresolvedHardwareReference":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_UNRESOLVED_HARDWARE_REFERENCE_CONTRACT
        )
        body = _StaticUnresolvedHardwareReferenceBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_unresolved_hardware_reference_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticUnresolvedHardwareReference":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_unresolved_hardware_reference_id(payload):
            raise ValueError("unresolved hardware reference ID mismatch")
        return self


def static_cross_layer_candidate_diagnostics(
    *,
    bindings: list[StaticCrossLayerCandidateBinding],
    unresolved_references: list[StaticUnresolvedHardwareReference],
) -> list[str]:
    """Return deterministic, non-scoring projection counts."""

    resolution_records = [*bindings, *unresolved_references]
    return sorted(
        [
            "candidate_case_count:"
            f"{len({item.source_case_candidate_id for item in resolution_records})}",
            "source_declared_hardware_reference_count:"
            f"{len(resolution_records)}",
            f"resolved_cross_layer_binding_count:{len(bindings)}",
            f"unresolved_reference_count:{len(unresolved_references)}",
            "documented_erratum_binding_count:"
            f"{sum(item.hardware_reference_kind is StaticHardwareReferenceKind.DOCUMENTED_HARDWARE_ERRATUM for item in bindings)}",
            "owned_synthetic_binding_count:"
            f"{sum(item.hardware_reference_kind is StaticHardwareReferenceKind.OWNED_SYNTHETIC_CONDITION for item in bindings)}",
            "reference_not_in_catalog_count:"
            f"{sum(item.reason is StaticUnresolvedHardwareReferenceReason.REFERENCE_NOT_IN_CATALOG for item in unresolved_references)}",
            "reference_architecture_mismatch_count:"
            f"{sum(item.reason is StaticUnresolvedHardwareReferenceReason.REFERENCE_ARCHITECTURE_MISMATCH for item in unresolved_references)}",
        ]
    )


class _StaticCrossLayerCandidateProjectionBody(DomainModel):
    contract: Literal["phase10d_static_cross_layer_candidate_projection_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    source_candidate_materialization_id: Identifier
    source_candidate_projection_id: Identifier
    source_hardware_reference_catalog_id: Identifier
    bindings: list[StaticCrossLayerCandidateBinding] = Field(default_factory=list)
    unresolved_references: list[StaticUnresolvedHardwareReference] = Field(
        default_factory=list
    )
    diagnostic_codes: list[Identifier]

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _validate_sha256(value)

    @field_validator("bindings")
    @classmethod
    def normalize_bindings(
        cls, values: list[StaticCrossLayerCandidateBinding]
    ) -> list[StaticCrossLayerCandidateBinding]:
        detached = [
            StaticCrossLayerCandidateBinding.model_validate(
                value.model_dump(mode="json")
            )
            for value in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("cross-layer binding IDs must be unique")
        return sorted(
            detached,
            key=lambda item: (
                item.source_case_candidate_id,
                item.source_hardware_reference_id,
                item.id,
            ),
        )

    @field_validator("unresolved_references")
    @classmethod
    def normalize_unresolved(
        cls, values: list[StaticUnresolvedHardwareReference]
    ) -> list[StaticUnresolvedHardwareReference]:
        detached = [
            StaticUnresolvedHardwareReference.model_validate(
                value.model_dump(mode="json")
            )
            for value in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("unresolved reference IDs must be unique")
        return sorted(
            detached,
            key=lambda item: (
                item.source_case_candidate_id,
                item.source_hardware_reference_id,
                item.id,
            ),
        )

    @model_validator(mode="after")
    def validate_internal_integrity(
        self,
    ) -> "_StaticCrossLayerCandidateProjectionBody":
        common = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.instruction_set,
            self.source_candidate_materialization_id,
            self.source_candidate_projection_id,
        )
        records = [*self.bindings, *self.unresolved_references]
        for item in records:
            if (
                item.architecture,
                item.artifact_id,
                item.artifact_sha256,
                item.instruction_set,
                item.source_candidate_materialization_id,
                item.source_candidate_projection_id,
            ) != common:
                raise ValueError("cross-layer resolution record provenance mismatch")
        logical_keys = [
            (item.source_case_candidate_id, item.source_hardware_reference_id)
            for item in records
        ]
        if len(logical_keys) != len(set(logical_keys)):
            raise ValueError("hardware reference resolution keys must be unique")
        expected_diagnostics = static_cross_layer_candidate_diagnostics(
            bindings=self.bindings,
            unresolved_references=self.unresolved_references,
        )
        if self.diagnostic_codes != expected_diagnostics:
            raise ValueError("cross-layer candidate diagnostics mismatch")
        return self


class StaticCrossLayerCandidateProjection(
    _StaticCrossLayerCandidateProjectionBody
):
    """Standalone internally consistent cross-layer reference projection."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticCrossLayerCandidateProjection":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_CROSS_LAYER_CANDIDATE_PROJECTION_CONTRACT
        )
        body_values["diagnostic_codes"] = static_cross_layer_candidate_diagnostics(
            bindings=list(body_values.get("bindings", [])),
            unresolved_references=list(
                body_values.get("unresolved_references", [])
            ),
        )
        body = _StaticCrossLayerCandidateProjectionBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(
            id=static_cross_layer_candidate_projection_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticCrossLayerCandidateProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_cross_layer_candidate_projection_id(payload):
            raise ValueError("static cross-layer candidate projection ID mismatch")
        return self
