"""Closed non-evaluative contracts for B2-B typed-state relevance binding."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture
from chipchain.verification.cross_layer_requirement_models import (
    CandidateRequirementKindV1,
    StaticCrossLayerEvidenceRequirementKind,
)


PHASE10D_CANDIDATE_STATE_REQUIREMENT_OBSERVATION_BINDING_CONTRACT = (
    "phase10d_candidate_state_requirement_observation_binding_v1"
)
PHASE10D_CANDIDATE_STATE_REQUIREMENT_ACQUISITION_GAP_CONTRACT = (
    "phase10d_candidate_state_requirement_acquisition_gap_v1"
)
PHASE10D_CANDIDATE_STATE_SOURCE_INCOMPATIBILITY_CONTRACT = (
    "phase10d_candidate_state_source_incompatibility_v1"
)
PHASE10D_CANDIDATE_STATE_REQUIREMENT_BINDING_PROJECTION_CONTRACT = (
    "phase10d_candidate_state_requirement_binding_projection_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CandidateStateObservationFamily(str, Enum):
    """Exact B2-A observation families supported by the B2-B v1 binder."""

    EFFECTIVE_MEMORY_TYPE = "effective_memory_type"
    EXECUTION_CONTEXT = "execution_context"


class CandidateStateRequirementBindingRole(str, Enum):
    """Exact role of a program-location state-source relevance link."""

    EXACT_PROGRAM_LOCATION_STATE_SOURCE_RELEVANCE = (
        "exact_program_location_state_source_relevance"
    )


class CandidateStateRequirementBindingSemantics(str, Enum):
    """The binding records relevance only, never requirement satisfaction."""

    SOURCE_RELEVANCE_ONLY = "source_relevance_only"


class CandidateStateRequirementAcquisitionGapReason(str, Enum):
    """Closed neutral absence reasons for supported B2-B requirements."""

    NO_COMPATIBLE_STATE_SOURCE = "no_compatible_state_source"
    NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT = (
        "no_effective_memory_type_observation_at_subject"
    )
    NO_EXECUTION_CONTEXT_OBSERVATION_AT_SUBJECT = (
        "no_execution_context_observation_at_subject"
    )


class CandidateStateSourceIncompatibilityReason(str, Enum):
    """Exact program-artifact provenance mismatches for one B2-A source."""

    ARCHITECTURE_MISMATCH = "architecture_mismatch"
    ARTIFACT_ID_MISMATCH = "artifact_id_mismatch"
    ARTIFACT_SHA256_MISMATCH = "artifact_sha256_mismatch"
    INSTRUCTION_SET_MISMATCH = "instruction_set_mismatch"


CandidateStateObservationFamilyV1 = Literal[
    CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE,
    CandidateStateObservationFamily.EXECUTION_CONTEXT,
]
CandidateStateRequirementBindingRoleV1 = Literal[
    CandidateStateRequirementBindingRole
    .EXACT_PROGRAM_LOCATION_STATE_SOURCE_RELEVANCE
]
CandidateStateRequirementBindingSemanticsV1 = Literal[
    CandidateStateRequirementBindingSemantics.SOURCE_RELEVANCE_ONLY
]
CandidateStateRequirementAcquisitionGapReasonV1 = Literal[
    CandidateStateRequirementAcquisitionGapReason.NO_COMPATIBLE_STATE_SOURCE,
    CandidateStateRequirementAcquisitionGapReason
    .NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT,
    CandidateStateRequirementAcquisitionGapReason
    .NO_EXECUTION_CONTEXT_OBSERVATION_AT_SUBJECT,
]
CandidateStateSourceIncompatibilityReasonV1 = Literal[
    CandidateStateSourceIncompatibilityReason.ARCHITECTURE_MISMATCH,
    CandidateStateSourceIncompatibilityReason.ARTIFACT_ID_MISMATCH,
    CandidateStateSourceIncompatibilityReason.ARTIFACT_SHA256_MISMATCH,
    CandidateStateSourceIncompatibilityReason.INSTRUCTION_SET_MISMATCH,
]


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _deterministic_id(prefix: str, payload: object) -> str:
    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"{prefix}:{digest}"


def candidate_state_requirement_observation_binding_id(payload: object) -> str:
    """Return one deterministic requirement/observation relevance ID."""

    return _deterministic_id(
        "candidate-state-requirement-observation-binding", payload
    )


def candidate_state_requirement_acquisition_gap_id(payload: object) -> str:
    """Return one deterministic supported-requirement acquisition-gap ID."""

    return _deterministic_id(
        "candidate-state-requirement-acquisition-gap", payload
    )


def candidate_state_source_incompatibility_id(payload: object) -> str:
    """Return one deterministic incompatible B2-A source record ID."""

    return _deterministic_id("candidate-state-source-incompatibility", payload)


def candidate_state_requirement_binding_projection_id(payload: object) -> str:
    """Return one deterministic B2-B projection ID."""

    return _deterministic_id(
        "candidate-state-requirement-binding-projection", payload
    )


def _normalized_ids(values: list[str], *, label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return sorted(values)


class _ProgramArtifactProvenance(DomainModel):
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier

    @field_validator("artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("state binding artifact SHA-256 is invalid")
        return value


class _CandidateStateRequirementObservationBindingBody(
    _ProgramArtifactProvenance
):
    contract: Literal[
        "phase10d_candidate_state_requirement_observation_binding_v1"
    ]
    source_requirement_materialization_id: Identifier
    source_requirement_projection_id: Identifier
    source_requirement_id: Identifier
    source_requirement_kind: CandidateRequirementKindV1
    source_case_candidate_id: Identifier
    source_state_materialization_id: Identifier
    source_state_manifest_id: Identifier
    source_state_observation_id: Identifier
    source_observation_family: CandidateStateObservationFamilyV1
    matched_subject_position_candidate_ids: list[Identifier] = Field(
        min_length=1
    )
    matched_subject_fused_fact_node_ids: list[Identifier] = Field(min_length=1)
    binding_role: CandidateStateRequirementBindingRoleV1 = (
        CandidateStateRequirementBindingRole
        .EXACT_PROGRAM_LOCATION_STATE_SOURCE_RELEVANCE
    )
    binding_semantics: CandidateStateRequirementBindingSemanticsV1 = (
        CandidateStateRequirementBindingSemantics.SOURCE_RELEVANCE_ONLY
    )

    @field_validator(
        "matched_subject_position_candidate_ids",
        "matched_subject_fused_fact_node_ids",
    )
    @classmethod
    def normalize_subject_ids(cls, values: list[str], info) -> list[str]:
        return _normalized_ids(values, label=info.field_name)

    @model_validator(mode="after")
    def validate_family_kind(
        self,
    ) -> "_CandidateStateRequirementObservationBindingBody":
        expected = {
            CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE: (
                StaticCrossLayerEvidenceRequirementKind
                .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED
            ),
            CandidateStateObservationFamily.EXECUTION_CONTEXT: (
                StaticCrossLayerEvidenceRequirementKind
                .EXECUTION_CONTEXT_EVIDENCE_REQUIRED
            ),
        }[self.source_observation_family]
        if self.source_requirement_kind is not expected:
            raise ValueError("state observation family/requirement kind mismatch")
        return self


class CandidateStateRequirementObservationBinding(
    _CandidateStateRequirementObservationBindingBody
):
    """Exact program-location source relevance; never a satisfaction result.

    For memory records, location association does not establish instruction
    execution, an access to the retained address, or an executed memory type.
    """

    id: Identifier

    @classmethod
    def create(
        cls, **values: object
    ) -> "CandidateStateRequirementObservationBinding":
        body = _CandidateStateRequirementObservationBindingBody.model_validate(
            {
                **values,
                "contract": (
                    PHASE10D_CANDIDATE_STATE_REQUIREMENT_OBSERVATION_BINDING_CONTRACT
                ),
            }
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_state_requirement_observation_binding_id(payload),
            **payload,
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateStateRequirementObservationBinding":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_state_requirement_observation_binding_id(payload):
            raise ValueError("state requirement observation binding ID mismatch")
        return self


class _CandidateStateRequirementAcquisitionGapBody(DomainModel):
    contract: Literal[
        "phase10d_candidate_state_requirement_acquisition_gap_v1"
    ]
    source_requirement_materialization_id: Identifier
    source_requirement_projection_id: Identifier
    source_requirement_id: Identifier
    source_requirement_kind: CandidateRequirementKindV1
    source_case_candidate_id: Identifier
    reason: CandidateStateRequirementAcquisitionGapReasonV1

    @model_validator(mode="after")
    def validate_reason_kind(
        self,
    ) -> "_CandidateStateRequirementAcquisitionGapBody":
        if (
            self.reason
            is CandidateStateRequirementAcquisitionGapReason
            .NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT
            and self.source_requirement_kind
            is not StaticCrossLayerEvidenceRequirementKind
            .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED
        ):
            raise ValueError("memory observation gap has the wrong requirement kind")
        if (
            self.reason
            is CandidateStateRequirementAcquisitionGapReason
            .NO_EXECUTION_CONTEXT_OBSERVATION_AT_SUBJECT
            and self.source_requirement_kind
            is not StaticCrossLayerEvidenceRequirementKind
            .EXECUTION_CONTEXT_EVIDENCE_REQUIRED
        ):
            raise ValueError("context observation gap has the wrong requirement kind")
        if self.source_requirement_kind not in {
            StaticCrossLayerEvidenceRequirementKind
            .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED,
            StaticCrossLayerEvidenceRequirementKind
            .EXECUTION_CONTEXT_EVIDENCE_REQUIRED,
        }:
            raise ValueError("state acquisition gap uses an unsupported requirement")
        return self


class CandidateStateRequirementAcquisitionGap(
    _CandidateStateRequirementAcquisitionGapBody
):
    """A neutral absence of relevant B2-A observations, never failure."""

    id: Identifier

    @classmethod
    def create(
        cls, **values: object
    ) -> "CandidateStateRequirementAcquisitionGap":
        body = _CandidateStateRequirementAcquisitionGapBody.model_validate(
            {
                **values,
                "contract": (
                    PHASE10D_CANDIDATE_STATE_REQUIREMENT_ACQUISITION_GAP_CONTRACT
                ),
            }
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_state_requirement_acquisition_gap_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateStateRequirementAcquisitionGap":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_state_requirement_acquisition_gap_id(payload):
            raise ValueError("state requirement acquisition gap ID mismatch")
        return self


class _CandidateStateSourceIncompatibilityBody(DomainModel):
    contract: Literal["phase10d_candidate_state_source_incompatibility_v1"]
    source_state_materialization_id: Identifier
    source_state_manifest_id: Identifier
    observed_architecture: Architecture
    observed_artifact_id: Identifier
    observed_artifact_sha256: Identifier
    observed_instruction_set: Identifier
    reasons: list[CandidateStateSourceIncompatibilityReasonV1] = Field(
        min_length=1
    )

    @field_validator("observed_artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("incompatible state source artifact SHA-256 is invalid")
        return value

    @field_validator("reasons")
    @classmethod
    def normalize_reasons(
        cls, values: list[CandidateStateSourceIncompatibilityReasonV1]
    ) -> list[CandidateStateSourceIncompatibilityReasonV1]:
        if len(values) != len(set(values)):
            raise ValueError("state source incompatibility reasons must be unique")
        return sorted(values, key=lambda item: item.value)


class CandidateStateSourceIncompatibility(
    _CandidateStateSourceIncompatibilityBody
):
    """One valid B2-A source excluded by exact program provenance."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateStateSourceIncompatibility":
        body = _CandidateStateSourceIncompatibilityBody.model_validate(
            {
                **values,
                "contract": (
                    PHASE10D_CANDIDATE_STATE_SOURCE_INCOMPATIBILITY_CONTRACT
                ),
            }
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_state_source_incompatibility_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateStateSourceIncompatibility":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_state_source_incompatibility_id(payload):
            raise ValueError("state source incompatibility ID mismatch")
        return self


def candidate_state_requirement_binding_diagnostics(
    *,
    source_state_materialization_ids: list[str],
    compatible_state_materialization_ids: list[str],
    incompatible_state_sources: list[CandidateStateSourceIncompatibility],
    observation_requirement_bindings: list[
        CandidateStateRequirementObservationBinding
    ],
    acquisition_gaps: list[CandidateStateRequirementAcquisitionGap],
    out_of_scope_requirement_ids: list[str],
) -> list[str]:
    """Return deterministic B2-B counts without ratios, scores, or verdicts."""

    requirement_kinds = {
        item.source_requirement_id: item.source_requirement_kind
        for item in [*observation_requirement_bindings, *acquisition_gaps]
    }
    bound_requirement_ids = {
        item.source_requirement_id for item in observation_requirement_bindings
    }
    gap_requirement_ids = {item.source_requirement_id for item in acquisition_gaps}
    return sorted(
        [
            f"state_source_count:{len(source_state_materialization_ids)}",
            "compatible_state_source_count:"
            f"{len(compatible_state_materialization_ids)}",
            "incompatible_state_source_count:"
            f"{len(incompatible_state_sources)}",
            "memory_requirement_count:"
            f"{sum(kind is StaticCrossLayerEvidenceRequirementKind.EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED for kind in requirement_kinds.values())}",
            "context_requirement_count:"
            f"{sum(kind is StaticCrossLayerEvidenceRequirementKind.EXECUTION_CONTEXT_EVIDENCE_REQUIRED for kind in requirement_kinds.values())}",
            "memory_binding_count:"
            f"{sum(item.source_observation_family is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE for item in observation_requirement_bindings)}",
            "context_binding_count:"
            f"{sum(item.source_observation_family is CandidateStateObservationFamily.EXECUTION_CONTEXT for item in observation_requirement_bindings)}",
            "requirements_with_state_observation_binding_count:"
            f"{len(bound_requirement_ids)}",
            "requirements_without_state_observation_binding_count:"
            f"{len(gap_requirement_ids)}",
            f"acquisition_gap_count:{len(acquisition_gaps)}",
            "out_of_scope_requirement_count:"
            f"{len(out_of_scope_requirement_ids)}",
        ]
    )


class _CandidateStateRequirementBindingProjectionBody(
    _ProgramArtifactProvenance
):
    contract: Literal[
        "phase10d_candidate_state_requirement_binding_projection_v1"
    ]
    source_requirement_materialization_id: Identifier
    source_requirement_projection_id: Identifier
    source_state_materialization_ids: list[Identifier] = Field(default_factory=list)
    compatible_state_materialization_ids: list[Identifier] = Field(
        default_factory=list
    )
    incompatible_state_sources: list[
        CandidateStateSourceIncompatibility
    ] = Field(default_factory=list)
    observation_requirement_bindings: list[
        CandidateStateRequirementObservationBinding
    ] = Field(default_factory=list)
    acquisition_gaps: list[CandidateStateRequirementAcquisitionGap] = Field(
        default_factory=list
    )
    out_of_scope_requirement_ids: list[Identifier] = Field(default_factory=list)
    diagnostic_codes: list[Identifier]

    @field_validator(
        "source_state_materialization_ids",
        "compatible_state_materialization_ids",
        "out_of_scope_requirement_ids",
        "diagnostic_codes",
    )
    @classmethod
    def normalize_ids(cls, values: list[str], info) -> list[str]:
        return _normalized_ids(values, label=info.field_name)

    @field_validator("incompatible_state_sources")
    @classmethod
    def normalize_incompatibilities(
        cls, values: list[CandidateStateSourceIncompatibility]
    ) -> list[CandidateStateSourceIncompatibility]:
        detached = [
            CandidateStateSourceIncompatibility.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        source_ids = [item.source_state_materialization_id for item in detached]
        if len({item.id for item in detached}) != len(detached) or len(
            source_ids
        ) != len(set(source_ids)):
            raise ValueError("state source incompatibilities must be source-specific")
        return sorted(detached, key=lambda item: item.source_state_materialization_id)

    @field_validator("observation_requirement_bindings")
    @classmethod
    def normalize_bindings(
        cls, values: list[CandidateStateRequirementObservationBinding]
    ) -> list[CandidateStateRequirementObservationBinding]:
        detached = [
            CandidateStateRequirementObservationBinding.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        logical = [
            (item.source_requirement_id, item.source_state_observation_id)
            for item in detached
        ]
        if len({item.id for item in detached}) != len(detached) or len(
            logical
        ) != len(set(logical)):
            raise ValueError("state observation bindings must be logically unique")
        return sorted(
            detached,
            key=lambda item: (
                item.source_requirement_id,
                item.source_state_observation_id,
                item.id,
            ),
        )

    @field_validator("acquisition_gaps")
    @classmethod
    def normalize_gaps(
        cls, values: list[CandidateStateRequirementAcquisitionGap]
    ) -> list[CandidateStateRequirementAcquisitionGap]:
        detached = [
            CandidateStateRequirementAcquisitionGap.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        requirement_ids = [item.source_requirement_id for item in detached]
        if len({item.id for item in detached}) != len(detached) or len(
            requirement_ids
        ) != len(set(requirement_ids)):
            raise ValueError("state acquisition gaps must be requirement-specific")
        return sorted(detached, key=lambda item: item.source_requirement_id)

    @model_validator(mode="after")
    def validate_integrity(
        self,
    ) -> "_CandidateStateRequirementBindingProjectionBody":
        incompatible_ids = {
            item.source_state_materialization_id
            for item in self.incompatible_state_sources
        }
        compatible_ids = set(self.compatible_state_materialization_ids)
        if incompatible_ids.intersection(compatible_ids):
            raise ValueError("state source cannot be compatible and incompatible")
        if set(self.source_state_materialization_ids) != (
            incompatible_ids | compatible_ids
        ):
            raise ValueError("state source compatibility partition is incomplete")

        artifact_common = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.instruction_set,
        )
        requirement_common = (
            self.source_requirement_materialization_id,
            self.source_requirement_projection_id,
        )
        bound_requirement_ids: set[str] = set()
        requirement_kinds: dict[str, CandidateRequirementKindV1] = {}
        for item in self.observation_requirement_bindings:
            if (
                item.architecture,
                item.artifact_id,
                item.artifact_sha256,
                item.instruction_set,
            ) != artifact_common:
                raise ValueError("state binding artifact provenance mismatch")
            if (
                item.source_requirement_materialization_id,
                item.source_requirement_projection_id,
            ) != requirement_common:
                raise ValueError("state binding requirement source mismatch")
            if item.source_state_materialization_id not in compatible_ids:
                raise ValueError("state binding uses an incompatible source")
            previous = requirement_kinds.setdefault(
                item.source_requirement_id, item.source_requirement_kind
            )
            if previous is not item.source_requirement_kind:
                raise ValueError("state binding requirement kind is inconsistent")
            bound_requirement_ids.add(item.source_requirement_id)

        gap_requirement_ids: set[str] = set()
        for item in self.acquisition_gaps:
            if (
                item.source_requirement_materialization_id,
                item.source_requirement_projection_id,
            ) != requirement_common:
                raise ValueError("state acquisition gap requirement source mismatch")
            previous = requirement_kinds.setdefault(
                item.source_requirement_id, item.source_requirement_kind
            )
            if previous is not item.source_requirement_kind:
                raise ValueError("state acquisition gap requirement kind is inconsistent")
            if compatible_ids:
                expected_reason = (
                    CandidateStateRequirementAcquisitionGapReason
                    .NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT
                    if item.source_requirement_kind
                    is StaticCrossLayerEvidenceRequirementKind
                    .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED
                    else CandidateStateRequirementAcquisitionGapReason
                    .NO_EXECUTION_CONTEXT_OBSERVATION_AT_SUBJECT
                )
            else:
                expected_reason = (
                    CandidateStateRequirementAcquisitionGapReason
                    .NO_COMPATIBLE_STATE_SOURCE
                )
            if item.reason is not expected_reason:
                raise ValueError("state acquisition gap/source compatibility mismatch")
            gap_requirement_ids.add(item.source_requirement_id)
        if bound_requirement_ids.intersection(gap_requirement_ids):
            raise ValueError("bound requirement cannot also have an acquisition gap")
        if (bound_requirement_ids | gap_requirement_ids).intersection(
            self.out_of_scope_requirement_ids
        ):
            raise ValueError("supported and out-of-scope requirements overlap")

        expected = candidate_state_requirement_binding_diagnostics(
            source_state_materialization_ids=self.source_state_materialization_ids,
            compatible_state_materialization_ids=(
                self.compatible_state_materialization_ids
            ),
            incompatible_state_sources=self.incompatible_state_sources,
            observation_requirement_bindings=self.observation_requirement_bindings,
            acquisition_gaps=self.acquisition_gaps,
            out_of_scope_requirement_ids=self.out_of_scope_requirement_ids,
        )
        if self.diagnostic_codes != expected:
            raise ValueError("state requirement binding diagnostics mismatch")
        return self


class CandidateStateRequirementBindingProjection(
    _CandidateStateRequirementBindingProjectionBody
):
    """Standalone internal integrity for non-evaluative B2-B relevance."""

    id: Identifier

    @classmethod
    def create(
        cls, **values: object
    ) -> "CandidateStateRequirementBindingProjection":
        body_values = {
            **values,
            "contract": (
                PHASE10D_CANDIDATE_STATE_REQUIREMENT_BINDING_PROJECTION_CONTRACT
            ),
        }
        typed_collections = (
            (
                "incompatible_state_sources",
                CandidateStateSourceIncompatibility,
            ),
            (
                "observation_requirement_bindings",
                CandidateStateRequirementObservationBinding,
            ),
            ("acquisition_gaps", CandidateStateRequirementAcquisitionGap),
        )
        for field_name, model in typed_collections:
            body_values[field_name] = [
                item if isinstance(item, model) else model.model_validate(item)
                for item in body_values.get(field_name, [])
            ]
        body_values["diagnostic_codes"] = (
            candidate_state_requirement_binding_diagnostics(
                source_state_materialization_ids=list(
                    body_values.get("source_state_materialization_ids", [])
                ),
                compatible_state_materialization_ids=list(
                    body_values.get("compatible_state_materialization_ids", [])
                ),
                incompatible_state_sources=list(
                    body_values.get("incompatible_state_sources", [])
                ),
                observation_requirement_bindings=list(
                    body_values.get("observation_requirement_bindings", [])
                ),
                acquisition_gaps=list(body_values.get("acquisition_gaps", [])),
                out_of_scope_requirement_ids=list(
                    body_values.get("out_of_scope_requirement_ids", [])
                ),
            )
        )
        body = _CandidateStateRequirementBindingProjectionBody.model_validate(
            body_values
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_state_requirement_binding_projection_id(payload),
            **payload,
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateStateRequirementBindingProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_state_requirement_binding_projection_id(payload):
            raise ValueError("state requirement binding projection ID mismatch")
        return self


__all__ = [
    "CandidateStateObservationFamily",
    "CandidateStateRequirementBindingRole",
    "CandidateStateRequirementBindingSemantics",
    "CandidateStateRequirementAcquisitionGapReason",
    "CandidateStateSourceIncompatibilityReason",
    "CandidateStateObservationFamilyV1",
    "CandidateStateRequirementBindingRoleV1",
    "CandidateStateRequirementBindingSemanticsV1",
    "CandidateStateRequirementAcquisitionGapReasonV1",
    "CandidateStateSourceIncompatibilityReasonV1",
    "CandidateStateRequirementObservationBinding",
    "CandidateStateRequirementAcquisitionGap",
    "CandidateStateSourceIncompatibility",
    "CandidateStateRequirementBindingProjection",
    "candidate_state_requirement_observation_binding_id",
    "candidate_state_requirement_acquisition_gap_id",
    "candidate_state_source_incompatibility_id",
    "candidate_state_requirement_binding_projection_id",
]
