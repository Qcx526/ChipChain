"""Neutral runtime-observation artifacts for candidate requirements."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier
from chipchain.runtime.enums import RuntimeBackendKind, RuntimeRunMode
from chipchain.verification.cross_layer_requirement_models import (
    CandidateRequirementKindV1,
    StaticCrossLayerEvidenceRequirementKind,
)
from chipchain.verification.models import ProgramAddress


PHASE10D_CANDIDATE_RUNTIME_INSTRUCTION_EVIDENCE_CONTRACT = (
    "phase10d_candidate_runtime_instruction_evidence_v1"
)
PHASE10D_CANDIDATE_RUNTIME_ORDER_EVIDENCE_CONTRACT = (
    "phase10d_candidate_runtime_order_evidence_v1"
)
PHASE10D_CANDIDATE_RUNTIME_REQUIREMENT_EVIDENCE_BINDING_CONTRACT = (
    "phase10d_candidate_runtime_requirement_evidence_binding_v1"
)
PHASE10D_CANDIDATE_RUNTIME_EVIDENCE_GAP_CONTRACT = (
    "phase10d_candidate_runtime_evidence_gap_v1"
)
PHASE10D_CANDIDATE_RUNTIME_TRACE_INCOMPATIBILITY_CONTRACT = (
    "phase10d_candidate_runtime_trace_incompatibility_v1"
)
PHASE10D_CANDIDATE_RUNTIME_EVIDENCE_PROJECTION_CONTRACT = (
    "phase10d_candidate_runtime_evidence_projection_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CandidateRuntimeEvidenceKind(str, Enum):
    """Closed v1 runtime observation artifact kinds."""

    INSTRUCTION_EXECUTION_OBSERVATION = "instruction_execution_observation"
    STATIC_WITNESS_ENDPOINT_RUNTIME_ORDER_OBSERVATION = (
        "static_witness_endpoint_runtime_order_observation"
    )


class CandidateRuntimeEvidenceSemantics(str, Enum):
    """Non-evaluative meaning shared by B1 runtime artifacts."""

    OBJECTIVE_RUNTIME_OBSERVATION_ONLY = "objective_runtime_observation_only"


class CandidateRuntimeEvidenceBindingRole(str, Enum):
    """Closed role of an exact observation-to-requirement reference."""

    RELEVANT_RUNTIME_OBSERVATION = "relevant_runtime_observation"


class CandidateRuntimeEvidenceBindingSemantics(str, Enum):
    """Binding is source relevance only, never requirement evaluation."""

    EXACT_SOURCE_SUBJECT_BINDING_ONLY = "exact_source_subject_binding_only"


class CandidateRuntimeEvidenceGapReason(str, Enum):
    """Closed evidence-acquisition gaps, not verification outcomes."""

    NO_COMPATIBLE_RUNTIME_TRACE = "no_compatible_runtime_trace"
    NO_MATCHING_INSTRUCTION_OBSERVATION = (
        "no_matching_instruction_observation"
    )
    NO_MATCHING_RUNTIME_ORDER_OBSERVATION = "no_matching_runtime_order_observation"
    CURRENT_RUNTIME_CONTRACT_DOES_NOT_OBSERVE_REQUIREMENT_KIND = (
        "current_runtime_contract_does_not_observe_requirement_kind"
    )


class CandidateRuntimeTraceIncompatibilityReason(str, Enum):
    """Exact provenance fields that exclude an otherwise valid trace."""

    ARCHITECTURE_MISMATCH = "architecture_mismatch"
    ARTIFACT_ID_MISMATCH = "artifact_id_mismatch"
    ARTIFACT_SHA256_MISMATCH = "artifact_sha256_mismatch"


CandidateRuntimeEvidenceGapReasonV1 = Literal[
    CandidateRuntimeEvidenceGapReason.NO_COMPATIBLE_RUNTIME_TRACE,
    CandidateRuntimeEvidenceGapReason.NO_MATCHING_INSTRUCTION_OBSERVATION,
    CandidateRuntimeEvidenceGapReason.NO_MATCHING_RUNTIME_ORDER_OBSERVATION,
    CandidateRuntimeEvidenceGapReason.CURRENT_RUNTIME_CONTRACT_DOES_NOT_OBSERVE_REQUIREMENT_KIND,
]
CandidateRuntimeTraceIncompatibilityReasonV1 = Literal[
    CandidateRuntimeTraceIncompatibilityReason.ARCHITECTURE_MISMATCH,
    CandidateRuntimeTraceIncompatibilityReason.ARTIFACT_ID_MISMATCH,
    CandidateRuntimeTraceIncompatibilityReason.ARTIFACT_SHA256_MISMATCH,
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


def candidate_runtime_instruction_evidence_id(payload: object) -> str:
    """Return one deterministic instruction-observation artifact ID."""

    return _deterministic_id("candidate-runtime-instruction-evidence", payload)


def candidate_runtime_order_evidence_id(payload: object) -> str:
    """Return one deterministic endpoint-order observation artifact ID."""

    return _deterministic_id("candidate-runtime-order-evidence", payload)


def candidate_runtime_requirement_evidence_binding_id(payload: object) -> str:
    """Return one deterministic requirement-to-artifact binding ID."""

    return _deterministic_id(
        "candidate-runtime-requirement-evidence-binding", payload
    )


def candidate_runtime_evidence_gap_id(payload: object) -> str:
    """Return one deterministic requirement-specific acquisition-gap ID."""

    return _deterministic_id("candidate-runtime-evidence-gap", payload)


def candidate_runtime_trace_incompatibility_id(payload: object) -> str:
    """Return one deterministic incompatible-source record ID."""

    return _deterministic_id("candidate-runtime-trace-incompatibility", payload)


def candidate_runtime_evidence_projection_id(payload: object) -> str:
    """Return one deterministic B1 projection ID."""

    return _deterministic_id("candidate-runtime-evidence-projection", payload)


def _normalized_ids(values: list[str], *, label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return sorted(values)


class _RuntimeArtifactProvenance(DomainModel):
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    source_runtime_trace_id: Identifier
    source_runtime_manifest_id: Identifier
    source_runtime_backend_manifest_id: Identifier
    source_runtime_backend_kind: RuntimeBackendKind
    source_runtime_run_mode: RuntimeRunMode

    @field_validator("artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("runtime evidence artifact SHA-256 is invalid")
        return value

    @model_validator(mode="after")
    def validate_trace_identity(self) -> "_RuntimeArtifactProvenance":
        if self.source_runtime_trace_id != self.source_runtime_manifest_id:
            raise ValueError("runtime trace and manifest identity must agree")
        return self


class _CandidateRuntimeInstructionEvidenceBody(_RuntimeArtifactProvenance):
    contract: Literal["phase10d_candidate_runtime_instruction_evidence_v1"]
    source_position_candidate_ids: list[Identifier] = Field(min_length=1)
    source_fused_fact_node_ids: list[Identifier] = Field(min_length=1)
    expected_instruction_address: ProgramAddress
    source_runtime_observation_id: Identifier
    observation_sequence_index: int = Field(ge=0)
    observation_vcpu_index: int = Field(ge=0)
    observed_pc: ProgramAddress
    evidence_kind: Literal[
        CandidateRuntimeEvidenceKind.INSTRUCTION_EXECUTION_OBSERVATION
    ] = CandidateRuntimeEvidenceKind.INSTRUCTION_EXECUTION_OBSERVATION
    evidence_semantics: Literal[
        CandidateRuntimeEvidenceSemantics.OBJECTIVE_RUNTIME_OBSERVATION_ONLY
    ] = CandidateRuntimeEvidenceSemantics.OBJECTIVE_RUNTIME_OBSERVATION_ONLY

    @field_validator(
        "source_position_candidate_ids", "source_fused_fact_node_ids"
    )
    @classmethod
    def normalize_subject_ids(cls, values: list[str], info) -> list[str]:
        return _normalized_ids(values, label=info.field_name)

    @field_validator(
        "expected_instruction_address", "observed_pc", mode="before"
    )
    @classmethod
    def normalize_addresses(cls, value: object) -> object:
        if isinstance(value, str):
            return ProgramAddress(value=value)
        return value

    @model_validator(mode="after")
    def validate_exact_pc(self) -> "_CandidateRuntimeInstructionEvidenceBody":
        if self.observed_pc != self.expected_instruction_address:
            raise ValueError("observed PC differs from exact subject address")
        return self


class CandidateRuntimeInstructionEvidence(
    _CandidateRuntimeInstructionEvidenceBody
):
    """One neutral exact instruction-execution observation artifact."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateRuntimeInstructionEvidence":
        body = _CandidateRuntimeInstructionEvidenceBody.model_validate(
            {
                **values,
                "contract": (
                    PHASE10D_CANDIDATE_RUNTIME_INSTRUCTION_EVIDENCE_CONTRACT
                ),
            }
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_runtime_instruction_evidence_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateRuntimeInstructionEvidence":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_runtime_instruction_evidence_id(payload):
            raise ValueError("runtime instruction evidence ID mismatch")
        return self


class _CandidateRuntimeOrderEvidenceBody(_RuntimeArtifactProvenance):
    contract: Literal["phase10d_candidate_runtime_order_evidence_v1"]
    source_static_order_witness_id: Identifier
    source_position_candidate_id: Identifier
    target_position_candidate_id: Identifier
    source_fused_fact_node_id: Identifier
    target_fused_fact_node_id: Identifier
    expected_source_instruction_address: ProgramAddress
    expected_target_instruction_address: ProgramAddress
    source_runtime_observation_id: Identifier
    target_runtime_observation_id: Identifier
    source_sequence_index: int = Field(ge=0)
    target_sequence_index: int = Field(ge=0)
    vcpu_index: int = Field(ge=0)
    evidence_kind: Literal[
        CandidateRuntimeEvidenceKind
        .STATIC_WITNESS_ENDPOINT_RUNTIME_ORDER_OBSERVATION
    ] = (
        CandidateRuntimeEvidenceKind
        .STATIC_WITNESS_ENDPOINT_RUNTIME_ORDER_OBSERVATION
    )
    evidence_semantics: Literal[
        CandidateRuntimeEvidenceSemantics.OBJECTIVE_RUNTIME_OBSERVATION_ONLY
    ] = CandidateRuntimeEvidenceSemantics.OBJECTIVE_RUNTIME_OBSERVATION_ONLY

    @field_validator(
        "expected_source_instruction_address",
        "expected_target_instruction_address",
        mode="before",
    )
    @classmethod
    def normalize_addresses(cls, value: object) -> object:
        if isinstance(value, str):
            return ProgramAddress(value=value)
        return value

    @model_validator(mode="after")
    def validate_order_shape(self) -> "_CandidateRuntimeOrderEvidenceBody":
        if self.source_position_candidate_id == self.target_position_candidate_id:
            raise ValueError("runtime order endpoints must be distinct positions")
        if self.source_fused_fact_node_id == self.target_fused_fact_node_id:
            raise ValueError("runtime order endpoints must be distinct facts")
        if self.source_runtime_observation_id == self.target_runtime_observation_id:
            raise ValueError("runtime order endpoints must be distinct observations")
        if self.source_sequence_index >= self.target_sequence_index:
            raise ValueError("runtime order requires increasing sequence indexes")
        return self


class CandidateRuntimeOrderEvidence(_CandidateRuntimeOrderEvidenceBody):
    """One same-trace, same-vCPU ordered static-witness endpoint pair."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateRuntimeOrderEvidence":
        body = _CandidateRuntimeOrderEvidenceBody.model_validate(
            {
                **values,
                "contract": PHASE10D_CANDIDATE_RUNTIME_ORDER_EVIDENCE_CONTRACT,
            }
        )
        payload = body.model_dump(mode="json")
        return cls(id=candidate_runtime_order_evidence_id(payload), **payload)

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateRuntimeOrderEvidence":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_runtime_order_evidence_id(payload):
            raise ValueError("runtime order evidence ID mismatch")
        return self


class _CandidateRuntimeRequirementEvidenceBindingBody(DomainModel):
    contract: Literal[
        "phase10d_candidate_runtime_requirement_evidence_binding_v1"
    ]
    source_requirement_materialization_id: Identifier
    source_requirement_projection_id: Identifier
    source_requirement_id: Identifier
    source_requirement_kind: CandidateRequirementKindV1
    source_case_candidate_id: Identifier
    source_runtime_evidence_id: Identifier
    binding_role: Literal[
        CandidateRuntimeEvidenceBindingRole.RELEVANT_RUNTIME_OBSERVATION
    ] = CandidateRuntimeEvidenceBindingRole.RELEVANT_RUNTIME_OBSERVATION
    binding_semantics: Literal[
        CandidateRuntimeEvidenceBindingSemantics
        .EXACT_SOURCE_SUBJECT_BINDING_ONLY
    ] = (
        CandidateRuntimeEvidenceBindingSemantics
        .EXACT_SOURCE_SUBJECT_BINDING_ONLY
    )


class CandidateRuntimeRequirementEvidenceBinding(
    _CandidateRuntimeRequirementEvidenceBindingBody
):
    """An exact relevance link, separate from its runtime artifact."""

    id: Identifier

    @classmethod
    def create(
        cls, **values: object
    ) -> "CandidateRuntimeRequirementEvidenceBinding":
        body = _CandidateRuntimeRequirementEvidenceBindingBody.model_validate(
            {
                **values,
                "contract": (
                    PHASE10D_CANDIDATE_RUNTIME_REQUIREMENT_EVIDENCE_BINDING_CONTRACT
                ),
            }
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_runtime_requirement_evidence_binding_id(payload),
            **payload,
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateRuntimeRequirementEvidenceBinding":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_runtime_requirement_evidence_binding_id(payload):
            raise ValueError("runtime requirement evidence binding ID mismatch")
        return self


class _CandidateRuntimeEvidenceGapBody(DomainModel):
    contract: Literal["phase10d_candidate_runtime_evidence_gap_v1"]
    source_requirement_materialization_id: Identifier
    source_requirement_projection_id: Identifier
    source_requirement_id: Identifier
    source_requirement_kind: CandidateRequirementKindV1
    source_case_candidate_id: Identifier
    reason: CandidateRuntimeEvidenceGapReasonV1


class CandidateRuntimeEvidenceGap(_CandidateRuntimeEvidenceGapBody):
    """Absence of the requirement kind's primary B1 observation artifact.

    A path gap can coexist with ancillary endpoint instruction bindings.
    It records missing runtime-order evidence, not a feasibility verdict.
    """

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateRuntimeEvidenceGap":
        body = _CandidateRuntimeEvidenceGapBody.model_validate(
            {
                **values,
                "contract": PHASE10D_CANDIDATE_RUNTIME_EVIDENCE_GAP_CONTRACT,
            }
        )
        payload = body.model_dump(mode="json")
        return cls(id=candidate_runtime_evidence_gap_id(payload), **payload)

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateRuntimeEvidenceGap":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_runtime_evidence_gap_id(payload):
            raise ValueError("candidate runtime evidence gap ID mismatch")
        return self


class _CandidateRuntimeTraceIncompatibilityBody(DomainModel):
    contract: Literal["phase10d_candidate_runtime_trace_incompatibility_v1"]
    source_runtime_trace_id: Identifier
    source_runtime_manifest_id: Identifier
    source_runtime_backend_manifest_id: Identifier
    source_runtime_backend_kind: RuntimeBackendKind
    source_runtime_run_mode: RuntimeRunMode
    observed_architecture: Architecture
    observed_artifact_id: Identifier
    observed_artifact_sha256: Identifier
    reasons: list[CandidateRuntimeTraceIncompatibilityReasonV1] = Field(
        min_length=1
    )

    @field_validator("observed_artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("incompatible trace artifact SHA-256 is invalid")
        return value

    @field_validator("reasons")
    @classmethod
    def normalize_reasons(
        cls, values: list[CandidateRuntimeTraceIncompatibilityReasonV1]
    ) -> list[CandidateRuntimeTraceIncompatibilityReasonV1]:
        if len(values) != len(set(values)):
            raise ValueError("trace incompatibility reasons must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_trace_identity(
        self,
    ) -> "_CandidateRuntimeTraceIncompatibilityBody":
        if self.source_runtime_trace_id != self.source_runtime_manifest_id:
            raise ValueError("incompatible trace and manifest identity must agree")
        return self


class CandidateRuntimeTraceIncompatibility(
    _CandidateRuntimeTraceIncompatibilityBody
):
    """An auditable exclusion of one valid but provenance-incompatible trace."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateRuntimeTraceIncompatibility":
        body = _CandidateRuntimeTraceIncompatibilityBody.model_validate(
            {
                **values,
                "contract": (
                    PHASE10D_CANDIDATE_RUNTIME_TRACE_INCOMPATIBILITY_CONTRACT
                ),
            }
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_runtime_trace_incompatibility_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateRuntimeTraceIncompatibility":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_runtime_trace_incompatibility_id(payload):
            raise ValueError("runtime trace incompatibility ID mismatch")
        return self


def candidate_runtime_acquisition_gap_reason(
    requirement_kind: CandidateRequirementKindV1,
    *,
    has_compatible_trace: bool,
    evidence_kinds: set[CandidateRuntimeEvidenceKind],
) -> CandidateRuntimeEvidenceGapReasonV1 | None:
    """Select an acquisition gap from typed artifact presence, never sufficiency."""

    primary_kinds = {
        StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED:
            CandidateRuntimeEvidenceKind.INSTRUCTION_EXECUTION_OBSERVATION,
        StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED:
            CandidateRuntimeEvidenceKind.STATIC_WITNESS_ENDPOINT_RUNTIME_ORDER_OBSERVATION,
    }
    if requirement_kind not in primary_kinds:
        return CandidateRuntimeEvidenceGapReason.CURRENT_RUNTIME_CONTRACT_DOES_NOT_OBSERVE_REQUIREMENT_KIND
    if not has_compatible_trace:
        return CandidateRuntimeEvidenceGapReason.NO_COMPATIBLE_RUNTIME_TRACE
    if primary_kinds[requirement_kind] in evidence_kinds:
        return None
    if requirement_kind is StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED:
        return CandidateRuntimeEvidenceGapReason.NO_MATCHING_INSTRUCTION_OBSERVATION
    return CandidateRuntimeEvidenceGapReason.NO_MATCHING_RUNTIME_ORDER_OBSERVATION


def candidate_runtime_evidence_diagnostics(
    *,
    source_runtime_trace_ids: list[str],
    instruction_evidence: list[CandidateRuntimeInstructionEvidence],
    order_evidence: list[CandidateRuntimeOrderEvidence],
    requirement_evidence_bindings: list[
        CandidateRuntimeRequirementEvidenceBinding
    ],
    evidence_gaps: list[CandidateRuntimeEvidenceGap],
    out_of_scope_requirement_ids: list[str],
) -> list[str]:
    """Return deterministic non-scoring B1 counts."""

    requirement_kinds: dict[str, CandidateRequirementKindV1] = {
        item.source_requirement_id: item.source_requirement_kind
        for item in [*requirement_evidence_bindings, *evidence_gaps]
    }
    with_evidence = {
        item.source_requirement_id for item in requirement_evidence_bindings
    }
    instruction_ids = {item.id for item in instruction_evidence}
    order_ids = {item.id for item in order_evidence}
    runtime_requirements = {
        key for key, kind in requirement_kinds.items()
        if kind is StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED
    }
    path_requirements = {
        key for key, kind in requirement_kinds.items()
        if kind is StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED
    }
    with_instruction = {
        item.source_requirement_id for item in requirement_evidence_bindings
        if item.source_runtime_evidence_id in instruction_ids
    }
    with_order = {
        item.source_requirement_id for item in requirement_evidence_bindings
        if item.source_runtime_evidence_id in order_ids
    }
    return sorted(
        [
            f"runtime_trace_count:{len(source_runtime_trace_ids)}",
            f"instruction_observation_evidence_count:{len(instruction_evidence)}",
            f"runtime_order_evidence_count:{len(order_evidence)}",
            "requirement_evidence_binding_count:"
            f"{len(requirement_evidence_bindings)}",
            "runtime_execution_requirement_count:"
            f"{sum(kind.value == 'runtime_execution_trace_required' for kind in requirement_kinds.values())}",
            "path_requirement_count:"
            f"{sum(kind.value == 'path_feasibility_evidence_required' for kind in requirement_kinds.values())}",
            "requirements_with_any_runtime_evidence_count:"
            f"{len(with_evidence)}",
            "requirements_without_any_runtime_evidence_count:"
            f"{len(set(requirement_kinds) - with_evidence)}",
            "runtime_requirements_with_instruction_evidence_count:"
            f"{len(runtime_requirements & with_instruction)}",
            "runtime_requirements_without_instruction_evidence_count:"
            f"{len(runtime_requirements - with_instruction)}",
            "path_requirements_with_runtime_order_evidence_count:"
            f"{len(path_requirements & with_order)}",
            "path_requirements_without_runtime_order_evidence_count:"
            f"{len(path_requirements - with_order)}",
            "unsupported_candidate_requirement_count:"
            f"{sum(gap.reason is CandidateRuntimeEvidenceGapReason.CURRENT_RUNTIME_CONTRACT_DOES_NOT_OBSERVE_REQUIREMENT_KIND for gap in evidence_gaps)}",
            "out_of_scope_hardware_requirement_count:"
            f"{len(out_of_scope_requirement_ids)}",
        ]
    )


class _CandidateRuntimeEvidenceProjectionBody(DomainModel):
    contract: Literal["phase10d_candidate_runtime_evidence_projection_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    source_requirement_materialization_id: Identifier
    source_requirement_projection_id: Identifier
    source_runtime_trace_ids: list[Identifier] = Field(default_factory=list)
    compatible_runtime_trace_ids: list[Identifier] = Field(default_factory=list)
    incompatible_runtime_sources: list[
        CandidateRuntimeTraceIncompatibility
    ] = Field(default_factory=list)
    instruction_evidence: list[CandidateRuntimeInstructionEvidence] = Field(
        default_factory=list
    )
    order_evidence: list[CandidateRuntimeOrderEvidence] = Field(
        default_factory=list
    )
    requirement_evidence_bindings: list[
        CandidateRuntimeRequirementEvidenceBinding
    ] = Field(default_factory=list)
    evidence_gaps: list[CandidateRuntimeEvidenceGap] = Field(default_factory=list)
    out_of_scope_requirement_ids: list[Identifier] = Field(default_factory=list)
    diagnostic_codes: list[Identifier]

    @field_validator("artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("runtime evidence projection SHA-256 is invalid")
        return value

    @field_validator(
        "source_runtime_trace_ids",
        "compatible_runtime_trace_ids",
        "out_of_scope_requirement_ids",
        "diagnostic_codes",
    )
    @classmethod
    def normalize_ids(cls, values: list[str], info) -> list[str]:
        return _normalized_ids(values, label=info.field_name)

    @field_validator("incompatible_runtime_sources")
    @classmethod
    def normalize_incompatibilities(
        cls, values: list[CandidateRuntimeTraceIncompatibility]
    ) -> list[CandidateRuntimeTraceIncompatibility]:
        detached = [
            CandidateRuntimeTraceIncompatibility.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        if len({item.id for item in detached}) != len(detached):
            raise ValueError("runtime trace incompatibility IDs must be unique")
        if len({item.source_runtime_trace_id for item in detached}) != len(detached):
            raise ValueError("runtime trace incompatibility trace IDs must be unique")
        return sorted(detached, key=lambda item: item.source_runtime_trace_id)

    @field_validator("instruction_evidence")
    @classmethod
    def normalize_instruction_evidence(
        cls, values: list[CandidateRuntimeInstructionEvidence]
    ) -> list[CandidateRuntimeInstructionEvidence]:
        detached = [
            CandidateRuntimeInstructionEvidence.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        if len({item.id for item in detached}) != len(detached):
            raise ValueError("runtime instruction evidence IDs must be unique")
        observations = [item.source_runtime_observation_id for item in detached]
        if len(observations) != len(set(observations)):
            raise ValueError("one runtime observation may appear in the catalog once")
        return sorted(
            detached,
            key=lambda item: (
                item.source_runtime_trace_id,
                item.observation_sequence_index,
                item.id,
            ),
        )

    @field_validator("order_evidence")
    @classmethod
    def normalize_order_evidence(
        cls, values: list[CandidateRuntimeOrderEvidence]
    ) -> list[CandidateRuntimeOrderEvidence]:
        detached = [
            CandidateRuntimeOrderEvidence.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        if len({item.id for item in detached}) != len(detached):
            raise ValueError("runtime order evidence IDs must be unique")
        return sorted(
            detached,
            key=lambda item: (
                item.source_static_order_witness_id,
                item.source_runtime_trace_id,
                item.source_sequence_index,
                item.target_sequence_index,
                item.id,
            ),
        )

    @field_validator("requirement_evidence_bindings")
    @classmethod
    def normalize_bindings(
        cls, values: list[CandidateRuntimeRequirementEvidenceBinding]
    ) -> list[CandidateRuntimeRequirementEvidenceBinding]:
        detached = [
            CandidateRuntimeRequirementEvidenceBinding.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        logical = [
            (item.source_requirement_id, item.source_runtime_evidence_id)
            for item in detached
        ]
        if len({item.id for item in detached}) != len(detached) or len(
            logical
        ) != len(set(logical)):
            raise ValueError("runtime evidence bindings must be logically unique")
        return sorted(
            detached,
            key=lambda item: (
                item.source_requirement_id,
                item.source_runtime_evidence_id,
                item.id,
            ),
        )

    @field_validator("evidence_gaps")
    @classmethod
    def normalize_gaps(
        cls, values: list[CandidateRuntimeEvidenceGap]
    ) -> list[CandidateRuntimeEvidenceGap]:
        detached = [
            CandidateRuntimeEvidenceGap.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        requirement_ids = [item.source_requirement_id for item in detached]
        if len({item.id for item in detached}) != len(detached) or len(
            requirement_ids
        ) != len(set(requirement_ids)):
            raise ValueError("runtime evidence gaps must be requirement-specific")
        return sorted(detached, key=lambda item: item.source_requirement_id)

    @model_validator(mode="after")
    def validate_integrity(self) -> "_CandidateRuntimeEvidenceProjectionBody":
        incompatible_ids = {
            item.source_runtime_trace_id
            for item in self.incompatible_runtime_sources
        }
        compatible_ids = set(self.compatible_runtime_trace_ids)
        if compatible_ids.intersection(incompatible_ids):
            raise ValueError("runtime trace cannot be compatible and incompatible")
        if set(self.source_runtime_trace_ids) != compatible_ids | incompatible_ids:
            raise ValueError("runtime trace compatibility partition is incomplete")

        artifact_common = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.instruction_set,
        )
        evidence_ids: set[str] = set()
        for item in [*self.instruction_evidence, *self.order_evidence]:
            if (
                item.architecture,
                item.artifact_id,
                item.artifact_sha256,
                item.instruction_set,
            ) != artifact_common:
                raise ValueError("runtime evidence artifact provenance mismatch")
            if item.source_runtime_trace_id not in compatible_ids:
                raise ValueError("runtime evidence uses an incompatible trace")
            if item.id in evidence_ids:
                raise ValueError("runtime evidence IDs must be globally unique")
            evidence_ids.add(item.id)

        requirement_common = (
            self.source_requirement_materialization_id,
            self.source_requirement_projection_id,
        )
        bound_requirements: set[str] = set()
        requirement_kinds: dict[str, CandidateRequirementKindV1] = {}
        for item in self.requirement_evidence_bindings:
            if (
                item.source_requirement_materialization_id,
                item.source_requirement_projection_id,
            ) != requirement_common:
                raise ValueError("runtime evidence binding source mismatch")
            if item.source_runtime_evidence_id not in evidence_ids:
                raise ValueError("runtime evidence binding references absent evidence")
            prior = requirement_kinds.setdefault(
                item.source_requirement_id, item.source_requirement_kind
            )
            if prior is not item.source_requirement_kind:
                raise ValueError("runtime requirement kind is inconsistent")
            bound_requirements.add(item.source_requirement_id)
        gap_requirements: set[str] = set()
        for item in self.evidence_gaps:
            if (
                item.source_requirement_materialization_id,
                item.source_requirement_projection_id,
            ) != requirement_common:
                raise ValueError("runtime evidence gap source mismatch")
            prior = requirement_kinds.setdefault(
                item.source_requirement_id, item.source_requirement_kind
            )
            if prior is not item.source_requirement_kind:
                raise ValueError("runtime requirement gap kind is inconsistent")
            gap_requirements.add(item.source_requirement_id)
        catalog = {
            item.id: item for item in [*self.instruction_evidence, *self.order_evidence]
        }
        kinds_by_requirement: dict[str, set[CandidateRuntimeEvidenceKind]] = {}
        for binding in self.requirement_evidence_bindings:
            kinds_by_requirement.setdefault(binding.source_requirement_id, set()).add(
                catalog[binding.source_runtime_evidence_id].evidence_kind
            )
        gaps_by_requirement = {item.source_requirement_id: item for item in self.evidence_gaps}
        for requirement_id, kind in requirement_kinds.items():
            evidence_kinds = kinds_by_requirement.get(requirement_id, set())
            allowed = {CandidateRuntimeEvidenceKind.INSTRUCTION_EXECUTION_OBSERVATION}
            if kind is StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED:
                allowed.add(CandidateRuntimeEvidenceKind.STATIC_WITNESS_ENDPOINT_RUNTIME_ORDER_OBSERVATION)
            elif kind is not StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED:
                allowed = set()
            if not evidence_kinds <= allowed:
                raise ValueError("evidence kind is not relevant to requirement kind")
            expected_reason = candidate_runtime_acquisition_gap_reason(
                kind, has_compatible_trace=bool(compatible_ids),
                evidence_kinds=evidence_kinds,
            )
            gap = gaps_by_requirement.get(requirement_id)
            if (gap.reason if gap else None) != expected_reason:
                raise ValueError("requirement-kind-specific acquisition gap mismatch")
        if (bound_requirements | gap_requirements).intersection(
            self.out_of_scope_requirement_ids
        ):
            raise ValueError("candidate and out-of-scope requirements overlap")

        expected = candidate_runtime_evidence_diagnostics(
            source_runtime_trace_ids=self.source_runtime_trace_ids,
            instruction_evidence=self.instruction_evidence,
            order_evidence=self.order_evidence,
            requirement_evidence_bindings=self.requirement_evidence_bindings,
            evidence_gaps=self.evidence_gaps,
            out_of_scope_requirement_ids=self.out_of_scope_requirement_ids,
        )
        if self.diagnostic_codes != expected:
            raise ValueError("candidate runtime evidence diagnostics mismatch")
        return self


class CandidateRuntimeEvidenceProjection(
    _CandidateRuntimeEvidenceProjectionBody
):
    """Standalone internal integrity for neutral B1 runtime evidence."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateRuntimeEvidenceProjection":
        body_values = {
            **values,
            "contract": PHASE10D_CANDIDATE_RUNTIME_EVIDENCE_PROJECTION_CONTRACT,
        }
        typed_collections = (
            ("instruction_evidence", CandidateRuntimeInstructionEvidence),
            ("order_evidence", CandidateRuntimeOrderEvidence),
            (
                "requirement_evidence_bindings",
                CandidateRuntimeRequirementEvidenceBinding,
            ),
            ("evidence_gaps", CandidateRuntimeEvidenceGap),
        )
        for field_name, model in typed_collections:
            body_values[field_name] = [
                item if isinstance(item, model) else model.model_validate(item)
                for item in body_values.get(field_name, [])
            ]
        body_values["diagnostic_codes"] = candidate_runtime_evidence_diagnostics(
            source_runtime_trace_ids=list(
                body_values.get("source_runtime_trace_ids", [])
            ),
            instruction_evidence=list(body_values.get("instruction_evidence", [])),
            order_evidence=list(body_values.get("order_evidence", [])),
            requirement_evidence_bindings=list(
                body_values.get("requirement_evidence_bindings", [])
            ),
            evidence_gaps=list(body_values.get("evidence_gaps", [])),
            out_of_scope_requirement_ids=list(
                body_values.get("out_of_scope_requirement_ids", [])
            ),
        )
        body = _CandidateRuntimeEvidenceProjectionBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=candidate_runtime_evidence_projection_id(payload), **payload)

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateRuntimeEvidenceProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_runtime_evidence_projection_id(payload):
            raise ValueError("candidate runtime evidence projection ID mismatch")
        return self
