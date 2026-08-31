"""Versioned ARM A-profile semantic trigger-pattern contracts.

The models in this module describe predicates for future objective analyzers.
They contain neither static/runtime occurrences nor observation outcomes.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.hardware_trigger.documented_erratum_models import (
    PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT = (
    "phase10d_a_profile_semantic_trigger_pattern_v1"
)

_CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_CPU_REVISION = re.compile(r"^r[0-9]+p[0-9]+$")


class AProfileSemanticEventKind(str, Enum):
    """Minimal semantic event vocabulary supported by pattern v1."""

    MEMORY_LOAD = "memory_load"
    STORE_EXCLUSIVE = "store_exclusive"
    SYSTEM_REGISTER_READ = "system_register_read"


class AProfileExecutionApplicability(str, Enum):
    """Predicate applicability, not an observed execution state."""

    ARM_A_PROFILE = "arm_a_profile"
    PRIVILEGED_AARCH64 = "privileged_aarch64"


class AProfileSystemRegister(str, Enum):
    """System registers supported by semantic pattern v1."""

    PAR_EL1 = "PAR_EL1"


class AProfileMemoryType(str, Enum):
    """Architectural memory types supported by semantic pattern v1."""

    DEVICE = "device"
    NORMAL_NON_CACHEABLE = "normal_non_cacheable"


class AProfileMemoryTypeSemantics(str, Enum):
    """Meaning of a memory-type predicate."""

    EFFECTIVE_ARCHITECTURAL_MEMORY_TYPE = (
        "effective_architectural_memory_type"
    )


class MemoryTypeObservationRequirement(str, Enum):
    """Objective fact a future analyzer must establish for a load."""

    OBJECTIVE_EFFECTIVE_MEMORY_TYPE_REQUIRED = (
        "objective_effective_memory_type_required"
    )


class SemanticAlternativeSemantics(str, Enum):
    """Combination rule for predicates at one ordered position."""

    OR = "or"


class SemanticPositionOrder(str, Enum):
    """Ordering rule between event positions."""

    PROGRAM_ORDER = "program_order"


class AProfileSemanticRelation(str, Enum):
    """Relations supported by semantic trigger-pattern v1."""

    CLOSE_PROXIMITY = "close_proximity"


class AProfileRelationPrecision(str, Enum):
    """Source precision for one semantic relation."""

    QUALITATIVE_ONLY = "qualitative_only"


class SemanticRelationEvaluability(str, Enum):
    """Limits on objective software-only relation evaluation."""

    SOURCE_INSUFFICIENT_FOR_EXACT_SOFTWARE_ONLY_SATISFACTION = (
        "source_insufficient_for_exact_software_only_satisfaction"
    )


class AProfileAdditionalTimingPrecision(str, Enum):
    """Precision inherited from the documented semantic source."""

    UNSPECIFIED_BY_PUBLIC_SOURCE = "unspecified_by_public_source"


class AdditionalTimingConditionRequirement(str, Enum):
    """Pattern-side obligation for hardware timing not specified publicly."""

    UNRESOLVED_FROM_PUBLIC_DOCUMENTATION = (
        "unresolved_from_public_documentation"
    )


class AProfileRevisionDisposition(str, Enum):
    """Documented processor-revision scope retained by a pattern."""

    AFFECTED = "affected"
    FIXED = "fixed"


class AProfileDocumentedEffectKind(str, Enum):
    """Documented effect reference vocabulary for pattern v1."""

    CORE_DEADLOCK = "core_deadlock"


class AProfileDocumentedEffectModality(str, Enum):
    """Modal force of a documented effect reference."""

    POSSIBLE = "possible"


class AProfileMitigationReferenceKind(str, Enum):
    """Documentation-only mitigation categories carried by pattern v1."""

    PAR_EL1_DMB_SY_ORDERING = "par_el1_dmb_sy_ordering"
    EXCLUSIVE_RELATED_FIRMWARE_OR_HARDWARE = (
        "exclusive_related_firmware_or_hardware"
    )
    CASE_B_EL0_DEVICE_ACCESS_RESTRICTION = (
        "case_b_el0_device_access_restriction"
    )


class AProfileMitigationReferenceSemantics(str, Enum):
    """Separate a documented mitigation reference from active state."""

    DOCUMENTED_MITIGATION_REFERENCE = "documented_mitigation_reference"


class AProfileSemanticPatternUse(str, Enum):
    """Non-outcome use boundary for semantic predicates."""

    OBJECTIVE_ANALYZER_PREDICATES_ONLY = "objective_analyzer_predicates_only"


class AProfileSemanticEventPredicate(DomainModel):
    """One event predicate with no occurrence or observation fields."""

    kind: AProfileSemanticEventKind
    applicability: AProfileExecutionApplicability
    system_register: AProfileSystemRegister | None = None
    memory_type_constraints: list[AProfileMemoryType] = Field(
        default_factory=list
    )
    memory_type_semantics: AProfileMemoryTypeSemantics | None = None
    memory_type_observation_requirement: (
        MemoryTypeObservationRequirement | None
    ) = None

    @field_validator("memory_type_constraints")
    @classmethod
    def normalize_memory_types(
        cls, values: list[AProfileMemoryType]
    ) -> list[AProfileMemoryType]:
        if len(values) != len(set(values)):
            raise ValueError("memory-type constraints must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_predicate_shape(self) -> "AProfileSemanticEventPredicate":
        if self.kind is AProfileSemanticEventKind.MEMORY_LOAD:
            if not self.memory_type_constraints:
                raise ValueError("memory load requires memory-type constraints")
            if self.memory_type_semantics is not (
                AProfileMemoryTypeSemantics.EFFECTIVE_ARCHITECTURAL_MEMORY_TYPE
            ):
                raise ValueError("memory load requires effective memory-type semantics")
            if self.memory_type_observation_requirement is not (
                MemoryTypeObservationRequirement.OBJECTIVE_EFFECTIVE_MEMORY_TYPE_REQUIRED
            ):
                raise ValueError("memory load requires objective memory-type resolution")
            if self.system_register is not None:
                raise ValueError("memory load cannot carry a system register")
            if self.applicability is not AProfileExecutionApplicability.ARM_A_PROFILE:
                raise ValueError("memory load must preserve A-profile applicability")
        elif self.kind is AProfileSemanticEventKind.SYSTEM_REGISTER_READ:
            if self.system_register is not AProfileSystemRegister.PAR_EL1:
                raise ValueError("system-register read requires PAR_EL1")
            if self.applicability is not (
                AProfileExecutionApplicability.PRIVILEGED_AARCH64
            ):
                raise ValueError("PAR_EL1 requires privileged AArch64")
            self._require_no_memory_type_payload()
        else:
            if self.system_register is not None:
                raise ValueError("store exclusive cannot carry a system register")
            if self.applicability is not AProfileExecutionApplicability.ARM_A_PROFILE:
                raise ValueError("store exclusive must preserve A-profile applicability")
            self._require_no_memory_type_payload()
        return self

    def _require_no_memory_type_payload(self) -> None:
        if (
            self.memory_type_constraints
            or self.memory_type_semantics is not None
            or self.memory_type_observation_requirement is not None
        ):
            raise ValueError("non-load predicates cannot carry memory-type data")


class AProfileSemanticEventPosition(DomainModel):
    """One indexed program-order position whose alternatives have OR meaning."""

    position_index: int = Field(ge=1)
    alternative_semantics: Literal[SemanticAlternativeSemantics.OR] = (
        SemanticAlternativeSemantics.OR
    )
    alternatives: list[AProfileSemanticEventPredicate] = Field(min_length=1)

    @field_validator("alternatives")
    @classmethod
    def normalize_alternatives(
        cls, values: list[AProfileSemanticEventPredicate]
    ) -> list[AProfileSemanticEventPredicate]:
        keys = [
            json.dumps(
                item.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            for item in values
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("semantic event alternatives must be unique")
        return sorted(values, key=lambda item: item.kind.value)


class AProfileSemanticPatternCase(DomainModel):
    """One ordered two-position semantic trigger-pattern case."""

    case_id: Identifier
    position_order: Literal[SemanticPositionOrder.PROGRAM_ORDER] = (
        SemanticPositionOrder.PROGRAM_ORDER
    )
    positions: list[AProfileSemanticEventPosition] = Field(
        min_length=2, max_length=2
    )
    relation: Literal[AProfileSemanticRelation.CLOSE_PROXIMITY]
    relation_precision: Literal[AProfileRelationPrecision.QUALITATIVE_ONLY]
    quantitative_bound: int | None = Field(default=None, ge=0)
    relation_evaluability: Literal[
        SemanticRelationEvaluability.SOURCE_INSUFFICIENT_FOR_EXACT_SOFTWARE_ONLY_SATISFACTION
    ]

    @field_validator("positions")
    @classmethod
    def normalize_positions(
        cls, values: list[AProfileSemanticEventPosition]
    ) -> list[AProfileSemanticEventPosition]:
        indexes = [item.position_index for item in values]
        if len(indexes) != len(set(indexes)):
            raise ValueError("semantic positions must have unique indexes")
        if set(indexes) != {1, 2}:
            raise ValueError("pattern v1 requires positions 1 and 2")
        return sorted(values, key=lambda item: item.position_index)

    @model_validator(mode="after")
    def reject_quantitative_bound(self) -> "AProfileSemanticPatternCase":
        if self.quantitative_bound is not None:
            raise ValueError("qualitative relation cannot carry a numeric bound")
        return self


class AProfileProcessorRevisionScope(DomainModel):
    """Documented processor scope, not an observed runtime CPU revision."""

    processor: Identifier
    revision: Identifier
    disposition: AProfileRevisionDisposition

    @field_validator("revision")
    @classmethod
    def validate_revision(cls, value: str) -> str:
        if not _CPU_REVISION.fullmatch(value):
            raise ValueError("processor revision must use canonical rNpN form")
        return value


class AProfileDocumentedEffectReference(DomainModel):
    """Reference to a documented possible effect, never an observed effect."""

    kind: Literal[AProfileDocumentedEffectKind.CORE_DEADLOCK]
    modality: Literal[AProfileDocumentedEffectModality.POSSIBLE]


class AProfileMitigationReference(DomainModel):
    """One documentation-only mitigation category reference."""

    kind: AProfileMitigationReferenceKind
    semantics: Literal[
        AProfileMitigationReferenceSemantics.DOCUMENTED_MITIGATION_REFERENCE
    ]


class AProfileSourcePrecisionObligations(DomainModel):
    """Source limits that future objective analyzers must not overclaim."""

    program_order_source_defined: Literal[True]
    quantitative_proximity_source_defined: Literal[False]
    additional_timing_conditions_source_defined: Literal[False]
    machine_code_sequence_source_defined: Literal[False]
    effective_memory_type_resolution_source_defined: Literal[False]
    runtime_environment_source_defined: Literal[False]
    hardware_effect_empirical_source_defined: Literal[False]


def a_profile_semantic_trigger_pattern_id(payload: dict[str, object]) -> str:
    """Return the deterministic identity for one semantic pattern."""

    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"a-profile-semantic-trigger-pattern:{hashlib.sha256(canonical).hexdigest()}"


class _AProfileSemanticTriggerPatternBody(DomainModel):
    """Generic semantic pattern body shared by creation and validation."""

    architecture: Literal[Architecture.ARM]
    architecture_profile: Literal["a_profile"]
    processor: Identifier
    cve_id: Identifier
    erratum_id: Identifier
    configurations: Identifier
    source_documented_erratum_id: Identifier
    source_documented_erratum_sha256: Identifier
    source_documented_erratum_contract: Literal[
        PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT
    ]
    revision_scope: list[AProfileProcessorRevisionScope] = Field(min_length=1)
    cases: list[AProfileSemanticPatternCase] = Field(min_length=1)
    source_additional_timing_precision: Literal[
        AProfileAdditionalTimingPrecision.UNSPECIFIED_BY_PUBLIC_SOURCE
    ]
    additional_timing_condition_requirement: Literal[
        AdditionalTimingConditionRequirement.UNRESOLVED_FROM_PUBLIC_DOCUMENTATION
    ]
    documented_effect_reference: AProfileDocumentedEffectReference
    mitigation_references: list[AProfileMitigationReference] = Field(
        default_factory=list
    )
    source_precision_obligations: AProfileSourcePrecisionObligations
    pattern_use: Literal[
        AProfileSemanticPatternUse.OBJECTIVE_ANALYZER_PREDICATES_ONLY
    ]

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str) -> str:
        if not _CVE_ID.fullmatch(value):
            raise ValueError("semantic pattern CVE ID must use canonical syntax")
        return value

    @field_validator("source_documented_erratum_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        if not value.startswith("documented-hardware-erratum:"):
            raise ValueError("source documented-erratum ID has the wrong namespace")
        digest = value.removeprefix("documented-hardware-erratum:")
        if len(digest) != 64 or any(item not in "0123456789abcdef" for item in digest):
            raise ValueError("source documented-erratum ID must contain SHA-256")
        return value

    @field_validator("source_documented_erratum_sha256")
    @classmethod
    def validate_source_sha256(cls, value: str) -> str:
        if len(value) != 64 or any(item not in "0123456789abcdef" for item in value):
            raise ValueError("source documented-erratum SHA-256 is invalid")
        return value

    @field_validator("revision_scope")
    @classmethod
    def normalize_revision_scope(
        cls, values: list[AProfileProcessorRevisionScope]
    ) -> list[AProfileProcessorRevisionScope]:
        keys = [(item.processor, item.revision) for item in values]
        if len(keys) != len(set(keys)):
            raise ValueError("processor revision scope must be unique")
        if not any(
            item.disposition is AProfileRevisionDisposition.AFFECTED
            for item in values
        ):
            raise ValueError("semantic pattern requires an affected revision")
        return sorted(values, key=lambda item: (item.processor, item.revision))

    @field_validator("cases")
    @classmethod
    def normalize_cases(
        cls, values: list[AProfileSemanticPatternCase]
    ) -> list[AProfileSemanticPatternCase]:
        case_ids = [item.case_id for item in values]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("semantic pattern cases must be unique")
        return sorted(values, key=lambda item: item.case_id)

    @field_validator("mitigation_references")
    @classmethod
    def normalize_mitigation_references(
        cls, values: list[AProfileMitigationReference]
    ) -> list[AProfileMitigationReference]:
        kinds = [item.kind for item in values]
        if len(kinds) != len(set(kinds)):
            raise ValueError("mitigation references must be unique")
        return sorted(values, key=lambda item: item.kind.value)

    @model_validator(mode="after")
    def validate_processor_scope(self) -> "_AProfileSemanticTriggerPatternBody":
        if any(item.processor != self.processor for item in self.revision_scope):
            raise ValueError("revision scope processor must match pattern processor")
        return self


class AProfileSemanticTriggerPattern(_AProfileSemanticTriggerPatternBody):
    """Versioned A-profile predicates for future objective analyzers."""

    id: Identifier
    contract: Literal[
        PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT
    ] = PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT

    @classmethod
    def create(cls, **values: object) -> "AProfileSemanticTriggerPattern":
        """Create a pattern whose identity binds all predicate semantics."""

        snapshot = _AProfileSemanticTriggerPatternBody.model_validate(values)
        normalized = snapshot.model_dump(mode="json")
        normalized["contract"] = (
            PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT
        )
        return cls(
            id=a_profile_semantic_trigger_pattern_id(normalized),
            contract=PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT,
            **snapshot.model_dump(mode="json"),
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "AProfileSemanticTriggerPattern":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != a_profile_semantic_trigger_pattern_id(payload):
            raise ValueError("semantic trigger-pattern ID does not match content")
        return self
