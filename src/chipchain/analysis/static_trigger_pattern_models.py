"""Architecture-neutral declarative static hardware-trigger pattern IR."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.analysis.static_semantic_models import (
    StaticSemanticAttribute,
    StaticSemanticAttributeName,
    StaticSemanticOperation,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_TRIGGER_PREDICATE_CONTRACT = (
    "phase10d_static_trigger_predicate_v1"
)
PHASE10D_STATIC_TRIGGER_POSITION_CONTRACT = (
    "phase10d_static_trigger_position_v1"
)
PHASE10D_STATIC_TRIGGER_RELATION_REQUIREMENT_CONTRACT = (
    "phase10d_static_trigger_relation_requirement_v1"
)
PHASE10D_STATIC_TRIGGER_CASE_CONTRACT = "phase10d_static_trigger_case_v1"
PHASE10D_STATIC_TRIGGER_PATTERN_CONTRACT = (
    "phase10d_static_trigger_pattern_v1"
)
PHASE10D_STATIC_TRIGGER_PATTERN_CATALOG_CONTRACT = (
    "phase10d_static_trigger_pattern_catalog_v1"
)

_FORBIDDEN_OUTCOME_FRAGMENTS = (
    "attack_chain",
    "caused",
    "confidence",
    "executed",
    "exploit_feasible",
    "match_success",
    "matched",
    "probability",
    "runtime_reached",
    "score",
    "triggerable",
    "triggered",
    "verified",
    "vulnerable",
)


class StaticTriggerAlternativeSemantics(str, Enum):
    """Closed v1 combination rule for alternatives at one position."""

    OR = "or"


class StaticTriggerPositionOrder(str, Enum):
    """Declarative source ordering, not an observed runtime order."""

    PROGRAM_ORDER = "program_order"


class StaticTriggerRelationKind(str, Enum):
    """Closed v1 relation vocabulary."""

    CLOSE_PROXIMITY = "close_proximity"


class StaticTriggerRelationPrecision(str, Enum):
    """Precision supplied by the source for one relation requirement."""

    QUALITATIVE_ONLY = "qualitative_only"


class StaticTriggerRelationEvaluability(str, Enum):
    """Objective limits on static evaluation of a source relation."""

    SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION = (
        "source_insufficient_for_exact_static_satisfaction"
    )


class StaticTriggerObjectiveRequirement(str, Enum):
    """Closed unresolved objective requirements preserved by pattern v1."""

    EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED = (
        "effective_memory_type_resolution_required"
    )
    RUNTIME_EXECUTION_CONTEXT_REQUIRED = (
        "runtime_execution_context_required"
    )
    RELATION_PROXIMITY_REMAINS_UNRESOLVED = (
        "relation_proximity_remains_unresolved"
    )
    ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED = (
        "additional_hardware_timing_remains_unresolved"
    )


class StaticTriggerPatternUse(str, Enum):
    """Non-outcome use boundary of a declarative pattern."""

    OBJECTIVE_STATIC_CANDIDATE_MATCHING_ONLY = (
        "objective_static_candidate_matching_only"
    )


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _deterministic_id(prefix: str, payload: object) -> str:
    return f"{prefix}:{hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()}"


def _validate_identifier(value: str, *, label: str) -> str:
    lowered = value.lower()
    if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
        raise ValueError(f"{label} must be path-neutral")
    if any(fragment in lowered for fragment in _FORBIDDEN_OUTCOME_FRAGMENTS):
        raise ValueError(f"{label} must be outcome-neutral")
    return value


def _normalize_identifiers(values: list[str], *, label: str) -> list[str]:
    normalized = [_validate_identifier(value, label=label) for value in values]
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} must be unique")
    return sorted(normalized)


def _normalize_objective_requirements(
    values: list[StaticTriggerObjectiveRequirement],
) -> list[StaticTriggerObjectiveRequirement]:
    if len(values) != len(set(values)):
        raise ValueError("static trigger objective requirements must be unique")
    return sorted(values, key=lambda item: item.value)


def static_trigger_predicate_id(payload: object) -> str:
    """Return the deterministic ID of one predicate."""

    return _deterministic_id("static-trigger-predicate", payload)


def static_trigger_position_id(payload: object) -> str:
    """Return the deterministic ID of one ordered position."""

    return _deterministic_id("static-trigger-position", payload)


def static_trigger_relation_requirement_id(payload: object) -> str:
    """Return the deterministic ID of one qualitative relation requirement."""

    return _deterministic_id("static-trigger-relation-requirement", payload)


def static_trigger_case_id(payload: object) -> str:
    """Return the deterministic ID of one pattern case."""

    return _deterministic_id("static-trigger-case", payload)


def static_trigger_pattern_id(payload: object) -> str:
    """Return the deterministic ID of one source-backed pattern."""

    return _deterministic_id("static-trigger-pattern", payload)


def static_trigger_pattern_catalog_id(payload: object) -> str:
    """Return the deterministic ID of one normalized pattern catalog."""

    return _deterministic_id("static-trigger-pattern-catalog", payload)


class _StaticTriggerPredicateBody(DomainModel):
    contract: Literal["phase10d_static_trigger_predicate_v1"]
    operation: StaticSemanticOperation
    required_attributes: list[StaticSemanticAttribute] = Field(
        default_factory=list
    )
    required_effective_memory_types: list[Identifier] = Field(
        default_factory=list
    )
    required_execution_contexts: list[Identifier] = Field(
        default_factory=list
    )
    objective_requirements: list[StaticTriggerObjectiveRequirement] = Field(
        default_factory=list
    )

    @field_validator("required_attributes")
    @classmethod
    def normalize_required_attributes(
        cls, values: list[StaticSemanticAttribute]
    ) -> list[StaticSemanticAttribute]:
        detached = [
            StaticSemanticAttribute.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        names = [item.name for item in detached]
        if len(names) != len(set(names)):
            raise ValueError("required semantic attribute names must be unique")
        return sorted(detached, key=lambda item: (item.name.value, item.value))

    @field_validator(
        "required_effective_memory_types", "required_execution_contexts"
    )
    @classmethod
    def normalize_external_requirements(cls, values: list[str]) -> list[str]:
        return _normalize_identifiers(
            values, label="static trigger external requirement"
        )

    @field_validator("objective_requirements")
    @classmethod
    def normalize_objective_requirements(
        cls, values: list[StaticTriggerObjectiveRequirement]
    ) -> list[StaticTriggerObjectiveRequirement]:
        return _normalize_objective_requirements(values)

    @model_validator(mode="after")
    def validate_requirement_compatibility(self) -> "_StaticTriggerPredicateBody":
        attribute_names = {item.name for item in self.required_attributes}
        system_operations = {
            StaticSemanticOperation.SYSTEM_REGISTER_READ,
            StaticSemanticOperation.SYSTEM_REGISTER_WRITE,
        }
        barrier_operations = {
            StaticSemanticOperation.MEMORY_BARRIER,
            StaticSemanticOperation.INSTRUCTION_BARRIER,
        }
        memory_operations = {
            StaticSemanticOperation.MEMORY_LOAD,
            StaticSemanticOperation.MEMORY_STORE,
            StaticSemanticOperation.LOAD_EXCLUSIVE,
            StaticSemanticOperation.STORE_EXCLUSIVE,
        }
        if (
            StaticSemanticAttributeName.SYSTEM_REGISTER in attribute_names
            and self.operation not in system_operations
        ):
            raise ValueError(
                "non-system-register predicate carries register identity"
            )
        barrier_attributes = {
            StaticSemanticAttributeName.BARRIER_KIND,
            StaticSemanticAttributeName.BARRIER_OPTION,
        }
        if attribute_names.intersection(barrier_attributes) and (
            self.operation not in barrier_operations
        ):
            raise ValueError("non-barrier predicate carries barrier requirements")
        if (
            StaticSemanticAttributeName.TLB_OPERATION in attribute_names
            and self.operation is not StaticSemanticOperation.TLB_INVALIDATE
        ):
            raise ValueError("non-TLB predicate carries TLB requirements")
        if (
            StaticSemanticAttributeName.EFFECTIVE_MEMORY_TYPE_RESOLUTION
            in attribute_names
            and self.operation not in memory_operations
        ):
            raise ValueError(
                "non-memory predicate carries memory-type resolution state"
            )
        if (
            StaticSemanticAttributeName.MEMORY_EXCLUSIVITY in attribute_names
            and self.operation
            not in {
                StaticSemanticOperation.LOAD_EXCLUSIVE,
                StaticSemanticOperation.STORE_EXCLUSIVE,
            }
        ):
            raise ValueError(
                "non-exclusive predicate carries exclusivity requirements"
            )
        if self.required_effective_memory_types and (
            self.operation not in memory_operations
        ):
            raise ValueError(
                "effective memory types require a memory operation predicate"
            )
        if self.required_effective_memory_types and (
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
            not in self.objective_requirements
        ):
            raise ValueError(
                "effective memory types require an objective resolution requirement"
            )
        if self.required_execution_contexts and (
            StaticTriggerObjectiveRequirement
            .RUNTIME_EXECUTION_CONTEXT_REQUIRED
            not in self.objective_requirements
        ):
            raise ValueError(
                "execution contexts require an objective runtime requirement"
            )
        return self


class StaticTriggerPredicate(_StaticTriggerPredicateBody):
    """One address-independent semantic instruction requirement."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerPredicate":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_TRIGGER_PREDICATE_CONTRACT
        body = _StaticTriggerPredicateBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_predicate_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerPredicate":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_predicate_id(payload):
            raise ValueError("static trigger predicate ID mismatch")
        return self


class _StaticTriggerPositionBody(DomainModel):
    contract: Literal["phase10d_static_trigger_position_v1"]
    position_index: int = Field(ge=1)
    alternative_semantics: Literal[StaticTriggerAlternativeSemantics.OR] = (
        StaticTriggerAlternativeSemantics.OR
    )
    alternatives: list[StaticTriggerPredicate] = Field(min_length=1)

    @field_validator("alternatives")
    @classmethod
    def normalize_alternatives(
        cls, values: list[StaticTriggerPredicate]
    ) -> list[StaticTriggerPredicate]:
        detached = [
            StaticTriggerPredicate.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("static trigger alternatives must be unique")
        return sorted(detached, key=lambda item: item.id)


class StaticTriggerPosition(_StaticTriggerPositionBody):
    """One explicit program-order position with OR alternatives."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerPosition":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_TRIGGER_POSITION_CONTRACT
        body = _StaticTriggerPositionBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_position_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerPosition":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_position_id(payload):
            raise ValueError("static trigger position ID mismatch")
        return self


class _StaticTriggerRelationRequirementBody(DomainModel):
    contract: Literal[
        "phase10d_static_trigger_relation_requirement_v1"
    ]
    relation_kind: Literal[StaticTriggerRelationKind.CLOSE_PROXIMITY]
    precision: Literal[StaticTriggerRelationPrecision.QUALITATIVE_ONLY]
    quantitative_bound: Literal[None] = None
    evaluability: Literal[
        StaticTriggerRelationEvaluability
        .SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION
    ]


class StaticTriggerRelationRequirement(
    _StaticTriggerRelationRequirementBody
):
    """One source-faithful qualitative relation without an invented bound."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerRelationRequirement":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_TRIGGER_RELATION_REQUIREMENT_CONTRACT
        )
        body = _StaticTriggerRelationRequirementBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(
            id=static_trigger_relation_requirement_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerRelationRequirement":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_relation_requirement_id(payload):
            raise ValueError("static trigger relation requirement ID mismatch")
        return self


class _StaticTriggerCaseBody(DomainModel):
    contract: Literal["phase10d_static_trigger_case_v1"]
    case_reference_id: Identifier
    position_order: Literal[StaticTriggerPositionOrder.PROGRAM_ORDER] = (
        StaticTriggerPositionOrder.PROGRAM_ORDER
    )
    positions: list[StaticTriggerPosition] = Field(min_length=1)
    relation_requirement: StaticTriggerRelationRequirement | None = None
    objective_requirements: list[StaticTriggerObjectiveRequirement] = Field(
        default_factory=list
    )

    @field_validator("case_reference_id")
    @classmethod
    def validate_case_reference_id(cls, value: str) -> str:
        return _validate_identifier(value, label="static trigger case reference")

    @field_validator("positions")
    @classmethod
    def normalize_positions(
        cls, values: list[StaticTriggerPosition]
    ) -> list[StaticTriggerPosition]:
        detached = [
            StaticTriggerPosition.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        indexes = [item.position_index for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("static trigger position IDs must be unique")
        if len(indexes) != len(set(indexes)):
            raise ValueError("static trigger position indices must be unique")
        if sorted(indexes) != list(range(1, len(detached) + 1)):
            raise ValueError(
                "static trigger position indices must be contiguous from one"
            )
        return sorted(detached, key=lambda item: item.position_index)

    @field_validator("relation_requirement")
    @classmethod
    def detach_relation_requirement(
        cls, value: StaticTriggerRelationRequirement | None
    ) -> StaticTriggerRelationRequirement | None:
        if value is None:
            return None
        return StaticTriggerRelationRequirement.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("objective_requirements")
    @classmethod
    def normalize_objective_requirements(
        cls, values: list[StaticTriggerObjectiveRequirement]
    ) -> list[StaticTriggerObjectiveRequirement]:
        return _normalize_objective_requirements(values)

    @model_validator(mode="after")
    def validate_relation_obligation(self) -> "_StaticTriggerCaseBody":
        unresolved = (
            StaticTriggerObjectiveRequirement
            .RELATION_PROXIMITY_REMAINS_UNRESOLVED
            in self.objective_requirements
        )
        if (self.relation_requirement is not None) != unresolved:
            raise ValueError(
                "qualitative relation and unresolved requirement must coexist"
            )
        return self


class StaticTriggerCase(_StaticTriggerCaseBody):
    """One declarative program-ordered alternative case."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerCase":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_TRIGGER_CASE_CONTRACT
        body = _StaticTriggerCaseBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_case_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerCase":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_case_id(payload):
            raise ValueError("static trigger case ID mismatch")
        return self


class _StaticTriggerPatternBody(DomainModel):
    contract: Literal["phase10d_static_trigger_pattern_v1"]
    architecture: Architecture
    instruction_set: Identifier
    pattern_name: Identifier
    source_reference_ids: list[Identifier] = Field(min_length=1)
    hardware_reference_ids: list[Identifier] = Field(min_length=1)
    cases: list[StaticTriggerCase] = Field(min_length=1)
    objective_requirements: list[StaticTriggerObjectiveRequirement] = Field(
        default_factory=list
    )
    pattern_use: Literal[
        StaticTriggerPatternUse.OBJECTIVE_STATIC_CANDIDATE_MATCHING_ONLY
    ] = StaticTriggerPatternUse.OBJECTIVE_STATIC_CANDIDATE_MATCHING_ONLY

    @field_validator("instruction_set", "pattern_name")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_identifier(value, label="static trigger pattern identifier")

    @field_validator("source_reference_ids", "hardware_reference_ids")
    @classmethod
    def normalize_references(cls, values: list[str]) -> list[str]:
        return _normalize_identifiers(
            values, label="static trigger pattern reference"
        )

    @field_validator("cases")
    @classmethod
    def normalize_cases(
        cls, values: list[StaticTriggerCase]
    ) -> list[StaticTriggerCase]:
        detached = [
            StaticTriggerCase.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        references = [item.case_reference_id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("static trigger case IDs must be unique")
        if len(references) != len(set(references)):
            raise ValueError("static trigger case references must be unique")
        return sorted(detached, key=lambda item: item.id)

    @field_validator("objective_requirements")
    @classmethod
    def normalize_objective_requirements(
        cls, values: list[StaticTriggerObjectiveRequirement]
    ) -> list[StaticTriggerObjectiveRequirement]:
        return _normalize_objective_requirements(values)


class StaticTriggerPattern(_StaticTriggerPatternBody):
    """One source-backed pattern that makes no firmware observation claim."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerPattern":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_TRIGGER_PATTERN_CONTRACT
        body = _StaticTriggerPatternBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_pattern_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerPattern":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_pattern_id(payload):
            raise ValueError("static trigger pattern ID mismatch")
        return self


class _StaticTriggerPatternCatalogBody(DomainModel):
    contract: Literal["phase10d_static_trigger_pattern_catalog_v1"]
    patterns: list[StaticTriggerPattern] = Field(default_factory=list)

    @field_validator("patterns")
    @classmethod
    def normalize_patterns(
        cls, values: list[StaticTriggerPattern]
    ) -> list[StaticTriggerPattern]:
        detached = [
            StaticTriggerPattern.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("static trigger pattern IDs must be unique")
        return sorted(detached, key=lambda item: item.id)


class StaticTriggerPatternCatalog(_StaticTriggerPatternCatalogBody):
    """A deterministic mixed-architecture declarative pattern catalog."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerPatternCatalog":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_TRIGGER_PATTERN_CATALOG_CONTRACT
        )
        body = _StaticTriggerPatternCatalogBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_pattern_catalog_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerPatternCatalog":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_pattern_catalog_id(payload):
            raise ValueError("static trigger pattern catalog ID mismatch")
        return self
