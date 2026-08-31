"""Contracts for future ARM A-profile static semantic extraction.

These contracts describe extraction plans and objective static artifact facts.
They do not implement instruction decoding, case assembly, runtime observation,
or triggerability evaluation.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.hardware_trigger.a_profile_semantic_models import (
    PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT,
    AProfileAdditionalTimingPrecision,
    AProfileExecutionApplicability,
    AProfileMemoryType,
    AProfileMemoryTypeSemantics,
    AProfileRelationPrecision,
    AProfileSemanticEventKind,
    AProfileSemanticEventPredicate,
    AProfileSemanticRelation,
    AProfileSystemRegister,
    AdditionalTimingConditionRequirement,
    MemoryTypeObservationRequirement,
    SemanticRelationEvaluability,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_A_PROFILE_STATIC_SEMANTIC_EXTRACTION_PLAN_CONTRACT = (
    "phase10d_a_profile_static_semantic_extraction_plan_v1"
)
PHASE10D_A_PROFILE_STATIC_SEMANTIC_FACT_CONTRACT = (
    "phase10d_a_profile_static_semantic_fact_v1"
)
PHASE10D_A_PROFILE_STATIC_PREDICATE_CANDIDATE_CONTRACT = (
    "phase10d_a_profile_static_predicate_candidate_v1"
)
PHASE10D_A_PROFILE_STATIC_EXTRACTION_RESULT_CONTRACT = (
    "phase10d_a_profile_static_semantic_extraction_result_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_DIAGNOSTIC_FRAGMENTS = (
    "confidence",
    "effective_memory_type",
    "executed",
    "feasibility",
    "matched",
    "observed",
    "primary",
    "proximity_satisfied",
    "runtime_el",
    "runtime_privilege",
    "satisfied",
    "score",
    "triggered",
    "triggerability",
    "verification",
)


class AProfileStaticInstructionSetState(str, Enum):
    """Instruction-set states supported by static semantic contract v1."""

    AARCH64 = "aarch64"


class StaticEffectiveMemoryTypeResolution(str, Enum):
    """Whether effective architectural memory type is available statically."""

    REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT = (
        "requires_objective_translation_context"
    )
    NOT_APPLICABLE = "not_applicable"


class StaticRecognitionSemantics(str, Enum):
    """Required basis for future static semantic classification."""

    DECODED_INSTRUCTION_SEMANTICS = "decoded_instruction_semantics"


class RemainingObjectiveObligation(str, Enum):
    """Closed obligations a static candidate cannot discharge."""

    RUNTIME_EXECUTION_REQUIRED = "runtime_execution_required"
    RUNTIME_EXECUTION_CONTEXT_REQUIRED = (
        "runtime_execution_context_required"
    )
    EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED = (
        "effective_memory_type_resolution_required"
    )
    RELATION_PROXIMITY_REMAINS_UNRESOLVED = (
        "relation_proximity_remains_unresolved"
    )
    ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED = (
        "additional_hardware_timing_remains_unresolved"
    )


class StaticFactScope(str, Enum):
    """Narrow meaning of an objective static instruction fact."""

    DECODED_ARTIFACT_INSTRUCTION_SEMANTICS_ONLY = (
        "decoded_artifact_instruction_semantics_only"
    )


def _canonical_sha256(value: str) -> str:
    candidate = value.strip()
    if not _SHA256.fullmatch(candidate):
        raise ValueError("SHA-256 must contain 64 lowercase hexadecimal digits")
    return candidate


def _canonical_hex(value: object, *, digits: int, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a hexadecimal string")
    candidate = value.strip()
    if not re.fullmatch(rf"0x[0-9a-fA-F]{{{digits}}}", candidate):
        raise ValueError(
            f"{label} must use 0x followed by exactly {digits} hexadecimal digits"
        )
    return candidate.lower()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _semantic_id(prefix: str, payload: object) -> str:
    return f"{prefix}:{hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()}"


def _normalize_obligations(
    values: list[RemainingObjectiveObligation],
) -> list[RemainingObjectiveObligation]:
    if len(values) != len(set(values)):
        raise ValueError("remaining objective obligations must be unique")
    return sorted(values, key=lambda item: item.value)


def obligations_for_predicate(
    predicate: AProfileSemanticEventPredicate,
) -> list[RemainingObjectiveObligation]:
    """Return every objective obligation retained after static recognition."""

    obligations = {
        RemainingObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
        RemainingObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED,
        RemainingObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
    }
    if predicate.applicability is AProfileExecutionApplicability.PRIVILEGED_AARCH64:
        obligations.add(
            RemainingObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED
        )
    if predicate.kind is AProfileSemanticEventKind.MEMORY_LOAD:
        obligations.add(
            RemainingObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        )
    return sorted(obligations, key=lambda item: item.value)


def a_profile_semantic_predicate_ref(
    *,
    pattern_id: str,
    case_id: str,
    position_index: int,
    predicate: AProfileSemanticEventPredicate,
) -> str:
    """Identify one predicate by pattern location and canonical content."""

    snapshot = AProfileSemanticEventPredicate.model_validate(
        predicate.model_dump(mode="json")
    )
    return _semantic_id(
        "a-profile-semantic-predicate-ref",
        {
            "case_id": case_id,
            "pattern_id": pattern_id,
            "position_index": position_index,
            "predicate": snapshot.model_dump(mode="json"),
        },
    )


class AProfileStaticPredicatePlanEntry(DomainModel):
    """One future decoded-instruction recognition target."""

    predicate_ref: Identifier
    case_id: Identifier
    position_index: int = Field(ge=1)
    event_kind: AProfileSemanticEventKind
    applicability: AProfileExecutionApplicability
    system_register: AProfileSystemRegister | None = None
    required_memory_type_constraints: list[AProfileMemoryType] = Field(
        default_factory=list
    )
    memory_type_semantics: AProfileMemoryTypeSemantics | None = None
    memory_type_observation_requirement: (
        MemoryTypeObservationRequirement | None
    ) = None
    static_recognition_semantics: Literal[
        StaticRecognitionSemantics.DECODED_INSTRUCTION_SEMANTICS
    ]
    remaining_objective_obligations: list[
        RemainingObjectiveObligation
    ] = Field(min_length=3)

    @field_validator("required_memory_type_constraints")
    @classmethod
    def normalize_memory_constraints(
        cls, values: list[AProfileMemoryType]
    ) -> list[AProfileMemoryType]:
        if len(values) != len(set(values)):
            raise ValueError("required memory-type constraints must be unique")
        return sorted(values, key=lambda item: item.value)

    @field_validator("remaining_objective_obligations")
    @classmethod
    def normalize_obligations(
        cls, values: list[RemainingObjectiveObligation]
    ) -> list[RemainingObjectiveObligation]:
        return _normalize_obligations(values)

    def as_predicate(self) -> AProfileSemanticEventPredicate:
        """Reconstruct the exact source predicate represented by this entry."""

        return AProfileSemanticEventPredicate(
            kind=self.event_kind,
            applicability=self.applicability,
            system_register=self.system_register,
            memory_type_constraints=self.required_memory_type_constraints,
            memory_type_semantics=self.memory_type_semantics,
            memory_type_observation_requirement=(
                self.memory_type_observation_requirement
            ),
        )

    @model_validator(mode="after")
    def validate_entry_obligations(self) -> "AProfileStaticPredicatePlanEntry":
        if self.remaining_objective_obligations != obligations_for_predicate(
            self.as_predicate()
        ):
            raise ValueError("plan entry objective obligations are incomplete")
        return self


class AProfileStaticCaseSourceLimitation(DomainModel):
    """Case-level limitations inherited unchanged from the source pattern."""

    case_id: Identifier
    relation: Literal[AProfileSemanticRelation.CLOSE_PROXIMITY]
    relation_precision: Literal[AProfileRelationPrecision.QUALITATIVE_ONLY]
    quantitative_bound: int | None = Field(default=None, ge=0)
    relation_evaluability: Literal[
        SemanticRelationEvaluability.SOURCE_INSUFFICIENT_FOR_EXACT_SOFTWARE_ONLY_SATISFACTION
    ]
    source_additional_timing_precision: Literal[
        AProfileAdditionalTimingPrecision.UNSPECIFIED_BY_PUBLIC_SOURCE
    ]
    additional_timing_condition_requirement: Literal[
        AdditionalTimingConditionRequirement.UNRESOLVED_FROM_PUBLIC_DOCUMENTATION
    ]

    @model_validator(mode="after")
    def reject_quantitative_bound(self) -> "AProfileStaticCaseSourceLimitation":
        if self.quantitative_bound is not None:
            raise ValueError("qualitative proximity cannot carry a numeric bound")
        return self


def a_profile_static_semantic_extraction_plan_id(payload: object) -> str:
    """Return a deterministic extraction-plan identity."""

    return _semantic_id("a-profile-static-semantic-extraction-plan", payload)


class _AProfileStaticSemanticExtractionPlanBody(DomainModel):
    architecture: Literal[Architecture.ARM]
    architecture_profile: Literal["a_profile"]
    processor: Identifier
    cve_id: Identifier
    erratum_id: Identifier
    source_pattern_id: Identifier
    source_pattern_sha256: Identifier
    source_pattern_contract: Literal[
        PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT
    ]
    target_instruction_set_state: Literal[
        AProfileStaticInstructionSetState.AARCH64
    ]
    predicate_entries: list[AProfileStaticPredicatePlanEntry] = Field(
        min_length=1
    )
    case_source_limitations: list[AProfileStaticCaseSourceLimitation] = Field(
        min_length=1
    )

    @field_validator("source_pattern_sha256")
    @classmethod
    def validate_source_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("predicate_entries")
    @classmethod
    def normalize_entries(
        cls, values: list[AProfileStaticPredicatePlanEntry]
    ) -> list[AProfileStaticPredicatePlanEntry]:
        refs = [item.predicate_ref for item in values]
        if len(refs) != len(set(refs)):
            raise ValueError("extraction-plan predicate references must be unique")
        return sorted(
            values,
            key=lambda item: (
                item.case_id,
                item.position_index,
                item.event_kind.value,
                item.predicate_ref,
            ),
        )

    @field_validator("case_source_limitations")
    @classmethod
    def normalize_case_limitations(
        cls, values: list[AProfileStaticCaseSourceLimitation]
    ) -> list[AProfileStaticCaseSourceLimitation]:
        case_ids = [item.case_id for item in values]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("case source limitations must use unique case IDs")
        return sorted(values, key=lambda item: item.case_id)

    @model_validator(mode="after")
    def validate_references_and_cases(
        self,
    ) -> "_AProfileStaticSemanticExtractionPlanBody":
        for entry in self.predicate_entries:
            expected_ref = a_profile_semantic_predicate_ref(
                pattern_id=self.source_pattern_id,
                case_id=entry.case_id,
                position_index=entry.position_index,
                predicate=entry.as_predicate(),
            )
            if entry.predicate_ref != expected_ref:
                raise ValueError("plan entry predicate reference is not deterministic")
        entry_case_ids = {item.case_id for item in self.predicate_entries}
        limitation_case_ids = {
            item.case_id for item in self.case_source_limitations
        }
        if entry_case_ids != limitation_case_ids:
            raise ValueError("plan entries and case limitations must cover same cases")
        return self


class AProfileStaticSemanticExtractionPlan(
    _AProfileStaticSemanticExtractionPlanBody
):
    """Artifact-neutral plan for a future decoded-instruction extractor."""

    id: Identifier
    contract: Literal[
        PHASE10D_A_PROFILE_STATIC_SEMANTIC_EXTRACTION_PLAN_CONTRACT
    ] = PHASE10D_A_PROFILE_STATIC_SEMANTIC_EXTRACTION_PLAN_CONTRACT

    @classmethod
    def create(cls, **values: object) -> "AProfileStaticSemanticExtractionPlan":
        snapshot = _AProfileStaticSemanticExtractionPlanBody.model_validate(
            values
        )
        payload = snapshot.model_dump(mode="json")
        payload["contract"] = (
            PHASE10D_A_PROFILE_STATIC_SEMANTIC_EXTRACTION_PLAN_CONTRACT
        )
        return cls(
            id=a_profile_static_semantic_extraction_plan_id(payload),
            contract=PHASE10D_A_PROFILE_STATIC_SEMANTIC_EXTRACTION_PLAN_CONTRACT,
            **snapshot.model_dump(mode="json"),
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "AProfileStaticSemanticExtractionPlan":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != a_profile_static_semantic_extraction_plan_id(payload):
            raise ValueError("static semantic extraction-plan ID mismatch")
        return self


def a_profile_static_semantic_fact_id(payload: object) -> str:
    """Return a deterministic objective static-instruction fact identity."""

    return _semantic_id("a-profile-static-semantic-fact", payload)


class _AProfileStaticSemanticInstructionFactBody(DomainModel):
    artifact_id: Identifier
    artifact_sha256: Identifier
    architecture: Literal[Architecture.ARM]
    architecture_profile: Literal["a_profile"]
    instruction_set_state: Literal[AProfileStaticInstructionSetState.AARCH64]
    instruction_address: Identifier
    instruction_word: Identifier
    instruction_size: Literal[4]
    basic_block_address: Identifier
    function_address: Identifier | None = None
    function_name: Identifier | None = None
    event_kind: AProfileSemanticEventKind
    system_register: AProfileSystemRegister | None = None
    memory_type_resolution: StaticEffectiveMemoryTypeResolution
    static_fact_scope: Literal[
        StaticFactScope.DECODED_ARTIFACT_INSTRUCTION_SEMANTICS_ONLY
    ]

    @field_validator("artifact_id")
    @classmethod
    def reject_artifact_path(cls, value: str) -> str:
        lowered = value.lower()
        if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
            raise ValueError("artifact ID must be path-neutral")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator(
        "instruction_address",
        "basic_block_address",
        "function_address",
        mode="before",
    )
    @classmethod
    def normalize_code_address(cls, value: object) -> str | None:
        if value is None:
            return None
        return _canonical_hex(value, digits=16, label="A-profile code address")

    @field_validator("instruction_word", mode="before")
    @classmethod
    def normalize_instruction_word(cls, value: object) -> str:
        return _canonical_hex(value, digits=8, label="A64 instruction word")

    @model_validator(mode="after")
    def validate_static_fact_shape(
        self,
    ) -> "_AProfileStaticSemanticInstructionFactBody":
        if self.function_name is not None and self.function_address is None:
            raise ValueError("function name requires a function address")
        if self.event_kind is AProfileSemanticEventKind.SYSTEM_REGISTER_READ:
            if self.system_register is not AProfileSystemRegister.PAR_EL1:
                raise ValueError("system-register static fact requires PAR_EL1")
        elif self.system_register is not None:
            raise ValueError("non-system-register static fact cannot carry PAR_EL1")
        expected_resolution = (
            StaticEffectiveMemoryTypeResolution.REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT
            if self.event_kind is AProfileSemanticEventKind.MEMORY_LOAD
            else StaticEffectiveMemoryTypeResolution.NOT_APPLICABLE
        )
        if self.memory_type_resolution is not expected_resolution:
            raise ValueError("static memory-type resolution contradicts event kind")
        return self


class AProfileStaticSemanticInstructionFact(
    _AProfileStaticSemanticInstructionFactBody
):
    """One decoded artifact instruction fact; it says nothing about execution."""

    id: Identifier
    contract: Literal[
        PHASE10D_A_PROFILE_STATIC_SEMANTIC_FACT_CONTRACT
    ] = PHASE10D_A_PROFILE_STATIC_SEMANTIC_FACT_CONTRACT

    @classmethod
    def create(cls, **values: object) -> "AProfileStaticSemanticInstructionFact":
        snapshot = _AProfileStaticSemanticInstructionFactBody.model_validate(
            values
        )
        payload = snapshot.model_dump(mode="json")
        payload["contract"] = PHASE10D_A_PROFILE_STATIC_SEMANTIC_FACT_CONTRACT
        return cls(
            id=a_profile_static_semantic_fact_id(payload),
            contract=PHASE10D_A_PROFILE_STATIC_SEMANTIC_FACT_CONTRACT,
            **snapshot.model_dump(mode="json"),
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "AProfileStaticSemanticInstructionFact":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != a_profile_static_semantic_fact_id(payload):
            raise ValueError("static semantic instruction-fact ID mismatch")
        return self


def a_profile_static_predicate_candidate_id(payload: object) -> str:
    """Return a deterministic static predicate-candidate identity."""

    return _semantic_id("a-profile-static-predicate-candidate", payload)


class _AProfileStaticPredicateCandidateBody(DomainModel):
    extraction_plan_id: Identifier
    source_pattern_id: Identifier
    predicate_ref: Identifier
    static_instruction_fact_id: Identifier
    case_id: Identifier
    position_index: int = Field(ge=1)
    remaining_objective_obligations: list[
        RemainingObjectiveObligation
    ] = Field(min_length=3)

    @field_validator("remaining_objective_obligations")
    @classmethod
    def normalize_obligations(
        cls, values: list[RemainingObjectiveObligation]
    ) -> list[RemainingObjectiveObligation]:
        values = _normalize_obligations(values)
        mandatory = {
            RemainingObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
            RemainingObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED,
            RemainingObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
        }
        if not mandatory.issubset(values):
            raise ValueError("static candidate dropped mandatory obligations")
        return values


class AProfileStaticPredicateCandidate(
    _AProfileStaticPredicateCandidateBody
):
    """One fact-to-predicate candidate with unresolved objective obligations."""

    id: Identifier
    contract: Literal[
        PHASE10D_A_PROFILE_STATIC_PREDICATE_CANDIDATE_CONTRACT
    ] = PHASE10D_A_PROFILE_STATIC_PREDICATE_CANDIDATE_CONTRACT

    @classmethod
    def create(
        cls,
        *,
        extraction_plan: AProfileStaticSemanticExtractionPlan,
        predicate_entry: AProfileStaticPredicatePlanEntry,
        static_instruction_fact: AProfileStaticSemanticInstructionFact,
    ) -> "AProfileStaticPredicateCandidate":
        plan = AProfileStaticSemanticExtractionPlan.model_validate(
            extraction_plan.model_dump(mode="json")
        )
        entry = AProfileStaticPredicatePlanEntry.model_validate(
            predicate_entry.model_dump(mode="json")
        )
        fact = AProfileStaticSemanticInstructionFact.model_validate(
            static_instruction_fact.model_dump(mode="json")
        )
        plan_entries = {item.predicate_ref: item for item in plan.predicate_entries}
        if plan_entries.get(entry.predicate_ref) != entry:
            raise ValueError("predicate entry does not belong to extraction plan")
        if fact.event_kind is not entry.event_kind:
            raise ValueError("static fact event kind does not match predicate")
        if fact.system_register is not entry.system_register:
            raise ValueError("static fact system register does not match predicate")
        values = {
            "extraction_plan_id": plan.id,
            "source_pattern_id": plan.source_pattern_id,
            "predicate_ref": entry.predicate_ref,
            "static_instruction_fact_id": fact.id,
            "case_id": entry.case_id,
            "position_index": entry.position_index,
            "remaining_objective_obligations": (
                entry.remaining_objective_obligations
            ),
        }
        snapshot = _AProfileStaticPredicateCandidateBody.model_validate(values)
        payload = snapshot.model_dump(mode="json")
        payload["contract"] = (
            PHASE10D_A_PROFILE_STATIC_PREDICATE_CANDIDATE_CONTRACT
        )
        return cls(
            id=a_profile_static_predicate_candidate_id(payload),
            contract=PHASE10D_A_PROFILE_STATIC_PREDICATE_CANDIDATE_CONTRACT,
            **snapshot.model_dump(mode="json"),
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "AProfileStaticPredicateCandidate":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != a_profile_static_predicate_candidate_id(payload):
            raise ValueError("static predicate-candidate ID mismatch")
        return self


def a_profile_static_semantic_extraction_result_id(payload: object) -> str:
    """Return a deterministic static extraction-result identity."""

    return _semantic_id("a-profile-static-semantic-extraction-result", payload)


class _AProfileStaticSemanticExtractionResultBody(DomainModel):
    artifact_id: Identifier
    artifact_sha256: Identifier
    architecture: Literal[Architecture.ARM]
    architecture_profile: Literal["a_profile"]
    instruction_set_state: Literal[AProfileStaticInstructionSetState.AARCH64]
    extraction_plan_id: Identifier
    source_pattern_id: Identifier
    extraction_plan_snapshot: AProfileStaticSemanticExtractionPlan
    instruction_facts: list[AProfileStaticSemanticInstructionFact] = Field(
        default_factory=list
    )
    predicate_candidates: list[AProfileStaticPredicateCandidate] = Field(
        default_factory=list
    )
    diagnostic_codes: list[Identifier] = Field(default_factory=list)

    @field_validator("artifact_id")
    @classmethod
    def reject_artifact_path(cls, value: str) -> str:
        lowered = value.lower()
        if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
            raise ValueError("result artifact ID must be path-neutral")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("instruction_facts")
    @classmethod
    def normalize_facts(
        cls, values: list[AProfileStaticSemanticInstructionFact]
    ) -> list[AProfileStaticSemanticInstructionFact]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static instruction facts must have unique IDs")
        return sorted(
            values,
            key=lambda item: (int(item.instruction_address, 16), item.id),
        )

    @field_validator("predicate_candidates")
    @classmethod
    def normalize_candidates(
        cls, values: list[AProfileStaticPredicateCandidate]
    ) -> list[AProfileStaticPredicateCandidate]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static predicate candidates must have unique IDs")
        return sorted(
            values,
            key=lambda item: (
                item.case_id,
                item.position_index,
                item.predicate_ref,
                item.static_instruction_fact_id,
                item.id,
            ),
        )

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("static semantic diagnostics must be unique")
        for value in values:
            lowered = value.lower()
            if any(item in lowered for item in _FORBIDDEN_DIAGNOSTIC_FRAGMENTS):
                raise ValueError("static semantic diagnostic contains an outcome")
        return sorted(values)

    @model_validator(mode="after")
    def validate_cross_bindings(
        self,
    ) -> "_AProfileStaticSemanticExtractionResultBody":
        plan = self.extraction_plan_snapshot
        if self.extraction_plan_id != plan.id:
            raise ValueError("result extraction-plan binding mismatch")
        if self.source_pattern_id != plan.source_pattern_id:
            raise ValueError("result source-pattern binding mismatch")
        if (
            self.architecture,
            self.architecture_profile,
            self.instruction_set_state,
        ) != (
            plan.architecture,
            plan.architecture_profile,
            plan.target_instruction_set_state,
        ):
            raise ValueError("result architecture or ISA binding mismatch")

        fact_by_id = {item.id: item for item in self.instruction_facts}
        entry_by_ref = {
            item.predicate_ref: item for item in plan.predicate_entries
        }
        for fact in self.instruction_facts:
            if (
                fact.artifact_id,
                fact.artifact_sha256,
                fact.architecture,
                fact.architecture_profile,
                fact.instruction_set_state,
            ) != (
                self.artifact_id,
                self.artifact_sha256,
                self.architecture,
                self.architecture_profile,
                self.instruction_set_state,
            ):
                raise ValueError("static instruction fact artifact binding mismatch")
        for candidate in self.predicate_candidates:
            if candidate.extraction_plan_id != plan.id:
                raise ValueError("candidate extraction-plan binding mismatch")
            if candidate.source_pattern_id != plan.source_pattern_id:
                raise ValueError("candidate source-pattern binding mismatch")
            fact = fact_by_id.get(candidate.static_instruction_fact_id)
            if fact is None:
                raise ValueError("candidate references a fact outside the result")
            entry = entry_by_ref.get(candidate.predicate_ref)
            if entry is None:
                raise ValueError("candidate references a predicate outside the plan")
            if (
                candidate.case_id,
                candidate.position_index,
                candidate.remaining_objective_obligations,
            ) != (
                entry.case_id,
                entry.position_index,
                entry.remaining_objective_obligations,
            ):
                raise ValueError("candidate predicate binding details mismatch")
            if (
                fact.event_kind is not entry.event_kind
                or fact.system_register is not entry.system_register
            ):
                raise ValueError("candidate fact semantics do not match predicate")
        return self


class AProfileStaticSemanticExtractionResult(
    _AProfileStaticSemanticExtractionResultBody
):
    """Future static facts and candidates; no case/order outcome is represented."""

    id: Identifier
    contract: Literal[
        PHASE10D_A_PROFILE_STATIC_EXTRACTION_RESULT_CONTRACT
    ] = PHASE10D_A_PROFILE_STATIC_EXTRACTION_RESULT_CONTRACT

    @classmethod
    def create(
        cls,
        *,
        artifact_id: str,
        artifact_sha256: str,
        extraction_plan: AProfileStaticSemanticExtractionPlan,
        instruction_facts: list[AProfileStaticSemanticInstructionFact],
        predicate_candidates: list[AProfileStaticPredicateCandidate],
        diagnostic_codes: list[str] | None = None,
    ) -> "AProfileStaticSemanticExtractionResult":
        plan = AProfileStaticSemanticExtractionPlan.model_validate(
            extraction_plan.model_dump(mode="json")
        )
        values = {
            "artifact_id": artifact_id,
            "artifact_sha256": artifact_sha256,
            "architecture": plan.architecture,
            "architecture_profile": plan.architecture_profile,
            "instruction_set_state": plan.target_instruction_set_state,
            "extraction_plan_id": plan.id,
            "source_pattern_id": plan.source_pattern_id,
            "extraction_plan_snapshot": plan,
            "instruction_facts": instruction_facts,
            "predicate_candidates": predicate_candidates,
            "diagnostic_codes": diagnostic_codes or [],
        }
        snapshot = _AProfileStaticSemanticExtractionResultBody.model_validate(
            values
        )
        payload = snapshot.model_dump(mode="json")
        payload["contract"] = (
            PHASE10D_A_PROFILE_STATIC_EXTRACTION_RESULT_CONTRACT
        )
        return cls(
            id=a_profile_static_semantic_extraction_result_id(payload),
            contract=PHASE10D_A_PROFILE_STATIC_EXTRACTION_RESULT_CONTRACT,
            **snapshot.model_dump(mode="json"),
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "AProfileStaticSemanticExtractionResult":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != a_profile_static_semantic_extraction_result_id(payload):
            raise ValueError("static semantic extraction-result ID mismatch")
        return self
