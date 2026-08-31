"""Deterministic plan translation for future A-profile static extraction."""

from __future__ import annotations

import hashlib
from pathlib import Path

from chipchain.hardware_trigger.a_profile_semantic_models import (
    PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT,
    AProfileAdditionalTimingPrecision,
    AProfileMemoryTypeSemantics,
    AProfileRelationPrecision,
    AProfileSemanticEventKind,
    AProfileSemanticRelation,
    AProfileSemanticTriggerPattern,
    AdditionalTimingConditionRequirement,
    MemoryTypeObservationRequirement,
    SemanticRelationEvaluability,
)
from chipchain.hardware_trigger.a_profile_static_semantic_models import (
    AProfileStaticCaseSourceLimitation,
    AProfileStaticInstructionSetState,
    AProfileStaticPredicatePlanEntry,
    AProfileStaticSemanticExtractionPlan,
    StaticRecognitionSemantics,
    a_profile_semantic_predicate_ref,
    obligations_for_predicate,
)


_SUPPORTED_EVENTS = {
    AProfileSemanticEventKind.MEMORY_LOAD,
    AProfileSemanticEventKind.STORE_EXCLUSIVE,
    AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
}


def translate_a_profile_pattern_to_static_extraction_plan(
    pattern: AProfileSemanticTriggerPattern,
    *,
    source_pattern_sha256: str,
    expected_source_pattern_id: str,
    expected_source_pattern_sha256: str,
) -> AProfileStaticSemanticExtractionPlan:
    """Translate one detached frozen semantic pattern into a static plan."""

    source = AProfileSemanticTriggerPattern.model_validate(
        pattern.model_dump(mode="json")
    )
    if source_pattern_sha256 != expected_source_pattern_sha256:
        raise ValueError("source semantic-pattern artifact SHA-256 mismatch")
    if source.id != expected_source_pattern_id:
        raise ValueError("source semantic-pattern identity mismatch")
    if source.contract != PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT:
        raise ValueError("source semantic-pattern contract mismatch")
    precision = source.source_precision_obligations
    if not precision.program_order_source_defined:
        raise ValueError("source pattern no longer defines program order")
    if (
        precision.quantitative_proximity_source_defined
        or precision.additional_timing_conditions_source_defined
        or precision.machine_code_sequence_source_defined
        or precision.effective_memory_type_resolution_source_defined
        or precision.runtime_environment_source_defined
        or precision.hardware_effect_empirical_source_defined
    ):
        raise ValueError("source pattern precision changed unexpectedly")
    if source.source_additional_timing_precision is not (
        AProfileAdditionalTimingPrecision.UNSPECIFIED_BY_PUBLIC_SOURCE
    ):
        raise ValueError("source timing precision changed unexpectedly")
    if source.additional_timing_condition_requirement is not (
        AdditionalTimingConditionRequirement.UNRESOLVED_FROM_PUBLIC_DOCUMENTATION
    ):
        raise ValueError("source timing obligation changed unexpectedly")

    entries: list[AProfileStaticPredicatePlanEntry] = []
    limitations: list[AProfileStaticCaseSourceLimitation] = []
    for case in source.cases:
        if case.relation is not AProfileSemanticRelation.CLOSE_PROXIMITY:
            raise ValueError("source relation changed unexpectedly")
        if case.relation_precision is not AProfileRelationPrecision.QUALITATIVE_ONLY:
            raise ValueError("source relation precision changed unexpectedly")
        if case.quantitative_bound is not None:
            raise ValueError("source pattern introduced a quantitative bound")
        if case.relation_evaluability is not (
            SemanticRelationEvaluability.SOURCE_INSUFFICIENT_FOR_EXACT_SOFTWARE_ONLY_SATISFACTION
        ):
            raise ValueError("source relation evaluability changed unexpectedly")
        limitations.append(
            AProfileStaticCaseSourceLimitation(
                case_id=case.case_id,
                relation=case.relation,
                relation_precision=case.relation_precision,
                quantitative_bound=case.quantitative_bound,
                relation_evaluability=case.relation_evaluability,
                source_additional_timing_precision=(
                    source.source_additional_timing_precision
                ),
                additional_timing_condition_requirement=(
                    source.additional_timing_condition_requirement
                ),
            )
        )
        for position in case.positions:
            for predicate in position.alternatives:
                if predicate.kind not in _SUPPORTED_EVENTS:
                    raise ValueError("source pattern contains an unsupported event")
                if predicate.kind is AProfileSemanticEventKind.MEMORY_LOAD:
                    if predicate.memory_type_semantics is not (
                        AProfileMemoryTypeSemantics.EFFECTIVE_ARCHITECTURAL_MEMORY_TYPE
                    ):
                        raise ValueError("load memory-type semantics changed")
                    if predicate.memory_type_observation_requirement is not (
                        MemoryTypeObservationRequirement.OBJECTIVE_EFFECTIVE_MEMORY_TYPE_REQUIRED
                    ):
                        raise ValueError("load memory-type obligation changed")
                entries.append(
                    AProfileStaticPredicatePlanEntry(
                        predicate_ref=a_profile_semantic_predicate_ref(
                            pattern_id=source.id,
                            case_id=case.case_id,
                            position_index=position.position_index,
                            predicate=predicate,
                        ),
                        case_id=case.case_id,
                        position_index=position.position_index,
                        event_kind=predicate.kind,
                        applicability=predicate.applicability,
                        system_register=predicate.system_register,
                        required_memory_type_constraints=(
                            predicate.memory_type_constraints
                        ),
                        memory_type_semantics=predicate.memory_type_semantics,
                        memory_type_observation_requirement=(
                            predicate.memory_type_observation_requirement
                        ),
                        static_recognition_semantics=(
                            StaticRecognitionSemantics.DECODED_INSTRUCTION_SEMANTICS
                        ),
                        remaining_objective_obligations=(
                            obligations_for_predicate(predicate)
                        ),
                    )
                )

    return AProfileStaticSemanticExtractionPlan.create(
        architecture=source.architecture,
        architecture_profile=source.architecture_profile,
        processor=source.processor,
        cve_id=source.cve_id,
        erratum_id=source.erratum_id,
        source_pattern_id=source.id,
        source_pattern_sha256=source_pattern_sha256,
        source_pattern_contract=source.contract,
        target_instruction_set_state=AProfileStaticInstructionSetState.AARCH64,
        predicate_entries=entries,
        case_source_limitations=limitations,
    )


def build_a_profile_static_semantic_extraction_plan(
    *,
    semantic_pattern_bytes: bytes,
    expected_source_pattern_id: str,
    expected_source_pattern_sha256: str,
) -> AProfileStaticSemanticExtractionPlan:
    """Build from one immutable snapshot of the exact frozen 2B1 pattern."""

    source_sha256 = hashlib.sha256(semantic_pattern_bytes).hexdigest()
    if source_sha256 != expected_source_pattern_sha256:
        raise ValueError("source semantic-pattern artifact SHA-256 mismatch")
    source = AProfileSemanticTriggerPattern.model_validate_json(
        semantic_pattern_bytes
    )
    return translate_a_profile_pattern_to_static_extraction_plan(
        source,
        source_pattern_sha256=source_sha256,
        expected_source_pattern_id=expected_source_pattern_id,
        expected_source_pattern_sha256=expected_source_pattern_sha256,
    )


def serialize_a_profile_static_semantic_extraction_plan(
    plan: AProfileStaticSemanticExtractionPlan,
) -> str:
    """Return deterministic JSON text with one trailing newline."""

    snapshot = AProfileStaticSemanticExtractionPlan.model_validate(
        plan.model_dump(mode="json")
    )
    return snapshot.model_dump_json(indent=2, ensure_ascii=False) + "\n"


def write_a_profile_static_semantic_extraction_plan(
    plan: AProfileStaticSemanticExtractionPlan,
    path: str | Path,
) -> None:
    """Write one deterministic artifact-neutral extraction plan."""

    Path(path).write_text(
        serialize_a_profile_static_semantic_extraction_plan(plan),
        encoding="utf-8",
    )
