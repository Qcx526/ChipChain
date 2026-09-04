"""Source-faithful documented erratum to generic AArch64 pattern adapter."""

from __future__ import annotations

from chipchain.analysis.static_semantic_models import (
    StaticSemanticAttribute,
    StaticSemanticAttributeName,
    StaticSemanticOperation,
)
from chipchain.analysis.static_trigger_pattern_models import (
    StaticTriggerCase,
    StaticTriggerObjectiveRequirement,
    StaticTriggerPattern,
    StaticTriggerPosition,
    StaticTriggerPredicate,
    StaticTriggerRelationEvaluability,
    StaticTriggerRelationKind,
    StaticTriggerRelationPrecision,
    StaticTriggerRelationRequirement,
)
from chipchain.hardware_trigger.documented_erratum_models import (
    DocumentedHardwareErratumContract,
    DocumentedMemoryType,
    DocumentedOperationApplicability,
    DocumentedProgramOrderCase,
    DocumentedSemanticEvent,
    DocumentedSemanticEventKind,
)
from chipchain.models.enums import Architecture


_EVENT_OPERATION = {
    DocumentedSemanticEventKind.MEMORY_LOAD: StaticSemanticOperation.MEMORY_LOAD,
    DocumentedSemanticEventKind.STORE_EXCLUSIVE: (
        StaticSemanticOperation.STORE_EXCLUSIVE
    ),
    DocumentedSemanticEventKind.SYSTEM_REGISTER_READ: (
        StaticSemanticOperation.SYSTEM_REGISTER_READ
    ),
}
_MEMORY_TYPE = {
    DocumentedMemoryType.DEVICE: "device",
    DocumentedMemoryType.NORMAL_NON_CACHEABLE: "normal_non_cacheable",
}
_EXECUTION_CONTEXT = {
    DocumentedOperationApplicability.ARM_A_PROFILE: "arm_a_profile",
    DocumentedOperationApplicability.PRIVILEGED_AARCH64: "privileged_aarch64",
}


def _translate_event(event: DocumentedSemanticEvent) -> StaticTriggerPredicate:
    try:
        operation = _EVENT_OPERATION[event.kind]
        memory_types = [_MEMORY_TYPE[value] for value in event.memory_types]
        execution_context = _EXECUTION_CONTEXT[event.applicability]
    except KeyError as error:
        raise ValueError("unsupported documented erratum event vocabulary") from error
    attributes = []
    if event.system_register == "PAR_EL1":
        attributes.append(
            StaticSemanticAttribute(
                name=StaticSemanticAttributeName.SYSTEM_REGISTER,
                value="par_el1",
            )
        )
    requirements = [
        StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED
    ]
    if memory_types:
        requirements.append(
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        )
    return StaticTriggerPredicate.create(
        operation=operation,
        required_attributes=attributes,
        required_effective_memory_types=memory_types,
        required_execution_contexts=[execution_context],
        objective_requirements=requirements,
    )


def _translate_case(
    erratum_id: str,
    source: DocumentedProgramOrderCase,
) -> StaticTriggerCase:
    positions = [
        StaticTriggerPosition.create(
            position_index=index,
            alternatives=[
                _translate_event(event) for event in source_position.alternatives
            ],
        )
        for index, source_position in enumerate(
            (source.event_1, source.event_2), start=1
        )
    ]
    relation = StaticTriggerRelationRequirement.create(
        relation_kind=StaticTriggerRelationKind.CLOSE_PROXIMITY,
        precision=StaticTriggerRelationPrecision.QUALITATIVE_ONLY,
        quantitative_bound=None,
        evaluability=(
            StaticTriggerRelationEvaluability
            .SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION
        ),
    )
    return StaticTriggerCase.create(
        case_reference_id=(
            f"documented-erratum-{erratum_id}-{source.case_id.replace('_', '-')}"
        ),
        positions=positions,
        relation_requirement=relation,
        objective_requirements=[
            StaticTriggerObjectiveRequirement
            .RELATION_PROXIMITY_REMAINS_UNRESOLVED
        ],
    )


def translate_documented_erratum_to_aarch64_static_trigger_pattern(
    erratum: DocumentedHardwareErratumContract,
) -> StaticTriggerPattern:
    """Project broader documented A-profile semantics into AArch64 analysis IR."""

    source = DocumentedHardwareErratumContract.model_validate(
        erratum.model_dump(mode="json")
    )
    erratum_id = source.authoritative_source.erratum_id
    return StaticTriggerPattern.create(
        architecture=Architecture.ARM,
        instruction_set="aarch64",
        pattern_name=(
            f"documented_erratum_{erratum_id}_generic_aarch64_static_pattern"
        ),
        source_reference_ids=[
            source.id,
            source.authoritative_source.source_locator,
            source.public_corpus_id,
        ],
        hardware_reference_ids=[source.id],
        cases=[
            _translate_case(erratum_id, case)
            for case in source.program_order_cases
        ],
        objective_requirements=[
            StaticTriggerObjectiveRequirement
            .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
        ],
    )
