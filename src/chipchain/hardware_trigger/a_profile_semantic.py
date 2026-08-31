"""Offline translation from documented errata to A-profile predicates."""

from __future__ import annotations

import hashlib
from pathlib import Path

from chipchain.hardware_trigger.a_profile_semantic_models import (
    AProfileAdditionalTimingPrecision,
    AProfileDocumentedEffectKind,
    AProfileDocumentedEffectModality,
    AProfileDocumentedEffectReference,
    AProfileExecutionApplicability,
    AProfileMemoryType,
    AProfileMemoryTypeSemantics,
    AProfileMitigationReference,
    AProfileMitigationReferenceKind,
    AProfileMitigationReferenceSemantics,
    AProfileProcessorRevisionScope,
    AProfileRelationPrecision,
    AProfileRevisionDisposition,
    AProfileSemanticEventKind,
    AProfileSemanticEventPosition,
    AProfileSemanticEventPredicate,
    AProfileSemanticPatternCase,
    AProfileSemanticPatternUse,
    AProfileSemanticRelation,
    AProfileSemanticTriggerPattern,
    AProfileSourcePrecisionObligations,
    AProfileSystemRegister,
    AdditionalTimingConditionRequirement,
    MemoryTypeObservationRequirement,
    SemanticAlternativeSemantics,
    SemanticPositionOrder,
    SemanticRelationEvaluability,
)
from chipchain.hardware_trigger.documented_erratum_models import (
    PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT,
    AdditionalTimingConditionPrecision,
    CpuRevisionDisposition,
    DocumentedEffectModality,
    DocumentedHardwareEffectKind,
    DocumentedHardwareErratumContract,
    DocumentedMemoryType,
    DocumentedMitigationKind,
    DocumentedOperationApplicability,
    DocumentedProgramRelation,
    DocumentedRelationPrecision,
    DocumentedSemanticEvent,
    DocumentedSemanticEventKind,
)


_EXPECTED_SOURCE_ID = (
    "documented-hardware-erratum:"
    "8ad52bee747242179997fd58989c92f419ff051f618682e07e158d00a787096c"
)
_EXPECTED_SOURCE_SHA256 = (
    "bd50b8b50313041c3d5245cccaf51a0d4d479914033ad233d79a740180b0c5a1"
)

_EVENT_KIND = {
    DocumentedSemanticEventKind.MEMORY_LOAD: AProfileSemanticEventKind.MEMORY_LOAD,
    DocumentedSemanticEventKind.STORE_EXCLUSIVE: (
        AProfileSemanticEventKind.STORE_EXCLUSIVE
    ),
    DocumentedSemanticEventKind.SYSTEM_REGISTER_READ: (
        AProfileSemanticEventKind.SYSTEM_REGISTER_READ
    ),
}
_APPLICABILITY = {
    DocumentedOperationApplicability.ARM_A_PROFILE: (
        AProfileExecutionApplicability.ARM_A_PROFILE
    ),
    DocumentedOperationApplicability.PRIVILEGED_AARCH64: (
        AProfileExecutionApplicability.PRIVILEGED_AARCH64
    ),
}
_MEMORY_TYPE = {
    DocumentedMemoryType.DEVICE: AProfileMemoryType.DEVICE,
    DocumentedMemoryType.NORMAL_NON_CACHEABLE: (
        AProfileMemoryType.NORMAL_NON_CACHEABLE
    ),
}
_REVISION_DISPOSITION = {
    CpuRevisionDisposition.AFFECTED: AProfileRevisionDisposition.AFFECTED,
    CpuRevisionDisposition.FIXED: AProfileRevisionDisposition.FIXED,
}
_MITIGATION_KIND = {
    DocumentedMitigationKind.PAR_EL1_DMB_SY_ORDERING: (
        AProfileMitigationReferenceKind.PAR_EL1_DMB_SY_ORDERING
    ),
    DocumentedMitigationKind.EXCLUSIVE_RELATED_FIRMWARE_OR_HARDWARE: (
        AProfileMitigationReferenceKind.EXCLUSIVE_RELATED_FIRMWARE_OR_HARDWARE
    ),
    DocumentedMitigationKind.CASE_B_EL0_DEVICE_ACCESS_RESTRICTION: (
        AProfileMitigationReferenceKind.CASE_B_EL0_DEVICE_ACCESS_RESTRICTION
    ),
}


def _translate_event(
    event: DocumentedSemanticEvent,
) -> AProfileSemanticEventPredicate:
    try:
        kind = _EVENT_KIND[event.kind]
        applicability = _APPLICABILITY[event.applicability]
        memory_types = [_MEMORY_TYPE[item] for item in event.memory_types]
    except KeyError as exc:
        raise ValueError("documented erratum contains an unsupported event") from exc
    is_load = kind is AProfileSemanticEventKind.MEMORY_LOAD
    return AProfileSemanticEventPredicate(
        kind=kind,
        applicability=applicability,
        system_register=(
            AProfileSystemRegister.PAR_EL1
            if event.system_register == "PAR_EL1"
            else None
        ),
        memory_type_constraints=memory_types,
        memory_type_semantics=(
            AProfileMemoryTypeSemantics.EFFECTIVE_ARCHITECTURAL_MEMORY_TYPE
            if is_load
            else None
        ),
        memory_type_observation_requirement=(
            MemoryTypeObservationRequirement.OBJECTIVE_EFFECTIVE_MEMORY_TYPE_REQUIRED
            if is_load
            else None
        ),
    )


def translate_documented_erratum_to_a_profile_pattern(
    documented_erratum: DocumentedHardwareErratumContract,
    *,
    source_artifact_sha256: str,
) -> AProfileSemanticTriggerPattern:
    """Translate one detached frozen documented contract into predicates."""

    source = DocumentedHardwareErratumContract.model_validate(
        documented_erratum.model_dump(mode="json")
    )
    if source_artifact_sha256 != _EXPECTED_SOURCE_SHA256:
        raise ValueError("documented erratum artifact SHA-256 mismatch")
    if source.id != _EXPECTED_SOURCE_ID:
        raise ValueError("documented erratum identity mismatch")
    if source.contract != PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT:
        raise ValueError("documented erratum contract version mismatch")
    if len(source.program_order_cases) != 2:
        raise ValueError("frozen documented erratum must contain exactly two cases")
    if source.source_precision.unique_machine_code_sequence_defined:
        raise ValueError("semantic translation cannot consume a machine-code claim")
    if source.source_precision.hardware_failure_observation_present:
        raise ValueError("semantic translation cannot consume an empirical outcome")
    if not source.source_precision.program_order_defined:
        raise ValueError("semantic translation requires documented program order")
    if source.source_precision.effective_memory_type_resolution_defined:
        raise ValueError("frozen source unexpectedly resolves effective memory type")
    if source.additional_timing_condition_precision is not (
        AdditionalTimingConditionPrecision.UNSPECIFIED_BY_PUBLIC_SOURCE
    ):
        raise ValueError("unexpected additional timing-condition precision")
    if source.documented_effect.kind is not DocumentedHardwareEffectKind.CORE_DEADLOCK:
        raise ValueError("unsupported documented hardware effect")
    if source.documented_effect.modality is not DocumentedEffectModality.POSSIBLE:
        raise ValueError("documented effect must remain possible")

    cases: list[AProfileSemanticPatternCase] = []
    for source_case in source.program_order_cases:
        if source_case.relation is not DocumentedProgramRelation.CLOSE_PROXIMITY:
            raise ValueError("unsupported documented relation")
        if source_case.relation_precision is not (
            DocumentedRelationPrecision.QUALITATIVE_ONLY
        ):
            raise ValueError("unexpected documented relation precision")
        if source_case.quantitative_bound is not None:
            raise ValueError("documented qualitative relation has a numeric bound")
        cases.append(
            AProfileSemanticPatternCase(
                case_id=source_case.case_id,
                position_order=SemanticPositionOrder.PROGRAM_ORDER,
                positions=[
                    AProfileSemanticEventPosition(
                        position_index=1,
                        alternative_semantics=SemanticAlternativeSemantics.OR,
                        alternatives=[
                            _translate_event(item)
                            for item in source_case.event_1.alternatives
                        ],
                    ),
                    AProfileSemanticEventPosition(
                        position_index=2,
                        alternative_semantics=SemanticAlternativeSemantics.OR,
                        alternatives=[
                            _translate_event(item)
                            for item in source_case.event_2.alternatives
                        ],
                    ),
                ],
                relation=AProfileSemanticRelation.CLOSE_PROXIMITY,
                relation_precision=AProfileRelationPrecision.QUALITATIVE_ONLY,
                quantitative_bound=None,
                relation_evaluability=(
                    SemanticRelationEvaluability.SOURCE_INSUFFICIENT_FOR_EXACT_SOFTWARE_ONLY_SATISFACTION
                ),
            )
        )

    return AProfileSemanticTriggerPattern.create(
        architecture=source.architecture,
        architecture_profile=source.architecture_profile,
        processor=source.processor,
        cve_id=source.cve_id,
        erratum_id=source.authoritative_source.erratum_id,
        configurations=source.configurations,
        source_documented_erratum_id=source.id,
        source_documented_erratum_sha256=source_artifact_sha256,
        source_documented_erratum_contract=source.contract,
        revision_scope=[
            AProfileProcessorRevisionScope(
                processor=item.processor,
                revision=item.revision,
                disposition=_REVISION_DISPOSITION[item.disposition],
            )
            for item in source.revision_records
        ],
        cases=cases,
        source_additional_timing_precision=(
            AProfileAdditionalTimingPrecision.UNSPECIFIED_BY_PUBLIC_SOURCE
        ),
        additional_timing_condition_requirement=(
            AdditionalTimingConditionRequirement.UNRESOLVED_FROM_PUBLIC_DOCUMENTATION
        ),
        documented_effect_reference=AProfileDocumentedEffectReference(
            kind=AProfileDocumentedEffectKind.CORE_DEADLOCK,
            modality=AProfileDocumentedEffectModality.POSSIBLE,
        ),
        mitigation_references=[
            AProfileMitigationReference(
                kind=_MITIGATION_KIND[item.kind],
                semantics=(
                    AProfileMitigationReferenceSemantics.DOCUMENTED_MITIGATION_REFERENCE
                ),
            )
            for item in source.documented_mitigations
        ],
        source_precision_obligations=AProfileSourcePrecisionObligations(
            program_order_source_defined=(
                source.source_precision.program_order_defined
            ),
            quantitative_proximity_source_defined=(
                source.source_precision.quantitative_proximity_bound_defined
            ),
            additional_timing_conditions_source_defined=(
                source.source_precision.additional_timing_conditions_fully_defined
            ),
            machine_code_sequence_source_defined=(
                source.source_precision.unique_machine_code_sequence_defined
            ),
            effective_memory_type_resolution_source_defined=(
                source.source_precision.effective_memory_type_resolution_defined
            ),
            runtime_environment_source_defined=(
                source.source_precision.runtime_environment_defined
            ),
            hardware_effect_empirical_source_defined=(
                source.source_precision.hardware_failure_observation_present
            ),
        ),
        pattern_use=AProfileSemanticPatternUse.OBJECTIVE_ANALYZER_PREDICATES_ONLY,
    )


def build_a_profile_semantic_trigger_pattern(
    *,
    documented_erratum_bytes: bytes,
) -> AProfileSemanticTriggerPattern:
    """Build from one exact immutable snapshot of the frozen 2B0 artifact."""

    source_sha256 = hashlib.sha256(documented_erratum_bytes).hexdigest()
    if source_sha256 != _EXPECTED_SOURCE_SHA256:
        raise ValueError("documented erratum artifact SHA-256 mismatch")
    documented_erratum = DocumentedHardwareErratumContract.model_validate_json(
        documented_erratum_bytes
    )
    return translate_documented_erratum_to_a_profile_pattern(
        documented_erratum,
        source_artifact_sha256=source_sha256,
    )


def serialize_a_profile_semantic_trigger_pattern(
    pattern: AProfileSemanticTriggerPattern,
) -> str:
    """Return deterministic JSON text with one final newline."""

    snapshot = AProfileSemanticTriggerPattern.model_validate(
        pattern.model_dump(mode="json")
    )
    return snapshot.model_dump_json(indent=2, ensure_ascii=False) + "\n"


def write_a_profile_semantic_trigger_pattern(
    pattern: AProfileSemanticTriggerPattern,
    path: str | Path,
) -> None:
    """Write one deterministic semantic pattern without external state."""

    Path(path).write_text(
        serialize_a_profile_semantic_trigger_pattern(pattern),
        encoding="utf-8",
    )
