"""Phase 9A-R3 semantic binding-cardinality regressions."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.models import (
    Architecture,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.verification import (
    InteractionReferenceBinding,
    InteractionReferenceRole,
    InteractionSourceKind,
    InteractionVerificationInput,
    InteractionVerificationPipeline,
    InteractionVerificationResult,
    VerificationRecord,
    VerificationStatus,
    VerificationSubjectKind,
)


CARDINALITY_ERROR = (
    "each interaction reference may have only one source binding in Phase 9A-R MVP"
)


def _interaction(*, trigger_ids: list[str] | None = None) -> CrossLayerInteraction:
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["target-A"],
        trigger_behavior_ids=trigger_ids or ["trigger-A"],
        hardware_resource_ids=["resource-A"],
    )


def _binding(
    reference_id: str,
    role: InteractionReferenceRole,
    source_kind: InteractionSourceKind,
    source_id: str,
) -> InteractionReferenceBinding:
    return InteractionReferenceBinding(
        interaction_reference_id=reference_id,
        reference_role=role,
        source_kind=source_kind,
        source_id=source_id,
    )


@pytest.mark.parametrize(
    "reference_id,role,first_kind,second_kind",
    [
        (
            "trigger-A",
            InteractionReferenceRole.TRIGGER_BEHAVIOR,
            InteractionSourceKind.BEHAVIOR_EDGE,
            InteractionSourceKind.EVIDENCE,
        ),
        (
            "target-A",
            InteractionReferenceRole.TARGET_VULNERABILITY,
            InteractionSourceKind.KNOWLEDGE_NODE,
            InteractionSourceKind.EVIDENCE,
        ),
        (
            "resource-A",
            InteractionReferenceRole.HARDWARE_RESOURCE,
            InteractionSourceKind.ENTITY_LINK,
            InteractionSourceKind.BEHAVIOR_NODE,
        ),
    ],
)
def test_duplicate_semantic_reference_with_different_sources_is_rejected(
    reference_id: str,
    role: InteractionReferenceRole,
    first_kind: InteractionSourceKind,
    second_kind: InteractionSourceKind,
) -> None:
    bindings = [
        _binding(reference_id, role, first_kind, "source-A"),
        _binding(reference_id, role, second_kind, "source-B"),
    ]

    with pytest.raises(ValidationError, match=CARDINALITY_ERROR):
        InteractionVerificationInput.create(_interaction(), bindings=bindings)


def test_different_trigger_reference_ids_remain_allowed() -> None:
    interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    bindings = [
        _binding(
            "trigger-A",
            InteractionReferenceRole.TRIGGER_BEHAVIOR,
            InteractionSourceKind.BEHAVIOR_EDGE,
            "edge-A",
        ),
        _binding(
            "trigger-B",
            InteractionReferenceRole.TRIGGER_BEHAVIOR,
            InteractionSourceKind.BEHAVIOR_EDGE,
            "edge-B",
        ),
    ]

    verification_input = InteractionVerificationInput.create(
        interaction, bindings=bindings
    )

    assert verification_input.bindings == bindings


@pytest.mark.parametrize("reverse", [False, True])
def test_input_order_cannot_select_a_last_binding(reverse: bool) -> None:
    bindings = [
        _binding(
            "trigger-A",
            InteractionReferenceRole.TRIGGER_BEHAVIOR,
            InteractionSourceKind.BEHAVIOR_EDGE,
            "edge-A",
        ),
        _binding(
            "trigger-A",
            InteractionReferenceRole.TRIGGER_BEHAVIOR,
            InteractionSourceKind.EVIDENCE,
            "evidence-B",
        ),
    ]
    if reverse:
        bindings.reverse()

    with pytest.raises(ValidationError, match=CARDINALITY_ERROR):
        InteractionVerificationInput.create(_interaction(), bindings=bindings)


def _two_binding_result() -> InteractionVerificationResult:
    interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    bindings = [
        _binding(
            "trigger-A",
            InteractionReferenceRole.TRIGGER_BEHAVIOR,
            InteractionSourceKind.BEHAVIOR_EDGE,
            "edge-A",
        ),
        _binding(
            "trigger-B",
            InteractionReferenceRole.TRIGGER_BEHAVIOR,
            InteractionSourceKind.BEHAVIOR_EDGE,
            "edge-B",
        ),
    ]
    return InteractionVerificationPipeline().verify(
        interaction,
        InteractionVerificationInput.create(interaction, bindings=bindings),
    )


def test_binding_verification_record_ids_are_unique() -> None:
    result = _two_binding_result()

    record_ids = [record.id for record in result.binding_verifications]

    assert len(record_ids) == len(set(record_ids)) == 2


def test_binding_verification_subject_ids_are_unique() -> None:
    result = _two_binding_result()

    subject_ids = [record.subject_id for record in result.binding_verifications]

    assert len(subject_ids) == len(set(subject_ids)) == 2


def test_result_rejects_duplicate_binding_subject_ids_with_distinct_record_ids() -> None:
    result = _two_binding_result()
    values = result.model_dump(mode="json")
    original = result.binding_verifications[0]
    duplicate_subject = VerificationRecord.create(
        interaction_id=result.interaction_id,
        architecture=result.architecture,
        subject_kind=original.subject_kind,
        subject_id=original.subject_id,
        status=VerificationStatus.UNKNOWN,
        verifier="phase-9a-r3-defense-in-depth",
    )
    values["binding_verifications"].append(duplicate_subject.model_dump(mode="json"))

    with pytest.raises(ValidationError, match="duplicate subject IDs"):
        InteractionVerificationResult.model_validate(values)


@pytest.mark.parametrize(
    "field,subject_kind",
    [
        ("binding_verifications", VerificationSubjectKind.INTERACTION_PARTICIPANT),
        ("behavior_edge_verifications", VerificationSubjectKind.BEHAVIOR_EDGE),
        ("entity_link_verifications", VerificationSubjectKind.ENTITY_LINK),
        ("knowledge_edge_verifications", VerificationSubjectKind.KNOWLEDGE_EDGE),
        ("architecture_rule_verifications", VerificationSubjectKind.ARCHITECTURE_RULE),
    ],
)
def test_result_record_collections_reject_duplicate_record_ids(
    field: str, subject_kind: VerificationSubjectKind
) -> None:
    result = _two_binding_result()
    values = result.model_dump(mode="json")
    record = VerificationRecord.create(
        interaction_id=result.interaction_id,
        architecture=result.architecture,
        subject_kind=subject_kind,
        subject_id=f"r3-{field}",
        status=VerificationStatus.UNKNOWN,
        verifier="phase-9a-r3-defense-in-depth",
    ).model_dump(mode="json")
    values[field] = [record, record]

    with pytest.raises(ValidationError, match="duplicate VerificationRecord IDs"):
        InteractionVerificationResult.model_validate(values)
