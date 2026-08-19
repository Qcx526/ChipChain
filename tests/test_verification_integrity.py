"""Phase 9A-R2 final verification-integrity regressions."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.models import (
    Architecture,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Evidence,
    EvidenceType,
    Layer,
)
from chipchain.reasoning import InMemoryEvidenceResolver
from chipchain.verification import (
    InteractionReferenceBinding,
    InteractionReferenceRole,
    InteractionSourceKind,
    InteractionVerificationInput,
    InteractionVerificationPipeline,
    InteractionVerificationResult,
    VerificationInputError,
    VerificationStatus,
    merge_evidence,
)


def _type1():
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        initiating_vulnerability_ids=["firmware-vulnerability"],
        target_vulnerability_ids=["hardware-vulnerability"],
        trigger_behavior_ids=["trigger"],
    )


def _type2():
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        source_layer=Layer.DRIVER,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["hardware-vulnerability"],
        trigger_behavior_ids=["trigger"],
    )


def _linked_evidence(reference_id, role):
    return Evidence(
        id="direct-evidence",
        type=EvidenceType.STATIC_ANALYSIS,
        source="owned-r2-fixture",
        confidence=1.0,
        verified=True,
        metadata={
            "interaction_reference_id": reference_id,
            "reference_role": role.value,
        },
    )


@pytest.mark.parametrize(
    "interaction,reference_id,role",
    [
        (_type1(), "firmware-vulnerability", InteractionReferenceRole.INITIATING_VULNERABILITY),
        (_type2(), "hardware-vulnerability", InteractionReferenceRole.TARGET_VULNERABILITY),
    ],
)
def test_direct_evidence_cannot_independently_verify_vulnerability_participant(
    interaction, reference_id, role
):
    binding = InteractionReferenceBinding(
        interaction_reference_id=reference_id,
        reference_role=role,
        source_kind=InteractionSourceKind.EVIDENCE,
        source_id="direct-evidence",
    )
    data = InteractionVerificationInput.create(interaction, bindings=[binding])
    result = InteractionVerificationPipeline().verify(
        interaction,
        data,
        interaction_evidence=[_linked_evidence(reference_id, role)],
    )
    assert result.binding_verifications[0].status is VerificationStatus.UNKNOWN
    assert result.binding_verifications[0].supporting_evidence_ids == []
    assert "cannot independently verify" in result.binding_verifications[0].messages[0]


def test_behavior_direct_evidence_binding_still_uses_subject_linkage():
    interaction = _type2()
    role = InteractionReferenceRole.TRIGGER_BEHAVIOR
    binding = InteractionReferenceBinding(
        interaction_reference_id="trigger",
        reference_role=role,
        source_kind=InteractionSourceKind.EVIDENCE,
        source_id="direct-evidence",
    )
    result = InteractionVerificationPipeline().verify(
        interaction,
        InteractionVerificationInput.create(interaction, bindings=[binding]),
        interaction_evidence=[_linked_evidence("trigger", role)],
    )
    assert result.binding_verifications[0].status is VerificationStatus.VERIFIED


def test_identical_duplicate_evidence_ids_are_safely_deduplicated(
    reasoning_candidate,
    reasoning_behavior_repository,
    reasoning_behavior_evidence,
    synthetic_arm_knowledge_repository,
):
    interaction = _type2()
    data = InteractionVerificationInput.create(
        interaction, legacy_candidate_id=reasoning_candidate.id
    )
    duplicate = Evidence.model_validate(
        reasoning_behavior_evidence[0].model_dump(mode="json")
    )
    result = InteractionVerificationPipeline().verify(
        interaction,
        data,
        reasoning_behavior_repository,
        synthetic_arm_knowledge_repository,
        InMemoryEvidenceResolver(reasoning_behavior_evidence),
        legacy_candidate=reasoning_candidate,
        interaction_evidence=[duplicate],
    )
    assert result.interaction_id == interaction.id


def test_conflicting_duplicate_evidence_ids_are_rejected(
    reasoning_candidate,
    reasoning_behavior_repository,
    reasoning_behavior_evidence,
    synthetic_arm_knowledge_repository,
):
    interaction = _type2()
    data = InteractionVerificationInput.create(
        interaction, legacy_candidate_id=reasoning_candidate.id
    )
    conflict = reasoning_behavior_evidence[0].model_copy(
        update={"source": "conflicting-source"}
    )
    with pytest.raises(VerificationInputError):
        InteractionVerificationPipeline().verify(
            interaction,
            data,
            reasoning_behavior_repository,
            synthetic_arm_knowledge_repository,
            InMemoryEvidenceResolver(reasoning_behavior_evidence),
            legacy_candidate=reasoning_candidate,
            interaction_evidence=[conflict],
        )


def test_evidence_merge_is_order_independent():
    first = Evidence(
        id="z-evidence", type=EvidenceType.STATIC_ANALYSIS,
        source="fixture", confidence=1.0, verified=True,
    )
    second = Evidence(
        id="a-evidence", type=EvidenceType.DYNAMIC_ANALYSIS,
        source="fixture", confidence=1.0, verified=True,
    )
    duplicate = Evidence.model_validate(first.model_dump(mode="json"))
    forward = merge_evidence([first, second], [duplicate])
    reverse = merge_evidence([duplicate], [second, first])
    assert forward == reverse
    assert [item.id for item in forward] == ["a-evidence", "z-evidence"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("interaction_type", "firmware_vulnerability_to_hardware"),
        ("direction", "hardware_to_software"),
    ],
)
def test_result_rejects_trigger_feature_type_or_direction_mismatch(field, value):
    interaction = _type2()
    result = InteractionVerificationPipeline().verify(
        interaction, InteractionVerificationInput.create(interaction)
    )
    values = result.model_dump(mode="json")
    values["trigger_features"][field] = value
    with pytest.raises(ValidationError):
        InteractionVerificationResult.model_validate(values)
