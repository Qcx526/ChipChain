"""Phase 9A-R1 verification-boundary hardening regressions."""

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
    EvidenceCatalog,
    InteractionReferenceBinding,
    InteractionReferenceRole,
    InteractionSourceKind,
    InteractionVerificationInput,
    InteractionVerificationPipeline,
    InteractionVerificationResult,
    InteractionVerificationStatus,
    VerificationStatus,
    VerificationSubjectKind,
    VerificationCapabilityStatus,
    RequiredFactCategory,
    build_interaction_requirements,
)
from chipchain.verification.adapter import LegacyCandidateEvidenceContext
from chipchain.verification.localization import InteractionLocationLocalizer
from chipchain.verification.models import VerificationRecord
from chipchain.verification.pipeline import _interaction_status


def _interaction(*, security_mechanism_ids=None):
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        source_layer=Layer.DRIVER,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["synthetic-hardware-target"],
        trigger_behavior_ids=["explicit-trigger"],
        security_mechanism_ids=security_mechanism_ids or [],
    )


def _evidence(*, evidence_type=EvidenceType.STATIC_ANALYSIS, verified=True, metadata=None):
    return Evidence(
        id="binding-evidence",
        type=evidence_type,
        source="owned-r1-fixture",
        confidence=1.0,
        verified=verified,
        metadata=metadata or {},
    )


def _evidence_binding_result(evidence):
    interaction = _interaction()
    binding = InteractionReferenceBinding(
        interaction_reference_id="explicit-trigger",
        reference_role=InteractionReferenceRole.TRIGGER_BEHAVIOR,
        source_kind=InteractionSourceKind.EVIDENCE,
        source_id="binding-evidence",
    )
    data = InteractionVerificationInput.create(interaction, bindings=[binding])
    return InteractionVerificationPipeline().verify(
        interaction,
        data,
        interaction_evidence=[evidence],
    )


def test_arbitrary_verified_evidence_cannot_verify_binding_or_inventory():
    result = _evidence_binding_result(_evidence())
    interaction = _interaction()
    baseline = InteractionVerificationPipeline().verify(
        interaction, InteractionVerificationInput.create(interaction)
    )
    assert result.binding_verifications[0].status is VerificationStatus.UNKNOWN
    assert result.binding_verifications[0].supporting_evidence_ids == []
    assert result.evidence_inventory.verified_non_llm_evidence_count == 0
    assert result.verification_status is InteractionVerificationStatus.INSUFFICIENT_EVIDENCE
    assert result.verification_score == baseline.verification_score


def test_matching_structured_evidence_verifies_binding():
    result = _evidence_binding_result(_evidence(metadata={
        "interaction_reference_id": "explicit-trigger",
        "reference_role": "trigger_behavior",
    }))
    record = result.binding_verifications[0]
    assert record.status is VerificationStatus.VERIFIED
    assert record.supporting_evidence_ids == ["binding-evidence"]
    assert result.evidence_inventory.verified_non_llm_evidence_ids == ["binding-evidence"]
    assert result.verification_status is InteractionVerificationStatus.PARTIALLY_VERIFIED


def test_llm_evidence_with_matching_subject_remains_unknown():
    result = _evidence_binding_result(_evidence(
        evidence_type=EvidenceType.LLM_SEMANTIC,
        metadata={"interaction_reference_id": "explicit-trigger", "reference_role": "trigger_behavior"},
    ))
    assert result.binding_verifications[0].status is VerificationStatus.UNKNOWN


@pytest.mark.parametrize("field,value", [
    ("interaction_reference_id", "different-trigger"),
    ("reference_role", "target_vulnerability"),
])
def test_explicit_evidence_subject_mismatch_is_rejected(field, value):
    metadata = {
        "interaction_reference_id": "explicit-trigger",
        "reference_role": "trigger_behavior",
    }
    metadata[field] = value
    result = _evidence_binding_result(_evidence(metadata=metadata))
    assert result.binding_verifications[0].status is VerificationStatus.REJECTED
    assert result.binding_verifications[0].supporting_evidence_ids == []
    assert result.verification_status is InteractionVerificationStatus.REJECTED


def test_behavior_node_existence_cannot_verify_trigger(
    reasoning_candidate,
    reasoning_behavior_repository,
    reasoning_behavior_evidence,
    synthetic_arm_knowledge_repository,
):
    interaction = _interaction()
    binding = InteractionReferenceBinding(
        interaction_reference_id="explicit-trigger",
        reference_role=InteractionReferenceRole.TRIGGER_BEHAVIOR,
        source_kind=InteractionSourceKind.BEHAVIOR_NODE,
        source_id=reasoning_candidate.behavior_path.node_ids[0],
    )
    data = InteractionVerificationInput.create(
        interaction, bindings=[binding], legacy_candidate_id=reasoning_candidate.id
    )
    result = InteractionVerificationPipeline().verify(
        interaction,
        data,
        reasoning_behavior_repository,
        synthetic_arm_knowledge_repository,
        InMemoryEvidenceResolver(reasoning_behavior_evidence),
        legacy_candidate=reasoning_candidate,
    )
    assert result.binding_verifications[0].status is VerificationStatus.UNKNOWN


def test_knowledge_node_existence_cannot_verify_semantic_fact(
    reasoning_candidate,
    reasoning_behavior_repository,
    reasoning_behavior_evidence,
    synthetic_arm_knowledge_repository,
):
    interaction = _interaction(security_mechanism_ids=["semantic-mechanism"])
    binding = InteractionReferenceBinding(
        interaction_reference_id="semantic-mechanism",
        reference_role=InteractionReferenceRole.SECURITY_MECHANISM,
        source_kind=InteractionSourceKind.KNOWLEDGE_NODE,
        source_id=reasoning_candidate.cwe_node_ids[0],
    )
    data = InteractionVerificationInput.create(
        interaction, bindings=[binding], legacy_candidate_id=reasoning_candidate.id
    )
    result = InteractionVerificationPipeline().verify(
        interaction,
        data,
        reasoning_behavior_repository,
        synthetic_arm_knowledge_repository,
        InMemoryEvidenceResolver(reasoning_behavior_evidence),
        legacy_candidate=reasoning_candidate,
    )
    assert result.binding_verifications[0].status is VerificationStatus.UNKNOWN


def test_partially_supported_result_model_rejects_verified_status():
    interaction = _interaction()
    result = InteractionVerificationPipeline().verify(
        interaction, InteractionVerificationInput.create(interaction)
    )
    values = result.model_dump(mode="json")
    values["verification_status"] = "verified"
    with pytest.raises(ValidationError):
        InteractionVerificationResult.model_validate(values)


def test_pipeline_status_caps_all_verified_facts_for_partial_capability():
    requirements = build_interaction_requirements(
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    )
    facts = {
        item: VerificationStatus.VERIFIED
        for item in requirements.required_facts
    }
    assert _interaction_status(
        requirements.required_facts,
        facts,
        VerificationCapabilityStatus.PARTIALLY_SUPPORTED,
    ) is InteractionVerificationStatus.PARTIALLY_VERIFIED
    facts[RequiredFactCategory.TRIGGER_BEHAVIOR_SUPPORT] = VerificationStatus.UNKNOWN
    facts[RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT] = VerificationStatus.UNKNOWN
    facts[RequiredFactCategory.TARGET_VULNERABILITY_SUPPORT] = VerificationStatus.UNKNOWN
    assert _interaction_status(
        requirements.required_facts,
        facts,
        VerificationCapabilityStatus.PARTIALLY_SUPPORTED,
    ) is InteractionVerificationStatus.INSUFFICIENT_EVIDENCE


def test_verification_record_requires_support_subset_and_verified_status():
    interaction = _interaction()
    with pytest.raises(ValidationError):
        VerificationRecord.create(
            interaction_id=interaction.id,
            architecture=Architecture.ARM,
            subject_kind=VerificationSubjectKind.INTERACTION_PARTICIPANT,
            subject_id="subject",
            status=VerificationStatus.UNKNOWN,
            verifier="fixture-verifier",
            evidence_ids=["e1"],
            supporting_evidence_ids=["e1"],
        )
    with pytest.raises(ValidationError):
        VerificationRecord.create(
            interaction_id=interaction.id,
            architecture=Architecture.ARM,
            subject_kind=VerificationSubjectKind.INTERACTION_PARTICIPANT,
            subject_id="subject",
            status=VerificationStatus.VERIFIED,
            verifier="fixture-verifier",
            evidence_ids=["e1"],
            supporting_evidence_ids=["other"],
        )


def test_localizer_uses_supporting_evidence_not_first_resolved(
    reasoning_candidate,
    reasoning_behavior_repository,
):
    interaction = _interaction()
    edge_id = reasoning_candidate.behavior_path.edge_ids[-1]
    edge = reasoning_behavior_repository.get_edge(edge_id)
    nodes = tuple(
        reasoning_behavior_repository.get_node(item)
        for item in reasoning_candidate.behavior_path.node_ids
    )
    context = LegacyCandidateEvidenceContext(
        candidate=reasoning_candidate,
        behavior_nodes=nodes,
        behavior_edges=(edge,),
        knowledge_nodes=(),
        knowledge_edges=(),
        evidence=(),
    )
    unusable = Evidence(
        id="e1-unusable", type=EvidenceType.STATIC_ANALYSIS,
        source="fixture", address="0x111", confidence=1.0, verified=False,
    )
    supporting = Evidence(
        id="e2-supporting", type=EvidenceType.STATIC_ANALYSIS,
        source="fixture", address="0x222", confidence=1.0, verified=True,
    )
    record = VerificationRecord.create(
        interaction_id=interaction.id,
        architecture=Architecture.ARM,
        subject_kind=VerificationSubjectKind.BEHAVIOR_EDGE,
        subject_id=edge.id,
        status=VerificationStatus.VERIFIED,
        verifier="fixture-mmio-verifier",
        evidence_ids=[unusable.id, supporting.id],
        supporting_evidence_ids=[supporting.id],
    )
    binding = InteractionReferenceBinding(
        interaction_reference_id="explicit-trigger",
        reference_role=InteractionReferenceRole.TRIGGER_BEHAVIOR,
        source_kind=InteractionSourceKind.BEHAVIOR_EDGE,
        source_id=edge.id,
    )
    findings = InteractionLocationLocalizer().localize(
        interaction, [binding], context, EvidenceCatalog([unusable, supporting]), [record]
    )
    assert findings[0].instruction_address.value == "0x222"
    assert findings[0].supporting_evidence_ids == ["e2-supporting"]
