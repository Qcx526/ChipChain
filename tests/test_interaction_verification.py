"""Phase 9A-R interaction identity, contracts, verifiers, scoring, and boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.models import (Architecture, BehaviorEdge, BehaviorNode, CrossLayerInteraction,
    CrossLayerInteractionType, Evidence, EvidenceType, Layer, NodeKind, RelationType)
from chipchain.multi_agent import (CriticAgent, EvidenceAnalystAgent, MockStructuredOutputProvider,
    MultiAgentCoordinator, MultiAgentReasoningResult, SecurityReasoningAgent)
from chipchain.reasoning import (CandidateContextAssembler, CandidateRetrievalQueryBuilder,
    InMemoryEvidenceResolver, LocalLexicalKnowledgeRetriever)
from chipchain.verification import (BehaviorEdgeVerifier, ConditionStatus, EvidenceCatalog,
    ConditionKind, EntityLinkVerifier, InteractionConditionBinding,
    InteractionReferenceBinding, InteractionReferenceRole, InteractionSourceKind,
    InteractionVerificationInput, InteractionVerificationPipeline, InteractionVerificationStatus,
    RequiredFactCategory, VerificationCapabilityStatus, VerificationConfigurationError,
    VerificationInputError, VerificationScorer, VerificationStatus,
    build_interaction_requirements, load_verification_score_config)
from chipchain.verification.knowledge import VulnerabilityParticipantVerifier

ROOT = Path(__file__).resolve().parents[1]


def _type2(**changes) -> CrossLayerInteraction:
    values = dict(architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        source_layer=Layer.DRIVER, target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["synthetic-hw-vuln"], trigger_behavior_ids=["mmio-trigger"],
        hardware_resource_ids=["mmio-register"], evidence_ids=[], referenced_architectures=[],
        metadata={"fixture": True})
    values.update(changes)
    return CrossLayerInteraction.create(**values)


def _type1() -> CrossLayerInteraction:
    return CrossLayerInteraction.create(architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
        source_layer=Layer.FIRMWARE, target_layer=Layer.HARDWARE,
        initiating_vulnerability_ids=["fw-vuln"], target_vulnerability_ids=["hw-vuln"],
        trigger_behavior_ids=["trigger"])


def _type3() -> CrossLayerInteraction:
    return CrossLayerInteraction.create(architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE,
        source_layer=Layer.HARDWARE, target_layer=Layer.FIRMWARE,
        initiating_vulnerability_ids=["hw-vuln"], fault_state_ids=["fault-state"],
        propagation_behavior_ids=["propagation"], affected_execution_ids=["firmware-branch"])


@pytest.mark.parametrize("field,value", [
    ("evidence_ids", []), ("evidence_ids", ["e1", "e2"]),
    ("referenced_architectures", []), ("referenced_architectures", [Architecture.ARM]),
    ("metadata", {"changed": True}),
])
def test_interaction_identity_excludes_provenance(field, value):
    baseline = _type2()
    assert _type2(**{field: value}).id == baseline.id


@pytest.mark.parametrize("field,value", [
    ("trigger_behavior_ids", ["other-trigger"]),
    ("target_vulnerability_ids", ["other-vulnerability"]),
    ("fault_state_ids", ["new-fault-state"]),
])
def test_interaction_identity_changes_with_semantic_participants(field, value):
    baseline = _type2()
    assert _type2(**{field: value}).id != baseline.id


@pytest.mark.parametrize("kind,capability", [
    (CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE, VerificationCapabilityStatus.PARTIALLY_SUPPORTED),
    (CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE, VerificationCapabilityStatus.PARTIALLY_SUPPORTED),
    (CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE, VerificationCapabilityStatus.NOT_IMPLEMENTED),
])
def test_type_requirements_expose_honest_capability(kind, capability):
    assert build_interaction_requirements(kind).capability_status is capability


def test_type2_requirements_do_not_penalize_missing_firmware_vulnerability():
    requirements = build_interaction_requirements(CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE)
    assert RequiredFactCategory.INITIATING_VULNERABILITY_SUPPORT not in requirements.required_facts


def test_binding_must_reference_the_matching_interaction_role():
    interaction = _type2()
    binding = InteractionReferenceBinding(interaction_reference_id="not-the-trigger",
        reference_role=InteractionReferenceRole.TRIGGER_BEHAVIOR,
        source_kind=InteractionSourceKind.BEHAVIOR_EDGE, source_id="edge")
    with pytest.raises(VerificationInputError):
        InteractionVerificationInput.create(interaction, bindings=[binding])


@pytest.mark.parametrize("role,kind", [
    (InteractionReferenceRole.TARGET_VULNERABILITY, InteractionSourceKind.BEHAVIOR_EDGE),
    (InteractionReferenceRole.AFFECTED_EXECUTION, InteractionSourceKind.KNOWLEDGE_EDGE),
    (InteractionReferenceRole.INITIATING_VULNERABILITY, InteractionSourceKind.ENTITY_LINK),
])
def test_binding_rejects_disallowed_source_kind(role, kind):
    with pytest.raises(ValidationError):
        InteractionReferenceBinding(interaction_reference_id="ref", reference_role=role,
            source_kind=kind, source_id="source")


def _behavior_contract(relation=RelationType.MMIO_WRITE):
    source = BehaviorNode(id="function", kind=NodeKind.DRIVER_FUNCTION, name="driver",
        architecture=Architecture.ARM, layer=Layer.DRIVER, address="0x10000")
    target = BehaviorNode(id="register", kind=NodeKind.REGISTER, name="REG",
        architecture=Architecture.ARM, layer=Layer.HARDWARE, address="0x40000000",
        metadata={"memory_map_id": "map", "memory_map_region": "reg"})
    edge = BehaviorEdge(id="mmio", source_id=source.id, target_id=target.id, relation=relation,
        architecture=Architecture.ARM, evidence_ids=["static"],
        metadata={"observation": relation.value, "resolved_target_address": "0x40000000",
                  "memory_map_id": "map", "memory_map_region": "reg", "instruction_address": "0x10008"})
    evidence = Evidence(id="static", type=EvidenceType.STATIC_ANALYSIS, source="fixture",
        address="0x10008", confidence=1.0, verified=True,
        metadata={"observation": relation.value, "resolved_target_address": "0x40000000",
                  "memory_map_id": "map", "memory_map_region": "reg", "resolved": True})
    return source, target, edge, evidence


def test_verified_mmio_requires_matching_static_contract():
    source, target, edge, evidence = _behavior_contract()
    result = BehaviorEdgeVerifier().verify(_type2().id, edge, source, target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.VERIFIED


def _calls_contract():
    source = BehaviorNode(id="caller", kind=NodeKind.FUNCTION, name="caller",
        architecture=Architecture.ARM, layer=Layer.FIRMWARE, address="0x1000")
    target = BehaviorNode(id="callee", kind=NodeKind.DRIVER_FUNCTION, name="callee",
        architecture=Architecture.ARM, layer=Layer.DRIVER, address="0x2000")
    edge = BehaviorEdge(id="calls", source_id="caller", target_id="callee",
        relation=RelationType.CALLS, architecture=Architecture.ARM, evidence_ids=["call-evidence"],
        metadata={"observation": "call_xref"})
    evidence = Evidence(id="call-evidence", type=EvidenceType.STATIC_ANALYSIS,
        source="fixture", confidence=1.0, verified=True,
        metadata={"observation": "call_xref", "resolved": True,
                  "caller_address": "0x1000", "callee_address": "0x2000"})
    return source, target, edge, evidence


def test_calls_static_contract_is_verified():
    source, target, edge, evidence = _calls_contract()
    assert BehaviorEdgeVerifier().verify(_type1().id, edge, source, target,
        EvidenceCatalog([evidence])).status is VerificationStatus.VERIFIED


@pytest.mark.parametrize("field,value", [
    ("caller_address", "0x1004"), ("callee_address", "0x2004"),
    ("resolved", False), ("observation", "other"),
])
def test_calls_tampering_is_rejected(field, value):
    source, target, edge, evidence = _calls_contract()
    evidence = evidence.model_copy(update={"metadata": {**evidence.metadata, field: value}})
    assert BehaviorEdgeVerifier().verify(_type1().id, edge, source, target,
        EvidenceCatalog([evidence])).status is VerificationStatus.REJECTED


@pytest.mark.parametrize("field,value", [
    ("resolved_target_address", "0x40000004"),
    ("memory_map_id", "other-map"),
    ("memory_map_region", "other-region"),
    ("observation", "mmio_read"),
])
def test_mmio_edge_contract_conflicts_are_rejected(field, value):
    source, target, edge, evidence = _behavior_contract()
    edge = edge.model_copy(update={"metadata": {**edge.metadata, field: value}})
    result = BehaviorEdgeVerifier().verify(_type2().id, edge, source, target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.REJECTED


@pytest.mark.parametrize("evidence", [None, "unverified", "llm"])
def test_missing_unverified_or_llm_only_evidence_is_unknown(evidence):
    source, target, edge, item = _behavior_contract()
    if evidence is None: catalog = EvidenceCatalog([])
    elif evidence == "unverified": catalog = EvidenceCatalog([item.model_copy(update={"verified": False})])
    else: catalog = EvidenceCatalog([item.model_copy(update={"type": EvidenceType.LLM_SEMANTIC})])
    assert BehaviorEdgeVerifier().verify(_type2().id, edge, source, target, catalog).status is VerificationStatus.UNKNOWN


def test_type3_has_semantic_features_but_no_fake_status_or_score():
    interaction = _type3()
    data = InteractionVerificationInput.create(interaction)
    result = InteractionVerificationPipeline().verify(interaction, data)
    assert result.capability_status is VerificationCapabilityStatus.NOT_IMPLEMENTED
    assert result.verification_status is None
    assert result.verification_score is None
    assert result.score_components == {}
    assert result.behavior_edge_verifications == []
    assert result.entity_link_verifications == []
    assert result.trigger_features.fault_state_ids == ["fault-state"]
    assert result.trigger_features.affected_execution_ids == ["firmware-branch"]
    assert result.trigger_features.metadata["semantic_contract_only"] is True


def test_type3_rejects_legacy_candidate_identity_without_reversing_it():
    interaction = _type3()
    data = InteractionVerificationInput.create(interaction, legacy_candidate_id="legacy")
    with pytest.raises(VerificationInputError):
        InteractionVerificationPipeline().verify(interaction, data)


def test_unresolved_explicit_condition_remains_unknown():
    interaction = _type2()
    condition = InteractionConditionBinding(condition_node_id="missing-condition",
        condition_kind=ConditionKind.TRIGGER, required=True)
    data = InteractionVerificationInput.create(interaction, condition_bindings=[condition])
    result = InteractionVerificationPipeline().verify(interaction, data)
    assert result.condition_assessments[0].status is ConditionStatus.UNKNOWN


def test_exact_entity_link_is_recomputed(
    reasoning_candidate, reasoning_behavior_repository, synthetic_arm_knowledge_repository
):
    link = reasoning_candidate.entity_link
    result = EntityLinkVerifier().verify(_type2().id, link,
        reasoning_behavior_repository.get_node(link.behavior_node_id),
        synthetic_arm_knowledge_repository.get_node(link.knowledge_node_id))
    assert result.status is VerificationStatus.VERIFIED


def test_target_vulnerability_binding_rejects_software_layer(
    reasoning_candidate, synthetic_arm_knowledge_repository
):
    interaction = _type2()
    node = synthetic_arm_knowledge_repository.get_node(reasoning_candidate.knowledge_vulnerability_id)
    binding = InteractionReferenceBinding(interaction_reference_id="synthetic-hw-vuln",
        reference_role=InteractionReferenceRole.TARGET_VULNERABILITY,
        source_kind=InteractionSourceKind.KNOWLEDGE_NODE, source_id=node.id)
    result = VulnerabilityParticipantVerifier().verify(interaction.id,
        interaction.interaction_type, interaction.architecture, binding, node, EvidenceCatalog([]))
    assert result.status is VerificationStatus.REJECTED


def test_contract_only_type1_does_not_infer_legacy_kg_vulnerability():
    interaction = _type1()
    result = InteractionVerificationPipeline().verify(interaction, InteractionVerificationInput.create(interaction))
    assert result.verification_status is InteractionVerificationStatus.PARTIALLY_VERIFIED
    assert not result.binding_verifications
    assert result.verification_score < 1.0


def test_empty_required_evidence_never_scores_one():
    config = load_verification_score_config(ROOT / "configs" / "verification_scoring_mvp.json")
    result = VerificationScorer(config).score(
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE, {})
    assert result.verification_score == 0.0
    assert all(value == 0.0 for value in result.score_components.values())


def test_score_config_order_is_irrelevant(tmp_path):
    source = json.loads((ROOT / "configs" / "verification_scoring_mvp.json").read_text())
    path = tmp_path / "reordered.json"
    path.write_text(json.dumps(source, sort_keys=True), encoding="utf-8")
    first = load_verification_score_config(ROOT / "configs" / "verification_scoring_mvp.json")
    second = load_verification_score_config(path)
    statuses = {name: [VerificationStatus.VERIFIED] for name in first.profiles[CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE].weights}
    assert VerificationScorer(first).score(CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE, statuses) == \
           VerificationScorer(second).score(CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE, statuses)


def test_invalid_score_weight_sum_is_rejected(tmp_path):
    source = json.loads((ROOT / "configs" / "verification_scoring_mvp.json").read_text())
    source["profiles"]["firmware_behavior_to_hardware"]["weights"]["conditions"] = 0.2
    path = tmp_path / "invalid.json"; path.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(VerificationConfigurationError): load_verification_score_config(path)


def test_address_namespaces_are_distinct_models():
    from chipchain.verification import HardwareAddress, ProgramAddress
    assert ProgramAddress(value="0X0010").value == "0x10"
    assert HardwareAddress(value="0X0010").value == "0x10"
    assert type(ProgramAddress(value="0x10")) is not type(HardwareAddress(value="0x10"))


def test_multi_agent_advisory_changes_do_not_change_objective_result(
    reasoning_candidate, reasoning_behavior_repository, reasoning_behavior_evidence,
    synthetic_arm_knowledge_repository, rag_fixture_documents
):
    provider = MockStructuredOutputProvider()
    agent_result = MultiAgentCoordinator(context_assembler=CandidateContextAssembler(),
        query_builder=CandidateRetrievalQueryBuilder(),
        retriever=LocalLexicalKnowledgeRetriever(rag_fixture_documents),
        evidence_analyst=EvidenceAnalystAgent(provider),
        security_reasoner=SecurityReasoningAgent(provider), critic=CriticAgent(provider)).reason(
            reasoning_candidate, reasoning_behavior_repository,
            synthetic_arm_knowledge_repository,
            InMemoryEvidenceResolver(reasoning_behavior_evidence), top_k=3)
    altered_analysis = agent_result.evidence_analysis.model_copy(update={
        "recommended_evidence_collection_steps": ["Different advisory step."]})
    altered = MultiAgentReasoningResult.model_validate(agent_result.model_copy(
        update={"evidence_analysis": altered_analysis}).model_dump(mode="json"))
    interaction = _type2(trigger_behavior_ids=["bound-trigger"],
        hardware_resource_ids=["bound-resource"])
    edge_id = reasoning_candidate.behavior_path.edge_ids[-1]
    bindings = [InteractionReferenceBinding(interaction_reference_id="bound-trigger",
        reference_role=InteractionReferenceRole.TRIGGER_BEHAVIOR,
        source_kind=InteractionSourceKind.BEHAVIOR_EDGE, source_id=edge_id),
        InteractionReferenceBinding(interaction_reference_id="bound-resource",
        reference_role=InteractionReferenceRole.HARDWARE_RESOURCE,
        source_kind=InteractionSourceKind.ENTITY_LINK,
        source_id=reasoning_candidate.entity_link.id)]
    data = InteractionVerificationInput.create(interaction, bindings=bindings,
        legacy_candidate_id=reasoning_candidate.id)
    before_candidate = reasoning_candidate.model_dump(mode="json")
    pipeline = InteractionVerificationPipeline()
    common = (interaction, data, reasoning_behavior_repository,
        synthetic_arm_knowledge_repository, InMemoryEvidenceResolver(reasoning_behavior_evidence))
    first = pipeline.verify(*common, legacy_candidate=reasoning_candidate,
        multi_agent_result=agent_result)
    second = pipeline.verify(*common, legacy_candidate=reasoning_candidate,
        multi_agent_result=altered)
    first_data = first.model_dump(mode="json"); second_data = second.model_dump(mode="json")
    first_data.pop("advisory_verification_steps"); second_data.pop("advisory_verification_steps")
    assert first_data == second_data
    assert first.advisory_verification_steps != second.advisory_verification_steps
    assert reasoning_candidate.model_dump(mode="json") == before_candidate
