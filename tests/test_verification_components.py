"""Entity, knowledge, architecture-independent scoring, feature, and root tests."""

from __future__ import annotations

from chipchain.candidate import EntityLink
from chipchain.knowledge import (
    KnowledgeEdge,
    KnowledgeNode,
    KnowledgeNodeKind,
    KnowledgeRelationType,
    address_match_key,
)
from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Evidence,
    EvidenceType,
    Layer,
    NodeKind,
    RelationType,
)
from chipchain.verification import (
    ARMArchitectureRuleVerifier,
    ConditionAssessment,
    ConditionKind,
    ConditionStatus,
    EntityLinkVerifier,
    EvidenceCatalog,
    KnowledgeRelationVerifier,
    RootCauseLocalizationStatus,
    RootCauseLocalizer,
    TriggerFeatureExtractor,
    VerificationRecord,
    VerificationScorer,
    VerificationScoreConfig,
    VerificationStatus,
    VerificationSubjectKind,
)


def _behavior_anchor(address="0x40000000", *, architecture=Architecture.ARM, metadata=None):
    return BehaviorNode(
        id="behavior-register",
        kind=NodeKind.REGISTER,
        name="REG",
        architecture=architecture,
        layer=Layer.HARDWARE,
        address=address,
        metadata=metadata or {},
    )


def _knowledge_anchor(address="0x40000000", *, architecture=Architecture.ARM, match_keys=None):
    return KnowledgeNode(
        id="knowledge-register",
        kind=KnowledgeNodeKind.HARDWARE_RESOURCE,
        label="REG",
        architecture=architecture,
        layer=Layer.HARDWARE,
        external_ids=["reg-local"],
        match_keys=(match_keys if match_keys is not None else [address_match_key(architecture, address)]),
        metadata={"address": address},
    )


def _link():
    return EntityLink.create(
        architecture=Architecture.ARM,
        behavior_node_id="behavior-register",
        knowledge_node_id="knowledge-register",
        behavior_node_kind=NodeKind.REGISTER,
        knowledge_node_kind=KnowledgeNodeKind.HARDWARE_RESOURCE,
        match_keys=[address_match_key(Architecture.ARM, "0x40000000")],
    )


def test_entity_link_recomputation_verifies_correct_address():
    result = EntityLinkVerifier().verify(_link(), _behavior_anchor(), _knowledge_anchor())
    assert result.status is VerificationStatus.VERIFIED


def test_entity_link_address_mismatch_is_rejected():
    result = EntityLinkVerifier().verify(_link(), _behavior_anchor(), _knowledge_anchor("0x40000001"))
    assert result.status is VerificationStatus.REJECTED


def test_entity_link_architecture_mismatch_is_rejected():
    knowledge = _knowledge_anchor(
        architecture=Architecture.RISC_V,
        match_keys=[address_match_key(Architecture.ARM, "0x40000000")],
    )
    result = EntityLinkVerifier().verify(_link(), _behavior_anchor(), knowledge)
    assert result.status is VerificationStatus.REJECTED


def test_entity_link_missing_recomputed_key_is_unknown():
    behavior = _behavior_anchor(address=None)
    knowledge = _knowledge_anchor(match_keys=[])
    result = EntityLinkVerifier().verify(_link(), behavior, knowledge)
    assert result.status is VerificationStatus.UNKNOWN


def test_arm_architecture_rules_reject_cross_architecture_behavior_context(
    reasoning_candidate,
    reasoning_behavior_repository,
    synthetic_arm_knowledge_repository,
):
    behavior_nodes = [
        reasoning_behavior_repository.get_node(item)
        for item in reasoning_candidate.behavior_path.node_ids
    ]
    data = behavior_nodes[0].model_dump(mode="json")
    data["architecture"] = Architecture.RISC_V.value
    behavior_nodes[0] = BehaviorNode.model_validate(data)
    behavior_edges = [
        reasoning_behavior_repository.get_edge(item)
        for item in reasoning_candidate.behavior_path.edge_ids
    ]
    knowledge_nodes = [
        synthetic_arm_knowledge_repository.get_node(
            reasoning_candidate.knowledge_anchor_node_id
        )
    ]
    records = ARMArchitectureRuleVerifier().verify(
        reasoning_candidate, behavior_nodes, behavior_edges, knowledge_nodes
    )
    record = next(item for item in records if item.subject_id == "behavior-context-is-arm")
    assert record.status is VerificationStatus.REJECTED


def _knowledge_relation(evidence_ids: list[str]):
    source = KnowledgeNode(id="vuln", kind=KnowledgeNodeKind.VULNERABILITY, label="fixture vuln", architecture=Architecture.ARM, layer=Layer.DRIVER)
    target = _knowledge_anchor()
    edge = KnowledgeEdge(
        id="targets",
        source_id=source.id,
        target_id=target.id,
        relation=KnowledgeRelationType.TARGETS_RESOURCE,
        architecture=Architecture.ARM,
        evidence_ids=evidence_ids,
        metadata={"derived_from_sample": "fixture-sample"},
    )
    return source, target, edge


def test_targets_resource_without_evidence_is_unknown():
    source, target, edge = _knowledge_relation([])
    result = KnowledgeRelationVerifier().verify(edge, source, target, EvidenceCatalog([]))
    assert result.status is VerificationStatus.UNKNOWN


def test_targets_resource_with_source_consistent_non_llm_evidence_verifies():
    evidence_id = "sample:fixture-sample:evidence:target"
    source, target, edge = _knowledge_relation([evidence_id])
    evidence = Evidence(id=evidence_id, type=EvidenceType.SOURCE_REFERENCE, source="fixture", confidence=1.0, verified=True)
    result = KnowledgeRelationVerifier().verify(edge, source, target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.VERIFIED


def test_knowledge_relation_with_only_llm_evidence_is_unknown():
    evidence_id = "sample:fixture-sample:evidence:llm"
    source, target, edge = _knowledge_relation([evidence_id])
    evidence = Evidence(
        id=evidence_id,
        type=EvidenceType.LLM_SEMANTIC,
        source="fixture-llm",
        confidence=1.0,
        verified=True,
    )
    result = KnowledgeRelationVerifier().verify(
        edge, source, target, EvidenceCatalog([evidence])
    )
    assert result.status is VerificationStatus.UNKNOWN


def test_trigger_features_have_exact_provenance_and_do_not_create_conditions():
    trigger = KnowledgeNode(
        id="trigger",
        kind=KnowledgeNodeKind.TRIGGER,
        label="trigger",
        architecture=Architecture.ARM,
        layer=Layer.DRIVER,
        metadata={"entrypoint": "handler", "input": "request", "event": "ioctl"},
    )
    precondition = KnowledgeNode(
        id="precondition",
        kind=KnowledgeNodeKind.PRECONDITION,
        label="precondition",
        architecture=Architecture.ARM,
        layer=Layer.DRIVER,
        metadata={"privilege": "user", "security_state": "normal", "configuration": "enabled"},
    )
    edge = BehaviorEdge(id="mmio", source_id="driver", target_id="behavior-register", relation=RelationType.MMIO_WRITE, architecture=Architecture.ARM, metadata={"memory_map_id": "map", "memory_map_region": "reg"})
    features = TriggerFeatureExtractor().extract(
        candidate_id="candidate",
        architecture=Architecture.ARM,
        behavior_nodes=[_behavior_anchor(metadata={"memory_map_id": "map", "memory_map_region": "reg"})],
        behavior_edges=[edge],
        knowledge_nodes=[trigger, precondition],
        trigger_assessments=[ConditionAssessment(condition_node_id="trigger", condition_kind=ConditionKind.TRIGGER, status=ConditionStatus.UNKNOWN)],
        precondition_assessments=[ConditionAssessment(condition_node_id="precondition", condition_kind=ConditionKind.PRECONDITION, status=ConditionStatus.UNKNOWN)],
    )
    assert features.entrypoint_candidates == ["handler"]
    assert features.hardware_addresses[0].value == "0x40000000"
    assert features.mmio_access_types == [RelationType.MMIO_WRITE]
    assert "condition:trigger" in features.unresolved_feature_ids
    assert any(item.feature_id == "trigger_input:request" and item.source_id == "trigger" for item in features.provenance)


def test_empty_knowledge_context_does_not_manufacture_conditions_or_features():
    features = TriggerFeatureExtractor().extract(
        candidate_id="candidate",
        architecture=Architecture.ARM,
        behavior_nodes=[],
        behavior_edges=[],
        knowledge_nodes=[],
        trigger_assessments=[],
        precondition_assessments=[],
    )
    assert features.trigger_inputs == []
    assert features.trigger_events == []
    assert features.required_privileges == []
    assert features.unresolved_feature_ids == []


def _record(subject: str, status: VerificationStatus) -> VerificationRecord:
    return VerificationRecord.create(
        architecture=Architecture.ARM,
        subject_kind=VerificationSubjectKind.BEHAVIOR_EDGE,
        subject_id=subject,
        status=status,
        verifier="fixture",
    )


def test_scoring_is_deterministic_order_independent_and_unknown_is_zero():
    config = VerificationScoreConfig(
        behavior_evidence=0.2,
        entity_link=0.2,
        knowledge_evidence=0.2,
        conditions=0.2,
        architecture_rules=0.2,
        metadata={"profile": "engineering_mvp_uncalibrated"},
    )
    scorer = VerificationScorer(config)
    kwargs = {
        "behavior": [_record("a", VerificationStatus.VERIFIED), _record("b", VerificationStatus.UNKNOWN)],
        "entity_link": VerificationRecord.create(architecture=Architecture.ARM, subject_kind=VerificationSubjectKind.ENTITY_LINK, subject_id="link", status=VerificationStatus.VERIFIED, verifier="fixture"),
        "knowledge": [_record("kg", VerificationStatus.UNKNOWN)],
        "triggers": [ConditionAssessment(condition_node_id="trigger", condition_kind=ConditionKind.TRIGGER, status=ConditionStatus.UNKNOWN)],
        "preconditions": [],
        "architecture": [_record("arch", VerificationStatus.VERIFIED)],
    }
    first = scorer.score(**kwargs)
    kwargs["behavior"] = list(reversed(kwargs["behavior"]))
    second = scorer.score(**kwargs)
    assert first == second
    assert first.score_components["behavior_evidence"] == 0.5
    assert first.score_components["knowledge_evidence"] == 0.0
    assert first.metadata["llm_weight"] == 0.0


def test_score_config_field_order_does_not_change_result():
    ordered = {
        "behavior_evidence": 0.2,
        "entity_link": 0.2,
        "knowledge_evidence": 0.2,
        "conditions": 0.2,
        "architecture_rules": 0.2,
        "metadata": {"profile": "engineering_mvp_uncalibrated"},
    }
    reversed_order = dict(reversed(list(ordered.items())))
    assert VerificationScoreConfig.model_validate(ordered) == VerificationScoreConfig.model_validate(reversed_order)


def _root_inputs(*, hint_function="driver", hint_instruction="str r0, [r1]"):
    function = BehaviorNode(id="driver", kind=NodeKind.FUNCTION, name="driver", architecture=Architecture.ARM, layer=Layer.DRIVER, address="0x1000")
    hardware = _behavior_anchor()
    edge = BehaviorEdge(id="mmio", source_id=function.id, target_id=hardware.id, relation=RelationType.MMIO_WRITE, architecture=Architecture.ARM, evidence_ids=["sink"], metadata={"instruction_address": "0x1008"})
    evidence = Evidence(id="sink", type=EvidenceType.STATIC_ANALYSIS, source="fixture", address="0x1008", instruction="str r0, [r1]", confidence=1.0, verified=True)
    record = VerificationRecord.create(architecture=Architecture.ARM, subject_kind=VerificationSubjectKind.BEHAVIOR_EDGE, subject_id="mmio", status=VerificationStatus.VERIFIED, verifier="fixture", evidence_ids=["sink"])
    hint_evidence = Evidence(id="hint", type=EvidenceType.SOURCE_REFERENCE, source="fixture", address="0x40000000", confidence=1.0, verified=True)
    hint = KnowledgeNode(id="root", kind=KnowledgeNodeKind.ROOT_CAUSE, label="root", architecture=Architecture.ARM, layer=Layer.DRIVER, evidence_ids=["hint"], metadata={"function": hint_function, "binary_address": "0x1000", "instruction": hint_instruction, "mmio_address": "0x40000000", "hardware_resource": "reg-local"})
    return function, hardware, edge, evidence, record, hint, hint_evidence


def test_root_cause_localization_separates_program_and_hardware_addresses():
    function, hardware, edge, evidence, record, hint, hint_evidence = _root_inputs()
    result = RootCauseLocalizer().localize(candidate_id="candidate", architecture=Architecture.ARM, behavior_nodes=[function, hardware], behavior_edges=[edge], behavior_records=[record], knowledge_root_causes=[hint], knowledge_anchor=_knowledge_anchor(), catalog=EvidenceCatalog([evidence, hint_evidence]))
    assert result.localization_status is RootCauseLocalizationStatus.LOCALIZED_CANDIDATE
    assert result.candidate_binary_addresses[0].value == "0x1000"
    assert result.candidate_instruction_addresses[0].value == "0x1008"
    assert result.hardware_address.value == "0x40000000"
    assert result.source_file is None and result.source_line is None
    assert "knowledge_evidence_address_is_hardware_namespace" in result.reason_codes


def test_root_cause_hint_conflict_is_recorded_and_output_is_deterministic():
    function, hardware, edge, evidence, record, hint, hint_evidence = _root_inputs(hint_function="other", hint_instruction="other instruction")
    kwargs = dict(candidate_id="candidate", architecture=Architecture.ARM, behavior_nodes=[function, hardware], behavior_edges=[edge], behavior_records=[record], knowledge_root_causes=[hint], knowledge_anchor=_knowledge_anchor(), catalog=EvidenceCatalog([evidence, hint_evidence]))
    first = RootCauseLocalizer().localize(**kwargs)
    second = RootCauseLocalizer().localize(**kwargs)
    assert first == second
    assert first.localization_status is RootCauseLocalizationStatus.CONTRADICTORY_CONTEXT
    assert any("function_mismatch" in item for item in first.contradictions)
    assert all("llm" not in item.lower() for item in first.supporting_behavior_evidence_ids)


def test_llm_evidence_never_becomes_root_cause_support():
    function, hardware, edge, evidence, record, hint, _ = _root_inputs()
    hint_data = hint.model_dump(mode="json")
    hint_data["evidence_ids"] = ["llm-hint"]
    hint = KnowledgeNode.model_validate(hint_data)
    llm_hint = Evidence(
        id="llm-hint",
        type=EvidenceType.LLM_SEMANTIC,
        source="fixture-llm",
        confidence=1.0,
        verified=True,
    )
    result = RootCauseLocalizer().localize(
        candidate_id="candidate",
        architecture=Architecture.ARM,
        behavior_nodes=[function, hardware],
        behavior_edges=[edge],
        behavior_records=[record],
        knowledge_root_causes=[hint],
        knowledge_anchor=_knowledge_anchor(),
        catalog=EvidenceCatalog([evidence, llm_hint]),
    )
    assert result.supporting_knowledge_evidence_ids == []
