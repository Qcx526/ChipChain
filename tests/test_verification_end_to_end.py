"""Owned ARM ELF Phase 4B through deterministic Phase 9A verification."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("angr")
pytestmark = pytest.mark.angr

from chipchain.analysis import AngrAnalyzer, MemoryMap, ProgramArtifact, ingest_analysis_result
from chipchain.candidate import CrossGraphCandidateSearcher
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import (
    KnowledgeRelationType,
    NetworkXKnowledgeGraphRepository,
    VulnerabilityKnowledgeBuilder,
)
from chipchain.models import Architecture, Layer, RelationType, VulnerabilitySample
from chipchain.multi_agent import (
    CriticAgent,
    EvidenceAnalystAgent,
    MockStructuredOutputProvider,
    MultiAgentCoordinator,
    MultiAgentReasoningResult,
    SecurityReasoningAgent,
)
from chipchain.reasoning import (
    CandidateContextAssembler,
    CandidateRetrievalQueryBuilder,
    InMemoryEvidenceResolver,
    LocalLexicalKnowledgeRetriever,
    load_architecture_knowledge_documents,
)
from chipchain.verification import (
    CandidateVerificationPipeline,
    CandidateVerificationResult,
    CandidateVerificationStatus,
    ConditionStatus,
    RootCauseLocalizationStatus,
    VerificationStatus,
)

ROOT = Path(__file__).resolve().parents[1]


def _build_phase9a_fixture():
    mmio_dir = ROOT / "tests" / "fixtures" / "angr" / "arm_mmio"
    memory_map = MemoryMap.model_validate_json(
        (mmio_dir / "memory_map.json").read_text(encoding="utf-8")
    )
    analysis = AngrAnalyzer(memory_map=memory_map).analyze(
        ProgramArtifact(
            id="synthetic-arm-mmio",
            architecture=Architecture.ARM,
            artifact_type="elf",
            program_layer=Layer.DRIVER,
            path=str(mmio_dir / "arm_mmio.elf"),
            fixture_identifier="synthetic-arm-mmio-elf",
            metadata={"fixture": True, "synthetic": True, "owned": True},
        )
    )
    behavior = NetworkXGraphRepository(metadata={"fixture": True})
    ingest_analysis_result(analysis, behavior)
    sample = VulnerabilitySample.model_validate_json(
        (ROOT / "tests" / "fixtures" / "knowledge" / "synthetic_arm_vulnerability.json").read_text(encoding="utf-8")
    )
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(
        VulnerabilityKnowledgeBuilder().build(sample)
    )
    candidates = CrossGraphCandidateSearcher().search(
        behavior,
        knowledge,
        architecture=Architecture.ARM,
        start_node_id="synthetic-arm-mmio:function:00010030",
        max_hops=2,
    )
    resolver = InMemoryEvidenceResolver.from_analysis_result(analysis)
    candidate = next(
        item
        for item in candidates
        if behavior.get_edge(item.behavior_path.edge_ids[-1]).relation is RelationType.MMIO_WRITE
        and resolver.get(behavior.get_edge(item.behavior_path.edge_ids[-1]).evidence_ids[0]).address == "0x10008"
    )
    return analysis, behavior, knowledge, candidate, resolver


def _multi_agent_result(candidate, behavior, knowledge, resolver):
    provider = MockStructuredOutputProvider()
    return MultiAgentCoordinator(
        context_assembler=CandidateContextAssembler(),
        query_builder=CandidateRetrievalQueryBuilder(),
        retriever=LocalLexicalKnowledgeRetriever(
            load_architecture_knowledge_documents(ROOT / "tests" / "fixtures" / "rag")
        ),
        evidence_analyst=EvidenceAnalystAgent(provider),
        security_reasoner=SecurityReasoningAgent(provider),
        critic=CriticAgent(provider),
    ).reason(candidate, behavior, knowledge, resolver, top_k=3)


def test_phase4b_to_phase9a_expected_ground_truth_and_read_only_sources():
    analysis, behavior, knowledge, candidate, resolver = _build_phase9a_fixture()
    source_before = (
        candidate.model_dump_json(),
        [item.model_dump_json() for item in behavior.list_nodes()],
        [item.model_dump_json() for item in behavior.list_edges()],
        [item.model_dump_json() for item in knowledge.list_nodes()],
        [item.model_dump_json() for item in knowledge.list_edges()],
        [item.model_dump_json() for item in knowledge.list_evidence()],
        [item.model_dump_json() for item in analysis.evidence],
    )
    result = CandidateVerificationPipeline().verify(
        candidate, behavior, knowledge, resolver
    )
    restored = CandidateVerificationResult.model_validate_json(result.model_dump_json())
    assert restored == result
    assert [item.status for item in result.behavior_edge_verifications] == [
        VerificationStatus.VERIFIED,
        VerificationStatus.VERIFIED,
    ]
    assert result.entity_link_verification.status is VerificationStatus.VERIFIED
    target_record = next(
        record
        for record in result.knowledge_edge_verifications
        if record.metadata["relation"] == KnowledgeRelationType.TARGETS_RESOURCE.value
    )
    assert target_record.status is VerificationStatus.UNKNOWN
    assert all(item.status is VerificationStatus.VERIFIED for item in result.architecture_rule_verifications)
    assert [item.status for item in result.trigger_assessments] == [ConditionStatus.UNKNOWN]
    assert [item.status for item in result.precondition_assessments] == [ConditionStatus.UNKNOWN]
    assert result.verification_status is CandidateVerificationStatus.PARTIALLY_VERIFIED
    assert result.verification_score == pytest.approx(0.672727272727)
    assert result.root_cause_localization.function_name == "driver_like_function"
    assert result.root_cause_localization.candidate_instruction_addresses[0].value == "0x10008"
    assert result.root_cause_localization.hardware_address.value == "0x40000000"
    assert result.root_cause_localization.source_line is None
    assert result.root_cause_localization.localization_status is RootCauseLocalizationStatus.CONTRADICTORY_CONTEXT
    assert result.metadata["verified_attack_chain_created"] is False
    source_after = (
        candidate.model_dump_json(),
        [item.model_dump_json() for item in behavior.list_nodes()],
        [item.model_dump_json() for item in behavior.list_edges()],
        [item.model_dump_json() for item in knowledge.list_nodes()],
        [item.model_dump_json() for item in knowledge.list_edges()],
        [item.model_dump_json() for item in knowledge.list_evidence()],
        [item.model_dump_json() for item in analysis.evidence],
    )
    assert source_after == source_before


def test_two_different_legal_multi_agent_results_do_not_change_objective_result():
    _, behavior, knowledge, candidate, resolver = _build_phase9a_fixture()
    first_advisory = _multi_agent_result(candidate, behavior, knowledge, resolver)
    data = first_advisory.model_dump(mode="json")
    data["evidence_analysis"]["recommended_evidence_collection_steps"] = ["collect-authorized-fixture-trace"]
    data["security_reasoning"]["recommended_verification_steps"] = ["check-fixture-condition-contract"]
    data["critic_review"]["required_revisions"] = ["retain-all-unresolved-fixture-conditions"]
    second_advisory = MultiAgentReasoningResult.model_validate(data)
    pipeline = CandidateVerificationPipeline()
    first = pipeline.verify(candidate, behavior, knowledge, resolver, multi_agent_result=first_advisory)
    second = pipeline.verify(candidate, behavior, knowledge, resolver, multi_agent_result=second_advisory)
    assert first.advisory_verification_steps != second.advisory_verification_steps
    assert first.verification_status == second.verification_status
    assert first.verification_score == second.verification_score
    assert first.score_components == second.score_components
    assert first.trigger_assessments == second.trigger_assessments
    assert first.precondition_assessments == second.precondition_assessments
    assert first.root_cause_localization == second.root_cause_localization

