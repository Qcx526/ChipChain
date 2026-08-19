"""Run the owned ARM fixture through deterministic offline multi-agent reasoning."""

from __future__ import annotations

from pathlib import Path

from chipchain.analysis import (
    AngrAnalyzer,
    MemoryMap,
    ProgramArtifact,
    ingest_analysis_result,
)
from chipchain.candidate import CrossGraphCandidateSearcher
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import (
    NetworkXKnowledgeGraphRepository,
    VulnerabilityKnowledgeBuilder,
)
from chipchain.models import Architecture, Layer, RelationType, VulnerabilitySample
from chipchain.multi_agent import (
    CriticAgent,
    EvidenceAnalystAgent,
    MockStructuredOutputProvider,
    MultiAgentCoordinator,
    SecurityReasoningAgent,
)
from chipchain.reasoning import (
    CandidateContextAssembler,
    CandidateRetrievalQueryBuilder,
    InMemoryEvidenceResolver,
    LocalLexicalKnowledgeRetriever,
    load_architecture_knowledge_documents,
)


def main() -> None:
    """Print all three bounded analyses and deterministic final status."""

    root = Path(__file__).resolve().parents[1]
    mmio_directory = root / "tests" / "fixtures" / "angr" / "arm_mmio"
    memory_map = MemoryMap.model_validate_json(
        (mmio_directory / "memory_map.json").read_text(encoding="utf-8")
    )
    artifact = ProgramArtifact(
        id="synthetic-arm-mmio",
        architecture=Architecture.ARM,
        artifact_type="elf",
        program_layer=Layer.DRIVER,
        path=str(mmio_directory / "arm_mmio.elf"),
        fixture_identifier="synthetic-arm-mmio-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )
    analysis = AngrAnalyzer(memory_map=memory_map).analyze(artifact)
    behavior = NetworkXGraphRepository(metadata={"fixture": True})
    ingest_analysis_result(analysis, behavior)
    sample = VulnerabilitySample.model_validate_json(
        (
            root
            / "tests"
            / "fixtures"
            / "knowledge"
            / "synthetic_arm_vulnerability.json"
        ).read_text(encoding="utf-8")
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
    candidate = next(
        item
        for item in candidates
        if behavior.get_edge(item.behavior_path.edge_ids[-1]).relation
        is RelationType.MMIO_WRITE
    )
    documents = load_architecture_knowledge_documents(
        root / "tests" / "fixtures" / "rag"
    )
    provider = MockStructuredOutputProvider()
    result = MultiAgentCoordinator(
        context_assembler=CandidateContextAssembler(),
        query_builder=CandidateRetrievalQueryBuilder(),
        retriever=LocalLexicalKnowledgeRetriever(documents),
        evidence_analyst=EvidenceAnalystAgent(provider),
        security_reasoner=SecurityReasoningAgent(provider),
        critic=CriticAgent(provider),
    ).reason(
        candidate,
        behavior,
        knowledge,
        InMemoryEvidenceResolver.from_analysis_result(analysis),
        top_k=3,
    )

    print("ChipChain Phase 8 ARM multi-agent demo")
    print(f"Candidate: {result.candidate_id}")
    print(f"Architecture: {result.architecture.value}")
    print(
        "Evidence Analyst: "
        f"{result.evidence_analysis.analysis_status.value}"
    )
    print(
        "Security Reasoner: "
        f"{result.security_reasoning.semantic_status.value}"
    )
    print(f"Semantic Hypotheses: {len(result.security_reasoning.hypotheses)}")
    print(f"Critic: {result.critic_review.review_status.value}")
    print(f"Final Status: {result.final_semantic_status.value}")
    print(
        "Execution Order: "
        + " -> ".join(record.role.value for record in result.execution_trace)
    )
    print(
        "Unresolved Triggers: "
        f"{len(result.unresolved_trigger_node_ids)}"
    )
    print(
        "Unresolved Preconditions: "
        f"{len(result.unresolved_precondition_node_ids)}"
    )
    print("This is not a verified attack chain.")


if __name__ == "__main__":
    main()
