"""Run the owned ARM pipeline through local RAG and deterministic Mock reasoning."""

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
from chipchain.reasoning import (
    CandidateContextAssembler,
    CandidatePromptBuilder,
    CandidateReasoner,
    CandidateRetrievalQueryBuilder,
    InMemoryEvidenceResolver,
    LocalLexicalKnowledgeRetriever,
    MockLLMProvider,
    load_architecture_knowledge_documents,
)


def main() -> None:
    """Print a bounded semantic interpretation without verification claims."""

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
    result = CandidateReasoner(
        context_assembler=CandidateContextAssembler(),
        query_builder=CandidateRetrievalQueryBuilder(),
        retriever=LocalLexicalKnowledgeRetriever(documents),
        prompt_builder=CandidatePromptBuilder(),
        provider=MockLLMProvider(),
    ).reason(
        candidate,
        behavior,
        knowledge,
        InMemoryEvidenceResolver.from_analysis_result(analysis),
        top_k=3,
    )

    print("ChipChain Phase 7 ARM RAG reasoning demo")
    print(f"Candidate: {candidate.id}")
    print(f"Architecture: {candidate.architecture.value}")
    print("Retrieved:")
    for chunk in result.retrieval.chunks:
        print(chunk.document_id)
    print("Excluded by architecture:")
    for document_id in result.retrieval.excluded_document_ids:
        print(document_id)
    print(f"Semantic Status: {result.assessment.semantic_status.value}")
    print(
        f"Unresolved Triggers: "
        f"{len(result.assessment.unresolved_trigger_node_ids)}"
    )
    print(
        f"Unresolved Preconditions: "
        f"{len(result.assessment.unresolved_precondition_node_ids)}"
    )
    print("Supporting Behavior Evidence:")
    for evidence_id in result.assessment.supporting_observation_ids:
        print(evidence_id)
    print("Supporting Knowledge Chunks:")
    for chunk_id in result.assessment.supporting_knowledge_chunk_ids:
        print(chunk_id)
    print(f"Conclusion: {result.assessment.summary}")
    print("This is not a verified attack chain.")


if __name__ == "__main__":
    main()
