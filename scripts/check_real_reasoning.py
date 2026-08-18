"""Manual real-provider validation of the owned ARM fixture reasoning pipeline."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

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
    OpenAICompatibleLLMProvider,
    load_architecture_knowledge_documents,
)


def main() -> int:
    """Run real Qwen output through JSON, Pydantic, and reasoner validation."""

    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env", override=False)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

    try:
        provider = OpenAICompatibleLLMProvider.from_env()
        mmio_directory = project_root / "tests" / "fixtures" / "angr" / "arm_mmio"
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
                project_root
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
            project_root / "tests" / "fixtures" / "rag"
        )
        result = CandidateReasoner(
            context_assembler=CandidateContextAssembler(),
            query_builder=CandidateRetrievalQueryBuilder(),
            retriever=LocalLexicalKnowledgeRetriever(documents),
            prompt_builder=CandidatePromptBuilder(),
            provider=provider,
        ).reason(
            candidate,
            behavior,
            knowledge,
            InMemoryEvidenceResolver.from_analysis_result(analysis),
            top_k=3,
        )
    except Exception as exc:
        print("Real reasoning: FAILED")
        print(f"Error type: {type(exc).__name__}")
        print(f"Error stage: {getattr(exc, 'stage', 'pipeline')}")
        print(f"Error detail: {exc}")
        status_code = getattr(exc, "status_code", None)
        print(f"HTTP status: {status_code if status_code is not None else 'unavailable'}")
        print("This is not a verified attack chain.")
        return 1

    assessment = result.assessment
    print(f"Candidate ID: {candidate.id}")
    print(f"Architecture: {candidate.architecture.value}")
    print("Retrieved Chunk IDs:")
    for chunk in result.retrieval.chunks:
        print(f"- {chunk.chunk_id}")
    print(f"Semantic Status: {assessment.semantic_status.value}")
    print(f"Unresolved Trigger Count: {len(assessment.unresolved_trigger_node_ids)}")
    print(
        "Unresolved Precondition Count: "
        f"{len(assessment.unresolved_precondition_node_ids)}"
    )
    print(f"Missing Information Count: {len(assessment.missing_information)}")
    print("Recommended Verification Steps:")
    for step in assessment.recommended_verification_steps:
        print(f"- {step}")
    print("This is not a verified attack chain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
