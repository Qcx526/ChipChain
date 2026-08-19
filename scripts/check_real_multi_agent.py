"""Manual real-Qwen validation of the fixed three-agent ARM fixture pipeline."""

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
from chipchain.multi_agent import (
    AgentExecutionError,
    CriticAgent,
    EvidenceAnalystAgent,
    MultiAgentCoordinator,
    SecurityReasoningAgent,
)
from chipchain.reasoning import (
    CandidateContextAssembler,
    CandidateRetrievalQueryBuilder,
    InMemoryEvidenceResolver,
    LocalLexicalKnowledgeRetriever,
    OpenAICompatibleLLMProvider,
    load_architecture_knowledge_documents,
)


def main() -> int:
    """Run three real structured calls and print only bounded summary fields."""

    root = Path(__file__).resolve().parents[1]
    load_dotenv(root / ".env", override=False)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

    try:
        provider = OpenAICompatibleLLMProvider.from_env()
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
    except AgentExecutionError as exc:
        print("Multi-agent reasoning: FAILED")
        print(f"Failed role: {exc.failed_role.value}")
        error_type = (
            exc.execution_trace[-1].error_type
            if exc.execution_trace
            else type(exc).__name__
        )
        print(f"Error type: {error_type}")
        print(f"Error stage: {exc.stage}")
        print("This is not a verified attack chain.")
        return 1
    except Exception as exc:
        print("Multi-agent reasoning: FAILED")
        print("Failed role: unavailable")
        print(f"Error type: {type(exc).__name__}")
        print(f"Error stage: {getattr(exc, 'stage', 'pipeline')}")
        print("This is not a verified attack chain.")
        return 1

    print(f"Candidate ID: {result.candidate_id}")
    print(f"Architecture: {result.architecture.value}")
    print(f"Agent 1 Status: {result.evidence_analysis.analysis_status.value}")
    print(f"Evidence Gap Count: {len(result.evidence_analysis.evidence_gaps)}")
    print(
        "Agent 2 Semantic Status: "
        f"{result.security_reasoning.semantic_status.value}"
    )
    print(f"Hypothesis Count: {len(result.security_reasoning.hypotheses)}")
    print(
        "Verification Step Count: "
        f"{len(result.security_reasoning.recommended_verification_steps)}"
    )
    print(f"Agent 3 Review Status: {result.critic_review.review_status.value}")
    print(
        "Unsupported Statement Count: "
        f"{len(result.critic_review.unsupported_statements)}"
    )
    print(f"Contradiction Count: {len(result.critic_review.contradictions)}")
    print(f"Final Semantic Status: {result.final_semantic_status.value}")
    print(
        "Execution Trace Roles: "
        + " -> ".join(record.role.value for record in result.execution_trace)
    )
    print(
        "Unresolved Trigger Count: "
        f"{len(result.unresolved_trigger_node_ids)}"
    )
    print(
        "Unresolved Precondition Count: "
        f"{len(result.unresolved_precondition_node_ids)}"
    )
    print("This is not a verified attack chain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
