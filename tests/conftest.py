"""Shared fixture loaders for domain model tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from chipchain.analysis import DemoAnalyzer, ProgramAnalysisResult, ProgramArtifact
from chipchain.candidate import CrossGraphCandidate, CrossGraphCandidateSearcher
from chipchain.graph import NetworkXGraphRepository, build_arm_demo_graph
from chipchain.knowledge import (
    KnowledgeGraphBundle,
    NetworkXKnowledgeGraphRepository,
    VulnerabilityKnowledgeBuilder,
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
    VulnerabilitySample,
)
from chipchain.multi_agent import MultiAgentContext
from chipchain.reasoning import (
    ArchitectureKnowledgeDocument,
    CandidateContext,
    CandidateContextAssembler,
    CandidateRetrievalQueryBuilder,
    InMemoryEvidenceResolver,
    LocalLexicalKnowledgeRetriever,
    load_architecture_knowledge_documents,
)

FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures"


def load_fixture_data(name: str) -> dict[str, Any]:
    """Load a JSON fixture into a fresh dictionary."""

    path = FIXTURE_DIRECTORY / name
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def arm_chain_data() -> dict[str, Any]:
    """Return the valid ARM candidate-chain fixture data."""

    return load_fixture_data("valid_arm_chain.json")


@pytest.fixture
def arm_vulnerability_data() -> dict[str, Any]:
    """Return the valid ARM vulnerability fixture data."""

    return load_fixture_data("valid_arm_vulnerability.json")


@pytest.fixture
def arm_demo_graph() -> NetworkXGraphRepository:
    """Return a fresh synthetic ARM MultiDiGraph repository."""

    return build_arm_demo_graph()


@pytest.fixture
def synthetic_arm_knowledge_sample() -> VulnerabilitySample:
    """Load the owned Phase 5 ARM vulnerability knowledge fixture."""

    return VulnerabilitySample.model_validate(
        load_fixture_data("knowledge/synthetic_arm_vulnerability.json")
    )


@pytest.fixture
def synthetic_arm_knowledge_bundle(
    synthetic_arm_knowledge_sample: VulnerabilitySample,
) -> KnowledgeGraphBundle:
    """Build a fresh deterministic bundle from the owned fixture."""

    return VulnerabilityKnowledgeBuilder().build(synthetic_arm_knowledge_sample)


@pytest.fixture
def synthetic_arm_knowledge_repository(
    synthetic_arm_knowledge_bundle: KnowledgeGraphBundle,
) -> NetworkXKnowledgeGraphRepository:
    """Return a fresh independent knowledge repository."""

    return NetworkXKnowledgeGraphRepository.from_bundle(
        synthetic_arm_knowledge_bundle
    )


@pytest.fixture
def reasoning_behavior_evidence() -> list[Evidence]:
    """Return full Evidence for the compact Phase 7 behavior path."""

    return [
        Evidence(
            id="fixture-reasoning-mmio-evidence",
            type=EvidenceType.STATIC_ANALYSIS,
            source="phase7-fixture-observer",
            artifact="phase7-fixture-artifact",
            address="0x10008",
            instruction="fixture-store",
            confidence=1.0,
            verified=True,
            metadata={"fixture": True, "synthetic": True, "owned": True},
        )
    ]


@pytest.fixture
def reasoning_behavior_repository() -> NetworkXGraphRepository:
    """Build a compact reachable ARM driver-to-register behavior graph."""

    repository = NetworkXGraphRepository(metadata={"fixture": True})
    repository.add_node(
        BehaviorNode(
            id="phase7-fixture-driver",
            kind=NodeKind.FUNCTION,
            name="phase7_fixture_driver",
            architecture=Architecture.ARM,
            layer=Layer.DRIVER,
            metadata={"fixture": True},
        )
    )
    repository.add_node(
        BehaviorNode(
            id="phase7-fixture-register",
            kind=NodeKind.REGISTER,
            name="FIXTURE_MMIO_REGISTER",
            architecture=Architecture.ARM,
            layer=Layer.HARDWARE,
            address="0x40000000",
            metadata={
                "memory_map_id": "synthetic-arm-mmio-map",
                "memory_map_region": "fixture-mmio-register",
                "fixture": True,
            },
        )
    )
    repository.add_edge(
        BehaviorEdge(
            id="phase7-fixture-mmio-write",
            source_id="phase7-fixture-driver",
            target_id="phase7-fixture-register",
            relation=RelationType.MMIO_WRITE,
            architecture=Architecture.ARM,
            evidence_ids=["fixture-reasoning-mmio-evidence"],
            metadata={"fixture": True},
        )
    )
    return repository


@pytest.fixture
def reasoning_candidate(
    reasoning_behavior_repository: NetworkXGraphRepository,
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> CrossGraphCandidate:
    """Return one deterministic Phase 6 candidate for Phase 7 tests."""

    return CrossGraphCandidateSearcher().search(
        reasoning_behavior_repository,
        synthetic_arm_knowledge_repository,
        architecture=Architecture.ARM,
        start_node_id="phase7-fixture-driver",
        max_hops=1,
    )[0]


@pytest.fixture
def reasoning_context(
    reasoning_candidate: CrossGraphCandidate,
    reasoning_behavior_repository: NetworkXGraphRepository,
    reasoning_behavior_evidence: list[Evidence],
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> CandidateContext:
    """Resolve the compact candidate into a strict read-only context."""

    return CandidateContextAssembler().assemble(
        reasoning_candidate,
        reasoning_behavior_repository,
        synthetic_arm_knowledge_repository,
        InMemoryEvidenceResolver(reasoning_behavior_evidence),
    )


@pytest.fixture
def rag_fixture_documents() -> list[ArchitectureKnowledgeDocument]:
    """Load the owned Phase 7 ARM/global/RISC-V retrieval corpus."""

    return load_architecture_knowledge_documents(FIXTURE_DIRECTORY / "rag")


@pytest.fixture
def multi_agent_context(
    reasoning_context: CandidateContext,
    rag_fixture_documents: list[ArchitectureKnowledgeDocument],
) -> MultiAgentContext:
    """Build one shared architecture-filtered context for all Phase 8 agents."""

    query = CandidateRetrievalQueryBuilder().build(reasoning_context)
    retrieval = LocalLexicalKnowledgeRetriever(rag_fixture_documents).retrieve(
        query,
        architecture=reasoning_context.architecture,
        top_k=3,
    )
    return MultiAgentContext(
        candidate_id=reasoning_context.candidate_id,
        architecture=reasoning_context.architecture,
        candidate_context=reasoning_context,
        retrieval_query=query,
        retrieved_chunks=retrieval.chunks,
        metadata={"fixture": True, "shared_context": True},
    )


@pytest.fixture
def demo_program_spec_path() -> Path:
    """Return the auditable ARM DemoAnalyzer input fixture path."""

    return FIXTURE_DIRECTORY / "program_analysis" / "arm_demo_program.json"


@pytest.fixture
def demo_program_spec_data(demo_program_spec_path: Path) -> dict[str, Any]:
    """Return a fresh dictionary containing the demo program specification."""

    return json.loads(demo_program_spec_path.read_text(encoding="utf-8"))


@pytest.fixture
def demo_program_artifact(demo_program_spec_path: Path) -> ProgramArtifact:
    """Return the ProgramArtifact used by the deterministic DemoAnalyzer."""

    return ProgramArtifact(
        id="fixture-arm-program",
        architecture="arm",
        artifact_type="fixture",
        path=str(demo_program_spec_path),
        fixture_identifier="fixture-arm-demo-program-spec",
        metadata={"fixture": True, "real_program": False},
    )


@pytest.fixture
def demo_analysis_result(
    demo_program_artifact: ProgramArtifact,
) -> ProgramAnalysisResult:
    """Analyze the ARM program fixture into a fresh validated result."""

    return DemoAnalyzer().analyze(demo_program_artifact)
