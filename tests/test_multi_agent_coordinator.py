"""Tests for fixed ordering, validation, failure isolation, and read-only behavior."""

from __future__ import annotations

from typing import TypeVar

import pytest

from chipchain.models import Architecture, Evidence
from chipchain.models.common import DomainModel
from chipchain.multi_agent import (
    AgentExecutionError,
    CriticReviewStatus,
    CriticAgent,
    EvidenceAnalystAgent,
    EvidenceAnalysisStatus,
    MockStructuredOutputProvider,
    MultiAgentCoordinator,
    SecurityReasoningAgent,
    determine_final_semantic_status,
)
from chipchain.reasoning import (
    CandidateContextAssembler,
    CandidateRetrievalQueryBuilder,
    CandidateSemanticStatus,
    InMemoryEvidenceResolver,
    KnowledgeRetriever,
    LocalLexicalKnowledgeRetriever,
    StructuredOutputProvider,
    StructuredPromptRequest,
)

StructuredModelT = TypeVar("StructuredModelT", bound=DomainModel)


class CountingRetriever(KnowledgeRetriever):
    """Count calls while delegating to the real deterministic local retriever."""

    def __init__(self, delegate: KnowledgeRetriever) -> None:
        self.delegate = delegate
        self.calls = 0

    def retrieve(self, query, *, architecture, top_k):
        self.calls += 1
        return self.delegate.retrieve(
            query,
            architecture=architecture,
            top_k=top_k,
        )


class FaultingProvider(StructuredOutputProvider):
    """Inject one bounded malformed output while recording attempted roles."""

    def __init__(self, role: str, mode: str) -> None:
        self.role = role
        self.mode = mode
        self.calls: list[str] = []
        self.delegate = MockStructuredOutputProvider()

    def generate_structured(
        self,
        request: StructuredPromptRequest,
        output_type: type[StructuredModelT],
    ) -> StructuredModelT:
        self.calls.append(request.role)
        if request.role == self.role and self.mode == "raise":
            raise RuntimeError("fixture provider failure")
        output = self.delegate.generate_structured(request, output_type)
        if request.role != self.role:
            return output
        _mutate_output(output, self.mode)
        return output


def make_coordinator(documents, provider, *, retriever=None):
    """Build all three fixed agents around one shared provider."""

    selected_retriever = retriever or LocalLexicalKnowledgeRetriever(documents)
    return MultiAgentCoordinator(
        context_assembler=CandidateContextAssembler(),
        query_builder=CandidateRetrievalQueryBuilder(),
        retriever=selected_retriever,
        evidence_analyst=EvidenceAnalystAgent(provider),
        security_reasoner=SecurityReasoningAgent(provider),
        critic=CriticAgent(provider),
    )


def run_coordinator(
    coordinator,
    candidate,
    behavior_repository,
    behavior_evidence,
    knowledge_repository,
):
    return coordinator.reason(
        candidate,
        behavior_repository,
        knowledge_repository,
        InMemoryEvidenceResolver(behavior_evidence),
        top_k=3,
    )


def test_coordinator_runs_one_retrieval_and_fixed_deterministic_order(
    reasoning_candidate,
    reasoning_behavior_repository,
    reasoning_behavior_evidence: list[Evidence],
    synthetic_arm_knowledge_repository,
    rag_fixture_documents,
) -> None:
    provider = MockStructuredOutputProvider()
    retriever = CountingRetriever(LocalLexicalKnowledgeRetriever(rag_fixture_documents))
    coordinator = make_coordinator(
        rag_fixture_documents,
        provider,
        retriever=retriever,
    )

    first = run_coordinator(
        coordinator,
        reasoning_candidate,
        reasoning_behavior_repository,
        reasoning_behavior_evidence,
        synthetic_arm_knowledge_repository,
    )
    second = run_coordinator(
        coordinator,
        reasoning_candidate,
        reasoning_behavior_repository,
        reasoning_behavior_evidence,
        synthetic_arm_knowledge_repository,
    )

    assert retriever.calls == 2
    assert first == second
    assert first.final_semantic_status.value == "insufficient_context"
    assert [record.role.value for record in first.execution_trace] == [
        "evidence_analyst",
        "security_reasoner",
        "critic",
    ]
    assert [record.sequence for record in first.execution_trace] == [1, 2, 3]
    assert first.context.metadata["retrieval_runs"] == 1
    assert [call.role for call in provider.calls] == [
        "evidence_analyst",
        "security_reasoner",
        "critic",
    ] * 2


def test_coordinator_keeps_candidate_repositories_and_evidence_unchanged(
    reasoning_candidate,
    reasoning_behavior_repository,
    reasoning_behavior_evidence: list[Evidence],
    synthetic_arm_knowledge_repository,
    rag_fixture_documents,
) -> None:
    candidate_before = reasoning_candidate.model_dump_json()
    behavior_before = (
        reasoning_behavior_repository.list_nodes(),
        reasoning_behavior_repository.list_edges(),
        reasoning_behavior_repository.metadata,
    )
    knowledge_before = (
        synthetic_arm_knowledge_repository.list_nodes(),
        synthetic_arm_knowledge_repository.list_edges(),
        synthetic_arm_knowledge_repository.list_evidence(),
        synthetic_arm_knowledge_repository.metadata,
    )
    evidence_before = [item.model_dump_json() for item in reasoning_behavior_evidence]

    run_coordinator(
        make_coordinator(rag_fixture_documents, MockStructuredOutputProvider()),
        reasoning_candidate,
        reasoning_behavior_repository,
        reasoning_behavior_evidence,
        synthetic_arm_knowledge_repository,
    )

    assert reasoning_candidate.model_dump_json() == candidate_before
    assert behavior_before == (
        reasoning_behavior_repository.list_nodes(),
        reasoning_behavior_repository.list_edges(),
        reasoning_behavior_repository.metadata,
    )
    assert knowledge_before == (
        synthetic_arm_knowledge_repository.list_nodes(),
        synthetic_arm_knowledge_repository.list_edges(),
        synthetic_arm_knowledge_repository.list_evidence(),
        synthetic_arm_knowledge_repository.metadata,
    )
    assert [item.model_dump_json() for item in reasoning_behavior_evidence] == evidence_before


def test_final_status_rules_are_transparent_and_deterministic(
    reasoning_candidate,
    reasoning_behavior_repository,
    reasoning_behavior_evidence: list[Evidence],
    synthetic_arm_knowledge_repository,
    rag_fixture_documents,
) -> None:
    result = run_coordinator(
        make_coordinator(rag_fixture_documents, MockStructuredOutputProvider()),
        reasoning_candidate,
        reasoning_behavior_repository,
        reasoning_behavior_evidence,
        synthetic_arm_knowledge_repository,
    )
    ready = result.evidence_analysis.model_copy(
        update={"analysis_status": EvidenceAnalysisStatus.CONTEXT_READY}
    )
    requires = result.security_reasoning.model_copy(
        update={"semantic_status": CandidateSemanticStatus.REQUIRES_VERIFICATION}
    )
    reviewed = result.critic_review.model_copy(
        update={"review_status": CriticReviewStatus.REVIEW_COMPLETE}
    )

    assert determine_final_semantic_status(ready, requires, reviewed) is (
        CandidateSemanticStatus.REQUIRES_VERIFICATION
    )
    assert determine_final_semantic_status(
        result.evidence_analysis,
        requires,
        reviewed,
    ) is CandidateSemanticStatus.INSUFFICIENT_CONTEXT
    conflict = reviewed.model_copy(
        update={"review_status": CriticReviewStatus.CONTEXT_CONFLICT}
    )
    assert determine_final_semantic_status(ready, requires, conflict) is (
        CandidateSemanticStatus.CONTEXTUALLY_INCONSISTENT
    )


@pytest.mark.parametrize(
    ("role", "mode", "expected_calls"),
    [
        ("evidence_analyst", "raise", ["evidence_analyst"]),
        ("evidence_analyst", "wrong_candidate", ["evidence_analyst"]),
        ("evidence_analyst", "wrong_architecture", ["evidence_analyst"]),
        ("evidence_analyst", "unknown_evidence", ["evidence_analyst"]),
        ("evidence_analyst", "missing_trigger", ["evidence_analyst"]),
        ("evidence_analyst", "forbidden", ["evidence_analyst"]),
        (
            "security_reasoner",
            "unknown_chunk",
            ["evidence_analyst", "security_reasoner"],
        ),
        (
            "security_reasoner",
            "unknown_evidence",
            ["evidence_analyst", "security_reasoner"],
        ),
        (
            "security_reasoner",
            "architecture_leakage",
            ["evidence_analyst", "security_reasoner"],
        ),
        (
            "security_reasoner",
            "forbidden",
            ["evidence_analyst", "security_reasoner"],
        ),
        (
            "critic",
            "unknown_hypothesis",
            ["evidence_analyst", "security_reasoner", "critic"],
        ),
        (
            "critic",
            "unknown_chunk",
            ["evidence_analyst", "security_reasoner", "critic"],
        ),
        (
            "critic",
            "forbidden",
            ["evidence_analyst", "security_reasoner", "critic"],
        ),
        (
            "critic",
            "metadata_forbidden",
            ["evidence_analyst", "security_reasoner", "critic"],
        ),
    ],
)
def test_agent_failure_stops_later_roles_and_retains_safe_trace(
    role: str,
    mode: str,
    expected_calls: list[str],
    reasoning_candidate,
    reasoning_behavior_repository,
    reasoning_behavior_evidence: list[Evidence],
    synthetic_arm_knowledge_repository,
    rag_fixture_documents,
) -> None:
    provider = FaultingProvider(role, mode)

    with pytest.raises(AgentExecutionError) as exc_info:
        run_coordinator(
            make_coordinator(rag_fixture_documents, provider),
            reasoning_candidate,
            reasoning_behavior_repository,
            reasoning_behavior_evidence,
            synthetic_arm_knowledge_repository,
        )

    error = exc_info.value
    assert error.failed_role.value == role
    assert provider.calls == expected_calls
    assert [record.role.value for record in error.execution_trace] == expected_calls
    assert error.execution_trace[-1].execution_status.value == "failed"
    assert error.execution_trace[-1].output_digest is None or len(
        error.execution_trace[-1].output_digest
    ) == 64


def _mutate_output(output: DomainModel, mode: str) -> None:
    if mode == "wrong_candidate":
        object.__setattr__(output, "candidate_id", "wrong-candidate")
    elif mode == "wrong_architecture":
        object.__setattr__(output, "architecture", Architecture.RISC_V)
    elif mode == "unknown_evidence":
        field = (
            "observed_behavior_evidence_ids"
            if hasattr(output, "observed_behavior_evidence_ids")
            else "supporting_observation_ids"
        )
        object.__setattr__(output, field, ["unknown-evidence"])
    elif mode == "unknown_chunk":
        field = (
            "referenced_knowledge_chunk_ids"
            if hasattr(output, "referenced_knowledge_chunk_ids")
            else "supporting_knowledge_chunk_ids"
        )
        object.__setattr__(output, field, ["unknown-chunk"])
    elif mode == "unknown_hypothesis":
        object.__setattr__(output, "referenced_hypothesis_ids", ["unknown-hypothesis"])
    elif mode == "missing_trigger":
        object.__setattr__(output, "unresolved_trigger_node_ids", [])
    elif mode == "architecture_leakage":
        object.__setattr__(output, "summary", "RISC-V context leaked into ARM.")
    elif mode == "forbidden":
        if hasattr(output, "evidence_gaps"):
            object.__setattr__(output, "evidence_gaps", ["Vulnerability confirmed."])
        elif hasattr(output, "summary"):
            object.__setattr__(output, "summary", "Verified attack chain.")
        else:
            object.__setattr__(output, "required_revisions", ["Exploit confirmed."])
    elif mode == "metadata_forbidden":
        object.__setattr__(output, "metadata", {"Vulnerability confirmed.": True})
    else:
        raise AssertionError(f"unknown fixture mutation: {mode}")
