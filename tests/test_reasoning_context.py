"""Tests for strict CandidateContext and Evidence resolution."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.candidate import CrossGraphCandidate
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import NetworkXKnowledgeGraphRepository
from chipchain.models import Evidence
from chipchain.reasoning import (
    CandidateContext,
    CandidateContextAssembler,
    CandidateContextError,
    EvidenceResolutionError,
    InMemoryEvidenceResolver,
)


def test_candidate_context_resolves_domain_objects_and_round_trips(
    reasoning_context: CandidateContext,
) -> None:
    """Candidate IDs become complete typed facts rather than strings for the LLM."""

    restored = CandidateContext.model_validate_json(reasoning_context.model_dump_json())

    assert restored == reasoning_context
    assert len(reasoning_context.behavior_nodes) == 2
    assert len(reasoning_context.behavior_edges) == 1
    assert [item.id for item in reasoning_context.behavior_evidence] == [
        "fixture-reasoning-mmio-evidence"
    ]
    assert reasoning_context.knowledge_vulnerability.kind.value == "vulnerability"
    assert reasoning_context.knowledge_anchor.kind.value == "hardware_resource"
    assert len(reasoning_context.knowledge_edges) == 11
    assert len(reasoning_context.knowledge_evidence) == 2
    assert len(reasoning_context.trigger_nodes) == 1
    assert len(reasoning_context.precondition_nodes) == 1
    assert len(reasoning_context.impact_nodes) == 1
    assert {item.kind.value for item in reasoning_context.taxonomy_nodes} == {
        "cwe",
        "capec",
    }


def test_in_memory_evidence_resolver_is_strict_and_detached(
    reasoning_behavior_evidence: list[Evidence],
) -> None:
    """Missing Evidence is rejected and returned models cannot mutate the catalog."""

    resolver = InMemoryEvidenceResolver(reasoning_behavior_evidence)
    first = resolver.get("fixture-reasoning-mmio-evidence")
    first.verified = False

    assert resolver.get("fixture-reasoning-mmio-evidence").verified is True
    with pytest.raises(EvidenceResolutionError):
        resolver.get("missing-evidence")
    with pytest.raises(ValueError, match="IDs must be unique"):
        InMemoryEvidenceResolver(
            [reasoning_behavior_evidence[0], reasoning_behavior_evidence[0]]
        )


def test_context_assembly_rejects_missing_behavior_evidence(
    reasoning_candidate: CrossGraphCandidate,
    reasoning_behavior_repository: NetworkXGraphRepository,
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """The reasoning pipeline never silently drops an unresolved observation."""

    with pytest.raises(CandidateContextError) as exc_info:
        CandidateContextAssembler().assemble(
            reasoning_candidate,
            reasoning_behavior_repository,
            synthetic_arm_knowledge_repository,
            InMemoryEvidenceResolver([]),
        )

    assert isinstance(exc_info.value.__cause__, EvidenceResolutionError)


def test_context_assembly_rejects_missing_knowledge_reference(
    reasoning_candidate: CrossGraphCandidate,
    reasoning_behavior_repository: NetworkXGraphRepository,
    reasoning_behavior_evidence: list[Evidence],
) -> None:
    """Missing Knowledge Node/Edge references fail before retrieval or prompting."""

    empty_knowledge = NetworkXKnowledgeGraphRepository(architecture="arm")

    with pytest.raises(CandidateContextError):
        CandidateContextAssembler().assemble(
            reasoning_candidate,
            reasoning_behavior_repository,
            empty_knowledge,
            InMemoryEvidenceResolver(reasoning_behavior_evidence),
        )


def test_context_model_rejects_architecture_leakage(
    reasoning_context: CandidateContext,
) -> None:
    """Resolved Behavior and Knowledge facts remain architecture constrained."""

    data = reasoning_context.model_dump(mode="json")
    data["behavior_nodes"][0]["architecture"] = "risc_v"

    with pytest.raises(ValidationError, match="behavior context nodes"):
        CandidateContext.model_validate(data)
