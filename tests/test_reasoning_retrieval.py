"""Tests for architecture documents, query construction, and local retrieval."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.models import Architecture
from chipchain.reasoning import (
    ArchitectureKnowledgeDocument,
    CandidateContext,
    CandidateRetrievalQueryBuilder,
    LocalLexicalKnowledgeRetriever,
)


def test_architecture_document_scope_validation() -> None:
    """Architecture documents require architecture and global documents forbid it."""

    with pytest.raises(ValidationError, match="require architecture"):
        ArchitectureKnowledgeDocument(
            id="fixture-missing-architecture",
            scope="architecture",
            architecture=None,
            title="Fixture",
            content="Fixture content",
            source="fixture-source",
            reference="fixture-reference",
        )
    with pytest.raises(ValidationError, match="must not declare architecture"):
        ArchitectureKnowledgeDocument(
            id="fixture-bad-global",
            scope="global",
            architecture="arm",
            title="Fixture",
            content="Fixture content",
            source="fixture-source",
            reference="fixture-reference",
        )


def test_retrieval_query_is_deterministic_and_structured(
    reasoning_context: CandidateContext,
) -> None:
    """The same resolved facts always produce the same non-LLM query."""

    builder = CandidateRetrievalQueryBuilder()
    first = builder.build(reasoning_context)
    second = builder.build(reasoning_context)

    assert first == second
    assert first.architecture is Architecture.ARM
    assert "arch:arm:address:0x40000000" in first.terms
    assert "FIXTURE_MMIO_REGISTER" in first.terms
    assert "CWE-284" in first.terms
    assert "mmio_write" in first.terms
    assert reasoning_context.trigger_nodes[0].label in first.terms
    assert reasoning_context.precondition_nodes[0].label in first.terms


def test_local_retriever_filters_architecture_before_ranking(
    reasoning_context: CandidateContext,
    rag_fixture_documents: list[ArchitectureKnowledgeDocument],
) -> None:
    """Keyword-heavy RISC-V text never participates in an ARM result."""

    query = CandidateRetrievalQueryBuilder().build(reasoning_context)
    retriever = LocalLexicalKnowledgeRetriever(rag_fixture_documents)

    result = retriever.retrieve(query, architecture=Architecture.ARM, top_k=10)

    assert result.metadata["architecture_filter_stage"] == "before_scoring"
    assert "riscv-distractor-note" in result.excluded_document_ids
    assert all(
        chunk.document_id != "riscv-distractor-note" for chunk in result.chunks
    )
    assert "RISC-V keyword-heavy distractor" not in {
        chunk.content for chunk in result.chunks
    }
    assert all(
        chunk.architecture in {None, Architecture.ARM} for chunk in result.chunks
    )


def test_arm_and_global_documents_are_retrievable_with_provenance(
    reasoning_context: CandidateContext,
    rag_fixture_documents: list[ArchitectureKnowledgeDocument],
) -> None:
    """ARM and explicit global taxonomy references retain source and reference."""

    query = CandidateRetrievalQueryBuilder().build(reasoning_context)
    result = LocalLexicalKnowledgeRetriever(rag_fixture_documents).retrieve(
        query,
        architecture=Architecture.ARM,
        top_k=10,
    )
    by_id = {chunk.document_id: chunk for chunk in result.chunks}

    assert "arm-fixture-mmio-note" in by_id
    assert "global-fixture-taxonomy-note" in by_id
    assert by_id["arm-fixture-mmio-note"].source == (
        "chipchain-owned-rag-fixture"
    )
    assert by_id["global-fixture-taxonomy-note"].reference.endswith(
        "global_fixture_taxonomy_note.json"
    )
    assert all(chunk.chunk_id.endswith(":chunk:0") for chunk in result.chunks)
    assert all(0 < chunk.score <= 1 for chunk in result.chunks)


def test_local_retrieval_ranking_and_top_k_are_deterministic(
    reasoning_context: CandidateContext,
    rag_fixture_documents: list[ArchitectureKnowledgeDocument],
) -> None:
    """Equivalent corpus/query calls return stable order before truncation."""

    query = CandidateRetrievalQueryBuilder().build(reasoning_context)
    retriever = LocalLexicalKnowledgeRetriever(reversed(rag_fixture_documents))
    first = retriever.retrieve(query, architecture="arm", top_k=3)
    second = retriever.retrieve(query, architecture="arm", top_k=3)
    limited = retriever.retrieve(query, architecture="arm", top_k=1)

    assert first == second
    assert limited.chunks == first.chunks[:1]
    assert [item.score for item in first.chunks] == sorted(
        (item.score for item in first.chunks), reverse=True
    )
    with pytest.raises(ValueError, match="top_k"):
        retriever.retrieve(query, architecture="arm", top_k=0)
    with pytest.raises(ValueError, match="does not match"):
        retriever.retrieve(query, architecture="risc_v", top_k=1)
