"""Phase 9B2B Step 3 offline knowledge retrieval contract tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents import ReasoningContext
from chipchain.knowledge import (
    DeterministicKnowledgeRetriever,
    HardwareKnowledgeEntry,
    InMemoryKnowledgeEntryRepository,
    KnowledgeEntryKind,
    KnowledgeRetrievalQuery,
    KnowledgeRetrievalResult,
    VulnerabilityKnowledgeEntry,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]


def _entries() -> list[VulnerabilityKnowledgeEntry | HardwareKnowledgeEntry]:
    return [
        VulnerabilityKnowledgeEntry.create(
            entry_kind=KnowledgeEntryKind.CVE,
            external_id="CVE-FIXTURE-ARM-0001",
            architecture=Architecture.ARM,
            title="Fixture ARM MMIO condition",
            summary="Synthetic MMIO access condition for an owned ARM fixture",
            affected_components=["fixture-arm-driver"],
            metadata={"sample_type": "fixture"},
        ),
        VulnerabilityKnowledgeEntry.create(
            entry_kind=KnowledgeEntryKind.CVE,
            external_id="CVE-FIXTURE-RISCV-0001",
            architecture=Architecture.RISC_V,
            title="Fixture RISC-V MMIO condition",
            summary="Synthetic MMIO access condition for an owned RISC-V fixture",
            affected_components=["fixture-riscv-driver"],
            metadata={"sample_type": "fixture"},
        ),
        VulnerabilityKnowledgeEntry.create(
            entry_kind=KnowledgeEntryKind.CWE,
            external_id="CWE-FIXTURE-0001",
            architecture=None,
            title="Fixture global MMIO weakness",
            summary="Architecture-neutral taxonomy reference for MMIO access",
            metadata={"sample_type": "fixture"},
        ),
        VulnerabilityKnowledgeEntry.create(
            entry_kind=KnowledgeEntryKind.CAPEC,
            external_id="CAPEC-FIXTURE-0001",
            architecture=None,
            title="Fixture global MMIO pattern",
            summary="Architecture-neutral pattern reference for MMIO access",
            metadata={"sample_type": "fixture"},
        ),
        HardwareKnowledgeEntry.create(
            architecture=Architecture.ARM,
            component_id="fixture-arm-mmio",
            title="Fixture ARM MMIO peripheral",
            summary="Owned ARM hardware interface used for MMIO access",
            interface_ids=["fixture-arm-interface"],
            register_ids=["fixture-arm-register"],
            metadata={"sample_type": "fixture"},
        ),
        HardwareKnowledgeEntry.create(
            architecture=Architecture.RISC_V,
            component_id="fixture-riscv-mmio",
            title="Fixture RISC-V MMIO peripheral",
            summary="Owned RISC-V hardware interface used for MMIO access",
            interface_ids=["fixture-riscv-interface"],
            register_ids=["fixture-riscv-register"],
            metadata={"sample_type": "fixture"},
        ),
    ]


def _query(
    *,
    text: str = "fixture MMIO access",
    metadata: dict[str, object] | None = None,
) -> KnowledgeRetrievalQuery:
    return KnowledgeRetrievalQuery.create(
        architecture=Architecture.ARM,
        text=text,
        component_ids=["fixture-arm-driver"],
        top_k=10,
        metadata=metadata,
    )


def test_entry_query_and_result_ids_are_deterministic() -> None:
    entries = _entries()
    reordered_entry = VulnerabilityKnowledgeEntry.create(
        entry_kind=KnowledgeEntryKind.CVE,
        external_id="CVE-FIXTURE-ARM-0001",
        architecture=Architecture.ARM,
        title="Fixture ARM MMIO condition",
        summary="Synthetic MMIO access condition for an owned ARM fixture",
        affected_components=["fixture-arm-driver"],
        metadata={"different": "non-semantic"},
    )
    assert reordered_entry.id == entries[0].id
    assert _query(metadata={"order": 1}).id == _query(
        metadata={"order": 2}
    ).id

    first = DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository(entries)
    ).retrieve(_query())
    second = DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository(reversed(entries))
    ).retrieve(_query())
    assert first == second
    assert first.id == second.id
    assert [hit.id for hit in first.hits] == [hit.id for hit in second.hits]


def test_query_and_result_round_trip() -> None:
    query = _query()
    result = DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository(_entries())
    ).retrieve(query)

    assert KnowledgeRetrievalQuery.model_validate_json(
        query.model_dump_json()
    ) == query
    assert KnowledgeRetrievalResult.model_validate_json(
        result.model_dump_json()
    ) == result


def test_architecture_filtering_precedes_scoring_and_preserves_global_entries() -> None:
    entries = _entries()
    result = DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository(entries)
    ).retrieve(_query())
    by_id = {entry.id: entry for entry in entries}

    assert result.metadata["architecture_filter_stage"] == "before_scoring"
    assert {by_id[hit.entry_id].architecture for hit in result.hits} == {
        None,
        Architecture.ARM,
    }
    expected_excluded = sorted(
        entry.id for entry in entries if entry.architecture is Architecture.RISC_V
    )
    assert result.excluded_entry_ids == expected_excluded
    assert not set(result.knowledge_entry_ids).intersection(expected_excluded)


def test_empty_retrieval_result_is_valid_and_deterministic() -> None:
    repository = InMemoryKnowledgeEntryRepository(_entries()[:1])
    retriever = DeterministicKnowledgeRetriever(repository)
    query = KnowledgeRetrievalQuery.create(
        architecture=Architecture.ARM,
        text="unmatched-token-only",
    )

    first = retriever.retrieve(query)
    second = retriever.retrieve(query)
    assert first == second
    assert first.hits == []
    assert first.knowledge_entry_ids == []
    assert first.excluded_entry_ids == []


def test_retrieval_references_feed_reasoning_context_without_domain_objects() -> None:
    result = DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository(_entries())
    ).retrieve(_query())
    context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-phase9b2b-step3-subject",
        affected_components=["fixture-arm-driver"],
        knowledge_entry_ids=result.knowledge_entry_ids,
    )

    assert context.knowledge_entry_ids == sorted(result.knowledge_entry_ids)
    assert ReasoningContext.model_validate_json(context.model_dump_json()) == context
    assert all(type(item) is str for item in context.knowledge_entry_ids)


def test_retrieval_contract_has_no_verification_leakage() -> None:
    result = DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository(_entries())
    ).retrieve(_query())
    forbidden_keys = {
        "attack_chain",
        "attack_chain_status",
        "evidence",
        "interaction_verification_status",
        "verification_record",
        "verification_status",
        "vulnerability_status",
        "vulnerability_verdict",
    }
    serialized = result.model_dump(mode="json")

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert forbidden_keys.isdisjoint(keys(serialized))
    assert not hasattr(result, "create_evidence")
    assert not hasattr(result, "create_verification_record")

    with pytest.raises(ValidationError, match="evidence or verdict fields"):
        _query(metadata={"nested": {"verification_status": "verified"}})

    tree = ast.parse(
        (ROOT / "src/chipchain/knowledge/retrieval.py").read_text(
            encoding="utf-8"
        )
    )
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert {
        "AttackChain",
        "Evidence",
        "VerificationRecord",
    }.isdisjoint(imported_names)
