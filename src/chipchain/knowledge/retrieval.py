"""Offline deterministic retrieval over Phase 9B2B knowledge entries."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import Counter

from chipchain.knowledge.models import (
    HardwareKnowledgeEntry,
    KnowledgeRetrievalHit,
    KnowledgeRetrievalQuery,
    KnowledgeRetrievalResult,
    RetrievableKnowledgeEntry,
    VulnerabilityKnowledgeEntry,
    knowledge_retrieval_hit_id,
    knowledge_retrieval_result_id,
)
from chipchain.knowledge.repository import KnowledgeEntryRepository

_TOKEN = re.compile(r"[a-z0-9]+")


class KnowledgeRetrievalService(ABC):
    """Backend-neutral retrieval interface that returns references, not truth."""

    @abstractmethod
    def retrieve(self, query: KnowledgeRetrievalQuery) -> KnowledgeRetrievalResult:
        """Return deterministic architecture-filtered knowledge references."""


class DeterministicKnowledgeRetriever(KnowledgeRetrievalService):
    """Local token-overlap retriever with pre-score architecture filtering."""

    def __init__(self, repository: KnowledgeEntryRepository) -> None:
        self._repository = repository

    def retrieve(self, query: KnowledgeRetrievalQuery) -> KnowledgeRetrievalResult:
        """Retrieve references without creating Evidence or verification state."""

        detached_query = KnowledgeRetrievalQuery.model_validate(
            query.model_dump(mode="json")
        )
        entries = self._repository.list_entries()
        eligible: list[RetrievableKnowledgeEntry] = []
        excluded: list[str] = []
        for entry in entries:
            if entry.entry_kind not in detached_query.entry_kinds:
                continue
            if (
                entry.architecture is not None
                and entry.architecture is not detached_query.architecture
            ):
                excluded.append(entry.id)
                continue
            eligible.append(entry)

        query_tokens = _tokenize(
            " ".join([detached_query.text, *detached_query.component_ids])
        )
        hits: list[KnowledgeRetrievalHit] = []
        for entry in eligible:
            entry_tokens = _entry_tokens(entry)
            matched_terms = sorted(set(query_tokens).intersection(entry_tokens))
            if not matched_terms:
                continue
            relevance_score = _lexical_score(query_tokens, entry_tokens)
            hit_id = knowledge_retrieval_hit_id(
                query_id=detached_query.id,
                entry_id=entry.id,
                matched_terms=matched_terms,
                relevance_score=relevance_score,
            )
            hits.append(
                KnowledgeRetrievalHit(
                    id=hit_id,
                    query_id=detached_query.id,
                    entry_id=entry.id,
                    entry_kind=entry.entry_kind,
                    architecture=entry.architecture,
                    matched_terms=matched_terms,
                    relevance_score=relevance_score,
                )
            )

        hits.sort(key=lambda item: (-item.relevance_score, item.entry_id))
        selected_hits = hits[: detached_query.top_k]
        result_id = knowledge_retrieval_result_id(
            query_id=detached_query.id,
            hits=selected_hits,
            excluded_entry_ids=excluded,
        )
        return KnowledgeRetrievalResult(
            id=result_id,
            query=detached_query,
            hits=selected_hits,
            excluded_entry_ids=excluded,
            metadata={
                "architecture_filter_stage": "before_scoring",
                "corpus_entry_count": len(entries),
                "eligible_entry_count": len(eligible),
                "retrieval_mode": "deterministic_local_lexical",
                "score_semantics": "retrieval_relevance_not_security_confidence",
            },
        )


def _tokenize(value: str) -> Counter[str]:
    return Counter(_TOKEN.findall(value.lower()))


def _entry_tokens(entry: RetrievableKnowledgeEntry) -> Counter[str]:
    if isinstance(entry, VulnerabilityKnowledgeEntry):
        values = [
            entry.external_id,
            entry.title,
            entry.summary,
            *entry.affected_components,
            *entry.references,
        ]
    elif isinstance(entry, HardwareKnowledgeEntry):
        values = [
            entry.component_id,
            entry.title,
            entry.summary,
            *entry.interface_ids,
            *entry.register_ids,
        ]
    else:  # pragma: no cover - repository contract rejects other types
        raise TypeError("unsupported knowledge entry type")
    return _tokenize(" ".join(values))


def _lexical_score(query: Counter[str], entry: Counter[str]) -> float:
    overlap = sum(min(count, entry[token]) for token, count in query.items())
    return min(1.0, overlap / sum(query.values()))
