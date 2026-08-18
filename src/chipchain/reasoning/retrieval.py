"""Architecture-first deterministic local lexical knowledge retrieval."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterable

from chipchain.models import Architecture
from chipchain.reasoning.enums import ArchitectureKnowledgeScope
from chipchain.reasoning.models import (
    ArchitectureKnowledgeDocument,
    CandidateRetrievalQuery,
    RetrievalResult,
    RetrievedKnowledgeChunk,
)

_TOKEN = re.compile(r"[a-z0-9]+")


class KnowledgeRetriever(ABC):
    """Backend-neutral architecture-constrained knowledge retrieval contract."""

    @abstractmethod
    def retrieve(
        self,
        query: CandidateRetrievalQuery,
        *,
        architecture: Architecture,
        top_k: int,
    ) -> RetrievalResult:
        """Return deterministic architecture-safe reference chunks."""


class LocalLexicalKnowledgeRetriever(KnowledgeRetriever):
    """Small deterministic token-overlap retriever with pre-score filtering."""

    def __init__(self, documents: Iterable[ArchitectureKnowledgeDocument]) -> None:
        """Validate and detach a local document corpus."""

        material = list(documents)
        ids = [item.id for item in material]
        if len(ids) != len(set(ids)):
            raise ValueError("retrieval document IDs must be unique")
        self._documents = [
            ArchitectureKnowledgeDocument.model_validate(
                item.model_dump(mode="json")
            )
            for item in material
        ]

    def retrieve(
        self,
        query: CandidateRetrievalQuery,
        *,
        architecture: Architecture,
        top_k: int,
    ) -> RetrievalResult:
        """Filter by architecture before any lexical scoring."""

        normalized_architecture = Architecture(architecture)
        if query.architecture is not normalized_architecture:
            raise ValueError("retrieval query does not match requested architecture")
        if top_k <= 0:
            raise ValueError("top_k must be positive")

        eligible: list[ArchitectureKnowledgeDocument] = []
        excluded: list[str] = []
        for document in self._documents:
            if document.scope is ArchitectureKnowledgeScope.GLOBAL:
                eligible.append(document)
            elif document.architecture is normalized_architecture:
                eligible.append(document)
            else:
                excluded.append(document.id)

        query_tokens = _tokenize(query.text)
        scored: list[RetrievedKnowledgeChunk] = []
        for document in eligible:
            score = _lexical_score(query_tokens, _document_tokens(document))
            if score <= 0:
                continue
            scored.append(
                RetrievedKnowledgeChunk(
                    document_id=document.id,
                    chunk_id=f"{document.id}:chunk:0",
                    architecture=document.architecture,
                    scope=document.scope,
                    content=document.content,
                    source=document.source,
                    reference=document.reference,
                    section=document.section,
                    score=score,
                    metadata={
                        **document.metadata,
                        "retriever": "local_lexical",
                        "retrieval_score_semantics": "relevance_not_security_confidence",
                    },
                )
            )
        scored.sort(key=lambda item: (-item.score, item.document_id, item.chunk_id))
        return RetrievalResult(
            query=query,
            architecture=normalized_architecture,
            chunks=scored[:top_k],
            excluded_document_ids=sorted(excluded),
            metadata={
                "eligible_document_count": len(eligible),
                "corpus_document_count": len(self._documents),
                "architecture_filter_stage": "before_scoring",
            },
        )


def _tokenize(value: str) -> Counter[str]:
    return Counter(_TOKEN.findall(value.lower()))


def _document_tokens(document: ArchitectureKnowledgeDocument) -> Counter[str]:
    return _tokenize(
        " ".join(
            [
                document.title,
                document.content,
                document.section or "",
                *document.tags,
            ]
        )
    )


def _lexical_score(query: Counter[str], document: Counter[str]) -> float:
    if not query:
        return 0.0
    overlap = sum(min(count, document[token]) for token, count in query.items())
    return min(1.0, overlap / sum(query.values()))
