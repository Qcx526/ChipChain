"""Storage-neutral repository contract for vulnerability knowledge graphs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from collections.abc import Iterable
from typing import Self

from chipchain.knowledge.enums import KnowledgeNodeKind, KnowledgeRelationType
from chipchain.knowledge.models import (
    HardwareKnowledgeEntry,
    KnowledgeEdge,
    KnowledgeNode,
    RetrievableKnowledgeEntry,
    VulnerabilityKnowledgeEntry,
)
from chipchain.models import Architecture, Evidence
from chipchain.models.common import Metadata


class KnowledgeGraphRepository(ABC):
    """Independent knowledge storage API with no behavior-path operations."""

    @property
    @abstractmethod
    def architecture(self) -> Architecture:
        """Return the repository's architecture scope."""

    @property
    @abstractmethod
    def sample_ids(self) -> list[str]:
        """Return detached, deterministic source sample IDs."""

    @property
    @abstractmethod
    def metadata(self) -> Metadata:
        """Return detached repository metadata."""

    @abstractmethod
    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence without overwriting an existing ID."""

    @abstractmethod
    def add_node(self, node: KnowledgeNode) -> None:
        """Add a knowledge node after checking architecture and evidence."""

    @abstractmethod
    def add_edge(self, edge: KnowledgeEdge) -> None:
        """Add a knowledge edge after checking endpoints and evidence."""

    @abstractmethod
    def get_evidence(self, evidence_id: str) -> Evidence:
        """Return evidence by ID."""

    @abstractmethod
    def get_node(self, node_id: str) -> KnowledgeNode:
        """Return a knowledge node by ID."""

    @abstractmethod
    def get_edge(self, edge_id: str) -> KnowledgeEdge:
        """Return a knowledge edge by globally unique ID."""

    @abstractmethod
    def list_evidence(self) -> list[Evidence]:
        """List evidence in deterministic ID order."""

    @abstractmethod
    def list_nodes(
        self, *, kind: KnowledgeNodeKind | None = None
    ) -> list[KnowledgeNode]:
        """List nodes deterministically, optionally filtering node kind."""

    @abstractmethod
    def list_edges(
        self, *, relation: KnowledgeRelationType | None = None
    ) -> list[KnowledgeEdge]:
        """List edges deterministically, optionally filtering relation."""

    @abstractmethod
    def successors(self, node_id: str) -> list[KnowledgeNode]:
        """Return unique direct successor nodes."""

    @abstractmethod
    def predecessors(self, node_id: str) -> list[KnowledgeNode]:
        """Return unique direct predecessor nodes."""

    @abstractmethod
    def save(self, path: str | Path) -> None:
        """Persist a validated knowledge graph snapshot."""

    @classmethod
    @abstractmethod
    def load(cls, path: str | Path) -> Self:
        """Load and validate a knowledge graph snapshot."""


class KnowledgeEntryRepository(ABC):
    """Read-only local source for Phase 9B2B retrievable knowledge entries."""

    @abstractmethod
    def get_entry(self, entry_id: str) -> RetrievableKnowledgeEntry:
        """Return one detached entry by deterministic ID."""

    @abstractmethod
    def list_entries(self) -> list[RetrievableKnowledgeEntry]:
        """Return detached entries in deterministic ID order."""


class InMemoryKnowledgeEntryRepository(KnowledgeEntryRepository):
    """Offline deterministic repository with no database or network adapter."""

    def __init__(self, entries: Iterable[RetrievableKnowledgeEntry]) -> None:
        material = [_snapshot_entry(entry) for entry in entries]
        entry_ids = [entry.id for entry in material]
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("knowledge entry IDs must be unique")
        self._entries = {entry.id: entry for entry in material}

    def get_entry(self, entry_id: str) -> RetrievableKnowledgeEntry:
        """Return a detached entry, failing closed for an unknown ID."""

        try:
            return _snapshot_entry(self._entries[entry_id])
        except KeyError as exc:
            raise KeyError(f"unknown knowledge entry {entry_id!r}") from exc

    def list_entries(self) -> list[RetrievableKnowledgeEntry]:
        """Return detached entries in deterministic ID order."""

        return [
            _snapshot_entry(self._entries[entry_id])
            for entry_id in sorted(self._entries)
        ]


def _snapshot_entry(
    entry: RetrievableKnowledgeEntry,
) -> RetrievableKnowledgeEntry:
    if isinstance(entry, VulnerabilityKnowledgeEntry):
        return VulnerabilityKnowledgeEntry.model_validate(
            entry.model_dump(mode="json")
        )
    if isinstance(entry, HardwareKnowledgeEntry):
        return HardwareKnowledgeEntry.model_validate(entry.model_dump(mode="json"))
    raise TypeError(
        "knowledge entry repository accepts only vulnerability or hardware entries"
    )
