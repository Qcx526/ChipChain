"""Storage-neutral repository contract for vulnerability knowledge graphs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Self

from chipchain.knowledge.enums import KnowledgeNodeKind, KnowledgeRelationType
from chipchain.knowledge.models import KnowledgeEdge, KnowledgeNode
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
