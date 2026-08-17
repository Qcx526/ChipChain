"""Storage-neutral graph repository contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import AbstractSet, Self

from chipchain.graph.types import GraphPath
from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Layer,
    RelationType,
)
from chipchain.models.common import Metadata


class GraphRepository(ABC):
    """Abstract behavior-graph storage and deterministic query interface."""

    @property
    @abstractmethod
    def metadata(self) -> Metadata:
        """Return a detached copy of repository metadata."""

    @abstractmethod
    def add_node(self, node: BehaviorNode) -> None:
        """Add a node, rejecting an existing ID."""

    @abstractmethod
    def add_edge(self, edge: BehaviorEdge) -> None:
        """Add a validated edge, rejecting dangling endpoints and duplicate IDs."""

    @abstractmethod
    def get_node(self, node_id: str) -> BehaviorNode:
        """Return a detached node model or raise NodeNotFoundError."""

    @abstractmethod
    def get_edge(self, edge_id: str) -> BehaviorEdge:
        """Return an edge by its globally unique ID or raise EdgeNotFoundError."""

    @abstractmethod
    def list_nodes(
        self,
        *,
        architecture: Architecture | None = None,
        allowed_layers: AbstractSet[Layer] | None = None,
    ) -> list[BehaviorNode]:
        """List nodes deterministically, optionally filtering architecture and layers."""

    @abstractmethod
    def list_edges(
        self,
        *,
        architecture: Architecture | None = None,
        relation: RelationType | None = None,
    ) -> list[BehaviorEdge]:
        """List edges deterministically with optional architecture/relation filters."""

    @abstractmethod
    def remove_node(self, node_id: str) -> BehaviorNode:
        """Remove a node and its incident edges, returning the removed node."""

    @abstractmethod
    def remove_edge(self, edge_id: str) -> BehaviorEdge:
        """Remove and return an edge by globally unique ID."""

    @abstractmethod
    def successors(self, node_id: str) -> list[BehaviorNode]:
        """Return unique direct successor nodes in deterministic ID order."""

    @abstractmethod
    def predecessors(self, node_id: str) -> list[BehaviorNode]:
        """Return unique direct predecessor nodes in deterministic ID order."""

    @abstractmethod
    def find_paths(
        self,
        start_id: str,
        *,
        architecture: Architecture,
        max_hops: int,
        target_id: str | None = None,
        allowed_layers: AbstractSet[Layer] | None = None,
        max_results: int | None = None,
    ) -> list[GraphPath]:
        """Find directed simple paths under architecture and optional layer constraints.

        ``max_hops`` counts edges, not nodes. When ``allowed_layers`` is provided,
        every node in every returned path belongs to that set. Without a target,
        all reachable paths with 1..max_hops edges are eligible. A target equal to
        the start node yields the valid zero-hop path.
        """

    @abstractmethod
    def save(self, path: str | Path) -> None:
        """Persist a validated, stable JSON graph snapshot."""

    @classmethod
    @abstractmethod
    def load(cls, path: str | Path) -> Self:
        """Validate a JSON snapshot and return a new repository instance."""
