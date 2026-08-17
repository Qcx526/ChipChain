"""Storage-independent graph result, snapshot, and error types."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from chipchain.models import Architecture, BehaviorEdge, BehaviorNode
from chipchain.models.common import DomainModel, Identifier, Metadata


class GraphError(Exception):
    """Base class for graph repository failures."""


class NodeNotFoundError(GraphError):
    """Raised when a requested graph node does not exist."""


class EdgeNotFoundError(GraphError):
    """Raised when a requested graph edge does not exist."""


class DuplicateNodeError(GraphError):
    """Raised when adding a node whose ID already exists."""


class DuplicateEdgeError(GraphError):
    """Raised when adding an edge whose globally unique ID already exists."""


class ArchitectureMismatchError(GraphError):
    """Raised when an edge would connect architecture-inconsistent entities."""


class GraphPersistenceError(GraphError):
    """Raised when a graph snapshot cannot be read, validated, or written."""


class GraphPath(DomainModel):
    """A directed simple path in a graph, not a vulnerability AttackChain."""

    architecture: Architecture
    node_ids: list[Identifier] = Field(min_length=1)
    edge_ids: list[Identifier] = Field(default_factory=list)
    hop_count: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_path_shape(self) -> "GraphPath":
        """Require a simple node path and one edge per hop."""

        if len(self.node_ids) != len(set(self.node_ids)):
            raise ValueError("a GraphPath must not repeat nodes")
        if self.hop_count != len(self.edge_ids):
            raise ValueError("hop_count must equal the number of edges")
        if len(self.node_ids) != self.hop_count + 1:
            raise ValueError("a path requires exactly one more node than edges")
        if len(self.edge_ids) != len(set(self.edge_ids)):
            raise ValueError("a GraphPath must not repeat edges")
        return self


class GraphSnapshot(DomainModel):
    """Stable, backend-neutral JSON representation of a behavior graph."""

    format: Literal["chipchain_graph"] = "chipchain_graph"
    format_version: Literal[1] = 1
    nodes: list[BehaviorNode] = Field(default_factory=list)
    edges: list[BehaviorEdge] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_graph_integrity(self) -> "GraphSnapshot":
        """Reject duplicate IDs, dangling endpoints, and cross-architecture edges."""

        node_by_id = {node.id: node for node in self.nodes}
        if len(node_by_id) != len(self.nodes):
            raise ValueError("snapshot node IDs must be unique")

        edge_ids = [edge.id for edge in self.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("snapshot edge IDs must be unique")

        for edge in self.edges:
            source = node_by_id.get(edge.source_id)
            target = node_by_id.get(edge.target_id)
            if source is None or target is None:
                raise ValueError(
                    f"edge {edge.id!r} references an unknown endpoint"
                )
            if (
                edge.architecture is not source.architecture
                or edge.architecture is not target.architecture
            ):
                raise ValueError(
                    f"edge {edge.id!r} architecture does not match its endpoints"
                )
        return self
