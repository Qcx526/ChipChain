"""NetworkX MultiDiGraph implementation of the graph repository."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import AbstractSet, Any, Self

import networkx as nx
from pydantic import TypeAdapter, ValidationError

from chipchain.graph.repository import GraphRepository
from chipchain.graph.types import (
    ArchitectureMismatchError,
    DuplicateEdgeError,
    DuplicateNodeError,
    EdgeNotFoundError,
    GraphPath,
    GraphPersistenceError,
    GraphSnapshot,
    NodeNotFoundError,
)
from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Layer,
    RelationType,
)
from chipchain.models.common import Metadata

_METADATA_ADAPTER = TypeAdapter(Metadata)


class NetworkXGraphRepository(GraphRepository):
    """In-memory behavior graph backed by ``networkx.MultiDiGraph``."""

    def __init__(self, *, metadata: Metadata | None = None) -> None:
        """Create an empty repository with validated JSON metadata."""

        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._edge_index: dict[str, tuple[str, str]] = {}
        self._metadata = _METADATA_ADAPTER.validate_python(metadata or {})

    @property
    def metadata(self) -> Metadata:
        """Return a detached copy so callers cannot mutate repository state."""

        return deepcopy(self._metadata)

    def add_node(self, node: BehaviorNode) -> None:
        """Add a validated node without silently overwriting an existing ID."""

        if node.id in self._graph:
            raise DuplicateNodeError(f"node {node.id!r} already exists")
        self._graph.add_node(node.id, **node.model_dump(mode="json"))

    def add_edge(self, edge: BehaviorEdge) -> None:
        """Add an architecture-consistent edge using its ID as graph key."""

        if edge.id in self._edge_index:
            raise DuplicateEdgeError(f"edge {edge.id!r} already exists")
        if edge.source_id not in self._graph:
            raise NodeNotFoundError(f"source node {edge.source_id!r} does not exist")
        if edge.target_id not in self._graph:
            raise NodeNotFoundError(f"target node {edge.target_id!r} does not exist")

        source = self.get_node(edge.source_id)
        target = self.get_node(edge.target_id)
        if (
            edge.architecture is not source.architecture
            or edge.architecture is not target.architecture
        ):
            raise ArchitectureMismatchError(
                f"edge {edge.id!r} architecture must match both endpoints"
            )

        self._graph.add_edge(
            edge.source_id,
            edge.target_id,
            key=edge.id,
            **edge.model_dump(mode="json"),
        )
        self._edge_index[edge.id] = (edge.source_id, edge.target_id)

    def get_node(self, node_id: str) -> BehaviorNode:
        """Return a freshly validated node model."""

        if node_id not in self._graph:
            raise NodeNotFoundError(f"node {node_id!r} does not exist")
        return BehaviorNode.model_validate(dict(self._graph.nodes[node_id]))

    def get_edge(self, edge_id: str) -> BehaviorEdge:
        """Return a freshly validated edge located through the global ID index."""

        location = self._edge_index.get(edge_id)
        if location is None:
            raise EdgeNotFoundError(f"edge {edge_id!r} does not exist")
        source_id, target_id = location
        data = self._graph.get_edge_data(source_id, target_id, key=edge_id)
        if data is None:  # Defensive consistency check for backend corruption.
            raise EdgeNotFoundError(f"edge {edge_id!r} does not exist")
        return BehaviorEdge.model_validate(dict(data))

    def list_nodes(
        self,
        *,
        architecture: Architecture | None = None,
        allowed_layers: AbstractSet[Layer] | None = None,
    ) -> list[BehaviorNode]:
        """Return filtered nodes sorted by stable node ID."""

        normalized_architecture = (
            Architecture(architecture) if architecture is not None else None
        )
        normalized_layers = self._normalize_layers(allowed_layers)
        nodes = []
        for node_id in sorted(self._graph.nodes):
            node = self.get_node(node_id)
            if (
                normalized_architecture is not None
                and node.architecture is not normalized_architecture
            ):
                continue
            if normalized_layers is not None and node.layer not in normalized_layers:
                continue
            nodes.append(node)
        return nodes

    def list_edges(
        self,
        *,
        architecture: Architecture | None = None,
        relation: RelationType | None = None,
    ) -> list[BehaviorEdge]:
        """Return filtered edges sorted by globally unique edge ID."""

        normalized_architecture = (
            Architecture(architecture) if architecture is not None else None
        )
        normalized_relation = RelationType(relation) if relation is not None else None
        edges = []
        for edge_id in sorted(self._edge_index):
            edge = self.get_edge(edge_id)
            if (
                normalized_architecture is not None
                and edge.architecture is not normalized_architecture
            ):
                continue
            if normalized_relation is not None and edge.relation is not normalized_relation:
                continue
            edges.append(edge)
        return edges

    def remove_node(self, node_id: str) -> BehaviorNode:
        """Remove a node and clean all incident edge IDs from the index."""

        node = self.get_node(node_id)
        incident_edge_ids = {
            edge_id for _, _, edge_id in self._graph.in_edges(node_id, keys=True)
        }
        incident_edge_ids.update(
            edge_id for _, _, edge_id in self._graph.out_edges(node_id, keys=True)
        )
        self._graph.remove_node(node_id)
        for edge_id in incident_edge_ids:
            self._edge_index.pop(edge_id, None)
        return node

    def remove_edge(self, edge_id: str) -> BehaviorEdge:
        """Remove an edge without affecting parallel relations."""

        edge = self.get_edge(edge_id)
        self._graph.remove_edge(edge.source_id, edge.target_id, key=edge.id)
        del self._edge_index[edge.id]
        return edge

    def successors(self, node_id: str) -> list[BehaviorNode]:
        """Return unique direct successors, independent of parallel edge count."""

        self.get_node(node_id)
        return [self.get_node(item) for item in sorted(self._graph.successors(node_id))]

    def predecessors(self, node_id: str) -> list[BehaviorNode]:
        """Return unique direct predecessors, independent of parallel edge count."""

        self.get_node(node_id)
        return [
            self.get_node(item) for item in sorted(self._graph.predecessors(node_id))
        ]

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
        """Find deterministic directed simple paths while filtering during traversal."""

        if max_hops < 0:
            raise ValueError("max_hops must be non-negative")
        if max_results is not None and max_results <= 0:
            raise ValueError("max_results must be positive when provided")

        normalized_architecture = Architecture(architecture)
        normalized_layers = self._normalize_layers(allowed_layers)
        start = self.get_node(start_id)
        target = self.get_node(target_id) if target_id is not None else None

        if start.architecture is not normalized_architecture:
            return []
        if normalized_layers is not None and start.layer not in normalized_layers:
            return []
        if target is not None:
            if target.architecture is not normalized_architecture:
                return []
            if normalized_layers is not None and target.layer not in normalized_layers:
                return []
            if target.id == start.id:
                return [
                    GraphPath(
                        architecture=normalized_architecture,
                        node_ids=[start.id],
                        edge_ids=[],
                        hop_count=0,
                    )
                ]

        results: list[GraphPath] = []

        def walk(node_ids: list[str], edge_ids: list[str]) -> None:
            if len(edge_ids) >= max_hops:
                return

            current_id = node_ids[-1]
            outgoing: list[tuple[str, str, str, dict[str, Any]]] = sorted(
                self._graph.out_edges(current_id, keys=True, data=True),
                key=lambda item: (item[1], item[2]),
            )
            for _, next_id, edge_id, edge_data in outgoing:
                if next_id in node_ids:
                    continue

                edge = BehaviorEdge.model_validate(dict(edge_data))
                next_node = self.get_node(next_id)
                if edge.architecture is not normalized_architecture:
                    continue
                if next_node.architecture is not normalized_architecture:
                    continue
                if (
                    normalized_layers is not None
                    and next_node.layer not in normalized_layers
                ):
                    continue

                next_node_ids = [*node_ids, next_id]
                next_edge_ids = [*edge_ids, edge_id]
                reached_target = target is not None and next_id == target.id
                if target is None or reached_target:
                    results.append(
                        GraphPath(
                            architecture=normalized_architecture,
                            node_ids=next_node_ids,
                            edge_ids=next_edge_ids,
                            hop_count=len(next_edge_ids),
                        )
                    )
                if not reached_target:
                    walk(next_node_ids, next_edge_ids)

        walk([start.id], [])
        results.sort(
            key=lambda path: (
                path.hop_count,
                tuple(path.node_ids),
                tuple(path.edge_ids),
            )
        )
        return results[:max_results] if max_results is not None else results

    def save(self, path: str | Path) -> None:
        """Write a deterministic JSON snapshot using an atomic replacement."""

        destination = Path(path)
        snapshot = GraphSnapshot(
            nodes=self.list_nodes(),
            edges=self.list_edges(),
            metadata=self.metadata,
        )
        payload = json.dumps(
            snapshot.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        temporary = destination.with_suffix(f"{destination.suffix}.tmp")
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(payload + "\n", encoding="utf-8")
            temporary.replace(destination)
        except OSError as exc:
            raise GraphPersistenceError(
                f"failed to save graph snapshot to {destination}"
            ) from exc

    @classmethod
    def load(cls, path: str | Path) -> Self:
        """Load JSON and revalidate every node, edge, and graph invariant."""

        source = Path(path)
        try:
            raw_data = json.loads(source.read_text(encoding="utf-8"))
            snapshot = GraphSnapshot.model_validate(raw_data)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise GraphPersistenceError(
                f"failed to load valid graph snapshot from {source}"
            ) from exc

        repository = cls(metadata=snapshot.metadata)
        for node in snapshot.nodes:
            repository.add_node(node)
        for edge in snapshot.edges:
            repository.add_edge(edge)
        return repository

    @staticmethod
    def _normalize_layers(
        allowed_layers: AbstractSet[Layer] | None,
    ) -> frozenset[Layer] | None:
        """Normalize optional public layer filters to stable enum members."""

        if allowed_layers is None:
            return None
        return frozenset(Layer(item) for item in allowed_layers)
