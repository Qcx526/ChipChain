"""NetworkX MultiDiGraph vulnerability knowledge repository."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Self

import networkx as nx
from pydantic import TypeAdapter, ValidationError

from chipchain.knowledge.enums import KnowledgeNodeKind, KnowledgeRelationType
from chipchain.knowledge.errors import (
    DuplicateKnowledgeEdgeError,
    DuplicateKnowledgeEvidenceError,
    DuplicateKnowledgeNodeError,
    KnowledgeArchitectureMismatchError,
    KnowledgeEdgeNotFoundError,
    KnowledgeEvidenceNotFoundError,
    KnowledgeNodeNotFoundError,
    KnowledgePersistenceError,
)
from chipchain.knowledge.models import (
    KnowledgeEdge,
    KnowledgeGraphBundle,
    KnowledgeGraphSnapshot,
    KnowledgeNode,
)
from chipchain.knowledge.repository import KnowledgeGraphRepository
from chipchain.models import Architecture, Evidence
from chipchain.models.common import Metadata

_METADATA_ADAPTER = TypeAdapter(Metadata)


class NetworkXKnowledgeGraphRepository(KnowledgeGraphRepository):
    """Architecture-scoped knowledge graph backed by ``nx.MultiDiGraph``."""

    def __init__(
        self,
        *,
        architecture: Architecture,
        sample_ids: list[str] | None = None,
        metadata: Metadata | None = None,
    ) -> None:
        """Create an empty repository with validated scope and metadata."""

        self._architecture = Architecture(architecture)
        normalized_sample_ids = sorted(sample_ids or [])
        if len(normalized_sample_ids) != len(set(normalized_sample_ids)):
            raise ValueError("knowledge repository sample IDs must be unique")
        self._sample_ids = normalized_sample_ids
        self._metadata = _METADATA_ADAPTER.validate_python(metadata or {})
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._edge_index: dict[str, tuple[str, str]] = {}
        self._evidence: dict[str, dict[str, object]] = {}

    @property
    def architecture(self) -> Architecture:
        """Return the immutable architecture scope."""

        return self._architecture

    @property
    def sample_ids(self) -> list[str]:
        """Return a detached source sample ID list."""

        return list(self._sample_ids)

    @property
    def metadata(self) -> Metadata:
        """Return detached metadata so callers cannot mutate repository state."""

        return deepcopy(self._metadata)

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence without silent replacement."""

        if evidence.id in self._evidence:
            raise DuplicateKnowledgeEvidenceError(
                f"evidence {evidence.id!r} already exists"
            )
        self._evidence[evidence.id] = evidence.model_dump(mode="json")

    def add_node(self, node: KnowledgeNode) -> None:
        """Add one architecture-consistent node with valid evidence references."""

        if node.id in self._graph:
            raise DuplicateKnowledgeNodeError(f"node {node.id!r} already exists")
        if (
            node.architecture is not None
            and node.architecture is not self.architecture
        ):
            raise KnowledgeArchitectureMismatchError(
                f"node {node.id!r} does not match repository architecture"
            )
        self._require_evidence(node.evidence_ids, owner=f"node {node.id!r}")
        self._graph.add_node(node.id, **node.model_dump(mode="json"))

    def add_edge(self, edge: KnowledgeEdge) -> None:
        """Add an edge with existing endpoints and evidence."""

        if edge.id in self._edge_index:
            raise DuplicateKnowledgeEdgeError(f"edge {edge.id!r} already exists")
        if edge.source_id not in self._graph:
            raise KnowledgeNodeNotFoundError(
                f"source node {edge.source_id!r} does not exist"
            )
        if edge.target_id not in self._graph:
            raise KnowledgeNodeNotFoundError(
                f"target node {edge.target_id!r} does not exist"
            )
        if edge.architecture is not self.architecture:
            raise KnowledgeArchitectureMismatchError(
                f"edge {edge.id!r} does not match repository architecture"
            )
        source = self.get_node(edge.source_id)
        target = self.get_node(edge.target_id)
        for endpoint in (source, target):
            if (
                endpoint.architecture is not None
                and endpoint.architecture is not edge.architecture
            ):
                raise KnowledgeArchitectureMismatchError(
                    f"edge {edge.id!r} architecture does not match endpoints"
                )
        self._require_evidence(edge.evidence_ids, owner=f"edge {edge.id!r}")
        self._graph.add_edge(
            edge.source_id,
            edge.target_id,
            key=edge.id,
            **edge.model_dump(mode="json"),
        )
        self._edge_index[edge.id] = (edge.source_id, edge.target_id)

    def get_evidence(self, evidence_id: str) -> Evidence:
        """Return a freshly validated evidence model."""

        data = self._evidence.get(evidence_id)
        if data is None:
            raise KnowledgeEvidenceNotFoundError(
                f"evidence {evidence_id!r} does not exist"
            )
        return Evidence.model_validate(dict(data))

    def get_node(self, node_id: str) -> KnowledgeNode:
        """Return a freshly validated knowledge node."""

        if node_id not in self._graph:
            raise KnowledgeNodeNotFoundError(f"node {node_id!r} does not exist")
        return KnowledgeNode.model_validate(dict(self._graph.nodes[node_id]))

    def get_edge(self, edge_id: str) -> KnowledgeEdge:
        """Return a freshly validated knowledge edge."""

        location = self._edge_index.get(edge_id)
        if location is None:
            raise KnowledgeEdgeNotFoundError(f"edge {edge_id!r} does not exist")
        source_id, target_id = location
        data = self._graph.get_edge_data(source_id, target_id, key=edge_id)
        if data is None:
            raise KnowledgeEdgeNotFoundError(f"edge {edge_id!r} does not exist")
        return KnowledgeEdge.model_validate(dict(data))

    def list_evidence(self) -> list[Evidence]:
        """List evidence in deterministic stable-ID order."""

        return [self.get_evidence(item) for item in sorted(self._evidence)]

    def list_nodes(
        self, *, kind: KnowledgeNodeKind | None = None
    ) -> list[KnowledgeNode]:
        """List nodes in deterministic stable-ID order."""

        normalized_kind = KnowledgeNodeKind(kind) if kind is not None else None
        nodes = [self.get_node(item) for item in sorted(self._graph.nodes)]
        if normalized_kind is None:
            return nodes
        return [node for node in nodes if node.kind is normalized_kind]

    def list_edges(
        self, *, relation: KnowledgeRelationType | None = None
    ) -> list[KnowledgeEdge]:
        """List edges in deterministic global-ID order."""

        normalized_relation = (
            KnowledgeRelationType(relation) if relation is not None else None
        )
        edges = [self.get_edge(item) for item in sorted(self._edge_index)]
        if normalized_relation is None:
            return edges
        return [edge for edge in edges if edge.relation is normalized_relation]

    def successors(self, node_id: str) -> list[KnowledgeNode]:
        """Return unique direct successors regardless of parallel relations."""

        self.get_node(node_id)
        return [self.get_node(item) for item in sorted(self._graph.successors(node_id))]

    def predecessors(self, node_id: str) -> list[KnowledgeNode]:
        """Return unique direct predecessors regardless of parallel relations."""

        self.get_node(node_id)
        return [
            self.get_node(item) for item in sorted(self._graph.predecessors(node_id))
        ]

    def add_bundle(self, bundle: KnowledgeGraphBundle) -> None:
        """Populate an empty compatible repository from a validated bundle."""

        if bundle.architecture is not self.architecture:
            raise KnowledgeArchitectureMismatchError(
                "bundle does not match repository architecture"
            )
        if self._graph or self._edge_index or self._evidence:
            raise ValueError("add_bundle requires an empty repository")
        for item in bundle.evidence:
            self.add_evidence(item)
        for node in bundle.nodes:
            self.add_node(node)
        for edge in bundle.edges:
            self.add_edge(edge)
        self._sample_ids = sorted(set(self._sample_ids).union(bundle.sample_ids))

    @classmethod
    def from_bundle(
        cls, bundle: KnowledgeGraphBundle
    ) -> "NetworkXKnowledgeGraphRepository":
        """Create and populate a repository from one validated bundle."""

        repository = cls(
            architecture=bundle.architecture,
            sample_ids=bundle.sample_ids,
            metadata=bundle.metadata,
        )
        repository.add_bundle(bundle)
        return repository

    def save(self, path: str | Path) -> None:
        """Write a deterministic snapshot through an atomic replacement."""

        destination = Path(path)
        snapshot = KnowledgeGraphSnapshot(
            architecture=self.architecture,
            sample_ids=self.sample_ids,
            nodes=self.list_nodes(),
            edges=self.list_edges(),
            evidence=self.list_evidence(),
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
            raise KnowledgePersistenceError(
                f"failed to save knowledge graph snapshot to {destination}"
            ) from exc

    @classmethod
    def load(cls, path: str | Path) -> Self:
        """Load JSON and revalidate models plus cross-entity invariants."""

        source = Path(path)
        try:
            raw_data = json.loads(source.read_text(encoding="utf-8"))
            snapshot = KnowledgeGraphSnapshot.model_validate(raw_data)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise KnowledgePersistenceError(
                f"failed to load valid knowledge graph snapshot from {source}"
            ) from exc

        repository = cls(
            architecture=snapshot.architecture,
            sample_ids=snapshot.sample_ids,
            metadata=snapshot.metadata,
        )
        for item in snapshot.evidence:
            repository.add_evidence(item)
        for node in snapshot.nodes:
            repository.add_node(node)
        for edge in snapshot.edges:
            repository.add_edge(edge)
        return repository

    def _require_evidence(self, evidence_ids: list[str], *, owner: str) -> None:
        missing = sorted(set(evidence_ids).difference(self._evidence))
        if missing:
            raise KnowledgeEvidenceNotFoundError(
                f"{owner} references unknown evidence: {', '.join(missing)}"
            )
