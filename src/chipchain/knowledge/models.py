"""Storage-neutral vulnerability knowledge graph data contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.knowledge.enums import KnowledgeNodeKind, KnowledgeRelationType
from chipchain.models import Architecture, Evidence, Layer
from chipchain.models.common import DomainModel, Identifier, Metadata

_GLOBAL_NODE_KINDS = frozenset(
    {KnowledgeNodeKind.CWE, KnowledgeNodeKind.CAPEC}
)


class KnowledgeNode(DomainModel):
    """One semantic vulnerability-knowledge entity, separate from behavior nodes."""

    id: Identifier
    kind: KnowledgeNodeKind
    label: Identifier
    architecture: Architecture | None
    layer: Layer | None = None
    external_ids: list[Identifier] = Field(default_factory=list)
    match_keys: list[Identifier] = Field(default_factory=list)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("external_ids", "match_keys", "evidence_ids")
    @classmethod
    def require_unique_identifiers(cls, values: list[str]) -> list[str]:
        """Reject ambiguous repeated identifiers within one node."""

        if len(values) != len(set(values)):
            raise ValueError("knowledge node identifier lists must be unique")
        return values

    @model_validator(mode="after")
    def validate_architecture_scope(self) -> "KnowledgeNode":
        """Keep only global taxonomies architecture-neutral."""

        is_global_kind = self.kind in _GLOBAL_NODE_KINDS
        if is_global_kind and self.architecture is not None:
            raise ValueError("CWE and CAPEC knowledge nodes must be global")
        if not is_global_kind and self.architecture is None:
            raise ValueError(
                "only CWE and CAPEC knowledge nodes may omit architecture"
            )
        if is_global_kind and self.layer is not None:
            raise ValueError("global CWE and CAPEC nodes must not declare a layer")
        return self


class KnowledgeEdge(DomainModel):
    """A typed, architecture-scoped semantic relation between knowledge nodes."""

    id: Identifier
    source_id: Identifier
    target_id: Identifier
    relation: KnowledgeRelationType
    architecture: Architecture
    evidence_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("evidence_ids")
    @classmethod
    def require_unique_evidence_ids(cls, values: list[str]) -> list[str]:
        """Reject repeated evidence references on one edge."""

        if len(values) != len(set(values)):
            raise ValueError("knowledge edge evidence IDs must be unique")
        return values


class KnowledgeGraphBundle(DomainModel):
    """Validated knowledge graph material derived from one or more samples."""

    architecture: Architecture
    sample_ids: list[Identifier] = Field(min_length=1)
    nodes: list[KnowledgeNode] = Field(default_factory=list)
    edges: list[KnowledgeEdge] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("sample_ids")
    @classmethod
    def require_unique_sample_ids(cls, values: list[str]) -> list[str]:
        """Each source sample may be represented only once."""

        if len(values) != len(set(values)):
            raise ValueError("knowledge bundle sample IDs must be unique")
        return values

    @model_validator(mode="after")
    def validate_graph_integrity(self) -> "KnowledgeGraphBundle":
        """Reject duplicates, dangling references, and architecture leakage."""

        _validate_graph_integrity(
            architecture=self.architecture,
            nodes=self.nodes,
            edges=self.edges,
            evidence=self.evidence,
        )
        return self


class KnowledgeGraphSnapshot(DomainModel):
    """Stable JSON envelope for the independent knowledge graph repository."""

    format: Literal["chipchain_knowledge_graph"] = "chipchain_knowledge_graph"
    format_version: Literal[1] = 1
    architecture: Architecture
    sample_ids: list[Identifier] = Field(default_factory=list)
    nodes: list[KnowledgeNode] = Field(default_factory=list)
    edges: list[KnowledgeEdge] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_graph_integrity(self) -> "KnowledgeGraphSnapshot":
        """Revalidate every persisted graph invariant during loading."""

        if len(self.sample_ids) != len(set(self.sample_ids)):
            raise ValueError("knowledge snapshot sample IDs must be unique")
        _validate_graph_integrity(
            architecture=self.architecture,
            nodes=self.nodes,
            edges=self.edges,
            evidence=self.evidence,
        )
        return self


def _validate_graph_integrity(
    *,
    architecture: Architecture,
    nodes: list[KnowledgeNode],
    edges: list[KnowledgeEdge],
    evidence: list[Evidence],
) -> None:
    """Validate invariants shared by bundles and persisted snapshots."""

    node_by_id = {node.id: node for node in nodes}
    if len(node_by_id) != len(nodes):
        raise ValueError("knowledge node IDs must be unique")

    edge_ids = [edge.id for edge in edges]
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("knowledge edge IDs must be unique")

    evidence_ids = [item.id for item in evidence]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("knowledge evidence IDs must be unique")
    evidence_id_set = set(evidence_ids)

    for node in nodes:
        if node.architecture is not None and node.architecture is not architecture:
            raise ValueError(
                f"knowledge node {node.id!r} architecture does not match bundle"
            )
        missing = set(node.evidence_ids).difference(evidence_id_set)
        if missing:
            raise ValueError(
                f"knowledge node {node.id!r} references unknown evidence"
            )

    for edge in edges:
        source = node_by_id.get(edge.source_id)
        target = node_by_id.get(edge.target_id)
        if source is None or target is None:
            raise ValueError(
                f"knowledge edge {edge.id!r} references an unknown endpoint"
            )
        if edge.architecture is not architecture:
            raise ValueError(
                f"knowledge edge {edge.id!r} architecture does not match bundle"
            )
        for endpoint in (source, target):
            if (
                endpoint.architecture is not None
                and endpoint.architecture is not edge.architecture
            ):
                raise ValueError(
                    f"knowledge edge {edge.id!r} architecture does not match endpoint"
                )
        missing = set(edge.evidence_ids).difference(evidence_id_set)
        if missing:
            raise ValueError(
                f"knowledge edge {edge.id!r} references unknown evidence"
            )
