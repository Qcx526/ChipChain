"""Storage-independent behavior graph data contracts."""

from __future__ import annotations

from pydantic import Field

from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture, Layer, NodeKind, RelationType


class BehaviorNode(DomainModel):
    """A node that can be inserted into a future GraphRepository."""

    id: Identifier
    kind: NodeKind
    name: Identifier
    architecture: Architecture
    layer: Layer
    address: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)


class BehaviorEdge(DomainModel):
    """A typed edge referencing graph nodes and supporting evidence by ID."""

    id: Identifier
    source_id: Identifier
    target_id: Identifier
    relation: RelationType
    architecture: Architecture
    evidence_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)
