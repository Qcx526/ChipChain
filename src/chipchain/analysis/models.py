"""Backend-neutral program analysis input and result contracts."""

from __future__ import annotations

from pydantic import Field, model_validator

from chipchain.models import Architecture, BehaviorEdge, BehaviorNode, Evidence
from chipchain.models.common import DomainModel, Identifier, Metadata


class ProgramArtifact(DomainModel):
    """A lightweight reference to a fixture, ELF, binary, or firmware image."""

    id: Identifier
    architecture: Architecture
    artifact_type: Identifier
    path: Identifier | None = None
    fixture_identifier: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_location(self) -> "ProgramArtifact":
        """Require a filesystem path or an adapter-specific fixture identifier."""

        if self.path is None and self.fixture_identifier is None:
            raise ValueError("an artifact requires a path or fixture_identifier")
        return self


class ProgramAnalysisResult(DomainModel):
    """Validated observable program behavior, without vulnerability conclusions."""

    artifact: ProgramArtifact
    architecture: Architecture
    nodes: list[BehaviorNode] = Field(default_factory=list)
    edges: list[BehaviorEdge] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_result_integrity(self) -> "ProgramAnalysisResult":
        """Enforce IDs, endpoints, architecture, and evidence references."""

        if self.artifact.architecture is not self.architecture:
            raise ValueError("artifact architecture must match result architecture")

        node_by_id = {node.id: node for node in self.nodes}
        if len(node_by_id) != len(self.nodes):
            raise ValueError("analysis result node IDs must be unique")

        edge_ids = [edge.id for edge in self.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("analysis result edge IDs must be unique")

        evidence_by_id = {item.id: item for item in self.evidence}
        if len(evidence_by_id) != len(self.evidence):
            raise ValueError("analysis result evidence IDs must be unique")

        for node in self.nodes:
            if node.architecture is not self.architecture:
                raise ValueError(
                    f"node {node.id!r} architecture must match result architecture"
                )

        for edge in self.edges:
            if edge.architecture is not self.architecture:
                raise ValueError(
                    f"edge {edge.id!r} architecture must match result architecture"
                )
            if edge.source_id not in node_by_id or edge.target_id not in node_by_id:
                raise ValueError(f"edge {edge.id!r} references an unknown endpoint")
            if not edge.evidence_ids:
                raise ValueError(f"edge {edge.id!r} requires analysis evidence")
            missing_ids = set(edge.evidence_ids).difference(evidence_by_id)
            if missing_ids:
                missing = ", ".join(sorted(missing_ids))
                raise ValueError(
                    f"edge {edge.id!r} references unknown evidence IDs: {missing}"
                )

        return self
