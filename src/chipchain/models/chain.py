"""Linear attack-chain models and cross-field invariants."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import (
    DomainModel,
    Identifier,
    Metadata,
    NonNegativeOrder,
    UnitInterval,
    utc_now,
)
from chipchain.models.enums import (
    Architecture,
    ChainStatus,
    EdgeVerificationStatus,
    EvidenceType,
    Layer,
    NodeKind,
    RelationType,
)
from chipchain.models.evidence import Evidence
from chipchain.models.hardware import Impact, RootCause


class AttackChainNode(DomainModel):
    """An ordered view of a domain or graph entity in a linear chain."""

    entity_id: Identifier
    order: NonNegativeOrder
    kind: NodeKind
    architecture: Architecture
    layer: Layer
    label: Identifier


class AttackChainEdge(DomainModel):
    """A relation between adjacent chain nodes with verification state."""

    id: Identifier
    source_id: Identifier
    target_id: Identifier
    relation: RelationType
    architecture: Architecture
    evidence_ids: list[Identifier] = Field(default_factory=list)
    verification_status: EdgeVerificationStatus = EdgeVerificationStatus.UNVERIFIED
    verification_messages: list[Identifier] = Field(default_factory=list)
    confidence: UnitInterval = 0.0


class AttackChain(DomainModel):
    """A portable, evidence-aware, strictly linear candidate attack chain."""

    id: Identifier
    architecture: Architecture
    status: ChainStatus
    nodes: list[AttackChainNode] = Field(min_length=1)
    edges: list[AttackChainEdge]
    evidence: list[Evidence] = Field(default_factory=list)
    entry: Identifier
    impacts: list[Impact] = Field(default_factory=list)
    root_causes: list[RootCause] = Field(default_factory=list)
    score: UnitInterval = 0.0
    score_components: dict[str, UnitInterval] = Field(default_factory=dict)
    evidence_coverage: UnitInterval = 0.0
    unmet_conditions: list[Identifier] = Field(default_factory=list)
    explanation: Identifier | None = None
    created_at: datetime = Field(default_factory=utc_now)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("created_at")
    @classmethod
    def validate_timezone_aware_datetime(cls, value: datetime) -> datetime:
        """Reject ambiguous naive timestamps."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value

    @field_validator("score_components")
    @classmethod
    def validate_score_component_names(
        cls, value: dict[str, float]
    ) -> dict[str, float]:
        """Require meaningful component names in addition to bounded values."""

        if any(not name.strip() for name in value):
            raise ValueError("score component names must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_linear_chain(self) -> "AttackChain":
        """Enforce ordering, connectivity, architecture, and evidence rules."""

        if not self.nodes:
            raise ValueError("an attack chain requires at least one node")

        expected_orders = list(range(len(self.nodes)))
        actual_orders = [node.order for node in self.nodes]
        if actual_orders != expected_orders:
            raise ValueError(
                "node orders must be unique, listed in order, and contiguous from zero"
            )

        entity_ids = [node.entity_id for node in self.nodes]
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("node entity IDs must be unique within a chain")

        if len(self.edges) != len(self.nodes) - 1:
            raise ValueError("a linear chain requires exactly len(nodes) - 1 edges")

        edge_ids = [edge.id for edge in self.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("edge IDs must be unique within a chain")

        for index, edge in enumerate(self.edges):
            expected_source = self.nodes[index].entity_id
            expected_target = self.nodes[index + 1].entity_id
            if (edge.source_id, edge.target_id) != (
                expected_source,
                expected_target,
            ):
                raise ValueError(
                    "each edge must connect its two adjacent ordered nodes"
                )

        if any(node.architecture is not self.architecture for node in self.nodes):
            raise ValueError("all node architectures must match the chain architecture")
        if any(edge.architecture is not self.architecture for edge in self.edges):
            raise ValueError("all edge architectures must match the chain architecture")
        if any(
            cause.architecture is not self.architecture for cause in self.root_causes
        ):
            raise ValueError(
                "all root-cause architectures must match the chain architecture"
            )

        evidence_by_id = {item.id: item for item in self.evidence}
        if len(evidence_by_id) != len(self.evidence):
            raise ValueError("evidence IDs must be unique within a chain")

        referenced_ids = {
            evidence_id
            for edge in self.edges
            for evidence_id in edge.evidence_ids
        }
        referenced_ids.update(
            evidence_id
            for cause in self.root_causes
            for evidence_id in cause.evidence_ids
        )
        missing_ids = referenced_ids.difference(evidence_by_id)
        if missing_ids:
            missing = ", ".join(sorted(missing_ids))
            raise ValueError(f"chain contains unknown evidence IDs: {missing}")

        if self.status is ChainStatus.VERIFIED:
            for edge in self.edges:
                if edge.verification_status is not EdgeVerificationStatus.VERIFIED:
                    raise ValueError("every edge in a verified chain must be verified")
                if not edge.evidence_ids:
                    raise ValueError("every edge in a verified chain requires evidence")
                edge_evidence = [evidence_by_id[item] for item in edge.evidence_ids]
                if not any(
                    item.verified and item.type is not EvidenceType.LLM_SEMANTIC
                    for item in edge_evidence
                ):
                    raise ValueError(
                        "verified edges require verified non-LLM evidence"
                    )

        return self
