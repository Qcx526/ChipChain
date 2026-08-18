"""Strict pre-AttackChain models for cross-graph candidate correlation."""

from __future__ import annotations

import hashlib
import json

from pydantic import Field, field_validator, model_validator

from chipchain.candidate.enums import EntityLinkMethod
from chipchain.graph import GraphPath
from chipchain.knowledge import KnowledgeNodeKind
from chipchain.models import Architecture, Layer, NodeKind
from chipchain.models.common import DomainModel, Identifier, Metadata

_BEHAVIOR_HARDWARE_KINDS = frozenset(
    {NodeKind.REGISTER, NodeKind.HARDWARE_RESOURCE}
)
_CANDIDATE_BEHAVIOR_LAYERS = frozenset(
    {Layer.FIRMWARE, Layer.DRIVER, Layer.INTERFACE, Layer.HARDWARE}
)


def entity_link_id(
    architecture: Architecture,
    behavior_node_id: str,
    knowledge_node_id: str,
) -> str:
    """Return a compact deterministic identity for one exact entity pair."""

    digest = _stable_digest(
        [architecture.value, behavior_node_id, knowledge_node_id]
    )
    return f"entity-link:{architecture.value}:{digest}"


class EntityLink(DomainModel):
    """An exact identity anchor between two graphs, not an AttackChain edge."""

    id: Identifier
    architecture: Architecture
    behavior_node_id: Identifier
    knowledge_node_id: Identifier
    behavior_node_kind: NodeKind
    knowledge_node_kind: KnowledgeNodeKind
    match_keys: list[Identifier] = Field(min_length=1)
    link_method: EntityLinkMethod = EntityLinkMethod.EXACT_CANONICAL_KEY
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("match_keys")
    @classmethod
    def normalize_match_keys(cls, values: list[str]) -> list[str]:
        """Require unique exact anchors and store them deterministically."""

        if len(values) != len(set(values)):
            raise ValueError("EntityLink match keys must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_exact_hardware_link(self) -> "EntityLink":
        """Enforce deterministic identity and the Phase 6 hardware-only scope."""

        expected_id = entity_link_id(
            self.architecture,
            self.behavior_node_id,
            self.knowledge_node_id,
        )
        if self.id != expected_id:
            raise ValueError("EntityLink ID does not match its deterministic identity")
        if self.behavior_node_kind not in _BEHAVIOR_HARDWARE_KINDS:
            raise ValueError("EntityLink behavior endpoint must be hardware")
        if self.knowledge_node_kind is not KnowledgeNodeKind.HARDWARE_RESOURCE:
            raise ValueError("EntityLink knowledge endpoint must be a hardware resource")
        prefix = f"arch:{self.architecture.value}:"
        if any(not key.startswith(prefix) for key in self.match_keys):
            raise ValueError("EntityLink match keys must match link architecture")
        return self

    @classmethod
    def create(
        cls,
        *,
        architecture: Architecture,
        behavior_node_id: str,
        knowledge_node_id: str,
        behavior_node_kind: NodeKind,
        knowledge_node_kind: KnowledgeNodeKind,
        match_keys: list[str],
        metadata: Metadata | None = None,
    ) -> "EntityLink":
        """Create a link with its reproducible stable ID."""

        return cls(
            id=entity_link_id(
                architecture,
                behavior_node_id,
                knowledge_node_id,
            ),
            architecture=architecture,
            behavior_node_id=behavior_node_id,
            knowledge_node_id=knowledge_node_id,
            behavior_node_kind=behavior_node_kind,
            knowledge_node_kind=knowledge_node_kind,
            match_keys=match_keys,
            metadata=metadata or {},
        )


class EntityLinkResult(DomainModel):
    """Independent exact-linking output for direct evaluation and diagnostics."""

    architecture: Architecture
    links: list[EntityLink] = Field(default_factory=list)
    unmatched_behavior_node_ids: list[Identifier] = Field(default_factory=list)
    unmatched_knowledge_node_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "unmatched_behavior_node_ids", "unmatched_knowledge_node_ids"
    )
    @classmethod
    def normalize_unmatched_ids(cls, values: list[str]) -> list[str]:
        """Reject duplicates and provide deterministic diagnostics."""

        if len(values) != len(set(values)):
            raise ValueError("unmatched entity IDs must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_links(self) -> "EntityLinkResult":
        """Keep link IDs unique and architecture-consistent."""

        link_ids = [link.id for link in self.links]
        if len(link_ids) != len(set(link_ids)):
            raise ValueError("EntityLinkResult link IDs must be unique")
        if any(link.architecture is not self.architecture for link in self.links):
            raise ValueError("all links must match result architecture")
        return self


def cross_graph_candidate_id(
    architecture: Architecture,
    behavior_path: GraphPath,
    entity_link: EntityLink,
    knowledge_vulnerability_id: str,
) -> str:
    """Return a deterministic identity for one structural correlation."""

    digest = _stable_digest(
        [
            architecture.value,
            *behavior_path.node_ids,
            "--edges--",
            *behavior_path.edge_ids,
            "--link--",
            entity_link.id,
            "--vulnerability--",
            knowledge_vulnerability_id,
        ]
    )
    return f"cross-graph-candidate:{architecture.value}:{digest}"


class CrossGraphCandidate(DomainModel):
    """A behavior path exactly correlated with vulnerability knowledge context.

    This is an unverified structural correlation. It is neither a verified
    AttackChain nor a claim of vulnerability presence or exploitability.
    """

    id: Identifier
    architecture: Architecture
    behavior_path: GraphPath
    behavior_layers: list[Layer] = Field(min_length=1)
    entity_link: EntityLink
    knowledge_vulnerability_id: Identifier
    knowledge_anchor_node_id: Identifier
    knowledge_edge_ids: list[Identifier] = Field(min_length=1)
    component_node_ids: list[Identifier] = Field(default_factory=list)
    trigger_node_ids: list[Identifier] = Field(default_factory=list)
    precondition_node_ids: list[Identifier] = Field(default_factory=list)
    cwe_node_ids: list[Identifier] = Field(default_factory=list)
    capec_node_ids: list[Identifier] = Field(default_factory=list)
    behavior_node_ids: list[Identifier] = Field(default_factory=list)
    interface_node_ids: list[Identifier] = Field(default_factory=list)
    hardware_resource_node_ids: list[Identifier] = Field(default_factory=list)
    security_mechanism_node_ids: list[Identifier] = Field(default_factory=list)
    impact_node_ids: list[Identifier] = Field(default_factory=list)
    root_cause_node_ids: list[Identifier] = Field(default_factory=list)
    behavior_evidence_ids: list[Identifier] = Field(default_factory=list)
    knowledge_evidence_ids: list[Identifier] = Field(default_factory=list)
    knowledge_evidence_count: int = Field(ge=0)
    missing_knowledge_evidence: bool
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "knowledge_edge_ids",
        "component_node_ids",
        "trigger_node_ids",
        "precondition_node_ids",
        "cwe_node_ids",
        "capec_node_ids",
        "behavior_node_ids",
        "interface_node_ids",
        "hardware_resource_node_ids",
        "security_mechanism_node_ids",
        "impact_node_ids",
        "root_cause_node_ids",
        "behavior_evidence_ids",
        "knowledge_evidence_ids",
    )
    @classmethod
    def normalize_unique_ids(cls, values: list[str]) -> list[str]:
        """Reject repeated references and store each catalog deterministically."""

        if len(values) != len(set(values)):
            raise ValueError("CrossGraphCandidate ID lists must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_candidate_correlation(self) -> "CrossGraphCandidate":
        """Enforce architecture, anchor, cross-layer, and stable-ID invariants."""

        if self.behavior_path.architecture is not self.architecture:
            raise ValueError("behavior path architecture must match candidate")
        if self.entity_link.architecture is not self.architecture:
            raise ValueError("EntityLink architecture must match candidate")
        if self.behavior_path.node_ids[-1] != self.entity_link.behavior_node_id:
            raise ValueError("behavior path must end at the linked behavior anchor")
        if self.knowledge_anchor_node_id != self.entity_link.knowledge_node_id:
            raise ValueError("knowledge anchor must equal the linked knowledge node")
        if len(self.behavior_layers) != len(self.behavior_path.node_ids):
            raise ValueError("behavior layers must align with behavior path nodes")
        if any(layer not in _CANDIDATE_BEHAVIOR_LAYERS for layer in self.behavior_layers):
            raise ValueError("candidate behavior path contains a disallowed layer")
        if len(set(self.behavior_layers)) < 2:
            raise ValueError("candidate behavior path must cross at least two layers")
        if Layer.HARDWARE not in self.behavior_layers:
            raise ValueError("candidate behavior path must include hardware")
        if self.knowledge_evidence_count != len(self.knowledge_evidence_ids):
            raise ValueError("knowledge evidence count must match evidence IDs")
        if not self.knowledge_evidence_ids and not self.missing_knowledge_evidence:
            raise ValueError("empty knowledge evidence must be reported as missing")
        expected_id = cross_graph_candidate_id(
            self.architecture,
            self.behavior_path,
            self.entity_link,
            self.knowledge_vulnerability_id,
        )
        if self.id != expected_id:
            raise ValueError(
                "CrossGraphCandidate ID does not match its deterministic identity"
            )
        return self


def _stable_digest(parts: list[str]) -> str:
    encoded = json.dumps(
        parts,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]
