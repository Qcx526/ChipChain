"""Exact, hardware-only entity linking across independent repositories."""

from __future__ import annotations

from chipchain.candidate.errors import CandidateArchitectureMismatchError
from chipchain.candidate.models import EntityLink, EntityLinkResult
from chipchain.graph import GraphRepository
from chipchain.knowledge import (
    KnowledgeGraphRepository,
    KnowledgeNodeKind,
    hardware_resource_match_keys,
)
from chipchain.models import Architecture, Layer, NodeKind

_BEHAVIOR_HARDWARE_KINDS = frozenset(
    {NodeKind.REGISTER, NodeKind.HARDWARE_RESOURCE}
)


class ExactHardwareEntityLinker:
    """Link hardware entities only through exact canonical-key intersection."""

    def link(
        self,
        behavior_repository: GraphRepository,
        knowledge_repository: KnowledgeGraphRepository,
        *,
        architecture: Architecture,
    ) -> EntityLinkResult:
        """Return all exact one-to-many links without modifying either graph."""

        normalized_architecture = Architecture(architecture)
        if knowledge_repository.architecture is not normalized_architecture:
            raise CandidateArchitectureMismatchError(
                "knowledge repository does not match linking architecture"
            )

        behavior_nodes = [
            node
            for node in behavior_repository.list_nodes(
                architecture=normalized_architecture,
                allowed_layers={Layer.HARDWARE},
            )
            if node.kind in _BEHAVIOR_HARDWARE_KINDS
        ]
        knowledge_nodes = [
            node
            for node in knowledge_repository.list_nodes(
                kind=KnowledgeNodeKind.HARDWARE_RESOURCE
            )
            if node.architecture is normalized_architecture
        ]

        behavior_keys = {
            node.id: hardware_resource_match_keys(
                node.architecture,
                address=node.address,
                metadata=node.metadata,
            )
            for node in behavior_nodes
        }
        links: list[EntityLink] = []
        linked_behavior_ids: set[str] = set()
        linked_knowledge_ids: set[str] = set()
        for behavior_node in behavior_nodes:
            keys = set(behavior_keys[behavior_node.id])
            if not keys:
                continue
            for knowledge_node in knowledge_nodes:
                intersection = sorted(keys.intersection(knowledge_node.match_keys))
                if not intersection:
                    continue
                links.append(
                    EntityLink.create(
                        architecture=normalized_architecture,
                        behavior_node_id=behavior_node.id,
                        knowledge_node_id=knowledge_node.id,
                        behavior_node_kind=behavior_node.kind,
                        knowledge_node_kind=knowledge_node.kind,
                        match_keys=intersection,
                        metadata={
                            "scope": "hardware_anchor",
                            "claim": "exact_identity_correlation_only",
                        },
                    )
                )
                linked_behavior_ids.add(behavior_node.id)
                linked_knowledge_ids.add(knowledge_node.id)

        links.sort(
            key=lambda item: (
                item.behavior_node_id,
                item.knowledge_node_id,
                item.id,
            )
        )
        return EntityLinkResult(
            architecture=normalized_architecture,
            links=links,
            unmatched_behavior_node_ids=sorted(
                node.id
                for node in behavior_nodes
                if node.id not in linked_behavior_ids
            ),
            unmatched_knowledge_node_ids=sorted(
                node.id
                for node in knowledge_nodes
                if node.id not in linked_knowledge_ids
            ),
            metadata={
                "link_method": "exact_canonical_key",
                "behavior_hardware_node_count": len(behavior_nodes),
                "knowledge_hardware_node_count": len(knowledge_nodes),
            },
        )
