"""Deterministic candidate correlation over separate behavior and knowledge graphs."""

from __future__ import annotations

from collections.abc import Iterable

from chipchain.candidate.errors import (
    CandidateArchitectureMismatchError,
    InvalidKnowledgeContextError,
)
from chipchain.candidate.linking import ExactHardwareEntityLinker
from chipchain.candidate.models import (
    CrossGraphCandidate,
    EntityLink,
    cross_graph_candidate_id,
)
from chipchain.graph import GraphPath, GraphRepository
from chipchain.knowledge import (
    KnowledgeEdge,
    KnowledgeGraphRepository,
    KnowledgeNode,
    KnowledgeNodeKind,
    KnowledgeRelationType,
)
from chipchain.models import Architecture, Layer, RelationType

ARM_CANDIDATE_LAYERS = frozenset(
    {Layer.FIRMWARE, Layer.DRIVER, Layer.INTERFACE, Layer.HARDWARE}
)
ARM_CANDIDATE_RELATIONS = frozenset(
    {
        RelationType.CALLS,
        RelationType.ISSUES,
        RelationType.INVOKES,
        RelationType.DATA_FLOWS_TO,
        RelationType.MMIO_READ,
        RelationType.MMIO_WRITE,
        RelationType.ACCESSES,
    }
)

_CONTEXT_KIND_BY_RELATION = {
    KnowledgeRelationType.HAS_CWE: KnowledgeNodeKind.CWE,
    KnowledgeRelationType.HAS_CAPEC: KnowledgeNodeKind.CAPEC,
    KnowledgeRelationType.AFFECTS_COMPONENT: KnowledgeNodeKind.COMPONENT,
    KnowledgeRelationType.HAS_TRIGGER: KnowledgeNodeKind.TRIGGER,
    KnowledgeRelationType.REQUIRES_PRECONDITION: KnowledgeNodeKind.PRECONDITION,
    KnowledgeRelationType.INVOLVES_BEHAVIOR: KnowledgeNodeKind.BEHAVIOR,
    KnowledgeRelationType.USES_INTERFACE: KnowledgeNodeKind.INTERFACE,
    KnowledgeRelationType.TARGETS_RESOURCE: KnowledgeNodeKind.HARDWARE_RESOURCE,
    KnowledgeRelationType.INVOLVES_SECURITY_MECHANISM: (
        KnowledgeNodeKind.SECURITY_MECHANISM
    ),
    KnowledgeRelationType.LEADS_TO_IMPACT: KnowledgeNodeKind.IMPACT,
    KnowledgeRelationType.HAS_ROOT_CAUSE: KnowledgeNodeKind.ROOT_CAUSE,
}

_CONTEXT_FIELD_BY_RELATION = {
    KnowledgeRelationType.HAS_CWE: "cwe_node_ids",
    KnowledgeRelationType.HAS_CAPEC: "capec_node_ids",
    KnowledgeRelationType.AFFECTS_COMPONENT: "component_node_ids",
    KnowledgeRelationType.HAS_TRIGGER: "trigger_node_ids",
    KnowledgeRelationType.REQUIRES_PRECONDITION: "precondition_node_ids",
    KnowledgeRelationType.INVOLVES_BEHAVIOR: "behavior_node_ids",
    KnowledgeRelationType.USES_INTERFACE: "interface_node_ids",
    KnowledgeRelationType.TARGETS_RESOURCE: "hardware_resource_node_ids",
    KnowledgeRelationType.INVOLVES_SECURITY_MECHANISM: (
        "security_mechanism_node_ids"
    ),
    KnowledgeRelationType.LEADS_TO_IMPACT: "impact_node_ids",
    KnowledgeRelationType.HAS_ROOT_CAUSE: "root_cause_node_ids",
}


class CrossGraphCandidateSearcher:
    """Find unverified exact-anchor correlations without merging source graphs."""

    def __init__(self, *, linker: ExactHardwareEntityLinker | None = None) -> None:
        """Create a searcher with an injectable exact hardware linker."""

        self._linker = linker or ExactHardwareEntityLinker()

    def search(
        self,
        behavior_repository: GraphRepository,
        knowledge_repository: KnowledgeGraphRepository,
        *,
        architecture: Architecture,
        start_node_id: str,
        max_hops: int,
        top_n: int | None = None,
    ) -> list[CrossGraphCandidate]:
        """Correlate reachable hardware anchors with direct vulnerability context."""

        normalized_architecture = Architecture(architecture)
        if normalized_architecture is not Architecture.ARM:
            raise CandidateArchitectureMismatchError(
                "Phase 6 candidate search currently supports ARM only"
            )
        if knowledge_repository.architecture is not normalized_architecture:
            raise CandidateArchitectureMismatchError(
                "knowledge repository does not match search architecture"
            )
        if max_hops < 0:
            raise ValueError("max_hops must be non-negative")
        if top_n is not None and top_n <= 0:
            raise ValueError("top_n must be positive when provided")

        linking_result = self._linker.link(
            behavior_repository,
            knowledge_repository,
            architecture=normalized_architecture,
        )
        edges = knowledge_repository.list_edges()
        candidates: dict[str, CrossGraphCandidate] = {}
        for link in linking_result.links:
            paths = behavior_repository.find_paths(
                start_node_id,
                target_id=link.behavior_node_id,
                architecture=normalized_architecture,
                max_hops=max_hops,
                allowed_layers=ARM_CANDIDATE_LAYERS,
                allowed_relations=ARM_CANDIDATE_RELATIONS,
            )
            for path in paths:
                layers = [
                    behavior_repository.get_node(node_id).layer
                    for node_id in path.node_ids
                ]
                if len(set(layers)) < 2 or Layer.HARDWARE not in layers:
                    continue
                for vulnerability, target_edge in self._vulnerabilities_for_anchor(
                    knowledge_repository,
                    edges,
                    link,
                ):
                    candidate = self._build_candidate(
                        behavior_repository=behavior_repository,
                        knowledge_repository=knowledge_repository,
                        all_knowledge_edges=edges,
                        architecture=normalized_architecture,
                        path=path,
                        layers=layers,
                        link=link,
                        vulnerability=vulnerability,
                        target_edge=target_edge,
                    )
                    candidates[candidate.id] = candidate

        ordered = sorted(
            candidates.values(),
            key=lambda item: (
                item.behavior_path.hop_count,
                tuple(item.behavior_path.node_ids),
                tuple(item.behavior_path.edge_ids),
                item.entity_link.id,
                item.knowledge_vulnerability_id,
                item.id,
            ),
        )
        return ordered[:top_n] if top_n is not None else ordered

    @staticmethod
    def _vulnerabilities_for_anchor(
        knowledge_repository: KnowledgeGraphRepository,
        all_edges: list[KnowledgeEdge],
        link: EntityLink,
    ) -> list[tuple[KnowledgeNode, KnowledgeEdge]]:
        """Follow incoming TARGETS_RESOURCE edges in their original direction."""

        incoming = sorted(
            (
                edge
                for edge in all_edges
                if edge.target_id == link.knowledge_node_id
                and edge.relation is KnowledgeRelationType.TARGETS_RESOURCE
            ),
            key=lambda edge: edge.id,
        )
        results: list[tuple[KnowledgeNode, KnowledgeEdge]] = []
        for edge in incoming:
            source = knowledge_repository.get_node(edge.source_id)
            if source.kind is not KnowledgeNodeKind.VULNERABILITY:
                raise InvalidKnowledgeContextError(
                    f"TARGETS_RESOURCE edge {edge.id!r} must originate at a vulnerability"
                )
            results.append((source, edge))
        return results

    @staticmethod
    def _build_candidate(
        *,
        behavior_repository: GraphRepository,
        knowledge_repository: KnowledgeGraphRepository,
        all_knowledge_edges: list[KnowledgeEdge],
        architecture: Architecture,
        path: GraphPath,
        layers: list[Layer],
        link: EntityLink,
        vulnerability: KnowledgeNode,
        target_edge: KnowledgeEdge,
    ) -> CrossGraphCandidate:
        """Collect direct KG context and evidence IDs into one candidate model."""

        context_edges = sorted(
            (
                edge
                for edge in all_knowledge_edges
                if edge.source_id == vulnerability.id
                and edge.relation in _CONTEXT_KIND_BY_RELATION
            ),
            key=lambda edge: edge.id,
        )
        if target_edge.id not in {edge.id for edge in context_edges}:
            raise InvalidKnowledgeContextError(
                "linked TARGETS_RESOURCE edge is absent from vulnerability context"
            )

        context_ids: dict[str, list[str]] = {
            field_name: [] for field_name in set(_CONTEXT_FIELD_BY_RELATION.values())
        }
        context_nodes: list[KnowledgeNode] = []
        for edge in context_edges:
            target = knowledge_repository.get_node(edge.target_id)
            expected_kind = _CONTEXT_KIND_BY_RELATION[edge.relation]
            if target.kind is not expected_kind:
                raise InvalidKnowledgeContextError(
                    f"edge {edge.id!r} target kind does not match {edge.relation.value}"
                )
            context_nodes.append(target)
            context_ids[_CONTEXT_FIELD_BY_RELATION[edge.relation]].append(target.id)

        behavior_evidence_ids = sorted(
            {
                evidence_id
                for edge_id in path.edge_ids
                for evidence_id in behavior_repository.get_edge(edge_id).evidence_ids
            }
        )
        knowledge_evidence_ids = sorted(
            {
                evidence_id
                for evidence_id in _knowledge_evidence_ids(
                    vulnerability,
                    *context_nodes,
                    *context_edges,
                )
            }
        )
        missing_knowledge_evidence = any(
            not edge.evidence_ids for edge in context_edges
        )
        candidate_id = cross_graph_candidate_id(
            architecture,
            path,
            link,
            vulnerability.id,
        )
        return CrossGraphCandidate(
            id=candidate_id,
            architecture=architecture,
            behavior_path=path,
            behavior_layers=layers,
            entity_link=link,
            knowledge_vulnerability_id=vulnerability.id,
            knowledge_anchor_node_id=link.knowledge_node_id,
            knowledge_edge_ids=[edge.id for edge in context_edges],
            behavior_evidence_ids=behavior_evidence_ids,
            knowledge_evidence_ids=knowledge_evidence_ids,
            knowledge_evidence_count=len(knowledge_evidence_ids),
            missing_knowledge_evidence=missing_knowledge_evidence,
            metadata={
                "status": "unverified_correlation",
                "claim": "not_a_verified_attack_chain",
                "target_relation_id": target_edge.id,
            },
            **context_ids,
        )


def _knowledge_evidence_ids(
    *items: KnowledgeNode | KnowledgeEdge,
) -> Iterable[str]:
    """Yield existing references without inventing knowledge evidence."""

    for item in items:
        yield from item.evidence_ids
