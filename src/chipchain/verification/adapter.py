"""Read-only adapter from the legacy software-to-hardware candidate primitive."""

from dataclasses import dataclass

from chipchain.candidate import CrossGraphCandidate
from chipchain.graph import GraphRepository
from chipchain.knowledge import KnowledgeEdge, KnowledgeGraphRepository, KnowledgeNode
from chipchain.models import BehaviorEdge, BehaviorNode, CrossLayerDirection, CrossLayerInteraction, Evidence
from chipchain.reasoning import EvidenceResolver
from chipchain.reasoning.errors import EvidenceResolutionError
from chipchain.verification.errors import VerificationInputError


@dataclass(frozen=True)
class LegacyCandidateEvidenceContext:
    candidate: CrossGraphCandidate
    behavior_nodes: tuple[BehaviorNode, ...]
    behavior_edges: tuple[BehaviorEdge, ...]
    knowledge_nodes: tuple[KnowledgeNode, ...]
    knowledge_edges: tuple[KnowledgeEdge, ...]
    evidence: tuple[Evidence, ...]


class LegacyCandidateVerificationAdapter:
    """Resolve detached legacy facts without classifying an interaction."""

    def adapt(self, interaction: CrossLayerInteraction, candidate: CrossGraphCandidate,
              behavior_repository: GraphRepository,
              knowledge_repository: KnowledgeGraphRepository,
              behavior_evidence_resolver: EvidenceResolver) -> LegacyCandidateEvidenceContext:
        if interaction.direction is CrossLayerDirection.HARDWARE_TO_SOFTWARE:
            raise VerificationInputError("legacy Candidate cannot support hardware-to-software propagation")
        if candidate.architecture is not interaction.architecture:
            raise VerificationInputError("legacy Candidate architecture mismatch")
        behavior_nodes = tuple(behavior_repository.get_node(i) for i in candidate.behavior_path.node_ids)
        behavior_edges = tuple(behavior_repository.get_edge(i) for i in candidate.behavior_path.edge_ids)
        knowledge_ids = sorted({candidate.knowledge_vulnerability_id, candidate.knowledge_anchor_node_id,
            *candidate.component_node_ids, *candidate.trigger_node_ids, *candidate.precondition_node_ids,
            *candidate.cwe_node_ids, *candidate.capec_node_ids, *candidate.behavior_node_ids,
            *candidate.interface_node_ids, *candidate.hardware_resource_node_ids,
            *candidate.security_mechanism_node_ids, *candidate.impact_node_ids, *candidate.root_cause_node_ids})
        knowledge_nodes = tuple(knowledge_repository.get_node(i) for i in knowledge_ids)
        knowledge_edges = tuple(knowledge_repository.get_edge(i) for i in candidate.knowledge_edge_ids)
        evidence: list[Evidence] = []
        for evidence_id in sorted({e for edge in behavior_edges for e in edge.evidence_ids}):
            try: evidence.append(behavior_evidence_resolver.get(evidence_id))
            except EvidenceResolutionError: pass
        for evidence_id in candidate.knowledge_evidence_ids:
            evidence.append(knowledge_repository.get_evidence(evidence_id))
        return LegacyCandidateEvidenceContext(candidate, behavior_nodes, behavior_edges,
                                              knowledge_nodes, knowledge_edges, tuple(evidence))
