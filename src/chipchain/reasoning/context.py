"""Strict read-only resolution of candidate ID references into domain objects."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from chipchain.analysis import ProgramAnalysisResult
from chipchain.candidate import CrossGraphCandidate
from chipchain.graph import GraphRepository
from chipchain.knowledge import KnowledgeGraphRepository
from chipchain.models import Evidence
from chipchain.reasoning.errors import CandidateContextError, EvidenceResolutionError
from chipchain.reasoning.models import CandidateContext


class EvidenceResolver(ABC):
    """Read-only lookup abstraction for full behavior Evidence objects."""

    @abstractmethod
    def get(self, evidence_id: str) -> Evidence:
        """Return evidence or raise EvidenceResolutionError."""


class InMemoryEvidenceResolver(EvidenceResolver):
    """Validated deterministic Evidence catalog backed by detached JSON data."""

    def __init__(self, evidence: Iterable[Evidence]) -> None:
        catalog = list(evidence)
        ids = [item.id for item in catalog]
        if len(ids) != len(set(ids)):
            raise ValueError("behavior evidence resolver IDs must be unique")
        self._catalog = {
            item.id: item.model_dump(mode="json") for item in catalog
        }

    @classmethod
    def from_analysis_result(
        cls, result: ProgramAnalysisResult
    ) -> "InMemoryEvidenceResolver":
        """Create a resolver without modifying or retaining mutable result objects."""

        return cls(result.evidence)

    def get(self, evidence_id: str) -> Evidence:
        """Return a freshly validated Evidence model."""

        data = self._catalog.get(evidence_id)
        if data is None:
            raise EvidenceResolutionError(
                f"behavior evidence {evidence_id!r} could not be resolved"
            )
        return Evidence.model_validate(dict(data))


class CandidateContextAssembler:
    """Resolve every candidate reference or fail before retrieval and LLM use."""

    def assemble(
        self,
        candidate: CrossGraphCandidate,
        behavior_repository: GraphRepository,
        knowledge_repository: KnowledgeGraphRepository,
        behavior_evidence_resolver: EvidenceResolver,
    ) -> CandidateContext:
        """Build a complete read-only resolved view of one candidate."""

        try:
            behavior_nodes = [
                behavior_repository.get_node(item)
                for item in candidate.behavior_path.node_ids
            ]
            behavior_edges = [
                behavior_repository.get_edge(item)
                for item in candidate.behavior_path.edge_ids
            ]
            expected_behavior_evidence = sorted(
                {
                    evidence_id
                    for edge in behavior_edges
                    for evidence_id in edge.evidence_ids
                }
            )
            if expected_behavior_evidence != candidate.behavior_evidence_ids:
                raise CandidateContextError(
                    "candidate behavior evidence IDs do not match path edges"
                )
            behavior_evidence = [
                behavior_evidence_resolver.get(item)
                for item in candidate.behavior_evidence_ids
            ]

            vulnerability = knowledge_repository.get_node(
                candidate.knowledge_vulnerability_id
            )
            anchor = knowledge_repository.get_node(
                candidate.knowledge_anchor_node_id
            )
            knowledge_ids = sorted(
                {
                    candidate.knowledge_anchor_node_id,
                    *candidate.component_node_ids,
                    *candidate.trigger_node_ids,
                    *candidate.precondition_node_ids,
                    *candidate.cwe_node_ids,
                    *candidate.capec_node_ids,
                    *candidate.behavior_node_ids,
                    *candidate.interface_node_ids,
                    *candidate.hardware_resource_node_ids,
                    *candidate.security_mechanism_node_ids,
                    *candidate.impact_node_ids,
                    *candidate.root_cause_node_ids,
                }
            )
            knowledge_nodes = [
                knowledge_repository.get_node(item) for item in knowledge_ids
            ]
            knowledge_edges = [
                knowledge_repository.get_edge(item)
                for item in candidate.knowledge_edge_ids
            ]
            expected_knowledge_evidence = sorted(
                {
                    evidence_id
                    for item in [vulnerability, *knowledge_nodes, *knowledge_edges]
                    for evidence_id in item.evidence_ids
                }
            )
            if expected_knowledge_evidence != candidate.knowledge_evidence_ids:
                raise CandidateContextError(
                    "candidate knowledge evidence IDs do not match referenced context"
                )
            knowledge_evidence = [
                knowledge_repository.get_evidence(item)
                for item in candidate.knowledge_evidence_ids
            ]
            node_by_id = {node.id: node for node in knowledge_nodes}
            resolve_nodes = lambda ids: [node_by_id[item] for item in ids]
            return CandidateContext(
                candidate_id=candidate.id,
                architecture=candidate.architecture,
                behavior_nodes=behavior_nodes,
                behavior_edges=behavior_edges,
                behavior_evidence=behavior_evidence,
                knowledge_vulnerability=vulnerability,
                knowledge_anchor=anchor,
                knowledge_nodes=knowledge_nodes,
                knowledge_edges=knowledge_edges,
                knowledge_evidence=knowledge_evidence,
                trigger_nodes=resolve_nodes(candidate.trigger_node_ids),
                precondition_nodes=resolve_nodes(candidate.precondition_node_ids),
                impact_nodes=resolve_nodes(candidate.impact_node_ids),
                security_mechanism_nodes=resolve_nodes(
                    candidate.security_mechanism_node_ids
                ),
                root_cause_nodes=resolve_nodes(candidate.root_cause_node_ids),
                taxonomy_nodes=resolve_nodes(
                    [*candidate.cwe_node_ids, *candidate.capec_node_ids]
                ),
                metadata={
                    "view": "resolved_candidate_references",
                    "read_only": True,
                    "missing_knowledge_evidence": (
                        candidate.missing_knowledge_evidence
                    ),
                },
            )
        except CandidateContextError:
            raise
        except Exception as exc:
            raise CandidateContextError(
                "candidate context contains an unresolved or invalid reference"
            ) from exc
