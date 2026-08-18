"""Deterministic retrieval-query construction from resolved candidate facts."""

from __future__ import annotations

from chipchain.reasoning.models import CandidateContext, CandidateRetrievalQuery


class CandidateRetrievalQueryBuilder:
    """Build auditable lexical terms without asking an LLM to formulate queries."""

    def build(self, context: CandidateContext) -> CandidateRetrievalQuery:
        """Extract stable architecture, behavior, hardware, taxonomy, and condition terms."""

        terms = {
            context.architecture.value,
            context.knowledge_vulnerability.label,
            context.knowledge_anchor.label,
            *(edge.relation.value for edge in context.behavior_edges),
            *context.knowledge_anchor.match_keys,
            *(node.label for node in context.taxonomy_nodes),
            *(item for node in context.taxonomy_nodes for item in node.external_ids),
            *(node.label for node in context.trigger_nodes),
            *(node.label for node in context.precondition_nodes),
            *(node.label for node in context.security_mechanism_nodes),
        }
        normalized = sorted(item.strip() for item in terms if item.strip())
        return CandidateRetrievalQuery(
            candidate_id=context.candidate_id,
            architecture=context.architecture,
            text=" ".join(normalized),
            terms=normalized,
            metadata={"builder": "CandidateRetrievalQueryBuilder"},
        )
