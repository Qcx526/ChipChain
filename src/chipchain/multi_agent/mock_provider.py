"""Deterministic offline structured provider for realistic Phase 8 agent tests."""

from __future__ import annotations

import json
from typing import TypeVar

from chipchain.models.common import DomainModel
from chipchain.multi_agent.models import (
    CriticReview,
    EvidenceAnalysis,
    SecurityReasoningAssessment,
)
from chipchain.reasoning import StructuredOutputProvider, StructuredPromptRequest

StructuredModelT = TypeVar("StructuredModelT", bound=DomainModel)


class MockStructuredOutputProvider(StructuredOutputProvider):
    """Produce cited schema-specific outputs without API keys or network access."""

    def __init__(self) -> None:
        self.calls: list[StructuredPromptRequest] = []

    def generate_structured(
        self,
        request: StructuredPromptRequest,
        output_type: type[StructuredModelT],
    ) -> StructuredModelT:
        """Return deterministic realistic output for exactly three schemas."""

        self.calls.append(StructuredPromptRequest.model_validate(
            request.model_dump(mode="json")
        ))
        payload = json.loads(request.user_prompt)
        if output_type is EvidenceAnalysis:
            values = _evidence_analysis(payload)
        elif output_type is SecurityReasoningAssessment:
            values = _security_reasoning(payload)
        elif output_type is CriticReview:
            values = _critic_review(payload)
        else:
            raise TypeError(f"unsupported mock output schema: {output_type.__name__}")
        return output_type.model_validate(values)


def _context_parts(payload: dict[str, object]) -> tuple[dict, dict]:
    context = payload["multi_agent_context"]
    if not isinstance(context, dict):
        raise TypeError("mock multi-agent context must be an object")
    candidate_context = context["candidate_context"]
    if not isinstance(candidate_context, dict):
        raise TypeError("mock candidate context must be an object")
    return context, candidate_context


def _evidence_analysis(payload: dict[str, object]) -> dict[str, object]:
    context, candidate_context = _context_parts(payload)
    behavior_evidence_ids = sorted(
        item["id"] for item in candidate_context["behavior_evidence"]
    )
    knowledge_evidence_ids = sorted(
        item["id"] for item in candidate_context["knowledge_evidence"]
    )
    trigger_ids = sorted(item["id"] for item in candidate_context["trigger_nodes"])
    precondition_ids = sorted(
        item["id"] for item in candidate_context["precondition_nodes"]
    )
    behavior_edges = candidate_context["behavior_edges"]
    missing_behavior = not behavior_evidence_ids or any(
        not item["evidence_ids"] for item in behavior_edges
    )
    missing_knowledge = bool(
        candidate_context["metadata"].get("missing_knowledge_evidence", False)
    )
    gaps = [
        "Trigger satisfaction has no Phase 8 verification.",
        "Precondition satisfaction has no Phase 8 verification.",
    ]
    if missing_behavior:
        gaps.append("At least one behavior edge lacks supporting evidence.")
    if missing_knowledge:
        gaps.append("Referenced knowledge context reports missing evidence.")
    status = (
        "evidence_incomplete"
        if missing_behavior or missing_knowledge
        else "context_ready"
    )
    return {
        "candidate_id": context["candidate_id"],
        "architecture": context["architecture"],
        "observed_behavior_evidence_ids": behavior_evidence_ids,
        "observed_knowledge_evidence_ids": knowledge_evidence_ids,
        "unresolved_trigger_node_ids": trigger_ids,
        "unresolved_precondition_node_ids": precondition_ids,
        "evidence_gaps": gaps,
        "missing_behavior_evidence": missing_behavior,
        "missing_knowledge_evidence": missing_knowledge,
        "recommended_evidence_collection_steps": [
            "Collect runtime observations for the unresolved trigger path.",
            "Collect configuration-state evidence for unresolved preconditions.",
        ],
        "analysis_status": status,
        "metadata": {
            "mock": True,
            "analysis_not_verification": True,
        },
    }


def _security_reasoning(payload: dict[str, object]) -> dict[str, object]:
    context, candidate_context = _context_parts(payload)
    evidence_analysis = payload["prior_evidence_analysis"]
    if not isinstance(evidence_analysis, dict):
        raise TypeError("mock evidence analysis must be an object")
    observation_ids = evidence_analysis["observed_behavior_evidence_ids"]
    chunk_ids = sorted(item["chunk_id"] for item in context["retrieved_chunks"])
    trigger_ids = evidence_analysis["unresolved_trigger_node_ids"]
    precondition_ids = evidence_analysis["unresolved_precondition_node_ids"]
    hypothesis_id = f"semantic-hypothesis:{context['candidate_id']}:0"
    hypotheses = []
    if observation_ids and chunk_ids:
        hypotheses.append(
            {
                "id": hypothesis_id,
                "statement": (
                    "The observed ARM MMIO behavior may be semantically related "
                    "to the referenced hardware-access control context."
                ),
                "supporting_observation_ids": observation_ids,
                "supporting_knowledge_chunk_ids": chunk_ids,
                "related_trigger_node_ids": trigger_ids,
                "related_precondition_node_ids": precondition_ids,
                "missing_information": [
                    "Runtime reachability and authorization state remain unknown."
                ],
                "metadata": {"unverified_hypothesis": True},
            }
        )
    incomplete = evidence_analysis["analysis_status"] != "context_ready"
    return {
        "candidate_id": context["candidate_id"],
        "architecture": context["architecture"],
        "summary": (
            "The structural ARM correlation supports an unverified semantic "
            "hypothesis and requires evidence-based verification."
        ),
        "hypotheses": hypotheses,
        "supporting_observation_ids": observation_ids,
        "supporting_knowledge_chunk_ids": chunk_ids,
        "unresolved_trigger_node_ids": trigger_ids,
        "unresolved_precondition_node_ids": precondition_ids,
        "missing_information": evidence_analysis["evidence_gaps"],
        "contradictions": [],
        "recommended_verification_steps": [
            "Trace runtime reachability from the entry point to the MMIO access.",
            "Check authorization and security-mechanism state before the access.",
        ],
        "semantic_status": (
            "insufficient_context" if incomplete else "requires_verification"
        ),
        "metadata": {
            "mock": True,
            "prior_analysis_is_not_evidence": True,
        },
    }


def _critic_review(payload: dict[str, object]) -> dict[str, object]:
    context, _ = _context_parts(payload)
    evidence_analysis = payload["prior_evidence_analysis"]
    security_reasoning = payload["prior_security_reasoning"]
    if not isinstance(evidence_analysis, dict) or not isinstance(
        security_reasoning, dict
    ):
        raise TypeError("mock prior analyses must be objects")
    trigger_ids = evidence_analysis["unresolved_trigger_node_ids"]
    precondition_ids = evidence_analysis["unresolved_precondition_node_ids"]
    condition_issues = []
    if trigger_ids:
        condition_issues.append("Trigger satisfaction remains unresolved.")
    if precondition_ids:
        condition_issues.append("Precondition satisfaction remains unresolved.")
    status = (
        "context_conflict"
        if security_reasoning["semantic_status"] == "contextually_inconsistent"
        else "revision_required"
    )
    return {
        "candidate_id": context["candidate_id"],
        "architecture": context["architecture"],
        "referenced_observation_ids": security_reasoning[
            "supporting_observation_ids"
        ],
        "referenced_knowledge_chunk_ids": security_reasoning[
            "supporting_knowledge_chunk_ids"
        ],
        "referenced_trigger_node_ids": trigger_ids,
        "referenced_precondition_node_ids": precondition_ids,
        "referenced_hypothesis_ids": [
            item["id"] for item in security_reasoning["hypotheses"]
        ],
        "unresolved_trigger_node_ids": trigger_ids,
        "unresolved_precondition_node_ids": precondition_ids,
        "unsupported_statements": [],
        "citation_issues": [],
        "architecture_issues": [],
        "condition_issues": condition_issues,
        "contradictions": security_reasoning["contradictions"],
        "required_revisions": security_reasoning[
            "recommended_verification_steps"
        ],
        "review_status": status,
        "metadata": {
            "mock": True,
            "review_not_verification": True,
        },
    }
