"""Deterministic offline provider for all default Phase 7 tests and demos."""

from __future__ import annotations

from chipchain.reasoning.enums import CandidateSemanticStatus
from chipchain.reasoning.models import CandidateSemanticAssessment, PromptRequest
from chipchain.reasoning.provider import LLMProvider


class MockLLMProvider(LLMProvider):
    """Return a realistic structured assessment from supplied IDs only."""

    def generate(self, request: PromptRequest) -> CandidateSemanticAssessment:
        """Preserve unresolved conditions and cite only bounded input objects."""

        context = request.reasoning_input.candidate_context
        chunks = request.reasoning_input.retrieved_chunks
        missing_information = []
        if context.metadata.get("missing_knowledge_evidence") is True:
            missing_information.append(
                "Some knowledge relations have no referenced evidence."
            )
        if not chunks:
            missing_information.append("No architecture reference chunks were retrieved.")
        return CandidateSemanticAssessment(
            candidate_id=request.candidate_id,
            architecture=request.architecture,
            summary=(
                "The candidate has an evidence-backed structural correlation but "
                "still requires verification."
            ),
            supporting_observation_ids=[
                item.id for item in context.behavior_evidence
            ],
            supporting_knowledge_chunk_ids=[item.chunk_id for item in chunks],
            unresolved_trigger_node_ids=[item.id for item in context.trigger_nodes],
            unresolved_precondition_node_ids=[
                item.id for item in context.precondition_nodes
            ],
            missing_information=missing_information,
            contradictions=[],
            recommended_verification_steps=[
                "Verify trigger reachability against structured program evidence.",
                "Verify each precondition with architecture or dynamic evidence.",
                "Validate evidence-free knowledge relations before chain projection.",
            ],
            semantic_status=(
                CandidateSemanticStatus.REQUIRES_VERIFICATION
                if chunks
                else CandidateSemanticStatus.INSUFFICIENT_CONTEXT
            ),
            metadata={
                "provider": "mock",
                "deterministic": True,
                "security_confidence_score_provided": False,
            },
        )
