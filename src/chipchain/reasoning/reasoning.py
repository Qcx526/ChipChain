"""Single-reasoner orchestration with strict structured-output post-validation."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.candidate import CrossGraphCandidate
from chipchain.graph import GraphRepository
from chipchain.knowledge import KnowledgeGraphRepository
from chipchain.reasoning.context import CandidateContextAssembler, EvidenceResolver
from chipchain.reasoning.errors import LLMOutputValidationError
from chipchain.reasoning.models import (
    CandidateReasoningInput,
    CandidateReasoningResult,
    CandidateSemanticAssessment,
)
from chipchain.reasoning.prompts import CandidatePromptBuilder
from chipchain.reasoning.provider import LLMProvider
from chipchain.reasoning.query import CandidateRetrievalQueryBuilder
from chipchain.reasoning.retrieval import KnowledgeRetriever
from chipchain.reasoning.validation import validate_verification_boundary


class CandidateReasoner:
    """Run one deterministic context→retrieval→prompt→provider pipeline."""

    def __init__(
        self,
        *,
        context_assembler: CandidateContextAssembler,
        query_builder: CandidateRetrievalQueryBuilder,
        retriever: KnowledgeRetriever,
        prompt_builder: CandidatePromptBuilder,
        provider: LLMProvider,
    ) -> None:
        self._context_assembler = context_assembler
        self._query_builder = query_builder
        self._retriever = retriever
        self._prompt_builder = prompt_builder
        self._provider = provider

    def reason(
        self,
        candidate: CrossGraphCandidate,
        behavior_repository: GraphRepository,
        knowledge_repository: KnowledgeGraphRepository,
        behavior_evidence_resolver: EvidenceResolver,
        *,
        top_k: int,
    ) -> CandidateReasoningResult:
        """Interpret one candidate and reject citations outside bounded inputs."""

        context = self._context_assembler.assemble(
            candidate,
            behavior_repository,
            knowledge_repository,
            behavior_evidence_resolver,
        )
        query = self._query_builder.build(context)
        retrieval = self._retriever.retrieve(
            query,
            architecture=candidate.architecture,
            top_k=top_k,
        )
        reasoning_input = CandidateReasoningInput(
            candidate_id=candidate.id,
            architecture=candidate.architecture,
            candidate_context=context,
            retrieved_chunks=retrieval.chunks,
            analysis_instructions=self._prompt_builder.analysis_instructions,
        )
        prompt = self._prompt_builder.build(reasoning_input)
        raw_assessment = self._provider.generate(prompt)
        try:
            assessment = CandidateSemanticAssessment.model_validate(
                raw_assessment.model_dump(mode="json")
            )
        except (AttributeError, ValidationError) as exc:
            raise LLMOutputValidationError(
                "provider returned an invalid assessment object"
            ) from exc
        self._validate_assessment(assessment, reasoning_input)
        return CandidateReasoningResult(
            context=context,
            query=query,
            retrieval=retrieval,
            prompt=prompt,
            assessment=assessment,
        )

    @staticmethod
    def _validate_assessment(
        assessment: CandidateSemanticAssessment,
        reasoning_input: CandidateReasoningInput,
    ) -> None:
        if assessment.candidate_id != reasoning_input.candidate_id:
            raise LLMOutputValidationError("provider returned the wrong candidate ID")
        if assessment.architecture is not reasoning_input.architecture:
            raise LLMOutputValidationError("provider returned the wrong architecture")
        context = reasoning_input.candidate_context
        allowed_observations = {item.id for item in context.behavior_evidence}
        if not set(assessment.supporting_observation_ids).issubset(
            allowed_observations
        ):
            raise LLMOutputValidationError(
                "provider cited an unknown behavior Evidence ID"
            )
        allowed_chunks = {item.chunk_id for item in reasoning_input.retrieved_chunks}
        if not set(assessment.supporting_knowledge_chunk_ids).issubset(allowed_chunks):
            raise LLMOutputValidationError(
                "provider cited an unknown retrieved Chunk ID"
            )
        expected_triggers = {item.id for item in context.trigger_nodes}
        expected_preconditions = {item.id for item in context.precondition_nodes}
        if set(assessment.unresolved_trigger_node_ids) != expected_triggers:
            raise LLMOutputValidationError(
                "all trigger nodes must remain unresolved in Phase 7"
            )
        if set(assessment.unresolved_precondition_node_ids) != expected_preconditions:
            raise LLMOutputValidationError(
                "all precondition nodes must remain unresolved in Phase 7"
            )
        validate_verification_boundary(
            [
                assessment.summary,
                *assessment.missing_information,
                *assessment.contradictions,
                *assessment.recommended_verification_steps,
            ]
        )
