"""Deterministic fixed-order Phase 8 orchestration and failure isolation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import ValidationError

from chipchain.candidate import CrossGraphCandidate
from chipchain.graph import GraphRepository
from chipchain.knowledge import KnowledgeGraphRepository
from chipchain.models.common import DomainModel
from chipchain.multi_agent.agents import (
    CriticAgent,
    EvidenceAnalystAgent,
    SecurityReasoningAgent,
)
from chipchain.multi_agent.enums import (
    AgentExecutionStatus,
    AgentRole,
    CriticReviewStatus,
    EvidenceAnalysisStatus,
)
from chipchain.multi_agent.errors import AgentExecutionError, AgentOutputValidationError
from chipchain.multi_agent.models import (
    AgentExecutionRecord,
    CriticReview,
    EvidenceAnalysis,
    MultiAgentContext,
    MultiAgentReasoningResult,
    SecurityReasoningAssessment,
)
from chipchain.multi_agent.validation import (
    validate_critic_review,
    validate_evidence_analysis,
    validate_security_reasoning,
)
from chipchain.reasoning import (
    CandidateContextAssembler,
    CandidateRetrievalQueryBuilder,
    CandidateSemanticStatus,
    EvidenceResolver,
    KnowledgeRetriever,
    RetrievalResult,
    StructuredPromptRequest,
)
from chipchain.reasoning.errors import LLMOutputValidationError

OutputT = TypeVar("OutputT", bound=DomainModel)


class MultiAgentCoordinator:
    """Run exactly Evidence Analyst → Security Reasoner → Critic once each."""

    def __init__(
        self,
        *,
        context_assembler: CandidateContextAssembler,
        query_builder: CandidateRetrievalQueryBuilder,
        retriever: KnowledgeRetriever,
        evidence_analyst: EvidenceAnalystAgent,
        security_reasoner: SecurityReasoningAgent,
        critic: CriticAgent,
    ) -> None:
        self._context_assembler = context_assembler
        self._query_builder = query_builder
        self._retriever = retriever
        self._evidence_analyst = evidence_analyst
        self._security_reasoner = security_reasoner
        self._critic = critic

    def reason(
        self,
        candidate: CrossGraphCandidate,
        behavior_repository: GraphRepository,
        knowledge_repository: KnowledgeGraphRepository,
        behavior_evidence_resolver: EvidenceResolver,
        *,
        top_k: int,
    ) -> MultiAgentReasoningResult:
        """Build context/RAG once, execute fixed roles, and return all outputs."""

        candidate_context = self._context_assembler.assemble(
            candidate,
            behavior_repository,
            knowledge_repository,
            behavior_evidence_resolver,
        )
        query = self._query_builder.build(candidate_context)
        retrieval = self._retriever.retrieve(
            query,
            architecture=candidate.architecture,
            top_k=top_k,
        )
        context = MultiAgentContext(
            candidate_id=candidate.id,
            architecture=candidate.architecture,
            candidate_context=candidate_context,
            retrieval_query=query,
            retrieved_chunks=retrieval.chunks,
            metadata={
                "shared_context": True,
                "retrieval_runs": 1,
                "read_only": True,
            },
        )
        trace: list[AgentExecutionRecord] = []

        evidence_prompt = self._evidence_analyst.prepare(context)
        evidence_analysis = self._run_agent(
            sequence=1,
            role=AgentRole.EVIDENCE_ANALYST,
            input_models=[context],
            prompt=evidence_prompt,
            execute=self._evidence_analyst.execute,
            output_type=EvidenceAnalysis,
            validate=lambda output: validate_evidence_analysis(output, context),
            trace=trace,
        )

        security_prompt = self._security_reasoner.prepare(
            context,
            evidence_analysis,
        )
        security_reasoning = self._run_agent(
            sequence=2,
            role=AgentRole.SECURITY_REASONER,
            input_models=[context, evidence_analysis],
            prompt=security_prompt,
            execute=self._security_reasoner.execute,
            output_type=SecurityReasoningAssessment,
            validate=lambda output: validate_security_reasoning(output, context),
            trace=trace,
        )

        critic_prompt = self._critic.prepare(
            context,
            evidence_analysis,
            security_reasoning,
        )
        critic_review = self._run_agent(
            sequence=3,
            role=AgentRole.CRITIC,
            input_models=[context, evidence_analysis, security_reasoning],
            prompt=critic_prompt,
            execute=self._critic.execute,
            output_type=CriticReview,
            validate=lambda output: validate_critic_review(
                output,
                context,
                evidence_analysis,
                security_reasoning,
            ),
            trace=trace,
        )

        final_status = determine_final_semantic_status(
            evidence_analysis,
            security_reasoning,
            critic_review,
        )
        return MultiAgentReasoningResult(
            candidate_id=candidate.id,
            architecture=candidate.architecture,
            context=context,
            retrieval=retrieval,
            evidence_analysis=evidence_analysis,
            security_reasoning=security_reasoning,
            critic_review=critic_review,
            execution_trace=trace,
            unresolved_trigger_node_ids=[
                item.id for item in candidate_context.trigger_nodes
            ],
            unresolved_precondition_node_ids=[
                item.id for item in candidate_context.precondition_nodes
            ],
            final_semantic_status=final_status,
            metadata={
                "coordinator": "deterministic_python",
                "agent_calls": 3,
                "consensus_is_not_verification": True,
            },
        )

    def _run_agent(
        self,
        *,
        sequence: int,
        role: AgentRole,
        input_models: list[DomainModel],
        prompt: StructuredPromptRequest,
        execute: Callable[[StructuredPromptRequest], OutputT],
        output_type: type[OutputT],
        validate: Callable[[OutputT], None],
        trace: list[AgentExecutionRecord],
    ) -> OutputT:
        input_digest = _digest([item.model_dump(mode="json") for item in input_models])
        prompt_digest = _digest(prompt.model_dump(mode="json"))
        raw_output: Any = None
        try:
            raw_output = execute(prompt)
            output = output_type.model_validate(raw_output.model_dump(mode="json"))
            validate(output)
        except Exception as exc:
            output_digest = (
                _digest(raw_output.model_dump(mode="json"))
                if isinstance(raw_output, DomainModel)
                else None
            )
            failed_record = AgentExecutionRecord(
                sequence=sequence,
                role=role,
                candidate_id=prompt.candidate_id,
                architecture=prompt.architecture,
                input_digest=input_digest,
                prompt_digest=prompt_digest,
                output_digest=output_digest,
                execution_status=AgentExecutionStatus.FAILED,
                error_type=type(exc).__name__,
                metadata={"stage": _failure_stage(exc)},
            )
            trace.append(failed_record)
            raise AgentExecutionError(
                f"{role.value} execution failed",
                failed_role=role,
                stage=_failure_stage(exc),
                execution_trace=tuple(trace),
                validation_detail=(
                    str(exc)
                    if isinstance(
                        exc,
                        (AgentOutputValidationError, LLMOutputValidationError),
                    )
                    else None
                ),
            ) from None
        trace.append(
            AgentExecutionRecord(
                sequence=sequence,
                role=role,
                candidate_id=prompt.candidate_id,
                architecture=prompt.architecture,
                input_digest=input_digest,
                prompt_digest=prompt_digest,
                output_digest=_digest(output.model_dump(mode="json")),
                execution_status=AgentExecutionStatus.COMPLETED,
                metadata={"schema": output_type.__name__},
            )
        )
        return output

def _digest(value: object) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _failure_stage(exception: Exception) -> str:
    stage = getattr(exception, "stage", None)
    if isinstance(stage, str) and stage:
        return stage
    if isinstance(exception, (ValidationError,)):
        return "pydantic_validation"
    return "output_validation"


def determine_final_semantic_status(
    evidence: EvidenceAnalysis,
    security: SecurityReasoningAssessment,
    critic: CriticReview,
) -> CandidateSemanticStatus:
    """Apply transparent rule order without scores, voting, or LLM judgment."""

    if (
        evidence.analysis_status is EvidenceAnalysisStatus.CONTEXT_INCONSISTENT
        or security.semantic_status
        is CandidateSemanticStatus.CONTEXTUALLY_INCONSISTENT
        or critic.review_status is CriticReviewStatus.CONTEXT_CONFLICT
    ):
        return CandidateSemanticStatus.CONTEXTUALLY_INCONSISTENT
    if (
        evidence.analysis_status is EvidenceAnalysisStatus.EVIDENCE_INCOMPLETE
        or security.semantic_status is CandidateSemanticStatus.INSUFFICIENT_CONTEXT
    ):
        return CandidateSemanticStatus.INSUFFICIENT_CONTEXT
    return CandidateSemanticStatus.REQUIRES_VERIFICATION
