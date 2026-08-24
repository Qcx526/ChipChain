"""Deterministic coordinator for Phase 9B2B multi-agent reasoning."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from chipchain.agents.base import ReasoningContext, _snapshot_context
from chipchain.agents.state import (
    COORDINATOR_ID,
    AgentMessage,
    AgentMessageType,
    ReasoningSession,
    reasoning_session_id,
)
from chipchain.reasoning.enums import HypothesisSource
from chipchain.reasoning.evidence_request import EvidenceRequest
from chipchain.reasoning.feedback import (
    EvidenceFeedback,
    EvidenceFeedbackStatus,
)
from chipchain.reasoning.hypothesis import AttackHypothesis
from chipchain.reasoning.reasoning_result import ReasoningResult

if TYPE_CHECKING:
    from chipchain.agents.workflow import AgentWorkflow


class HypothesisMergeConflict(ValueError):
    """Raised when hypotheses cannot be combined without semantic invention."""


class MultiAgentReasoningCoordinator:
    """Schedule agents, collect contracts, and produce reasoning-only output."""

    def coordinate(
        self,
        context: ReasoningContext,
        workflow: "AgentWorkflow",
    ) -> ReasoningSession:
        """Execute one fixed workflow and return a complete reasoning session."""

        snapshot = _snapshot_context(context)
        contributions: list[
            tuple[
                str,
                AttackHypothesis,
                list[EvidenceRequest],
                ReasoningResult | None,
            ]
        ] = []
        completed_roles = []
        execution_order = []
        for agent in workflow.build_agents(snapshot):
            execution_order.append(agent.agent_type)
            try:
                hypothesis = agent.produce_hypothesis()
                if workflow.is_hypothesis_only(agent.agent_type):
                    requests: list[EvidenceRequest] = []
                    result = None
                else:
                    requests = agent.request_evidence()
                    result = agent.analyze(snapshot)
                    for request in requests:
                        request.validate_against(hypothesis)
                    result.validate_against(hypothesis)
            except Exception as error:
                wrapped = workflow.wrap_execution_error(
                    failed_role=agent.agent_type,
                    completed_roles=completed_roles,
                    error=error,
                )
                if wrapped is error:
                    raise
                raise wrapped from None
            contributions.append(
                (agent.agent_id, hypothesis, requests, result)
            )
            completed_roles.append(agent.agent_type)

        agent_ids = [item[0] for item in contributions]
        session_id = reasoning_session_id(
            reasoning_context_id=snapshot.id,
            agent_ids=agent_ids,
            workflow_contract=workflow.contract,
        )
        messages = _agent_output_messages(session_id, contributions)
        hypotheses = [item[1] for item in contributions]
        merged_hypothesis = self.merge_hypotheses(hypotheses)
        requests = self.aggregate_evidence_requests(
            request
            for _, _, agent_requests, _ in contributions
            for request in agent_requests
        )
        results = [
            result
            for _, _, _, result in contributions
            if result is not None
        ]
        final_result = self.merge_reasoning_results(
            merged_hypothesis,
            requests,
            results,
        )
        return ReasoningSession(
            session_id=session_id,
            reasoning_context=snapshot,
            agent_ids=agent_ids,
            messages=messages,
            hypotheses=hypotheses,
            merged_hypothesis=merged_hypothesis,
            evidence_requests=requests,
            feedbacks=[],
            reasoning_results=results,
            final_reasoning_result=final_result,
            metadata={
                "attack_chain_agent_scope": "hypothesis_only",
                "domain_truth_creation": False,
                "execution_order": [
                    role.value for role in execution_order
                ],
                "orchestration_mode": workflow.orchestration_mode,
            },
        )

    def merge_hypotheses(
        self,
        hypotheses: Iterable[AttackHypothesis],
    ) -> AttackHypothesis:
        """Merge compatible hypotheses, failing closed on semantic conflicts."""

        snapshots = [
            AttackHypothesis.model_validate(item.model_dump(mode="json"))
            for item in hypotheses
        ]
        if not snapshots:
            raise ValueError("hypothesis merge requires at least one hypothesis")
        architectures = {item.architecture for item in snapshots}
        if len(architectures) != 1:
            raise HypothesisMergeConflict(
                "hypothesis architectures cannot be merged"
            )
        attack_pattern_references = {
            item.attack_pattern_reference
            for item in snapshots
            if item.attack_pattern_reference is not None
        }
        if len(attack_pattern_references) > 1:
            raise HypothesisMergeConflict(
                "hypothesis attack-pattern references conflict"
            )
        source_ids = sorted({item.id for item in snapshots})
        affected_components = sorted(
            {
                component
                for item in snapshots
                for component in item.affected_components
            }
        )
        required_evidence_types = sorted(
            {
                evidence_type
                for item in snapshots
                for evidence_type in item.required_evidence_types
            },
            key=lambda item: item.value,
        )
        return AttackHypothesis.create(
            source=HypothesisSource.ANALYST,
            architecture=snapshots[0].architecture,
            description=(
                "Merged multi-agent hypothesis over source references: "
                + ", ".join(source_ids)
            ),
            affected_components=affected_components,
            attack_pattern_reference=(
                next(iter(attack_pattern_references))
                if attack_pattern_references
                else None
            ),
            required_evidence_types=required_evidence_types,
            confidence=min(item.confidence for item in snapshots),
            metadata={
                "confidence_semantics": "reasoning_only_not_verification_score",
                "domain_truth_creation": False,
                "merge_scope": "compatible_hypotheses_only",
                "source_hypothesis_ids": source_ids,
            },
        )

    def aggregate_evidence_requests(
        self,
        requests: Iterable[EvidenceRequest],
    ) -> list[EvidenceRequest]:
        """Collect unique request contracts without creating Evidence."""

        by_id: dict[str, EvidenceRequest] = {}
        for request in requests:
            snapshot = EvidenceRequest.model_validate(
                request.model_dump(mode="json")
            )
            existing = by_id.get(snapshot.id)
            if existing is not None and existing != snapshot:
                raise ValueError("evidence request ID collision")
            by_id[snapshot.id] = snapshot
        return [by_id[item_id] for item_id in sorted(by_id)]

    def merge_reasoning_results(
        self,
        merged_hypothesis: AttackHypothesis,
        requests: list[EvidenceRequest],
        results: list[ReasoningResult],
    ) -> ReasoningResult:
        """Combine agent reasoning while keeping confidence non-verifying."""

        if not results:
            raise ValueError("reasoning result merge requires agent results")
        result_snapshots = [
            ReasoningResult.model_validate(item.model_dump(mode="json"))
            for item in results
        ]
        reasoning_steps: list[str] = []
        supporting_ids: set[str] = set()
        for result in result_snapshots:
            for step in result.reasoning_steps:
                if step not in reasoning_steps:
                    reasoning_steps.append(step)
            supporting_ids.update(result.supporting_evidence_ids)
        return ReasoningResult.create(
            merged_hypothesis,
            reasoning_steps=reasoning_steps,
            supporting_evidence_ids=sorted(supporting_ids),
            missing_evidence=sorted(item.id for item in requests),
            confidence=min(item.confidence for item in result_snapshots),
            metadata={
                "confidence_semantics": "reasoning_only_not_verification_score",
                "domain_truth_creation": False,
                "merge_scope": "multi_agent_reasoning_only",
                "supporting_evidence_semantics": (
                    "reference_only_not_verified_evidence"
                ),
                "source_reasoning_result_ids": sorted(
                    item.id for item in result_snapshots
                ),
            },
        )

    def propagate_feedback(
        self,
        session: ReasoningSession,
        feedbacks: Iterable[EvidenceFeedback],
    ) -> ReasoningSession:
        """Route request-bound feedback to source agents without rerunning them."""

        snapshot = ReasoningSession.model_validate(
            session.model_dump(mode="json")
        )
        feedback_by_request = {
            item.request_id: item for item in snapshot.feedbacks
        }
        for feedback in feedbacks:
            detached = EvidenceFeedback.model_validate(
                feedback.model_dump(mode="json")
            )
            existing = feedback_by_request.get(detached.request_id)
            if existing is not None and existing.id != detached.id:
                raise ValueError("conflicting feedback for one evidence request")
            feedback_by_request[detached.request_id] = detached

        combined_feedback = [
            feedback_by_request[request_id]
            for request_id in sorted(feedback_by_request)
        ]
        source_messages = [
            item
            for item in snapshot.messages
            if item.message_type is not AgentMessageType.FEEDBACK
        ]
        request_senders: dict[str, set[str]] = {}
        for message in source_messages:
            if message.message_type is AgentMessageType.EVIDENCE_REQUEST:
                request_senders.setdefault(message.content_id, set()).add(
                    message.sender
                )
        messages = list(source_messages)
        agent_order = {
            agent_id: index
            for index, agent_id in enumerate(snapshot.agent_ids)
        }
        for feedback in combined_feedback:
            senders = request_senders.get(feedback.request_id)
            if not senders:
                raise ValueError("feedback references an unroutable evidence request")
            for receiver in sorted(senders, key=lambda item: agent_order[item]):
                messages.append(
                    AgentMessage.create(
                        session_id=snapshot.session_id,
                        sequence_index=len(messages),
                        sender=COORDINATOR_ID,
                        receiver=receiver,
                        message_type=AgentMessageType.FEEDBACK,
                        content_id=feedback.id,
                        metadata={
                            "direction": "coordinator_to_agent",
                            "feedback_scope": "request_observation_match_only",
                        },
                    )
                )
        values = snapshot.model_dump(mode="json")
        values["messages"] = [item.model_dump(mode="json") for item in messages]
        values["feedbacks"] = [
            item.model_dump(mode="json") for item in combined_feedback
        ]
        values["final_reasoning_result"] = _result_with_feedback(
            snapshot.merged_hypothesis,
            snapshot.final_reasoning_result,
            combined_feedback,
        ).model_dump(mode="json")
        return ReasoningSession.model_validate(values)


def _agent_output_messages(
    session_id: str,
    contributions: list[
        tuple[
            str,
            AttackHypothesis,
            list[EvidenceRequest],
            ReasoningResult | None,
        ]
    ],
) -> list[AgentMessage]:
    messages: list[AgentMessage] = []
    for agent_id, hypothesis, requests, result in contributions:
        outputs: list[tuple[AgentMessageType, str]] = [
            (AgentMessageType.HYPOTHESIS, hypothesis.id),
            *[
                (AgentMessageType.EVIDENCE_REQUEST, request.id)
                for request in requests
            ],
        ]
        if result is not None:
            outputs.append((AgentMessageType.REASONING_RESULT, result.id))
        for message_type, content_id in outputs:
            messages.append(
                AgentMessage.create(
                    session_id=session_id,
                    sequence_index=len(messages),
                    sender=agent_id,
                    receiver=COORDINATOR_ID,
                    message_type=message_type,
                    content_id=content_id,
                    metadata={"direction": "agent_to_coordinator"},
                )
            )
    return messages


def _result_with_feedback(
    merged_hypothesis: AttackHypothesis,
    previous: ReasoningResult,
    feedbacks: list[EvidenceFeedback],
) -> ReasoningResult:
    conclusive_statuses = {
        EvidenceFeedbackStatus.SUPPORTED,
        EvidenceFeedbackStatus.UNSUPPORTED,
    }
    conclusive_request_ids = {
        item.request_id
        for item in feedbacks
        if item.status in conclusive_statuses
    }
    unresolved_request_ids = {
        item.request_id
        for item in feedbacks
        if item.status not in conclusive_statuses
    }
    missing_references = set(previous.missing_evidence)
    missing_references.difference_update(conclusive_request_ids)
    missing_references.update(unresolved_request_ids)
    reasoning_steps = list(previous.reasoning_steps)
    for feedback in feedbacks:
        step = (
            f"Coordinator propagated feedback for request {feedback.request_id}: "
            f"{feedback.status.value}; feedback only, not verification"
        )
        if step not in reasoning_steps:
            reasoning_steps.append(step)
    metadata = dict(previous.metadata)
    metadata["feedback_propagation"] = {
        "domain_truth_creation": False,
        "feedback_ids": [item.id for item in feedbacks],
        "semantics": "request_observation_feedback_only",
    }
    return ReasoningResult.create(
        merged_hypothesis,
        reasoning_steps=reasoning_steps,
        supporting_evidence_ids=previous.supporting_evidence_ids,
        missing_evidence=sorted(missing_references),
        confidence=previous.confidence,
        metadata=metadata,
    )
