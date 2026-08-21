"""Deterministic orchestration state for Phase 9B2B Step 6."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.agents.base import ReasoningContext
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.reasoning.evidence_request import EvidenceRequest
from chipchain.reasoning.feedback import (
    EvidenceFeedback,
    validate_reasoning_feedback_metadata,
)
from chipchain.reasoning.hypothesis import (
    AttackHypothesis,
    _canonical_reasoning_id,
)
from chipchain.reasoning.reasoning_result import ReasoningResult


COORDINATOR_ID = "phase9b2b-reasoning-coordinator"


class AgentMessageType(str, Enum):
    """Permitted orchestration message types."""

    HYPOTHESIS = "hypothesis"
    EVIDENCE_REQUEST = "evidence_request"
    REASONING_RESULT = "reasoning_result"
    FEEDBACK = "feedback"


def reasoning_session_id(
    *,
    reasoning_context_id: str,
    agent_ids: list[str],
    workflow_contract: str,
) -> str:
    """Build session identity without time, run state, or output content."""

    return _canonical_reasoning_id(
        "reasoning-session",
        {
            "agent_ids": agent_ids,
            "reasoning_context_id": reasoning_context_id,
            "workflow_contract": workflow_contract,
        },
    )


def agent_message_id(
    *,
    session_id: str,
    sequence_index: int,
    sender: str,
    receiver: str,
    message_type: AgentMessageType,
    content_id: str,
) -> str:
    """Build deterministic identity for one ordered information transfer."""

    return _canonical_reasoning_id(
        "agent-message",
        {
            "content_id": content_id,
            "message_type": message_type.value,
            "receiver": receiver,
            "sender": sender,
            "sequence_index": sequence_index,
            "session_id": session_id,
        },
    )


class AgentMessage(DomainModel):
    """Reference-only message between an agent and the coordinator."""

    id: Identifier
    session_id: Identifier
    sequence_index: int = Field(ge=0)
    sender: Identifier
    receiver: Identifier
    message_type: AgentMessageType
    content_id: Identifier
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return validate_reasoning_feedback_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "AgentMessage":
        expected_id = agent_message_id(
            session_id=self.session_id,
            sequence_index=self.sequence_index,
            sender=self.sender,
            receiver=self.receiver,
            message_type=self.message_type,
            content_id=self.content_id,
        )
        if self.id != expected_id:
            raise ValueError("AgentMessage ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        sequence_index: int,
        sender: str,
        receiver: str,
        message_type: AgentMessageType | str,
        content_id: str,
        metadata: Metadata | None = None,
    ) -> "AgentMessage":
        """Create one deterministic message containing only an output reference."""

        normalized_type = AgentMessageType(message_type)
        normalized_sender = sender.strip()
        normalized_receiver = receiver.strip()
        normalized_content_id = content_id.strip()
        identity = agent_message_id(
            session_id=session_id,
            sequence_index=sequence_index,
            sender=normalized_sender,
            receiver=normalized_receiver,
            message_type=normalized_type,
            content_id=normalized_content_id,
        )
        return cls(
            id=identity,
            session_id=session_id,
            sequence_index=sequence_index,
            sender=normalized_sender,
            receiver=normalized_receiver,
            message_type=normalized_type,
            content_id=normalized_content_id,
            metadata=metadata or {},
        )


class ReasoningSession(DomainModel):
    """One complete, non-verifying multi-agent reasoning process."""

    workflow_contract: Literal["phase9b2b_multi_agent_workflow_v1"] = (
        "phase9b2b_multi_agent_workflow_v1"
    )
    session_id: Identifier
    reasoning_context: ReasoningContext
    agent_ids: list[Identifier] = Field(min_length=1)
    messages: list[AgentMessage]
    hypotheses: list[AttackHypothesis]
    merged_hypothesis: AttackHypothesis
    evidence_requests: list[EvidenceRequest]
    feedbacks: list[EvidenceFeedback] = Field(default_factory=list)
    reasoning_results: list[ReasoningResult]
    final_reasoning_result: ReasoningResult
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("agent_ids")
    @classmethod
    def validate_agent_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("reasoning session agent IDs must be unique")
        return values

    @field_validator("messages")
    @classmethod
    def normalize_messages(cls, values: list[AgentMessage]) -> list[AgentMessage]:
        ids = [item.id for item in values]
        indexes = [item.sequence_index for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("reasoning session message IDs must be unique")
        if len(indexes) != len(set(indexes)):
            raise ValueError("reasoning session message indexes must be unique")
        return sorted(values, key=lambda item: item.sequence_index)

    @field_validator("hypotheses")
    @classmethod
    def validate_hypotheses(
        cls, values: list[AttackHypothesis]
    ) -> list[AttackHypothesis]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("reasoning session hypothesis IDs must be unique")
        return values

    @field_validator("evidence_requests")
    @classmethod
    def normalize_requests(cls, values: list[EvidenceRequest]) -> list[EvidenceRequest]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("reasoning session request IDs must be unique")
        return sorted(values, key=lambda item: item.id)

    @field_validator("feedbacks")
    @classmethod
    def normalize_feedbacks(
        cls, values: list[EvidenceFeedback]
    ) -> list[EvidenceFeedback]:
        request_ids = [item.request_id for item in values]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("reasoning session permits one feedback per request")
        return sorted(values, key=lambda item: item.request_id)

    @field_validator("reasoning_results")
    @classmethod
    def validate_results(
        cls, values: list[ReasoningResult]
    ) -> list[ReasoningResult]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("reasoning session result IDs must be unique")
        return values

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return validate_reasoning_feedback_metadata(value)

    @model_validator(mode="after")
    def validate_session(self) -> "ReasoningSession":
        expected_id = reasoning_session_id(
            reasoning_context_id=self.reasoning_context.id,
            agent_ids=self.agent_ids,
            workflow_contract=self.workflow_contract,
        )
        if self.session_id != expected_id:
            raise ValueError("ReasoningSession ID is not deterministic")
        if [item.sequence_index for item in self.messages] != list(
            range(len(self.messages))
        ):
            raise ValueError("reasoning session messages must be contiguous")
        if any(item.session_id != self.session_id for item in self.messages):
            raise ValueError("agent message session identity mismatch")
        for message in self.messages:
            if message.message_type is AgentMessageType.FEEDBACK:
                if (
                    message.sender != COORDINATOR_ID
                    or message.receiver not in self.agent_ids
                ):
                    raise ValueError("feedback message direction is invalid")
            elif (
                message.sender not in self.agent_ids
                or message.receiver != COORDINATOR_ID
            ):
                raise ValueError("agent output message direction is invalid")
        if any(
            item.architecture is not self.reasoning_context.architecture
            for item in (*self.hypotheses, self.merged_hypothesis)
        ):
            raise ValueError("reasoning session hypothesis architecture mismatch")

        hypothesis_by_id = {item.id: item for item in self.hypotheses}
        request_by_id = {item.id: item for item in self.evidence_requests}
        result_by_id = {item.id: item for item in self.reasoning_results}
        feedback_by_id = {item.id: item for item in self.feedbacks}
        for request in self.evidence_requests:
            source_hypothesis = hypothesis_by_id.get(request.hypothesis_id)
            if source_hypothesis is None:
                raise ValueError("evidence request references an unknown hypothesis")
            request.validate_against(source_hypothesis)
        for result in self.reasoning_results:
            source_hypothesis = hypothesis_by_id.get(result.hypothesis_id)
            if source_hypothesis is None:
                raise ValueError("reasoning result references an unknown hypothesis")
            result.validate_against(source_hypothesis)
        self.final_reasoning_result.validate_against(self.merged_hypothesis)
        for feedback in self.feedbacks:
            request = request_by_id.get(feedback.request_id)
            if request is None:
                raise ValueError("feedback references an unknown evidence request")
            if feedback.hypothesis_id != request.hypothesis_id:
                raise ValueError("feedback hypothesis identity mismatch")

        content_ids = {
            AgentMessageType.HYPOTHESIS: set(hypothesis_by_id),
            AgentMessageType.EVIDENCE_REQUEST: set(request_by_id),
            AgentMessageType.REASONING_RESULT: {
                *result_by_id,
                self.final_reasoning_result.id,
            },
            AgentMessageType.FEEDBACK: set(feedback_by_id),
        }
        for message in self.messages:
            if message.content_id not in content_ids[message.message_type]:
                raise ValueError("agent message references unknown session content")
        return self

    def messages_for(self, participant_id: str) -> list[AgentMessage]:
        """Return detached messages sent or received by one participant."""

        return [
            AgentMessage.model_validate(item.model_dump(mode="json"))
            for item in self.messages
            if participant_id in {item.sender, item.receiver}
        ]

    def feedback_for_agent(self, agent_id: str) -> list[EvidenceFeedback]:
        """Resolve feedback messages addressed to one agent."""

        feedback_by_id = {item.id: item for item in self.feedbacks}
        return [
            EvidenceFeedback.model_validate(
                feedback_by_id[message.content_id].model_dump(mode="json")
            )
            for message in self.messages
            if message.receiver == agent_id
            and message.message_type is AgentMessageType.FEEDBACK
        ]
