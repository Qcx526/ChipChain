"""Phase 9B2B Step 6 multi-agent orchestration contract tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from chipchain.agents import (
    COORDINATOR_ID,
    AgentMessage,
    AgentMessageType,
    AgentWorkflow,
    HypothesisMergeConflict,
    MultiAgentReasoningCoordinator,
    ReasoningContext,
    ReasoningSession,
    reasoning_agent_id,
)
from chipchain.models import Architecture
from chipchain.reasoning import (
    AttackHypothesis,
    EvidenceCategory,
    EvidenceFeedback,
    EvidenceFeedbackStatus,
    EvidenceRequest,
    HypothesisSource,
    ObservationFeedbackRelation,
    ReasoningAgentType,
    ReasoningObservation,
    ReasoningResult,
)


ROOT = Path(__file__).resolve().parents[1]
EXECUTION_ORDER = [
    ReasoningAgentType.CODE,
    ReasoningAgentType.HARDWARE,
    ReasoningAgentType.VULNERABILITY,
    ReasoningAgentType.ATTACK_CHAIN,
]


def _context(
    *,
    metadata: dict[str, object] | None = None,
) -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-phase9b2b-step6-subject",
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        observed_fact_ids=["fixture-static-fact", "fixture-dynamic-fact"],
        available_evidence_ids=[
            "fixture-static-evidence",
            "fixture-runtime-evidence",
        ],
        knowledge_entry_ids=["fixture-cwe-entry", "fixture-hardware-entry"],
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-reference",
        attack_pattern_reference="CAPEC-fixture-reference",
        metadata=metadata,
    )


def _session() -> ReasoningSession:
    return AgentWorkflow().execute(_context())


def test_reasoning_session_id_is_deterministic() -> None:
    first = AgentWorkflow().execute(_context(metadata={"non_semantic": 1}))
    second = AgentWorkflow().execute(_context(metadata={"non_semantic": 2}))
    repeated = AgentWorkflow().execute(_context(metadata={"non_semantic": 1}))

    assert first.session_id == second.session_id == repeated.session_id
    assert first == repeated
    assert ReasoningSession.model_validate_json(
        first.model_dump_json()
    ) == first


def test_agent_messages_have_deterministic_ids_and_fixed_order() -> None:
    first = _session()
    second = _session()

    assert [item.id for item in first.messages] == [
        item.id for item in second.messages
    ]
    assert [item.sequence_index for item in first.messages] == list(range(13))
    assert [item.message_type for item in first.messages] == [
        AgentMessageType.HYPOTHESIS,
        AgentMessageType.EVIDENCE_REQUEST,
        AgentMessageType.EVIDENCE_REQUEST,
        AgentMessageType.REASONING_RESULT,
        AgentMessageType.HYPOTHESIS,
        AgentMessageType.EVIDENCE_REQUEST,
        AgentMessageType.EVIDENCE_REQUEST,
        AgentMessageType.REASONING_RESULT,
        AgentMessageType.HYPOTHESIS,
        AgentMessageType.EVIDENCE_REQUEST,
        AgentMessageType.EVIDENCE_REQUEST,
        AgentMessageType.REASONING_RESULT,
        AgentMessageType.HYPOTHESIS,
    ]
    assert all(item.receiver == COORDINATOR_ID for item in first.messages)
    assert AgentMessage.model_validate_json(
        first.messages[0].model_dump_json()
    ) == first.messages[0]


def test_workflow_execution_order_and_attack_chain_role_scope() -> None:
    session = _session()
    expected_agent_ids = [reasoning_agent_id(role) for role in EXECUTION_ORDER]

    assert session.agent_ids == expected_agent_ids
    assert session.metadata["execution_order"] == [
        role.value for role in EXECUTION_ORDER
    ]
    attack_chain_messages = session.messages_for(expected_agent_ids[-1])
    assert len(attack_chain_messages) == 1
    assert attack_chain_messages[0].message_type is AgentMessageType.HYPOTHESIS
    assert session.metadata["attack_chain_agent_scope"] == "hypothesis_only"


def test_multi_agent_hypothesis_and_result_merge() -> None:
    session = _session()

    assert len(session.hypotheses) == 4
    assert len(session.reasoning_results) == 3
    assert type(session.merged_hypothesis) is AttackHypothesis
    assert type(session.final_reasoning_result) is ReasoningResult
    assert session.final_reasoning_result.hypothesis_id == (
        session.merged_hypothesis.id
    )
    assert session.merged_hypothesis.metadata["source_hypothesis_ids"] == sorted(
        item.id for item in session.hypotheses
    )
    assert session.final_reasoning_result.metadata[
        "source_reasoning_result_ids"
    ] == sorted(item.id for item in session.reasoning_results)
    assert session.final_reasoning_result.supporting_evidence_ids == [
        "fixture-runtime-evidence",
        "fixture-static-evidence",
    ]
    assert session.final_reasoning_result.confidence == 0.0


def test_evidence_request_aggregation_is_unique_and_deterministic() -> None:
    session = _session()
    requests = session.evidence_requests
    hypothesis_by_id = {item.id: item for item in session.hypotheses}

    assert len(requests) == 6
    assert [item.id for item in requests] == sorted(item.id for item in requests)
    assert len({item.id for item in requests}) == len(requests)
    assert [item.evidence_type for item in requests].count(
        EvidenceCategory.STATIC_BEHAVIOR
    ) == 2
    assert [item.evidence_type for item in requests].count(
        EvidenceCategory.RUNTIME_OBSERVATION
    ) == 2
    assert [item.evidence_type for item in requests].count(
        EvidenceCategory.MMIO_ACCESS
    ) == 1
    assert [item.evidence_type for item in requests].count(
        EvidenceCategory.PRIVILEGE_TRANSITION
    ) == 1
    for request in requests:
        request.validate_against(hypothesis_by_id[request.hypothesis_id])
    assert session.final_reasoning_result.missing_evidence == [
        item.id for item in requests
    ]


def test_feedback_is_propagated_to_the_request_source_agent() -> None:
    workflow = AgentWorkflow()
    session = workflow.execute(_context())
    request = session.evidence_requests[0]
    hypothesis = next(
        item for item in session.hypotheses if item.id == request.hypothesis_id
    )
    observation = ReasoningObservation.create(
        source_observation_id="fixture-step6-observation",
        request=request,
        architecture=Architecture.ARM,
        observed_fact=request.required_fact,
        relation=ObservationFeedbackRelation.MATCH,
    )
    feedback = EvidenceFeedback.create(
        hypothesis,
        request,
        [observation],
    )
    updated = workflow.propagate_feedback(session, [feedback])
    repeated = workflow.propagate_feedback(updated, [feedback])
    request_message = next(
        item
        for item in session.messages
        if item.message_type is AgentMessageType.EVIDENCE_REQUEST
        and item.content_id == request.id
    )

    assert updated.session_id == session.session_id
    assert repeated == updated
    assert updated.feedbacks == [feedback]
    assert len(updated.messages) == len(session.messages) + 1
    feedback_message = updated.messages[-1]
    assert feedback_message.sender == COORDINATOR_ID
    assert feedback_message.receiver == request_message.sender
    assert feedback_message.message_type is AgentMessageType.FEEDBACK
    assert feedback_message.content_id == feedback.id
    assert updated.feedback_for_agent(request_message.sender) == [feedback]
    assert feedback.status is EvidenceFeedbackStatus.SUPPORTED
    assert request.id not in updated.final_reasoning_result.missing_evidence
    assert updated.final_reasoning_result.supporting_evidence_ids == (
        session.final_reasoning_result.supporting_evidence_ids
    )
    assert updated.final_reasoning_result.confidence == (
        session.final_reasoning_result.confidence
    )


def test_conflicting_hypotheses_fail_closed_without_a_verdict() -> None:
    coordinator = MultiAgentReasoningCoordinator()
    common = {
        "source": HypothesisSource.ANALYST,
        "architecture": Architecture.ARM,
        "description": "Fixture hypothesis",
        "affected_components": ["fixture-arm-driver"],
        "required_evidence_types": [EvidenceCategory.STATIC_BEHAVIOR],
        "confidence": 0.0,
    }
    first = AttackHypothesis.create(
        **common,
        attack_pattern_reference="CAPEC-fixture-a",
    )
    second = AttackHypothesis.create(
        **common,
        attack_pattern_reference="CAPEC-fixture-b",
    )

    with pytest.raises(HypothesisMergeConflict, match="references conflict"):
        coordinator.merge_hypotheses([first, second])


def test_orchestration_has_no_verdict_or_attack_chain_creation() -> None:
    session = _session()
    assert all(type(item) is AttackHypothesis for item in session.hypotheses)
    assert all(type(item) is EvidenceRequest for item in session.evidence_requests)
    assert all(type(item) is ReasoningResult for item in session.reasoning_results)
    assert type(session.final_reasoning_result) is ReasoningResult
    assert not hasattr(session, "attack_chain")

    forbidden_keys = {
        "attack_chain",
        "attack_chain_status",
        "evidence",
        "interaction_verification_status",
        "verification_record",
        "verification_score",
        "verification_status",
        "vulnerability_status",
        "vulnerability_verdict",
    }

    def all_keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(*(all_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(all_keys(item) for item in value))
        return set()

    assert forbidden_keys.isdisjoint(all_keys(session.model_dump(mode="json")))

    for relative_path in (
        "src/chipchain/agents/state.py",
        "src/chipchain/agents/coordinator.py",
        "src/chipchain/agents/workflow.py",
    ):
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        assert not any(
            module.startswith(
                (
                    "chipchain.runtime",
                    "chipchain.scoring",
                    "chipchain.verification",
                )
            )
            for module in imported_modules
        )
        assert {
            "AttackChain",
            "Evidence",
            "VerificationRecord",
        }.isdisjoint(imported_names)
        assert "AttackChain(" not in source
