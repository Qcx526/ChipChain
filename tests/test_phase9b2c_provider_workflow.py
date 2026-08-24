"""Offline Phase 9B2C Step 2 provider-backed workflow tests."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from chipchain.agents import (
    AgentMessageType,
    AgentWorkflow,
    ProviderBackedAgentWorkflow,
    ProviderBackedReasoningAgent,
    ProviderBackedWorkflowExecutionError,
    ReasoningContext,
    provider_backed_reasoning_agent_id,
    reasoning_agent_id,
)
from chipchain.models import Architecture, AttackChain, Evidence
from chipchain.reasoning import (
    AttackHypothesis,
    EvidenceRequest,
    LLMProviderResponseError,
    MockReasoningProvider,
    ReasoningAgentType,
    ReasoningEngine,
    ReasoningProvider,
    ReasoningResult,
    RoleBasedReasoningPromptBuilder,
    StructuredPromptRequest,
    reasoning_role_contract,
)


ROLE_ORDER = (
    ReasoningAgentType.CODE,
    ReasoningAgentType.HARDWARE,
    ReasoningAgentType.VULNERABILITY,
    ReasoningAgentType.ATTACK_CHAIN,
)


class RecordingReasoningProvider(ReasoningProvider):
    """Generate deterministic fixture output while recording bounded call data."""

    def __init__(
        self,
        *,
        fail_role: ReasoningAgentType | None = None,
        mutate: Callable[[dict[str, object], ReasoningAgentType], None]
        | None = None,
    ) -> None:
        self.fail_role = fail_role
        self.mutate = mutate
        self.calls: list[tuple[ReasoningAgentType, str]] = []
        self._delegate = MockReasoningProvider()

    def generate(self, request: StructuredPromptRequest) -> str:
        role = ReasoningAgentType(request.role)
        self.calls.append((role, request.candidate_id))
        if role is self.fail_role:
            raise LLMProviderResponseError(
                "bounded fixture provider failure",
                status_code=503,
                stage="transport",
            )
        payload = json.loads(self._delegate.generate(request))
        if self.mutate is not None:
            self.mutate(payload, role)
        return json.dumps(payload, sort_keys=True)


def _context() -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-phase9b2c-step2-subject",
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        observed_fact_ids=["fixture-static-fact", "fixture-runtime-fact"],
        available_evidence_ids=[
            "fixture-runtime-evidence",
            "fixture-static-evidence",
        ],
        knowledge_entry_ids=["fixture-arm-hardware", "fixture-cwe"],
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-step2",
        attack_pattern_reference="CAPEC-fixture-step2",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )


def _prompt_payload(
    role: ReasoningAgentType,
    *,
    context: ReasoningContext | None = None,
) -> tuple[StructuredPromptRequest, dict[str, object]]:
    prompt = RoleBasedReasoningPromptBuilder().build(
        context or _context(),
        role=role,
    )
    return prompt, json.loads(prompt.user_prompt)


def _workflow(
    provider: ReasoningProvider,
) -> ProviderBackedAgentWorkflow:
    return ProviderBackedAgentWorkflow(
        engine=ReasoningEngine(provider=provider)
    )


def test_prompt_limits_provider_authority_and_supporting_evidence_ids() -> None:
    context = _context()
    _, payload = _prompt_payload(ReasoningAgentType.HARDWARE, context=context)
    authority = payload["provider_authority"]

    assert authority["supporting_evidence_ids_allowed_values"] == (
        context.available_evidence_ids
    )
    assert authority["model_authored_fields"] == [
        "hypothesis.description",
        "hypothesis.confidence",
        "evidence_requests[].required_fact",
        "reasoning_result.reasoning_steps",
        "reasoning_result.supporting_evidence_ids",
        "reasoning_result.confidence",
    ]
    assert "output_skeleton" not in payload


def test_system_prompt_states_reduced_model_authority() -> None:
    prompt, _ = _prompt_payload(ReasoningAgentType.CODE)

    for instruction in (
        "does not author context identity or role-contract fields",
        "ChipChain binds those deterministically",
        "You may generate only hypothesis.description",
        "exactly one semantic proposal for each role_contract.evidence_requests",
        "select zero or more exact IDs from available_evidence_ids",
        "Do not emit affected_components",
        "no Markdown code fences",
        "Do not provide hidden reasoning or chain-of-thought",
    ):
        assert instruction in prompt.system_prompt


@pytest.mark.parametrize(
    "mutation",
    [
        "affected_components",
        "attack_pattern_reference",
        "required_evidence_types",
        "evidence_type",
        "priority",
        "dynamic_trigger_fact_reference",
    ],
)
def test_provider_extra_deterministic_fields_are_rejected_at_output_schema(
    mutation: str,
) -> None:
    def alter_binding(
        payload: dict[str, object], role: ReasoningAgentType
    ) -> None:
        if role is not ReasoningAgentType.CODE:
            return
        if mutation in {
            "affected_components",
            "attack_pattern_reference",
            "required_evidence_types",
        }:
            payload["hypothesis"][mutation] = "invented-binding"
        else:
            payload["evidence_requests"][0][mutation] = "invented-binding"

    provider = RecordingReasoningProvider(mutate=alter_binding)

    with pytest.raises(ProviderBackedWorkflowExecutionError) as exc_info:
        _workflow(provider).execute(_context())

    assert exc_info.value.failed_role is ReasoningAgentType.CODE
    assert exc_info.value.stage == "output_schema"
    assert len(provider.calls) == 1


@pytest.mark.parametrize("role", ROLE_ORDER)
def test_parser_deterministically_binds_context_and_role_contract(
    role: ReasoningAgentType,
) -> None:
    context = _context()
    hypothesis, requests, result = ReasoningEngine(
        provider=MockReasoningProvider()
    ).reason(context, role=role)
    role_requests = reasoning_role_contract(role)["evidence_requests"]

    assert hypothesis.affected_components == context.affected_components
    assert hypothesis.attack_pattern_reference == context.attack_pattern_reference
    assert [item.value for item in hypothesis.required_evidence_types] == sorted(
        item["evidence_type"] for item in role_requests
    )
    assert len(requests) == len(role_requests)
    for request, contract in zip(requests, role_requests, strict=True):
        assert request.evidence_type.value == contract["evidence_type"]
        assert request.priority.value == contract["priority"]
        assert request.dynamic_trigger_fact_reference == (
            context.dynamic_trigger_fact_reference
            if contract["use_dynamic_trigger_reference"]
            else None
        )
    assert set(result.supporting_evidence_ids).issubset(
        context.available_evidence_ids
    )


def test_parser_binds_null_attack_pattern_and_accepts_empty_evidence_selection() -> None:
    context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-null-attack-pattern",
        affected_components=["fixture-arm-driver"],
        available_evidence_ids=["fixture-unused-evidence"],
        attack_pattern_reference=None,
    )

    class EmptyEvidenceProvider(ReasoningProvider):
        def generate(self, request: StructuredPromptRequest) -> str:
            payload = json.loads(MockReasoningProvider().generate(request))
            payload["reasoning_result"]["supporting_evidence_ids"] = []
            return json.dumps(payload, sort_keys=True)

    hypothesis, _, result = ReasoningEngine(
        provider=EmptyEvidenceProvider()
    ).reason(context, role=ReasoningAgentType.CODE)

    assert hypothesis.attack_pattern_reference is None
    assert result.supporting_evidence_ids == []


@pytest.mark.parametrize("request_delta", [-1, 1])
def test_provider_request_cardinality_still_fails_closed(
    request_delta: int,
) -> None:
    def alter_cardinality(
        payload: dict[str, object], role: ReasoningAgentType
    ) -> None:
        if role is not ReasoningAgentType.CODE:
            return
        if request_delta < 0:
            payload["evidence_requests"].pop()
        else:
            payload["evidence_requests"].append(
                {"required_fact": "Invented extra request"}
            )

    provider = RecordingReasoningProvider(mutate=alter_cardinality)

    with pytest.raises(ProviderBackedWorkflowExecutionError) as exc_info:
        _workflow(provider).execute(_context())

    assert exc_info.value.failed_role is ReasoningAgentType.CODE
    assert exc_info.value.stage == "request_cardinality"
    assert len(provider.calls) == 1


def test_existing_mock_workflow_is_unchanged() -> None:
    first = AgentWorkflow().execute(_context())
    second = AgentWorkflow().execute(_context())

    assert first == second
    assert first.metadata["orchestration_mode"] == "deterministic_mock"
    assert first.agent_ids == [reasoning_agent_id(role) for role in ROLE_ORDER]
    assert first.metadata["execution_order"] == [
        role.value for role in ROLE_ORDER
    ]


def test_provider_backed_agent_caches_one_engine_call_and_returns_snapshots() -> None:
    provider = RecordingReasoningProvider()
    context = _context()
    agent = ProviderBackedReasoningAgent(
        context,
        role=ReasoningAgentType.CODE,
        engine=ReasoningEngine(provider=provider),
    )

    first_hypothesis = agent.produce_hypothesis()
    requests = agent.request_evidence()
    result = agent.analyze(context)
    first_hypothesis.metadata["caller_mutation"] = True
    repeated_hypothesis = agent.produce_hypothesis()

    assert provider.calls == [(ReasoningAgentType.CODE, context.id)]
    assert first_hypothesis.id == repeated_hypothesis.id
    assert "caller_mutation" not in repeated_hypothesis.metadata
    assert all(item.hypothesis_id == repeated_hypothesis.id for item in requests)
    assert result.hypothesis_id == repeated_hypothesis.id
    assert agent.agent_id == provider_backed_reasoning_agent_id(
        ReasoningAgentType.CODE
    )
    assert "mock" not in agent.agent_id


def test_provider_workflow_calls_four_roles_once_over_same_context() -> None:
    provider = RecordingReasoningProvider()
    context = _context()

    session = _workflow(provider).execute(context)

    assert [role for role, _ in provider.calls] == list(ROLE_ORDER)
    assert len(provider.calls) == 4
    assert {context_id for _, context_id in provider.calls} == {context.id}
    assert session.reasoning_context == ReasoningContext.model_validate(
        context.model_dump(mode="json")
    )
    assert session.agent_ids == [
        provider_backed_reasoning_agent_id(role) for role in ROLE_ORDER
    ]
    assert session.metadata["orchestration_mode"] == (
        "provider_backed_sequential"
    )
    assert session.metadata["execution_order"] == [
        role.value for role in ROLE_ORDER
    ]


def test_provider_session_preserves_attack_chain_hypothesis_only_boundary() -> None:
    provider = RecordingReasoningProvider()
    session = _workflow(provider).execute(_context())
    attack_chain_agent_id = provider_backed_reasoning_agent_id(
        ReasoningAgentType.ATTACK_CHAIN
    )

    assert len(session.hypotheses) == 4
    assert len(session.evidence_requests) == 6
    assert len(session.reasoning_results) == 3
    attack_messages = session.messages_for(attack_chain_agent_id)
    assert len(attack_messages) == 1
    assert attack_messages[0].message_type is AgentMessageType.HYPOTHESIS
    assert all(
        item.metadata["reasoning_role"] != ReasoningAgentType.ATTACK_CHAIN.value
        for item in session.evidence_requests
    )
    assert all(
        item.metadata["reasoning_role"] != ReasoningAgentType.ATTACK_CHAIN.value
        for item in session.reasoning_results
    )
    assert session.metadata["attack_chain_agent_scope"] == "hypothesis_only"


def test_provider_workflow_reuses_conservative_coordinator_merge() -> None:
    confidence_by_role = {
        ReasoningAgentType.CODE: 0.8,
        ReasoningAgentType.HARDWARE: 0.6,
        ReasoningAgentType.VULNERABILITY: 0.4,
        ReasoningAgentType.ATTACK_CHAIN: 0.2,
    }

    def set_confidence(
        payload: dict[str, object], role: ReasoningAgentType
    ) -> None:
        payload["hypothesis"]["confidence"] = confidence_by_role[role]
        payload["reasoning_result"]["confidence"] = confidence_by_role[role]

    session = _workflow(
        RecordingReasoningProvider(mutate=set_confidence)
    ).execute(_context())

    assert session.merged_hypothesis.confidence == 0.2
    assert session.final_reasoning_result.confidence == 0.4
    assert session.final_reasoning_result.supporting_evidence_ids == [
        "fixture-runtime-evidence",
        "fixture-static-evidence",
    ]
    assert session.final_reasoning_result.metadata["confidence_semantics"] == (
        "reasoning_only_not_verification_score"
    )


@pytest.mark.parametrize("failed_role", ROLE_ORDER)
def test_each_role_failure_stops_later_roles_without_retry_or_fallback(
    failed_role: ReasoningAgentType,
) -> None:
    provider = RecordingReasoningProvider(fail_role=failed_role)

    with pytest.raises(ProviderBackedWorkflowExecutionError) as exc_info:
        _workflow(provider).execute(_context())

    failed_index = ROLE_ORDER.index(failed_role)
    assert [role for role, _ in provider.calls] == list(
        ROLE_ORDER[: failed_index + 1]
    )
    assert exc_info.value.failed_role is failed_role
    assert exc_info.value.completed_roles == ROLE_ORDER[:failed_index]
    assert exc_info.value.error_type == "LLMProviderResponseError"
    assert exc_info.value.stage == "transport"
    assert exc_info.value.status_code == 503
    assert "fixture provider failure" not in str(exc_info.value)


@pytest.mark.parametrize("failed_role", ROLE_ORDER)
def test_hallucinated_evidence_at_any_role_fails_closed(
    failed_role: ReasoningAgentType,
) -> None:
    def hallucinate_evidence(
        payload: dict[str, object], role: ReasoningAgentType
    ) -> None:
        if role is failed_role:
            payload["reasoning_result"]["supporting_evidence_ids"].append(
                "invented-evidence"
            )

    provider = RecordingReasoningProvider(mutate=hallucinate_evidence)

    with pytest.raises(ProviderBackedWorkflowExecutionError) as exc_info:
        _workflow(provider).execute(_context())

    assert exc_info.value.failed_role is failed_role
    assert exc_info.value.stage == "evidence_reference"
    assert len(provider.calls) == ROLE_ORDER.index(failed_role) + 1


@pytest.mark.parametrize("failed_role", ROLE_ORDER)
def test_forbidden_truth_at_any_role_fails_closed(
    failed_role: ReasoningAgentType,
) -> None:
    def add_forbidden_truth(
        payload: dict[str, object], role: ReasoningAgentType
    ) -> None:
        if role is failed_role:
            payload["verification_status"] = "verified"

    provider = RecordingReasoningProvider(mutate=add_forbidden_truth)

    with pytest.raises(ProviderBackedWorkflowExecutionError) as exc_info:
        _workflow(provider).execute(_context())

    assert exc_info.value.failed_role is failed_role
    assert exc_info.value.stage == "forbidden_truth_field"
    assert len(provider.calls) == ROLE_ORDER.index(failed_role) + 1


@pytest.mark.parametrize("failed_role", ROLE_ORDER)
def test_reference_violation_at_any_role_fails_closed(
    failed_role: ReasoningAgentType,
) -> None:
    def alter_components(
        payload: dict[str, object], role: ReasoningAgentType
    ) -> None:
        if role is failed_role:
            payload["hypothesis"]["affected_components"] = [
                "invented-component"
            ]

    provider = RecordingReasoningProvider(mutate=alter_components)

    with pytest.raises(ProviderBackedWorkflowExecutionError) as exc_info:
        _workflow(provider).execute(_context())

    assert exc_info.value.failed_role is failed_role
    assert exc_info.value.stage == "output_schema"
    assert len(provider.calls) == ROLE_ORDER.index(failed_role) + 1


def test_provider_session_contains_only_typed_reasoning_and_safe_references() -> None:
    session = _workflow(RecordingReasoningProvider()).execute(_context())
    outputs = [
        *session.hypotheses,
        *session.evidence_requests,
        *session.reasoning_results,
        session.final_reasoning_result,
    ]
    serialized = session.model_dump(mode="json")

    assert all(
        type(item) in {AttackHypothesis, EvidenceRequest, ReasoningResult}
        for item in outputs
    )
    assert not any(isinstance(item, (Evidence, AttackChain)) for item in outputs)
    assert "system_prompt" not in serialized
    assert "user_prompt" not in serialized
    assert "raw_response" not in serialized
    assert "verification_record" not in serialized
    assert "vulnerability_verdict" not in serialized
    assert set(session.final_reasoning_result.supporting_evidence_ids).issubset(
        session.reasoning_context.available_evidence_ids
    )
    session_ids = {
        *(item.id for item in session.hypotheses),
        *(item.id for item in session.evidence_requests),
        *(item.id for item in session.reasoning_results),
        session.final_reasoning_result.id,
    }
    assert all(item.content_id in session_ids for item in session.messages)
