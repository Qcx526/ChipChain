"""Offline Phase 9B2C Step 3 schema and observation hardening tests."""

from __future__ import annotations

import pytest

from chipchain.agents import (
    ProviderBackedAgentWorkflow,
    ProviderBackedWorkflowExecutionError,
    ReasoningContext,
)
from chipchain.models import Architecture
from chipchain.reasoning import (
    LLMProviderResponseError,
    MockReasoningProvider,
    OpenAICompatibleReasoningProvider,
    REASONING_PROVIDER_SCHEMA_NAME,
    ReasoningAgentType,
    ReasoningEngine,
    ReasoningProvider,
    RoleBasedReasoningPromptBuilder,
    StructuredPromptRequest,
    reasoning_provider_output_json_schema,
)
from scripts.check_real_phase9b2c_multi_agent import ObservedReasoningProvider


ROLE_ORDER = (
    ReasoningAgentType.CODE,
    ReasoningAgentType.HARDWARE,
    ReasoningAgentType.VULNERABILITY,
    ReasoningAgentType.ATTACK_CHAIN,
)
OLD_SCHEMA_NAME = "phase9b2b_reasoning_output_v1"


def _context() -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-phase9b2c-step3-subject",
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        observed_fact_ids=["fixture-runtime-fact"],
        available_evidence_ids=["fixture-runtime-evidence-reference"],
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-step3",
        attack_pattern_reference="CAPEC-fixture-step3",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )


def _prompt() -> StructuredPromptRequest:
    return RoleBasedReasoningPromptBuilder().build(
        _context(),
        role=ReasoningAgentType.CODE,
    )


def _old_schema_prompt() -> StructuredPromptRequest:
    payload = _prompt().model_dump(mode="json")
    payload["schema_name"] = OLD_SCHEMA_NAME
    return StructuredPromptRequest.model_validate(payload)


class CapturingProvider(ReasoningProvider):
    """Delegate deterministic output and retain request identity for one test."""

    def __init__(
        self,
        *,
        fail_role: ReasoningAgentType | None = None,
    ) -> None:
        self.fail_role = fail_role
        self.requests: list[StructuredPromptRequest] = []
        self._delegate = MockReasoningProvider()

    def generate(self, request: StructuredPromptRequest) -> str:
        self.requests.append(request)
        if ReasoningAgentType(request.role) is self.fail_role:
            raise LLMProviderResponseError(
                "private fixture failure",
                status_code=503,
                stage="transport",
            )
        return self._delegate.generate(request)


def test_current_provider_schema_is_explicit_reduced_semantic_v2() -> None:
    prompt = _prompt()

    assert REASONING_PROVIDER_SCHEMA_NAME == (
        "phase9b2c_reasoning_semantic_output_v2"
    )
    assert prompt.schema_name == REASONING_PROVIDER_SCHEMA_NAME
    assert REASONING_PROVIDER_SCHEMA_NAME in prompt.system_prompt
    assert OLD_SCHEMA_NAME not in prompt.system_prompt


def test_old_v1_schema_is_rejected_by_mock_and_real_provider_bridge() -> None:
    old_prompt = _old_schema_prompt()

    with pytest.raises(ValueError, match="unsupported reasoning output schema"):
        MockReasoningProvider().generate(old_prompt)

    provider = OpenAICompatibleReasoningProvider.from_env(
        {
            "CHIPCHAIN_LLM_API_KEY": "fixture-secret",
            "CHIPCHAIN_LLM_BASE_URL": "https://fixture.invalid/v1",
            "CHIPCHAIN_LLM_MODEL": "fixture-model",
            "CHIPCHAIN_LLM_API_STYLE": "chat_completions",
            "CHIPCHAIN_LLM_JSON_MODE": "true",
        },
        client=object(),
    )
    with pytest.raises(ValueError, match="unsupported reasoning output schema"):
        provider.generate(old_prompt)


def test_v2_transport_schema_remains_reduced_to_semantic_fields() -> None:
    schema_text = str(reasoning_provider_output_json_schema()).lower()

    for immutable_binding in (
        "affected_components",
        "attack_pattern_reference",
        "required_evidence_types",
        "evidence_type",
        "priority",
        "dynamic_trigger_fact_reference",
    ):
        assert immutable_binding not in schema_text
    assert "description" in schema_text
    assert "required_fact" in schema_text
    assert "reasoning_steps" in schema_text
    assert "supporting_evidence_ids" in schema_text


def test_observed_provider_is_transparent_and_records_only_bounded_identity() -> None:
    delegate = CapturingProvider()
    provider = ObservedReasoningProvider(delegate)
    prompt = _prompt()

    result = provider.generate(prompt)

    assert delegate.requests == [prompt]
    assert delegate.requests[0] is prompt
    assert result == MockReasoningProvider().generate(prompt)
    assert provider.observed_calls == ((prompt.role, prompt.candidate_id),)
    observed_text = repr(provider.observed_calls)
    assert prompt.system_prompt not in observed_text
    assert prompt.user_prompt not in observed_text
    assert result not in observed_text
    assert "fixture-secret" not in observed_text


def test_observed_four_role_workflow_reports_actual_order_and_same_context() -> None:
    delegate = CapturingProvider()
    provider = ObservedReasoningProvider(delegate)
    context = _context()

    session = ProviderBackedAgentWorkflow(
        engine=ReasoningEngine(provider=provider)
    ).execute(context)

    assert provider.observed_calls == tuple(
        (role.value, context.id) for role in ROLE_ORDER
    )
    assert len(provider.observed_calls) == 4
    assert {context_id for _, context_id in provider.observed_calls} == {
        context.id
    }
    assert len(session.hypotheses) == 4
    assert len(session.reasoning_results) == 3


@pytest.mark.parametrize("failed_role", ROLE_ORDER)
def test_observation_preserves_fail_stop_without_retry_or_recovery(
    failed_role: ReasoningAgentType,
) -> None:
    provider = ObservedReasoningProvider(
        CapturingProvider(fail_role=failed_role)
    )

    with pytest.raises(ProviderBackedWorkflowExecutionError) as exc_info:
        ProviderBackedAgentWorkflow(
            engine=ReasoningEngine(provider=provider)
        ).execute(_context())

    failed_index = ROLE_ORDER.index(failed_role)
    assert tuple(role for role, _ in provider.observed_calls) == tuple(
        role.value for role in ROLE_ORDER[: failed_index + 1]
    )
    assert len(provider.observed_calls) == failed_index + 1
    assert exc_info.value.failed_role is failed_role
    assert exc_info.value.completed_roles == ROLE_ORDER[:failed_index]
