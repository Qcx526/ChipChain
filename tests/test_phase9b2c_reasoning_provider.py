"""Offline Phase 9B2C Step 1 real-provider bridge tests."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from chipchain.agents import ReasoningContext
from chipchain.models import Architecture
from chipchain.multi_agent import EvidenceAnalysis
from chipchain.reasoning import (
    AttackHypothesis,
    ConstrainedReasoningOutputParser,
    EvidenceRequest,
    LLMOutputValidationError,
    LLMProviderConfig,
    LLMProviderResponseError,
    MockReasoningProvider,
    OpenAICompatibleLLMProvider,
    OpenAICompatibleReasoningProvider,
    ReasoningAgentType,
    ReasoningEngine,
    ReasoningProvider,
    REASONING_PROVIDER_SCHEMA_NAME,
    ReasoningResult,
    RoleBasedReasoningPromptBuilder,
    StructuredPromptRequest,
    reasoning_provider_output_json_schema,
)


class FakeEndpoint:
    """Record one SDK-style endpoint without network access."""

    def __init__(
        self,
        response: object,
        *,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class FakeClient:
    """Expose both supported OpenAI SDK protocol shapes."""

    def __init__(
        self,
        content: object,
        *,
        error: Exception | None = None,
    ) -> None:
        self.responses = FakeEndpoint(
            SimpleNamespace(output_text=content),
            error=error,
        )
        completions = FakeEndpoint(
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content=content)
                    )
                ]
            ),
            error=error,
        )
        self.chat = SimpleNamespace(completions=completions)


class TransportFailure(RuntimeError):
    """SDK-like failure carrying an HTTP status without secret content."""

    status_code = 503


def _context() -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-phase9b2c-step1-subject",
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        observed_fact_ids=["fixture-static-fact"],
        available_evidence_ids=["fixture-static-evidence"],
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-reference",
        attack_pattern_reference="CAPEC-fixture-reference",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )


def _prompt() -> StructuredPromptRequest:
    return RoleBasedReasoningPromptBuilder().build(
        _context(),
        role=ReasoningAgentType.CODE,
    )


def _valid_output() -> str:
    return MockReasoningProvider().generate(_prompt())


def _environment(api_style: str) -> dict[str, str]:
    return {
        "CHIPCHAIN_LLM_API_KEY": "fixture-secret",
        "CHIPCHAIN_LLM_BASE_URL": "https://fixture.invalid/v1",
        "CHIPCHAIN_LLM_MODEL": "fixture-model",
        "CHIPCHAIN_LLM_API_STYLE": api_style,
        "CHIPCHAIN_LLM_JSON_MODE": "true",
        "CHIPCHAIN_LLM_TIMEOUT": "17",
        "CHIPCHAIN_LLM_REASONING_EFFORT": "low",
        "CHIPCHAIN_LLM_MAX_COMPLETION_TOKENS": "321",
    }


def _resolve_schema_ref(
    root: dict[str, object],
    value: object,
) -> dict[str, object]:
    assert isinstance(value, dict)
    reference = value.get("$ref")
    if reference is None:
        return value
    assert isinstance(reference, str)
    assert reference.startswith("#/$defs/")
    definitions = root["$defs"]
    assert isinstance(definitions, dict)
    resolved = definitions[reference.removeprefix("#/$defs/")]
    assert isinstance(resolved, dict)
    return resolved


def _nested_contracts() -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    schema = reasoning_provider_output_json_schema()
    properties = schema["properties"]
    assert isinstance(properties, dict)
    hypothesis = _resolve_schema_ref(schema, properties["hypothesis"])
    requests = properties["evidence_requests"]
    assert isinstance(requests, dict)
    request = _resolve_schema_ref(schema, requests["items"])
    result = _resolve_schema_ref(schema, properties["reasoning_result"])
    return schema, hypothesis, request, result


def _object_schemas(value: object):
    """Yield every inline or defined object contract exactly once by location."""

    if isinstance(value, dict):
        if isinstance(value.get("properties"), dict):
            yield value
        for nested in value.values():
            yield from _object_schemas(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _object_schemas(nested)


def test_chat_completions_bridge_returns_raw_text_and_propagates_config() -> None:
    prompt = _prompt()
    content = _valid_output()
    client = FakeClient(content)
    provider = OpenAICompatibleReasoningProvider.from_env(
        _environment("chat_completions"),
        client=client,
    )

    raw = provider.generate(prompt)

    assert isinstance(provider, ReasoningProvider)
    assert raw == content
    assert len(client.chat.completions.calls) == 1
    call = client.chat.completions.calls[0]
    assert call["model"] == "fixture-model"
    assert call["messages"] == [
        {"role": "system", "content": prompt.system_prompt},
        {"role": "user", "content": prompt.user_prompt},
    ]
    assert call["timeout"] == 17
    response_format = call["response_format"]
    assert isinstance(response_format, dict)
    assert response_format["type"] == "json_schema"
    strict_contract = response_format["json_schema"]
    assert isinstance(strict_contract, dict)
    assert strict_contract["name"] == REASONING_PROVIDER_SCHEMA_NAME
    assert strict_contract["strict"] is True
    assert strict_contract["schema"] == reasoning_provider_output_json_schema()
    assert call["extra_body"] == {"reasoning_effort": "low"}
    assert call["max_completion_tokens"] == 321
    assert "api_key" not in provider.config.model_dump(mode="json")


def test_responses_bridge_returns_raw_text_and_propagates_config() -> None:
    prompt = _prompt()
    content = _valid_output()
    client = FakeClient(content)
    provider = OpenAICompatibleReasoningProvider.from_env(
        _environment("responses"),
        client=client,
    )

    raw = provider.generate(prompt)

    assert raw == content
    assert len(client.responses.calls) == 1
    call = client.responses.calls[0]
    assert call["model"] == "fixture-model"
    assert call["input"] == [
        {"role": "system", "content": prompt.system_prompt},
        {"role": "user", "content": prompt.user_prompt},
    ]
    assert call["timeout"] == 17
    text_format = call["text"]
    assert isinstance(text_format, dict)
    strict_contract = text_format["format"]
    assert isinstance(strict_contract, dict)
    assert strict_contract["type"] == "json_schema"
    assert strict_contract["name"] == REASONING_PROVIDER_SCHEMA_NAME
    assert strict_contract["strict"] is True
    assert strict_contract["schema"] == reasoning_provider_output_json_schema()
    assert call["reasoning"] == {"effort": "low"}
    assert call["max_output_tokens"] == 321


def test_bridge_transport_exception_fails_closed_with_bounded_error() -> None:
    client = FakeClient("", error=TransportFailure("private-detail"))
    provider = OpenAICompatibleReasoningProvider.from_env(
        _environment("chat_completions"),
        client=client,
    )

    with pytest.raises(LLMProviderResponseError) as exc_info:
        provider.generate(_prompt())

    assert exc_info.value.stage == "transport"
    assert exc_info.value.status_code == 503
    assert "private-detail" not in str(exc_info.value)
    assert len(client.chat.completions.calls) == 1
    assert len(client.responses.calls) == 0


def test_non_text_and_malformed_results_do_not_become_reasoning_truth() -> None:
    non_text = OpenAICompatibleReasoningProvider.from_env(
        _environment("responses"),
        client=FakeClient(None),
    )
    with pytest.raises(LLMProviderResponseError) as exc_info:
        non_text.generate(_prompt())
    assert exc_info.value.stage == "response_content"

    malformed = OpenAICompatibleReasoningProvider.from_env(
        _environment("chat_completions"),
        client=FakeClient("not-json"),
    )
    with pytest.raises(LLMOutputValidationError, match="not valid JSON"):
        ReasoningEngine(provider=malformed).reason(
            _context(),
            role=ReasoningAgentType.CODE,
        )


def test_existing_structured_provider_api_still_validates_phase8_output() -> None:
    expected = EvidenceAnalysis(
        candidate_id="fixture-candidate",
        architecture=Architecture.ARM,
        missing_behavior_evidence=False,
        missing_knowledge_evidence=False,
        analysis_status="context_ready",
    )
    client = FakeClient(expected.model_dump_json())
    provider = OpenAICompatibleLLMProvider(
        config=LLMProviderConfig(
            base_url="https://fixture.invalid/v1",
            model="fixture-model",
            api_style="chat_completions",
        ),
        api_key="fixture-secret",
        client=client,
    )
    request = StructuredPromptRequest(
        candidate_id="fixture-candidate",
        architecture=Architecture.ARM,
        role="evidence_analyst",
        schema_name="EvidenceAnalysis",
        system_prompt="Return strict fixture JSON.",
        user_prompt="{}",
    )

    assert provider.generate_structured(request, EvidenceAnalysis) == expected
    assert len(client.chat.completions.calls) == 1


@pytest.mark.parametrize(
    ("api_style", "format_key"),
    [("chat_completions", "response_format"), ("responses", "text")],
)
def test_legacy_json_mode_remains_json_object(
    api_style: str,
    format_key: str,
) -> None:
    expected = EvidenceAnalysis(
        candidate_id="fixture-candidate",
        architecture=Architecture.ARM,
        missing_behavior_evidence=False,
        missing_knowledge_evidence=False,
        analysis_status="context_ready",
    )
    client = FakeClient(expected.model_dump_json())
    provider = OpenAICompatibleLLMProvider.from_env(
        _environment(api_style),
        client=client,
    )
    request = StructuredPromptRequest(
        candidate_id="fixture-candidate",
        architecture=Architecture.ARM,
        role="evidence_analyst",
        schema_name="EvidenceAnalysis",
        system_prompt="Return fixture JSON.",
        user_prompt="{}",
    )

    assert provider.generate_structured(request, EvidenceAnalysis) == expected
    call = (
        client.chat.completions.calls[0]
        if api_style == "chat_completions"
        else client.responses.calls[0]
    )
    expected_format = (
        {"type": "json_object"}
        if api_style == "chat_completions"
        else {"format": {"type": "json_object"}}
    )
    assert call[format_key] == expected_format


def test_generated_schema_is_deterministic_and_has_exact_required_fields() -> None:
    schema, hypothesis, request, result = _nested_contracts()

    assert schema == reasoning_provider_output_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "hypothesis",
        "evidence_requests",
        "reasoning_result",
    }
    assert set(schema["required"]) == set(schema["properties"])
    expected = (
        (
            hypothesis,
            {"description", "confidence", "chain_claim"},
        ),
        (
            request,
            {"required_fact"},
        ),
        (
            result,
            {"reasoning_steps", "supporting_evidence_ids", "confidence"},
        ),
    )
    for contract, fields in expected:
        assert contract["additionalProperties"] is False
        assert set(contract["properties"]) == fields
        assert set(contract["required"]) == fields

    claim_reference = hypothesis["properties"]["chain_claim"]["anyOf"][0]
    claim = schema["$defs"][claim_reference["$ref"].rsplit("/", 1)[-1]]
    assert claim["additionalProperties"] is False
    assert set(claim["properties"]) == {
        "interaction_type",
        "initiating_vulnerability_ids",
        "target_vulnerability_ids",
        "trigger_behavior_ids",
        "propagation_behavior_ids",
        "affected_execution_ids",
        "fault_state_ids",
        "hardware_resource_ids",
        "security_mechanism_ids",
    }
    assert set(claim["required"]) == set(claim["properties"])
    assert {item.get("type") for item in hypothesis["properties"]["chain_claim"]["anyOf"]} == {
        None,
        "null",
    }


def test_generated_strict_schema_recursively_requires_every_object_property() -> None:
    schema = reasoning_provider_output_json_schema()
    object_schemas = list(_object_schemas(schema))

    assert object_schemas
    for contract in object_schemas:
        assert set(contract["required"]) == set(contract["properties"])
        assert contract["additionalProperties"] is False


def test_mock_explicit_null_is_strict_transport_not_model_authorship() -> None:
    context = _context()
    parser = ConstrainedReasoningOutputParser()
    prompt = RoleBasedReasoningPromptBuilder().build(
        context,
        role=ReasoningAgentType.CODE,
    )
    explicit_null = json.loads(MockReasoningProvider().generate(prompt))
    omitted = json.loads(json.dumps(explicit_null))
    del omitted["hypothesis"]["chain_claim"]

    null_contracts = parser.parse(
        json.dumps(explicit_null),
        context=context,
        role=ReasoningAgentType.CODE,
    )
    omitted_contracts = parser.parse(
        json.dumps(omitted),
        context=context,
        role=ReasoningAgentType.CODE,
    )

    assert explicit_null["hypothesis"]["chain_claim"] is None
    assert null_contracts == omitted_contracts
    assert null_contracts[0].model_authored_chain_claim is None


def test_generated_schema_preserves_confidence_constraints() -> None:
    _, hypothesis, _, result = _nested_contracts()

    for contract in (hypothesis, result):
        confidence = contract["properties"]["confidence"]
        assert confidence["minimum"] == 0.0
        assert confidence["maximum"] == 1.0


def test_generated_schema_excludes_deterministic_binding_authority() -> None:
    _, hypothesis, request, _ = _nested_contracts()

    assert {
        "affected_components",
        "attack_pattern_reference",
        "required_evidence_types",
    }.isdisjoint(hypothesis["properties"])
    assert {
        "evidence_type",
        "priority",
        "dynamic_trigger_fact_reference",
    }.isdisjoint(request["properties"])


def test_prompt_requires_exact_unfenced_reference_bound_json() -> None:
    prompt = _prompt()

    for requirement in (
        "exactly one JSON object",
        "no Markdown code fences",
        "no text before or after",
        "Do not add fields",
        "does not author context identity or role-contract fields",
        "select zero or more exact IDs from available_evidence_ids",
        "Do not emit affected_components",
    ):
        assert requirement in prompt.system_prompt


def test_structurally_invalid_provider_output_is_rejected_at_schema_stage() -> None:
    payload = json.loads(_valid_output())
    del payload["reasoning_result"]["supporting_evidence_ids"]
    provider = OpenAICompatibleReasoningProvider.from_env(
        _environment("chat_completions"),
        client=FakeClient(json.dumps(payload)),
    )

    with pytest.raises(LLMOutputValidationError) as exc_info:
        ReasoningEngine(provider=provider).reason(
            _context(),
            role=ReasoningAgentType.CODE,
        )

    assert exc_info.value.stage == "output_schema"


@pytest.mark.parametrize(
    ("mutation", "expected_stage"),
    [("evidence", "evidence_reference"), ("component", "output_schema")],
)
def test_hallucinated_references_or_immutable_fields_are_rejected(
    mutation: str,
    expected_stage: str,
) -> None:
    payload = json.loads(_valid_output())
    if mutation == "evidence":
        payload["reasoning_result"]["supporting_evidence_ids"].append(
            "invented-evidence"
        )
    else:
        payload["hypothesis"]["affected_components"] = ["invented-component"]
    provider = OpenAICompatibleReasoningProvider.from_env(
        _environment("chat_completions"),
        client=FakeClient(json.dumps(payload)),
    )

    with pytest.raises(LLMOutputValidationError) as exc_info:
        ReasoningEngine(provider=provider).reason(
            _context(),
            role=ReasoningAgentType.CODE,
        )

    assert exc_info.value.stage == expected_stage


def test_reasoning_engine_real_bridge_executes_code_role_through_parser() -> None:
    client = FakeClient(_valid_output())
    provider = OpenAICompatibleReasoningProvider.from_env(
        _environment("chat_completions"),
        client=client,
    )

    hypothesis, requests, result = ReasoningEngine(provider=provider).reason(
        _context(),
        role=ReasoningAgentType.CODE,
    )

    assert type(hypothesis) is AttackHypothesis
    assert requests and all(type(item) is EvidenceRequest for item in requests)
    assert type(result) is ReasoningResult
    assert result.hypothesis_id == hypothesis.id
    assert len(client.chat.completions.calls) == 1


@pytest.mark.parametrize(
    "forbidden_field",
    ["verification_status", "vulnerability_verdict"],
)
def test_forbidden_provider_truth_is_rejected_only_by_existing_parser(
    forbidden_field: str,
) -> None:
    payload = json.loads(_valid_output())
    payload[forbidden_field] = "verified"
    provider = OpenAICompatibleReasoningProvider.from_env(
        _environment("chat_completions"),
        client=FakeClient(json.dumps(payload)),
    )

    with pytest.raises(LLMOutputValidationError, match="forbidden truth field"):
        try:
            ReasoningEngine(provider=provider).reason(
                _context(),
                role=ReasoningAgentType.CODE,
            )
        except LLMOutputValidationError as exc:
            assert exc.stage == "forbidden_truth_field"
            raise
