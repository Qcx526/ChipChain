"""Offline tests for explicit OpenAI-compatible protocol construction."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from chipchain.reasoning import (
    CandidatePromptBuilder,
    CandidateReasoningInput,
    CandidateRetrievalQueryBuilder,
    CandidateSemanticAssessment,
    LLMProviderConfig,
    LLMProviderConfigurationError,
    LLMProviderResponseError,
    LocalLexicalKnowledgeRetriever,
    OpenAICompatibleLLMProvider,
)


class FakeEndpoint:
    """Record protocol kwargs and return configured SDK-like response objects."""

    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class FakeClient:
    """Expose both SDK endpoint shapes without importing the optional SDK."""

    def __init__(self, content: str, *, error: Exception | None = None) -> None:
        self.responses = FakeEndpoint(
            SimpleNamespace(output_text=content),
            error=error,
        )
        chat_endpoint = FakeEndpoint(
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
            ),
            error=error,
        )
        self.chat = SimpleNamespace(
            completions=chat_endpoint
        )


def make_prompt_request(reasoning_context, rag_fixture_documents):
    """Create one bounded PromptRequest for provider transport tests."""

    query = CandidateRetrievalQueryBuilder().build(reasoning_context)
    chunks = LocalLexicalKnowledgeRetriever(rag_fixture_documents).retrieve(
        query,
        architecture="arm",
        top_k=2,
    ).chunks
    builder = CandidatePromptBuilder()
    reasoning_input = CandidateReasoningInput(
        candidate_id=reasoning_context.candidate_id,
        architecture="arm",
        candidate_context=reasoning_context,
        retrieved_chunks=chunks,
        analysis_instructions=builder.analysis_instructions,
    )
    return builder.build(reasoning_input)


def assessment_json(request) -> str:
    """Return strict minimal assessment JSON accepted by the provider parser."""

    return CandidateSemanticAssessment(
        candidate_id=request.candidate_id,
        architecture=request.architecture,
        summary="Fixture assessment requires verification.",
        unresolved_trigger_node_ids=[
            item.id
            for item in request.reasoning_input.candidate_context.trigger_nodes
        ],
        unresolved_precondition_node_ids=[
            item.id
            for item in request.reasoning_input.candidate_context.precondition_nodes
        ],
        semantic_status="requires_verification",
    ).model_dump_json()


@pytest.mark.parametrize(
    ("missing", "message"),
    [
        ("CHIPCHAIN_LLM_API_KEY", "API key"),
        ("CHIPCHAIN_LLM_BASE_URL", "base URL"),
        ("CHIPCHAIN_LLM_MODEL", "model"),
        ("CHIPCHAIN_LLM_API_STYLE", "API style"),
    ],
)
def test_provider_environment_requires_all_core_values(
    missing: str, message: str
) -> None:
    """Optional real provider never guesses credentials, endpoint, model, or protocol."""

    environment = {
        "CHIPCHAIN_LLM_API_KEY": "fixture-secret",
        "CHIPCHAIN_LLM_BASE_URL": "https://fixture.invalid/v1",
        "CHIPCHAIN_LLM_MODEL": "fixture-model",
        "CHIPCHAIN_LLM_API_STYLE": "chat_completions",
    }
    del environment[missing]

    with pytest.raises(LLMProviderConfigurationError, match=message):
        OpenAICompatibleLLMProvider.from_env(
            environment,
            client=FakeClient("{}"),
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CHIPCHAIN_LLM_API_STYLE", "automatic"),
        ("CHIPCHAIN_LLM_JSON_MODE", "maybe"),
        ("CHIPCHAIN_LLM_TIMEOUT", "zero"),
    ],
)
def test_provider_rejects_invalid_non_secret_configuration(
    name: str, value: str
) -> None:
    """Protocol, capability, and timeout choices are explicit and validated."""

    environment = {
        "CHIPCHAIN_LLM_API_KEY": "fixture-secret",
        "CHIPCHAIN_LLM_BASE_URL": "https://fixture.invalid/v1",
        "CHIPCHAIN_LLM_MODEL": "fixture-model",
        "CHIPCHAIN_LLM_API_STYLE": "chat_completions",
        name: value,
    }

    with pytest.raises(LLMProviderConfigurationError, match="non-secret"):
        OpenAICompatibleLLMProvider.from_env(
            environment,
            client=FakeClient("{}"),
        )


def test_provider_reads_explicit_optional_reasoning_limits() -> None:
    """Thinking effort and completion limits remain explicit environment choices."""

    provider = OpenAICompatibleLLMProvider.from_env(
        {
            "CHIPCHAIN_LLM_API_KEY": "fixture-secret",
            "CHIPCHAIN_LLM_BASE_URL": "https://fixture.invalid/v1",
            "CHIPCHAIN_LLM_MODEL": "fixture-model",
            "CHIPCHAIN_LLM_API_STYLE": "chat_completions",
            "CHIPCHAIN_LLM_REASONING_EFFORT": "none",
            "CHIPCHAIN_LLM_MAX_COMPLETION_TOKENS": "2048",
        },
        client=FakeClient("{}"),
    )

    assert provider.config.reasoning_effort == "none"
    assert provider.config.max_completion_tokens == 2048


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CHIPCHAIN_LLM_REASONING_EFFORT", "unsupported"),
        ("CHIPCHAIN_LLM_MAX_COMPLETION_TOKENS", "zero"),
    ],
)
def test_provider_rejects_invalid_optional_reasoning_limits(
    name: str,
    value: str,
) -> None:
    """Invalid compatible-model controls fail without transport fallback."""

    environment = {
        "CHIPCHAIN_LLM_API_KEY": "fixture-secret",
        "CHIPCHAIN_LLM_BASE_URL": "https://fixture.invalid/v1",
        "CHIPCHAIN_LLM_MODEL": "fixture-model",
        "CHIPCHAIN_LLM_API_STYLE": "chat_completions",
        name: value,
    }

    with pytest.raises(LLMProviderConfigurationError, match="non-secret"):
        OpenAICompatibleLLMProvider.from_env(
            environment,
            client=FakeClient("{}"),
        )


def test_manual_connection_check_records_raw_http_status() -> None:
    """The manual smoke path exposes status only, never headers or raw content."""

    parsed = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="OK"))]
    )
    raw_response = SimpleNamespace(status_code=200, parse=lambda: parsed)
    endpoint = SimpleNamespace(
        with_raw_response=SimpleNamespace(
            create=lambda **kwargs: raw_response
        )
    )
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=endpoint),
    )
    provider = OpenAICompatibleLLMProvider(
        config=LLMProviderConfig(
            base_url="https://fixture.invalid/v1",
            model="fixture-model",
            api_style="chat_completions",
        ),
        api_key="fixture-secret",
        client=client,
    )

    assert provider.check_connection() == "OK"
    assert provider.last_http_status == 200


def test_responses_request_construction_and_json_parsing(
    reasoning_context,
    rag_fixture_documents,
) -> None:
    """Responses style uses input/text configuration and strict Pydantic parsing."""

    request = make_prompt_request(reasoning_context, rag_fixture_documents)
    client = FakeClient(assessment_json(request))
    provider = OpenAICompatibleLLMProvider(
        config=LLMProviderConfig(
            base_url="https://fixture.invalid/v1",
            model="fixture-model",
            api_style="responses",
            json_mode=True,
            timeout=12,
            reasoning_effort="low",
            max_completion_tokens=2048,
        ),
        api_key="fixture-secret",
        client=client,
    )

    assessment = provider.generate(request)
    call = client.responses.calls[0]

    assert assessment.candidate_id == request.candidate_id
    assert call["model"] == "fixture-model"
    assert call["timeout"] == 12
    assert call["input"][0]["role"] == "system"  # type: ignore[index]
    assert call["text"] == {"format": {"type": "json_object"}}
    assert call["reasoning"] == {"effort": "low"}
    assert call["max_output_tokens"] == 2048


def test_chat_completions_request_construction_and_json_parsing(
    reasoning_context,
    rag_fixture_documents,
) -> None:
    """Chat Completions remains explicit and uses its own JSON-mode field."""

    request = make_prompt_request(reasoning_context, rag_fixture_documents)
    client = FakeClient(assessment_json(request))
    provider = OpenAICompatibleLLMProvider(
        config=LLMProviderConfig(
            base_url="https://fixture.invalid/v1",
            model="fixture-model",
            api_style="chat_completions",
            json_mode=True,
            reasoning_effort="low",
            max_completion_tokens=4096,
        ),
        api_key="fixture-secret",
        client=client,
    )

    assert provider.generate(request).candidate_id == request.candidate_id
    call = client.chat.completions.calls[0]
    assert call["messages"][1]["role"] == "user"  # type: ignore[index]
    assert call["response_format"] == {"type": "json_object"}
    assert call["extra_body"] == {"reasoning_effort": "low"}
    assert call["max_completion_tokens"] == 4096
    assert "api_key" not in provider.config.model_dump()


@pytest.mark.parametrize(
    "content",
    [
        "not-json",
        json.dumps({"candidate_id": "incomplete"}),
    ],
)
def test_provider_rejects_invalid_or_schema_incomplete_json(
    content: str,
    reasoning_context,
    rag_fixture_documents,
) -> None:
    """Provider output is never repaired with regex or accepted without Pydantic."""

    request = make_prompt_request(reasoning_context, rag_fixture_documents)
    provider = OpenAICompatibleLLMProvider(
        config=LLMProviderConfig(
            base_url="https://fixture.invalid/v1",
            model="fixture-model",
            api_style="responses",
        ),
        api_key="fixture-secret",
        client=FakeClient(content),
    )

    with pytest.raises(LLMProviderResponseError, match="invalid assessment JSON"):
        provider.generate(request)


def test_api_key_is_absent_from_configuration_and_error_text(
    reasoning_context,
    rag_fixture_documents,
) -> None:
    """Even a hostile client exception cannot echo the API key through our error."""

    secret = "fixture-super-secret-key"
    request = make_prompt_request(reasoning_context, rag_fixture_documents)
    provider = OpenAICompatibleLLMProvider(
        config=LLMProviderConfig(
            base_url="https://fixture.invalid/v1",
            model="fixture-model",
            api_style="chat_completions",
        ),
        api_key=secret,
        client=FakeClient("", error=RuntimeError(secret)),
    )

    with pytest.raises(LLMProviderResponseError) as exc_info:
        provider.generate(request)

    assert secret not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert secret not in repr(provider.config)
