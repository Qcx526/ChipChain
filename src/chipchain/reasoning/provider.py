"""Provider abstraction and optional OpenAI-compatible protocol client."""

from __future__ import annotations

from copy import deepcopy
import json
import os
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, TypeVar

from pydantic import ValidationError

from chipchain.reasoning.enums import (
    LLMAPIStyle,
    ReasoningAgentType,
    ReasoningPromptVisibility,
)
from chipchain.reasoning.errors import (
    LLMProviderConfigurationError,
    LLMProviderResponseError,
)
from chipchain.reasoning.models import (
    CandidateSemanticAssessment,
    LLMProviderConfig,
    PromptRequest,
    REASONING_PROVIDER_SCHEMA_NAME,
    StructuredPromptRequest,
)
from chipchain.reasoning.parser import (
    reasoning_provider_output_json_schema_for_role,
)
from chipchain.reasoning.prompts import reasoning_role_contract
from chipchain.models.common import DomainModel

StructuredModelT = TypeVar("StructuredModelT", bound=DomainModel)


class StructuredOutputProvider(ABC):
    """Vendor-neutral transport for one strict JSON→Pydantic output model."""

    @abstractmethod
    def generate_structured(
        self,
        request: StructuredPromptRequest,
        output_type: type[StructuredModelT],
    ) -> StructuredModelT:
        """Return one validated structured object for the requested schema."""


class ReasoningProvider(ABC):
    """Raw-output provider contract for the bounded reasoning engine."""

    @abstractmethod
    def generate(self, request: StructuredPromptRequest) -> str:
        """Return one JSON string for constrained parsing."""

    def generate_reasoning(self, request: StructuredPromptRequest) -> str:
        """Explicit alias retained for callers that distinguish reasoning output."""

        return self.generate(request)


class MockReasoningProvider(ReasoningProvider):
    """Deterministic offline provider with no transport or external dependency."""

    def generate(self, request: StructuredPromptRequest) -> str:
        """Generate a fixed role-specific proposal from bounded prompt references."""

        if request.schema_name != REASONING_PROVIDER_SCHEMA_NAME:
            raise ValueError("unsupported reasoning output schema")
        try:
            payload = json.loads(request.user_prompt)
            role = ReasoningAgentType(request.role)
            if payload["role"] != role.value:
                raise ValueError("reasoning prompt role mismatch")
            context = payload["reasoning_context"]
            visibility = ReasoningPromptVisibility(
                payload.get("prompt_visibility", "full_context")
            )
            if (
                visibility is ReasoningPromptVisibility.FULL_CONTEXT
                and context["id"] != request.candidate_id
            ):
                raise ValueError("reasoning prompt context identity mismatch")
            if (
                visibility is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
                and not context["id"].startswith("reasoning-prompt-view:")
            ):
                raise ValueError("masked reasoning prompt view identity mismatch")
            if context["architecture"] != request.architecture.value:
                raise ValueError("reasoning prompt architecture mismatch")
            contract = reasoning_role_contract(role)
            if payload["role_contract"] != contract:
                raise ValueError("reasoning prompt role contract mismatch")
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid deterministic reasoning prompt") from exc

        subject_id = context["subject_id"]
        requests = []
        for request_contract in contract["evidence_requests"]:
            requests.append(
                {
                    "required_fact": request_contract[
                        "required_fact_template"
                    ].format(subject_id=subject_id),
                }
            )
        output = {
            "evidence_requests": requests,
            "hypothesis": {
                "chain_claim": None,
                "confidence": 0.0,
                "description": contract["description_template"].format(
                    subject_id=subject_id
                ),
            },
            "reasoning_result": {
                "confidence": 0.0,
                "reasoning_steps": [
                    contract["reasoning_step_template"].format(
                        subject_id=subject_id
                    )
                ],
                "supporting_evidence_ids": context["available_evidence_ids"],
            },
        }
        return json.dumps(
            output,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )


class LLMProvider(ABC):
    """Vendor-neutral structured semantic-assessment provider contract."""

    @abstractmethod
    def generate(self, request: PromptRequest) -> CandidateSemanticAssessment:
        """Return a strict assessment without modifying candidate facts."""


class OpenAICompatibleLLMProvider(LLMProvider, StructuredOutputProvider):
    """Optional explicit Responses or Chat Completions compatible client."""

    def __init__(
        self,
        *,
        config: LLMProviderConfig,
        api_key: str,
        client: Any | None = None,
    ) -> None:
        """Create a client without storing the API key in serializable state."""

        if not api_key.strip():
            raise LLMProviderConfigurationError("LLM API key is required")
        self._config = config
        self._last_http_status: int | None = None
        if client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise LLMProviderConfigurationError(
                    "optional openai SDK is not installed; install chipchain[llm]"
                ) from exc
            client = OpenAI(
                api_key=api_key,
                base_url=config.base_url,
            )
        self._client = client

    @property
    def config(self) -> LLMProviderConfig:
        """Return detached non-secret provider configuration."""

        return LLMProviderConfig.model_validate(
            self._config.model_dump(mode="json")
        )

    @property
    def last_http_status(self) -> int | None:
        """Return the latest manual connection status without response content."""

        return self._last_http_status

    @classmethod
    def from_env(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        client: Any | None = None,
    ) -> "OpenAICompatibleLLMProvider":
        """Read all provider settings explicitly from environment variables."""

        values = environment if environment is not None else os.environ
        api_key = values.get("CHIPCHAIN_LLM_API_KEY", "")
        base_url = values.get("CHIPCHAIN_LLM_BASE_URL", "")
        model = values.get("CHIPCHAIN_LLM_MODEL", "")
        api_style = values.get("CHIPCHAIN_LLM_API_STYLE", "")
        if not api_key.strip():
            raise LLMProviderConfigurationError("LLM API key is required")
        if not base_url.strip():
            raise LLMProviderConfigurationError("LLM base URL is required")
        if not model.strip():
            raise LLMProviderConfigurationError("LLM model is required")
        if not api_style.strip():
            raise LLMProviderConfigurationError("LLM API style is required")
        try:
            json_mode = _parse_boolean(
                values.get("CHIPCHAIN_LLM_JSON_MODE", "false")
            )
            timeout = float(values.get("CHIPCHAIN_LLM_TIMEOUT", "30"))
            reasoning_effort = (
                values.get("CHIPCHAIN_LLM_REASONING_EFFORT", "").strip() or None
            )
            raw_max_completion_tokens = values.get(
                "CHIPCHAIN_LLM_MAX_COMPLETION_TOKENS", ""
            ).strip()
            max_completion_tokens = (
                int(raw_max_completion_tokens)
                if raw_max_completion_tokens
                else None
            )
            config = LLMProviderConfig(
                base_url=base_url,
                model=model,
                api_style=api_style,
                json_mode=json_mode,
                timeout=timeout,
                reasoning_effort=reasoning_effort,
                max_completion_tokens=max_completion_tokens,
            )
        except (ValueError, ValidationError) as exc:
            raise LLMProviderConfigurationError(
                "invalid non-secret LLM provider configuration"
            ) from exc
        return cls(config=config, api_key=api_key, client=client)

    def generate(self, request: PromptRequest) -> CandidateSemanticAssessment:
        """Preserve the Phase 7 semantic-assessment API."""

        return self.generate_structured(
            StructuredPromptRequest(
                candidate_id=request.candidate_id,
                architecture=request.architecture,
                role="candidate_reasoner",
                schema_name="CandidateSemanticAssessment",
                system_prompt=request.system_prompt,
                user_prompt=request.user_prompt,
            ),
            CandidateSemanticAssessment,
        )

    def generate_structured(
        self,
        request: StructuredPromptRequest,
        output_type: type[StructuredModelT],
    ) -> StructuredModelT:
        """Make one configured protocol call and validate its declared model."""

        content = self.generate_text(request)
        return _parse_structured_output(content, output_type)

    def generate_text(
        self,
        request: StructuredPromptRequest,
        *,
        strict_json_schema: Mapping[str, object] | None = None,
    ) -> str:
        """Make one configured protocol call and return its text unchanged."""

        try:
            if self._config.api_style is LLMAPIStyle.RESPONSES:
                kwargs: dict[str, Any] = {
                    "model": self._config.model,
                    "input": [
                        {"role": "system", "content": request.system_prompt},
                        {"role": "user", "content": request.user_prompt},
                    ],
                    "timeout": self._config.timeout,
                }
                if strict_json_schema is not None:
                    kwargs["text"] = {
                        "format": {
                            "type": "json_schema",
                            "name": request.schema_name,
                            "strict": True,
                            "schema": deepcopy(dict(strict_json_schema)),
                        }
                    }
                elif self._config.json_mode:
                    kwargs["text"] = {"format": {"type": "json_object"}}
                if self._config.reasoning_effort is not None:
                    kwargs["reasoning"] = {
                        "effort": self._config.reasoning_effort
                    }
                if self._config.max_completion_tokens is not None:
                    kwargs["max_output_tokens"] = (
                        self._config.max_completion_tokens
                    )
                response = self._client.responses.create(**kwargs)
                content = response.output_text
            else:
                kwargs = {
                    "model": self._config.model,
                    "messages": [
                        {"role": "system", "content": request.system_prompt},
                        {"role": "user", "content": request.user_prompt},
                    ],
                    "timeout": self._config.timeout,
                }
                if strict_json_schema is not None:
                    kwargs["response_format"] = {
                        "type": "json_schema",
                        "json_schema": {
                            "name": request.schema_name,
                            "strict": True,
                            "schema": deepcopy(dict(strict_json_schema)),
                        },
                    }
                elif self._config.json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                if self._config.reasoning_effort is not None:
                    kwargs["extra_body"] = {
                        "reasoning_effort": self._config.reasoning_effort
                    }
                if self._config.max_completion_tokens is not None:
                    kwargs["max_completion_tokens"] = (
                        self._config.max_completion_tokens
                    )
                response = self._client.chat.completions.create(**kwargs)
                content = response.choices[0].message.content
            return _require_text_output(content)
        except LLMProviderResponseError:
            raise
        except Exception as exc:
            raise LLMProviderResponseError(
                f"LLM provider request failed ({type(exc).__name__})",
                status_code=_status_code(exc),
                stage="transport",
            ) from None

    def check_connection(self) -> str:
        """Send the minimal manual smoke-test request using the configured protocol."""

        try:
            if self._config.api_style is LLMAPIStyle.RESPONSES:
                response = self._create_connection_response(
                    self._client.responses,
                    model=self._config.model,
                    input="Return exactly the word OK.",
                    timeout=self._config.timeout,
                )
                return str(response.output_text).strip()
            response = self._create_connection_response(
                self._client.chat.completions,
                model=self._config.model,
                messages=[
                    {"role": "user", "content": "Return exactly the word OK."}
                ],
                timeout=self._config.timeout,
            )
            return str(response.choices[0].message.content).strip()
        except Exception as exc:
            raise LLMProviderResponseError(
                f"LLM provider connection failed ({type(exc).__name__})",
                status_code=_status_code(exc),
                stage="connection",
            ) from None

    def _create_connection_response(self, endpoint: Any, **kwargs: Any) -> Any:
        """Use SDK raw-response support when available to retain only HTTP status."""

        raw_endpoint = getattr(endpoint, "with_raw_response", None)
        if raw_endpoint is None:
            self._last_http_status = None
            return endpoint.create(**kwargs)
        raw_response = raw_endpoint.create(**kwargs)
        status_code = getattr(raw_response, "status_code", None)
        self._last_http_status = status_code if isinstance(status_code, int) else None
        return raw_response.parse()


class OpenAICompatibleReasoningProvider(ReasoningProvider):
    """Bridge the current reduced semantic contract to existing transport."""

    def __init__(self, transport: OpenAICompatibleLLMProvider) -> None:
        if not isinstance(transport, OpenAICompatibleLLMProvider):
            raise TypeError(
                "reasoning provider bridge requires OpenAICompatibleLLMProvider"
            )
        self._transport = transport

    @property
    def config(self) -> LLMProviderConfig:
        """Return the transport's detached, non-secret configuration."""

        return self._transport.config

    @classmethod
    def from_env(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        client: Any | None = None,
    ) -> "OpenAICompatibleReasoningProvider":
        """Build the bridge from the existing explicit environment contract."""

        return cls(
            OpenAICompatibleLLMProvider.from_env(
                environment,
                client=client,
            )
        )

    def generate(self, request: StructuredPromptRequest) -> str:
        """Return provider text for the existing constrained reasoning parser."""

        if request.schema_name != REASONING_PROVIDER_SCHEMA_NAME:
            raise ValueError("unsupported reasoning output schema")
        try:
            role = ReasoningAgentType(request.role)
            reasoning_role_contract(role)
        except ValueError:
            raise ValueError("unsupported reasoning provider role") from None
        strict_schema = (
            reasoning_provider_output_json_schema_for_role(role)
            if self._transport.config.json_mode
            else None
        )
        return self._transport.generate_text(
            request,
            strict_json_schema=strict_schema,
        )


def _parse_boolean(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError("boolean configuration must be true or false")


def _parse_structured_output(
    content: object,
    output_type: type[StructuredModelT],
) -> StructuredModelT:
    text = _require_text_output(content)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        raise LLMProviderResponseError(
            "LLM provider returned invalid structured output JSON",
            stage="json_parse",
        ) from None
    try:
        return output_type.model_validate(payload)
    except ValidationError:
        raise LLMProviderResponseError(
            "LLM provider returned invalid structured output JSON",
            stage="pydantic_validation",
        ) from None


def _require_text_output(content: object) -> str:
    if not isinstance(content, str):
        raise LLMProviderResponseError(
            "LLM provider returned non-text output",
            stage="response_content",
        )
    return content


def _status_code(exception: Exception) -> int | None:
    value = getattr(exception, "status_code", None)
    return value if isinstance(value, int) else None
