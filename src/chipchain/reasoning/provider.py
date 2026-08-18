"""Provider abstraction and optional OpenAI-compatible protocol client."""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from chipchain.reasoning.enums import LLMAPIStyle
from chipchain.reasoning.errors import (
    LLMProviderConfigurationError,
    LLMProviderResponseError,
)
from chipchain.reasoning.models import (
    CandidateSemanticAssessment,
    LLMProviderConfig,
    PromptRequest,
)


class LLMProvider(ABC):
    """Vendor-neutral structured semantic-assessment provider contract."""

    @abstractmethod
    def generate(self, request: PromptRequest) -> CandidateSemanticAssessment:
        """Return a strict assessment without modifying candidate facts."""


class OpenAICompatibleLLMProvider(LLMProvider):
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
            config = LLMProviderConfig(
                base_url=base_url,
                model=model,
                api_style=api_style,
                json_mode=json_mode,
                timeout=timeout,
            )
        except (ValueError, ValidationError) as exc:
            raise LLMProviderConfigurationError(
                "invalid non-secret LLM provider configuration"
            ) from exc
        return cls(config=config, api_key=api_key, client=client)

    def generate(self, request: PromptRequest) -> CandidateSemanticAssessment:
        """Make the configured protocol call and strictly parse assessment JSON."""

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
                if self._config.json_mode:
                    kwargs["text"] = {"format": {"type": "json_object"}}
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
                if self._config.json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                response = self._client.chat.completions.create(**kwargs)
                content = response.choices[0].message.content
            return _parse_assessment(content)
        except LLMProviderResponseError:
            raise
        except Exception as exc:
            raise LLMProviderResponseError(
                f"LLM provider request failed ({type(exc).__name__})",
                status_code=_status_code(exc),
            ) from None

    def check_connection(self) -> str:
        """Send the minimal manual smoke-test request using the configured protocol."""

        try:
            if self._config.api_style is LLMAPIStyle.RESPONSES:
                response = self._client.responses.create(
                    model=self._config.model,
                    input="Return exactly the word OK.",
                    timeout=self._config.timeout,
                )
                return str(response.output_text).strip()
            response = self._client.chat.completions.create(
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
            ) from None


def _parse_boolean(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError("boolean configuration must be true or false")


def _parse_assessment(content: object) -> CandidateSemanticAssessment:
    if not isinstance(content, str):
        raise LLMProviderResponseError("LLM provider returned non-text output")
    try:
        payload = json.loads(content)
        return CandidateSemanticAssessment.model_validate(payload)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise LLMProviderResponseError(
            "LLM provider returned invalid assessment JSON"
        ) from None


def _status_code(exception: Exception) -> int | None:
    value = getattr(exception, "status_code", None)
    return value if isinstance(value, int) else None
