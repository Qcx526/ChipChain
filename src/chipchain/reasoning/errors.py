"""Public exception hierarchy for Phase 7 reasoning."""

from chipchain.reasoning.enums import (
    ProviderCompletionState,
    ProviderIncompleteReason,
)


class ReasoningError(Exception):
    """Base class for context, retrieval, prompt, and provider failures."""


class EvidenceResolutionError(ReasoningError):
    """Raised when a requested full Evidence object is unavailable."""


class CandidateContextError(ReasoningError):
    """Raised when candidate references cannot be resolved completely."""


class RetrievalError(ReasoningError):
    """Raised when a retrieval request violates its contract."""


class LLMProviderConfigurationError(ReasoningError):
    """Raised for missing or invalid optional real-provider configuration."""


class LLMProviderResponseError(ReasoningError):
    """Raised when provider output is not strict assessment JSON."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        stage: str = "provider_response",
        completion_state: ProviderCompletionState | str | None = None,
        completion_reason: ProviderIncompleteReason | str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.stage = stage
        self.completion_state = (
            ProviderCompletionState(completion_state)
            if completion_state is not None
            else None
        )
        self.completion_reason = (
            ProviderIncompleteReason(completion_reason)
            if completion_reason is not None
            else None
        )
        if (
            self.completion_reason is not None
            and self.completion_state is not ProviderCompletionState.INCOMPLETE
        ):
            raise ValueError(
                "completion reason requires incomplete provider response"
            )


class LLMOutputValidationError(ReasoningError):
    """Raised when structured output cites facts absent from its input."""

    def __init__(self, message: str, *, stage: str = "output_schema") -> None:
        super().__init__(message)
        self.stage = stage
