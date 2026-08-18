"""Public exception hierarchy for Phase 7 reasoning."""


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

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class LLMOutputValidationError(ReasoningError):
    """Raised when structured output cites facts absent from its input."""
