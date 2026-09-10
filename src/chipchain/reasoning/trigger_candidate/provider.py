"""Provider interface only; no HTTP implementation, configuration or key loading."""

from typing import Protocol

from chipchain.reasoning.trigger_candidate.contracts import ReasoningProviderProfile, TriggerCandidateReasoningRequest


class TriggerCandidateReasoningProvider(Protocol):
    """Trusted host implementation returns untrusted model text for one request."""

    @property
    def profile(self) -> ReasoningProviderProfile:
        """Explicit declared profile/model; it must stay unchanged during a call."""
        ...

    def generate(self, request: TriggerCandidateReasoningRequest) -> str:
        """Return one raw response; caller always parses/validates it fail closed."""
        ...
