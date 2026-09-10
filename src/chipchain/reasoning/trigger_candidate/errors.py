"""Sanitized boundary errors; never echo untrusted provider output or secrets."""


class TriggerCandidateReasoningError(ValueError):
    """A reasoning declaration or execution failed closed."""


class ReasoningRequestError(TriggerCandidateReasoningError):
    """Request/context/profile integrity failed before provider invocation."""


class ProposalParseError(TriggerCandidateReasoningError):
    """Raw JSON or the closed proposal schema was rejected, without repair."""


class CandidateMaterializationError(TriggerCandidateReasoningError):
    """References or frozen normative/candidate constraints were rejected."""


class ProviderGenerationError(TriggerCandidateReasoningError):
    """Provider failed or changed its declared profile; no retry is performed."""
