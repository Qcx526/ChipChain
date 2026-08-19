"""Public failures for deterministic interaction verification."""


class VerificationError(Exception):
    """Base verification failure."""


class VerificationInputError(VerificationError):
    """The supplied interaction, binding, or legacy context is inconsistent."""


class VerificationConfigurationError(VerificationError):
    """A score profile is missing or invalid."""


class UnsupportedVerificationCapabilityError(VerificationError):
    """The requested propagation verifier is intentionally unavailable."""
