"""Public errors raised by deterministic Phase 9A verification."""


class VerificationError(Exception):
    """Base exception for verification configuration or input failures."""


class VerificationInputError(VerificationError):
    """Raised when verification receives inconsistent referenced objects."""


class VerificationConfigurationError(VerificationError):
    """Raised when a score configuration cannot be loaded."""

