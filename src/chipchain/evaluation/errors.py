"""Fail-closed errors for Phase 10A objective feasibility assessment."""


class EvaluationOracleError(Exception):
    """Base class for invalid objective-oracle invocation and binding."""


class InvalidChainFeasibilityInputError(EvaluationOracleError):
    """Raised when an oracle input fails type or detached-model validation."""


class ChainFeasibilityBindingError(EvaluationOracleError):
    """Raised when individually valid candidate-side contracts contradict."""
