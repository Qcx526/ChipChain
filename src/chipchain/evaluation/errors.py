"""Fail-closed errors for Phase 10A objective feasibility assessment."""


class EvaluationOracleError(Exception):
    """Base class for invalid objective-oracle invocation and binding."""


class InvalidChainFeasibilityInputError(EvaluationOracleError):
    """Raised when an oracle input fails type or detached-model validation."""


class ChainFeasibilityBindingError(EvaluationOracleError):
    """Raised when individually valid candidate-side contracts contradict."""


class ModelClaimBindingError(EvaluationOracleError):
    """Raised when valid claim-binding inputs contradict one another."""


class InvalidModelClaimBindingInputError(EvaluationOracleError):
    """Raised when a claim-binding input fails detached validation."""


class BenchmarkEvaluationError(Exception):
    """Base class for invalid Phase 10B aggregation inputs."""


class InvalidBenchmarkEvaluationInputError(BenchmarkEvaluationError):
    """Raised when a runner input fails type or detached revalidation."""


class BenchmarkEvaluationBindingError(BenchmarkEvaluationError):
    """Raised when individually valid frozen evaluation outputs contradict."""


class BenchmarkCaseAccountingError(BenchmarkEvaluationError):
    """Raised when manifest cases are missing, duplicated, or added post hoc."""
