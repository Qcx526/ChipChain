"""Bounded public errors for hardware-trigger and semantic analysis."""


class HardwareTriggerMatchingError(Exception):
    """Base class for static firmware trigger-matching failures."""


class UnsupportedTriggerArtifactError(HardwareTriggerMatchingError):
    """Raised when an artifact is outside the ARM A32 ELF scope."""


class InvalidTriggerMatchingInputError(HardwareTriggerMatchingError):
    """Raised when detached inputs, paths, or backend output are invalid."""


class RuntimeTriggerMatchingError(HardwareTriggerMatchingError):
    """Raised when runtime trigger-sequence matching fails closed."""


class InvalidRuntimeTriggerInputError(RuntimeTriggerMatchingError):
    """Raised when a detached runtime/static input violates its contract."""


class RuntimeTriggerBindingError(RuntimeTriggerMatchingError):
    """Raised when runtime and static artifact identities do not match."""


class TriggerabilityAggregationError(HardwareTriggerMatchingError):
    """Base class for fail-closed triggerability aggregation failures."""


class InvalidTriggerabilityInputError(TriggerabilityAggregationError):
    """Raised when a detached Step 4 input violates its own contract."""


class TriggerabilityBindingError(TriggerabilityAggregationError):
    """Raised when valid Step 1-3A contracts contradict each other."""


class AProfileStaticSemanticExtractionError(Exception):
    """Base error for A-profile decoded static semantic extraction."""


class UnsupportedAProfileStaticSemanticArtifactError(
    AProfileStaticSemanticExtractionError
):
    """Raised when an input artifact is outside the ARM64 ELF scope."""


class InvalidAProfileStaticSemanticInputError(
    AProfileStaticSemanticExtractionError
):
    """Raised when detached inputs, paths, or backend output are invalid."""


class AProfileStaticSemanticBackendError(
    AProfileStaticSemanticExtractionError
):
    """Raised when angr cannot complete bounded static extraction."""
