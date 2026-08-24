"""Bounded public errors for Phase 9C trigger matching."""


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
