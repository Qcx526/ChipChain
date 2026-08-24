"""Bounded public errors for Phase 9C static trigger matching."""


class HardwareTriggerMatchingError(Exception):
    """Base class for static firmware trigger-matching failures."""


class UnsupportedTriggerArtifactError(HardwareTriggerMatchingError):
    """Raised when an artifact is outside the ARM A32 ELF scope."""


class InvalidTriggerMatchingInputError(HardwareTriggerMatchingError):
    """Raised when detached inputs, paths, or backend output are invalid."""
