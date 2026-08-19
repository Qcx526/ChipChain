"""Public exceptions for exact linking and candidate search."""


class CandidateError(Exception):
    """Base class for Phase 6 candidate-correlation failures."""


class CandidateArchitectureMismatchError(CandidateError):
    """Raised when source repositories do not match the search architecture."""


class InvalidKnowledgeContextError(CandidateError):
    """Raised when TARGETS_RESOURCE does not originate at a vulnerability."""


class UnsupportedCrossLayerSearchError(CandidateError):
    """Raised when a requested cross-layer direction has no search implementation."""
