"""Public exception hierarchy for vulnerability knowledge graph storage."""


class KnowledgeGraphError(Exception):
    """Base class for knowledge graph repository failures."""


class KnowledgeNodeNotFoundError(KnowledgeGraphError):
    """Raised when a requested knowledge node does not exist."""


class KnowledgeEdgeNotFoundError(KnowledgeGraphError):
    """Raised when a requested knowledge edge does not exist."""


class KnowledgeEvidenceNotFoundError(KnowledgeGraphError):
    """Raised when requested evidence does not exist."""


class DuplicateKnowledgeNodeError(KnowledgeGraphError):
    """Raised when adding an existing knowledge node ID."""


class DuplicateKnowledgeEdgeError(KnowledgeGraphError):
    """Raised when adding an existing knowledge edge ID."""


class DuplicateKnowledgeEvidenceError(KnowledgeGraphError):
    """Raised when adding an existing evidence ID."""


class KnowledgeArchitectureMismatchError(KnowledgeGraphError):
    """Raised when a knowledge entity violates repository architecture scope."""


class KnowledgePersistenceError(KnowledgeGraphError):
    """Raised when a knowledge snapshot cannot be read, validated, or written."""
