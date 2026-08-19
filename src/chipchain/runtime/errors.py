"""Errors raised by the runtime contract and persistence boundary."""


class RuntimeContractError(Exception):
    """Base class for Phase 9B0 runtime contract failures."""


class RuntimeCapabilityError(RuntimeContractError):
    """Raised when a trace exceeds its backend's declared capabilities."""


class RuntimePersistenceError(RuntimeContractError):
    """Raised when a runtime trace cannot be loaded or saved safely."""
