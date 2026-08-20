"""Fail-closed errors for the Phase 9B1 QEMU observer boundary."""


class QemuRuntimeError(Exception):
    """Base class for QEMU observer failures."""


class QemuProbeError(QemuRuntimeError):
    """Raised when the executable or plugin environment cannot be proven."""


class QemuRawTraceError(QemuRuntimeError):
    """Raised when untrusted observer JSONL violates its strict contract."""


class QemuQmpError(QemuRuntimeError):
    """Raised when QMP greeting, command order, or responses are invalid."""


class QemuTopologyError(QemuRuntimeError):
    """Raised when a QEMU FlatView artifact violates the strict contract."""


class QemuTopologyClassificationError(QemuTopologyError):
    """Raised when a physical access cannot be classified unambiguously."""


class QemuRunnerError(QemuRuntimeError):
    """Raised when a passive QEMU run cannot produce a complete trace."""


class QemuRunnerTimeoutError(QemuRunnerError):
    """Raised when QEMU is terminated before a clean end record is produced."""
