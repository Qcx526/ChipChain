"""Closed ARM A32 hardware-trigger contract enums for Phase 9C Step 1."""

from __future__ import annotations

from enum import Enum


class ArmExecutionMode(str, Enum):
    """Execution modes supported by the Phase 9C Step 1 trigger contract."""

    A32 = "arm_a32"


class ArmPrivilegeMode(str, Enum):
    """Architectural A32 privilege modes accepted as exact preconditions."""

    USER = "user"
    FIQ = "fiq"
    IRQ = "irq"
    SUPERVISOR = "supervisor"
    MONITOR = "monitor"
    ABORT = "abort"
    HYPERVISOR = "hypervisor"
    UNDEFINED = "undefined"
    SYSTEM = "system"


class HardwareFailureEffectKind(str, Enum):
    """Primary hardware-side failure effects represented in the MVP."""

    REGISTER_MISMATCH = "register_mismatch"
    ASSERTION_VIOLATION = "assertion_violation"


class HardwareTriggerProofKind(str, Enum):
    """Prior hardware-side proof mechanisms supporting a trigger contract."""

    GOLDEN_MODEL_MISMATCH = "golden_model_mismatch"
    ASSERTION_VIOLATION = "assertion_violation"
