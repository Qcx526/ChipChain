"""Public V2-4 hardware-side requirement contracts; no extraction or satisfaction."""

from chipchain.trigger.enums import TriggerOrderKind, TriggerSourceKind
from chipchain.trigger.models import HardwareTriggerSpec, TriggerSourceContext
from chipchain.trigger.relations import TriggerOrderRequirement
from chipchain.trigger.requirements import (
    ControlTransferTriggerRequirement, EventTriggerRequirement, InstructionTriggerRequirement,
    MemoryAccessTriggerRequirement, MemoryStateTriggerRequirement,
    PrivilegeStateTriggerRequirement, RegisterAccessTriggerRequirement, RegisterStateTriggerRequirement,
    StateTriggerRequirement, StepTriggerRequirement,
)
from chipchain.trigger.values import (
    AnyOperandRequirement, ExactScalarConstraint, MaskedScalarConstraint, OperandRequirement,
    RegisterOperandRequirement, ScalarConstraint, ScalarOperandRequirement, TextOperandRequirement,
)

__all__ = [
    "TriggerSourceKind", "TriggerOrderKind", "TriggerSourceContext", "HardwareTriggerSpec",
    "TriggerOrderRequirement", "InstructionTriggerRequirement", "RegisterAccessTriggerRequirement",
    "RegisterStateTriggerRequirement", "MemoryAccessTriggerRequirement", "MemoryStateTriggerRequirement",
    "PrivilegeStateTriggerRequirement", "ControlTransferTriggerRequirement", "EventTriggerRequirement",
    "StateTriggerRequirement", "StepTriggerRequirement", "ExactScalarConstraint", "MaskedScalarConstraint",
    "ScalarConstraint", "AnyOperandRequirement", "RegisterOperandRequirement", "ScalarOperandRequirement",
    "TextOperandRequirement", "OperandRequirement",
]
