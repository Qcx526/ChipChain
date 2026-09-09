"""Architecture-neutral normative state/step declarations, not processor facts."""

from typing import Annotated, Literal, Self, TypeAlias

from pydantic import Field, model_validator

from chipchain.core import Identifier, ProgramAddress
from chipchain.behavior.processor import (
    AccessKind, ControlTransferKind, MemoryAddress, ProcessorEventKind, RegisterReference,
)
from chipchain.trigger.base import _PositiveInt, _Requirement
from chipchain.trigger.values import OperandRequirement, RegisterOperandRequirement, ScalarConstraint


class InstructionTriggerRequirement(_Requirement):
    """Require a mnemonic; None operands is unconstrained, () requires zero operands."""

    _namespace = "v2-trigger-instruction-requirement-v1"
    kind: Literal["instruction"] = "instruction"
    mnemonic: Identifier
    operands: tuple[OperandRequirement, ...] | None = None

    @model_validator(mode="after")
    def validate_architecture(self) -> Self:
        """Reject contradictory nested register architecture without coercion."""

        for operand in self.operands or ():
            if isinstance(operand, RegisterOperandRequirement):
                if operand.register_ref.architecture != self.architecture:
                    raise ValueError("operand register architecture mismatch")
        return self


class _RegisterRequirement(_Requirement):
    register_ref: RegisterReference

    @model_validator(mode="after")
    def validate_architecture(self) -> Self:
        """Keep register requirements within their explicitly declared architecture."""

        if self.register_ref.architecture != self.architecture:
            raise ValueError("register architecture mismatch")
        return self


class RegisterAccessTriggerRequirement(_RegisterRequirement):
    """Require register access, without attaching or observing a register value."""

    _namespace = "v2-trigger-register-access-requirement-v1"
    kind: Literal["register_access"] = "register_access"
    access: AccessKind


class RegisterStateTriggerRequirement(_RegisterRequirement):
    """Require a register bit-pattern constraint, not an access or state fact."""

    _namespace = "v2-trigger-register-state-requirement-v1"
    kind: Literal["register_state"] = "register_state"
    constraint: ScalarConstraint


class MemoryAccessTriggerRequirement(_Requirement):
    """Require access; absent width/address leaves that dimension unconstrained."""

    _namespace = "v2-trigger-memory-access-requirement-v1"
    kind: Literal["memory_access"] = "memory_access"
    access: AccessKind
    width_bytes: _PositiveInt | None = None
    memory_address: MemoryAddress | None = None


class MemoryStateTriggerRequirement(_Requirement):
    """Require state at an explicit data address, without classifying RAM/MMIO."""

    _namespace = "v2-trigger-memory-state-requirement-v1"
    kind: Literal["memory_state"] = "memory_state"
    memory_address: MemoryAddress
    constraint: ScalarConstraint


class PrivilegeStateTriggerRequirement(_Requirement):
    """Require a declared architecture-scoped profile/mode; no support inference."""

    _namespace = "v2-trigger-privilege-state-requirement-v1"
    kind: Literal["privilege_state"] = "privilege_state"
    profile_id: Identifier
    mode_id: Identifier


class ControlTransferTriggerRequirement(_Requirement):
    """Require transfer semantics, not CFG or an observed taken branch."""

    _namespace = "v2-trigger-control-transfer-requirement-v1"
    kind: Literal["control_transfer"] = "control_transfer"
    transfer: ControlTransferKind
    target: ProgramAddress | None = None


class EventTriggerRequirement(_Requirement):
    """Require an event, with an optional cause constraint; not an occurrence."""

    _namespace = "v2-trigger-event-requirement-v1"
    kind: Literal["event"] = "event"
    event: ProcessorEventKind
    cause_id: Identifier | None = None


StateTriggerRequirement: TypeAlias = Annotated[
    RegisterStateTriggerRequirement | MemoryStateTriggerRequirement | PrivilegeStateTriggerRequirement,
    Field(discriminator="kind"),
]
StepTriggerRequirement: TypeAlias = Annotated[
    InstructionTriggerRequirement | RegisterAccessTriggerRequirement
    | MemoryAccessTriggerRequirement | ControlTransferTriggerRequirement | EventTriggerRequirement,
    Field(discriminator="kind"),
]
