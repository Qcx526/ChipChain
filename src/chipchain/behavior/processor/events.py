"""Instruction effects and event semantics; source nature never implies execution."""

from typing import Literal, Self

from pydantic import model_validator

from chipchain.core import Identifier, ProgramAddress
from chipchain.behavior.processor.base import NonnegativeInt, PositiveInt, _BehaviorRecord
from chipchain.behavior.processor.enums import AccessKind, BehaviorFactNature, ControlTransferKind, ProcessorEventKind
from chipchain.behavior.processor.values import MemoryAddress, RegisterReference


class RegisterAccessBehavior(_BehaviorRecord):
    """Declared register access semantics without concrete register values."""

    _namespace = "v2-processor-register-access-v1"
    kind: Literal["register_access"] = "register_access"
    effect_index: NonnegativeInt
    instruction_id: Identifier
    register_ref: RegisterReference
    access: AccessKind

    @model_validator(mode="after")
    def validate_register(self) -> Self:
        """Reject a register from a different architecture."""

        if self.register_ref.architecture != self.architecture:
            raise ValueError("register architecture mismatch")
        return self


class MemoryAccessBehavior(_BehaviorRecord):
    """Memory access semantics; READ_WRITE does not assert architectural atomicity."""

    _namespace = "v2-processor-memory-access-v1"
    kind: Literal["memory_access"] = "memory_access"
    effect_index: NonnegativeInt
    instruction_id: Identifier | None = None
    access: AccessKind
    width_bytes: PositiveInt | None = None
    memory_address: MemoryAddress | None = None


class ControlTransferBehavior(_BehaviorRecord):
    """An optional declared target is not a runtime taken branch."""

    _namespace = "v2-processor-control-transfer-v1"
    kind: Literal["control_transfer"] = "control_transfer"
    effect_index: NonnegativeInt
    instruction_id: Identifier
    transfer: ControlTransferKind
    target_address: ProgramAddress | None = None


class ProcessorEvent(_BehaviorRecord):
    """Event semantics or an explicitly identified source-local occurrence.

    occurrence_ordinal identifies an occurrence, not a clock, address or static
    instruction ordinal. effect_index remains an effect slot, not an execution
    counter. A runtime occurrence does not itself establish order or causality.
    """

    _namespace = "v2-processor-event-v1"
    kind: Literal["processor_event"] = "processor_event"
    effect_index: NonnegativeInt
    occurrence_ordinal: NonnegativeInt | None = None
    instruction_id: Identifier | None = None
    event: ProcessorEventKind
    cause_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_cause(self) -> Self:
        """Validate declared cause and explicit runtime/fixture occurrence scope."""

        if self.event == ProcessorEventKind.OTHER_DECLARED and self.cause_id is None:
            raise ValueError("other_declared event requires cause_id")
        if self.nature == BehaviorFactNature.RUNTIME_OBSERVED and self.occurrence_ordinal is None:
            raise ValueError("runtime event requires occurrence_ordinal")
        if self.occurrence_ordinal is not None and self.nature not in {
            BehaviorFactNature.RUNTIME_OBSERVED, BehaviorFactNature.SYNTHETIC_FIXTURE,
        }:
            raise ValueError("occurrence_ordinal requires runtime or synthetic fixture nature")
        return self
