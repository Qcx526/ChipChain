"""Minimal exact/unknown state facts, never trigger requirements or a solver."""

from typing import Literal, Self

from pydantic import model_validator

from chipchain.core import Identifier
from chipchain.behavior.processor.base import NonnegativeInt, _BehaviorRecord
from chipchain.behavior.processor.values import ExactScalar, MemoryAddress, RegisterReference


class RegisterStateFact(_BehaviorRecord):
    """Register or system/CSR value in its declared source nature; None is unknown."""

    _namespace = "v2-processor-register-state-v1"
    kind: Literal["register_state"] = "register_state"
    fact_index: NonnegativeInt
    register_ref: RegisterReference
    value: ExactScalar | None

    @model_validator(mode="after")
    def validate_register(self) -> Self:
        """Reject cross-architecture state attribution."""

        if self.register_ref.architecture != self.architecture:
            raise ValueError("register state architecture mismatch")
        return self


class PrivilegeStateFact(_BehaviorRecord):
    """Architecture-scoped profile/label with no universal privilege ordering."""

    _namespace = "v2-processor-privilege-state-v1"
    kind: Literal["privilege_state"] = "privilege_state"
    fact_index: NonnegativeInt
    profile_id: Identifier
    mode_id: Identifier | None


class MemoryStateFact(_BehaviorRecord):
    """Exact/unknown bit pattern at an explicitly declared data location."""

    _namespace = "v2-processor-memory-state-v1"
    kind: Literal["memory_state"] = "memory_state"
    fact_index: NonnegativeInt
    memory_address: MemoryAddress
    value: ExactScalar | None
