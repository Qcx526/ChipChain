"""Typed scalar, register, operand and memory-location values, without decoding."""

import re
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import Field, StringConstraints, field_validator, model_validator

from chipchain.core import Architecture, DomainModel, Identifier
from chipchain.behavior.processor.base import PositiveInt, _IdentifiedModel
from chipchain.behavior.processor.enums import RegisterClass


def _normalize_hex(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"0[xX][0-9a-fA-F]+", value) is None:
        raise ValueError("value must be an explicit unsigned hex string")
    return hex(int(value, 16))


class ExactScalar(DomainModel):
    """An exact unsigned bit pattern with explicit width; None is modeled separately."""

    width_bits: PositiveInt
    value: str

    @field_validator("value", mode="before")
    @classmethod
    def normalize_value(cls, value: object) -> str:
        """Normalize representation, never convert symbolic/unknown values to zero."""

        return _normalize_hex(value)

    @model_validator(mode="after")
    def validate_width(self) -> Self:
        """Reject a bit pattern that does not fit the declared width."""

        if int(self.value, 16).bit_length() > self.width_bits:
            raise ValueError("scalar value exceeds width_bits")
        return self


class MemoryAddress(DomainModel):
    """Explicit data location, not ProgramAddress and not an MMIO classifier."""

    value: str
    address_space_id: Identifier | None = None

    @field_validator("value", mode="before")
    @classmethod
    def normalize_value(cls, value: object) -> str:
        """Normalize a declared address without classifying its memory region."""

        return _normalize_hex(value)


class RegisterReference(_IdentifiedModel):
    """Adapter-canonical name in an explicit architecture/register namespace."""

    _namespace = "v2-processor-register-v1"
    architecture: Architecture
    register_class: RegisterClass
    namespace: Identifier
    name: Identifier


class RegisterOperand(DomainModel):
    """Register operand identity, not register access or value inference."""

    kind: Literal["register"] = "register"
    register_ref: RegisterReference


class ScalarOperand(DomainModel):
    """Exact operand bit pattern, not an observed processor state."""

    kind: Literal["scalar"] = "scalar"
    scalar: ExactScalar


class DeclaredOperand(DomainModel):
    """Opaque source-normalized operand text; no expression evaluation/equivalence."""

    kind: Literal["declared"] = "declared"
    text: Annotated[str, StringConstraints(strict=True, pattern=r"^\S(?:[^\r\n]*\S)?$")]


InstructionOperand: TypeAlias = Annotated[
    RegisterOperand | ScalarOperand | DeclaredOperand, Field(discriminator="kind"),
]
