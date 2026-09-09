"""Architecture-neutral instruction declarations; never a disassembler."""

import re
from typing import Literal, Self

from pydantic import field_validator, model_validator

from chipchain.core import Identifier, ProgramAddress
from chipchain.behavior.processor.base import NonnegativeInt, PositiveInt, _BehaviorRecord
from chipchain.behavior.processor.values import InstructionOperand, RegisterOperand


class InstructionBehavior(_BehaviorRecord):
    """One source instruction description, never a dynamic execution occurrence.

    source_ordinal is not a program address, occurrence ordinal or clock.
    """

    _namespace = "v2-processor-instruction-v1"
    kind: Literal["instruction"] = "instruction"
    source_ordinal: NonnegativeInt
    program_address: ProgramAddress | None = None
    encoding_hex: str | None = None
    size_bytes: PositiveInt | None = None
    mnemonic: Identifier
    operands: tuple[InstructionOperand, ...] = ()

    @field_validator("encoding_hex", mode="before")
    @classmethod
    def normalize_encoding(cls, value: object) -> str | None:
        """Hex denotes bytes in source order, no prefix or implicit endianness."""

        if value is None:
            return None
        if not isinstance(value, str) or re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value) is None:
            raise ValueError("encoding must contain complete hex byte pairs")
        return value.lower()

    @model_validator(mode="after")
    def validate_instruction(self) -> Self:
        """Validate supplied byte length and operand architecture, without ISA rules."""

        if self.encoding_hex is not None:
            if self.size_bytes is None or len(self.encoding_hex) != 2 * self.size_bytes:
                raise ValueError("encoding byte length must match explicit size_bytes")
        for operand in self.operands:
            if isinstance(operand, RegisterOperand) and operand.register_ref.architecture != self.architecture:
                raise ValueError("register operand architecture mismatch")
        return self
