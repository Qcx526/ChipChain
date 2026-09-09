"""Scalar and positional operand constraints; no satisfaction evaluation."""

from typing import Annotated, Literal, Self, TypeAlias

from pydantic import Field, StringConstraints, model_validator

from chipchain.behavior.processor import ExactScalar, RegisterReference
from chipchain.trigger.base import _TriggerModel


class ExactScalarConstraint(_TriggerModel):
    """Require an exact unsigned bit pattern at its explicit width."""

    _namespace = "v2-trigger-exact-scalar-constraint-v1"
    kind: Literal["exact"] = "exact"
    value: ExactScalar


class MaskedScalarConstraint(_TriggerModel):
    """Declare (actual & mask) == value; do not compare any actual state."""

    _namespace = "v2-trigger-masked-scalar-constraint-v1"
    kind: Literal["masked"] = "masked"
    value: ExactScalar
    mask: ExactScalar

    @model_validator(mode="after")
    def validate_constraint(self) -> Self:
        """Reject inconsistent widths, empty constraints and bits outside the mask."""

        if self.value.width_bits != self.mask.width_bits:
            raise ValueError("value and mask widths must match")
        mask = int(self.mask.value, 16)
        if mask == 0:
            raise ValueError("zero mask constrains nothing")
        if int(self.value.value, 16) & ~mask:
            raise ValueError("value contains bits outside mask")
        return self


ScalarConstraint: TypeAlias = Annotated[
    ExactScalarConstraint | MaskedScalarConstraint, Field(discriminator="kind"),
]


class AnyOperandRequirement(_TriggerModel):
    """Intentionally leave this operand position unconstrained."""

    _namespace = "v2-trigger-any-operand-v1"
    kind: Literal["any"] = "any"


class RegisterOperandRequirement(_TriggerModel):
    """Require this exact architecture-scoped register reference, not its value."""

    _namespace = "v2-trigger-register-operand-v1"
    kind: Literal["register"] = "register"
    register_ref: RegisterReference


class ScalarOperandRequirement(_TriggerModel):
    """Constrain a scalar operand without evaluating an instruction."""

    _namespace = "v2-trigger-scalar-operand-v1"
    kind: Literal["scalar"] = "scalar"
    constraint: ScalarConstraint


class TextOperandRequirement(_TriggerModel):
    """Exact lexical operand text; no alias or semantic equivalence claim."""

    _namespace = "v2-trigger-text-operand-v1"
    kind: Literal["text"] = "text"
    text: Annotated[str, StringConstraints(strict=True, pattern=r"^\S(?:[^\r\n]*\S)?$")]


OperandRequirement: TypeAlias = Annotated[
    AnyOperandRequirement | RegisterOperandRequirement
    | ScalarOperandRequirement | TextOperandRequirement,
    Field(discriminator="kind"),
]
