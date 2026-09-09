"""Numerical addresses with no execution or address-space inference."""

import re

from pydantic import field_validator

from chipchain.core.models import DomainModel


class ProgramAddress(DomainModel):
    """An immutable non-negative hexadecimal program/source address."""

    value: str

    @field_validator("value", mode="before")
    @classmethod
    def normalize_hex(cls, value: object) -> str:
        """Accept explicit hexadecimal strings and remove leading zeroes."""

        if not isinstance(value, str) or re.fullmatch(r"0[xX][0-9a-fA-F]+", value) is None:
            raise ValueError("address must be an explicit non-negative hex string")
        return hex(int(value, 16))
