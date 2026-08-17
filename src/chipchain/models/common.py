"""Shared types and configuration for ChipChain domain models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints

Identifier: TypeAlias = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1),
]
"""A non-empty, whitespace-trimmed identifier or label."""

UnitInterval: TypeAlias = Annotated[float, Field(ge=0.0, le=1.0)]
"""A numeric value in the inclusive interval [0, 1]."""

NonNegativeOrder: TypeAlias = Annotated[int, Field(ge=0)]
"""A zero-based position in a linear attack chain."""

Metadata: TypeAlias = dict[str, JsonValue]
"""JSON-serializable extension data for adapters and experiments."""


def utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""

    return datetime.now(timezone.utc)


class DomainModel(BaseModel):
    """Base class that rejects unknown fields and validates assignments."""

    model_config = ConfigDict(
        extra="forbid",
        validate_by_alias=True,
        validate_by_name=True,
        validate_assignment=True,
        serialize_by_alias=True,
    )
