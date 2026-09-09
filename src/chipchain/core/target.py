"""Declared hardware targets, not hardware applicability assessments."""

from typing import Annotated, TypeAlias

from pydantic import StringConstraints

from chipchain.core.architecture import Architecture
from chipchain.core.identity import deterministic_id
from chipchain.core.models import DomainModel, Identifier


_HardwareLabel: TypeAlias = Annotated[
    str, StringConstraints(strict=True, pattern=r"^\S(?:[^\r\n]*\S)?$"),
]


class HardwareTargetIdentity(DomainModel):
    """Caller-declared target identity; missing revision stays unknown.

    Neither equal architecture nor equal model text establishes equivalence
    between a ProcessorFuzz implementation and a client processor/board.
    """

    target_id: Identifier
    architecture: Architecture
    hardware_model: _HardwareLabel
    hardware_revision: _HardwareLabel | None = None
    instruction_set_profile_id: Identifier | None = None

    @property
    def id(self) -> str:
        """Derive a versioned descriptor identity from all declared fields."""

        return deterministic_id("v2-hardware-target-v1", self.model_dump(mode="json"))
