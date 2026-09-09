"""Trigger-owned identity and binding helpers; no behavior implementation imports."""

from typing import Annotated, ClassVar, TypeAlias

from pydantic import Field

from chipchain.core import Architecture, DomainModel, Identifier, deterministic_id


_NonnegativeInt: TypeAlias = Annotated[int, Field(strict=True, ge=0)]
_PositiveInt: TypeAlias = Annotated[int, Field(strict=True, gt=0)]


class _TriggerModel(DomainModel):
    _namespace: ClassVar[str]

    @property
    def id(self) -> str:
        """Identify the complete normalized declaration, not its truth or satisfaction."""

        return deterministic_id(self._namespace, self.model_dump(mode="json"))


class _SourceBoundModel(_TriggerModel):
    source_context_id: Identifier
    architecture: Architecture


class _Requirement(_SourceBoundModel):
    """A local normative node; a slot is neither a source nor runtime ordinal."""

    requirement_slot: _NonnegativeInt
