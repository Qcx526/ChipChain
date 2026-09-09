"""Private v1 identity/ownership foundation; independent of archived models."""

from typing import Annotated, ClassVar, TypeAlias

from pydantic import Field

from chipchain.core import Architecture, DomainModel, Identifier, deterministic_id
from chipchain.behavior.processor.enums import BehaviorFactNature


NonnegativeInt: TypeAlias = Annotated[int, Field(strict=True, ge=0)]
PositiveInt: TypeAlias = Annotated[int, Field(strict=True, gt=0)]


class _IdentifiedModel(DomainModel):
    _namespace: ClassVar[str]

    @property
    def id(self) -> str:
        """Recompute identity from normalized fields, never accept a supplied digest."""

        return deterministic_id(self._namespace, self.model_dump(mode="json"))


class _BehaviorRecord(_IdentifiedModel):
    """Every element/relation carries the exact context ID and explicit nature."""

    source_context_id: Identifier
    architecture: Architecture
    nature: BehaviorFactNature
