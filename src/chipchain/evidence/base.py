"""Immutable, version-namespaced evidence contracts, not verification results."""

from typing import Annotated, ClassVar

from pydantic import Field

from chipchain.core import DomainModel, deterministic_id


Ordinal = Annotated[int, Field(strict=True, ge=0)]


class EvidenceModel(DomainModel):
    """Identity includes the complete declared payload, never a local path/time."""

    _namespace: ClassVar[str]

    @property
    def id(self) -> str:
        """Return a deterministic identity; computed views are not duplicate data."""

        return deterministic_id(self._namespace, self.model_dump(mode="json"))
