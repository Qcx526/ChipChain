"""Candidate-owned immutable identity and bounded scalar types."""

from typing import Annotated, ClassVar

from pydantic import Field

from chipchain.core import DomainModel, deterministic_id

Ordinal = Annotated[int, Field(strict=True, ge=0)]
ContextBound = Annotated[int, Field(strict=True, ge=0, le=8)]
Sha256 = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]
Word = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{8}$")]


class CandidateModel(DomainModel):
    """Identity describes a declaration, never its evidentiary authority."""

    _namespace: ClassVar[str]

    @property
    def id(self) -> str:
        """Hash the complete normalized declaration, without time or host data."""

        return deterministic_id(self._namespace, self.model_dump(mode="json"))
