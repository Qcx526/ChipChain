"""Hardware-experiment anchor identity and errors, independent of frozen helpers."""

from typing import Annotated, ClassVar

from pydantic import Field

from chipchain.core import DomainModel, deterministic_id


UInt64 = Annotated[int, Field(strict=True, ge=0, lt=1 << 64)]
Ordinal = Annotated[int, Field(strict=True, ge=0)]
Sha256 = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]


class AnchorError(ValueError):
    """Unsupported or inconsistent source input; never a vulnerability status."""


class MissingSymbolError(AnchorError):
    """No defined exact label symbol; the SI record stays unanchored."""


class AmbiguousSymbolError(AnchorError):
    """Multiple symbol occurrences prevent a unique lexical anchor."""


class AnchorModel(DomainModel):
    """A closed immutable declaration. Source-backed APIs must recheck bytes."""

    _namespace: ClassVar[str]

    @property
    def id(self) -> str:
        """Hash the complete versioned payload, without path/time/random identity."""

        return deterministic_id(self._namespace, self.model_dump(mode="json"))
