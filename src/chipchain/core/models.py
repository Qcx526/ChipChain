"""Small strict model foundation owned by ChipChain V2."""

from typing import Annotated, TypeAlias

from pydantic import BaseModel, ConfigDict, StringConstraints


Identifier: TypeAlias = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]
"""A nonempty, path-independent token; no automatic trimming or generation."""


class DomainModel(BaseModel):
    """Reject extras, freeze fields, and revalidate nested model instances.

    Future contracts must use immutable field types (e.g. tuples, not lists).
    Pydantic's frozen setting alone does not freeze arbitrary nested containers.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
    )
