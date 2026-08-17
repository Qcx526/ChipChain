"""Evidence models kept separate from the facts they support."""

from __future__ import annotations

from pydantic import Field

from chipchain.models.common import DomainModel, Identifier, Metadata, UnitInterval
from chipchain.models.enums import EvidenceType


class Evidence(DomainModel):
    """A traceable observation supporting a domain fact or graph edge."""

    id: Identifier
    type: EvidenceType
    source: Identifier
    artifact: Identifier | None = None
    address: Identifier | None = None
    instruction: Identifier | None = None
    rule_id: Identifier | None = None
    confidence: UnitInterval
    verified: bool = False
    metadata: Metadata = Field(default_factory=dict)
    reference: Identifier | None = None
