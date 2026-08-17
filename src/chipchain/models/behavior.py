"""Program behavior and cross-layer interface models."""

from __future__ import annotations

from pydantic import Field

from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture, BehaviorType, Layer


class Behavior(DomainModel):
    """A security-relevant action observed in a program or hardware path."""

    id: Identifier
    type: BehaviorType
    architecture: Architecture
    layer: Layer
    subject: Identifier
    object: Identifier | None = None
    address: Identifier | None = None
    evidence_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)


class Interface(DomainModel):
    """A syscall, ioctl, SMC, SVC, mmap, or MMIO cross-layer boundary."""

    id: Identifier
    name: Identifier
    architecture: Architecture
    source_layer: Layer
    target_layer: Layer
    kind: Identifier
    identifier: Identifier | None = None
    evidence_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)
