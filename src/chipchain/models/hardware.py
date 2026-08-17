"""Hardware, security mechanism, impact, and root-cause models."""

from __future__ import annotations

from pydantic import Field

from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture


class HardwareResource(DomainModel):
    """A register, peripheral, controller, or other hardware resource."""

    id: Identifier
    name: Identifier
    architecture: Architecture
    kind: Identifier
    device: Identifier | None = None
    register_name: Identifier | None = None
    address: Identifier | None = None
    address_range: Identifier | None = None
    owner: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)


class SecurityMechanism(DomainModel):
    """An architecture or hardware mechanism that protects a target."""

    id: Identifier
    name: Identifier
    architecture: Architecture
    kind: Identifier
    protected_target: Identifier
    rule_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)


class Impact(DomainModel):
    """A security impact without a model confidence score."""

    id: Identifier
    type: Identifier
    target: Identifier
    severity: Identifier
    scope: Identifier
    description: Identifier


class RootCause(DomainModel):
    """A root cause localized at software, interface, or hardware level."""

    id: Identifier
    kind: Identifier
    location: Identifier
    architecture: Architecture
    function: Identifier | None = None
    binary_address: Identifier | None = None
    instruction: Identifier | None = None
    register_name: Identifier | None = Field(default=None, alias="register")
    mmio_address: Identifier | None = None
    hardware_resource: Identifier | None = None
    security_mechanism: Identifier | None = None
    evidence_ids: list[Identifier] = Field(default_factory=list)
    description: Identifier | None = None

    @property
    def register(self) -> str | None:
        """Expose the JSON ``register`` value through the expected domain name."""

        return self.register_name
