"""Existing external endpoints and host-side delivery provenance only."""

from enum import Enum
from typing import Annotated, Self

from pydantic import Field, model_validator

from chipchain.core.artifacts import ImmutableFirmwareArtifact
from chipchain.core.identity import deterministic_id
from chipchain.core.models import DomainModel, Identifier
from chipchain.core.provenance import ArtifactProvenance
from chipchain.core.target import HardwareTargetIdentity


class ExternalInputTransport(str, Enum):
    """Declared endpoint families, not adapter support or application protocols."""

    SERIAL_UART = "serial_uart"
    CAN = "can"
    LIN = "lin"
    USB = "usb"
    NETWORK = "network"
    SPI = "spi"
    I2C = "i2c"
    OTHER_DECLARED = "other_declared"


class ExternalInputEndpoint(DomainModel):
    """Declaration of an already-existing target endpoint, not its discovery."""

    endpoint_id: Identifier
    hardware_target: HardwareTargetIdentity
    transport: ExternalInputTransport
    application_protocol_profile_id: Identifier | None = None
    declared_transport_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_transport(self) -> Self:
        """Require an explicit token only for the bounded OTHER declaration."""

        if (self.transport == ExternalInputTransport.OTHER_DECLARED) != (
            self.declared_transport_id is not None
        ):
            raise ValueError("declared_transport_id is required exactly for other_declared")
        return self

    @property
    def id(self) -> str:
        """Identify an endpoint independently of any delivery tool."""

        return deterministic_id("v2-external-input-endpoint-v1", self.model_dump(mode="json"))


class InputSynchronizationMode(str, Enum):
    """Declared host/target coordination; unknown does not mean no handshake."""

    UNKNOWN = "unknown"
    TARGET_READY_MARKER = "target_ready_marker"
    HOST_INITIATED = "host_initiated"
    DECLARED_PROFILE = "declared_profile"


class InputDeliveryProvenance(DomainModel):
    """Describe host input delivery; neither consumption nor firmware behavior.

    Unknown optional profiles remain None. No universal GDBFuzz handshake,
    reset strategy or firmware harness is implied by these fields.
    """

    producer_tool: Identifier
    producer_profile_id: Identifier
    host_adapter_profile_id: Identifier
    endpoint: ExternalInputEndpoint
    framing_profile_id: Identifier | None = None
    synchronization_mode: InputSynchronizationMode = InputSynchronizationMode.UNKNOWN
    synchronization_profile_id: Identifier | None = None
    reset_profile_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_synchronization(self) -> Self:
        """Keep unknown synchronization distinct from an explicit profile."""

        if self.synchronization_mode == InputSynchronizationMode.DECLARED_PROFILE:
            if self.synchronization_profile_id is None:
                raise ValueError("declared synchronization requires a profile")
        if self.synchronization_mode == InputSynchronizationMode.UNKNOWN:
            if self.synchronization_profile_id is not None:
                raise ValueError("unknown synchronization cannot declare a profile")
        return self

    @property
    def id(self) -> str:
        """Identify delivery provenance without performing delivery."""

        return deterministic_id("v2-input-delivery-v1", self.model_dump(mode="json"))


class ExternalInputArtifact(DomainModel):
    """A byte-backed testcase declaration bound to delivery and exact firmware."""

    provenance: ArtifactProvenance
    firmware: ImmutableFirmwareArtifact
    delivery: InputDeliveryProvenance
    byte_length: Annotated[int, Field(strict=True, ge=0)] | None = None

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        """Require the endpoint target and any declared input architecture to agree."""

        if self.delivery.endpoint.hardware_target != self.firmware.hardware_target:
            raise ValueError("input endpoint hardware target mismatch")
        architecture = self.provenance.architecture
        if architecture is not None and architecture != self.firmware.hardware_target.architecture:
            raise ValueError("input artifact architecture mismatch")
        return self

    def require_firmware(self, expected: ImmutableFirmwareArtifact) -> None:
        """Reject reuse against a different exact firmware target."""

        snapshot = ExternalInputArtifact.model_validate(self.model_dump(mode="json"))
        snapshot.firmware.require_same_target(expected)

    @property
    def id(self) -> str:
        """Identify input provenance and binding, never input interpretation."""

        return deterministic_id("v2-external-input-artifact-v1", self.model_dump(mode="json"))
