"""Owned synthetic V2 contract declarations, with no files or hardware access."""

import pytest

from chipchain.core import (
    ArtifactProvenance, ExternalInputEndpoint, ExternalInputTransport,
    HardwareTargetIdentity, ImmutableFirmwareArtifact, InputDeliveryProvenance,
)


@pytest.fixture
def target() -> HardwareTargetIdentity:
    return HardwareTargetIdentity(
        target_id="synthetic-client", architecture="riscv",
        hardware_model="Synthetic Processor", hardware_revision="rev 1",
        instruction_set_profile_id="synthetic-rv64-profile-v1",
    )


@pytest.fixture
def firmware(target: HardwareTargetIdentity) -> ImmutableFirmwareArtifact:
    return ImmutableFirmwareArtifact(
        provenance=ArtifactProvenance(
            artifact_id="synthetic-firmware", artifact_sha256="AB" * 32,
            architecture="riscv", source_kind="synthetic",
        ),
        hardware_target=target, instruction_set_profile_id="synthetic-rv64-profile-v1",
    )


@pytest.fixture
def endpoint(target: HardwareTargetIdentity) -> ExternalInputEndpoint:
    return ExternalInputEndpoint(
        endpoint_id="synthetic-existing-uart", hardware_target=target,
        transport=ExternalInputTransport.SERIAL_UART,
        application_protocol_profile_id="synthetic-existing-protocol-v1",
    )


@pytest.fixture
def delivery(endpoint: ExternalInputEndpoint) -> InputDeliveryProvenance:
    return InputDeliveryProvenance(
        producer_tool="synthetic-host-tool", producer_profile_id="synthetic-tool-v1",
        host_adapter_profile_id="synthetic-host-adapter-v1", endpoint=endpoint,
    )
