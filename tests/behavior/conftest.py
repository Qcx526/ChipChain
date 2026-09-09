"""Benign owned synthetic contract data, not decoded code or a hardware finding."""

import pytest

from chipchain.core import ArtifactProvenance, HardwareTargetIdentity, ImmutableFirmwareArtifact
from chipchain.behavior.processor import BehaviorSourceContext


@pytest.fixture
def processor_target() -> HardwareTargetIdentity:
    return HardwareTargetIdentity(
        target_id="synthetic-contract-target", architecture="riscv",
        hardware_model="Synthetic Model", hardware_revision="fixture-r1",
    )


@pytest.fixture
def processor_firmware(processor_target) -> ImmutableFirmwareArtifact:
    return ImmutableFirmwareArtifact(
        hardware_target=processor_target,
        provenance=ArtifactProvenance(
            artifact_id="synthetic-firmware", artifact_sha256="a" * 64,
            architecture="riscv", source_kind="synthetic",
        ),
    )


@pytest.fixture
def source_context(processor_target) -> BehaviorSourceContext:
    return BehaviorSourceContext(
        source_kind="synthetic_fixture",
        artifact=ArtifactProvenance(
            artifact_id="synthetic-contract-source", artifact_sha256="b" * 64,
            architecture="riscv", source_kind="synthetic",
        ),
        hardware_target=processor_target, producer_profile_id="synthetic-contract-v1",
    )
