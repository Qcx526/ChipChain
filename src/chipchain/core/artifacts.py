"""Byte-anchored firmware and tool-source declarations; no format parsing."""

from typing import Self

from pydantic import model_validator

from chipchain.core.architecture import Architecture
from chipchain.core.identity import deterministic_id
from chipchain.core.models import DomainModel, Identifier
from chipchain.core.provenance import ArtifactProvenance
from chipchain.core.target import HardwareTargetIdentity


def _require_architecture(source: ArtifactProvenance, architecture: Architecture) -> None:
    if source.architecture != architecture:
        raise ValueError("source architecture must explicitly match the hardware/firmware target")


def _require_producer(source: ArtifactProvenance) -> None:
    if source.producer_profile_id is None:
        raise ValueError("tool source requires an explicit producer_profile_id")


class ImmutableFirmwareArtifact(DomainModel):
    """Exact declared firmware bytes associated with one hardware target.

    No file is opened and the declared SHA is not independently verified.
    The immutable image contract does not assert runtime non-perturbation.
    """

    provenance: ArtifactProvenance
    hardware_target: HardwareTargetIdentity
    instruction_set_profile_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        """Reject unknown or contradictory firmware architecture."""

        _require_architecture(self.provenance, self.hardware_target.architecture)
        return self

    @property
    def id(self) -> str:
        """Identify the full declaration, including provenance and target."""

        return deterministic_id("v2-immutable-firmware-v1", self.model_dump(mode="json"))

    def require_same_target(self, expected: "ImmutableFirmwareArtifact") -> None:
        """Revalidate both snapshots and require exact firmware/target binding.

        Source-kind/producer differences can describe byte-identical copies;
        they do not relax artifact ID, SHA, architecture, target or ISA profile.
        """

        actual = ImmutableFirmwareArtifact.model_validate(self.model_dump(mode="json"))
        other = ImmutableFirmwareArtifact.model_validate(expected.model_dump(mode="json"))
        if (
            actual.provenance.artifact_id != other.provenance.artifact_id
            or actual.provenance.artifact_sha256 != other.provenance.artifact_sha256
            or actual.provenance.architecture != other.provenance.architecture
            or actual.hardware_target != other.hardware_target
            or actual.instruction_set_profile_id != other.instruction_set_profile_id
        ):
            raise ValueError("exact firmware target binding mismatch")


class ProcessorFuzzArtifact(DomainModel):
    """Raw SI source provenance, not a trigger or client applicability claim."""

    provenance: ArtifactProvenance
    hardware_target: HardwareTargetIdentity

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        """Require the source's declared architecture and producer profile."""

        _require_architecture(self.provenance, self.hardware_target.architecture)
        _require_producer(self.provenance)
        return self

    @property
    def id(self) -> str:
        """Identify the raw source declaration without interpreting SI bytes."""

        return deterministic_id("v2-processorfuzz-artifact-v1", self.model_dump(mode="json"))


class GDBFuzzArtifact(DomainModel):
    """One campaign output/context artifact bound to an exact firmware snapshot.

    The provenance may describe a config, trial output or another declared
    artifact; this model neither parses it nor infers coverage/crash semantics.
    """

    provenance: ArtifactProvenance
    firmware: ImmutableFirmwareArtifact

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        """Reject source/firmware architecture mismatch or missing producer."""

        _require_architecture(self.provenance, self.firmware.hardware_target.architecture)
        _require_producer(self.provenance)
        return self

    def require_firmware(self, expected: ImmutableFirmwareArtifact) -> None:
        """Fail closed when attaching this source to a different firmware target."""

        snapshot = GDBFuzzArtifact.model_validate(self.model_dump(mode="json"))
        snapshot.firmware.require_same_target(expected)

    @property
    def id(self) -> str:
        """Identify the source and its exact firmware binding."""

        return deterministic_id("v2-gdbfuzz-artifact-v1", self.model_dump(mode="json"))
