"""Minimal public V2 contracts; architecture labels do not enable backends."""

from chipchain.core.address import ProgramAddress
from chipchain.core.architecture import Architecture
from chipchain.core.identity import canonical_json_bytes, deterministic_id
from chipchain.core.models import DomainModel, Identifier
from chipchain.core.provenance import ArtifactProvenance
from chipchain.core.target import HardwareTargetIdentity
from chipchain.core.artifacts import GDBFuzzArtifact, ImmutableFirmwareArtifact, ProcessorFuzzArtifact
from chipchain.core.input import (
    ExternalInputArtifact, ExternalInputEndpoint, ExternalInputTransport,
    InputDeliveryProvenance, InputSynchronizationMode,
)
from chipchain.core.debug import DebugObservationMode, DebugProvenance, ExecutionPerturbation

__all__ = [
    "Architecture",
    "ArtifactProvenance",
    "DomainModel",
    "Identifier",
    "ProgramAddress",
    "canonical_json_bytes",
    "deterministic_id",
    "HardwareTargetIdentity",
    "ImmutableFirmwareArtifact",
    "ProcessorFuzzArtifact",
    "GDBFuzzArtifact",
    "ExternalInputEndpoint",
    "ExternalInputTransport",
    "InputDeliveryProvenance",
    "InputSynchronizationMode",
    "ExternalInputArtifact",
    "DebugObservationMode",
    "ExecutionPerturbation",
    "DebugProvenance",
]
