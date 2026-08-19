"""Strict, backend-neutral Phase 9B0 runtime data models."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.verification.models import HardwareAddress, ProgramAddress

from chipchain.runtime.enums import (
    RuntimeBackendKind,
    RuntimeCapability,
    RuntimeEventKind,
    RuntimeInterventionKind,
    RuntimeRunMode,
)

NonNegativeIndex = Annotated[int, Field(ge=0)]
PositiveCount = Annotated[int, Field(gt=0)]
ValueWidth = Annotated[int, Field(gt=0, le=4096)]
RuntimeValue = int | str
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIXTURE_PROVENANCE_FLAGS = {
    "fixture",
    "synthetic",
    "owned",
    "not_real_vulnerability",
    "not_benchmark",
}


def _canonical_id(prefix: str, payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(serialized).hexdigest()}"


def _address_value(value: ProgramAddress | HardwareAddress | None) -> str | None:
    return value.value if value is not None else None


def _validate_value(value: RuntimeValue | None, width: int | None) -> None:
    if value is None and width is not None:
        raise ValueError("value_width_bits requires a runtime value")
    if value is not None and width is None:
        raise ValueError("runtime value requires value_width_bits")
    if isinstance(value, bool) or (isinstance(value, int) and value < 0):
        raise ValueError("runtime value must be a non-negative integer or identifier")
    if isinstance(value, str) and not value.strip():
        raise ValueError("runtime value identifier must not be empty")
    if isinstance(value, int) and width is not None and value.bit_length() > width:
        raise ValueError("runtime value does not fit value_width_bits")


def runtime_backend_manifest_id(
    *,
    backend_kind: RuntimeBackendKind,
    backend_name: str,
    backend_version: str,
    architecture: Architecture,
    system_emulation: bool,
    capabilities: list[RuntimeCapability],
) -> str:
    """Build a deterministic backend identity without mutable metadata."""

    return _canonical_id(
        "runtime-backend",
        {
            "architecture": architecture.value,
            "backend_kind": backend_kind.value,
            "backend_name": backend_name,
            "backend_version": backend_version,
            "capabilities": sorted(item.value for item in capabilities),
            "system_emulation": system_emulation,
        },
    )


class RuntimeBackendManifest(DomainModel):
    """Versioned backend identity and explicitly declared capabilities."""

    id: Identifier
    backend_kind: RuntimeBackendKind
    backend_name: Identifier
    backend_version: Identifier
    architecture: Architecture
    system_emulation: bool
    capabilities: list[RuntimeCapability] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(
        cls, values: list[RuntimeCapability]
    ) -> list[RuntimeCapability]:
        if len(values) != len(set(values)):
            raise ValueError("runtime backend capabilities must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_identity(self) -> "RuntimeBackendManifest":
        if self.backend_kind is RuntimeBackendKind.OWNED_FIXTURE and any(
            self.metadata.get(key) is not True for key in _FIXTURE_PROVENANCE_FLAGS
        ):
            raise ValueError("owned fixture backend requires complete synthetic provenance")
        expected = runtime_backend_manifest_id(
            backend_kind=self.backend_kind,
            backend_name=self.backend_name,
            backend_version=self.backend_version,
            architecture=self.architecture,
            system_emulation=self.system_emulation,
            capabilities=self.capabilities,
        )
        if self.id != expected:
            raise ValueError("RuntimeBackendManifest ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        backend_kind: RuntimeBackendKind,
        backend_name: str,
        backend_version: str,
        architecture: Architecture,
        system_emulation: bool,
        capabilities: list[RuntimeCapability],
        metadata: Metadata | None = None,
    ) -> "RuntimeBackendManifest":
        """Create a backend manifest with its canonical identity."""

        normalized_kind = RuntimeBackendKind(backend_kind)
        normalized_architecture = Architecture(architecture)
        normalized_capabilities = [RuntimeCapability(item) for item in capabilities]
        identity = runtime_backend_manifest_id(
            backend_kind=normalized_kind,
            backend_name=backend_name,
            backend_version=backend_version,
            architecture=normalized_architecture,
            system_emulation=system_emulation,
            capabilities=normalized_capabilities,
        )
        return cls(
            id=identity,
            backend_kind=normalized_kind,
            backend_name=backend_name,
            backend_version=backend_version,
            architecture=normalized_architecture,
            system_emulation=system_emulation,
            capabilities=normalized_capabilities,
            metadata=metadata or {},
        )


def runtime_trace_manifest_id(**values: object) -> str:
    """Build a deterministic trace-manifest identity from semantic run fields."""

    payload = dict(values)
    architecture = payload.get("architecture")
    run_mode = payload.get("run_mode")
    if isinstance(architecture, Architecture):
        payload["architecture"] = architecture.value
    if isinstance(run_mode, RuntimeRunMode):
        payload["run_mode"] = run_mode.value
    return _canonical_id("runtime-trace", payload)


class RuntimeTraceManifest(DomainModel):
    """Stable identity and provenance for one runtime execution artifact."""

    id: Identifier
    run_id: Identifier
    scenario_id: Identifier
    architecture: Architecture
    backend_manifest_id: Identifier
    run_mode: RuntimeRunMode
    artifact_id: Identifier
    artifact_sha256: Identifier
    machine: Identifier
    cpu: Identifier
    vcpu_count: PositiveCount
    memory_map_id: Identifier | None = None
    memory_map_sha256: Identifier | None = None
    input_fingerprint: Identifier | None = None
    environment_fingerprint: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("artifact_sha256", "memory_map_sha256")
    @classmethod
    def validate_sha256(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256.fullmatch(value):
            raise ValueError("runtime artifact hashes must be lowercase SHA-256")
        return value

    def _identity_fields(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "backend_manifest_id": self.backend_manifest_id,
            "cpu": self.cpu,
            "environment_fingerprint": self.environment_fingerprint,
            "input_fingerprint": self.input_fingerprint,
            "machine": self.machine,
            "memory_map_id": self.memory_map_id,
            "memory_map_sha256": self.memory_map_sha256,
            "run_id": self.run_id,
            "run_mode": self.run_mode,
            "scenario_id": self.scenario_id,
            "vcpu_count": self.vcpu_count,
        }

    @model_validator(mode="after")
    def validate_identity(self) -> "RuntimeTraceManifest":
        if (self.memory_map_id is None) is not (self.memory_map_sha256 is None):
            raise ValueError("memory map ID and SHA-256 must be supplied together")
        if self.id != runtime_trace_manifest_id(**self._identity_fields()):
            raise ValueError("RuntimeTraceManifest ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "RuntimeTraceManifest":
        """Create a trace manifest with its deterministic identity."""

        values = dict(values)
        values["architecture"] = Architecture(values["architecture"])
        values["run_mode"] = RuntimeRunMode(values["run_mode"])
        identity_values = {
            key: values.get(key)
            for key in (
                "architecture",
                "artifact_id",
                "artifact_sha256",
                "backend_manifest_id",
                "cpu",
                "environment_fingerprint",
                "input_fingerprint",
                "machine",
                "memory_map_id",
                "memory_map_sha256",
                "run_id",
                "run_mode",
                "scenario_id",
                "vcpu_count",
            )
        }
        identity = runtime_trace_manifest_id(**identity_values)
        return cls(id=identity, **values)


def runtime_observation_id(**values: object) -> str:
    """Build an observation identity without timestamps or metadata."""

    payload: dict[str, object] = {}
    for key, value in values.items():
        if isinstance(value, (Architecture, RuntimeEventKind)):
            payload[key] = value.value
        elif isinstance(value, (ProgramAddress, HardwareAddress)):
            payload[key] = value.value
        else:
            payload[key] = value
    return _canonical_id("runtime-observation", payload)


class RuntimeObservation(DomainModel):
    """One ordered, security-neutral observation from a runtime trace."""

    id: Identifier
    trace_id: Identifier
    architecture: Architecture
    sequence_index: NonNegativeIndex
    vcpu_index: NonNegativeIndex
    event_kind: RuntimeEventKind
    pc: ProgramAddress | None = None
    virtual_address: HardwareAddress | None = None
    physical_address: HardwareAddress | None = None
    is_io: bool | None = None
    access_size: PositiveCount | None = None
    value: RuntimeValue | None = None
    value_width_bits: ValueWidth | None = None
    from_pc: ProgramAddress | None = None
    to_pc: ProgramAddress | None = None
    device_id: Identifier | None = None
    address_space_id: Identifier | None = None
    host_timestamp: datetime | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("host_timestamp")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("host timestamp must include timezone information")
        return value

    def _identity_fields(self) -> dict[str, object]:
        return {
            "access_size": self.access_size,
            "address_space_id": self.address_space_id,
            "architecture": self.architecture,
            "device_id": self.device_id,
            "event_kind": self.event_kind,
            "from_pc": _address_value(self.from_pc),
            "is_io": self.is_io,
            "pc": _address_value(self.pc),
            "physical_address": _address_value(self.physical_address),
            "sequence_index": self.sequence_index,
            "to_pc": _address_value(self.to_pc),
            "trace_id": self.trace_id,
            "value": self.value,
            "value_width_bits": self.value_width_bits,
            "vcpu_index": self.vcpu_index,
            "virtual_address": _address_value(self.virtual_address),
        }

    @model_validator(mode="after")
    def validate_event(self) -> "RuntimeObservation":
        _validate_value(self.value, self.value_width_bits)
        if self.event_kind is RuntimeEventKind.INSTRUCTION_EXEC and self.pc is None:
            raise ValueError("instruction execution requires PC")
        if self.event_kind in {RuntimeEventKind.MMIO_READ, RuntimeEventKind.MMIO_WRITE}:
            if self.pc is None or self.physical_address is None or self.access_size is None:
                raise ValueError("MMIO observation requires PC, physical address, and access size")
            if self.is_io is not True:
                raise ValueError("MMIO observation requires is_io=true")
        if self.event_kind in {
            RuntimeEventKind.INTERRUPT_DISCONTINUITY,
            RuntimeEventKind.EXCEPTION_DISCONTINUITY,
        } and (self.from_pc is None or self.to_pc is None):
            raise ValueError("runtime discontinuity requires from_pc and to_pc")
        if self.event_kind in {RuntimeEventKind.DMA_READ, RuntimeEventKind.DMA_WRITE}:
            if (
                self.physical_address is None
                or self.access_size is None
                or self.device_id is None
            ):
                raise ValueError("DMA observation requires physical address, access size, and device ID")
        if (
            self.value is not None
            and self.access_size is not None
            and self.value_width_bits != self.access_size * 8
        ):
            raise ValueError("runtime memory value width must match access size")
        if self.id != runtime_observation_id(**self._identity_fields()):
            raise ValueError("RuntimeObservation ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "RuntimeObservation":
        """Create an observation with identity derived from event semantics."""

        values = dict(values)
        values["architecture"] = Architecture(values["architecture"])
        values["event_kind"] = RuntimeEventKind(values["event_kind"])
        for field, address_type in (
            ("pc", ProgramAddress),
            ("from_pc", ProgramAddress),
            ("to_pc", ProgramAddress),
            ("virtual_address", HardwareAddress),
            ("physical_address", HardwareAddress),
        ):
            value = values.get(field)
            if value is not None and not isinstance(value, address_type):
                values[field] = address_type(value=value)
        identity_values = {
            key: values.get(key)
            for key in (
                "access_size",
                "address_space_id",
                "architecture",
                "device_id",
                "event_kind",
                "from_pc",
                "is_io",
                "pc",
                "physical_address",
                "sequence_index",
                "to_pc",
                "trace_id",
                "value",
                "value_width_bits",
                "vcpu_index",
                "virtual_address",
            )
        }
        identity = runtime_observation_id(**identity_values)
        return cls(id=identity, **values)


def runtime_intervention_id(**values: object) -> str:
    """Build an intervention identity independent of metadata."""

    payload: dict[str, object] = {}
    for key, value in values.items():
        if isinstance(value, (Architecture, RuntimeInterventionKind)):
            payload[key] = value.value
        elif isinstance(value, HardwareAddress):
            payload[key] = value.value
        else:
            payload[key] = value
    return _canonical_id("runtime-intervention", payload)


class RuntimeIntervention(DomainModel):
    """A declared controlled action, never an observed runtime event."""

    id: Identifier
    run_id: Identifier
    scenario_id: Identifier
    architecture: Architecture
    intervention_kind: RuntimeInterventionKind
    controller_backend: Identifier
    target_device_id: Identifier | None = None
    target_address: HardwareAddress | None = None
    value: RuntimeValue | None = None
    value_width_bits: ValueWidth | None = None
    before_sequence_index: NonNegativeIndex | None = None
    metadata: Metadata = Field(default_factory=dict)

    def _identity_fields(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "before_sequence_index": self.before_sequence_index,
            "controller_backend": self.controller_backend,
            "intervention_kind": self.intervention_kind,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "target_address": _address_value(self.target_address),
            "target_device_id": self.target_device_id,
            "value": self.value,
            "value_width_bits": self.value_width_bits,
        }

    @model_validator(mode="after")
    def validate_intervention(self) -> "RuntimeIntervention":
        _validate_value(self.value, self.value_width_bits)
        if any(self.metadata.get(key) is True for key in _FIXTURE_PROVENANCE_FLAGS):
            if any(
                self.metadata.get(key) is not True
                for key in _FIXTURE_PROVENANCE_FLAGS
            ):
                raise ValueError("fixture intervention requires complete synthetic provenance")
        if self.id != runtime_intervention_id(**self._identity_fields()):
            raise ValueError("RuntimeIntervention ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "RuntimeIntervention":
        """Create an intervention with deterministic controlled-action identity."""

        values = dict(values)
        values["architecture"] = Architecture(values["architecture"])
        values["intervention_kind"] = RuntimeInterventionKind(
            values["intervention_kind"]
        )
        target_address = values.get("target_address")
        if target_address is not None and not isinstance(target_address, HardwareAddress):
            values["target_address"] = HardwareAddress(value=target_address)
        identity_values = {
            key: values.get(key)
            for key in (
                "architecture",
                "before_sequence_index",
                "controller_backend",
                "intervention_kind",
                "run_id",
                "scenario_id",
                "target_address",
                "target_device_id",
                "value",
                "value_width_bits",
            )
        }
        identity = runtime_intervention_id(**identity_values)
        return cls(id=identity, **values)


class RuntimeTrace(DomainModel):
    """Versioned backend manifest, run manifest, and ordered observations."""

    format: Literal["chipchain_runtime_trace"] = "chipchain_runtime_trace"
    format_version: Literal[1] = 1
    backend_manifest: RuntimeBackendManifest
    manifest: RuntimeTraceManifest
    observations: list[RuntimeObservation] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_trace_integrity(self) -> "RuntimeTrace":
        if self.backend_manifest.id != self.manifest.backend_manifest_id:
            raise ValueError("trace backend manifest identity mismatch")
        if self.backend_manifest.architecture is not self.manifest.architecture:
            raise ValueError("trace backend architecture mismatch")
        if self.backend_manifest.backend_kind is RuntimeBackendKind.OWNED_FIXTURE and any(
            self.manifest.metadata.get(key) is not True
            for key in _FIXTURE_PROVENANCE_FLAGS
        ):
            raise ValueError("owned fixture trace requires complete synthetic provenance")
        observation_ids = [item.id for item in self.observations]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("runtime trace observation IDs must be unique")
        sequence_indexes = [item.sequence_index for item in self.observations]
        if len(sequence_indexes) != len(set(sequence_indexes)):
            raise ValueError("runtime trace sequence indexes must be unique")
        for item in self.observations:
            if item.trace_id != self.manifest.id:
                raise ValueError("runtime observation trace identity mismatch")
            if item.architecture is not self.manifest.architecture:
                raise ValueError("runtime observation architecture mismatch")
            if item.vcpu_index >= self.manifest.vcpu_count:
                raise ValueError("runtime observation vCPU index is out of range")
        self.observations.sort(key=lambda item: item.sequence_index)

        from chipchain.runtime.capabilities import validate_runtime_capabilities

        validate_runtime_capabilities(self.backend_manifest, self.observations)
        return self
