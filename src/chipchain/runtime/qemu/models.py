"""Strict Phase 9B1 QEMU environment, raw-record, and runner models."""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.runtime import RuntimeCapability, RuntimeTrace
from chipchain.verification.models import HardwareAddress, ProgramAddress


NonNegativeCount = Annotated[int, Field(ge=0)]
PositiveCount = Annotated[int, Field(gt=0)]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PLUGIN_VALUE = re.compile(r"^[A-Za-z0-9._:-]+$")

PHASE9B1_PASSIVE_CAPABILITIES = frozenset(
    {
        RuntimeCapability.INSTRUCTION_EXECUTION,
        RuntimeCapability.MEMORY_ACCESS,
        RuntimeCapability.PHYSICAL_ADDRESS,
        RuntimeCapability.IO_CLASSIFICATION,
    }
)


def _semantic_id(prefix: str, payload: object) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(canonical).hexdigest()}"


class QemuExecutableProbeResult(DomainModel):
    """Host-local executable discovery result without plugin claims."""

    qemu_executable: Identifier
    qemu_version: Identifier
    probe_method: Literal["explicit_path", "environment", "path_lookup"]


def qemu_runtime_environment_id(
    *,
    qemu_version: str,
    target_architecture: Architecture,
    system_emulation: bool,
    plugin_supported: bool,
    plugin_api_min: int,
    plugin_api_current: int,
    smp_vcpus: int,
    capabilities: list[RuntimeCapability],
) -> str:
    """Build a path-independent identity for a proven QEMU environment."""

    return _semantic_id(
        "qemu-runtime-environment",
        {
            "capabilities": sorted(item.value for item in capabilities),
            "plugin_api_current": plugin_api_current,
            "plugin_api_min": plugin_api_min,
            "plugin_supported": plugin_supported,
            "qemu_version": qemu_version,
            "smp_vcpus": smp_vcpus,
            "system_emulation": system_emulation,
            "target_architecture": target_architecture.value,
        },
    )


class QemuRuntimeEnvironment(DomainModel):
    """Executable probe plus plugin-runtime facts for the ARM passive MVP."""

    id: Identifier
    qemu_executable: Identifier
    qemu_version: Identifier
    target_architecture: Architecture
    system_emulation: bool
    plugin_supported: bool
    plugin_api_min: NonNegativeCount
    plugin_api_current: NonNegativeCount
    smp_vcpus: PositiveCount
    capabilities: list[RuntimeCapability]
    probe_method: Identifier
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(
        cls, values: list[RuntimeCapability]
    ) -> list[RuntimeCapability]:
        if len(values) != len(set(values)):
            raise ValueError("QEMU capabilities must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_environment(self) -> "QemuRuntimeEnvironment":
        if self.target_architecture is not Architecture.ARM:
            raise ValueError("Phase 9B1 supports only ARM")
        if not self.system_emulation or not self.plugin_supported:
            raise ValueError("Phase 9B1 requires a proven system-emulation plugin")
        if self.smp_vcpus != 1:
            raise ValueError("Phase 9B1 requires exactly one vCPU")
        if self.plugin_api_current < self.plugin_api_min:
            raise ValueError("QEMU plugin API current must be at least minimum")
        if set(self.capabilities) != PHASE9B1_PASSIVE_CAPABILITIES:
            raise ValueError("Phase 9B1 environment must declare only passive MVP capabilities")
        expected = qemu_runtime_environment_id(
            qemu_version=self.qemu_version,
            target_architecture=self.target_architecture,
            system_emulation=self.system_emulation,
            plugin_supported=self.plugin_supported,
            plugin_api_min=self.plugin_api_min,
            plugin_api_current=self.plugin_api_current,
            smp_vcpus=self.smp_vcpus,
            capabilities=self.capabilities,
        )
        if self.id != expected:
            raise ValueError("QemuRuntimeEnvironment ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "QemuRuntimeEnvironment":
        """Create a proven environment with a path-neutral identity."""

        values = dict(values)
        values["target_architecture"] = Architecture(values["target_architecture"])
        values["capabilities"] = [
            RuntimeCapability(item) for item in values["capabilities"]
        ]
        identity = qemu_runtime_environment_id(
            qemu_version=str(values["qemu_version"]),
            target_architecture=values["target_architecture"],
            system_emulation=bool(values["system_emulation"]),
            plugin_supported=bool(values["plugin_supported"]),
            plugin_api_min=int(values["plugin_api_min"]),
            plugin_api_current=int(values["plugin_api_current"]),
            smp_vcpus=int(values["smp_vcpus"]),
            capabilities=values["capabilities"],
        )
        return cls(id=identity, **values)


class QemuRawEventKind(str, Enum):
    """The only event kinds emitted by the Phase 9B1 passive plugin."""

    INSTRUCTION_EXEC = "instruction_exec"
    MMIO_READ = "mmio_read"
    MMIO_WRITE = "mmio_write"


class QemuRawHeader(DomainModel):
    """First JSONL record, populated from qemu_info_t by the plugin."""

    record_type: Literal["header"] = "header"
    format: Literal["chipchain_qemu_raw_trace"] = "chipchain_qemu_raw_trace"
    format_version: Literal[1] = 1
    plugin_name: Literal["chipchain-qemu-passive-observer"]
    plugin_build_api_version: NonNegativeCount
    target_name: Identifier
    plugin_api_min: NonNegativeCount
    plugin_api_current: NonNegativeCount
    system_emulation: bool
    smp_vcpus: PositiveCount
    max_vcpus: PositiveCount
    run_id: Identifier

    @field_validator("run_id")
    @classmethod
    def validate_raw_run_id(cls, value: str) -> str:
        if not _SAFE_PLUGIN_VALUE.fullmatch(value):
            raise ValueError("raw QEMU run_id is not a safe identifier")
        return value

    @model_validator(mode="after")
    def validate_header(self) -> "QemuRawHeader":
        if self.target_name != "arm":
            raise ValueError("Phase 9B1 raw target must be arm")
        if not self.system_emulation:
            raise ValueError("Phase 9B1 requires QEMU system emulation")
        if self.smp_vcpus != 1:
            raise ValueError("Phase 9B1 raw trace requires one vCPU")
        if self.max_vcpus < self.smp_vcpus:
            raise ValueError("QEMU max_vcpus cannot be smaller than smp_vcpus")
        if self.plugin_api_current < self.plugin_api_min:
            raise ValueError("QEMU plugin API current must be at least minimum")
        if not (
            self.plugin_api_min
            <= self.plugin_build_api_version
            <= self.plugin_api_current
        ):
            raise ValueError("observer build API is outside QEMU's supported range")
        return self


class QemuRawEvent(DomainModel):
    """One untrusted but strictly shaped instruction or IO-classified MMIO event."""

    record_type: Literal["event"] = "event"
    schema_version: Literal[1] = 1
    sequence_index: NonNegativeCount
    vcpu_index: NonNegativeCount
    event_kind: QemuRawEventKind
    pc: ProgramAddress
    virtual_address: HardwareAddress | None = None
    physical_address: HardwareAddress | None = None
    is_io: bool | None = None
    access_size: PositiveCount | None = None

    @model_validator(mode="after")
    def validate_event(self) -> "QemuRawEvent":
        if self.vcpu_index != 0:
            raise ValueError("Phase 9B1 raw event vCPU index must be zero")
        if self.event_kind is QemuRawEventKind.INSTRUCTION_EXEC:
            if any(
                value is not None
                for value in (
                    self.virtual_address,
                    self.physical_address,
                    self.is_io,
                    self.access_size,
                )
            ):
                raise ValueError("instruction raw event cannot contain memory fields")
        else:
            if (
                self.virtual_address is None
                or self.physical_address is None
                or self.access_size is None
            ):
                raise ValueError("raw MMIO event requires virtual/physical address and access size")
            if self.is_io is not True:
                raise ValueError("raw MMIO event requires plugin is_io=true")
        return self


class QemuRawEnd(DomainModel):
    """Required final JSONL record proving a clean, complete observer shutdown."""

    record_type: Literal["end"] = "end"
    schema_version: Literal[1] = 1
    event_count: NonNegativeCount
    last_sequence_index: NonNegativeCount | None = None
    clean_shutdown: Literal[True] = True

    @model_validator(mode="after")
    def validate_count_shape(self) -> "QemuRawEnd":
        expected = self.event_count - 1 if self.event_count else None
        if self.last_sequence_index != expected:
            raise ValueError("raw end record count and last sequence are inconsistent")
        return self


class QemuParsedRawTrace(DomainModel):
    """Fully parsed raw artifact with content hash and contiguous events."""

    header: QemuRawHeader
    events: list[QemuRawEvent] = Field(default_factory=list)
    end: QemuRawEnd
    artifact_sha256: Identifier

    @field_validator("artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("raw QEMU artifact hash must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def validate_complete_trace(self) -> "QemuParsedRawTrace":
        indexes = [item.sequence_index for item in self.events]
        if indexes != list(range(len(self.events))):
            raise ValueError("raw QEMU sequence indexes must be contiguous from zero")
        if self.end.event_count != len(self.events):
            raise ValueError("raw QEMU end event count does not match events")
        return self


class QemuArmPassiveRunConfig(DomainModel):
    """Safe argv inputs for one owned ARM system-emulation run."""

    qemu_executable: Path
    plugin_path: Path
    firmware_elf: Path
    raw_trace_path: Path
    run_id: Identifier
    scenario_id: Identifier
    artifact_id: Identifier
    firmware_sha256: Identifier
    timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 30.0
    machine: Literal["virt"] = "virt"
    cpu: Literal["cortex-a15"] = "cortex-a15"
    vcpu_count: Literal[1] = 1

    @field_validator("firmware_sha256")
    @classmethod
    def validate_firmware_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("firmware_sha256 must be lowercase SHA-256")
        return value

    @field_validator("run_id")
    @classmethod
    def validate_plugin_run_id(cls, value: str) -> str:
        if not _SAFE_PLUGIN_VALUE.fullmatch(value):
            raise ValueError("run_id contains unsafe plugin-option characters")
        return value

    @field_validator("artifact_id")
    @classmethod
    def validate_path_neutral_artifact_id(cls, value: str) -> str:
        if not _SAFE_PLUGIN_VALUE.fullmatch(value):
            raise ValueError("artifact_id must be a path-neutral identifier")
        return value

    @model_validator(mode="after")
    def validate_plugin_paths(self) -> "QemuArmPassiveRunConfig":
        if any(
            "," in str(path)
            for path in (self.plugin_path, self.firmware_elf, self.raw_trace_path)
        ):
            raise ValueError("QEMU option paths must not contain commas")
        if self.raw_trace_path in {self.plugin_path, self.firmware_elf}:
            raise ValueError("raw trace output must not overwrite an input artifact")
        return self


class QemuPassiveRunResult(DomainModel):
    """Successful passive run output; no vulnerability or interaction decision."""

    environment: QemuRuntimeEnvironment
    parsed_trace: QemuParsedRawTrace
    runtime_trace: RuntimeTrace
