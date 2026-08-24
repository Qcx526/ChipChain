"""Isolated QEMU contracts for Phase 9C Step 3A instruction traces."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from chipchain.hardware_trigger.runtime_models import (
    RuntimeTriggerExecutionTrace,
    canonical_raw_instruction_bytes,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.verification.models import ProgramAddress


NonNegativeCount = Annotated[int, Field(ge=0)]
PositiveCount = Annotated[int, Field(gt=0)]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PLUGIN_VALUE = re.compile(r"^[A-Za-z0-9._:-]+$")


def _semantic_id(prefix: str, payload: object) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(canonical).hexdigest()}"


class QemuTriggerRawHeader(DomainModel):
    """First record emitted by the dedicated passive trigger observer."""

    record_type: Literal["header"] = "header"
    format: Literal["chipchain_qemu_trigger_sequence_trace"] = (
        "chipchain_qemu_trigger_sequence_trace"
    )
    format_version: Literal[1] = 1
    plugin_name: Literal["chipchain-qemu-trigger-sequence-observer"]
    plugin_build_api_version: NonNegativeCount
    target_name: Literal["arm"]
    plugin_api_min: NonNegativeCount
    plugin_api_current: NonNegativeCount
    system_emulation: Literal[True]
    smp_vcpus: Literal[1]
    max_vcpus: PositiveCount
    run_id: Identifier

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        if not _SAFE_PLUGIN_VALUE.fullmatch(value):
            raise ValueError("trigger raw run_id is not a safe identifier")
        return value

    @model_validator(mode="after")
    def validate_api_range(self) -> "QemuTriggerRawHeader":
        if self.max_vcpus < self.smp_vcpus:
            raise ValueError("QEMU max_vcpus cannot be smaller than smp_vcpus")
        if self.plugin_api_current < self.plugin_api_min:
            raise ValueError("QEMU plugin API current must be at least minimum")
        if not (
            self.plugin_api_min
            <= self.plugin_build_api_version
            <= self.plugin_api_current
        ):
            raise ValueError("trigger observer build API is outside runtime range")
        return self


class QemuTriggerRawInstructionEvent(DomainModel):
    """One instruction event emitted only when its execution callback runs."""

    record_type: Literal["event"] = "event"
    schema_version: Literal[1] = 1
    sequence_index: NonNegativeCount
    vcpu_index: Literal[0]
    event_kind: Literal["instruction_exec"] = "instruction_exec"
    pc: ProgramAddress
    instruction_size: Annotated[int, Field(gt=0, le=16)]
    instruction_bytes: Identifier

    @field_validator("instruction_bytes", mode="before")
    @classmethod
    def validate_instruction_bytes(
        cls, value: object, info: ValidationInfo
    ) -> str:
        size = info.data.get("instruction_size")
        if not isinstance(size, int):
            raise ValueError("instruction_size must precede instruction_bytes")
        return canonical_raw_instruction_bytes(value, size=size)


class QemuTriggerRawEnd(DomainModel):
    """Required clean final record for one complete trigger raw artifact."""

    record_type: Literal["end"] = "end"
    schema_version: Literal[1] = 1
    event_count: NonNegativeCount
    last_sequence_index: NonNegativeCount | None = None
    clean_shutdown: Literal[True] = True

    @model_validator(mode="after")
    def validate_count_shape(self) -> "QemuTriggerRawEnd":
        expected = self.event_count - 1 if self.event_count else None
        if self.last_sequence_index != expected:
            raise ValueError("trigger end count and last sequence are inconsistent")
        return self


def qemu_parsed_trigger_trace_id(
    *,
    header: QemuTriggerRawHeader,
    events: list[QemuTriggerRawInstructionEvent],
    end: QemuTriggerRawEnd,
    raw_trace_sha256: str,
) -> str:
    """Bind exact raw bytes to the parsed semantic instruction records."""

    if not _SHA256.fullmatch(raw_trace_sha256):
        raise ValueError("trigger raw hash must be lowercase SHA-256")
    return _semantic_id(
        "qemu-trigger-raw-trace",
        {
            "end": end.model_dump(mode="json"),
            "events": [item.model_dump(mode="json") for item in events],
            "header": header.model_dump(mode="json"),
            "raw_trace_sha256": raw_trace_sha256,
        },
    )


class QemuParsedTriggerTrace(DomainModel):
    """Complete strict raw trace with exact-content and semantic identity."""

    id: Identifier
    header: QemuTriggerRawHeader
    events: list[QemuTriggerRawInstructionEvent] = Field(default_factory=list)
    end: QemuTriggerRawEnd
    raw_trace_sha256: Identifier

    @field_validator("raw_trace_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("trigger raw hash must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def validate_complete_identity(self) -> "QemuParsedTriggerTrace":
        indexes = [item.sequence_index for item in self.events]
        if indexes != list(range(len(self.events))):
            raise ValueError(
                "trigger raw sequence indexes must be contiguous from zero"
            )
        if self.end.event_count != len(self.events):
            raise ValueError("trigger raw event count does not match end record")
        expected = qemu_parsed_trigger_trace_id(
            header=self.header,
            events=self.events,
            end=self.end,
            raw_trace_sha256=self.raw_trace_sha256,
        )
        if self.id != expected:
            raise ValueError("QemuParsedTriggerTrace ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "QemuParsedTriggerTrace":
        """Create a parsed trace with deterministic semantic tamper detection."""

        data = dict(values)
        header = QemuTriggerRawHeader.model_validate(data["header"])
        events = [
            QemuTriggerRawInstructionEvent.model_validate(item)
            for item in data.get("events", [])
        ]
        end = QemuTriggerRawEnd.model_validate(data["end"])
        raw_hash = str(data["raw_trace_sha256"])
        identity = qemu_parsed_trigger_trace_id(
            header=header,
            events=events,
            end=end,
            raw_trace_sha256=raw_hash,
        )
        return cls(
            id=identity,
            header=header,
            events=events,
            end=end,
            raw_trace_sha256=raw_hash,
        )


class QemuArmTriggerSequenceRunConfig(DomainModel):
    """Strict argv inputs for the ARM A32 passive trigger observer."""

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
    accelerator: Literal["tcg"] = "tcg"
    little_endian: Literal[True] = True

    @field_validator("firmware_sha256")
    @classmethod
    def validate_firmware_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("firmware_sha256 must be lowercase SHA-256")
        return value

    @field_validator("run_id", "artifact_id")
    @classmethod
    def validate_safe_plugin_values(cls, value: str) -> str:
        if not _SAFE_PLUGIN_VALUE.fullmatch(value):
            raise ValueError("run/artifact ID must be a path-neutral safe identifier")
        return value

    @model_validator(mode="after")
    def validate_paths(self) -> "QemuArmTriggerSequenceRunConfig":
        paths = (
            self.qemu_executable,
            self.plugin_path,
            self.firmware_elf,
            self.raw_trace_path,
        )
        if any("," in str(path) for path in paths):
            raise ValueError("QEMU trigger option paths must not contain commas")
        if len(set(paths)) != len(paths):
            raise ValueError("QEMU trigger inputs and output must use distinct paths")
        return self


class QemuTriggerSequenceRunResult(DomainModel):
    """Successful passive execution facts with no security verdict."""

    qemu_version: Identifier
    run_id: Identifier
    scenario_id: Identifier
    artifact_id: Identifier
    firmware_sha256: Identifier
    parsed_trace: QemuParsedTriggerTrace
    runtime_trace: RuntimeTriggerExecutionTrace

    @model_validator(mode="after")
    def validate_bindings(self) -> "QemuTriggerSequenceRunResult":
        expected = (
            self.run_id,
            self.scenario_id,
            self.artifact_id,
            self.firmware_sha256,
            self.parsed_trace.id,
            self.parsed_trace.raw_trace_sha256,
        )
        actual = (
            self.runtime_trace.run_id,
            self.runtime_trace.scenario_id,
            self.runtime_trace.artifact_id,
            self.runtime_trace.artifact_sha256,
            self.runtime_trace.raw_trace_id,
            self.runtime_trace.raw_trace_sha256,
        )
        if actual != expected or self.parsed_trace.header.run_id != self.run_id:
            raise ValueError("QEMU trigger run result binding mismatch")
        return self
