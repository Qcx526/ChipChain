"""Non-verifying Phase 9C Step 3A runtime trigger-sequence contracts."""

from __future__ import annotations

import hashlib
import json
import re

from pydantic import Field, field_validator, model_validator

from chipchain.hardware_trigger.enums import ArmExecutionMode
from chipchain.hardware_trigger.models import _canonical_hex
from chipchain.hardware_trigger.static_models import (
    StaticFirmwareTriggerMatchResult,
    _canonical_sha256,
)
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture


_RAW_BYTES = re.compile(r"^[0-9a-f]+$")


def _canonical_id(prefix: str, payload: object) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(canonical).hexdigest()}"


def canonical_raw_instruction_bytes(value: object, *, size: int) -> str:
    """Validate one exact lowercase, prefix-free instruction-byte string."""

    if not isinstance(value, str) or not _RAW_BYTES.fullmatch(value):
        raise ValueError(
            "instruction bytes must be lowercase hexadecimal without a prefix"
        )
    if len(value) != size * 2:
        raise ValueError("instruction byte length must equal instruction_size")
    return value


def raw_little_endian_a32_word(instruction_bytes: str) -> str:
    """Convert exactly four canonical little-endian bytes to a logical A32 word."""

    normalized = canonical_raw_instruction_bytes(instruction_bytes, size=4)
    return f"0x{int.from_bytes(bytes.fromhex(normalized), 'little'):08x}"


class RuntimeInstructionOccurrence(DomainModel):
    """One actually executed instruction with independently observed identity."""

    sequence_index: int = Field(ge=0)
    pc: Identifier
    instruction_size: int = Field(gt=0, le=16)
    instruction_bytes: Identifier
    instruction_word: Identifier | None = None

    @field_validator("pc", mode="before")
    @classmethod
    def normalize_pc(cls, value: object) -> str:
        return _canonical_hex(value, digits=8, label="runtime ARM32 PC")

    @field_validator("instruction_bytes", mode="before")
    @classmethod
    def validate_instruction_bytes(cls, value: object, info) -> str:
        size = info.data.get("instruction_size")
        if not isinstance(size, int):
            raise ValueError("instruction_size must precede instruction_bytes")
        return canonical_raw_instruction_bytes(value, size=size)

    @field_validator("instruction_word", mode="before")
    @classmethod
    def normalize_instruction_word(cls, value: object) -> str | None:
        if value is None:
            return None
        return _canonical_hex(value, digits=8, label="runtime A32 instruction word")

    @model_validator(mode="after")
    def validate_word_binding(self) -> "RuntimeInstructionOccurrence":
        if self.instruction_size == 4:
            expected = raw_little_endian_a32_word(self.instruction_bytes)
            if self.instruction_word != expected:
                raise ValueError(
                    "runtime A32 word must match observed little-endian bytes"
                )
        elif self.instruction_word is not None:
            raise ValueError("non-4-byte runtime instruction cannot carry an A32 word")
        return self

    @classmethod
    def create(
        cls,
        *,
        sequence_index: int,
        pc: str,
        instruction_size: int,
        instruction_bytes: str,
    ) -> "RuntimeInstructionOccurrence":
        """Create one normalized instruction without inferring identity from PC."""

        word = (
            raw_little_endian_a32_word(instruction_bytes)
            if instruction_size == 4
            else None
        )
        return cls(
            sequence_index=sequence_index,
            pc=pc,
            instruction_size=instruction_size,
            instruction_bytes=instruction_bytes,
            instruction_word=word,
        )


def runtime_trigger_execution_trace_id(
    *,
    raw_trace_id: str,
    raw_trace_sha256: str,
    artifact_id: str,
    artifact_sha256: str,
    architecture: Architecture,
    execution_mode: ArmExecutionMode,
    instructions: list[RuntimeInstructionOccurrence],
) -> str:
    """Build a path- and metadata-independent runtime trace identity."""

    return _canonical_id(
        "runtime-trigger-execution-trace",
        {
            "architecture": Architecture(architecture).value,
            "artifact_id": artifact_id,
            "artifact_sha256": _canonical_sha256(artifact_sha256),
            "execution_mode": ArmExecutionMode(execution_mode).value,
            "instructions": [item.model_dump(mode="json") for item in instructions],
            "raw_trace_id": raw_trace_id,
            "raw_trace_sha256": _canonical_sha256(raw_trace_sha256),
        },
    )


class RuntimeTriggerExecutionTrace(DomainModel):
    """Path-neutral normalized execution facts from one dedicated raw trace."""

    id: Identifier
    raw_trace_id: Identifier
    raw_trace_sha256: Identifier
    run_id: Identifier
    scenario_id: Identifier
    artifact_id: Identifier
    artifact_sha256: Identifier
    architecture: Architecture
    execution_mode: ArmExecutionMode
    instructions: list[RuntimeInstructionOccurrence] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("raw_trace_sha256", "artifact_sha256", mode="before")
    @classmethod
    def normalize_sha256(cls, value: object) -> str:
        return _canonical_sha256(value)

    @model_validator(mode="after")
    def validate_scope_sequence_and_identity(self) -> "RuntimeTriggerExecutionTrace":
        if self.architecture is not Architecture.ARM:
            raise ValueError("runtime trigger execution traces support ARM only")
        if self.execution_mode is not ArmExecutionMode.A32:
            raise ValueError("runtime trigger execution traces support ARM A32 only")
        indexes = [item.sequence_index for item in self.instructions]
        if indexes != list(range(len(self.instructions))):
            raise ValueError(
                "runtime trigger instruction indexes must be contiguous from zero"
            )
        expected = runtime_trigger_execution_trace_id(
            raw_trace_id=self.raw_trace_id,
            raw_trace_sha256=self.raw_trace_sha256,
            artifact_id=self.artifact_id,
            artifact_sha256=self.artifact_sha256,
            architecture=self.architecture,
            execution_mode=self.execution_mode,
            instructions=self.instructions,
        )
        if self.id != expected:
            raise ValueError("RuntimeTriggerExecutionTrace ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "RuntimeTriggerExecutionTrace":
        """Create a detached normalized trace with semantic tamper detection."""

        data = dict(values)
        raw_instructions = data.get("instructions", [])
        if not isinstance(raw_instructions, list):
            raise ValueError("runtime trigger instructions must be a list")
        instructions = [
            RuntimeInstructionOccurrence.model_validate(
                item.model_dump(mode="json")
                if isinstance(item, RuntimeInstructionOccurrence)
                else item
            )
            for item in raw_instructions
        ]
        data["instructions"] = instructions
        data["architecture"] = Architecture(data["architecture"])
        data["execution_mode"] = ArmExecutionMode(data["execution_mode"])
        identity = runtime_trigger_execution_trace_id(
            raw_trace_id=str(data["raw_trace_id"]),
            raw_trace_sha256=str(data["raw_trace_sha256"]),
            artifact_id=str(data["artifact_id"]),
            artifact_sha256=str(data["artifact_sha256"]),
            architecture=data["architecture"],
            execution_mode=data["execution_mode"],
            instructions=instructions,
        )
        return cls(id=identity, **data)


def static_trigger_result_sha256(result: StaticFirmwareTriggerMatchResult) -> str:
    """Hash static semantic bindings without diagnostics or display metadata."""

    payload = {
        "architecture": result.architecture.value,
        "artifact_id": result.artifact_id,
        "artifact_sha256": result.artifact_sha256,
        "execution_mode": result.execution_mode.value,
        "hardware_vulnerability_id": result.hardware_vulnerability_id,
        "matches": [
            {
                "id": item.id,
                "instruction_locations": [
                    location.model_dump(mode="json")
                    for location in item.instruction_locations
                ],
            }
            for item in result.matches
        ],
        "signature_id": result.signature_id,
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def runtime_firmware_trigger_occurrence_id(
    *,
    raw_trace_sha256: str,
    artifact_sha256: str,
    static_match_id: str,
    signature_id: str,
    sequence_indexes: list[int],
    pcs: list[str],
    instruction_words: list[str],
) -> str:
    """Build an exact content-bound runtime occurrence identity."""

    return _canonical_id(
        "runtime-firmware-trigger-occurrence",
        {
            "artifact_sha256": _canonical_sha256(artifact_sha256),
            "instruction_words": instruction_words,
            "pcs": pcs,
            "raw_trace_sha256": _canonical_sha256(raw_trace_sha256),
            "sequence_indexes": sequence_indexes,
            "signature_id": signature_id,
            "static_match_id": static_match_id,
        },
    )


class RuntimeFirmwareTriggerOccurrence(DomainModel):
    """One exact executed T occurrence, with no precondition or verdict fields."""

    id: Identifier
    trace_id: Identifier
    raw_trace_sha256: Identifier
    artifact_id: Identifier
    artifact_sha256: Identifier
    static_match_id: Identifier
    signature_id: Identifier
    hardware_vulnerability_id: Identifier
    architecture: Architecture
    execution_mode: ArmExecutionMode
    instructions: list[RuntimeInstructionOccurrence] = Field(min_length=1)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("raw_trace_sha256", "artifact_sha256", mode="before")
    @classmethod
    def normalize_sha256(cls, value: object) -> str:
        return _canonical_sha256(value)

    @model_validator(mode="after")
    def validate_scope_and_identity(self) -> "RuntimeFirmwareTriggerOccurrence":
        if self.architecture is not Architecture.ARM:
            raise ValueError("runtime firmware trigger occurrences support ARM only")
        if self.execution_mode is not ArmExecutionMode.A32:
            raise ValueError("runtime firmware trigger occurrences support A32 only")
        if any(item.instruction_word is None for item in self.instructions):
            raise ValueError("runtime A32 occurrence requires 4-byte instruction words")
        indexes = [item.sequence_index for item in self.instructions]
        if indexes != list(range(indexes[0], indexes[0] + len(indexes))):
            raise ValueError("runtime trigger occurrence must be contiguous")
        expected = runtime_firmware_trigger_occurrence_id(
            raw_trace_sha256=self.raw_trace_sha256,
            artifact_sha256=self.artifact_sha256,
            static_match_id=self.static_match_id,
            signature_id=self.signature_id,
            sequence_indexes=indexes,
            pcs=[item.pc for item in self.instructions],
            instruction_words=[
                item.instruction_word for item in self.instructions if item.instruction_word
            ],
        )
        if self.id != expected:
            raise ValueError("RuntimeFirmwareTriggerOccurrence ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "RuntimeFirmwareTriggerOccurrence":
        """Create one exact occurrence with deterministic content identity."""

        data = dict(values)
        instructions = [
            RuntimeInstructionOccurrence.model_validate(
                item.model_dump(mode="json")
                if isinstance(item, RuntimeInstructionOccurrence)
                else item
            )
            for item in data["instructions"]
        ]
        data["instructions"] = instructions
        identity = runtime_firmware_trigger_occurrence_id(
            raw_trace_sha256=str(data["raw_trace_sha256"]),
            artifact_sha256=str(data["artifact_sha256"]),
            static_match_id=str(data["static_match_id"]),
            signature_id=str(data["signature_id"]),
            sequence_indexes=[item.sequence_index for item in instructions],
            pcs=[item.pc for item in instructions],
            instruction_words=[
                item.instruction_word for item in instructions if item.instruction_word
            ],
        )
        return cls(id=identity, **data)


class RuntimeFirmwareTriggerMatchResult(DomainModel):
    """Zero-or-more executed exact T occurrences, never a verification result."""

    trace_id: Identifier
    raw_trace_sha256: Identifier
    artifact_id: Identifier
    artifact_sha256: Identifier
    static_result_sha256: Identifier
    signature_id: Identifier
    hardware_vulnerability_id: Identifier
    architecture: Architecture
    execution_mode: ArmExecutionMode
    static_match_ids: list[Identifier] = Field(default_factory=list)
    occurrences: list[RuntimeFirmwareTriggerOccurrence] = Field(default_factory=list)
    diagnostics: list[Identifier] = Field(default_factory=list)

    @field_validator(
        "raw_trace_sha256", "artifact_sha256", "static_result_sha256", mode="before"
    )
    @classmethod
    def normalize_sha256(cls, value: object) -> str:
        return _canonical_sha256(value)

    @field_validator("static_match_ids", "diagnostics")
    @classmethod
    def normalize_unique_strings(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("runtime trigger result lists must be unique")
        return sorted(values)

    @field_validator("occurrences")
    @classmethod
    def normalize_occurrences(
        cls, values: list[RuntimeFirmwareTriggerOccurrence]
    ) -> list[RuntimeFirmwareTriggerOccurrence]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("runtime trigger occurrence IDs must be unique")
        return sorted(
            values,
            key=lambda item: (
                item.instructions[0].sequence_index,
                item.static_match_id,
                item.id,
            ),
        )

    @model_validator(mode="after")
    def validate_bindings(self) -> "RuntimeFirmwareTriggerMatchResult":
        if self.architecture is not Architecture.ARM:
            raise ValueError("runtime trigger matching supports ARM only")
        if self.execution_mode is not ArmExecutionMode.A32:
            raise ValueError("runtime trigger matching supports ARM A32 only")
        allowed_static_ids = set(self.static_match_ids)
        expected = (
            self.trace_id,
            self.raw_trace_sha256,
            self.artifact_id,
            self.artifact_sha256,
            self.signature_id,
            self.hardware_vulnerability_id,
            self.architecture,
            self.execution_mode,
        )
        for occurrence in self.occurrences:
            actual = (
                occurrence.trace_id,
                occurrence.raw_trace_sha256,
                occurrence.artifact_id,
                occurrence.artifact_sha256,
                occurrence.signature_id,
                occurrence.hardware_vulnerability_id,
                occurrence.architecture,
                occurrence.execution_mode,
            )
            if actual != expected or occurrence.static_match_id not in allowed_static_ids:
                raise ValueError("runtime trigger occurrence binding mismatch")
        return self


def runtime_trigger_match_result_sha256(
    result: RuntimeFirmwareTriggerMatchResult,
) -> str:
    """Hash semantic Step 3A result fields, excluding diagnostics/metadata."""

    payload = {
        "architecture": result.architecture.value,
        "artifact_id": result.artifact_id,
        "artifact_sha256": result.artifact_sha256,
        "execution_mode": result.execution_mode.value,
        "hardware_vulnerability_id": result.hardware_vulnerability_id,
        "occurrence_ids": [item.id for item in result.occurrences],
        "raw_trace_sha256": result.raw_trace_sha256,
        "signature_id": result.signature_id,
        "static_match_ids": result.static_match_ids,
        "static_result_sha256": result.static_result_sha256,
        "trace_id": result.trace_id,
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
