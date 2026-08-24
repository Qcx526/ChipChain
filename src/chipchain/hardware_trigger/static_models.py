"""Strict non-verifying result contracts for exact static trigger matching."""

from __future__ import annotations

import hashlib
import json
import re

from pydantic import Field, field_validator, model_validator

from chipchain.hardware_trigger.enums import ArmExecutionMode
from chipchain.hardware_trigger.models import _canonical_hex
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _canonical_sha256(value: object) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value.strip()):
        raise ValueError("artifact SHA-256 must contain exactly 64 hexadecimal digits")
    return value.strip().lower()


class StaticInstructionLocation(DomainModel):
    """One decoded executable A32 instruction in an exact static occurrence."""

    instruction_address: Identifier
    instruction_word: Identifier
    basic_block_address: Identifier

    @field_validator(
        "instruction_address",
        "basic_block_address",
        mode="before",
    )
    @classmethod
    def normalize_address(cls, value: object) -> str:
        return _canonical_hex(value, digits=8, label="ARM32 code address")

    @field_validator("instruction_word", mode="before")
    @classmethod
    def normalize_instruction_word(cls, value: object) -> str:
        return _canonical_hex(value, digits=8, label="A32 instruction word")


def static_firmware_trigger_match_id(
    *,
    artifact_sha256: str,
    signature_id: str,
    hardware_vulnerability_id: str,
    architecture: Architecture,
    execution_mode: ArmExecutionMode,
    function_address: str,
    instruction_locations: list[StaticInstructionLocation],
    basic_block_path: list[str],
) -> str:
    """Build identity from content-bound exact structural match facts."""

    payload = {
        "architecture": Architecture(architecture).value,
        "artifact_sha256": _canonical_sha256(artifact_sha256),
        "basic_block_path": [
            _canonical_hex(item, digits=8, label="ARM32 basic-block address")
            for item in basic_block_path
        ],
        "execution_mode": ArmExecutionMode(execution_mode).value,
        "function_address": _canonical_hex(
            function_address,
            digits=8,
            label="ARM32 function address",
        ),
        "hardware_vulnerability_id": hardware_vulnerability_id,
        "instruction_locations": [
            item.model_dump(mode="json") for item in instruction_locations
        ],
        "signature_id": signature_id,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"static-firmware-trigger-match:{hashlib.sha256(canonical).hexdigest()}"


class StaticFirmwareTriggerMatch(DomainModel):
    """One exact function-local CFG occurrence, not a verification verdict."""

    id: Identifier
    artifact_id: Identifier
    artifact_sha256: Identifier
    signature_id: Identifier
    hardware_vulnerability_id: Identifier
    architecture: Architecture
    execution_mode: ArmExecutionMode
    function_address: Identifier
    function_name: Identifier | None = None
    instruction_locations: list[StaticInstructionLocation] = Field(min_length=1)
    basic_block_path: list[Identifier] = Field(min_length=1)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("artifact_sha256", mode="before")
    @classmethod
    def normalize_artifact_sha256(cls, value: object) -> str:
        return _canonical_sha256(value)

    @field_validator("function_address", mode="before")
    @classmethod
    def normalize_function_address(cls, value: object) -> str:
        return _canonical_hex(value, digits=8, label="ARM32 function address")

    @field_validator("basic_block_path", mode="before")
    @classmethod
    def normalize_basic_block_path(cls, value: object) -> list[str]:
        if not isinstance(value, list) or not value:
            raise ValueError("basic-block path must be a non-empty JSON list")
        return [
            _canonical_hex(item, digits=8, label="ARM32 basic-block address")
            for item in value
        ]

    @model_validator(mode="after")
    def validate_scope_path_and_identity(self) -> "StaticFirmwareTriggerMatch":
        """Require ARM/A32 path consistency and deterministic identity."""

        if self.architecture is not Architecture.ARM:
            raise ValueError("static firmware trigger matches support ARM only")
        if self.execution_mode is not ArmExecutionMode.A32:
            raise ValueError("static firmware trigger matches support ARM A32 only")
        observed_path: list[str] = []
        for location in self.instruction_locations:
            if (
                not observed_path
                or observed_path[-1] != location.basic_block_address
            ):
                observed_path.append(location.basic_block_address)
        if observed_path != self.basic_block_path:
            raise ValueError(
                "basic-block path must match ordered instruction locations"
            )
        expected_id = static_firmware_trigger_match_id(
            artifact_sha256=self.artifact_sha256,
            signature_id=self.signature_id,
            hardware_vulnerability_id=self.hardware_vulnerability_id,
            architecture=self.architecture,
            execution_mode=self.execution_mode,
            function_address=self.function_address,
            instruction_locations=self.instruction_locations,
            basic_block_path=self.basic_block_path,
        )
        if self.id != expected_id:
            raise ValueError("StaticFirmwareTriggerMatch ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        artifact_id: str,
        artifact_sha256: str,
        signature_id: str,
        hardware_vulnerability_id: str,
        architecture: Architecture,
        execution_mode: ArmExecutionMode,
        function_address: str,
        function_name: str | None,
        instruction_locations: list[
            StaticInstructionLocation | dict[str, object]
        ],
        basic_block_path: list[str],
        metadata: Metadata | None = None,
    ) -> "StaticFirmwareTriggerMatch":
        """Create a detached match with its content-bound deterministic ID."""

        locations = [
            StaticInstructionLocation.model_validate(
                item.model_dump(mode="json")
                if isinstance(item, StaticInstructionLocation)
                else item
            )
            for item in instruction_locations
        ]
        identity = static_firmware_trigger_match_id(
            artifact_sha256=artifact_sha256,
            signature_id=signature_id,
            hardware_vulnerability_id=hardware_vulnerability_id,
            architecture=architecture,
            execution_mode=execution_mode,
            function_address=function_address,
            instruction_locations=locations,
            basic_block_path=basic_block_path,
        )
        return cls(
            id=identity,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            signature_id=signature_id,
            hardware_vulnerability_id=hardware_vulnerability_id,
            architecture=architecture,
            execution_mode=execution_mode,
            function_address=function_address,
            function_name=function_name,
            instruction_locations=locations,
            basic_block_path=basic_block_path,
            metadata=metadata or {},
        )


class StaticFirmwareTriggerMatchResult(DomainModel):
    """Deterministic zero-or-more static occurrences for one artifact/signature."""

    artifact_id: Identifier
    artifact_sha256: Identifier
    signature_id: Identifier
    hardware_vulnerability_id: Identifier
    architecture: Architecture
    execution_mode: ArmExecutionMode
    matches: list[StaticFirmwareTriggerMatch] = Field(default_factory=list)
    diagnostics: list[Identifier] = Field(default_factory=list)

    @field_validator("artifact_sha256", mode="before")
    @classmethod
    def normalize_artifact_sha256(cls, value: object) -> str:
        return _canonical_sha256(value)

    @field_validator("matches")
    @classmethod
    def normalize_matches(
        cls, values: list[StaticFirmwareTriggerMatch]
    ) -> list[StaticFirmwareTriggerMatch]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static firmware trigger match IDs must be unique")
        return sorted(
            values,
            key=lambda item: (
                int(item.function_address, 16),
                tuple(
                    int(location.instruction_address, 16)
                    for location in item.instruction_locations
                ),
                tuple(int(address, 16) for address in item.basic_block_path),
                item.id,
            ),
        )

    @field_validator("diagnostics")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("static trigger diagnostics must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_result_bindings(self) -> "StaticFirmwareTriggerMatchResult":
        """Require every occurrence to bind to this exact content and signature."""

        if self.architecture is not Architecture.ARM:
            raise ValueError("static firmware trigger results support ARM only")
        if self.execution_mode is not ArmExecutionMode.A32:
            raise ValueError("static firmware trigger results support ARM A32 only")
        expected = (
            self.artifact_id,
            self.artifact_sha256,
            self.signature_id,
            self.hardware_vulnerability_id,
            self.architecture,
            self.execution_mode,
        )
        for match in self.matches:
            actual = (
                match.artifact_id,
                match.artifact_sha256,
                match.signature_id,
                match.hardware_vulnerability_id,
                match.architecture,
                match.execution_mode,
            )
            if actual != expected:
                raise ValueError("static trigger match result binding mismatch")
        return self
