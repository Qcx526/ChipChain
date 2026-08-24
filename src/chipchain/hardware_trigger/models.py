"""Strict machine-level hardware-trigger contracts for Phase 9C Step 1."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from chipchain.hardware_trigger.enums import (
    ArmExecutionMode,
    ArmPrivilegeMode,
    HardwareFailureEffectKind,
    HardwareTriggerProofKind,
)
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture


_ARM_REGISTER = re.compile(r"^r(?:[0-9]|1[0-5])$")


def _canonical_hex(value: object, *, digits: int, label: str) -> str:
    """Return one exact-width lowercase hexadecimal string."""

    if not isinstance(value, str):
        raise ValueError(f"{label} must be an explicit hexadecimal string")
    candidate = value.strip()
    if not re.fullmatch(rf"0x[0-9a-fA-F]{{{digits}}}", candidate):
        raise ValueError(
            f"{label} must use 0x followed by exactly {digits} hexadecimal digits"
        )
    return candidate.lower()


def _canonical_arm_register(value: object) -> str:
    """Require the unaliased canonical A32 register spelling r0 through r15."""

    if not isinstance(value, str) or not _ARM_REGISTER.fullmatch(value.strip()):
        raise ValueError("ARM register must use canonical spelling r0 through r15")
    return value.strip()


class ArmRegisterPrecondition(DomainModel):
    """Exact initial uint32 value required for one canonical A32 register."""

    register_name: Identifier = Field(alias="register")
    value: Identifier

    @field_validator("register_name", mode="before")
    @classmethod
    def validate_register(cls, value: object) -> str:
        return _canonical_arm_register(value)

    @field_validator("value", mode="before")
    @classmethod
    def validate_value(cls, value: object) -> str:
        return _canonical_hex(value, digits=8, label="register value")

    @property
    def register(self) -> str:
        """Expose the canonical JSON ``register`` identity."""

        return self.register_name


class ArmMemoryPrecondition(DomainModel):
    """Exact initial value at one untranslated ARM32 address and access size."""

    address: Identifier
    access_size: Literal[1, 2, 4]
    value: Identifier

    @field_validator("address", mode="before")
    @classmethod
    def validate_address(cls, value: object) -> str:
        return _canonical_hex(value, digits=8, label="memory address")

    @field_validator("value", mode="before")
    @classmethod
    def validate_value(cls, value: object, info: ValidationInfo) -> str:
        access_size = info.data.get("access_size")
        digits = {1: 2, 2: 4, 4: 8}.get(access_size)
        if digits is None:
            raise ValueError("memory access size must be 1, 2, or 4 bytes")
        return _canonical_hex(value, digits=digits, label="memory value")


class HardwareTriggerPreconditions(DomainModel):
    """Declared exact machine-state requirements for one hardware trigger.

    An empty object means only that the available hardware-side knowledge does
    not declare additional requirements.  It does not prove that no hidden
    preconditions exist.
    """

    privilege_mode: ArmPrivilegeMode | None = None
    register_preconditions: list[ArmRegisterPrecondition] = Field(
        default_factory=list
    )
    memory_preconditions: list[ArmMemoryPrecondition] = Field(
        default_factory=list
    )

    @field_validator("register_preconditions")
    @classmethod
    def normalize_register_preconditions(
        cls, values: list[ArmRegisterPrecondition]
    ) -> list[ArmRegisterPrecondition]:
        registers = [item.register for item in values]
        if len(registers) != len(set(registers)):
            raise ValueError("register preconditions must use unique registers")
        return sorted(values, key=lambda item: int(item.register.removeprefix("r")))

    @field_validator("memory_preconditions")
    @classmethod
    def normalize_memory_preconditions(
        cls, values: list[ArmMemoryPrecondition]
    ) -> list[ArmMemoryPrecondition]:
        bindings = [(item.address, item.access_size) for item in values]
        if len(bindings) != len(set(bindings)):
            raise ValueError(
                "memory preconditions must use unique address/access-size bindings"
            )
        return sorted(values, key=lambda item: (item.address, item.access_size))


class HardwareFailureEffect(DomainModel):
    """One primary hardware-side failure previously observed for the trigger."""

    kind: HardwareFailureEffectKind
    register_name: Identifier | None = Field(default=None, alias="register")
    expected_value: Identifier | None = None
    observed_value: Identifier | None = None
    assertion_id: Identifier | None = None
    assertion_description: Identifier | None = None

    @field_validator("register_name", mode="before")
    @classmethod
    def validate_register(cls, value: object) -> str | None:
        if value is None:
            return None
        return _canonical_arm_register(value)

    @field_validator("expected_value", "observed_value", mode="before")
    @classmethod
    def validate_register_value(cls, value: object) -> str | None:
        if value is None:
            return None
        return _canonical_hex(value, digits=8, label="failure register value")

    @property
    def register(self) -> str | None:
        """Expose the canonical JSON ``register`` identity."""

        return self.register_name

    @model_validator(mode="after")
    def validate_effect_shape(self) -> "HardwareFailureEffect":
        """Require exactly the fields meaningful for the selected effect kind."""

        register_fields = (
            self.register,
            self.expected_value,
            self.observed_value,
        )
        assertion_fields = (self.assertion_id, self.assertion_description)
        if self.kind is HardwareFailureEffectKind.REGISTER_MISMATCH:
            if any(value is None for value in register_fields):
                raise ValueError(
                    "register_mismatch requires register, expected_value, and observed_value"
                )
            if self.expected_value == self.observed_value:
                raise ValueError(
                    "register_mismatch expected and observed values must differ"
                )
            if any(value is not None for value in assertion_fields):
                raise ValueError(
                    "register_mismatch must not contain assertion fields"
                )
        else:
            if not any(value is not None for value in assertion_fields):
                raise ValueError(
                    "assertion_violation requires assertion identity or description"
                )
            if any(value is not None for value in register_fields):
                raise ValueError(
                    "assertion_violation must not contain register mismatch fields"
                )
        return self


class HardwareTriggerProof(DomainModel):
    """Prior hardware-side provenance for T + P leading to the failure effect."""

    kind: HardwareTriggerProofKind
    description: Identifier
    reference_ids: list[Identifier] = Field(min_length=1)

    @field_validator("reference_ids")
    @classmethod
    def normalize_reference_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("hardware trigger proof references must be unique")
        return sorted(values)


def hardware_trigger_signature_id(
    *,
    architecture: Architecture,
    execution_mode: ArmExecutionMode,
    hardware_vulnerability_id: str,
    instruction_sequence: list[str],
    preconditions: HardwareTriggerPreconditions,
    expected_effect: HardwareFailureEffect,
) -> str:
    """Build identity from trigger semantics, excluding proof and metadata."""

    normalized_architecture = Architecture(architecture)
    normalized_mode = ArmExecutionMode(execution_mode)
    if normalized_architecture is not Architecture.ARM:
        raise ValueError("hardware trigger signatures support ARM only")
    if normalized_mode is not ArmExecutionMode.A32:
        raise ValueError("hardware trigger signatures support ARM A32 only")
    if not isinstance(hardware_vulnerability_id, str) or not (
        normalized_vulnerability_id := hardware_vulnerability_id.strip()
    ):
        raise ValueError("hardware vulnerability ID must be non-empty text")
    if not instruction_sequence:
        raise ValueError("instruction sequence must be non-empty")
    normalized_instructions = [
        _canonical_hex(item, digits=8, label="A32 instruction word")
        for item in instruction_sequence
    ]
    normalized_preconditions = HardwareTriggerPreconditions.model_validate(
        preconditions.model_dump(mode="json")
    )
    normalized_effect = HardwareFailureEffect.model_validate(
        expected_effect.model_dump(mode="json")
    )
    payload = {
        "architecture": normalized_architecture.value,
        "execution_mode": normalized_mode.value,
        "expected_effect": normalized_effect.model_dump(mode="json"),
        "hardware_vulnerability_id": normalized_vulnerability_id,
        "instruction_sequence": normalized_instructions,
        "preconditions": normalized_preconditions.model_dump(mode="json"),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"hardware-trigger-signature:{hashlib.sha256(canonical).hexdigest()}"


class HardwareTriggerSignature(DomainModel):
    """Known ARM A32 machine trigger contract, not triggerability evidence.

    The model records prior hardware knowledge that an exact instruction
    sequence and declared preconditions produce a known primary hardware-side
    failure.  It does not state that firmware can execute the sequence, and it
    is not Evidence, a VerificationRecord, an AttackChain, or a score input.
    """

    id: Identifier
    architecture: Architecture
    execution_mode: ArmExecutionMode
    hardware_vulnerability_id: Identifier
    instruction_sequence: list[Identifier] = Field(min_length=1)
    preconditions: HardwareTriggerPreconditions
    expected_effect: HardwareFailureEffect
    proof: HardwareTriggerProof
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("instruction_sequence", mode="before")
    @classmethod
    def normalize_instruction_sequence(cls, value: object) -> list[str]:
        if not isinstance(value, list) or not value:
            raise ValueError("instruction sequence must be a non-empty JSON list")
        return [
            _canonical_hex(item, digits=8, label="A32 instruction word")
            for item in value
        ]

    @model_validator(mode="after")
    def validate_scope_and_identity(self) -> "HardwareTriggerSignature":
        """Enforce ARM/A32-only scope and reject semantic ID tampering."""

        if self.architecture is not Architecture.ARM:
            raise ValueError("hardware trigger signatures support ARM only")
        if self.execution_mode is not ArmExecutionMode.A32:
            raise ValueError("hardware trigger signatures support ARM A32 only")
        expected_id = hardware_trigger_signature_id(
            architecture=self.architecture,
            execution_mode=self.execution_mode,
            hardware_vulnerability_id=self.hardware_vulnerability_id,
            instruction_sequence=self.instruction_sequence,
            preconditions=self.preconditions,
            expected_effect=self.expected_effect,
        )
        if self.id != expected_id:
            raise ValueError("HardwareTriggerSignature ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        architecture: Architecture,
        execution_mode: ArmExecutionMode,
        hardware_vulnerability_id: str,
        instruction_sequence: list[str],
        preconditions: HardwareTriggerPreconditions | None = None,
        expected_effect: HardwareFailureEffect,
        proof: HardwareTriggerProof,
        metadata: Metadata | None = None,
    ) -> "HardwareTriggerSignature":
        """Create a detached signature with its deterministic semantic ID."""

        normalized_architecture = Architecture(architecture)
        normalized_mode = ArmExecutionMode(execution_mode)
        normalized_instructions = [
            _canonical_hex(item, digits=8, label="A32 instruction word")
            for item in instruction_sequence
        ]
        normalized_preconditions = HardwareTriggerPreconditions.model_validate(
            (preconditions or HardwareTriggerPreconditions()).model_dump(
                mode="json"
            )
        )
        normalized_effect = HardwareFailureEffect.model_validate(
            expected_effect.model_dump(mode="json")
        )
        normalized_proof = HardwareTriggerProof.model_validate(
            proof.model_dump(mode="json")
        )
        identity = hardware_trigger_signature_id(
            architecture=normalized_architecture,
            execution_mode=normalized_mode,
            hardware_vulnerability_id=hardware_vulnerability_id,
            instruction_sequence=normalized_instructions,
            preconditions=normalized_preconditions,
            expected_effect=normalized_effect,
        )
        return cls(
            id=identity,
            architecture=normalized_architecture,
            execution_mode=normalized_mode,
            hardware_vulnerability_id=hardware_vulnerability_id,
            instruction_sequence=normalized_instructions,
            preconditions=normalized_preconditions,
            expected_effect=normalized_effect,
            proof=normalized_proof,
            metadata=metadata or {},
        )
