"""Plan-independent, architecture-neutral static semantic IR contracts."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_SEMANTIC_INSTRUCTION_FACT_CONTRACT = (
    "phase10d_static_semantic_instruction_fact_v1"
)
PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT = (
    "phase10d_static_semantic_inventory_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")
_HEX_BYTES = re.compile(r"^0x(?:[0-9a-fA-F]{2})+$")
_FORBIDDEN_OUTCOME_FRAGMENTS = (
    "causes",
    "exploit",
    "feasible_attack",
    "proximity_satisfied",
    "runtime_executed",
    "triggerable",
    "triggered",
    "verified",
    "vulnerable",
)


class StaticSemanticOperation(str, Enum):
    """Closed partial v1 vocabulary for security-relevant ISA semantics."""

    MEMORY_LOAD = "memory_load"
    MEMORY_STORE = "memory_store"
    LOAD_EXCLUSIVE = "load_exclusive"
    STORE_EXCLUSIVE = "store_exclusive"
    SYSTEM_REGISTER_READ = "system_register_read"
    SYSTEM_REGISTER_WRITE = "system_register_write"
    MEMORY_BARRIER = "memory_barrier"
    INSTRUCTION_BARRIER = "instruction_barrier"
    TLB_INVALIDATE = "tlb_invalidate"
    EXCEPTION_RETURN = "exception_return"


class StaticSemanticAttributeName(str, Enum):
    """Closed attribute-name vocabulary for semantic fact v1."""

    SYSTEM_REGISTER = "system_register"
    EFFECTIVE_MEMORY_TYPE_RESOLUTION = (
        "effective_memory_type_resolution"
    )
    BARRIER_KIND = "barrier_kind"
    BARRIER_OPTION = "barrier_option"
    TLB_OPERATION = "tlb_operation"
    MEMORY_EXCLUSIVITY = "memory_exclusivity"


class StaticSemanticFactScope(str, Enum):
    """The objective scope of one decoded static semantic fact."""

    DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY = (
        "decoded_static_instruction_semantics_only"
    )


class StaticSemanticInventoryScope(str, Enum):
    """Honest completeness boundary for a declared decoder profile."""

    PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY = (
        "partial_audited_static_semantic_inventory"
    )


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _semantic_id(prefix: str, payload: object) -> str:
    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"{prefix}:{digest}"


def _canonical_sha256(value: str) -> str:
    candidate = value.strip()
    if not _SHA256.fullmatch(candidate):
        raise ValueError("SHA-256 must contain 64 lowercase hexadecimal digits")
    return candidate


def _canonical_address(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("static semantic address must be a hexadecimal string")
    candidate = value.strip()
    if not _HEX_ADDRESS.fullmatch(candidate):
        raise ValueError("static semantic address must use hexadecimal notation")
    return hex(int(candidate, 16))


def _canonical_instruction_bytes(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("instruction bytes must be a hexadecimal string")
    candidate = value.strip()
    if not _HEX_BYTES.fullmatch(candidate):
        raise ValueError(
            "instruction bytes must use 0x plus an even number of hex digits"
        )
    return candidate.lower()


def _reject_path_like_identifier(value: str, *, label: str) -> str:
    lowered = value.lower()
    if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
        raise ValueError(f"{label} must be path-neutral")
    return value


def _reject_outcome_like_value(value: str, *, label: str) -> str:
    lowered = value.lower()
    if any(item in lowered for item in _FORBIDDEN_OUTCOME_FRAGMENTS):
        raise ValueError(f"{label} must be outcome-neutral")
    return value


class StaticSemanticAttribute(DomainModel):
    """One typed, flat and outcome-neutral semantic attribute."""

    name: StaticSemanticAttributeName
    value: Identifier

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = _reject_path_like_identifier(
            value, label="static semantic attribute value"
        )
        return _reject_outcome_like_value(
            value, label="static semantic attribute value"
        )


def static_semantic_instruction_fact_id(payload: object) -> str:
    """Return a deterministic plan-independent semantic fact identity."""

    return _semantic_id("static-semantic-instruction-fact", payload)


class _StaticSemanticInstructionFactBody(DomainModel):
    contract: Literal[PHASE10D_STATIC_SEMANTIC_INSTRUCTION_FACT_CONTRACT]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    decoder_profile_id: Identifier
    instruction_set: Identifier
    instruction_address: Identifier
    instruction_bytes: Identifier
    instruction_size: int = Field(ge=1)
    function_address: Identifier | None = None
    function_name: Identifier | None = None
    basic_block_address: Identifier | None = None
    operation: StaticSemanticOperation
    attributes: list[StaticSemanticAttribute] = Field(default_factory=list)
    fact_scope: Literal[
        StaticSemanticFactScope.DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
    ]

    @field_validator("artifact_id", "decoder_profile_id", "instruction_set")
    @classmethod
    def validate_path_neutral_identifier(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="static semantic provenance identifier"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator(
        "instruction_address",
        "function_address",
        "basic_block_address",
        mode="before",
    )
    @classmethod
    def normalize_address(cls, value: object) -> str | None:
        return _canonical_address(value)

    @field_validator("instruction_bytes", mode="before")
    @classmethod
    def normalize_instruction_bytes(cls, value: object) -> str:
        return _canonical_instruction_bytes(value)

    @field_validator("attributes")
    @classmethod
    def normalize_attributes(
        cls, values: list[StaticSemanticAttribute]
    ) -> list[StaticSemanticAttribute]:
        names = [item.name for item in values]
        if len(names) != len(set(names)):
            raise ValueError("static semantic attribute names must be unique")
        return sorted(values, key=lambda item: (item.name.value, item.value))

    @model_validator(mode="after")
    def validate_fact_semantics(self) -> "_StaticSemanticInstructionFactBody":
        decoded_size = (len(self.instruction_bytes) - 2) // 2
        if decoded_size != self.instruction_size:
            raise ValueError("instruction byte length does not match instruction size")
        if self.function_name is not None and self.function_address is None:
            raise ValueError("function name requires a function address")

        attribute_names = {item.name for item in self.attributes}
        system_operations = {
            StaticSemanticOperation.SYSTEM_REGISTER_READ,
            StaticSemanticOperation.SYSTEM_REGISTER_WRITE,
        }
        barrier_operations = {
            StaticSemanticOperation.MEMORY_BARRIER,
            StaticSemanticOperation.INSTRUCTION_BARRIER,
        }
        memory_operations = {
            StaticSemanticOperation.MEMORY_LOAD,
            StaticSemanticOperation.MEMORY_STORE,
            StaticSemanticOperation.LOAD_EXCLUSIVE,
            StaticSemanticOperation.STORE_EXCLUSIVE,
        }
        if self.operation in system_operations:
            if StaticSemanticAttributeName.SYSTEM_REGISTER not in attribute_names:
                raise ValueError("system-register operation requires register identity")
        elif StaticSemanticAttributeName.SYSTEM_REGISTER in attribute_names:
            raise ValueError("non-system-register operation carries register identity")
        barrier_names = {
            StaticSemanticAttributeName.BARRIER_KIND,
            StaticSemanticAttributeName.BARRIER_OPTION,
        }
        if self.operation in barrier_operations:
            if StaticSemanticAttributeName.BARRIER_KIND not in attribute_names:
                raise ValueError("barrier operation requires barrier kind")
        elif attribute_names.intersection(barrier_names):
            raise ValueError("non-barrier operation carries barrier attributes")
        if self.operation is StaticSemanticOperation.TLB_INVALIDATE:
            if StaticSemanticAttributeName.TLB_OPERATION not in attribute_names:
                raise ValueError("TLB invalidation requires operation identity")
        elif StaticSemanticAttributeName.TLB_OPERATION in attribute_names:
            raise ValueError("non-TLB operation carries TLB identity")
        if (
            StaticSemanticAttributeName.EFFECTIVE_MEMORY_TYPE_RESOLUTION
            in attribute_names
            and self.operation not in memory_operations
        ):
            raise ValueError("non-memory operation carries memory-type state")
        if (
            StaticSemanticAttributeName.MEMORY_EXCLUSIVITY in attribute_names
            and self.operation
            not in {
                StaticSemanticOperation.LOAD_EXCLUSIVE,
                StaticSemanticOperation.STORE_EXCLUSIVE,
            }
        ):
            raise ValueError("non-exclusive operation carries exclusivity state")
        return self


class StaticSemanticInstructionFact(_StaticSemanticInstructionFactBody):
    """One objective decoded static instruction-semantic fact."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticSemanticInstructionFact":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_SEMANTIC_INSTRUCTION_FACT_CONTRACT
        )
        body = _StaticSemanticInstructionFactBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_semantic_instruction_fact_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticSemanticInstructionFact":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_semantic_instruction_fact_id(payload):
            raise ValueError("static semantic instruction-fact ID mismatch")
        return self


def static_semantic_inventory_id(payload: object) -> str:
    """Return a deterministic plan-independent inventory identity."""

    return _semantic_id("static-semantic-inventory", payload)


class _StaticSemanticInventoryBody(DomainModel):
    contract: Literal[PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    decoder_profile_id: Identifier
    instruction_set: Identifier
    analysis_scope: Literal[
        StaticSemanticInventoryScope.PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
    ]
    facts: list[StaticSemanticInstructionFact] = Field(default_factory=list)
    diagnostic_codes: list[Identifier] = Field(default_factory=list)

    @field_validator("artifact_id", "decoder_profile_id", "instruction_set")
    @classmethod
    def validate_path_neutral_identifier(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="static semantic inventory identifier"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("facts")
    @classmethod
    def normalize_facts(
        cls, values: list[StaticSemanticInstructionFact]
    ) -> list[StaticSemanticInstructionFact]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static semantic fact IDs must be unique")
        return sorted(
            values,
            key=lambda item: (
                int(item.instruction_address, 16),
                item.operation.value,
                item.id,
            ),
        )

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("static semantic diagnostics must be unique")
        normalized = []
        for value in values:
            value = _reject_path_like_identifier(
                value, label="static semantic diagnostic"
            )
            normalized.append(
                _reject_outcome_like_value(
                    value, label="static semantic diagnostic"
                )
            )
        return sorted(normalized)

    @model_validator(mode="after")
    def validate_fact_bindings(self) -> "_StaticSemanticInventoryBody":
        expected = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.decoder_profile_id,
            self.instruction_set,
        )
        for fact in self.facts:
            detached = StaticSemanticInstructionFact.model_validate(
                fact.model_dump(mode="json")
            )
            if (
                detached.architecture,
                detached.artifact_id,
                detached.artifact_sha256,
                detached.decoder_profile_id,
                detached.instruction_set,
            ) != expected:
                raise ValueError("semantic fact crosses inventory provenance")
        return self


class StaticSemanticInventory(_StaticSemanticInventoryBody):
    """Audited partial inventory emitted by one declared decoder profile."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticSemanticInventory":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT
        body = _StaticSemanticInventoryBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_semantic_inventory_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticSemanticInventory":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_semantic_inventory_id(payload):
            raise ValueError("static semantic inventory ID mismatch")
        return self
