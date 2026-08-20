"""Serializable Phase 9B2A dynamic trigger binding contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models import (
    Architecture,
    CrossLayerDirection,
    CrossLayerInteraction,
    CrossLayerInteractionType,
)
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.runtime.enums import RuntimeEventKind
from chipchain.verification.enums import InteractionReferenceRole
from chipchain.verification.models import HardwareAddress, ProgramAddress


PositiveAccessSize = Annotated[int, Field(gt=0)]
SupportedArchitecture = Literal[Architecture.ARM]
SupportedInteractionType = Literal[
    CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
    CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
]
SupportedDirection = Literal[CrossLayerDirection.SOFTWARE_TO_HARDWARE]
TriggerReferenceRole = Literal[InteractionReferenceRole.TRIGGER_BEHAVIOR]
SupportedDynamicTriggerEvent = Literal[
    RuntimeEventKind.MMIO_READ,
    RuntimeEventKind.MMIO_WRITE,
]


def _canonical_id(prefix: str, payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(serialized).hexdigest()}"


def dynamic_trigger_fact_id(
    *,
    interaction_id: str,
    architecture: Architecture,
    interaction_type: CrossLayerInteractionType,
    direction: CrossLayerDirection,
    interaction_reference_id: str,
    reference_role: InteractionReferenceRole,
    event_kind: RuntimeEventKind,
    program_address: ProgramAddress,
    physical_address: HardwareAddress,
    access_size: int,
    address_space_id: str | None,
    memory_map_id: str | None,
) -> str:
    """Build a deterministic identity for a declared dynamic trigger fact."""

    return _canonical_id(
        "dynamic-trigger-fact",
        {
            "access_size": access_size,
            "address_space_id": address_space_id,
            "architecture": architecture.value,
            "direction": direction.value,
            "event_kind": event_kind.value,
            "interaction_id": interaction_id,
            "interaction_reference_id": interaction_reference_id,
            "interaction_type": interaction_type.value,
            "memory_map_id": memory_map_id,
            "physical_address": physical_address.value,
            "program_address": program_address.value,
            "reference_role": reference_role.value,
        },
    )


class DynamicTriggerFact(DomainModel):
    """A declared Type I/II MMIO trigger fact, not an observation or verdict."""

    id: Identifier
    interaction_id: Identifier
    architecture: SupportedArchitecture
    interaction_type: SupportedInteractionType
    direction: SupportedDirection
    interaction_reference_id: Identifier
    reference_role: TriggerReferenceRole = InteractionReferenceRole.TRIGGER_BEHAVIOR
    event_kind: SupportedDynamicTriggerEvent
    program_address: ProgramAddress
    physical_address: HardwareAddress
    access_size: PositiveAccessSize
    address_space_id: Identifier | None = None
    memory_map_id: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)

    def _identity_fields(self) -> dict[str, object]:
        return {
            "access_size": self.access_size,
            "address_space_id": self.address_space_id,
            "architecture": self.architecture,
            "direction": self.direction,
            "event_kind": self.event_kind,
            "interaction_id": self.interaction_id,
            "interaction_reference_id": self.interaction_reference_id,
            "interaction_type": self.interaction_type,
            "memory_map_id": self.memory_map_id,
            "physical_address": self.physical_address,
            "program_address": self.program_address,
            "reference_role": self.reference_role,
        }

    @model_validator(mode="after")
    def validate_identity(self) -> "DynamicTriggerFact":
        if self.id != dynamic_trigger_fact_id(**self._identity_fields()):
            raise ValueError("DynamicTriggerFact ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        interaction: CrossLayerInteraction,
        *,
        interaction_reference_id: str,
        event_kind: RuntimeEventKind,
        program_address: ProgramAddress | str,
        physical_address: HardwareAddress | str,
        access_size: int,
        address_space_id: str | None = None,
        memory_map_id: str | None = None,
        metadata: Metadata | None = None,
    ) -> "DynamicTriggerFact":
        """Create a fact scoped to an existing software-to-hardware trigger."""

        _validate_supported_interaction(interaction)
        if interaction_reference_id not in interaction.trigger_behavior_ids:
            raise ValueError(
                "dynamic trigger reference must exist in interaction trigger_behavior_ids"
            )
        normalized_event = RuntimeEventKind(event_kind)
        if normalized_event not in {
            RuntimeEventKind.MMIO_READ,
            RuntimeEventKind.MMIO_WRITE,
        }:
            raise ValueError("Phase 9B2A supports only MMIO trigger observations")
        normalized_program_address = (
            program_address
            if isinstance(program_address, ProgramAddress)
            else ProgramAddress(value=program_address)
        )
        normalized_physical_address = (
            physical_address
            if isinstance(physical_address, HardwareAddress)
            else HardwareAddress(value=physical_address)
        )
        identity_fields = {
            "interaction_id": interaction.id,
            "architecture": interaction.architecture,
            "interaction_type": interaction.interaction_type,
            "direction": interaction.direction,
            "interaction_reference_id": interaction_reference_id,
            "reference_role": InteractionReferenceRole.TRIGGER_BEHAVIOR,
            "event_kind": normalized_event,
            "program_address": normalized_program_address,
            "physical_address": normalized_physical_address,
            "access_size": access_size,
            "address_space_id": address_space_id,
            "memory_map_id": memory_map_id,
        }
        return cls(
            id=dynamic_trigger_fact_id(**identity_fields),
            metadata=metadata or {},
            **identity_fields,
        )

    def validate_against(self, interaction: CrossLayerInteraction) -> None:
        """Reject a fact that is outside the supplied interaction contract."""

        _validate_supported_interaction(interaction)
        if (
            self.interaction_id,
            self.architecture,
            self.interaction_type,
            self.direction,
        ) != (
            interaction.id,
            interaction.architecture,
            interaction.interaction_type,
            interaction.direction,
        ):
            raise ValueError("dynamic trigger fact identity does not match interaction")
        if self.interaction_reference_id not in interaction.trigger_behavior_ids:
            raise ValueError(
                "dynamic trigger reference must exist in interaction trigger_behavior_ids"
            )


def dynamic_trigger_observation_binding_id(
    *,
    interaction_id: str,
    dynamic_trigger_fact_id: str,
    dynamic_evidence_id: str,
    runtime_trace_id: str,
    runtime_observation_id: str,
    run_id: str | None,
) -> str:
    """Build a deterministic identity for one explicit observation binding."""

    return _canonical_id(
        "dynamic-trigger-binding",
        {
            "dynamic_evidence_id": dynamic_evidence_id,
            "dynamic_trigger_fact_id": dynamic_trigger_fact_id,
            "interaction_id": interaction_id,
            "run_id": run_id,
            "runtime_observation_id": runtime_observation_id,
            "runtime_trace_id": runtime_trace_id,
        },
    )


class DynamicTriggerObservationBinding(DomainModel):
    """Explicit linkage from a declared trigger fact to runtime provenance."""

    id: Identifier
    interaction_id: Identifier
    dynamic_trigger_fact_id: Identifier
    dynamic_evidence_id: Identifier
    runtime_trace_id: Identifier
    runtime_observation_id: Identifier
    run_id: Identifier | None = None
    metadata: Metadata = Field(default_factory=dict)

    def _identity_fields(self) -> dict[str, object]:
        return {
            "dynamic_evidence_id": self.dynamic_evidence_id,
            "dynamic_trigger_fact_id": self.dynamic_trigger_fact_id,
            "interaction_id": self.interaction_id,
            "run_id": self.run_id,
            "runtime_observation_id": self.runtime_observation_id,
            "runtime_trace_id": self.runtime_trace_id,
        }

    @model_validator(mode="after")
    def validate_identity(self) -> "DynamicTriggerObservationBinding":
        if self.id != dynamic_trigger_observation_binding_id(
            **self._identity_fields()
        ):
            raise ValueError(
                "DynamicTriggerObservationBinding ID is not deterministic"
            )
        return self

    @classmethod
    def create(
        cls,
        fact: DynamicTriggerFact,
        *,
        dynamic_evidence_id: str,
        runtime_trace_id: str,
        runtime_observation_id: str,
        run_id: str | None = None,
        metadata: Metadata | None = None,
    ) -> "DynamicTriggerObservationBinding":
        """Create a binding without modifying the referenced runtime Evidence."""

        identity_fields = {
            "interaction_id": fact.interaction_id,
            "dynamic_trigger_fact_id": fact.id,
            "dynamic_evidence_id": dynamic_evidence_id,
            "runtime_trace_id": runtime_trace_id,
            "runtime_observation_id": runtime_observation_id,
            "run_id": run_id,
        }
        return cls(
            id=dynamic_trigger_observation_binding_id(**identity_fields),
            metadata=metadata or {},
            **identity_fields,
        )

    def validate_against(self, fact: DynamicTriggerFact) -> None:
        """Reject linkage to a different fact or interaction."""

        if (
            self.interaction_id != fact.interaction_id
            or self.dynamic_trigger_fact_id != fact.id
        ):
            raise ValueError("dynamic observation binding does not match trigger fact")


class DynamicInteractionVerificationInput(DomainModel):
    """Serializable Phase 9B2A request, independent of Phase 9A-R bindings."""

    interaction_id: Identifier
    architecture: SupportedArchitecture
    interaction_type: SupportedInteractionType
    direction: SupportedDirection
    trigger_facts: list[DynamicTriggerFact] = Field(default_factory=list)
    observation_bindings: list[DynamicTriggerObservationBinding] = Field(
        default_factory=list
    )
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("trigger_facts", mode="before")
    @classmethod
    def snapshot_facts(cls, values: object) -> object:
        """Detach supplied models so stale nested identity cannot be reused."""

        if isinstance(values, list):
            return [
                item.model_dump(mode="json")
                if isinstance(item, DynamicTriggerFact)
                else item
                for item in values
            ]
        return values

    @field_validator("trigger_facts")
    @classmethod
    def normalize_facts(
        cls, values: list[DynamicTriggerFact]
    ) -> list[DynamicTriggerFact]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("dynamic trigger fact IDs must be unique")
        return sorted(values, key=lambda item: item.id)

    @field_validator("observation_bindings", mode="before")
    @classmethod
    def snapshot_bindings(cls, values: object) -> object:
        """Detach supplied bindings before validating identity and linkage."""

        if isinstance(values, list):
            return [
                item.model_dump(mode="json")
                if isinstance(item, DynamicTriggerObservationBinding)
                else item
                for item in values
            ]
        return values

    @field_validator("observation_bindings")
    @classmethod
    def normalize_bindings(
        cls, values: list[DynamicTriggerObservationBinding]
    ) -> list[DynamicTriggerObservationBinding]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("dynamic observation binding IDs must be unique")
        return sorted(values, key=lambda item: item.id)

    @model_validator(mode="after")
    def validate_linkage(self) -> "DynamicInteractionVerificationInput":
        facts = {item.id: item for item in self.trigger_facts}
        for fact in self.trigger_facts:
            if (
                fact.interaction_id,
                fact.architecture,
                fact.interaction_type,
                fact.direction,
            ) != (
                self.interaction_id,
                self.architecture,
                self.interaction_type,
                self.direction,
            ):
                raise ValueError("dynamic trigger fact identity does not match input")

        linkage_keys: list[tuple[str, str, str]] = []
        observation_keys: dict[tuple[str, str], str] = {}
        evidence_ids: list[str] = []
        for binding in self.observation_bindings:
            fact = facts.get(binding.dynamic_trigger_fact_id)
            if fact is None:
                raise ValueError("dynamic observation binding references an unknown fact")
            binding.validate_against(fact)
            linkage_keys.append(
                (
                    binding.dynamic_trigger_fact_id,
                    binding.runtime_trace_id,
                    binding.runtime_observation_id,
                )
            )
            observation_key = (
                binding.runtime_trace_id,
                binding.runtime_observation_id,
            )
            existing_fact_id = observation_keys.get(observation_key)
            if (
                existing_fact_id is not None
                and existing_fact_id != binding.dynamic_trigger_fact_id
            ):
                raise ValueError(
                    "one runtime observation cannot bind conflicting trigger facts"
                )
            observation_keys[observation_key] = binding.dynamic_trigger_fact_id
            evidence_ids.append(binding.dynamic_evidence_id)

        if len(linkage_keys) != len(set(linkage_keys)):
            raise ValueError("dynamic observation linkage must be unique")
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("dynamic Evidence IDs must be unique within the input")
        return self

    @classmethod
    def create(
        cls,
        interaction: CrossLayerInteraction,
        *,
        trigger_facts: list[DynamicTriggerFact] | None = None,
        observation_bindings: list[DynamicTriggerObservationBinding] | None = None,
        metadata: Metadata | None = None,
    ) -> "DynamicInteractionVerificationInput":
        """Create and validate a request against one existing interaction."""

        _validate_supported_interaction(interaction)
        value = cls(
            interaction_id=interaction.id,
            architecture=interaction.architecture,
            interaction_type=interaction.interaction_type,
            direction=interaction.direction,
            trigger_facts=trigger_facts or [],
            observation_bindings=observation_bindings or [],
            metadata=metadata or {},
        )
        value.validate_against(interaction)
        return value

    def validate_against(self, interaction: CrossLayerInteraction) -> None:
        """Reject a request that is not scoped to the supplied interaction."""

        _validate_supported_interaction(interaction)
        if (
            self.interaction_id,
            self.architecture,
            self.interaction_type,
            self.direction,
        ) != (
            interaction.id,
            interaction.architecture,
            interaction.interaction_type,
            interaction.direction,
        ):
            raise ValueError("dynamic verification input does not match interaction")
        for fact in self.trigger_facts:
            fact.validate_against(interaction)


def _validate_supported_interaction(interaction: CrossLayerInteraction) -> None:
    if interaction.architecture is not Architecture.ARM:
        raise ValueError("Phase 9B2A supports only ARM interactions")
    if interaction.interaction_type not in {
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
    }:
        raise ValueError("Phase 9B2A Type III verification is not implemented")
    if interaction.direction is not CrossLayerDirection.SOFTWARE_TO_HARDWARE:
        raise ValueError("Phase 9B2A supports only software-to-hardware triggers")
