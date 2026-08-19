"""Formal Phase 8R cross-layer interaction semantics, independent of graphs."""

from __future__ import annotations

import hashlib
import json
from enum import Enum

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture, Layer


class CrossLayerInteractionType(str, Enum):
    """The three closed interaction classes defined for ChipChain research."""

    FIRMWARE_VULNERABILITY_TO_HARDWARE = (
        "firmware_vulnerability_to_hardware"
    )
    FIRMWARE_BEHAVIOR_TO_HARDWARE = "firmware_behavior_to_hardware"
    HARDWARE_VULNERABILITY_TO_FIRMWARE = (
        "hardware_vulnerability_to_firmware"
    )


class CrossLayerDirection(str, Enum):
    """Physical propagation direction of a cross-layer interaction."""

    SOFTWARE_TO_HARDWARE = "software_to_hardware"
    HARDWARE_TO_SOFTWARE = "hardware_to_software"


class CrossLayerLocationRole(str, Enum):
    """Distinct semantic roles for locations referenced by an interaction."""

    INITIATING_ROOT_CAUSE = "initiating_root_cause"
    CROSS_LAYER_TRIGGER_POINT = "cross_layer_trigger_point"
    AFFECTED_EXECUTION_POINT = "affected_execution_point"


SOFTWARE_SIDE_LAYERS = frozenset(
    {Layer.FIRMWARE, Layer.DRIVER, Layer.INTERFACE}
)
"""Existing layers treated as the firmware/software execution side."""

HARDWARE_SIDE_LAYERS = frozenset({Layer.HARDWARE})
"""Existing layers treated as the hardware side."""

_DIRECTION_BY_TYPE = {
    CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE: (
        CrossLayerDirection.SOFTWARE_TO_HARDWARE
    ),
    CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE: (
        CrossLayerDirection.SOFTWARE_TO_HARDWARE
    ),
    CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE: (
        CrossLayerDirection.HARDWARE_TO_SOFTWARE
    ),
}


def direction_for_interaction_type(
    interaction_type: CrossLayerInteractionType,
) -> CrossLayerDirection:
    """Return the only legal direction for an explicit interaction type."""

    return _DIRECTION_BY_TYPE[CrossLayerInteractionType(interaction_type)]


def cross_layer_interaction_id(
    *,
    architecture: Architecture,
    interaction_type: CrossLayerInteractionType,
    direction: CrossLayerDirection,
    source_layer: Layer,
    target_layer: Layer,
    initiating_vulnerability_ids: list[str],
    target_vulnerability_ids: list[str],
    trigger_behavior_ids: list[str],
    propagation_behavior_ids: list[str],
    affected_execution_ids: list[str],
    fault_state_ids: list[str],
    hardware_resource_ids: list[str],
    security_mechanism_ids: list[str],
    evidence_ids: list[str] | None = None,
    referenced_architectures: list[Architecture] | None = None,
) -> str:
    """Build identity from semantic participants, never mutable provenance.

    ``evidence_ids`` and ``referenced_architectures`` remain accepted for API
    compatibility with Phase 8R callers, but deliberately do not contribute to
    identity.  Adding evidence or provenance must not create a new interaction.
    """

    payload = {
        "affected_execution_ids": sorted(affected_execution_ids),
        "architecture": architecture.value,
        "direction": direction.value,
        "fault_state_ids": sorted(fault_state_ids),
        "hardware_resource_ids": sorted(hardware_resource_ids),
        "initiating_vulnerability_ids": sorted(initiating_vulnerability_ids),
        "interaction_type": interaction_type.value,
        "propagation_behavior_ids": sorted(propagation_behavior_ids),
        "security_mechanism_ids": sorted(security_mechanism_ids),
        "source_layer": source_layer.value,
        "target_layer": target_layer.value,
        "target_vulnerability_ids": sorted(target_vulnerability_ids),
        "trigger_behavior_ids": sorted(trigger_behavior_ids),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return f"cross-layer-interaction:{architecture.value}:{digest}"


class CrossLayerInteraction(DomainModel):
    """One typed cross-layer hypothesis or known scenario.

    The object is not a graph edge, an AttackChain, a search result, or a
    verification decision. Classification must be supplied explicitly by a
    dataset annotation or another deterministic system boundary.
    """

    id: Identifier
    architecture: Architecture
    interaction_type: CrossLayerInteractionType
    direction: CrossLayerDirection
    source_layer: Layer
    target_layer: Layer
    initiating_vulnerability_ids: list[Identifier] = Field(default_factory=list)
    target_vulnerability_ids: list[Identifier] = Field(default_factory=list)
    trigger_behavior_ids: list[Identifier] = Field(default_factory=list)
    propagation_behavior_ids: list[Identifier] = Field(default_factory=list)
    affected_execution_ids: list[Identifier] = Field(default_factory=list)
    fault_state_ids: list[Identifier] = Field(default_factory=list)
    hardware_resource_ids: list[Identifier] = Field(default_factory=list)
    security_mechanism_ids: list[Identifier] = Field(default_factory=list)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    referenced_architectures: list[Architecture] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "initiating_vulnerability_ids",
        "target_vulnerability_ids",
        "trigger_behavior_ids",
        "propagation_behavior_ids",
        "affected_execution_ids",
        "fault_state_ids",
        "hardware_resource_ids",
        "security_mechanism_ids",
        "evidence_ids",
    )
    @classmethod
    def normalize_id_lists(cls, values: list[str]) -> list[str]:
        """Reject repeated references and store canonical list order."""

        if len(values) != len(set(values)):
            raise ValueError("cross-layer interaction ID lists must be unique")
        return sorted(values)

    @field_validator("referenced_architectures")
    @classmethod
    def normalize_architectures(
        cls, values: list[Architecture]
    ) -> list[Architecture]:
        """Keep optional referenced-entity architecture declarations canonical."""

        if len(values) != len(set(values)):
            raise ValueError("referenced architectures must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_interaction_semantics(self) -> "CrossLayerInteraction":
        """Enforce type, direction, layer, participant, and stable-ID rules."""

        expected_direction = direction_for_interaction_type(self.interaction_type)
        if self.direction is not expected_direction:
            raise ValueError("interaction type and direction are inconsistent")
        if any(item is not self.architecture for item in self.referenced_architectures):
            raise ValueError("referenced entity architecture must match interaction")

        if self.direction is CrossLayerDirection.SOFTWARE_TO_HARDWARE:
            if self.source_layer not in SOFTWARE_SIDE_LAYERS:
                raise ValueError("software-to-hardware source must be a software-side layer")
            if self.target_layer not in HARDWARE_SIDE_LAYERS:
                raise ValueError("software-to-hardware target must be hardware")
        else:
            if self.source_layer not in HARDWARE_SIDE_LAYERS:
                raise ValueError("hardware-to-software source must be hardware")
            if self.target_layer not in SOFTWARE_SIDE_LAYERS:
                raise ValueError("hardware-to-software target must be a software-side layer")

        if (
            self.interaction_type
            is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
        ):
            self._require(
                self.initiating_vulnerability_ids,
                "Type I requires an initiating software-side vulnerability",
            )
            self._require(
                self.target_vulnerability_ids,
                "Type I requires a target hardware-side vulnerability",
            )
            self._require(
                self.trigger_behavior_ids,
                "Type I requires trigger behavior",
            )
        elif (
            self.interaction_type
            is CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
        ):
            if self.initiating_vulnerability_ids:
                raise ValueError(
                    "Type II must not invent an initiating software vulnerability"
                )
            self._require(
                self.target_vulnerability_ids,
                "Type II requires a target hardware-side vulnerability",
            )
            self._require(
                self.trigger_behavior_ids,
                "Type II requires trigger behavior",
            )
        else:
            self._require(
                self.initiating_vulnerability_ids,
                "Type III requires an initiating hardware-side vulnerability",
            )
            self._require(
                self.affected_execution_ids,
                "Type III requires affected software execution",
            )

        expected_id = cross_layer_interaction_id(
            architecture=self.architecture,
            interaction_type=self.interaction_type,
            direction=self.direction,
            source_layer=self.source_layer,
            target_layer=self.target_layer,
            initiating_vulnerability_ids=self.initiating_vulnerability_ids,
            target_vulnerability_ids=self.target_vulnerability_ids,
            trigger_behavior_ids=self.trigger_behavior_ids,
            propagation_behavior_ids=self.propagation_behavior_ids,
            affected_execution_ids=self.affected_execution_ids,
            fault_state_ids=self.fault_state_ids,
            hardware_resource_ids=self.hardware_resource_ids,
            security_mechanism_ids=self.security_mechanism_ids,
            evidence_ids=self.evidence_ids,
            referenced_architectures=self.referenced_architectures,
        )
        if self.id != expected_id:
            raise ValueError("CrossLayerInteraction ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        architecture: Architecture,
        interaction_type: CrossLayerInteractionType,
        source_layer: Layer,
        target_layer: Layer,
        initiating_vulnerability_ids: list[str] | None = None,
        target_vulnerability_ids: list[str] | None = None,
        trigger_behavior_ids: list[str] | None = None,
        propagation_behavior_ids: list[str] | None = None,
        affected_execution_ids: list[str] | None = None,
        fault_state_ids: list[str] | None = None,
        hardware_resource_ids: list[str] | None = None,
        security_mechanism_ids: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        referenced_architectures: list[Architecture] | None = None,
        metadata: Metadata | None = None,
    ) -> "CrossLayerInteraction":
        """Create a model with its deterministic direction and identity."""

        normalized_architecture = Architecture(architecture)
        normalized_type = CrossLayerInteractionType(interaction_type)
        normalized_source_layer = Layer(source_layer)
        normalized_target_layer = Layer(target_layer)
        direction = direction_for_interaction_type(normalized_type)
        lists = {
            "initiating_vulnerability_ids": initiating_vulnerability_ids or [],
            "target_vulnerability_ids": target_vulnerability_ids or [],
            "trigger_behavior_ids": trigger_behavior_ids or [],
            "propagation_behavior_ids": propagation_behavior_ids or [],
            "affected_execution_ids": affected_execution_ids or [],
            "fault_state_ids": fault_state_ids or [],
            "hardware_resource_ids": hardware_resource_ids or [],
            "security_mechanism_ids": security_mechanism_ids or [],
            "evidence_ids": evidence_ids or [],
        }
        architectures = [
            Architecture(item) for item in (referenced_architectures or [])
        ]
        identity = cross_layer_interaction_id(
            architecture=normalized_architecture,
            interaction_type=normalized_type,
            direction=direction,
            source_layer=normalized_source_layer,
            target_layer=normalized_target_layer,
            referenced_architectures=architectures,
            **lists,
        )
        return cls(
            id=identity,
            architecture=normalized_architecture,
            interaction_type=normalized_type,
            direction=direction,
            source_layer=normalized_source_layer,
            target_layer=normalized_target_layer,
            referenced_architectures=architectures,
            metadata=metadata or {},
            **lists,
        )

    @staticmethod
    def _require(values: list[str], message: str) -> None:
        if not values:
            raise ValueError(message)
