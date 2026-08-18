"""Strict explicit memory-map configuration for program analyzers."""

from __future__ import annotations

import re
from enum import Enum

from pydantic import Field, field_validator, model_validator

from chipchain.models import Architecture, NodeKind
from chipchain.models.common import DomainModel, Identifier, Metadata


_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")


class MemoryRegionKind(str, Enum):
    """Memory-region semantics supported by the Phase 4B analyzer."""

    MMIO = "mmio"


class MemoryRegion(DomainModel):
    """One inclusive address range supplied by an audited device memory map."""

    id: Identifier
    name: Identifier
    start: Identifier
    end: Identifier
    kind: MemoryRegionKind
    resource_kind: NodeKind = NodeKind.HARDWARE_RESOURCE
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("start", "end", mode="before")
    @classmethod
    def normalize_address(cls, value: object) -> str:
        """Require external hexadecimal strings and return a canonical form."""

        if not isinstance(value, str) or not _HEX_ADDRESS.fullmatch(value.strip()):
            raise ValueError("memory region addresses must be hexadecimal strings")
        return hex(int(value, 16))

    @field_validator("resource_kind")
    @classmethod
    def validate_resource_kind(cls, value: NodeKind) -> NodeKind:
        """Limit memory-map resources to graph hardware node kinds."""

        if value not in {NodeKind.REGISTER, NodeKind.HARDWARE_RESOURCE}:
            raise ValueError(
                "resource_kind must be register or hardware_resource"
            )
        return value

    @model_validator(mode="after")
    def validate_range(self) -> "MemoryRegion":
        """Require a non-inverted inclusive address range."""

        if self.start_address > self.end_address:
            raise ValueError("memory region start must not exceed end")
        return self

    @property
    def start_address(self) -> int:
        """Return the inclusive integer start used inside analyzers."""

        return int(self.start, 16)

    @property
    def end_address(self) -> int:
        """Return the inclusive integer end used inside analyzers."""

        return int(self.end, 16)

    def contains(self, address: int) -> bool:
        """Return whether *address* lies inside this inclusive region."""

        return self.start_address <= address <= self.end_address


class MemoryMap(DomainModel):
    """Small architecture-scoped set of non-overlapping known memory regions."""

    id: Identifier
    architecture: Architecture
    regions: list[MemoryRegion] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_regions(self) -> "MemoryMap":
        """Reject duplicate IDs and ambiguous inclusive overlaps."""

        region_ids = [region.id for region in self.regions]
        if len(region_ids) != len(set(region_ids)):
            raise ValueError("memory region IDs must be unique")

        ordered = sorted(
            self.regions,
            key=lambda region: (region.start_address, region.end_address, region.id),
        )
        for previous, current in zip(ordered, ordered[1:], strict=False):
            if current.start_address <= previous.end_address:
                raise ValueError(
                    f"memory regions {previous.id!r} and {current.id!r} overlap"
                )
        return self

    def find_region(self, address: int) -> MemoryRegion | None:
        """Return the unique configured region containing *address*, if any."""

        return next(
            (
                region
                for region in sorted(self.regions, key=lambda item: item.id)
                if region.contains(address)
            ),
            None,
        )
