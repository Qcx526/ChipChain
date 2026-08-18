"""Tests for strict explicit analyzer memory-map configuration."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.analysis import MemoryMap, MemoryRegion, ProgramArtifact
from chipchain.models import Layer, NodeKind


def test_memory_region_normalizes_hex_and_includes_both_bounds() -> None:
    """External addresses are canonical hex and ranges are inclusive."""

    region = MemoryRegion(
        id="fixture-window",
        name="FIXTURE_WINDOW",
        start="0x00004000",
        end="0x00004FFF",
        kind="mmio",
    )

    assert region.start == "0x4000"
    assert region.end == "0x4fff"
    assert region.contains(0x4000)
    assert region.contains(0x4FFF)
    assert not region.contains(0x3FFF)
    assert not region.contains(0x5000)


@pytest.mark.parametrize("address", ["4000", "0X4000", "not-hex", 0x4000])
def test_memory_region_rejects_noncanonical_input_types(address: object) -> None:
    """Memory maps must not silently reinterpret decimal or malformed input."""

    with pytest.raises(ValidationError, match="hexadecimal strings"):
        MemoryRegion(
            id="fixture-window",
            name="FIXTURE_WINDOW",
            start=address,
            end="0x4fff",
            kind="mmio",
        )


def test_memory_region_rejects_inverted_range() -> None:
    """An inclusive range cannot end before it starts."""

    with pytest.raises(ValidationError, match="start must not exceed end"):
        MemoryRegion(
            id="fixture-window",
            name="FIXTURE_WINDOW",
            start="0x5000",
            end="0x4000",
            kind="mmio",
        )


def test_register_memory_region_rejects_address_range() -> None:
    """A register identity must resolve to one exact hardware address."""

    with pytest.raises(ValidationError, match="identify one address"):
        MemoryRegion(
            id="fixture-register",
            name="FIXTURE_REGISTER",
            start="0x40000000",
            end="0x4000000f",
            kind="mmio",
            resource_kind=NodeKind.REGISTER,
        )


@pytest.mark.parametrize("resource_kind", ["function", "interface", "weakness"])
def test_memory_region_rejects_non_hardware_node_kind(resource_kind: str) -> None:
    """Memory-map targets can only become Register or HardwareResource nodes."""

    with pytest.raises(ValidationError, match="resource_kind"):
        MemoryRegion(
            id="fixture-window",
            name="FIXTURE_WINDOW",
            start="0x4000",
            end="0x4fff",
            kind="mmio",
            resource_kind=resource_kind,
        )


def test_memory_map_rejects_duplicate_ids_and_overlaps() -> None:
    """Ambiguous resource identity or classification must fail validation."""

    first = MemoryRegion(
        id="fixture-a",
        name="FIXTURE_A",
        start="0x4000",
        end="0x4fff",
        kind="mmio",
    )
    duplicate = first.model_copy(update={"start": "0x6000", "end": "0x6fff"})
    with pytest.raises(ValidationError, match="IDs must be unique"):
        MemoryMap(
            id="fixture-map",
            architecture="arm",
            regions=[first, duplicate],
        )

    overlap = MemoryRegion(
        id="fixture-b",
        name="FIXTURE_B",
        start="0x4fff",
        end="0x5fff",
        kind="mmio",
    )
    with pytest.raises(ValidationError, match="overlap"):
        MemoryMap(
            id="fixture-map",
            architecture="arm",
            regions=[first, overlap],
        )


def test_memory_map_lookup_and_empty_map_are_deterministic() -> None:
    """Lookup accepts boundaries, rejects outside addresses, and permits no regions."""

    region = MemoryRegion(
        id="fixture-window",
        name="FIXTURE_WINDOW",
        start="0x40000000",
        end="0x4000000f",
        kind="mmio",
        resource_kind=NodeKind.HARDWARE_RESOURCE,
    )
    memory_map = MemoryMap(
        id="fixture-map",
        architecture="arm",
        regions=[region],
    )

    assert memory_map.find_region(0x40000000) == region
    assert memory_map.find_region(0x4000000F) == region
    assert memory_map.find_region(0x3FFFFFFF) is None
    assert memory_map.find_region(0x40000010) is None
    assert MemoryMap(id="empty-map", architecture="arm").find_region(0) is None


def test_program_artifact_layer_defaults_and_validation() -> None:
    """Existing artifacts remain firmware while driver code is explicit."""

    firmware = ProgramArtifact(
        id="firmware-artifact",
        architecture="arm",
        artifact_type="elf",
        path="fixture.elf",
    )
    driver = ProgramArtifact(
        id="driver-artifact",
        architecture="arm",
        artifact_type="elf",
        program_layer="driver",
        path="fixture.elf",
    )

    assert firmware.program_layer is Layer.FIRMWARE
    assert driver.program_layer is Layer.DRIVER


@pytest.mark.parametrize("program_layer", ["hardware", "impact", "interface"])
def test_program_artifact_rejects_non_program_layers(program_layer: str) -> None:
    """Hardware and analytical layers cannot label executable ELF functions."""

    with pytest.raises(ValidationError, match="firmware or driver"):
        ProgramArtifact(
            id="invalid-layer-artifact",
            architecture="arm",
            artifact_type="elf",
            program_layer=program_layer,
            path="fixture.elf",
        )
