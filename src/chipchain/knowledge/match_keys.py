"""Canonical exact-match keys shared by future entity-linking adapters."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from chipchain.models import Architecture

_HEX_ADDRESS = re.compile(r"^0[xX][0-9a-fA-F]+$")


def address_match_key(architecture: Architecture, address: str) -> str:
    """Return an architecture-scoped canonical hardware-address key."""

    if not _HEX_ADDRESS.fullmatch(address.strip()):
        raise ValueError("hardware address match keys require hexadecimal strings")
    return f"arch:{architecture.value}:address:{hex(int(address, 16))}"


def memory_map_region_match_key(
    architecture: Architecture,
    memory_map_id: str,
    region_id: str,
) -> str:
    """Return the exact key for one audited memory-map region identity."""

    return (
        f"arch:{architecture.value}:mmio-map:{memory_map_id}:region:{region_id}"
    )


def component_match_key(architecture: Architecture, component_id: str) -> str:
    """Return the exact architecture-scoped component identifier key."""

    return f"arch:{architecture.value}:component:{component_id}"


def interface_match_key(
    architecture: Architecture,
    kind: str,
    identifier: str,
) -> str:
    """Return an exact key from a structured interface kind and identifier."""

    return f"arch:{architecture.value}:interface:{kind}:{identifier}"


def hardware_resource_match_keys(
    architecture: Architecture,
    *,
    address: str | None,
    metadata: Mapping[str, Any],
) -> list[str]:
    """Build deterministic address and memory-map keys without fuzzy labels."""

    keys: set[str] = set()
    if address is not None and _HEX_ADDRESS.fullmatch(address.strip()):
        keys.add(address_match_key(architecture, address))

    memory_map_id = metadata.get("memory_map_id")
    region_id = metadata.get("memory_map_region")
    if isinstance(memory_map_id, str) and isinstance(region_id, str):
        if memory_map_id.strip() and region_id.strip():
            keys.add(
                memory_map_region_match_key(
                    architecture,
                    memory_map_id.strip(),
                    region_id.strip(),
                )
            )
    return sorted(keys)
