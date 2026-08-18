"""Stable enums for exact cross-graph candidate correlation."""

from __future__ import annotations

from enum import Enum


class EntityLinkMethod(str, Enum):
    """Implemented entity-linking methods for the ARM MVP."""

    EXACT_CANONICAL_KEY = "exact_canonical_key"
