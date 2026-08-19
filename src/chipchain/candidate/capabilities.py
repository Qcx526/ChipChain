"""Direction-aware search capability boundary without a new search algorithm."""

from __future__ import annotations

from enum import Enum

from chipchain.candidate.errors import UnsupportedCrossLayerSearchError
from chipchain.models import CrossLayerDirection


class CrossLayerSearchStrategy(str, Enum):
    """Closed declaration of currently available directional search support."""

    SOFTWARE_TO_HARDWARE_EXACT_ANCHOR = (
        "software_to_hardware_exact_anchor"
    )
    HARDWARE_TO_SOFTWARE_NOT_IMPLEMENTED = (
        "hardware_to_software_not_implemented"
    )


def search_strategy_for_direction(
    direction: CrossLayerDirection,
) -> CrossLayerSearchStrategy:
    """Describe support without silently invoking the legacy searcher."""

    normalized = CrossLayerDirection(direction)
    if normalized is CrossLayerDirection.SOFTWARE_TO_HARDWARE:
        return CrossLayerSearchStrategy.SOFTWARE_TO_HARDWARE_EXACT_ANCHOR
    return CrossLayerSearchStrategy.HARDWARE_TO_SOFTWARE_NOT_IMPLEMENTED


def require_supported_search_strategy(
    direction: CrossLayerDirection,
) -> CrossLayerSearchStrategy:
    """Return the implemented strategy or raise a stable domain error."""

    strategy = search_strategy_for_direction(direction)
    if strategy is CrossLayerSearchStrategy.HARDWARE_TO_SOFTWARE_NOT_IMPLEMENTED:
        raise UnsupportedCrossLayerSearchError(
            "hardware-to-software cross-layer search is not implemented"
        )
    return strategy

