"""Normative trigger vocabulary, deliberately separate from fact nature/order."""

from enum import StrEnum


class TriggerSourceKind(StrEnum):
    """Declared source association, not authenticated provenance or trigger proof."""

    PROCESSORFUZZ_ARTIFACT = "processorfuzz_artifact"
    SYNTHETIC_FIXTURE = "synthetic_fixture"


class TriggerOrderKind(StrEnum):
    """Required step order, never a source/static/runtime observation."""

    REQUIRED_PRECEDES = "required_precedes"
    REQUIRED_IMMEDIATELY_PRECEDES = "required_immediately_precedes"
