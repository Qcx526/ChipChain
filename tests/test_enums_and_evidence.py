"""Tests for stable enums and evidence validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.models import Architecture, BehaviorNode, Evidence, EvidenceType


def valid_evidence_data() -> dict[str, object]:
    """Return minimal valid evidence input."""

    return {
        "id": "fixture-evidence",
        "type": "static_analysis",
        "source": "chipchain-test-fixture",
        "confidence": 0.5,
    }


def test_stable_enum_values_are_loaded_from_json_strings() -> None:
    """Public JSON values should resolve to their enum members."""

    evidence = Evidence.model_validate(valid_evidence_data())

    assert Architecture.RISC_V.value == "risc_v"
    assert evidence.type is EvidenceType.STATIC_ANALYSIS


def test_invalid_enum_value_is_rejected() -> None:
    """Unknown architecture strings must not silently enter graph data."""

    with pytest.raises(ValidationError):
        BehaviorNode.model_validate(
            {
                "id": "fixture-node",
                "kind": "function",
                "name": "fixture_function",
                "architecture": "unknown_architecture",
                "layer": "firmware",
            }
        )


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_evidence_confidence_must_be_in_unit_interval(confidence: float) -> None:
    """Evidence confidence outside [0, 1] must be rejected."""

    data = valid_evidence_data()
    data["confidence"] = confidence

    with pytest.raises(ValidationError):
        Evidence.model_validate(data)


def test_unknown_evidence_field_is_rejected() -> None:
    """A misspelled upstream field must not be silently ignored."""

    data = valid_evidence_data()
    data["confidnce"] = 0.5

    with pytest.raises(ValidationError):
        Evidence.model_validate(data)


def test_mutable_metadata_defaults_are_not_shared() -> None:
    """Default metadata dictionaries must be independent per instance."""

    first = Evidence.model_validate(valid_evidence_data())
    second_data = valid_evidence_data()
    second_data["id"] = "fixture-evidence-2"
    second = Evidence.model_validate(second_data)

    first.metadata["fixture"] = True

    assert second.metadata == {}
