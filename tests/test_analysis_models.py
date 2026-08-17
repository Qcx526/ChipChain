"""Tests for ProgramArtifact, DemoProgramSpec, and analysis-result contracts."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from chipchain.analysis import ProgramAnalysisResult, ProgramArtifact
from chipchain.analysis.demo_spec import DemoProgramSpec


def test_valid_demo_program_spec_loads(
    demo_program_spec_data: dict[str, Any],
) -> None:
    """The auditable fixture should validate as adapter-specific semantic input."""

    spec = DemoProgramSpec.model_validate(demo_program_spec_data)

    assert spec.sample_type == "fixture"
    assert spec.architecture.value == "arm"
    assert len(spec.functions) == 3


def test_malformed_spec_is_rejected(
    demo_program_spec_data: dict[str, Any],
) -> None:
    """Missing required semantic collections must fail Pydantic validation."""

    demo_program_spec_data["functions"] = []

    with pytest.raises(ValidationError):
        DemoProgramSpec.model_validate(demo_program_spec_data)


def test_wrong_object_architecture_is_rejected(
    demo_program_spec_data: dict[str, Any],
) -> None:
    """A RISC-V observation cannot appear in an ARM fixture specification."""

    demo_program_spec_data["functions"][0]["architecture"] = "risc_v"

    with pytest.raises(ValidationError, match="match the spec architecture"):
        DemoProgramSpec.model_validate(demo_program_spec_data)


def test_duplicate_function_id_is_rejected(
    demo_program_spec_data: dict[str, Any],
) -> None:
    """Function discovery IDs must be unique before transformation."""

    demo_program_spec_data["functions"][1]["id"] = demo_program_spec_data[
        "functions"
    ][0]["id"]

    with pytest.raises(ValidationError, match="function IDs must be unique"):
        DemoProgramSpec.model_validate(demo_program_spec_data)


def test_dangling_call_endpoint_is_rejected(
    demo_program_spec_data: dict[str, Any],
) -> None:
    """Call observations must reference discovered caller and callee functions."""

    demo_program_spec_data["calls"][0]["callee_id"] = "missing-function"

    with pytest.raises(ValidationError, match="unknown function"):
        DemoProgramSpec.model_validate(demo_program_spec_data)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("caller_function_id", "unknown caller"),
        ("driver_function_id", "unknown driver function"),
    ],
)
def test_dangling_ioctl_endpoint_is_rejected(
    demo_program_spec_data: dict[str, Any], field: str, message: str
) -> None:
    """Both sides of an ioctl observation must reference known functions."""

    demo_program_spec_data["ioctls"][0][field] = "missing-function"

    with pytest.raises(ValidationError, match=message):
        DemoProgramSpec.model_validate(demo_program_spec_data)


def test_dangling_mmio_function_is_rejected(
    demo_program_spec_data: dict[str, Any],
) -> None:
    """An MMIO access must name the function that performs the observation."""

    demo_program_spec_data["mmio_accesses"][0]["function_id"] = "missing-function"

    with pytest.raises(ValidationError, match="unknown function"):
        DemoProgramSpec.model_validate(demo_program_spec_data)


def test_program_artifact_requires_a_location() -> None:
    """Future binary artifacts and fixtures need a path or adapter identifier."""

    with pytest.raises(ValidationError, match="path or fixture_identifier"):
        ProgramArtifact(
            id="fixture-artifact",
            architecture="arm",
            artifact_type="fixture",
        )


def test_program_analysis_result_round_trip_preserves_semantics(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Analyzer output should survive JSON serialization and reconstruction."""

    restored = ProgramAnalysisResult.model_validate_json(
        demo_analysis_result.model_dump_json()
    )

    assert restored == demo_analysis_result


def test_program_analysis_result_rejects_mixed_architecture(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Every result node must match the artifact and result architecture."""

    data = demo_analysis_result.model_dump(mode="json")
    data["nodes"][0]["architecture"] = "risc_v"

    with pytest.raises(ValidationError, match="architecture must match"):
        ProgramAnalysisResult.model_validate(data)


def test_program_analysis_result_rejects_dangling_evidence(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Every Edge evidence reference must resolve within the analysis result."""

    data = demo_analysis_result.model_dump(mode="json")
    data["edges"][0]["evidence_ids"] = ["missing-evidence"]

    with pytest.raises(ValidationError, match="unknown evidence IDs"):
        ProgramAnalysisResult.model_validate(data)
