"""Closed-contract tests for Phase 10D 2D4-A requirement IR."""

from __future__ import annotations

import inspect
from pathlib import Path
import runpy

from pydantic import ValidationError
import pytest

from chipchain.verification import (
    BINDING_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1,
    CANDIDATE_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1,
    StaticCandidateVerificationRequirement,
    StaticCrossLayerBindingVerificationRequirement,
    StaticCrossLayerEvidenceRequirementKind,
    StaticCrossLayerVerificationRequirementOrigin,
    StaticCrossLayerVerificationRequirementSemantics,
    project_cross_layer_verification_requirements,
)
pytest.importorskip("angr")

_RUNNER = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts/export_static_cross_layer_candidates.py"),
    run_name="phase10d_requirement_ir_source_runner",
)
build_owned_static_cross_layer_materialization = _RUNNER[
    "build_owned_static_cross_layer_materialization"
]


@pytest.fixture(scope="module")
def materialization():
    return project_cross_layer_verification_requirements(
        build_owned_static_cross_layer_materialization()
    )


def test_public_api_has_exactly_one_logical_input() -> None:
    assert list(inspect.signature(project_cross_layer_verification_requirements).parameters) == ["cross_layer_materialization"]


def test_closed_v1_schema_vocabularies() -> None:
    candidate = StaticCandidateVerificationRequirement.model_json_schema()["properties"]
    binding = StaticCrossLayerBindingVerificationRequirement.model_json_schema()["properties"]
    assert set(candidate["source_obligation"]["enum"]) == {
        "runtime_execution_required", "symbolic_path_feasibility_remains_unresolved",
        "effective_memory_type_resolution_required", "runtime_execution_context_required",
        "relation_proximity_remains_unresolved", "additional_hardware_timing_remains_unresolved",
    }
    assert set(candidate["evidence_requirement_kind"]["enum"]) == {
        "runtime_execution_trace_required", "path_feasibility_evidence_required",
        "effective_memory_type_evidence_required", "execution_context_evidence_required",
        "qualitative_proximity_evidence_required", "hardware_timing_evidence_required",
    }
    assert set(binding["source_obligation"]["enum"]) == {
        "target_hardware_identity_required", "target_hardware_applicability_required",
        "hardware_effect_observation_required",
    }
    assert set(binding["evidence_requirement_kind"]["enum"]) == {
        "target_hardware_identity_evidence_required",
        "target_hardware_applicability_evidence_required",
        "hardware_effect_observation_evidence_required",
    }


def test_exact_v1_obligation_mappings_are_closed() -> None:
    expected_candidate = {
        "runtime_execution_required": "runtime_execution_trace_required",
        "symbolic_path_feasibility_remains_unresolved": (
            "path_feasibility_evidence_required"
        ),
        "effective_memory_type_resolution_required": (
            "effective_memory_type_evidence_required"
        ),
        "runtime_execution_context_required": (
            "execution_context_evidence_required"
        ),
        "relation_proximity_remains_unresolved": (
            "qualitative_proximity_evidence_required"
        ),
        "additional_hardware_timing_remains_unresolved": (
            "hardware_timing_evidence_required"
        ),
    }
    expected_binding = {
        "target_hardware_identity_required": (
            "target_hardware_identity_evidence_required"
        ),
        "target_hardware_applicability_required": (
            "target_hardware_applicability_evidence_required"
        ),
        "hardware_effect_observation_required": (
            "hardware_effect_observation_evidence_required"
        ),
    }
    actual_candidate = {
        key.value: value.value
        for key, value in (
            CANDIDATE_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1.items()
        )
    }
    actual_binding = {
        key.value: value.value
        for key, value in (
            BINDING_OBLIGATION_TO_EVIDENCE_REQUIREMENT_KIND_V1.items()
        )
    }
    assert actual_candidate == expected_candidate
    assert set(actual_candidate) == set(expected_candidate)
    assert set(actual_candidate.values()) == set(expected_candidate.values())
    assert actual_binding == expected_binding
    assert set(actual_binding) == set(expected_binding)
    assert set(actual_binding.values()) == set(expected_binding.values())


def test_candidate_and_binding_provenance_layers_are_unambiguous() -> None:
    candidate = StaticCandidateVerificationRequirement.model_json_schema()[
        "properties"
    ]
    binding = StaticCrossLayerBindingVerificationRequirement.model_json_schema()[
        "properties"
    ]
    assert "source_candidate_materialization_id" in candidate
    assert "source_candidate_projection_id" in candidate
    assert "source_cross_layer_materialization_id" not in candidate
    assert "source_cross_layer_projection_id" not in candidate
    assert "source_cross_layer_materialization_id" in binding
    assert "source_cross_layer_projection_id" in binding


def test_models_expose_requirements_only(materialization) -> None:
    forbidden = {"satisfied", "verified", "rejected", "available", "confidence", "probability", "score", "severity"}
    for item in [*materialization.projection.candidate_requirements, *materialization.projection.binding_requirements]:
        assert forbidden.isdisjoint(type(item).model_fields)
        assert item.requirement_semantics is StaticCrossLayerVerificationRequirementSemantics.OBJECTIVE_EVIDENCE_REQUIRED_ONLY
    assert all(item.requirement_origin is StaticCrossLayerVerificationRequirementOrigin.CANDIDATE_OBLIGATION for item in materialization.projection.candidate_requirements)
    assert all(item.requirement_origin is StaticCrossLayerVerificationRequirementOrigin.CROSS_LAYER_BINDING_OBLIGATION for item in materialization.projection.binding_requirements)


def test_wrong_kind_for_obligation_fails_closed(materialization) -> None:
    payload = materialization.projection.candidate_requirements[0].model_dump(mode="json")
    payload["evidence_requirement_kind"] = StaticCrossLayerEvidenceRequirementKind.HARDWARE_TIMING_EVIDENCE_REQUIRED.value
    with pytest.raises(ValidationError, match="mapping mismatch"):
        StaticCandidateVerificationRequirement.model_validate(payload)


def test_core_modules_obey_dependency_firewall() -> None:
    roots = [Path("src/chipchain/verification/cross_layer_requirement_models.py"), Path("src/chipchain/verification/cross_layer_requirements.py")]
    forbidden = ("angr", "capstone", "qemu", "RuntimeObservation", "RuntimeTraceManifest", "VerificationRecord", "InteractionVerificationPipeline", "provider", "reasoning")
    for path in roots:
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden)
