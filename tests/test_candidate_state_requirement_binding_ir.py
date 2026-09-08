"""Closed-schema and non-verdict tests for Phase 10D B2-B contracts."""

from __future__ import annotations

import ast
from pathlib import Path
import runpy

from pydantic import ValidationError
import pytest

from chipchain.verification import (
    CandidateStateObservationFamily,
    CandidateStateRequirementAcquisitionGap,
    CandidateStateRequirementAcquisitionGapReason,
    CandidateStateRequirementBindingMaterialization,
    CandidateStateRequirementBindingProjection,
    CandidateStateRequirementBindingRole,
    CandidateStateRequirementBindingSemantics,
    CandidateStateRequirementObservationBinding,
    CandidateStateSourceIncompatibility,
    CandidateStateSourceIncompatibilityReason,
    StaticCrossLayerEvidenceRequirementKind,
)


ROOT = Path(__file__).resolve().parents[1]
RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_candidate_state_requirement_bindings.py"),
    run_name="phase10d_b2b_ir_runner",
)


@pytest.fixture(scope="module")
def result():
    return RUNNER["build_owned_state_requirement_binding_materialization"]()


@pytest.mark.parametrize(
    ("model", "field", "expected"),
    [
        (
            CandidateStateRequirementObservationBinding,
            "source_observation_family",
            ["effective_memory_type", "execution_context"],
        ),
        (
            CandidateStateRequirementObservationBinding,
            "binding_role",
            ["exact_program_location_state_source_relevance"],
        ),
        (
            CandidateStateRequirementObservationBinding,
            "binding_semantics",
            ["source_relevance_only"],
        ),
        (
            CandidateStateRequirementAcquisitionGap,
            "reason",
            [
                "no_compatible_state_source",
                "no_effective_memory_type_observation_at_subject",
                "no_execution_context_observation_at_subject",
            ],
        ),
        (
            CandidateStateSourceIncompatibility,
            "reasons",
            [
                "architecture_mismatch",
                "artifact_id_mismatch",
                "artifact_sha256_mismatch",
                "instruction_set_mismatch",
            ],
        ),
    ],
)
def test_exact_v1_schema_vocabularies(model, field, expected):
    schema = model.model_json_schema()["properties"][field]
    if field == "reasons":
        schema = schema["items"]
    assert schema.get("enum", [schema.get("const")]) == expected


def test_roundtrip_and_deterministic_ids(result) -> None:
    objects = [
        result,
        result.projection,
        *result.projection.observation_requirement_bindings,
        *result.projection.acquisition_gaps,
        *result.projection.incompatible_state_sources,
    ]
    for item in objects:
        assert type(item).model_validate_json(item.model_dump_json()) == item
        assert type(item).model_validate(item.model_dump(mode="json")) == item


def test_binding_family_kind_closure(result) -> None:
    memory = next(
        item
        for item in result.projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
    )
    values = memory.model_dump(mode="python", exclude={"contract", "id"})
    with pytest.raises(ValidationError, match="family/requirement kind mismatch"):
        CandidateStateRequirementObservationBinding.create(
            **{
                **values,
                "source_requirement_kind": (
                    StaticCrossLayerEvidenceRequirementKind
                    .EXECUTION_CONTEXT_EVIDENCE_REQUIRED
                ),
            }
        )
    with pytest.raises(ValidationError):
        CandidateStateRequirementObservationBinding.create(
            **{**values, "binding_role": "supports_requirement"}
        )
    with pytest.raises(ValidationError):
        CandidateStateRequirementObservationBinding.create(
            **{**values, "binding_semantics": "satisfies"}
        )


def test_gap_reason_kind_closure(result) -> None:
    binding = result.projection.observation_requirement_bindings[0]
    common = {
        "source_requirement_materialization_id": (
            binding.source_requirement_materialization_id
        ),
        "source_requirement_projection_id": binding.source_requirement_projection_id,
        "source_requirement_id": binding.source_requirement_id,
        "source_requirement_kind": binding.source_requirement_kind,
        "source_case_candidate_id": binding.source_case_candidate_id,
    }
    valid = CandidateStateRequirementAcquisitionGap.create(
        **common,
        reason=CandidateStateRequirementAcquisitionGapReason.NO_COMPATIBLE_STATE_SOURCE,
    )
    assert valid.reason is (
        CandidateStateRequirementAcquisitionGapReason.NO_COMPATIBLE_STATE_SOURCE
    )
    wrong_reason = (
        CandidateStateRequirementAcquisitionGapReason
        .NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT
        if binding.source_observation_family
        is CandidateStateObservationFamily.EXECUTION_CONTEXT
        else CandidateStateRequirementAcquisitionGapReason
        .NO_EXECUTION_CONTEXT_OBSERVATION_AT_SUBJECT
    )
    with pytest.raises(ValidationError, match="wrong requirement kind"):
        CandidateStateRequirementAcquisitionGap.create(
            **common, reason=wrong_reason
        )


def test_projection_gap_reason_tracks_source_compatibility(result) -> None:
    projection = result.projection
    binding = projection.observation_requirement_bindings[0]
    gap = CandidateStateRequirementAcquisitionGap.create(
        source_requirement_materialization_id=(
            binding.source_requirement_materialization_id
        ),
        source_requirement_projection_id=binding.source_requirement_projection_id,
        source_requirement_id="owned-synthetic-unbound-requirement",
        source_requirement_kind=binding.source_requirement_kind,
        source_case_candidate_id=binding.source_case_candidate_id,
        reason=CandidateStateRequirementAcquisitionGapReason.NO_COMPATIBLE_STATE_SOURCE,
    )
    values = projection.model_dump(
        mode="python", exclude={"contract", "id", "diagnostic_codes"}
    )
    with pytest.raises(ValidationError, match="source compatibility mismatch"):
        CandidateStateRequirementBindingProjection.create(
            **{**values, "acquisition_gaps": [gap]}
        )


def test_incompatibility_reason_normalization(result) -> None:
    source = result.source_state_observation_materialization_snapshots[0]
    manifest = source.source_manifest_snapshot
    values = {
        "source_state_materialization_id": source.id,
        "source_state_manifest_id": manifest.id,
        "observed_architecture": manifest.architecture,
        "observed_artifact_id": manifest.artifact_id,
        "observed_artifact_sha256": manifest.artifact_sha256,
        "observed_instruction_set": manifest.instruction_set,
    }
    reasons = [
        CandidateStateSourceIncompatibilityReason.INSTRUCTION_SET_MISMATCH,
        CandidateStateSourceIncompatibilityReason.ARTIFACT_ID_MISMATCH,
    ]
    item = CandidateStateSourceIncompatibility.create(**values, reasons=reasons)
    assert item.reasons == sorted(reasons, key=lambda value: value.value)
    with pytest.raises(ValidationError, match="must be unique"):
        CandidateStateSourceIncompatibility.create(
            **values, reasons=[reasons[0], reasons[0]]
        )


def test_no_verdict_or_evaluation_fields(result) -> None:
    forbidden = {
        "status",
        "verified",
        "satisfied",
        "value_matches_requirement",
        "match_result",
        "expected_value_match",
        "conflict",
        "supports",
        "confidence",
        "score",
        "verification_record",
    }
    objects = [
        result,
        result.projection,
        *result.projection.observation_requirement_bindings,
        *result.projection.acquisition_gaps,
        *result.projection.incompatible_state_sources,
    ]
    for item in objects:
        assert forbidden.isdisjoint(type(item).model_fields)
        for field in forbidden:
            with pytest.raises(ValidationError):
                type(item).model_validate(
                    {**item.model_dump(mode="json"), field: "forbidden"}
                )


def test_projection_rejects_duplicate_logical_records(result) -> None:
    projection = result.projection
    values = projection.model_dump(
        mode="python", exclude={"contract", "id", "diagnostic_codes"}
    )
    binding = projection.observation_requirement_bindings[0]
    with pytest.raises(ValidationError, match="logically unique"):
        CandidateStateRequirementBindingProjection.create(
            **{
                **values,
                "observation_requirement_bindings": [
                    *projection.observation_requirement_bindings,
                    binding,
                ],
            }
        )


def test_core_dependency_firewall() -> None:
    allowed = {
        "__future__",
        "dataclasses",
        "enum",
        "hashlib",
        "json",
        "re",
        "typing",
        "pydantic",
        "chipchain.models.common",
        "chipchain.models.enums",
        "chipchain.verification.candidate_state_observation_models",
        "chipchain.verification.candidate_state_requirement_binding_models",
        "chipchain.verification.cross_layer_requirement_models",
        "chipchain.verification.cross_layer_requirements",
    }
    for relative in (
        "src/chipchain/verification/candidate_state_requirement_binding_models.py",
        "src/chipchain/verification/candidate_state_requirement_binding.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(name.name in allowed for name in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.module in allowed


def test_public_package_exports(result) -> None:
    from chipchain.verification import (
        bind_candidate_state_observations_to_requirements,
        export_candidate_state_requirement_binding_artifact_bundle,
    )

    assert callable(bind_candidate_state_observations_to_requirements)
    assert callable(export_candidate_state_requirement_binding_artifact_bundle)
    assert isinstance(result, CandidateStateRequirementBindingMaterialization)
    assert CandidateStateRequirementBindingRole.EXACT_PROGRAM_LOCATION_STATE_SOURCE_RELEVANCE.value == "exact_program_location_state_source_relevance"
    assert CandidateStateRequirementBindingSemantics.SOURCE_RELEVANCE_ONLY.value == "source_relevance_only"
