"""Closed-contract tests for Phase 10D 2D4-B1 runtime evidence IR."""

from __future__ import annotations

import inspect
from pathlib import Path
import runpy

from pydantic import ValidationError
import pytest

from chipchain.verification import (
    CandidateRuntimeEvidenceBindingRole,
    CandidateRuntimeEvidenceBindingSemantics,
    CandidateRuntimeEvidenceGap,
    CandidateRuntimeEvidenceGapReason,
    CandidateRuntimeEvidenceKind,
    CandidateRuntimeEvidenceMaterialization,
    CandidateRuntimeEvidenceProjection,
    CandidateRuntimeEvidenceSemantics,
    CandidateRuntimeInstructionEvidence,
    CandidateRuntimeOrderEvidence,
    CandidateRuntimeRequirementEvidenceBinding,
    CandidateRuntimeTraceIncompatibility,
    CandidateRuntimeTraceIncompatibilityReason,
    bind_candidate_runtime_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
_RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_candidate_runtime_evidence.py"),
    run_name="phase10d_candidate_runtime_evidence_ir_runner",
)


@pytest.fixture(scope="module")
def materialization():
    return _RUNNER["build_owned_candidate_runtime_evidence_materialization"]()


def test_public_api_has_exactly_two_logical_inputs() -> None:
    assert list(inspect.signature(bind_candidate_runtime_evidence).parameters) == [
        "requirement_materialization",
        "runtime_traces",
    ]


def test_contract_literals_and_closed_v1_vocabularies() -> None:
    models = (
        CandidateRuntimeInstructionEvidence,
        CandidateRuntimeOrderEvidence,
        CandidateRuntimeRequirementEvidenceBinding,
        CandidateRuntimeEvidenceGap,
        CandidateRuntimeTraceIncompatibility,
        CandidateRuntimeEvidenceProjection,
        CandidateRuntimeEvidenceMaterialization,
    )
    for model in models:
        contract = model.model_json_schema()["properties"]["contract"]
        assert "const" in contract
        assert contract["const"].startswith("phase10d_candidate_runtime_")
        assert contract["const"].endswith("_v1")
    assert {item.value for item in CandidateRuntimeEvidenceKind} == {
        "instruction_execution_observation",
        "static_witness_endpoint_runtime_order_observation",
    }
    assert {item.value for item in CandidateRuntimeEvidenceGapReason} == {
        "no_compatible_runtime_trace",
        "no_matching_instruction_observation",
        "no_matching_runtime_order_observation",
        "current_runtime_contract_does_not_observe_requirement_kind",
    }
    assert {item.value for item in CandidateRuntimeTraceIncompatibilityReason} == {
        "architecture_mismatch",
        "artifact_id_mismatch",
        "artifact_sha256_mismatch",
    }


def test_models_expose_no_evaluation_or_verdict_fields(materialization) -> None:
    forbidden = {
        "status",
        "satisfied",
        "verified",
        "rejected",
        "confidence",
        "score",
        "severity",
        "fully_observed",
        "all_positions_seen",
        "path_complete",
        "evidence_sufficient",
    }
    values = [
        *materialization.projection.instruction_evidence,
        *materialization.projection.order_evidence,
        *materialization.projection.requirement_evidence_bindings,
        *materialization.projection.evidence_gaps,
    ]
    assert all(forbidden.isdisjoint(type(item).model_fields) for item in values)
    assert all(
        item.evidence_semantics
        is CandidateRuntimeEvidenceSemantics.OBJECTIVE_RUNTIME_OBSERVATION_ONLY
        for item in [
            *materialization.projection.instruction_evidence,
            *materialization.projection.order_evidence,
        ]
    )
    assert all(
        item.binding_role
        is CandidateRuntimeEvidenceBindingRole.RELEVANT_RUNTIME_OBSERVATION
        and item.binding_semantics
        is CandidateRuntimeEvidenceBindingSemantics
        .EXACT_SOURCE_SUBJECT_BINDING_ONLY
        for item in materialization.projection.requirement_evidence_bindings
    )


def test_deterministic_ids_reject_stale_payloads(materialization) -> None:
    instruction = materialization.projection.instruction_evidence[0]
    payload = instruction.model_dump(mode="json")
    payload["observation_sequence_index"] += 1
    with pytest.raises(ValidationError, match="ID mismatch"):
        CandidateRuntimeInstructionEvidence.model_validate(payload)

    payload = materialization.model_dump(mode="json")
    payload["projection"]["diagnostic_codes"].append("foreign:1")
    with pytest.raises(ValidationError):
        CandidateRuntimeEvidenceMaterialization.model_validate(payload)


def test_reverse_order_is_rejected_by_standalone_model(materialization) -> None:
    order = materialization.projection.order_evidence[0]
    values = order.model_dump(mode="python", exclude={"contract", "id"})
    values["source_sequence_index"] = order.target_sequence_index
    with pytest.raises(ValidationError, match="increasing sequence indexes"):
        CandidateRuntimeOrderEvidence.create(**values)


def test_instruction_observation_appears_once_in_neutral_catalog(
    materialization,
) -> None:
    observations = [
        item.source_runtime_observation_id
        for item in materialization.projection.instruction_evidence
    ]
    assert len(observations) == len(set(observations))
    reused = {}
    for binding in materialization.projection.requirement_evidence_bindings:
        reused.setdefault(binding.source_runtime_evidence_id, set()).add(
            binding.source_requirement_id
        )
    assert any(len(requirements) > 1 for requirements in reused.values())


def test_core_dependency_and_historical_evidence_firewall() -> None:
    paths = (
        Path("src/chipchain/verification/candidate_runtime_evidence_models.py"),
        Path("src/chipchain/verification/candidate_runtime_evidence_binding.py"),
    )
    forbidden_imports = (
        "angr",
        "capstone",
        "AArch64",
        "ProgramArtifact",
        "qemu",
        "knowledge",
        "reasoning",
        "provider",
        "VerificationRecord",
        "VerificationStatus",
        "RuntimeEvidenceNormalizer",
    )
    for path in paths:
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden_imports)


def test_v1_reason_json_schemas_are_explicit_literals() -> None:
    gap = CandidateRuntimeEvidenceGap.model_json_schema()["properties"]["reason"]
    assert gap["enum"] == [
        "no_compatible_runtime_trace",
        "no_matching_instruction_observation",
        "no_matching_runtime_order_observation",
        "current_runtime_contract_does_not_observe_requirement_kind",
    ]
    assert "$ref" not in gap
    reasons = CandidateRuntimeTraceIncompatibility.model_json_schema()["properties"]["reasons"]["items"]
    assert reasons["enum"] == [
        "architecture_mismatch", "artifact_id_mismatch", "artifact_sha256_mismatch"
    ]
    assert "$ref" not in reasons
